package space.jyscan.modules.nuclei.protocol;

import space.jyscan.modules.nuclei.model.HTTPRequest;
import space.jyscan.modules.nuclei.variable.Engine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpHeaders;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * HTTP 协议执行器，对应 Go 的 {@code protocol.HTTPExecutor}。
 *
 * <p>跨包契约：runner 持有字段 {@code httpExec} 并调用
 * {@link #execute(HTTPRequest, String, Map)}。
 *
 * <p>Go 侧 {@code NewHTTPExecutor()} 的配置与 Java 侧等价复刻：
 * <ul>
 *   <li>{@code TLSClientConfig: InsecureSkipVerify: true} → {@link TrustAll#context()}（信任全部证书）；</li>
 *   <li>{@code Dialer{Timeout: 10s, KeepAlive: 30s}} → {@code HttpClient.connectTimeout(10s)}（KeepAlive 无对应可配项）；</li>
 *   <li>{@code Client{Timeout: 10s}} → 每跳一份 {@code hopDeadline = now+10s}：响应头阶段
 *       {@code HttpRequest.timeout(10s)}（JDK 计时器）+ {@code sendAsync.get(+2s)} 自有时钟兜底；
 *       响应体读取同样受该跳剩余预算约束（看门线程限时，见 {@code readLimited}）——
 *       与 Go {@code Client.Timeout} 全程覆盖对齐，半开连接/对端静默不再可能无限期阻塞；</li>
 *   <li>{@code CheckRedirect: len(via) >= 10 即 http.ErrUseLastResponse} →
 *       {@code Redirect.NEVER} + 手动重定向循环，上限 10（同样按「已发请求书 &gt;= 上限即停止」计数，
 *       实际最多跟随 9 次跳转）；</li>
 *   <li>{@code buildRedirectClient}（{@code redirects != 5} 时启用）→ {@link #redirectPolicy}：
 *       自定义次数上限 + {@code !req.HostRedirects} 时跨 host 立即停止；</li>
 *   <li>{@code MaxIdleConns: 100 / IdleConnTimeout: 30s} → java.net.http 内置连接池，无对应可配项（已知偏差）；</li>
 *   <li>强制 HTTP/1.1（Go 自定义 Transport 未开启 HTTP/2）。</li>
 * </ul>
 *
 * <p>注：Go 的 {@code protocol.Cluster}（{@code cluster.go}）与四个桩执行器
 * （{@code NewWSExecutor}/{@code NewWhoisExecutor}/{@code NewFileExecutor}/{@code NewCodeExecutor}）
 * 在 Go 全树均为 0 调用方，按项目「不移植 Go 死代码」的约定一并跳过，
 * 故本包只含 HTTP/DNS/TCP/SSL 四个执行器。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/protocol/protocol.go}。
 */
public class HTTPExecutor {

    /** 对应 Go 默认 client 的 {@code CheckRedirect} 上限（{@code len(via) >= 10}）。 */
    private static final int DEFAULT_REDIRECT_CAP = 10;

    /** 对应 Go {@code Client{Timeout: 10s}}。 */
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    /** 对应 Go {@code Dialer{Timeout: 10s}}。 */
    private static final int DIAL_TIMEOUT_MILLIS = 10_000;

    /** Go 跨 host 重定向时不再复制的敏感头（{@code net/http} 的 {@code stripSensitiveHeaders}）。 */
    private static final Set<String> SENSITIVE_HEADERS =
            Set.of("cookie", "authorization", "www-authenticate", "cookie2");

    private final HttpClient client;
    private final Engine varEngine;

    /** 对应 Go 的 {@code NewHTTPExecutor() *HTTPExecutor}。 */
    public HTTPExecutor() {
        this.varEngine = new Engine();
        this.client = HttpClient.newBuilder()
                .sslContext(TrustAll.context())
                .connectTimeout(Duration.ofMillis(DIAL_TIMEOUT_MILLIS))
                // 重定向改为手动循环，复刻 CheckRedirect 的次数上限与跨 host 停止
                .followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    /**
     * 执行一次 HTTP 请求。
     *
     * <p>对应 Go 的 {@code (e *HTTPExecutor) Execute(req *model.HTTPRequest, target string, vars map[string]interface{}) *ProtocolResult}。
     * 错误按 Go 的方式放在 {@link ProtocolResult#error} 字段内。
     */
    public ProtocolResult execute(HTTPRequest req, String target, Map<String, Object> vars) {
        long start = System.nanoTime();

        if (req.raw != null && !req.raw.isEmpty()) {
            return executeRaw(req, target, vars, start);
        }

        List<String> paths = (req.path == null || req.path.isEmpty()) ? List.of("/") : req.path;
        ProtocolResult lastResult = null;
        for (String p : paths) {
            String fullURL = buildURL(target, p, req.query);
            fullURL = varEngine.render(fullURL, vars);
            String method = req.getMethod();
            byte[] body = (req.body == null || req.body.isEmpty())
                    ? new byte[0]
                    : varEngine.render(req.body, vars).getBytes(StandardCharsets.UTF_8);
            Map<String, String> headers = renderHeaders(req, vars);
            String cookies = renderCookies(req, vars);

            URI uri;
            try {
                uri = URI.create(fullURL);
            } catch (RuntimeException e) {
                // Go: http.NewRequest 出错 →「构建请求失败: %w」，随后 continue
                lastResult = ProtocolResult.failure("http", wrap("构建请求失败: ", e), start);
                continue;
            }
            try {
                Exchange ex = exchange(method, body, headers, cookies, uri,
                        redirectPolicy(req), req.getMaxSize());
                Map<String, Object> data = buildData(fullURL, method, ex);
                lastResult = ProtocolResult.success("http", data, ex.body(), start);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                lastResult = ProtocolResult.failure("http", e, start);
            } catch (Exception e) {
                // Go: client.Do / io.ReadAll 出错 → Error: err，随后 continue
                lastResult = ProtocolResult.failure("http", e, start);
            }
        }
        return lastResult;
    }

    /**
     * 执行 raw 模板请求。
     *
     * <p>对应 Go 的 {@code (e *HTTPExecutor) executeRaw(req, target, vars, start)}：
     * 渲染 raw → 还原字面 {@code \r\n}/{@code \n} → 解析请求行与头部 →
     * {@code buildRawURL} 拼 URL → 发送并收集数据（额外带 {@code response} 原文 dump）。
     */
    private ProtocolResult executeRaw(HTTPRequest req, String target, Map<String, Object> vars, long start) {
        String rawStr = varEngine.render(req.raw == null ? "" : req.raw, vars);
        rawStr = rawStr.replace("\\r\\n", "\r\n").replace("\\n", "\n");

        RawRequest parsed;
        try {
            parsed = parseRawRequest(rawStr);
        } catch (IOException e) {
            return ProtocolResult.failure("http", wrap("解析 raw 请求失败: ", e), start);
        }

        String fullURL = buildRawURL(parsed.host(), parsed.target(), target);
        URI uri;
        try {
            uri = URI.create(fullURL);
        } catch (RuntimeException e) {
            // Go: httpReq.URL, _ := url.Parse(fullURL) 忽略错误，实际失败会 nil 解引用 panic；
            // Java 侧返回「构建请求失败」错误结果（优于 panic）
            return ProtocolResult.failure("http", wrap("构建请求失败: ", e), start);
        }

        try {
            // raw 请求的 Cookie/Host 已在头部集合内，cookies 参数为 null
            Exchange ex = exchange(parsed.method(), parsed.body(), parsed.headers(), null,
                    uri, redirectPolicy(req), req.getMaxSize());
            Map<String, Object> data = buildData(fullURL, parsed.method(), ex);
            data.put("response", dumpResponse(ex));
            return ProtocolResult.success("http", data, ex.body(), start);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ProtocolResult.failure("http", e, start);
        } catch (Exception e) {
            return ProtocolResult.failure("http", e, start);
        }
    }

    /**
     * 发送一次请求并跟随重定向，直到到达最终响应。
     *
     * <p>复刻 Go 两个 client 的 {@code CheckRedirect} 行为：
     * <ul>
     *   <li>已发请求书（含本次）&gt;= 上限 → 停止并返回当前响应（{@code http.ErrUseLastResponse}）；</li>
     *   <li>{@code policy.stopOnHostChange()} 且下一跳 host 与当前不同 → 停止
     *       （{@code buildRedirectClient} 里的 {@code !req.HostRedirects} 分支）；</li>
     *   <li>301/302/303 且方法非 GET/HEAD → 改写为 GET 并丢弃 body（Go {@code redirectBehavior}）；</li>
     *   <li>跨原始 host 的后续请求不带敏感头（Go {@code stripSensitiveHeaders}）。</li>
     * </ul>
     */
    private Exchange exchange(String method, byte[] body, Map<String, String> headers, String cookies,
                              URI initialUri, RedirectPolicy policy, int maxBody)
            throws IOException, InterruptedException {
        String originalHost = hostKey(initialUri);
        String currentHost = originalHost;
        URI currentUri = initialUri;
        String currentMethod = method;
        byte[] currentBody = body;
        int followed = 0;
        while (true) {
            // Go 每次 client.Do 独享一份 Client.Timeout(10s)：发起→收头→读完 body 全程计时。
            // JDK 的 HttpRequest.timeout 只到响应头且依赖内部计时器，这里用自有时钟对
            // 「等待响应头」兜底、对「读取响应体」强制同跳剩余预算（修复卡死类缺陷）。
            long hopDeadline = System.nanoTime() + REQUEST_TIMEOUT.toNanos();
            HttpRequest httpReq = buildRequest(currentUri, currentMethod, currentBody, headers, cookies,
                    !currentHost.equals(originalHost));
            HttpResponse<InputStream> resp = sendWithDeadline(httpReq);
            int code = resp.statusCode();
            Optional<String> location = resp.headers().firstValue("Location");
            if (!isRedirect(code) || location.isEmpty()) {
                return new Exchange(code, resp.headers(), readLimited(resp.body(), maxBody, hopDeadline));
            }
            // Go: len(via) >= cap → ErrUseLastResponse（返回最后一次响应）
            if (followed + 1 >= policy.cap()) {
                return new Exchange(code, resp.headers(), readLimited(resp.body(), maxBody, hopDeadline));
            }
            URI next;
            try {
                next = currentUri.resolve(location.get());
            } catch (IllegalArgumentException e) {
                // Go: resp.Location() 解析失败 → 不再跟随，返回当前响应
                return new Exchange(code, resp.headers(), readLimited(resp.body(), maxBody, hopDeadline));
            }
            String nextHost = hostKey(next);
            if (policy.stopOnHostChange() && !nextHost.equals(currentHost)) {
                return new Exchange(code, resp.headers(), readLimited(resp.body(), maxBody, hopDeadline));
            }
            // Go 会排空并关闭中间跳转的响应体以复用连接
            resp.body().close();

            if ((code == 301 || code == 302 || code == 303)
                    && !"GET".equals(currentMethod) && !"HEAD".equals(currentMethod)) {
                currentMethod = "GET";
                currentBody = new byte[0];
            }
            currentUri = next;
            currentHost = nextHost;
            followed++;
        }
    }

    /**
     * 组装单次（不跟随）请求。
     *
     * <p>{@code Host} 头被跳过：Go 的 {@code net/http} 同样忽略 {@code Header["Host"]}
     * （以 URL 的 host 为准）。其余 java.net.http 受限头（{@code Connection}/
     * {@code Content-Length}/{@code Upgrade} 等）由 Java 自行管理，设置时被拒绝则静默跳过。
     */
    private static HttpRequest buildRequest(URI uri, String method, byte[] body,
                                            Map<String, String> headers, String cookies, boolean crossHost) {
        HttpRequest.Builder b = HttpRequest.newBuilder(uri).timeout(REQUEST_TIMEOUT);
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (crossHost && SENSITIVE_HEADERS.contains(e.getKey().toLowerCase(Locale.ROOT))) {
                continue;
            }
            setHeaderQuietly(b, e.getKey(), e.getValue());
        }
        if (cookies != null && !cookies.isEmpty() && !crossHost) {
            setHeaderQuietly(b, "Cookie", cookies);
        }
        HttpRequest.BodyPublisher publisher = body.length == 0
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(body);
        return b.method(method, publisher).build();
    }

    private static void setHeaderQuietly(HttpRequest.Builder b, String name, String value) {
        try {
            b.setHeader(name, value);
        } catch (IllegalArgumentException ignored) {
            // java.net.http 的受限头（Host/Connection/Content-Length/Upgrade 等），见 buildRequest 注释
        }
    }

    /** 对应 Go 的 {@code if req.GetRedirects() != 5 { client = e.buildRedirectClient(req, ...) }}。 */
    private static RedirectPolicy redirectPolicy(HTTPRequest req) {
        int redirects = req.getRedirects();
        if (redirects != 5) {
            // buildRedirectClient(req, redirects)：自定义上限 + host-redirects 校验
            return new RedirectPolicy(redirects, !req.hostRedirects);
        }
        // e.client 默认 CheckRedirect：上限 10、不校验跨 host
        return new RedirectPolicy(DEFAULT_REDIRECT_CAP, false);
    }

    /** Go {@code CheckRedirect} 的两个参数：次数上限与是否在跨 host 时停止。 */
    private record RedirectPolicy(int cap, boolean stopOnHostChange) {
    }

    /** 一次最终响应的状态（对应 Go {@code resp *http.Response} 中用到的字段）。 */
    private record Exchange(int status, HttpHeaders headers, String body) {
    }

    /**
     * 发送单跳请求，并用自有时钟兜底 Go {@code Client.Timeout} 的「等待响应头」阶段。
     *
     * <p>JDK 的 {@code HttpRequest.timeout} 正常会先触发（错误信息更准）；这里在
     * {@code sendAsync} 之上再加一层 {@code get(10s+2s)}，到期 {@code cancel(true)}，
     * 保证调用线程在任何情况下（计时器失效、对端静默）都有限时返回。
     */
    private HttpResponse<InputStream> sendWithDeadline(HttpRequest httpReq)
            throws IOException, InterruptedException {
        CompletableFuture<HttpResponse<InputStream>> pending =
                client.sendAsync(httpReq, HttpResponse.BodyHandlers.ofInputStream());
        try {
            // 2s 退避：留给 JDK 自带超时（10s）先触发，本层仅兜底
            return pending.get(REQUEST_TIMEOUT.toNanos() + 2_000_000_000L, TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            pending.cancel(true);
            throw new IOException("context deadline exceeded "
                    + "(Client.Timeout exceeded while awaiting headers)", e);
        } catch (ExecutionException e) {
            Throwable c = e.getCause();
            if (c instanceof IOException ioe) {
                throw ioe;
            }
            if (c instanceof RuntimeException re) {
                throw re;
            }
            throw new IOException(c);
        }
    }

    /**
     * 按 {@code GetMaxSize} 上限读取响应体，并受该跳剩余预算约束。
     *
     * <p>对应 Go {@code io.ReadAll(io.LimitReader(resp.Body, int64(req.GetMaxSize())))}。
     * Go 的 {@code Client.Timeout} 同样覆盖响应体读取，而 JDK 的响应体流没有读取超时——
     * 对端发完响应头后悬挂会让 {@code readNBytes} 无限期阻塞。故用看门线程限时读取，
     * 到期 {@code interrupt + close} 唤醒（响应体流的阻塞点可被中断/关闭解除）。
     */
    private static String readLimited(InputStream in, int maxBody, long hopDeadline)
            throws IOException, InterruptedException {
        FutureTask<String> readTask = new FutureTask<>(() -> readLimitedNow(in, maxBody));
        Thread reader = new Thread(readTask, "jyscan-http-body-read");
        reader.setDaemon(true);
        reader.start();
        try {
            long budget = Math.max(0L, hopDeadline - System.nanoTime());
            return readTask.get(budget, TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            readTask.cancel(true);
            try {
                in.close();
            } catch (IOException ignored) {
                // 唤醒阻塞中的读取；失败也无妨，读线程是 daemon
            }
            throw new IOException("context deadline exceeded "
                    + "(Client.Timeout exceeded while reading body)", e);
        } catch (ExecutionException e) {
            Throwable c = e.getCause();
            if (c instanceof IOException ioe) {
                throw ioe;
            }
            throw new IOException(c);
        } catch (InterruptedException e) {
            readTask.cancel(true);
            try {
                in.close();
            } catch (IOException ignored) {
                // 同上
            }
            throw e;
        }
    }

    /** 原读取实现（上限 + UTF-8），由 {@link #readLimited} 限时调度。 */
    private static String readLimitedNow(InputStream in, int maxBody) throws IOException {
        try (InputStream stream = in) {
            int limit = maxBody > 0 ? maxBody : Integer.MAX_VALUE;
            return new String(stream.readNBytes(limit), StandardCharsets.UTF_8);
        }
    }

    /** 对应 Go 的 {@code headerToString(h http.Header)}（逐值追加 {@code "k: v\n"}）。 */
    static String headerToString(HttpHeaders h) {
        StringBuilder b = new StringBuilder();
        h.map().forEach((k, vs) -> {
            for (String v : vs) {
                b.append(canonicalHeaderKey(k)).append(": ").append(v).append('\n');
            }
        });
        return b.toString();
    }

    /**
     * 对应 Go 的 {@code textproto.CanonicalMIMEHeaderKey}：
     * 按 {@code -} 分段、段首字母大写其余小写；含非法字节时原样返回。
     *
     * <p>Java 侧响应回来的头名是服务端原样小写，而 Go 的 {@code http.Header}
     * 键恒为规范形式（如 {@code Content-Type}），matchers 依赖该形态，故统一转换。
     */
    static String canonicalHeaderKey(String s) {
        if (s == null) {
            return null;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!isHeaderTextByte(s.charAt(i))) {
                return s;
            }
        }
        StringBuilder out = new StringBuilder(s.length());
        boolean upper = true;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (upper && c >= 'a' && c <= 'z') {
                c = (char) (c - ('a' - 'A'));
            } else if (!upper && c >= 'A' && c <= 'Z') {
                c = (char) (c + ('a' - 'A'));
            }
            upper = s.charAt(i) == '-';
            out.append(c);
        }
        return out.toString();
    }

    /** Go {@code textproto.validHeaderFieldByte}。 */
    private static boolean isHeaderTextByte(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
    }

    /** 汇总 data map，对应 Go Execute/executeRaw 中的 {@code data := map[string]interface{}{...}}。 */
    private static Map<String, Object> buildData(String fullURL, String method, Exchange ex) {
        String path = "";
        String scheme = "";
        String host = "";
        String hostname = "";
        String port = "";
        try {
            URI u = URI.create(fullURL);
            path = u.getPath() == null ? "" : u.getPath();
            scheme = u.getScheme() == null ? "" : u.getScheme();
            // Go: u.Host / u.Hostname() / u.Port()
            host = authorityHost(u);
            if (host.startsWith("[")) {
                int bracket = host.indexOf(']');
                hostname = bracket >= 0 ? host.substring(1, bracket) : host;
                port = bracket >= 0 && host.length() > bracket + 2 ? host.substring(bracket + 2) : "";
            } else {
                int colon = host.lastIndexOf(':');
                if (colon >= 0) {
                    hostname = host.substring(0, colon);
                    port = host.substring(colon + 1);
                } else {
                    hostname = host;
                }
            }
        } catch (IllegalArgumentException e) {
            // Go: u, _ := url.Parse(fullURL) 忽略错误（失败会 panic）；这里取空串
        }

        long contentLength = ex.headers().firstValueAsLong("Content-Length").orElse(-1L);
        String contentType = ex.headers().firstValue("Content-Type").orElse("");

        Map<String, List<String>> canonicalHeaders = new LinkedHashMap<>();
        ex.headers().map().forEach((k, vs) -> canonicalHeaders.put(canonicalHeaderKey(k), vs));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("status_code", ex.status());
        data.put("all_headers", headerToString(ex.headers()));
        data.put("headers", canonicalHeaders);
        data.put("content_type", contentType);
        data.put("body", ex.body());
        data.put("all", ex.body());
        data.put("raw", ex.body());
        data.put("url", fullURL);
        data.put("path", path);
        data.put("scheme", scheme);
        data.put("host", host);
        data.put("hostname", hostname);
        data.put("port", port);
        data.put("method", method);
        data.put("content_length", contentLength);
        data.put("status", ex.status());

        Map<String, String> headerMap = new LinkedHashMap<>();
        ex.headers().map().forEach((k, vs) -> headerMap.put(canonicalHeaderKey(k), vs.isEmpty() ? "" : vs.get(0)));
        data.put("header", headerMap);
        return data;
    }

    /**
     * 对应 Go 的 {@code buildRawURL(httpReq, target, vars)}：
     * host 取请求 {@code Host} 头（空则用 target），scheme 按 target 前缀判定，
     * path 取请求行目标（空则 {@code "/"}）。注：Go 侧该函数的 {@code vars} 参数未被使用。
     */
    static String buildRawURL(String reqHost, String requestTarget, String target) {
        String host = (reqHost == null || reqHost.isEmpty()) ? target : reqHost;
        String scheme = "https";
        if (target.startsWith("http://")) {
            scheme = "http";
        } else if (!target.startsWith("http")) {
            host = target;
        }
        String path = rawTargetPath(requestTarget);
        if (path.isEmpty()) {
            path = "/";
        }
        return scheme + "://" + host + path;
    }

    /** 对应 Go {@code httpReq.URL.Path}：绝对形式去 authority、去 query/fragment；非路径形式取空。 */
    private static String rawTargetPath(String target) {
        String p = target;
        if (p.startsWith("http://") || p.startsWith("https://")) {
            int schemeLen = p.startsWith("https://") ? 8 : 7;
            int slash = p.indexOf('/', schemeLen);
            p = slash < 0 ? "" : p.substring(slash);
        } else if (p.matches("^[A-Za-z][A-Za-z0-9+.-]*:.*")) {
            // Go: url.Parse("host:443") → scheme/opaque，Path 为空
            return "";
        }
        int query = p.indexOf('?');
        if (query >= 0) {
            p = p.substring(0, query);
        }
        int fragment = p.indexOf('#');
        if (fragment >= 0) {
            p = p.substring(0, fragment);
        }
        return p;
    }

    /**
     * 对应 Go 的 {@code buildURL(target, path, query)}（{@code protocol.go:292}），逐分支照抄：
     * <ul>
     *   <li>path 为绝对 URL → 解析后合并 query（按键排序编码）返回；</li>
     *   <li>target 无 scheme → 补 {@code https://}；解析失败 → 返回 {@code target + path}；</li>
     *   <li>path 以 {@code /} 开头 → 整体替换路径，否则按 Go 规则拼接（缺 {@code /} 先补）；</li>
     *   <li>query 非空 → {@code q.Set} 覆盖后重新编码。</li>
     * </ul>
     */
    static String buildURL(String target, String path, Map<String, String> query) {
        boolean hasQuery = query != null && !query.isEmpty();
        if (path != null && (path.startsWith("http://") || path.startsWith("https://"))) {
            if (!hasQuery) {
                return path;
            }
            try {
                URI parsed = URI.create(path);
                return rebuild(parsed, mergeQuery(rawQueryOf(path), query));
            } catch (IllegalArgumentException e) {
                return path; // Go: url.Parse 失败 → 返回 path
            }
        }

        String t = target == null ? "" : target;
        if (!t.startsWith("http://") && !t.startsWith("https://")) {
            t = "https://" + t;
        }
        URI u;
        try {
            u = URI.create(t);
        } catch (IllegalArgumentException e) {
            return t + (path == null ? "" : path); // Go: return target + path
        }

        String rawPath = u.getRawPath() == null ? "" : u.getRawPath();
        boolean pathChanged = path != null && !path.isEmpty();
        if (pathChanged) {
            if (path.startsWith("/")) {
                rawPath = escapeGoPath(path);
            } else {
                if (!rawPath.endsWith("/")) {
                    rawPath += "/";
                }
                rawPath += escapeGoPath(path);
            }
        }
        if (!pathChanged && !hasQuery) {
            return t;
        }
        String rawQuery = hasQuery ? mergeQuery(rawQueryOf(t), query) : rawQueryOf(t);
        return rebuild(u, rawPath, rawQuery);
    }

    /** 合并 query：{@code q := u.Query(); q.Set(k, v)...; q.Encode()}（按键字典序）。 */
    private static String mergeQuery(String rawQuery, Map<String, String> query) {
        Map<String, List<String>> q = parseQuery(rawQuery);
        for (Map.Entry<String, String> e : query.entrySet()) {
            q.put(e.getKey(), List.of(e.getValue() == null ? "" : e.getValue()));
        }
        return encodeQuery(q);
    }

    /** 对应 Go {@code url.Values} 的解析：按 {@code &} 分段、{@code QueryUnescape} 解码（忽略错误）。 */
    private static Map<String, List<String>> parseQuery(String rawQuery) {
        Map<String, List<String>> q = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isEmpty()) {
            return q;
        }
        for (String segment : rawQuery.split("&", -1)) {
            if (segment.isEmpty()) {
                continue;
            }
            int eq = segment.indexOf('=');
            String k = Protocol.urlDecode(eq < 0 ? segment : segment.substring(0, eq));
            String v = eq < 0 ? "" : Protocol.urlDecode(segment.substring(eq + 1));
            q.computeIfAbsent(k, key -> new java.util.ArrayList<>()).add(v);
        }
        return q;
    }

    /** 对应 Go {@code url.Values.Encode()}：按键排序、{@code QueryEscape} 编码。 */
    private static String encodeQuery(Map<String, List<String>> q) {
        StringBuilder sb = new StringBuilder();
        for (String k : new java.util.TreeSet<>(q.keySet())) {
            for (String v : q.get(k)) {
                if (sb.length() > 0) {
                    sb.append('&');
                }
                sb.append(Protocol.urlEncode(k)).append('=').append(Protocol.urlEncode(v));
            }
        }
        return sb.toString();
    }

    /** 取 URL 的 raw query（首个 {@code ?} 到 {@code #} 之间）。 */
    private static String rawQueryOf(String url) {
        int q = url.indexOf('?');
        if (q < 0) {
            return "";
        }
        int end = url.length();
        int fragment = url.indexOf('#', q);
        if (fragment >= 0) {
            end = fragment;
        }
        return url.substring(q + 1, end);
    }

    /** 用新 raw query 重建 URL（保留 scheme/authority/path/fragment 的 raw 形式）。 */
    private static String rebuild(URI u, String rawQuery) {
        return rebuild(u, u.getRawPath() == null ? "" : u.getRawPath(), rawQuery);
    }

    private static String rebuild(URI u, String rawPath, String rawQuery) {
        StringBuilder sb = new StringBuilder();
        sb.append(u.getScheme()).append("://").append(u.getRawAuthority()).append(rawPath);
        if (!rawQuery.isEmpty()) {
            sb.append('?').append(rawQuery);
        }
        if (u.getRawFragment() != null) {
            sb.append('#').append(u.getRawFragment());
        }
        return sb.toString();
    }

    /**
     * 对应 Go {@code url.String()} 对 {@code u.Path} 的 {@code encodePath} 转义：
     * 保留 {@code A-Za-z0-9} 与 {@code -_.~!$&'()*+,;=:@/}，{@code ?} 及其余字符（含 {@code %}、空格）按字节编码。
     */
    private static String escapeGoPath(String s) {
        byte[] in = s.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(in.length);
        for (byte b : in) {
            int c = b & 0xff;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || "-_.~!$&'()*+,;=:@/".indexOf(c) >= 0) {
                sb.append((char) c);
            } else {
                sb.append('%');
                sb.append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xf, 16)));
                sb.append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
            }
        }
        return sb.toString();
    }

    /** 渲染请求头（对应 Go 逐个 {@code httpReq.Header.Set(k, e.varEngine.Render(v, vars))}）。 */
    private Map<String, String> renderHeaders(HTTPRequest req, Map<String, Object> vars) {
        Map<String, String> headers = new LinkedHashMap<>();
        if (req.headers == null) {
            return headers;
        }
        for (Map.Entry<String, String> e : req.headers.entrySet()) {
            if (e.getKey() == null) {
                continue;
            }
            if (e.getKey().equalsIgnoreCase("Cookie")) {
                // Cookie 头与 req.cookies 合并后统一设置（见 renderCookies），此处仍需渲染
                continue;
            }
            String v = e.getValue() == null ? "" : e.getValue();
            // Go: httpReq.Header.Set 会把键规范成 CanonicalMIMEHeaderKey
            headers.put(canonicalHeaderKey(e.getKey()), varEngine.render(v, vars));
        }
        return headers;
    }

    /** 渲染 Cookie 头：既有 Cookie 头值 + 各 cookie（对应 Go {@code AddCookie} 逐个追加）。 */
    private String renderCookies(HTTPRequest req, Map<String, Object> vars) {
        StringBuilder sb = new StringBuilder();
        if (req.headers != null) {
            for (Map.Entry<String, String> e : req.headers.entrySet()) {
                if (e.getKey() != null && e.getKey().equalsIgnoreCase("Cookie") && e.getValue() != null) {
                    // 对应 Go 先 Header.Set（值经 Render）再 AddCookie 的效果
                    sb.append(varEngine.render(e.getValue(), vars));
                }
            }
        }
        if (req.cookies != null) {
            for (Map.Entry<String, String> c : req.cookies.entrySet()) {
                if (sb.length() > 0) {
                    sb.append("; ");
                }
                String v = c.getValue() == null ? "" : c.getValue();
                v = varEngine.render(v, vars).trim(); // Go: AddCookie 前 TrimSpace
                sb.append(c.getKey()).append('=').append(v);
            }
        }
        return sb.toString();
    }

    /** Go 的 {@code URL.Host} 形态 {@code host[:port]}（不含 userinfo），authority 不可拆分时原样返回。 */
    private static String authorityHost(URI u) {
        if (u.getHost() != null) {
            String host = u.getHost();
            return u.getPort() >= 0 ? host + ":" + u.getPort() : host;
        }
        String authority = u.getRawAuthority();
        if (authority == null) {
            return "";
        }
        int at = authority.lastIndexOf('@');
        return at >= 0 ? authority.substring(at + 1) : authority;
    }

    /** 对应 Go 重定向比较用的 {@code URL.Host}。 */
    private static String hostKey(URI u) {
        return authorityHost(u);
    }

    private static boolean isRedirect(int code) {
        // Go redirectBehavior 关注的跳转状态码
        return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    }

    private static Throwable wrap(String prefix, Throwable e) {
        // 对应 Go fmt.Errorf("%s: %w", ...)
        return new IOException(prefix + e.getMessage(), e);
    }

    // ------------------------------------------------------------------
    // raw 请求解析（对应 Go bufio.NewReader + http.ReadRequest 的常用子集）
    // ------------------------------------------------------------------

    /** 解析后的 raw 请求，对应 Go {@code http.ReadRequest} 得到的 {@code *http.Request} 关键字段。 */
    private record RawRequest(String method, String target, String host,
                              Map<String, String> headers, byte[] body) {
    }

    private static RawRequest parseRawRequest(String rawStr) throws IOException {
        int headEnd = rawStr.indexOf("\r\n\r\n");
        int sepLen = 4;
        if (headEnd < 0) {
            headEnd = rawStr.indexOf("\n\n");
            sepLen = 2;
        }
        String head = headEnd >= 0 ? rawStr.substring(0, headEnd) : rawStr;
        byte[] body = headEnd >= 0
                ? rawStr.substring(headEnd + sepLen).getBytes(StandardCharsets.UTF_8)
                : new byte[0];

        String[] lines = head.split("\r\n|\n", -1);
        if (lines.length == 0 || lines[0].isBlank()) {
            throw new IOException("空请求行");
        }
        String[] fields = lines[0].trim().split("\\s+");
        if (fields.length != 3 || !fields[2].startsWith("HTTP/")) {
            throw new IOException("malformed HTTP request line: " + lines[0]);
        }
        String method = fields[0];
        String target = fields[1];

        Map<String, String> headers = new LinkedHashMap<>();
        String host = "";
        String lastName = null;
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) {
                break;
            }
            if (line.charAt(0) == ' ' || line.charAt(0) == '\t') {
                if (lastName == null) {
                    throw new IOException("malformed header line: " + line);
                }
                headers.put(lastName, headers.get(lastName) + "\n" + line.trim());
                continue;
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                throw new IOException("malformed header line: " + line);
            }
            String name = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            lastName = name;
            if (name.equalsIgnoreCase("Host")) {
                host = value; // Go: ReadRequest 将 Host 头提升到 req.Host
            } else {
                // Go: ReadMIMEHeader 存入 MIMEHeader 时已规范成 CanonicalMIMEHeaderKey
                headers.put(canonicalHeaderKey(name), value);
            }
        }

        // Go http.ReadRequest 按 Content-Length / Transfer-Encoding 读取 body；
        // 两者皆无时请求体为空（Go readTransfer 规则）
        String transferEncoding = findHeader(headers, "Transfer-Encoding");
        String contentLength = findHeader(headers, "Content-Length");
        if (transferEncoding != null && transferEncoding.toLowerCase(Locale.ROOT).contains("chunked")) {
            body = dechunk(body);
        } else if (contentLength != null) {
            long n;
            try {
                n = Long.parseLong(contentLength.trim());
            } catch (NumberFormatException e) {
                n = -1;
            }
            if (n >= 0 && n < body.length) {
                byte[] trimmed = new byte[(int) n];
                System.arraycopy(body, 0, trimmed, 0, (int) n);
                body = trimmed;
            }
            // Go 侧 Content-Length 大于实际 body 会在发送时报错；这里按实际长度发送（已知偏差）
        } else {
            body = new byte[0];
        }
        return new RawRequest(method, target, host, headers, body);
    }

    private static String findHeader(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) {
                return e.getValue();
            }
        }
        return null;
    }

    /** 解码 {@code Transfer-Encoding: chunked} 的请求体，对应 Go {@code http.ReadRequest} 的分块解码。 */
    private static byte[] dechunk(byte[] body) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(body.length);
        int i = 0;
        while (i < body.length) {
            int eol = i;
            while (eol < body.length && body[eol] != '\n') {
                eol++;
            }
            if (eol >= body.length) {
                throw new IOException("chunked body: 缺少行结束符");
            }
            String line = new String(body, i, eol - i, StandardCharsets.US_ASCII).trim();
            int semi = line.indexOf(';');
            if (semi >= 0) {
                line = line.substring(0, semi).trim();
            }
            int size;
            try {
                size = Integer.parseInt(line, 16);
            } catch (NumberFormatException e) {
                throw new IOException("chunked body: 非法块大小 " + line);
            }
            i = eol + 1;
            if (size == 0) {
                break;
            }
            if (i + size > body.length) {
                throw new IOException("chunked body: 块长度越界");
            }
            out.write(body, i, size);
            i += size;
            if (i < body.length && body[i] == '\r') {
                i++;
            }
            if (i < body.length && body[i] == '\n') {
                i++;
            }
        }
        return out.toByteArray();
    }

    /**
     * 对应 Go {@code httputil.DumpResponse(resp, false)}：状态行 + 头部 + 空行。
     *
     * <p>已知偏差：java.net.http 不暴露服务端原因短语，常见状态码用内置表补全，
     * 未知状态码省略原因短语。
     */
    private static String dumpResponse(Exchange ex) {
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(ex.status());
        String reason = statusText(ex.status());
        if (!reason.isEmpty()) {
            sb.append(' ').append(reason);
        }
        sb.append("\r\n");
        ex.headers().map().forEach((k, vs) -> {
            for (String v : vs) {
                sb.append(k).append(": ").append(v).append("\r\n");
            }
        });
        sb.append("\r\n");
        return sb.toString();
    }

    private static String statusText(int code) {
        switch (code) {
            case 100: return "Continue";
            case 101: return "Switching Protocols";
            case 200: return "OK";
            case 201: return "Created";
            case 202: return "Accepted";
            case 203: return "Non Authoritative Information";
            case 204: return "No Content";
            case 205: return "Reset Content";
            case 206: return "Partial Content";
            case 300: return "Multiple Choices";
            case 301: return "Moved Permanently";
            case 302: return "Found";
            case 303: return "See Other";
            case 304: return "Not Modified";
            case 305: return "Use Proxy";
            case 307: return "Temporary Redirect";
            case 308: return "Permanent Redirect";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 402: return "Payment Required";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 406: return "Not Acceptable";
            case 407: return "Proxy Authentication Required";
            case 408: return "Request Timeout";
            case 409: return "Conflict";
            case 410: return "Gone";
            case 411: return "Length Required";
            case 412: return "Precondition Failed";
            case 413: return "Payload Too Large";
            case 414: return "URI Too Long";
            case 415: return "Unsupported Media Type";
            case 416: return "Range Not Satisfiable";
            case 417: return "Expectation Failed";
            case 418: return "I'm a teapot";
            case 426: return "Upgrade Required";
            case 429: return "Too Many Requests";
            case 500: return "Internal Server Error";
            case 501: return "Not Implemented";
            case 502: return "Bad Gateway";
            case 503: return "Service Unavailable";
            case 504: return "Gateway Timeout";
            case 505: return "HTTP Version Not Supported";
            default: return "";
        }
    }
}

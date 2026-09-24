package space.jyscan.modules.weakpass;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

/**
 * weakpass.com 密码字典 API 客户端（JYscan 原创功能；freeclient 的
 * {@code internal/weakpass} 只是弱口令爆破模块的空壳注释，无 API 实现可移植）。
 *
 * <p>API 规范来自 {@code https://weakpass.com/openapi.json}（base: {@code /api/v1}），
 * 全部13个路径均已对接（.json 与 base 实测字节一致，文本形态走 .txt 变体）：
 * <ul>
 *   <li>{@code GET /wordlists} —— 纯文本换行分隔的字典名列表；</li>
 *   <li>{@code GET /wordlists/{name}} —— 字典内容（404 = 不存在）；</li>
 *   <li>{@code GET /search/{hash}[.txt|.json]} —— 哈希查明文（自动识别算法，
 *       404 = 未命中）；</li>
 *   <li>{@code GET /range/{prefix}[.txt|.json]} —— 按前缀检索 hash:pass 对
 *       （{@code type=md5|ntlm|sha1|sha256}、{@code filter=hash|pass}；前缀不足
 *       3 字符 → 500 {@code "Invalid prefix"}；.txt 默认 {@code hash:pass} 行）；</li>
 *   <li>{@code GET /generate/{string}} / {@code POST /generate} —— 预设规则集变异
 *       （{@code set=*.rule}、{@code type=txt|json}；string 含 '/' 无法入 path 时
 *       自动回退 POST query 形式）；</li>
 *   <li>{@code POST /generate/file[/{string}]} —— multipart 上传自定义规则文件；</li>
 *   <li>{@code POST /generate/custom/{string]} —— raw text/plain 规则体
 *       （本客户端从标准输入读取）。</li>
 * </ul>
 * 服务端对 generate 的 string 统一限制不超过64字符（超限 500 +
 * {@code string length should be less 64}，原样透传）。
 *
 * <p>超时设计（与 nuclei {@code HTTPExecutor} 卡死修复同一套思路，杜绝无界阻塞）：
 * <ul>
 *   <li>响应头阶段：{@code sendAsync + get(15s+2s)} 自有时钟兜底（下载请求<b>不</b>设
 *       {@code HttpRequest.timeout}，原因见下）；</li>
 *   <li>列表（小载荷）：{@code HttpRequest.timeout(15s)} + {@code ofString} 的 {@code get}
 *       覆盖到 body 收齐，全程限时；</li>
 *   <li>下载 body：看门轮询，连续 30s 无新字节即断开报错（大文件正常匀速传输不受影响，
 *       卡死/半开连接被限时中断）。</li>
 * </ul>
 *
 * <p>实测注意（weakpass rockyou.txt 140MB 复现）：JDK 的 {@code HttpRequest.timeout}
 * 对 {@code ofInputStream} <b>同样约束 body 读取阶段</b> —— 计时到点后
 * {@code HttpResponseInputStream.read} 抛 {@code IOException: closed}，
 * caused by {@code HttpTimeoutException}（15s 掐断 26s 的正常下载）。因此流式下载
 * 请求绝不能设该超时，头/body 的限时分别由上面两层自有机制承担。
 */
public final class WeakpassClient {

    /** 默认 API 基地址（也可用 {@code --api} 指向自建/测试镜像）。 */
    public static final String DEFAULT_BASE_URL = "https://weakpass.com/api/v1";

    /** 响应头阶段超时（JDK 计时器）。 */
    private static final Duration HEADER_TIMEOUT = Duration.ofSeconds(15);

    /** 自有时钟兜底余量：留给 JDK 超时先触发（错误信息更准），本层仅保底。 */
    private static final long BACKSTOP_NANOS = 2_000_000_000L;

    /** 下载体空闲阈值：连续无新字节达到该时长即判定停滞并中断。 */
    private static final long BODY_IDLE_NANOS = 30_000_000_000L;

    /** API 非 2xx 响应（携带状态码，404 = 字典/列表不存在）。 */
    public static final class ApiException extends IOException {
        private final int status;

        public ApiException(int status, String message) {
            super(message);
            this.status = status;
        }

        public int status() {
            return status;
        }
    }

    private final String baseUrl;
    private final HttpClient client;

    public WeakpassClient() {
        this(DEFAULT_BASE_URL);
    }

    public WeakpassClient(String baseUrl) {
        String b = baseUrl == null || baseUrl.isBlank() ? DEFAULT_BASE_URL : baseUrl.trim();
        while (b.endsWith("/")) {
            b = b.substring(0, b.length() - 1);
        }
        this.baseUrl = b;
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /** GET /wordlists → 字典名列表（跳过空行、保留服务器顺序）。 */
    public List<String> list() throws IOException, InterruptedException {
        HttpRequest req = requestBuilder(baseUrl + "/wordlists")
                .timeout(HEADER_TIMEOUT)
                .GET()
                .build();
        HttpResponse<String> resp = sendString(req);
        checkStatus(resp.statusCode(), resp.body(), "获取字典列表");
        List<String> names = new ArrayList<>();
        for (String line : resp.body().split("\r?\n")) {
            String t = line.trim();
            if (!t.isEmpty()) {
                names.add(t);
            }
        }
        return names;
    }

    /**
     * GET /wordlists/{name} → 流式写入 {@code target}，返回写入字节数。
     *
     * <p>名字先经 {@link #requireSafeName} 校验（防路径穿越），失败时由调用方
     * 负责删除半成品文件（本方法内部出错同样会留下部分文件，交给调用方清理）。
     */
    public long download(String name, Path target) throws IOException, InterruptedException {
        requireSafeName(name);
        // 注意：不设 HttpRequest.timeout —— JDK 计时器会连 body 一起掐（见类注释）；
        // 响应头阶段由下面的 get(15s+2s) 兜底，body 阶段由 copyWithIdleGuard 兜底。
        HttpRequest req = requestBuilder(baseUrl + "/wordlists/" + name)
                .GET()
                .build();

        CompletableFuture<HttpResponse<InputStream>> pending =
                client.sendAsync(req, HttpResponse.BodyHandlers.ofInputStream());
        HttpResponse<InputStream> resp;
        try {
            resp = pending.get(HEADER_TIMEOUT.toNanos() + BACKSTOP_NANOS, TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            pending.cancel(true);
            throw new IOException("下载请求超时(15s): " + name, e);
        } catch (ExecutionException e) {
            throw unwrap(e);
        }

        int code = resp.statusCode();
        if (code != 200) {
            String snippet;
            try (InputStream err = resp.body()) {
                snippet = new String(err.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                snippet = "";
            }
            throw statusException(code, snippet, "下载");
        }

        try (InputStream in = resp.body();
             OutputStream out = Files.newOutputStream(target)) {
            return copyWithIdleGuard(name, in, out);
        }
    }

    /**
     * GET /search/{hash}[.txt|.json] → 查询结果文本（小载荷，全程限时）。
     *
     * <p>文本形态 {@code type;hash;pass}；JSON 形态 {@code {"type","hash","pass"}}。
     * 404 = 库中无此哈希。
     */
    public String search(String hash, boolean json) throws IOException, InterruptedException {
        if (hash == null || hash.isBlank()) {
            throw new IOException("哈希不能为空");
        }
        HttpRequest req = requestBuilder(baseUrl + "/search/" + enc(hash) + (json ? ".json" : ".txt"))
                .timeout(HEADER_TIMEOUT)
                .GET()
                .build();
        HttpResponse<String> resp = sendString(req);
        if (resp.statusCode() == 404) {
            throw new ApiException(404, "未命中: 库中无此哈希 " + hash);
        }
        checkStatus(resp.statusCode(), resp.body(), "哈希查询");
        return resp.body();
    }

    /**
     * GET /range/{prefix}[.txt|.json]?type=&amp;filter= → 流式写 {@code out}，返回字节数。
     *
     * <p>.txt 默认 {@code hash:pass} 行，filter=pass/hash 裁成单列；json 为对象数组。
     * 前缀不足 3 字符 → 500 {@code "Invalid prefix"}（以 ApiException 透传）。
     */
    public long range(String prefix, String type, String filter, boolean json, OutputStream out)
            throws IOException, InterruptedException {
        if (prefix == null || prefix.isBlank()) {
            throw new IOException("前缀不能为空");
        }
        StringBuilder url = new StringBuilder(baseUrl)
                .append("/range/").append(enc(prefix)).append(json ? ".json" : ".txt")
                .append("?type=").append(q(type));
        if (filter != null && !filter.isBlank()) {
            url.append("&filter=").append(q(filter));
        }
        return streamTo(requestBuilder(url.toString()).GET().build(), "前缀检索",
                "range " + prefix, out);
    }

    /**
     * 字典生成（三种模式，响应均流式写出）：
     * <ul>
     *   <li>{@code ruleFile == null} —— 预设规则集：string 可安全入 path 走
     *       {@code GET /generate/{string}?set=&type=}，否则（含 '/'）自动回退
     *       {@code POST /generate?string=&set=&type=}；</li>
     *   <li>{@code ruleFile == "-"} —— 规则从 {@code stdin} 读，走
     *       {@code POST /generate/custom/{string}（raw text/plain body）}；</li>
     *   <li>{@code ruleFile == <路径>} —— 规则文件 multipart 上传：string 可入 path 走
     *       {@code /generate/file/{string}}，否则走 {@code /generate/file}
     *       （string 进表单字段）。JDK 无内置 multipart API，boundary 由本类手拼。</li>
     * </ul>
     */
    public long generate(String string, String set, String ruleFile, boolean json,
                         OutputStream out, InputStream stdin)
            throws IOException, InterruptedException {
        if (string == null || string.isEmpty()) {
            throw new IOException("生成字符串不能为空");
        }
        String type = json ? "json" : "txt";

        if (ruleFile == null) {
            HttpRequest req;
            if (pathSafe(string)) {
                req = requestBuilder(baseUrl + "/generate/" + enc(string)
                        + "?set=" + q(set) + "&type=" + type).GET().build();
            } else {
                req = requestBuilder(baseUrl + "/generate?string=" + q(string)
                        + "&set=" + q(set) + "&type=" + type)
                        .POST(HttpRequest.BodyPublishers.noBody()).build();
            }
            return streamTo(req, "规则生成", "generate " + string, out);
        }

        if ("-".equals(ruleFile)) {
            if (!pathSafe(string)) {
                throw new IOException("字符串含 '/' 无法入 custom 端点路径（该端点无 query 变体），"
                        + "请改用 --rule-file <文件>");
            }
            InputStream src = stdin == null ? InputStream.nullInputStream() : stdin;
            HttpRequest req = requestBuilder(baseUrl + "/generate/custom/" + enc(string)
                    + "?type=" + type)
                    .header("Content-Type", "text/plain; charset=UTF-8")
                    .POST(HttpRequest.BodyPublishers.ofInputStream(() -> src))
                    .build();
            return streamTo(req, "自定义规则生成", "generate custom " + string, out);
        }

        Path rf = Paths.get(ruleFile);
        byte[] rules;
        try {
            rules = Files.readAllBytes(rf);
        } catch (IOException e) {
            throw new IOException("读取规则文件失败: " + ruleFile + ": " + e.getMessage(), e);
        }
        String filename = rf.getFileName().toString();
        String boundary = "----JYscanWeakpass" + Long.toUnsignedString(System.nanoTime());
        Part filePart = part("file", filename, "application/octet-stream", rules);
        Part typePart = part("type", null, null, type.getBytes(StandardCharsets.UTF_8));
        String url;
        List<Part> parts;
        if (pathSafe(string)) {
            url = baseUrl + "/generate/file/" + enc(string);
            parts = List.of(filePart, typePart);
        } else {
            url = baseUrl + "/generate/file";
            parts = List.of(filePart,
                    part("string", null, null, string.getBytes(StandardCharsets.UTF_8)),
                    typePart);
        }
        HttpRequest req = requestBuilder(url)
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(multipartBody(parts, boundary)))
                .build();
        return streamTo(req, "规则文件上传生成", "generate file " + string, out);
    }

    /** 字典名安全校验：拒绝空名、路径分隔符与 `..`（同时保护输出路径）。 */
    public static void requireSafeName(String name) throws IOException {
        if (name == null || name.isBlank()
                || name.contains("/") || name.contains("\\")
                || name.contains("..") || name.indexOf('\0') >= 0) {
            throw new IOException("非法字典名: " + name);
        }
    }

    // ------------------------------------------------------------------
    // 内部实现
    // ------------------------------------------------------------------

    private HttpRequest.Builder requestBuilder(String url) {
        return HttpRequest.newBuilder(URI.create(url))
                .header("Accept", "text/plain, */*")
                .header("User-Agent", "JYscan");
    }

    /** 小载荷全限时发送：ofString 完成 = 头 + 体全部收齐，get 盖住整个往返。 */
    private HttpResponse<String> sendString(HttpRequest req)
            throws IOException, InterruptedException {
        CompletableFuture<HttpResponse<String>> pending =
                client.sendAsync(req, HttpResponse.BodyHandlers.ofString());
        try {
            return pending.get(HEADER_TIMEOUT.toNanos() + BACKSTOP_NANOS, TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            pending.cancel(true);
            throw new IOException("请求超时(15s): " + req.uri(), e);
        } catch (ExecutionException e) {
            throw unwrap(e);
        }
    }

    /**
     * 流式请求三段式：头阶段 {@link #sendStream} 有界（15s+2s 兜底，同样<b>不</b>设
     * {@code HttpRequest.timeout}），非 2xx 读错误体成 {@link ApiException}，
     * 200 的 body 过 {@link #copyWithIdleGuard} 写 {@code out}。
     */
    private long streamTo(HttpRequest req, String what, String nameForMsg, OutputStream out)
            throws IOException, InterruptedException {
        HttpResponse<InputStream> resp = sendStream(req);
        int code = resp.statusCode();
        if (code != 200) {
            String snippet;
            try (InputStream err = resp.body()) {
                snippet = new String(err.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                snippet = "";
            }
            throw statusException(code, snippet, what);
        }
        try (InputStream in = resp.body()) {
            return copyWithIdleGuard(nameForMsg, in, out);
        }
    }

    /** 头阶段有界的流式响应获取（body 留给 streamTo 消费）。 */
    private HttpResponse<InputStream> sendStream(HttpRequest req)
            throws IOException, InterruptedException {
        CompletableFuture<HttpResponse<InputStream>> pending =
                client.sendAsync(req, HttpResponse.BodyHandlers.ofInputStream());
        try {
            return pending.get(HEADER_TIMEOUT.toNanos() + BACKSTOP_NANOS, TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            pending.cancel(true);
            throw new IOException("请求超时(15s): " + req.uri(), e);
        } catch (ExecutionException e) {
            throw unwrap(e);
        }
    }

    private static ApiException statusException(int code, String body, String what) {
        String snippet = body == null ? "" : body.strip();
        if (snippet.length() > 120) {
            snippet = snippet.substring(0, 120) + "...";
        }
        return new ApiException(code, what + "失败: HTTP " + code
                + (snippet.isEmpty() ? "" : " " + snippet));
    }

    private static void checkStatus(int code, String body, String what) throws ApiException {
        if (code == 200) {
            return;
        }
        throw statusException(code, body, what);
    }

    // ---- multipart（JDK 无内置 API，手拼 boundary） ----

    private record Part(String name, String filename, String contentType, byte[] content) {
    }

    private static Part part(String name, String filename, String contentType, byte[] content) {
        return new Part(name, filename, contentType, content);
    }

    private static byte[] multipartBody(List<Part> parts, String boundary) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] crlf = "\r\n".getBytes(StandardCharsets.US_ASCII);
        for (Part p : parts) {
            bos.write(("--" + boundary).getBytes(StandardCharsets.US_ASCII), 0,
                    ("--" + boundary).length());
            bos.write(crlf, 0, crlf.length);
            StringBuilder disp = new StringBuilder("Content-Disposition: form-data; name=\"")
                    .append(p.name()).append('"');
            if (p.filename() != null) {
                disp.append("; filename=\"").append(p.filename().replace("\"", "")).append('"');
            }
            byte[] d = disp.toString().getBytes(StandardCharsets.US_ASCII);
            bos.write(d, 0, d.length);
            bos.write(crlf, 0, crlf.length);
            if (p.contentType() != null) {
                byte[] ct = ("Content-Type: " + p.contentType())
                        .getBytes(StandardCharsets.US_ASCII);
                bos.write(ct, 0, ct.length);
                bos.write(crlf, 0, crlf.length);
            }
            bos.write(crlf, 0, crlf.length);
            bos.write(p.content(), 0, p.content().length);
            bos.write(crlf, 0, crlf.length);
        }
        byte[] tail = ("--" + boundary + "--").getBytes(StandardCharsets.US_ASCII);
        bos.write(tail, 0, tail.length);
        bos.write(crlf, 0, crlf.length);
        return bos.toByteArray();
    }

    // ---- URL 编码与路径安全 ----

    /** path 段百分号编码（空格→%20；'/' 由 {@link #pathSafe} 排除，%2F 服务端会 302）。 */
    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /** query 值表单编码（空格→+ 在 query 中合法）。 */
    private static String q(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /** string 能否安全入 URL path：服务端对 %2F 返回 302，故 '/' 一律排除。 */
    private static boolean pathSafe(String s) {
        return s.indexOf('/') < 0;
    }

    private static IOException unwrap(ExecutionException e) {
        Throwable c = e.getCause();
        if (c instanceof IOException ioe) {
            return ioe;
        }
        if (c instanceof RuntimeException re) {
            return new IOException(re.getMessage(), re);
        }
        return new IOException(c);
    }

    /**
     * 看门线程式流拷贝：读取在独立 daemon 线程进行，调用线程按
     * {@link #BODY_IDLE_NANOS} 轮询进度 —— 每轮之间无新字节即判定停滞，
     * {@code interrupt + close} 唤醒读取线程并报错；有进度则继续等。
     */
    private static long copyWithIdleGuard(String name, InputStream in, OutputStream out)
            throws IOException, InterruptedException {
        AtomicLong progress = new AtomicLong();
        FutureTask<Long> task = new FutureTask<>(() -> {
            byte[] buf = new byte[64 * 1024];
            long total = 0;
            int n;
            try {
                while ((n = in.read(buf)) >= 0) {
                    if (n > 0) {
                        out.write(buf, 0, n);
                        total += n;
                        progress.set(total);
                    }
                }
                out.flush();
            } catch (IOException e) {
                // 带上 cause（如 HttpTimeoutException / 服务端重置），避免只报一个 "closed"
                Throwable cause = e.getCause();
                throw new IOException(cause != null
                        ? "读取中断: " + e.getMessage() + " (" + cause + ")"
                        : "读取中断: " + e.getMessage(), e);
            }
            return total;
        });
        Thread reader = new Thread(task, "jyscan-weakpass-dl");
        reader.setDaemon(true);
        reader.start();

        long last = progress.get();
        try {
            while (true) {
                try {
                    return task.get(BODY_IDLE_NANOS, TimeUnit.NANOSECONDS);
                } catch (TimeoutException idle) {
                    long now = progress.get();
                    if (now == last) {
                        task.cancel(true);
                        try {
                            in.close();
                        } catch (IOException ignored) {
                            // 唤醒阻塞读；失败也无妨，读线程是 daemon
                        }
                        throw new IOException("下载停滞: " + name + " 连续30s无新数据，已中断");
                    }
                    last = now;
                }
            }
        } catch (ExecutionException e) {
            throw unwrap(e);
        } catch (InterruptedException e) {
            task.cancel(true);
            try {
                in.close();
            } catch (IOException ignored) {
                // 同上
            }
            throw e;
        }
    }
}

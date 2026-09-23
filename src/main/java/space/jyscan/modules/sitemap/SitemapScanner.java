package space.jyscan.modules.sitemap;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import space.jyscan.core.util.Fmt;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Writer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Semaphore;

/**
 * Sitemap 分析器，移植自 freeclient/internal/sitemap/sitemap.go。
 *
 * <p>行为映射：
 * <ul>
 *   <li>{@code NewScanner} —— 构建跳过证书校验的 HttpClient，重定向策略随
 *       {@link SitemapConfig#followRedirect}（对应 Go 的 CheckRedirect）；</li>
 *   <li>{@code Start} —— 先探测常见路径，未命中再解析 robots.txt；命中后用
 *       {@link SitemapConfig#threads} 个并发解析各源（对应 Go 的信号量 + goroutine）；</li>
 *   <li>{@code parseSitemap} —— 依次尝试 sitemapindex / urlset / 纯文本三种格式，
 *       与 Go 的 {@code xml.Unmarshal} 尝试顺序一致；</li>
 *   <li>{@code displayResults} / {@code ExportResults} —— 输出与导出保持 Go 的布局。</li>
 * </ul>
 */
public final class SitemapScanner {

    /** 默认 sitemap 探测路径，逐项对应 Go 的 defaultSitemapPaths。 */
    private static final List<String> DEFAULT_SITEMAP_PATHS = List.of(
            "/sitemap.xml",
            "/sitemap_index.xml",
            "/sitemap.txt",
            "/sitemapindex.xml",
            "/sitemap1.xml",
            "/sitemap.gz",
            "/sitemap.xml.gz",
            "/wp-sitemap.xml",
            "/news-sitemap.xml",
            "/video-sitemap.xml",
            "/image-sitemap.xml",
            "/page-sitemap.xml",
            "/post-sitemap.xml",
            "/category-sitemap.xml",
            "/product-sitemap.xml"
    );

    /** 单次响应体读取上限，对应 Go 的 io.LimitReader(resp.Body, 1MB / 10MB)。 */
    private static final long PROBE_LIMIT = 1024L * 1024L;
    private static final long PARSE_LIMIT = 10L * 1024L * 1024L;

    private final SitemapConfig config;
    private final HttpClient client;
    private final List<SitemapResult> results = new ArrayList<>();
    private final Object mu = new Object();
    private final Set<String> visited = Collections.synchronizedSet(new HashSet<>());

    /** 文档解析器工厂在类级别复用（避免每次解析重复初始化）。 */
    private final DocumentBuilderFactory dbf;

    /**
     * 创建扫描器，对应 Go 的 {@code NewScanner}。
     *
     * @throws IllegalStateException TLS 初始化失败（对应 Go 里不可能失败的 transport 构建）
     */
    public SitemapScanner(SitemapConfig config) {
        this.config = config == null ? new SitemapConfig() : config;

        HttpClient.Builder builder = HttpClient.newBuilder();
        Duration timeout = this.config.timeout;
        if (timeout != null && !timeout.isZero() && !timeout.isNegative()) {
            builder.connectTimeout(timeout);
        }
        builder.followRedirects(this.config.followRedirect ? HttpClient.Redirect.NORMAL
                : HttpClient.Redirect.NEVER);

        // Go: &tls.Config{InsecureSkipVerify: true}
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }}, new SecureRandom());
            builder.sslContext(ctx);
            if (System.getProperty("jdk.internal.httpclient.disableHostnameVerification") == null) {
                System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
            }
        } catch (Exception e) {
            throw new IllegalStateException(Fmt.format("初始化TLS失败: %v", e), e);
        }

        this.client = builder.build();

        this.dbf = DocumentBuilderFactory.newInstance();
        // sitemap 里命名空间可有可无（Go 的 encoding/xml 按标签名匹配），这里关闭命名空间感知
        this.dbf.setNamespaceAware(false);
        try {
            // 关闭外部实体，避免 XXE（Go 的 encoding/xml 同样不解析外部实体）
            this.dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            this.dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            this.dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        } catch (Exception ignored) {
            // 部分实现不支持这些 feature：忽略即可，行为与 Go 的宽松解析一致
        }
        this.dbf.setExpandEntityReferences(false);
    }

    // =====================================================================
    // Start 启动扫描（对应 Go 的 (*Scanner).Start）
    // =====================================================================

    /**
     * 执行 sitemap 分析。
     *
     * @return 未找到任何 sitemap 时返回错误消息，成功返回 null
     */
    public String start() {
        String baseURL = trimSuffix(config.targetURL, "/");
        if (!baseURL.startsWith("http://") && !baseURL.startsWith("https://")) {
            baseURL = "http://" + baseURL;
        }

        System.out.println("[JYscan-Sitemap] 开始分析网站地图...");
        System.out.println(Fmt.format("[JYscan-Sitemap] 目标: %s", baseURL));

        List<String> paths = config.customPaths;
        if (paths == null || paths.isEmpty()) {
            paths = DEFAULT_SITEMAP_PATHS;
        }

        System.out.println(Fmt.format("[JYscan-Sitemap] 正在探测 %d 个常见路径...", paths.size()));

        List<String> foundPaths = new ArrayList<>();
        for (String path : paths) {
            String targetURL = baseURL + path;
            if (isVisited(targetURL)) {
                continue;
            }
            if (probePath(targetURL)) {
                foundPaths.add(targetURL);
            }
        }

        if (foundPaths.isEmpty()) {
            System.out.println("[JYscan-Sitemap] 未在常见路径中找到 sitemap，尝试从 robots.txt 获取...");
            List<String> robotsSitemaps = fetchRobotsSitemaps(baseURL);
            if (!robotsSitemaps.isEmpty()) {
                System.out.println(Fmt.format("[JYscan-Sitemap] 从 robots.txt 找到 %d 个 sitemap",
                        robotsSitemaps.size()));
                foundPaths.addAll(robotsSitemaps);
            }
        }

        if (foundPaths.isEmpty()) {
            return "未找到任何 sitemap 文件";
        }

        System.out.println(Fmt.format("[JYscan-Sitemap] 发现 %d 个 sitemap 文件", foundPaths.size()));
        System.out.println("-".repeat(50));

        // 并发解析各源（对应 Go 的 sem := make(chan struct{}, Threads)）
        int threads = Math.max(1, config.threads);
        Semaphore sem = new Semaphore(threads);
        BlockingQueue<SitemapResult> resultCh = new LinkedBlockingQueue<>();
        CountDownLatch latch = new CountDownLatch(foundPaths.size());

        for (String path : foundPaths) {
            Thread t = new Thread(() -> {
                try {
                    sem.acquire();
                    try {
                        resultCh.add(parseSitemap(path, 0));
                    } finally {
                        sem.release();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    latch.countDown();
                }
            }, "jyscan-sitemap");
            t.setDaemon(true);
            t.start();
        }

        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        List<SitemapResult> allResults = new ArrayList<>(resultCh);

        synchronized (mu) {
            results.clear();
            results.addAll(allResults);
        }

        displayResults();
        return null;
    }

    // =====================================================================
    // probePath / fetchRobotsSitemaps / isVisited
    // =====================================================================

    /** 探测指定路径是否为 sitemap，对应 Go 的 {@code (*Scanner).probePath}。 */
    private boolean probePath(String targetURL) {
        HttpResponse<byte[]> resp = doGet(targetURL, PROBE_LIMIT);
        if (resp == null) {
            return false;
        }
        int code = resp.statusCode();
        if (code >= 200 && code < 400) {
            String content = new String(resp.body(), StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
            if (content.contains("<urlset") || content.contains("<sitemapindex")
                    || (targetURL.endsWith(".txt") && content.contains("http"))) {
                return true;
            }
        }
        return false;
    }

    /** 从 robots.txt 提取 sitemap 地址，对应 Go 的 {@code (*Scanner).fetchRobotsSitemaps}。 */
    private List<String> fetchRobotsSitemaps(String baseURL) {
        String robotsURL = baseURL + "/robots.txt";
        HttpResponse<byte[]> resp = doGet(robotsURL, PROBE_LIMIT);
        List<String> sitemaps = new ArrayList<>();
        if (resp == null || resp.statusCode() != 200) {
            return sitemaps;
        }

        String body = new String(resp.body(), StandardCharsets.UTF_8);
        for (String line : body.split("\n", -1)) {
            line = line.trim();
            String lowerLine = line.toLowerCase(Locale.ROOT);
            if (lowerLine.startsWith("sitemap:")) {
                int idx = line.indexOf(':');
                if (idx >= 0) {
                    String sitemapURL = line.substring(idx + 1).trim();
                    if (!sitemapURL.isEmpty()) {
                        if (!sitemapURL.startsWith("http")) {
                            sitemapURL = baseURL + "/" + trimPrefix(sitemapURL, "/");
                        }
                        sitemaps.add(sitemapURL);
                    }
                }
            }
        }
        return sitemaps;
    }

    /** 标记并查询是否已访问，对应 Go 的 {@code (*Scanner).isVisited}（首个访问者返回 false）。 */
    private boolean isVisited(String url) {
        return !visited.add(url);
    }


    // =====================================================================
    // parseSitemap 解析单个 sitemap
    // =====================================================================

    /** 解析单个 sitemap 文件，对应 Go 的 {@code (*Scanner).parseSitemap}。 */
    private SitemapResult parseSitemap(String sitemapURL, int depth) {
        SitemapResult result = new SitemapResult(sitemapURL);

        // Go: if s.config.Recursive && depth > s.config.MaxDepth { return result }
        if (config.recursive && depth > config.maxDepth) {
            return result;
        }

        HttpResponse<byte[]> resp = doGet(sitemapURL, PARSE_LIMIT);
        if (resp == null) {
            result.error = "请求失败";
            return result;
        }
        if (resp.statusCode() != 200) {
            result.error = Fmt.format("HTTP %d", resp.statusCode());
            return result;
        }

        byte[] body = resp.body();
        String content = new String(body, StandardCharsets.UTF_8);

        // 1) sitemapindex
        List<Element> sitemapElements = findElements(body, "sitemap");
        if (!sitemapElements.isEmpty()) {
            String baseURL = getBaseURL(sitemapURL);
            for (Element sm : sitemapElements) {
                String loc = childText(sm, "loc");
                if (!loc.startsWith("http")) {
                    loc = baseURL + "/" + trimPrefix(loc, "/");
                }
                if (!isVisited(loc)) {
                    SitemapResult sub = parseSitemap(loc, depth + 1);
                    result.pageURLs.addAll(sub.pageURLs);
                    result.totalCount += sub.totalCount;
                }
            }
            return result;
        }

        // 2) urlset
        List<Element> urlElements = findElements(body, "url");
        if (!urlElements.isEmpty()) {
            for (Element u : urlElements) {
                result.pageURLs.add(new SitemapUrl(
                        childText(u, "loc"),
                        childText(u, "lastmod"),
                        childText(u, "changefreq"),
                        parsePriority(childText(u, "priority"))));
            }
            result.totalCount = result.pageURLs.size();
            return result;
        }

        // 3) 纯文本（sitemap.txt）
        for (String line : content.split("\n", -1)) {
            line = line.trim();
            if (line.startsWith("http")) {
                result.pageURLs.add(new SitemapUrl(line));
            }
        }
        result.totalCount = result.pageURLs.size();

        if (result.totalCount == 0) {
            result.error = "无法解析 sitemap 内容";
        }

        return result;
    }

    /** 计算 origin，对应 Go 的 {@code (*Scanner).getBaseURL}（url.Parse 失败时原样返回）。 */
    private static String getBaseURL(String targetURL) {
        try {
            URI u = URI.create(targetURL);
            String scheme = u.getScheme();
            String host = u.getHost();
            if (scheme == null || host == null) {
                return targetURL;
            }
            String authority = host;
            if (u.getPort() > 0) {
                authority += ":" + u.getPort();
            }
            return scheme + "://" + authority;
        } catch (Exception e) {
            return targetURL;
        }
    }


    // =====================================================================
    // 输出 / 导出（对应 displayResults / GetResults / ExportResults）
    // =====================================================================

    /** 打印结果，逐行对应 Go 的 {@code (*Scanner).displayResults}。 */
    private void displayResults() {
        int totalURLs = 0;
        int totalSources = 0;

        List<SitemapResult> snapshot;
        synchronized (mu) {
            snapshot = new ArrayList<>(results);
        }

        for (SitemapResult result : snapshot) {
            if (result.error != null) {
                System.out.println(Fmt.format("[!] %s: %v", result.sourceURL, result.error));
                continue;
            }
            totalSources++;
            totalURLs += result.totalCount;

            System.out.println();
            System.out.println(Fmt.format("[+] 来源: %s", result.sourceURL));
            System.out.println(Fmt.format("    页面数量: %d", result.totalCount));

            int displayCount = result.pageURLs.size();
            if (!config.showAll && displayCount > 20) {
                displayCount = 20;
            }

            for (int i = 0; i < displayCount; i++) {
                SitemapUrl page = result.pageURLs.get(i);
                StringBuilder extra = new StringBuilder();
                if (!page.lastMod.isEmpty()) {
                    extra.append(Fmt.format(" [修改: %s]", page.lastMod));
                }
                if (!page.changeFreq.isEmpty()) {
                    extra.append(Fmt.format(" [频率: %s]", page.changeFreq));
                }
                if (page.priority > 0) {
                    extra.append(Fmt.format(" [优先级: %.1f]", page.priority));
                }
                System.out.println(Fmt.format("    %d. %s%s", i + 1, page.loc, extra.toString()));
            }

            if (!config.showAll && result.pageURLs.size() > 20) {
                System.out.println(Fmt.format("    ... 还有 %d 个页面 (使用 --show-all 显示全部)",
                        result.pageURLs.size() - 20));
            }
        }

        System.out.println();
        System.out.println("=".repeat(50));
        System.out.println(Fmt.format("[JYscan-Sitemap] 分析完成: %d 个源, 共 %d 个页面",
                totalSources, totalURLs));
    }

    /** 返回结果快照，对应 Go 的 {@code GetResults}。 */
    public List<SitemapResult> getResults() {
        synchronized (mu) {
            return new ArrayList<>(results);
        }
    }

    /** 导出结果，对应 Go 的 {@code ExportResults}（写入 {@code # 来源} 注释 + URL 列表）。 */
    public void exportResults(Writer w) throws IOException {
        List<SitemapResult> snapshot;
        synchronized (mu) {
            snapshot = new ArrayList<>(results);
        }
        for (SitemapResult result : snapshot) {
            if (result.error != null) {
                continue;
            }
            w.write(Fmt.format("# 来源: %s\n", result.sourceURL));
            for (SitemapUrl page : result.pageURLs) {
                w.write(Fmt.format("%s\n", page.loc));
            }
            w.write(System.lineSeparator());
        }
    }


    // =====================================================================
    // 内部工具
    // =====================================================================

    /**
     * 发起 GET 请求，响应体超过 {@code limit} 时截断（对应 Go 的 io.LimitReader）。
     *
     * @return 响应；请求失败返回 null（对应 Go 的 err != nil）
     */
    private HttpResponse<byte[]> doGet(String url, long limit) {
        try {
            HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(url)).GET();
            if (config.userAgent != null && !config.userAgent.isEmpty()) {
                rb.header("User-Agent", config.userAgent);
            }
            Duration timeout = config.timeout;
            if (timeout != null && !timeout.isZero() && !timeout.isNegative()) {
                rb.timeout(timeout);
            }
            HttpResponse<byte[]> resp = client.send(rb.build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            byte[] body = resp.body();
            if (body != null && body.length > limit) {
                resp = new LimitedResponse(resp.statusCode(), Arrays.copyOf(body, (int) limit));
            }
            return resp;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 截断后的响应包装：Go 用 io.LimitReader 只读取前 N 字节，
     * Java 的 ofByteArray 会读完整个体，这里在内存中截断以保持等价语义。
     */
    private static final class LimitedResponse implements HttpResponse<byte[]> {
        private final int status;
        private final byte[] body;

        LimitedResponse(int status, byte[] body) {
            this.status = status;
            this.body = body;
        }

        @Override
        public int statusCode() {
            return status;
        }

        @Override
        public byte[] body() {
            return body;
        }

        @Override
        public HttpRequest request() {
            return null;
        }

        @Override
        public java.util.Optional<HttpResponse<byte[]>> previousResponse() {
            return java.util.Optional.empty();
        }

        @Override
        public java.net.http.HttpHeaders headers() {
            return java.net.http.HttpHeaders.of(java.util.Map.of(), (a, b) -> true);
        }

        @Override
        public java.util.Optional<javax.net.ssl.SSLSession> sslSession() {
            return java.util.Optional.empty();
        }

        @Override
        public URI uri() {
            return null;
        }

        @Override
        public HttpClient.Version version() {
            return HttpClient.Version.HTTP_1_1;
        }
    }

    /** 用非命名空间感知的 DOM 解析出所有指定标签名的元素；解析失败返回空列表。 */
    private List<Element> findElements(byte[] xml, String tagName) {
        List<Element> out = new ArrayList<>();
        try {
            DocumentBuilder builder = dbf.newDocumentBuilder();
            // 关闭 entity resolver，行为与 Go 的 encoding/xml 一致
            builder.setEntityResolver((publicId, systemId) ->
                    new org.xml.sax.InputSource(new java.io.StringReader("")));
            Document doc = builder.parse(new ByteArrayInputStream(xml));
            NodeList nodes = doc.getElementsByTagName(tagName);
            for (int i = 0; i < nodes.getLength(); i++) {
                Node n = nodes.item(i);
                if (n instanceof Element el) {
                    out.add(el);
                }
            }
        } catch (Exception e) {
            out.clear();
        }
        return out;
    }

    /** 取直接子元素文本（对应 Go 的 xml 标签映射；取首个匹配）。 */
    private static String childText(Element parent, String tag) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            if (n instanceof Element el && tag.equals(el.getTagName())) {
                String text = el.getTextContent();
                return text == null ? "" : text.trim();
            }
        }
        return "";
    }

    /** 解析 priority：非法或缺失按 0 处理（Go 的 float64 零值）。 */
    private static double parsePriority(String s) {
        if (s == null || s.isEmpty()) {
            return 0;
        }
        try {
            return Double.parseDouble(s.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** Go 的 strings.TrimSuffix。 */
    private static String trimSuffix(String s, String suffix) {
        if (s == null) {
            return "";
        }
        if (s.endsWith(suffix)) {
            return s.substring(0, s.length() - suffix.length());
        }
        return s;
    }

    /** Go 的 strings.TrimPrefix。 */
    private static String trimPrefix(String s, String prefix) {
        if (s == null) {
            return "";
        }
        if (s.startsWith(prefix)) {
            return s.substring(prefix.length());
        }
        return s;
    }
}

package space.jyscan.modules.weakpass;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import space.jyscan.core.util.JsonUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * weakpass.com 站内字典目录（{@code /wordlists} 页面）抓取与压缩包直链下载。
 *
 * <p>与官方 API（{@link WeakpassClient}，{@code /api/v1/wordlists} 仅5个可直下
 * 文本字典）不同，站内目录是 Inertia 服务端渲染页面：上千条记录、Laravel 分页器
 * 每页25条。抓取协议（非官方，页面结构变化会失败）：
 * <ol>
 *   <li>GET {@code {root}/wordlists} → HTML 的 {@code data-page} 属性 = 实体转义的
 *       JSON（含 {@code version} 与第1页数据）；</li>
 *   <li>其余页带 {@code X-Inertia: true} + {@code X-Inertia-Version: <version>}
 *       请求同路径 → 纯 JSON；version 过期返回409（刷新 version 后每页重试一次）。</li>
 * </ol>
 * 分页10路并发，全量约10秒。
 *
 * <p>下载路由来自站内 SPA 的 Ziggy 路由表：{@code GET /download/{id}/{link}}
 * → 302 → {@code https://download.weakpass.com/wordlists/{id}/{download_link}}
 * （匿名可下，内容为 .7z/.gz 压缩包，单文件可达数十GB）。因此流式下载复用
 * {@link WeakpassClient} 的三段式传输（头阶段有界等待、body30s空闲看门狗、
 * 不设 {@code HttpRequest.timeout} —— 理由见 WeakpassClient 类注释）。
 *
 * <p>freeclient 无任何对应实现（其 weakpass 仅为爆破模块空壳），本类为 JYscan 原创。
 */
public final class WeakpassCatalog {

    /** 目录记录（保留列表展示与直链下载所需字段）。 */
    public record Entry(long id, String name, String link, String downloadLink,
                        long size, long count, String checksum) {
    }

    private static final Pattern DATA_PAGE = Pattern.compile("data-page=\"([^\"]*)\"");
    private static final int PAGE_WORKERS = 10;

    /** 站内根地址（如 {@code https://weakpass.com}）。 */
    private final String siteRoot;

    /** 复用 API 客户端传输层（UA、头阶段有界、body 空闲看门狗）。 */
    private final WeakpassClient transport;

    /** Inertia 资产版本（分页并发抓取前就绪；409 时刷新）。 */
    private volatile String version;

    public WeakpassCatalog(String siteRoot, WeakpassClient transport) {
        this.siteRoot = siteRoot;
        this.transport = transport;
    }

    /** 由 API 基地址推导站内根：去掉尾部 {@code /api/v1}（或 {@code /api}）。 */
    public static String siteRootOf(String apiBase) {
        if (apiBase.endsWith("/api/v1")) {
            return apiBase.substring(0, apiBase.length() - "/api/v1".length());
        }
        if (apiBase.endsWith("/api")) {
            return apiBase.substring(0, apiBase.length() - "/api".length());
        }
        return apiBase;
    }

    /**
     * 抓取全量目录：首页 HTML（拿 version + 第1页）+ 其余页 X-Inertia JSON 并发抓取。
     *
     * @return 按站点顺序去重后的全部记录
     */
    public List<Entry> fetchAll() throws IOException, InterruptedException {
        Map<Long, Entry> byId = new LinkedHashMap<>();
        long lastPage = fetchFirstPage(byId);
        if (lastPage <= 1) {
            return List.copyOf(byId.values());
        }
        ExecutorService pool = Executors.newFixedThreadPool(
                (int) Math.min(PAGE_WORKERS, lastPage));
        try {
            List<Future<List<Entry>>> futures = new ArrayList<>();
            for (long p = 2; p <= lastPage; p++) {
                // 拷贝为 final 局部再入 lambda：兼容 ECJ（Eclipse/m2e 增量编译）对
                // for 更新变量捕获的严格判定，避免其写出运行期报错的占位 class。
                final long pageNo = p;
                futures.add(pool.submit(() -> fetchPageJson(pageNo)));
            }
            for (Future<List<Entry>> f : futures) {
                List<Entry> pageEntries;
                try {
                    pageEntries = f.get();
                } catch (ExecutionException e) {
                    Throwable c = e.getCause();
                    if (c instanceof InterruptedException ie) {
                        throw ie;
                    }
                    if (c instanceof IOException ioe) {
                        throw ioe;
                    }
                    throw new IOException("站内目录抓取失败: " + c, c);
                }
                for (Entry entry : pageEntries) {
                    byId.putIfAbsent(entry.id(), entry);
                }
            }
        } finally {
            pool.shutdownNow();
        }
        return List.copyOf(byId.values());
    }

    /** 按 name / download_link / link 精确匹配，再退化为 name 忽略大小写；无则 {@code null}。 */
    public static Entry find(List<Entry> entries, String query) {
        if (query == null || query.isBlank()) {
            return null;
        }
        String q = query.trim();
        for (Entry e : entries) {
            if (e.name().equals(q) || e.downloadLink().equals(q) || e.link().equals(q)) {
                return e;
            }
        }
        String lq = q.toLowerCase(Locale.ROOT);
        for (Entry e : entries) {
            if (e.name().toLowerCase(Locale.ROOT).equals(lq)) {
                return e;
            }
        }
        return null;
    }

    /**
     * 直链下载：{@code GET /download/{id}/{link}} → 302 → CDN，流式写 {@code out}。
     *
     * <p>不设 {@code HttpRequest.timeout}（大文件 body 会被它掐断），头阶段由
     * {@link WeakpassClient#streamTo} 的有界等待兜底，body 由空闲看门狗限制。
     *
     * @return 实际写入字节数（压缩包大小）
     */
    public long download(Entry e, OutputStream out) throws IOException, InterruptedException {
        String url = siteRoot + "/download/" + e.id() + "/"
                + URLEncoder.encode(e.link(), StandardCharsets.UTF_8).replace("+", "%20");
        return transport.streamTo(transport.requestBuilder(url).GET().build(),
                "站内下载", e.downloadLink(), out);
    }

    // ------------------------------------------------------------------
    // 页面解析（Inertia data-page / X-Inertia JSON）
    // ------------------------------------------------------------------

    /** 首页（HTML）：解析 {@code data-page} → version + 第1页记录，返回总页数。 */
    private long fetchFirstPage(Map<Long, Entry> byId) throws IOException, InterruptedException {
        HttpResponse<String> resp = transport.sendString(
                transport.requestBuilder(siteRoot + "/wordlists").GET().build());
        if (resp.statusCode() != 200) {
            throw new IOException("站内目录页 HTTP " + resp.statusCode());
        }
        JsonNode page = parseDataPage(resp.body());
        String v = str(page, "version");
        if (v.isEmpty()) {
            throw new IOException("站内目录页缺少 version（页面结构变化或被风控拦截）");
        }
        version = v;
        JsonNode wl = page.path("props").path("wordlists");
        for (Entry e : parseEntries(wl.path("data"))) {
            byId.putIfAbsent(e.id(), e);
        }
        long lastPage = lng(wl, "last_page");
        return Math.max(lastPage, 1);
    }

    /** 后续页（X-Inertia JSON）；409 = version 过期 → 刷新后重试一次。 */
    private List<Entry> fetchPageJson(long pageNo) throws IOException, InterruptedException {
        for (int attempt = 0; attempt < 2; attempt++) {
            HttpRequest req = transport.requestBuilder(siteRoot + "/wordlists?page=" + pageNo)
                    .header("X-Inertia", "true")
                    .header("X-Inertia-Version", version)
                    .GET()
                    .build();
            HttpResponse<String> resp = transport.sendString(req);
            int code = resp.statusCode();
            if (code == 409) {
                refreshVersion();
                continue;
            }
            if (code != 200) {
                throw new IOException("站内目录 page " + pageNo + " HTTP " + code);
            }
            JsonNode page = parseJson(resp.body());
            return parseEntries(page.path("props").path("wordlists").path("data"));
        }
        throw new IOException("站内目录 page " + pageNo + " 版本协商失败（连续409）");
    }

    /**409 后刷新 Inertia version（重新抓首页 HTML）。 */
    private synchronized void refreshVersion() throws IOException, InterruptedException {
        HttpResponse<String> resp = transport.sendString(
                transport.requestBuilder(siteRoot + "/wordlists").GET().build());
        if (resp.statusCode() != 200) {
            throw new IOException("刷新站内目录 version 失败: HTTP " + resp.statusCode());
        }
        String v = str(parseDataPage(resp.body()), "version");
        if (v.isEmpty()) {
            throw new IOException("站内目录页缺少 version");
        }
        version = v;
    }

    /** 从 HTML 中取第一个 {@code data-page} 属性并反实体化解析为 JSON。 */
    private static JsonNode parseDataPage(String html) throws IOException {
        Matcher m = DATA_PAGE.matcher(html);
        if (!m.find()) {
            throw new IOException("站内目录页缺少 data-page（页面结构变化或被风控拦截）");
        }
        return parseJson(unescapeHtml(m.group(1)));
    }

    /** HTML 实体反转义（{@code &amp;} 必须最后处理）。 */
    private static String unescapeHtml(String s) {
        return s.replace("&quot;", "\"")
                .replace("&#039;", "'")
                .replace("&#39;", "'")
                .replace("&#x27;", "'")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&");
    }

    private static JsonNode parseJson(String s) throws IOException {
        if (s == null || s.isBlank()) {
            throw new IOException("站内目录响应为空");
        }
        try {
            return JsonUtil.MAPPER.readTree(s);
        } catch (JsonProcessingException e) {
            throw new IOException("站内目录响应解析失败: " + e.getOriginalMessage(), e);
        }
    }

    /** 取字符串字段（缺失/null → ""）。 */
    private static String str(JsonNode obj, String key) {
        JsonNode v = obj.get(key);
        if (v == null || v.isNull()) {
            return "";
        }
        return v.isTextual() ? v.asText() : v.toString();
    }

    /** 取数值字段（缺失/null → 0）。 */
    private static long lng(JsonNode obj, String key) {
        JsonNode v = obj.get(key);
        if (v == null || v.isNull()) {
            return 0;
        }
        return v.asLong();
    }

    /** 记录数组 → Entry 列表（缺关键字段的记录跳过：下载路由需要 id + link）。 */
    private static List<Entry> parseEntries(JsonNode arr) {
        List<Entry> out = new ArrayList<>();
        if (arr == null || !arr.isArray()) {
            return out;
        }
        for (JsonNode n : arr) {
            long id = lng(n, "id");
            String name = str(n, "name");
            String link = str(n, "link");
            String dl = str(n, "download_link");
            if (id <= 0 || name.isEmpty() || link.isEmpty() || dl.isEmpty()) {
                continue;
            }
            out.add(new Entry(id, name, link, dl,
                    lng(n, "size"), lng(n, "count"),
                    str(n, "checksum")));
        }
        return out;
    }
}

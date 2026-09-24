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
 *       JSON（含 {@code version}、第1页数据与分页元信息）；</li>
 *   <li>其余页带 {@code X-Inertia: true} + {@code X-Inertia-Version: <version>}
 *       请求同路径 → 纯 JSON；version 过期返回409（刷新 version 后每页重试一次）。</li>
 * </ol>
 * 全量分页10路并发约10秒；给定上限时只抓够用的页（如前50条=2页，约1秒）。
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

    /** 目录抓取快照：entries =（按上限截断后的）记录；total = 站点声称的全目录条数。 */
    public record Snapshot(List<Entry> entries, long total) {
    }

    /** 首页（HTML）携带的分页元信息。 */
    private record FirstPage(long lastPage, long perPage, long total) {
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
     * 抓取目录（全量或前 N 条）：首页 HTML（拿 version + 第1页）+ 其余页并发抓取。
     *
     * @param maxEntries 显示上限：非空且为正时只抓够用的页
     *                   （{@code ceil(N/perPage)}，显著更快）并截断到前 N 条；
     *                   null = 全量抓取
     * @return 截断后的记录 + 站点声称的全目录条数（header 展示"共 X 条"用）
     */
    public Snapshot fetch(Long maxEntries) throws IOException, InterruptedException {
        return fetchRange(1, maxEntries == null ? Long.MAX_VALUE : maxEntries);
    }

    /**
     * 抓取第 {@code from} 到 {@code to} 条（1-based 闭区间）：只抓覆盖该区间的页
     * （如每页25条时第12-15条只需首页），返回值含站点总条数。
     *
     * <p>区间超出全目录范围时返回空 entries（total 仍为站点总数），由调用方判定报错。
     */
    public Snapshot fetchRange(long from, long to) throws IOException, InterruptedException {
        if (from < 1) {
            from = 1;
        }
        Map<Long, Entry> byId = new LinkedHashMap<>();
        FirstPage fp = fetchFirstPage(byId);
        long perPage = fp.perPage();
        long lastPage = fp.lastPage();
        long total = fp.total();
        long effTo = total > 0 ? Math.min(to, total) : to;
        if (effTo < from) {
            return new Snapshot(List.of(), total);
        }
        long fromPage = (from - 1) / perPage + 1;
        long toPage = (effTo - 1) / perPage + 1;
        if (toPage > lastPage) {
            toPage = lastPage;
        }
        if (fromPage > 1) {
            byId.clear(); // 只需元信息：第1页记录不属于目标区间
        }
        fetchPagesInto(byId, Math.max(2, fromPage), toPage);
        long startRow = (fromPage - 1) * perPage + 1;
        List<Entry> all = new ArrayList<>(byId.values());
        List<Entry> out = new ArrayList<>();
        for (long i = from - startRow, end = effTo - startRow; i <= end && i < all.size(); i++) {
            if (i >= 0) {
                out.add(all.get((int) i));
            }
        }
        return new Snapshot(List.copyOf(out), Math.max(total, startRow - 1 + all.size()));
    }

    /** 并发抓取 [fromPage, toPage] 的 X-Inertia 页，按页序并入 {@code byId}。 */
    private void fetchPagesInto(Map<Long, Entry> byId, long fromPage, long toPage)
            throws IOException, InterruptedException {
        if (toPage < fromPage) {
            return;
        }
        ExecutorService pool = Executors.newFixedThreadPool(
                (int) Math.min(PAGE_WORKERS, toPage - fromPage + 1));
        try {
            List<Future<List<Entry>>> futures = new ArrayList<>();
            for (long p = fromPage; p <= toPage; p++) {
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
        return download(e, out, null);
    }

    /** 同 {@link #download(Entry, OutputStream)}，可选进度回调（进度条用）。 */
    public long download(Entry e, OutputStream out, WeakpassClient.ProgressListener progress)
            throws IOException, InterruptedException {
        String url = siteRoot + "/download/" + e.id() + "/"
                + URLEncoder.encode(e.link(), StandardCharsets.UTF_8).replace("+", "%20");
        return transport.streamTo(transport.requestBuilder(url).GET().build(),
                "站内下载", e.downloadLink(), out, progress);
    }

    // ------------------------------------------------------------------
    // 页面解析（Inertia data-page / X-Inertia JSON）
    // ------------------------------------------------------------------

    /** 首页（HTML）：解析 {@code data-page} → version + 第1页记录，返回分页元信息。 */
    private FirstPage fetchFirstPage(Map<Long, Entry> byId)
            throws IOException, InterruptedException {
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
        long lastPage = Math.max(lng(wl, "last_page"), 1);
        long perPage = Math.max(lng(wl, "per_page"), 1);
        return new FirstPage(lastPage, perPage, lng(wl, "total"));
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

    /** 409 后刷新 Inertia version（重新抓首页 HTML）。 */
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

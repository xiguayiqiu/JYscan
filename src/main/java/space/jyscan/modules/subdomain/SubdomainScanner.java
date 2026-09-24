package space.jyscan.modules.subdomain;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;
import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.TextFiles;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * 子域名爆破扫描器，移植自 freeclient/internal/subdomain/subdomain.go。
 *
 * <p>实现映射：
 * <ul>
 *   <li>DNS 查询：Go 用 miekg/dns 直连 {@code 8.8.8.8:53}，这里用 dnsjava
 *       {@link SimpleResolver}，但服务器改为「系统 /etc/resolv.conf 优先、
 *       失败逐个换、末尾回退 8.8.8.8」（见偏差列表）；</li>
 *   <li>通配符检测：5 次随机子域 A 查询，收集命中的 IP，后续命中同样 IP 的候选直接丢弃；</li>
 *   <li>并发模型：Go 的 {@code jobs chan} + N 个 goroutine → Java 的
 *       {@link Executors#newFixedThreadPool} + 任务队列；</li>
 *   <li>进度条：逐字符照搬 Go 的算法，输出到 {@code System.err}。</li>
 * </ul>
 *
 * <p>与 Go 的有意偏差（均已注释在对应方法上）：
 * <ul>
 *   <li>{@code -T/--type}：Go 侧 {@code scanSubdomain} 固定查 A 记录，该 flag 实际未生效；
 *       这里按 flag 文档让它参与查询（默认 A 时行为与 Go 完全一致）；</li>
 *   <li>{@code -f/--output}：Go 侧 {@code saveResults} 定义了但从未调用，输出文件永远不落盘；
 *       这里按 flag 文档在扫描结束后调用一次；</li>
 *   <li>DNS 服务器：Go 硬编码 8.8.8.8；国内实测其丢包约 20%、RTT 均值 572ms
 *       （系统 resolver 24ms 零失败），在 1s 读超时下子域名被随机丢弃。
 *       这里改为系统 resolver 优先 + 8.8.8.8 兜底，失败自动换下一家。</li>
 * </ul>
 */
public final class SubdomainScanner {

    /** 回退公共 DNS（Go 硬编码的 "8.8.8.8:53" 原值）。 */
    private static final String FALLBACK_DNS_SERVER = "8.8.8.8";

    /**
     * 查询用 DNS 服务器序列：系统 /etc/resolv.conf 的 IPv4 nameserver 优先，
     * 末尾追加 Go 原值 8.8.8.8 兜底。与 Go 的有意偏差——实测 8.8.8.8 国内
     * 丢包约 20%、RTT 均值 572ms，1s 读超时下结果被随机丢弃（同一批词表
     * 反复跑出 1/2/3 个不同结果）；系统 resolver 24ms 零失败。进程内解析一次。
     */
    private static final List<String> DNS_SERVERS = resolveDnsServers();

    /**
     * 解析 /etc/resolv.conf 的 nameserver（仅 IPv4：链路本地 IPv6 缺 scope id
     * 无法直用），读不到时仅保留回退 DNS。
     */
    private static List<String> resolveDnsServers() {
        List<String> servers = new ArrayList<>();
        try {
            for (String line : Files.readAllLines(Path.of("/etc/resolv.conf"))) {
                String trimmed = line.trim();
                if (!trimmed.startsWith("nameserver")) {
                    continue;
                }
                String[] parts = trimmed.split("\\s+");
                if (parts.length >= 2 && !parts[1].contains(":") && !servers.contains(parts[1])) {
                    servers.add(parts[1]);
                }
            }
        } catch (Exception ignored) {
            // 读不到（非 Unix / 无权限）→ 只走回退 DNS，与 Go 行为一致
        }
        if (!servers.contains(FALLBACK_DNS_SERVER)) {
            servers.add(FALLBACK_DNS_SERVER);
        }
        return List.copyOf(servers);
    }

    /** 单次 A 查询超时，与 Go 的 {@code c.ReadTimeout = 1 * time.Second} 一致。 */
    private static final Duration SCAN_DNS_TIMEOUT = Duration.ofSeconds(1);

    /** 域名校验正则，逐字对应 Go 的 pattern。 */
    private static final Pattern DOMAIN_PATTERN =
            Pattern.compile("^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$");

    private static final SecureRandom RANDOM = new SecureRandom();

    /** 扫描起点（对应 Go 的包级变量 scanStartTime）。 */
    private static volatile long scanStartNanos;

    private final SubdomainConfig config;
    private final List<String> wordlist = new ArrayList<>();
    private final AtomicLong foundCount = new AtomicLong();
    private final AtomicLong scannedCount = new AtomicLong();
    private int totalWords;
    private final Set<String> wildcardIPs = ConcurrentHashMap.newKeySet();
    private final List<SubdomainResult> allResults = new ArrayList<>();
    private final Object mutex = new Object();

    /** 对应 Go 的 config.VerifyHTTP：决定是否做 HTTP 存活校验。 */
    private final boolean verifyHTTP;

    private volatile boolean cancelled;

    /**
     * 创建扫描器，对应 Go 的 {@code NewScanner}（顺带完成字典加载与通配符检测）。
     *
     * @throws IOException 字典文件无法打开 / 读取（消息与 Go 的 error 文案一致）
     */
    public SubdomainScanner(SubdomainConfig config) throws IOException {
        this.config = config == null ? new SubdomainConfig() : config;
        this.verifyHTTP = this.config.verifyHTTP;

        loadWordlist();
        this.totalWords = wordlist.size();

        detectWildcard();
    }

    // =====================================================================
    // 域名校验与字典加载
    // =====================================================================

    /** 域名格式校验，对应 Go 的 {@code IsValidDomain}。 */
    public static boolean isValidDomain(String domain) {
        if (domain == null) {
            return false;
        }
        return DOMAIN_PATTERN.matcher(domain).matches();
    }

    /**
     * 读取字典：给了 -w 则读文件（跳过空行与 # 注释、统一小写），
     * 读不到任何词时回退到内置字典，对应 Go 的 {@code loadWordlist}。
     *
     * @throws IOException 打开或读取文件失败
     */
    private void loadWordlist() throws IOException {
        if (config.wordlist != null && !config.wordlist.isEmpty()) {
            Path file = Path.of(config.wordlist);
            List<String> lines;
            if (!Files.isReadable(file)) {
                // Go: os.Open 失败 → "无法打开字典文件: %v"
                throw new IOException("无法打开字典文件: " + config.wordlist);
            }
            try {
                // 宽容解码：非 UTF-8 字典（GBK/Latin-1 等）不再抛 MalformedInputException
                lines = TextFiles.readLines(file);
            } catch (IOException e) {
                // Go: scanner.Err() → "读取字典文件错误: %v"
                throw new IOException(Fmt.format("读取字典文件错误: %v", e.getMessage()), e);
            }
            for (String raw : lines) {
                String line = raw.trim().toLowerCase(Locale.ROOT);
                if (!line.isEmpty() && !line.startsWith("#")) {
                    wordlist.add(line);
                }
            }
        }

        if (wordlist.isEmpty()) {
            wordlist.addAll(defaultWordlist());
        }
    }

    /** 内置默认字典，从 classpath {@code subdomain/default_wordlist.txt} 读取。 */
    private static List<String> defaultWordlist() {
        List<String> list = new ArrayList<>(2048);
        java.io.InputStream in =
                SubdomainScanner.class.getResourceAsStream("/subdomain/default_wordlist.txt");
        if (in == null) {
            // 资源缺失时返回空列表：totalWords=0 → 扫描自然结束，不打印调用栈
            return list;
        }
        try (java.io.BufferedReader r = new java.io.BufferedReader(
                new java.io.InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                String w = line.trim();
                if (!w.isEmpty()) {
                    list.add(w);
                }
            }
        } catch (Exception e) {
            list.clear();
        }
        return list;
    }
    /** Go 的 generateRandomString：16 字节随机数转 32 位十六进制。 */
    private static String generateRandomString(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    /**
     * 通配符 DNS 检测，对应 Go 的 {@code detectWildcard}：
     * 连续 5 次查询随机子域，命中的 A 记录 IP 记入 {@link #wildcardIPs}；
     * 命中超过 3 次则告警。
     */
    private void detectWildcard() {
        int wildcardCount = 0;

        for (int i = 0; i < 5; i++) {
            String randomSub = generateRandomString(16) + "." + config.domain;

            for (String ip : queryAnswers(randomSub, Type.A, config.timeout, true)) {
                wildcardIPs.add(ip);
                wildcardCount++;
            }
        }

        if (wildcardCount > 3) {
            Colors.warningPrint("\n[!] 警告: 检测到通配符DNS配置");
        }
    }

    // =====================================================================
    // DNS 查询辅助（对应 miekg/dns 的 c.Exchange）
    // =====================================================================

    /**
     * 依次向 {@link #DNS_SERVERS} 查询指定类型并收集答案区的记录值。
     *
     * <p>与 Go 的偏差：Go 只查硬编码的 8.8.8.8 一次，失败即视为无结果；
     * 这里按序列逐个尝试——超时/不可达/SERVFAIL/REFUSED 换下一家，
     * NOERROR/NXDOMAIN 等明确答复直接返回（NXDOMAIN 是权威结论，不再重试）。
     *
     * @param target  目标名（会自动补全为 FQDN）
     * @param qtype   查询类型（{@link Type}）
     * @param timeout 读超时
     * @param aOnly   是否只取 A 记录（Go 的 detectWildcard / scanSubdomain 都用 {@code *dns.A} 分支）
     * @return 答案列表；所有服务器都失败返回空列表（对应 Go 的 err != nil / Rcode != Success）
     */
    private static List<String> queryAnswers(String target, int qtype, Duration timeout,
                                             boolean aOnly) {
        List<String> out = new ArrayList<>();
        for (String server : DNS_SERVERS) {
            try {
                SimpleResolver resolver = new SimpleResolver(server);
                resolver.setPort(53);
                if (timeout != null && !timeout.isZero() && !timeout.isNegative()) {
                    resolver.setTimeout(timeout);
                } else {
                    resolver.setTimeout(Duration.ofSeconds(1));
                }
                Name qname = Name.fromString(target, Name.root);
                Message query = Message.newQuery(
                        org.xbill.DNS.Record.newRecord(qname, qtype, DClass.IN));
                Message in = resolver.send(query);

                int rcode = in.getRcode();
                if (rcode != org.xbill.DNS.Rcode.NOERROR) {
                    // SERVFAIL/REFUSED 是服务器侧故障 → 换下一家；NXDOMAIN 等明确答复直接返回
                    if (rcode == org.xbill.DNS.Rcode.SERVFAIL
                            || rcode == org.xbill.DNS.Rcode.REFUSED) {
                        continue;
                    }
                    return out;
                }
                for (Record r : in.getSectionArray(Section.ANSWER)) {
                    if (aOnly) {
                        if (r instanceof ARecord a) {
                            out.add(a.getAddress().getHostAddress());
                        }
                    } else if (r instanceof ARecord a) {
                        out.add(a.getAddress().getHostAddress());
                    } else if (r instanceof CNAMERecord c) {
                        out.add(c.getTarget().toString());
                    } else {
                        out.add(r.toString());
                    }
                }
                return out;
            } catch (Exception e) {
                // 超时 / 不可达 → 尝试下一个服务器（与 Go「网络失败按无结果处理」
                // 的语义一致，只是多了一次换源机会）
            }
        }
        return out;
    }

    /**
     * 解析 -T/--type 成 dnsjava 的类型码；仅支持 Go 帮助里声明的 A / CNAME，
     * 其余（含空值）按默认 A 处理。
     */
    private static int parseQueryType(String queryType) {
        if (queryType == null) {
            return Type.A;
        }
        String rt = queryType.trim().toUpperCase(Locale.ROOT);
        if ("CNAME".equals(rt)) {
            return Type.CNAME;
        }
        return Type.A;
    }

    // =====================================================================
    // 扫描流程（对应 Start / worker / scanSubdomain / updateProgress）
    // =====================================================================

    /**
     * 执行枚举，对应 Go 的 {@code SubdomainScan} + {@code (*Scanner).Start}。
     *
     * @return 命中结果（保持发现顺序，与 Go 的 allResults 一致）
     */
    public List<SubdomainResult> start() {
        scanStartNanos = System.nanoTime();
        cancelled = false;

        Colors.infoPrint("\n[+] 开始枚举域名...\n");

        int threadCount = Math.max(1, config.threads);
        ExecutorService pool = Executors.newFixedThreadPool(threadCount, r -> {
            Thread t = new Thread(r, "jyscan-sub-worker");
            t.setDaemon(true);
            return t;
        });

        // 进度显示（对应 go s.updateProgress(ctx)）
        Thread progress = new Thread(this::updateProgress, "jyscan-sub-progress");
        progress.setDaemon(true);
        progress.start();

        for (String word : wordlist) {
            if (cancelled) {
                break;
            }
            pool.submit(() -> scanSubdomain(word));
        }

        pool.shutdown();
        try {
            // 等价 Go 的 s.wg.Wait()：所有 worker 归还
            pool.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Go: time.Sleep(100 * time.Millisecond)
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // 扫描结束后按 -f/--output 落盘（Go 侧漏调用，见类注释里的偏差说明）
        if (config.output != null && !config.output.isEmpty()) {
            try {
                saveResults();
            } catch (IOException e) {
                Colors.errorPrint("保存结果失败: %v", e.getMessage() == null ? e : e.getMessage());
            }
        }

        synchronized (mutex) {
            return new ArrayList<>(allResults);
        }
    }

    /**
     * 扫描单个子域名，对应 Go 的 {@code (*Scanner).scanSubdomain}
     * （Go 的 {@code worker} + job 投递在 Java 侧合并为线程池任务）。
     */
    private void scanSubdomain(String subdomain) {
        if (cancelled) {
            return;
        }

        String target = subdomain + "." + config.domain;
        int qtype = parseQueryType(config.queryType);

        // Go: c.ReadTimeout = 1 * time.Second
        List<String> answers = queryAnswers(target, qtype, SCAN_DNS_TIMEOUT, qtype == Type.A);

        if (answers.isEmpty()) {
            scannedCount.incrementAndGet();
            return;
        }

        // Go: 取第一个 *dns.A 记录，ip 为空直接返回
        String ip = answers.get(0);
        if (ip.isEmpty()) {
            scannedCount.incrementAndGet();
            return;
        }

        // 通配符 IP 过滤（-T CNAME 时该集合是 IP，天然不匹配，等于不过滤）
        if (wildcardIPs.contains(ip)) {
            scannedCount.incrementAndGet();
            return;
        }

        if (verifyHTTP) {
            int httpStatus = verifyHTTP(target, SCAN_DNS_TIMEOUT);
            if (httpStatus == 0) {
                scannedCount.incrementAndGet();
                return;
            }
            synchronized (mutex) {
                allResults.add(new SubdomainResult(target, ip, httpStatus));
                foundCount.incrementAndGet();
            }
        } else {
            synchronized (mutex) {
                allResults.add(new SubdomainResult(target, ip));
                foundCount.incrementAndGet();
            }
        }

        scannedCount.incrementAndGet();
    }

    /** 共享 HTTP 客户端：等价 Go 复用 http.DefaultTransport 的效果（仅超时随调用变化）。 */
    private static volatile HttpClient sharedHttpVerifyClient;

    private static HttpClient httpVerifyClient() {
        HttpClient c = sharedHttpVerifyClient;
        if (c != null) {
            return c;
        }
        synchronized (SubdomainScanner.class) {
            if (sharedHttpVerifyClient == null) {
                // Go: CheckRedirect 返回 http.ErrUseLastResponse —— 不跟随重定向
                sharedHttpVerifyClient = HttpClient.newBuilder()
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build();
            }
            return sharedHttpVerifyClient;
        }
    }

    /**
     * HTTP 存活校验，对应 Go 的 {@code verifyHTTP}：先 http 再 https，状态码 &lt; 400 即通过。
     *
     * <p>与 Go 的两点差异：
     * <ul>
     *   <li>Go 每次调用新建 http.Client 但共享 DefaultTransport，这里直接共享一个
     *       {@link HttpClient}（行为等价、避免每次重建连接池）；</li>
     *   <li>Go 的 {@code ctx} 超时兜底 200ms 在这里对应「客户端已取消」——
     *       {@link #cancelled} 为真时直接返回 0（对应 Go 的 ctx.Done 分支）。</li>
     * </ul>
     *
     * <p>保持与 Go 一致：这里<b>不做</b>证书校验豁免，自签名证书的 https 会失败。
     */
    private int verifyHTTP(String domain, Duration timeout) {
        if (cancelled) {
            return 0;
        }

        Duration httpTimeout = timeout;
        if (httpTimeout == null || httpTimeout.isZero() || httpTimeout.isNegative()) {
            httpTimeout = Duration.ofMillis(200);
        }

        HttpClient client = httpVerifyClient();

        for (String url : new String[]{"http://" + domain, "https://" + domain}) {
            if (cancelled) {
                return 0;
            }
            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                        .GET()
                        .timeout(httpTimeout)
                        // Go: req.Host = domain —— Java 不需要：URL 里已带 domain，
                        // Host 头由 HttpClient 自动生成。显式设置会抛
                        // IAE("restricted header name: Host")（曾导致 HTTP 验证
                        // 全部失败、所有子域名被丢弃）
                        // Go 的 UA 原值即 freeclient/1.0，按移植约定保留
                        .header("User-Agent", "freeclient/1.0")
                        .build();
                HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());
                if (resp.statusCode() < 400) {
                    return resp.statusCode();
                }
            } catch (Exception e) {
                // 连接失败 / 超时：尝试下一个协议（与 Go 的 continue 一致）
            }
        }

        return 0;
    }

    /**
     * 进度条，对应 Go 的 {@code updateProgress}：每 200ms 刷新一次，
     * 逐字符照搬 Go 的算法并写到 {@code System.err}。
     */
    private void updateProgress() {
        while (!cancelled) {
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }

            long scanned = scannedCount.get();
            if (scanned >= totalWords) {
                return;
            }

            double progress = (double) scanned / (double) totalWords * 100;
            int width = 20;
            int filled = (int) (progress / 100 * width);
            if (filled > width) {
                filled = width;
            }

            StringBuilder bar = new StringBuilder("[");
            for (int i = 0; i < width; i++) {
                if (i < filled - 1) {
                    bar.append('=');
                } else if (i == filled - 1) {
                    bar.append('>');
                } else {
                    bar.append(' ');
                }
            }
            bar.append(']');

            System.err.printf("\r%s %d/%d", bar, scanned, totalWords);
        }
    }

    /** 保存结果，对应 Go 的 {@code saveResults}（Go 侧未被调用，见类注释的偏差说明）。 */
    private void saveResults() throws IOException {
        List<SubdomainResult> snapshot;
        synchronized (mutex) {
            snapshot = new ArrayList<>(allResults);
        }
        StringBuilder sb = new StringBuilder();
        for (SubdomainResult result : snapshot) {
            if (result.httpStatus > 0) {
                sb.append(Fmt.format("%d %s\n", result.httpStatus, result.subdomain));
            } else {
                sb.append(Fmt.format("%s -> %s\n", result.subdomain, result.ip));
            }
        }
        Files.writeString(Path.of(config.output), sb.toString(), StandardCharsets.UTF_8);
    }

    /** 取消扫描（对应 Go 的 ctx.CancelFunc），供命令的中断钩子调用。 */
    public void cancel() {
        cancelled = true;
    }

    /** 返回结果快照（对应 Go 侧直接返回的 allResults）。 */
    public List<SubdomainResult> getAllResults() {
        synchronized (mutex) {
            return new ArrayList<>(allResults);
        }
    }

    /** 已发现数量，对应 Go 的 foundCount。 */
    public long foundCount() {
        return foundCount.get();
    }

    /** 已扫描数量，对应 Go 的 scannedCount。 */
    public long scannedCount() {
        return scannedCount.get();
    }

    /** 字典总词数，对应 Go 的 totalWords。 */
    public int totalWords() {
        return totalWords;
    }

    /** 扫描耗时，对应 Go 的 {@code GetScanDuration}。 */
    public static Duration getScanDuration() {
        long start = scanStartNanos;
        if (start == 0) {
            return Duration.ZERO;
        }
        return Duration.ofNanos(Math.max(0L, System.nanoTime() - start));
    }
}

package space.jyscan.modules.dirscan;

import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.TextFiles;

import org.jsoup.Jsoup;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedWriter;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 目录扫描器，移植自 freeclient/internal/dirscan/dirscan.go。
 *
 * <p>并发模型与 Go 版一一对应：
 * <ul>
 *   <li>{@code jobs}：任务队列（Go 的 buffered channel，容量为字典长度）；</li>
 *   <li>{@code results}：结果队列（Go 的 buffered channel，容量 100），由单独的结果处理线程消费；</li>
 *   <li>{@code threads} 个工作线程（Go 的 worker goroutine）从任务队列取词扫描；</li>
 *   <li>主线程每 100ms 刷新一次进度（Go 的 ticker），直到工作线程全部结束；</li>
 *   <li>Ctrl+C 由 JVM 关闭钩子处理（Go 的 signal.Notify），打印中断部分报告。</li>
 * </ul>
 */
public class Scanner {

    /** 结果队列结束标记（对应 Go 的 close(s.results)）。 */
    private static final ScanResult POISON = new ScanResult();

    /** 默认状态码颜色：2xx绿 3xx蓝 4xx黄 5xx红 其他白。 */
    private static final Set<Integer> VALID_STATUS_CODES = Set.of(200, 301, 302, 100, 101);

    private final ScanConfig config;
    private HttpClient client;
    private final List<String> wordlist = new ArrayList<>();

    /** 对应 Go 的 results chan ScanResult（容量 100）。 */
    private final BlockingQueue<ScanResult> results = new LinkedBlockingQueue<>(100);

    /** 对应 Go 的 jobs chan string（容量 len(wordlist)）。 */
    private final BlockingQueue<String> jobs = new LinkedBlockingQueue<>();

    private final Object mutex = new Object();

    private int foundCount;
    private int scannedCount;
    private int totalWords;
    private final List<ScanResult> allResults = new ArrayList<>();

    /** 对应 Go 的 ctx 取消：置位后工作线程退出。 */
    private volatile boolean interrupted = false;

    /** 对应 Go 的 s.wg：全部工作线程结束后计数归零。 */
    private volatile CountDownLatch workersLatch;

    private Thread consumerThread;
    private BufferedWriter outputFile;

    /** 中断报告只打印一次。 */
    private final AtomicBoolean interruptHandled = new AtomicBoolean(false);
    /** 中断报告打印完成信号（供关闭钩子与主线程互相等待）。 */
    private final CountDownLatch reportDone = new CountDownLatch(1);

    // =====================================================================
    // NewScanner 创建新的扫描器
    // =====================================================================

    /**
     * 创建新的扫描器，对应 Go 的 NewScanner。
     *
     * @throws IllegalStateException 代理无效 / 字典无法加载（消息与 Go 的 error 文案一致）
     */
    public Scanner(ScanConfig config) throws Exception {
        this.config = config;

        // 配置HTTP客户端
        HttpClient.Builder builder = HttpClient.newBuilder();

        // Go: Timeout 覆盖整个请求；Java 侧用 connectTimeout + 每请求 timeout 组合
        if (config.timeout != null && !config.timeout.isZero() && !config.timeout.isNegative()) {
            builder.connectTimeout(config.timeout);
        }

        // 跟随重定向（Go: FollowRedirects: true -> CheckRedirect 返回 nil）
        builder.followRedirects(config.followRedirects ? HttpClient.Redirect.NORMAL : HttpClient.Redirect.NEVER);

        // Go: TLSClientConfig: InsecureSkipVerify: true —— 跳过证书校验
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
            // 与 InsecureSkipVerify 等价：同时跳过主机名校验
            if (System.getProperty("jdk.internal.httpclient.disableHostnameVerification") == null) {
                System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
            }
        } catch (Exception e) {
            throw new IllegalStateException(Fmt.format("初始化TLS失败: %v", e), e);
        }

        // 设置代理
        if (config.proxy != null && !config.proxy.isEmpty()) {
            builder.proxy(createProxySelector(config.proxy));
        }

        client = builder.build();

        // 加载字典文件或内置字典
        loadWordlist();

        totalWords = wordlist.size();
    }

    /** 解析代理地址，对应 Go 的 url.Parse(config.Proxy) + http.ProxyURL。 */
    private static ProxySelector createProxySelector(String proxy) {
        try {
            URI uri = new URI(proxy);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                throw new URISyntaxException(proxy, "缺少主机名");
            }
            String scheme = uri.getScheme() == null ? "http" : uri.getScheme().toLowerCase();
            int port = uri.getPort();
            if (port < 0) {
                // 按协议给出默认端口
                port = switch (scheme) {
                    case "https", "ssl" -> 443;
                    case "socks", "socks5" -> 1080;
                    default -> 80;
                };
            }
            Proxy.Type type = scheme.startsWith("socks") ? Proxy.Type.SOCKS : Proxy.Type.HTTP;
            Proxy p = new Proxy(type, new InetSocketAddress(host, port));
            // ProxySelector.of 只支持HTTP代理，这里自定义以同时支持Go版声明的SOCKS
            return new ProxySelector() {
                @Override
                public List<Proxy> select(URI uri) {
                    return List.of(p);
                }

                @Override
                public void connectFailed(URI uri, java.net.SocketAddress sa, IOException ioe) {
                    // 与Go一致：连接失败不额外处理，由请求层上报错误
                }
            };
        } catch (Exception e) {
            // Go: fmt.Errorf("无效的代理地址: %v", err)
            throw new IllegalStateException(Fmt.format("无效的代理地址: %v", e), e);
        }
    }

    // =====================================================================
    // loadWordlist 加载字典文件
    // =====================================================================

    private void loadWordlist() {
        // 加载外部字典文件
        List<String> lines;
        try {
            // 宽容解码（UTF-8→GB18030→ISO-8859-1 兜底）：Go 版按字节读不炸，
            // Java 严格 UTF-8 会因非法字节抛 MalformedInputException（"Input length = 1"）
            lines = TextFiles.readLines(Path.of(config.wordlist));
        } catch (Exception e) {
            // Go: fmt.Errorf("无法打开字典文件: %v", err)
            throw new IllegalStateException(Fmt.format("无法打开字典文件: %v", e), e);
        }

        for (String text : lines) {
            String line = text.trim();
            // 空行与 # 注释行跳过（与 Go 版一致）
            if (!line.isEmpty() && !line.startsWith("#")) {
                wordlist.add(line);
            }
        }

        if (wordlist.isEmpty()) {
            // Go: fmt.Errorf("字典文件为空")
            throw new IllegalStateException("字典文件为空");
        }
    }

    // =====================================================================
    // clearScreen 跨平台清屏（用 ANSI 转义序列替代 Go 的 exec clear/cls）
    // =====================================================================

    private static void clearScreen() {
        System.out.print("\u001b[2J\u001b[H");
        System.out.flush();
    }

    // =====================================================================
    // Start 开始扫描
    // =====================================================================

    /** 开始扫描，对应 Go 的 (*Scanner).Start()。 */
    public void start() throws Exception {
        List<String> extList = config.extensions == null ? List.of() : config.extensions;

        Colors.infoPrint("开始目录扫描...");
        Colors.infoPrint("目标: %s", config.url);
        Colors.infoPrint("字典: %s (%d 个条目)", config.wordlist, wordlist.size());
        Colors.infoPrint("扩展名: %v (共 %d 个)", extList, extList.size());
        Colors.infoPrint("预计总任务数: %d", totalWords);
        Colors.infoPrint("线程: %d", config.threads);
        Colors.infoPrint("超时: %v", config.timeout);

        // 显示扩展名配置
        if (!extList.isEmpty()) {
            Colors.infoPrint("扩展名: %s", String.join(", ", extList));
        }

        Colors.infoPrint("%s", "-".repeat(50));

        // 设置Ctrl+C信号处理（JVM关闭钩子，替代 Go 的 signal.Notify）
        Thread hook = new Thread(this::handleInterrupt, "dirscan-signal");
        Runtime.getRuntime().addShutdownHook(hook);

        try {
            // 创建输出文件
            if (config.outputFile != null && !config.outputFile.isEmpty()) {
                try {
                    outputFile = Files.newBufferedWriter(Path.of(config.outputFile), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    // Go: fmt.Errorf("创建输出文件失败: %v", err)
                    throw new IllegalStateException(Fmt.format("创建输出文件失败: %v", e), e);
                }
            }

            // 启动结果处理器（对应 Go 的 go s.processResults(outputFile)）
            consumerThread = new Thread(this::processResults, "dirscan-results");
            consumerThread.setDaemon(true);
            consumerThread.start();

            // 创建工作池（对应 Go 的 jobs channel + worker goroutine）
            int workerCount = Math.max(1, config.threads);
            for (String word : wordlist) {
                jobs.put(word);
            }
            workersLatch = new CountDownLatch(workerCount);
            ExecutorService pool = Executors.newFixedThreadPool(workerCount, r -> {
                Thread t = new Thread(r, "dirscan-worker");
                t.setDaemon(true);
                return t;
            });
            for (int i = 0; i < workerCount; i++) {
                pool.submit(() -> {
                    try {
                        worker();
                    } finally {
                        workersLatch.countDown();
                    }
                });
            }

            // 实时显示进度，直到扫描完成（对应 Go 的 100ms ticker）
            while (!interrupted) {
                if (workersLatch.await(100, TimeUnit.MILLISECONDS)) {
                    break;
                }
                // 定期更新进度显示
                synchronized (mutex) {
                    printTickerProgress();
                }
            }

            // Ctrl+C被按下：打印中断报告并返回
            if (interrupted) {
                pool.shutdownNow();
                handleInterrupt();
                return;
            }

            // 扫描完成：等待所有工作完成，然后结束结果处理器
            pool.shutdown();
            results.put(POISON);
            if (consumerThread != null) {
                consumerThread.join();
            }

            // 显示扫描完成进度
            Colors.infoPrint("\r扫描进度: %d/%d (100.0%%)", totalWords, totalWords);

            // 显示排序后的结果
            displaySortedResults();

            Colors.infoPrint("");
            Colors.infoPrint("扫描完成! 找到 %d 个有效路径", foundCountSnapshot());
            if (config.outputFile != null && !config.outputFile.isEmpty()) {
                Colors.infoPrint("结果已保存到: %s", config.outputFile);
            }
        } finally {
            // 扫描正常结束：移除关闭钩子，避免退出时再打印中断报告
            try {
                Runtime.getRuntime().removeShutdownHook(hook);
            } catch (IllegalStateException ignored) {
                // JVM正在关闭，钩子已在执行
            }
            closeOutput();
        }
    }

    // =====================================================================
    // handleInterrupt 处理中断信号
    // =====================================================================

    /**
     * 处理中断（关闭钩子与主线程都可能进入，只有一个线程真正打印报告）。
     *
     * <p>与 Go 版的差异：Go 会阻塞等待"按任意键"，JVM 关闭钩子里不能等待标准输入，
     * 因此只打印提示后由 JVM 正常退出（见报告末尾）。
     */
    private void handleInterrupt() {
        if (!interruptHandled.compareAndSet(false, true)) {
            // 已有线程在打印报告：等待它完成（有界等待，避免挂死JVM关闭流程）
            try {
                reportDone.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            return;
        }

        try {
            // 对应 Go 的 s.interrupted = true + s.cancel()：让工作线程尽快退出
            interrupted = true;

            CountDownLatch latch = workersLatch;
            if (latch != null) {
                try {
                    // 有界等待在途请求完成
                    latch.await(3, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }

            // 对应 Go 的 close(s.results)，唤醒结果处理器
            try {
                results.offer(POISON, 1, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            Thread consumer = consumerThread;
            if (consumer != null) {
                try {
                    consumer.join(2000);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            }

            // 清屏并显示整理后的结果
            clearScreen();

            Colors.infoPrint("");
            Colors.infoPrint("=== 扫描被中断 ===");
            synchronized (mutex) {
                double progress = totalWords == 0 ? 0 : (double) scannedCount / totalWords * 100;
                Colors.infoPrint("已扫描: %d/%d (%.1f%%)", scannedCount, totalWords, progress);
            }
            Colors.infoPrint("找到有效路径: %d", foundCountSnapshot());
            Colors.infoPrint("");

            // 显示整理后的结果
            displayOrganizedResults();

            // Go: fmt.Println("\n按任意键退出...") + 阻塞读取stdin。
            // JVM关闭钩子中不能等待标准输入，只打印提示。
            Colors.infoPrint("");
            Colors.infoPrint("按任意键退出...");
        } finally {
            reportDone.countDown();
        }
    }

    // =====================================================================
    // worker 工作线程
    // =====================================================================

    /** 工作线程，对应 Go 的 (*Scanner).worker(jobs)。 */
    private void worker() {
        while (!interrupted) {
            String word = jobs.poll();
            if (word == null) {
                // 任务已全部取完（对应Go的channel关闭）
                return;
            }
            scanPath(word);
        }
        // 对应 Go 的 case <-s.ctx.Done(): return
    }

    // =====================================================================
    // scanPath 扫描单个路径
    // =====================================================================

    private void scanPath(String path) {
        if (config.extensions != null && !config.extensions.isEmpty()) {
            for (String ext : config.extensions) {
                scanWithExtension(path, ext);
            }
        } else {
            if (path.contains("%EXT%")) {
                updateProgress();
                return;
            }
            scanURL(path);
        }
        updateProgress();
    }

    /** 扫描带扩展名的路径。 */
    private void scanWithExtension(String path, String extension) {
        List<String> pathsToScan = new ArrayList<>();

        // 处理路径中的占位符
        if (path.contains("%EXT%")) {
            pathsToScan.add(path.replace("%EXT%", extension));
        } else {
            pathsToScan.add(path + "." + extension);
        }

        for (String p : pathsToScan) {
            scanURL(p);
        }
    }

    // =====================================================================
    // scanURL 扫描URL
    // =====================================================================

    private void scanURL(String path) {
        String targetURL = normalizeURL(path);

        try {
            HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(targetURL)).GET();

            // 设置User-Agent
            if (config.userAgent != null && !config.userAgent.isEmpty()) {
                req.header("User-Agent", config.userAgent);
            } else {
                req.header("User-Agent", "JYscan DirScanner/1.0");
            }

            // 请求超时（对应Go的 http.Client.Timeout）
            if (config.timeout != null && !config.timeout.isZero() && !config.timeout.isNegative()) {
                req.timeout(config.timeout);
            }

            HttpResponse<byte[]> resp = client.send(req.build(), HttpResponse.BodyHandlers.ofByteArray());

            // 读取响应体大小（对应Go的 io.ReadAll）
            byte[] body = resp.body() == null ? new byte[0] : resp.body();

            // 提取页面标题
            String title = extractTitle(new String(body, StandardCharsets.UTF_8));

            results.put(ScanResult.of(targetURL, resp.statusCode(), body.length, title));
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            // 请求构造/传输/读取失败：记录错误结果（processResults 会跳过不显示）
            try {
                results.put(ScanResult.ofError(targetURL, e));
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }
    }

    // =====================================================================
    // updateProgress 更新扫描进度
    // =====================================================================

    private void updateProgress() {
        synchronized (mutex) {
            scannedCount++;

            // 每扫描10个路径或扫描完成时显示进度
            if (scannedCount % 10 == 0 || scannedCount == totalWords) {
                double progress = (double) scannedCount / totalWords * 100;
                System.out.print(Fmt.format("\r扫描进度: %d/%d (%.1f%%)", scannedCount, totalWords, progress));
                System.out.flush();
            }
        }
    }

    /** 主进度循环的定时刷新，对应 Go ticker 的 {@code \r\033[K扫描进度...}。 */
    private void printTickerProgress() {
        double progress = (double) scannedCount / totalWords * 100;
        System.out.print(Fmt.format("\r\u001b[K扫描进度: %d/%d (%.1f%%)", scannedCount, totalWords, progress));
        System.out.flush();
    }

    // =====================================================================
    // normalizeURL 标准化URL
    // =====================================================================

    private String normalizeURL(String path) {
        String baseURL = config.url;
        // 对应 Go 的 strings.TrimSuffix（只去掉一个结尾斜杠）
        if (baseURL.endsWith("/")) {
            baseURL = baseURL.substring(0, baseURL.length() - 1);
        }
        // 对应 Go 的 strings.TrimPrefix（只去掉一个开头斜杠）
        if (path.startsWith("/")) {
            path = path.substring(1);
        }

        // 检查基础URL是否包含协议，如果没有则添加默认协议
        if (!baseURL.startsWith("http://") && !baseURL.startsWith("https://")) {
            baseURL = "http://" + baseURL;
        }

        return baseURL + "/" + path;
    }

    // =====================================================================
    // processResults 处理扫描结果
    // =====================================================================

    /** 处理扫描结果（独立线程），对应 Go 的 processResults。 */
    private void processResults() {
        while (true) {
            ScanResult result;
            try {
                result = results.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (result == POISON) {
                return;
            }

            // 过滤掉错误结果，不存储错误路径
            if (result.error != null) {
                // 不显示错误信息，直接跳过
                continue;
            }

            // 存储有效结果用于后续排序显示
            synchronized (mutex) {
                allResults.add(result);
            }

            if (!passesFilter(result)) {
                continue;
            }

            // 显示所有扫描结果
            displayResult(result);

            // 保存到文件
            BufferedWriter writer = outputFile;
            if (writer != null) {
                saveResult(writer, result);
            }

            if (result.statusCode >= 200 && result.statusCode < 400) {
                synchronized (mutex) {
                    foundCount++;
                }
            }
        }
    }

    /**
     * 状态码过滤逻辑，与 Go 的 processResults / displayOrganizedResults 中
     * 完全相同的分支保持一致：
     * <pre>
     * // 默认只显示有效状态码（200, 301, 302, 100, 101）
     * // --show-all 或指定 --status-codes 时走自定义逻辑
     * </pre>
     */
    private boolean passesFilter(ScanResult result) {
        // 检查是否为有效状态码
        boolean isValidStatusCode = VALID_STATUS_CODES.contains(result.statusCode);

        // 检查是否为404/403状态码
        boolean is404403 = result.statusCode == 404 || result.statusCode == 403;

        // 如果启用了显示404/403，则允许显示这些状态码
        boolean allow404403 = config.show404403 && is404403;

        List<Integer> filter = config.statusCodeFilter;

        // 如果启用了显示所有状态码，或者有自定义的状态码过滤器，则使用原有逻辑
        if (config.showAll || (filter != null && !filter.isEmpty())) {
            if (filter != null && !filter.isEmpty()) {
                boolean found = false;
                for (int code : filter) {
                    if (result.statusCode == code) {
                        found = true;
                        break;
                    }
                }
                if (!found && !config.showAll) {
                    return false;
                }
            }
            return true;
        }

        // 默认情况下，只显示有效状态码或允许的404/403状态码
        return isValidStatusCode || allow404403;
    }

    // =====================================================================
    // displayResult 显示扫描结果
    // =====================================================================

    private void displayResult(ScanResult result) {
        synchronized (this) {
            String statusColor = statusCodeColor(result.statusCode);

            // 保存光标位置，显示结果，然后恢复光标位置
            System.out.print("\u001b[s");

            System.out.print(Fmt.format("[%s] %-8d %s",
                    Colors.wrap(Fmt.format("%3d", result.statusCode), statusColor),
                    result.size,
                    result.url));

            if (result.title != null && !result.title.isEmpty()) {
                System.out.print(Fmt.format(" - %s", result.title));
            }
            System.out.println();

            // 恢复光标位置并显示进度
            System.out.print("\u001b[u");
            synchronized (mutex) {
                double progress = (double) scannedCount / totalWords * 100;
                System.out.print(Fmt.format("\r\u001b[K扫描进度: %d/%d (%.1f%%)",
                        scannedCount, totalWords, progress));
            }
            System.out.flush();
        }
    }

    // =====================================================================
    // displaySortedResults 显示排序后的结果
    // =====================================================================

    private void displaySortedResults() {
        displayOrganizedResults();
    }

    // =====================================================================
    // displayOrganizedResults 显示整理后的结果
    // =====================================================================

    private void displayOrganizedResults() {
        List<ScanResult> snapshot;
        synchronized (mutex) {
            snapshot = new ArrayList<>(allResults);
        }

        if (snapshot.isEmpty()) {
            Colors.infoPrint("没有找到任何有效路径");
            return;
        }

        // 按状态码分类结果
        Map<Integer, List<ScanResult>> resultsByStatus = new TreeMap<>();

        for (ScanResult result : snapshot) {
            if (result.error != null) {
                continue;
            }

            // 应用与实时扫描相同的过滤逻辑
            if (!passesFilter(result)) {
                continue;
            }

            resultsByStatus.computeIfAbsent(result.statusCode, k -> new ArrayList<>()).add(result);
        }

        // 显示每个状态码的结果（TreeMap按状态码升序，对应Go的sort.Ints）
        for (Map.Entry<Integer, List<ScanResult>> entry : resultsByStatus.entrySet()) {
            int statusCode = entry.getKey();
            List<ScanResult> group = entry.getValue();

            // 按URL长度排序，便于阅读
            group.sort(Comparator.comparingInt(r -> r.url.length()));

            // 显示状态码标题
            String statusColor = statusCodeColor(statusCode);
            System.out.println();
            System.out.println(Colors.wrap(
                    Fmt.format("=== 状态码 %d (%d 个路径) ===", statusCode, group.size()),
                    statusColor));

            // 显示结果
            for (ScanResult result : group) {
                displayResult(result);
            }
        }
        System.out.flush();

        // 显示错误结果（如果存在）。与Go一致：错误结果从不写入allResults，
        // 因此该分支实际不会触发，保留以维持移植的完整性。
        List<ScanResult> errorResults = new ArrayList<>();
        for (ScanResult result : snapshot) {
            if (result.error != null) {
                errorResults.add(result);
            }
        }

        if (!errorResults.isEmpty()) {
            Colors.infoPrint("");
            Colors.infoPrint("=== 错误结果 (%d 个) ===", errorResults.size());
            for (ScanResult result : errorResults) {
                Colors.infoPrint("[ERROR] %s: %v", result.url, result.error);
            }
        }
    }

    // =====================================================================
    // saveResult 保存结果到文件
    // =====================================================================

    private void saveResult(BufferedWriter file, ScanResult result) {
        try {
            file.write(Fmt.format("%d\t%d\t%s\t%s\n",
                    result.statusCode, result.size, result.url, result.title));
        } catch (IOException ignored) {
            // 与Go一致：file.WriteString 的错误未被检查
        }
    }

    private void closeOutput() {
        BufferedWriter writer = outputFile;
        if (writer != null) {
            try {
                writer.close();
            } catch (IOException ignored) {
            }
            outputFile = null;
        }
    }

    private int foundCountSnapshot() {
        synchronized (mutex) {
            return foundCount;
        }
    }

    // =====================================================================
    // extractTitle 从HTML中提取标题
    // =====================================================================

    /**
     * 从HTML中提取标题。Go 版用字符串查找 {@code <title>}，这里按实现指引改用 jsoup 解析，
     * 之后应用与 Go 完全相同的后处理：TrimSpace、换行/制表符替换为空格、超长截断。
     */
    static String extractTitle(String html) {
        if (html == null || html.isEmpty()) {
            return "";
        }

        String title;
        try {
            title = Jsoup.parse(html).title();
        } catch (Exception e) {
            // 解析失败按无标题处理
            return "";
        }
        if (title == null) {
            return "";
        }

        title = title.trim();
        title = title.replace('\n', ' ').replace('\t', ' ');

        // 限制标题长度（Go: len(title) > 50 -> title[:47] + "..."）
        if (title.length() > 50) {
            title = title.substring(0, 47) + "...";
        }

        return title;
    }

    // =====================================================================
    // statusCodeColor 根据状态码获取颜色（对应 Go 的 getStatusCodeColor）
    // =====================================================================

    static String statusCodeColor(int statusCode) {
        if (statusCode >= 200 && statusCode < 300) {
            return Colors.FG_GREEN;
        } else if (statusCode >= 300 && statusCode < 400) {
            return Colors.FG_BLUE;
        } else if (statusCode >= 400 && statusCode < 500) {
            return Colors.FG_YELLOW;
        } else if (statusCode >= 500) {
            return Colors.FG_RED;
        }
        return Colors.FG_WHITE;
    }
}

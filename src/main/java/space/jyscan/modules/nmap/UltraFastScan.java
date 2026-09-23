package space.jyscan.modules.nmap;

import space.jyscan.core.i18n.I18n;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 超高速端口扫描引擎，移植自 freeclient/internal/nmap/scan_optimized.go(961) 与
 * scan_optimized_linux.go(212) / scan_optimized_windows.go(36)。
 *
 * <p><b>归属</b>：集成者接管 B 号后补建（B 号留下 {@code ScanEngine} 对本类的两处引用未实现，
 * 导致全树编译失败）。
 *
 * <p>本类承载 Go 的 {@code UltraFastScan}(165) 主函数、{@code servicePortMap}(85)、
 * {@code portPriorityMap}(19)、轮次执行 {@code runScanRound}/{@code scanPortBatch}、
 * 辅助函数 {@code sortPortsByPriority}/{@code getRemainingPorts}/{@code getOpenPorts}、
 * Banner 抓取 {@code grabBannersConcurrent}/{@code grabBannerFast}，以及同文件里的
 * {@code hostDiscoveryFast}(812)。
 *
 * <h2>有意偏差</h2>
 * <ol>
 *   <li><b>{@code ultraFastTCPConnect} 的实现手段</b>：Go 的 Linux 版用裸
 *       {@code socket/connect/ppoll/getsockopt}（scan_optimized_linux.go:29，注释称比
 *       {@code net.DialTimeout} 快 5-10 倍）；Java 侧用 {@link Socket#connect}（JDK 内部
 *       同样是非阻塞 connect + poll）。<b>三态判定与 Go 逐条对齐</b>（见该方法 javadoc），
 *       差别只在单次探测的绝对耗时，不引入 JNA 裸套接字——Java 没有 Go 那样的
 *       {@code faccessat2}/seccomp 障碍，且路由模块的 JNA 路径会额外触发
 *       JDK 26 的 "restricted native access" 提示。</li>
 *   <li><b>并发载体</b>：Go 用 goroutine + {@code sync.Map}；Java 复用
 *       {@link ScanEngine#workerPool()}（512 线程守护池）+ {@link ConcurrentHashMap}。
 *       当 {@code concurrency} &gt; 512（如 -T5 的 1000）时实际并发被池上限压到 512，
 *       与 Go 的 1000 goroutine 有性能差、无结果差。</li>
 *   <li><b>进度显示</b>：Go 起一个 100ms ticker 的 goroutine 写 {@code \r} 单行；
 *       Java 用同为守护线程的 100ms 轮询，输出格式与 {@code \r%-Ns\r} 清行逻辑一致。</li>
 *   <li><b>{@code context.Context} 未移植</b>：Go 每轮循环内 {@code select ctx.Done()}；
 *       Java 由 {@link ScanEngine#cancelScan()} 的 {@code shutdownNow()} 中断承担。</li>
 * </ol>
 */
public final class UltraFastScan {

    private UltraFastScan() {
    }

    /**
     * 服务端口映射（快速服务识别），对应 Go {@code servicePortMap}（scan_optimized.go:85）。
     *
     * <p>供 {@link ScanEngine} 在超高速路径上直接套用服务名（Go: {@code servicePortMap[port]}）。
     */
    public static final Map<Integer, String> OPTIMIZED_SERVICE_PORT_MAP = Map.ofEntries(
            Map.entry(21, "ftp"),
            Map.entry(22, "ssh"),
            Map.entry(23, "telnet"),
            Map.entry(25, "smtp"),
            Map.entry(53, "domain"),
            Map.entry(80, "http"),
            Map.entry(110, "pop3"),
            Map.entry(111, "rpcbind"),
            Map.entry(135, "msrpc"),
            Map.entry(139, "netbios-ssn"),
            Map.entry(143, "imap"),
            Map.entry(161, "snmp"),
            Map.entry(389, "ldap"),
            Map.entry(443, "https"),
            Map.entry(445, "microsoft-ds"),
            Map.entry(465, "smtps"),
            Map.entry(514, "shell"),
            Map.entry(587, "submission"),
            Map.entry(636, "ldaps"),
            Map.entry(993, "imaps"),
            Map.entry(995, "pop3s"),
            Map.entry(1433, "ms-sql-s"),
            Map.entry(1521, "oracle"),
            Map.entry(1723, "pptp"),
            Map.entry(3306, "mysql"),
            Map.entry(3389, "ms-wbt-server"),
            Map.entry(5432, "postgresql"),
            Map.entry(5900, "vnc"),
            Map.entry(6379, "redis"),
            Map.entry(8080, "http-proxy"),
            Map.entry(8443, "https-alt"),
            Map.entry(9200, "elasticsearch"),
            Map.entry(27017, "mongodb"));

    /**
     * 端口优先级表，对应 Go {@code portPriorityMap}（scan_optimized.go:19）。
     *
     * <p>Go 的构造是 {@code for i, port := range commonPriority { m[port] = i }}——
     * <b>重复端口取最后一次出现的下标</b>（如 445/587/636/993/995/1433/1521/1723/3306/3389/
     * 5432/5900/6379 都重复过），此处逐下标 {@code put} 复刻同样的"后写覆盖"语义。
     */
    private static final Map<Integer, Integer> PORT_PRIORITY_MAP;

    static {
        int[] commonPriority = {
                // 极高优先级: 核心服务
                80, 443, 22, 21, 23, 25, 53, 110, 143, 993, 995,
                // 高优先级: 常见服务
                135, 139, 445, 587, 636, 989, 990, 1433, 1521, 1723,
                3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
                // 中优先级: 其他常见端口
                81, 88, 111, 113, 119, 123, 137, 138, 161, 162, 179,
                194, 389, 427, 444, 445, 464, 465, 500, 512, 513, 514,
                515, 543, 544, 548, 554, 563, 587, 591, 593, 631, 636,
                639, 646, 691, 749, 750, 754, 873, 902, 993, 995, 1025,
                1026, 1027, 1028, 1029, 1080, 1099, 1110, 1194, 1198,
                1214, 1241, 1290, 1311, 1337, 1433, 1434, 1500, 1521,
                1522, 1526, 1533, 1541, 1550, 1589, 1701, 1718, 1720,
                1723, 1755, 1761, 1801, 1812, 1813, 1863, 1900, 1935,
                1985, 2000, 2001, 2002, 2049, 2082, 2083, 2086, 2087,
                2095, 2096, 2100, 2121, 2161, 2222, 2301, 2375, 2376,
                2381, 2401, 2443, 2483, 2484, 2546, 2593, 2601, 2602,
                2604, 2605, 2700, 2710, 2800, 2809, 2947, 2967, 3000,
                3001, 3031, 3050, 3071, 3128, 3260, 3268, 3269, 3283,
                3300, 3333, 3389, 3390, 3396, 3455, 3478, 3527, 3546,
                3632, 3689, 3690, 3780, 3784, 3800, 3820, 3830, 3845,
                3872, 3880, 3899, 3900, 3920, 3945, 3971, 4000, 4001,
                4006, 4045, 4111, 4224, 4242, 4279, 4321, 4343, 4443,
                4444, 4445, 4500, 4567, 4662, 4711, 4712, 4848, 4899,
                4998, 5000, 5001, 5003, 5009, 5030, 5033, 5050, 5051,
                5054, 5060, 5061, 5080, 5087, 5100, 5101, 5120, 5190,
                5222, 5223, 5269, 5280, 5298, 5353, 5357, 5400, 5405,
                5432, 5433, 5498, 5500, 5510, 5544, 5550, 5555, 5560,
                5566, 5631, 5632, 5666, 5678, 5720, 5800, 5801, 5802,
                5810, 5811, 5900, 5901, 5910, 5911, 5920, 5960, 5977,
                5984, 5985, 5986, 5999, 6000, 6001, 6060, 6070, 6080,
                6100, 6112, 6129, 6156, 6257, 6346, 6347, 6379, 6380,
                6500, 6502, 6503, 6505, 6506, 6507, 6510, 6543, 6547,
                6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669,
                6679, 6697, 6881, 6891, 6901, 6969, 7000, 7001, 7002,
                7004, 7007, 7019, 7025, 7070, 7099, 7100, 7161, 7171,
                7200, 7210, 7300, 7396, 7400, 7401, 7402, 7435, 7443,
                7496, 7512, 7547, 7625, 7676, 7700, 7707, 7708, 7720,
                7741, 7777, 7778, 7800, 7911, 7920, 7937, 7938, 7999,
                8000, 8001, 8002, 8003, 8007, 8008, 8009, 8010, 8014,
                8020, 8021, 8030, 8031, 8042, 8045, 8080, 8081, 8082,
                8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093,
                8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222,
                8254, 8290, 8291, 8300, 8333, 8383, 8400, 8443, 8444,
                8500, 8543, 8600, 8612, 8649, 8651, 8652, 8654, 8701,
                8765, 8787, 8800, 8834, 8848, 8873, 8880, 8881, 8888,
                8899, 8943, 8983, 9000, 9001, 9002, 9003, 9009, 9010,
                9040, 9050, 9051, 9060, 9080, 9081, 9090, 9091, 9099,
                9100, 9101, 9102, 9103, 9110, 9111, 9151, 9191, 9200,
                9207, 9220, 9290, 9300, 9306, 9322, 9323, 9332, 9343,
                9392, 9418, 9443, 9495, 9500, 9535, 9536, 9595, 9600,
                9666, 9675, 9710, 9777, 9780, 9800, 9801, 9802, 9876,
                9898, 9910, 9920, 9943, 9944, 9968, 9981, 9987, 9990,
                9997, 9998, 9999,
                // 低优先级: 10000-65535 (按顺序扫描)
        };
        Map<Integer, Integer> m = new HashMap<>();
        for (int i = 0; i < commonPriority.length; i++) {
            m.put(commonPriority[i], i);
        }
        PORT_PRIORITY_MAP = Collections.unmodifiableMap(m);
    }

    /** Go: {@code progressMu}——多主机并发扫描时防止进度行重叠（scan_optimized.go:141）。 */
    private static final Object PROGRESS_MU = new Object();

    // =====================================================================
    // ultraFastTCPConnect —— 单端口三态探测
    // =====================================================================

    /**
     * 超高速 TCP 连接检测，对应 Go {@code ultraFastTCPConnect}（scan_optimized_linux.go:29 /
     * scan_optimized_windows.go:20）。
     *
     * <p><b>三态判定与 Go 逐条对齐</b>：
     * <table border="1">
     *   <caption>Go 分支 → Java 分支</caption>
     *   <tr><th>Go 触发条件</th><th>返回</th><th>Java 对应</th></tr>
     *   <tr><td>{@code net.ParseIP(ip) == nil}</td><td>{@code closed}</td>
     *       <td>IP 解析失败/空串 → 直接 {@code closed}</td></tr>
     *   <tr><td>{@code connect} 立即成功</td><td>{@code open}</td>
     *       <td>{@link Socket#connect} 正常返回</td></tr>
     *   <tr><td>非 {@code EINPROGRESS} 的立即失败</td><td>{@code closed}</td>
     *       <td>{@link java.net.ConnectException}（ECONNREFUSED 等）→ {@code closed}</td></tr>
     *   <tr><td>{@code ppoll} 超时（ret==0）/ {@code EINTR}</td><td>{@code filtered}</td>
     *       <td>{@link java.net.SocketTimeoutException} → {@code filtered}</td></tr>
     *   <tr><td>{@code SO_ERROR} ∈ {ETIMEDOUT, EHOSTUNREACH, ENETUNREACH}</td>
     *       <td>{@code filtered}</td><td>{@link java.net.NoRouteToHostException} →
     *       {@code filtered}</td></tr>
     *   <tr><td>其他 {@code SO_ERROR}</td><td>{@code closed}</td>
     *       <td>其余 {@link java.net.SocketException} → {@code closed}</td></tr>
     * </table>
     *
     * <p>超时钳制也与 Go 相同：{@code <=0} 取 1ms、{@code >1000ms} 取 1000ms
     * （scan_optimized_linux.go:81-87）。
     *
     * @param ip      目标 IP
     * @param port    目标端口
     * @param timeout 探测超时
     * @return {@link NmapConstants#PORT_STATE_OPEN} / {@link NmapConstants#PORT_STATE_CLOSED}
     *         / {@link NmapConstants#PORT_STATE_FILTERED}
     */
    public static String ultraFastTCPConnect(String ip, int port, Duration timeout) {
        // Go: addr := net.ParseIP(ip); if addr == nil { return PortStateClosed }
        if (ip == null || ip.isEmpty() || ScanParse.parseIP(ip) == null) {
            return NmapConstants.PORT_STATE_CLOSED;
        }

        // Go: timeoutMs<=0 -> 1; >1000 -> 1000
        long millis = timeout == null ? 0 : timeout.toMillis();
        if (millis <= 0) {
            millis = 1;
        }
        if (millis > 1000) {
            millis = 1000;
        }

        try (Socket socket = new Socket()) {
            // Go: connect 立即成功 -> open；立即失败 -> closed；EINPROGRESS -> 等 ppoll
            socket.connect(new InetSocketAddress(ip, port), (int) millis);
            return NmapConstants.PORT_STATE_OPEN;
        } catch (java.net.SocketTimeoutException e) {
            // Go: ppoll ret==0 / EINTR -> filtered
            return NmapConstants.PORT_STATE_FILTERED;
        } catch (java.net.NoRouteToHostException e) {
            // Go: SO_ERROR ∈ {ETIMEDOUT, EHOSTUNREACH, ENETUNREACH} -> filtered
            return NmapConstants.PORT_STATE_FILTERED;
        } catch (java.net.ConnectException e) {
            // Go: ECONNREFUSED -> closed
            return NmapConstants.PORT_STATE_CLOSED;
        } catch (java.net.UnknownHostException e) {
            // 域名解析失败（Go 侧入参恒为已解析 IP，此分支为 Java 防御）
            return NmapConstants.PORT_STATE_CLOSED;
        } catch (java.net.SocketException e) {
            // Go: default -> closed
            return NmapConstants.PORT_STATE_CLOSED;
        } catch (java.io.IOException e) {
            // Go 的 syscall 错误兜底 + try-with-resources close() 的受检异常 -> closed
            return NmapConstants.PORT_STATE_CLOSED;
        } catch (RuntimeException e) {
            // Go: syscall.Socket/Connect 报错 -> closed
            return NmapConstants.PORT_STATE_CLOSED;
        }
    }

    // =====================================================================
    // ultraFastScan —— 超高速扫描主函数
    // =====================================================================

    /**
     * 超高速端口扫描，对应 Go {@code UltraFastScan}（scan_optimized.go:165）。
     *
     * <p>四阶段流程与 Go 一致：① 端口按优先级排序 → ② 首轮快速超时 → ③ 重试 filtered
     * → ④ 最终确认剩余 filtered → ⑤ 仅对开放端口延迟抓 Banner。
     *
     * @param ip     目标 IP
     * @param ports  端口列表（顺序不影响结果，内部会按优先级排序）
     * @param config 超高速配置；为 {@code null} 时用 {@link UltraFastScanConfig#defaultConfig()}
     * @return 端口 → {@link PortInfo}；<b>端口列表为空时返回 {@code null}</b>，
     *         对应 Go 的 {@code (nil, error{"没有端口需要扫描"})}，由调用方打印
     *         {@code nmap.err.ultra_scan_failed} 并回退到
     *         {@link ScanEngine#portScanWithProgress}
     */
    public static Map<Integer, PortInfo> ultraFastScan(String ip, List<Integer> ports,
                                                       UltraFastScanConfig config) {
        if (config == null) {
            config = UltraFastScanConfig.defaultConfig();
        }
        // Go: if config.Concurrency <= 0 { config.Concurrency = 2000 }
        if (config.concurrency <= 0) {
            config.concurrency = 2000;
        }
        // Go: if config.InitialTimeout <= 0 { config.InitialTimeout = 5ms }
        if (config.initialTimeout == null || config.initialTimeout.isZero()
                || config.initialTimeout.isNegative()) {
            config.initialTimeout = Duration.ofMillis(5);
        }

        int totalPorts = ports == null ? 0 : ports.size();
        if (totalPorts == 0) {
            return null;
        }

        // 端口排序: 常见端口优先
        List<Integer> sortedPorts = sortPortsByPriority(ports);

        // 进度追踪（Go: atomic int64）
        AtomicLong completed = new AtomicLong();
        AtomicLong openCount = new AtomicLong();
        AtomicLong closedCount = new AtomicLong();
        AtomicLong filteredCount = new AtomicLong();
        AtomicInteger currentPort = new AtomicInteger(-1);

        long startTime = System.nanoTime();

        // 启动进度显示线程（单行 \r 覆盖模式，避免刷屏）
        final boolean[] progressDone = {false};
        Thread progress = new Thread(() -> {
            int lastLineLen = 0;
            int lastShownPort = -1;
            while (true) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                synchronized (progressDone) {
                    if (progressDone[0]) {
                        return;
                    }
                }
                int p = currentPort.get();
                if (p <= 0 || p == lastShownPort) {
                    continue;
                }
                lastShownPort = p;
                String line = I18n.Tf("nmap.progress.port_scan", ip, p);
                int pad = lastLineLen - line.length();
                if (line.length() > lastLineLen) {
                    lastLineLen = line.length();
                    pad = 0;
                }
                synchronized (PROGRESS_MU) {
                    System.out.printf("\r%s%s", line, " ".repeat(Math.max(0, pad)));
                    System.out.flush();
                }
            }
        }, "jyscan-nmap-progress");
        progress.setDaemon(true);
        progress.start();

        // 结果收集（Go: sync.Map）
        Map<Integer, PortInfo> resultMap = new ConcurrentHashMap<>();

        // 阶段1: 首轮高速扫描
        runScanRound(ip, new ArrayList<>(sortedPorts), config.initialTimeout,
                config.concurrency, resultMap, completed, openCount, closedCount,
                filteredCount, currentPort);

        // 阶段2: 重试 filtered 端口
        if (config.maxRetries >= 1 && config.retryTimeout != null
                && !config.retryTimeout.isZero() && !config.retryTimeout.isNegative()) {
            List<Integer> remaining = getRemainingPorts(sortedPorts, resultMap);
            if (!remaining.isEmpty()) {
                runScanRound(ip, remaining, config.retryTimeout, config.concurrency, resultMap,
                        completed, openCount, closedCount, filteredCount, currentPort);
            }
        }

        // 阶段3: 最终确认剩余的 filtered 端口
        if (config.maxRetries >= 2 && config.finalTimeout != null
                && !config.finalTimeout.isZero() && !config.finalTimeout.isNegative()) {
            List<Integer> remaining = getRemainingPorts(sortedPorts, resultMap);
            if (!remaining.isEmpty()) {
                runScanRound(ip, remaining, config.finalTimeout, config.concurrency, resultMap,
                        completed, openCount, closedCount, filteredCount, currentPort);
            }
        }

        long elapsedNanos = System.nanoTime() - startTime;

        // 停止进度显示
        synchronized (progressDone) {
            progressDone[0] = true;
        }
        progress.interrupt();

        // 构建结果（Go 侧直接用 sync.Map Range 拷进新 map，此处 ConcurrentHashMap 即结果）
        Map<Integer, PortInfo> results = new ConcurrentHashMap<>(resultMap);

        // 阶段4: Banner 抓取 (仅对开放端口，延迟执行)
        if (config.grabBanner && config.skipBannerOnAll) {
            List<Integer> openPorts = getOpenPorts(results);
            if (!openPorts.isEmpty()) {
                grabBannersConcurrent(ip, openPorts, results, config.bannerTimeout,
                        config.concurrency);
            }
        }

        // 清除进度行，换行以准备后续输出
        synchronized (PROGRESS_MU) {
            if (config.enableVerbose) {
                System.out.printf("\r%-120s\r  %s%n", "",
                        I18n.Tf("nmap.log.port_verbose", ip, totalPorts,
                                openCount.get(), filteredCount.get(), closedCount.get(),
                                java.time.Duration.ofMillis(Math.round(elapsedNanos / 1_000_000.0)),
                                totalPorts / Math.max(1e-9, elapsedNanos / 1e9)));
            } else {
                System.out.printf("\r%-120s\r", "");
            }
            System.out.flush();
        }

        return results;
    }

    // =====================================================================
    // 扫描轮次执行 —— runScanRound / scanPortBatch
    // =====================================================================

    /**
     * 执行一轮扫描，对应 Go {@code runScanRound}（scan_optimized.go:309）。
     *
     * <p>Go 把端口切成 {@code min(concurrency, len(ports))} 份，每份交给一个 goroutine 顺序扫；
     * Java 等价地把端口切成同样份数，每份作为一个任务提交到 {@link ScanEngine#workerPool()}。
     */
    private static void runScanRound(String ip, List<Integer> ports, Duration timeout,
                                     int concurrency, Map<Integer, PortInfo> resultMap,
                                     AtomicLong completed, AtomicLong openCount,
                                     AtomicLong closedCount, AtomicLong filteredCount,
                                     AtomicInteger currentPort) {
        if (ports.isEmpty()) {
            return;
        }

        // 计算 worker 数量
        int workerCount = concurrency;
        if (workerCount > ports.size()) {
            workerCount = ports.size();
        }
        if (workerCount < 1) {
            workerCount = 1;
        }

        // 每个 worker 分配的端口数（Go: portsPerWorker = (n + workerCount - 1) / workerCount）
        int portsPerWorker = (ports.size() + workerCount - 1) / workerCount;

        ExecutorService pool = ScanEngine.workerPool();
        CountDownLatch done = new CountDownLatch(workerCount);

        for (int i = 0; i < workerCount; i++) {
            int start = i * portsPerWorker;
            int end = Math.min(start + portsPerWorker, ports.size());
            if (start >= end) {
                done.countDown();
                continue;
            }
            List<Integer> batch = ports.subList(start, end);
            try {
                pool.execute(() -> {
                    try {
                        scanPortBatch(ip, batch, timeout, resultMap, completed, openCount,
                                closedCount, filteredCount, currentPort);
                    } finally {
                        done.countDown();
                    }
                });
            } catch (java.util.concurrent.RejectedExecutionException e) {
                // 池已关闭（Ctrl-C / cancelScan）——等价 Go 的 ctx.Done() 提前返回
                done.countDown();
            }
        }

        try {
            done.await();
        } catch (InterruptedException e) {
            // Go: <-ctx.Done() -> return
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 扫描一批端口，对应 Go {@code scanPortBatch}（scan_optimized.go:354）。
     *
     * <p>Go 的 {@code select ctx.Done()} 由本方法的中断位与池的 {@code shutdownNow()} 承担。
     */
    private static void scanPortBatch(String ip, List<Integer> ports, Duration timeout,
                                      Map<Integer, PortInfo> resultMap, AtomicLong completed,
                                      AtomicLong openCount, AtomicLong closedCount,
                                      AtomicLong filteredCount, AtomicInteger currentPort) {
        for (int port : ports) {
            if (Thread.currentThread().isInterrupted()) {
                // Go: case <-ctx.Done(): return
                return;
            }

            // 记录当前正在探测的端口，供 \r 进度显示使用
            currentPort.set(port);

            String state = ultraFastTCPConnect(ip, port, timeout);

            PortInfo info = new PortInfo();
            info.port = port;
            info.protocol = "tcp";
            info.state = state;
            // Go: Service: servicePortMap[port] —— 不存在时为 Go 零值 ""
            String svc = OPTIMIZED_SERVICE_PORT_MAP.get(port);
            info.service = svc == null ? "" : svc;
            resultMap.put(port, info);

            if (NmapConstants.PORT_STATE_OPEN.equals(state)) {
                openCount.incrementAndGet();
            } else if (NmapConstants.PORT_STATE_FILTERED.equals(state)
                    || NmapConstants.PORT_STATE_OPEN_FILTERED.equals(state)) {
                filteredCount.incrementAndGet();
            } else {
                closedCount.incrementAndGet();
            }

            completed.incrementAndGet();
        }
    }

    // =====================================================================
    // 辅助函数
    // =====================================================================

    /**
     * 按优先级排序端口（常见端口优先），对应 Go {@code sortPortsByPriority}
     * （scan_optimized.go:398）。
     *
     * <p>排序规则与 Go {@code sort.SliceStable} 逐条对应：都在表中按下标升序；只有 i 在表中
     * 排前面；只有 j 在表中排后面；都不在表中按端口号升序。稳定性由
     * {@link java.util.List#sort} 的稳定排序保证。
     */
    public static List<Integer> sortPortsByPriority(List<Integer> ports) {
        List<Integer> result = new ArrayList<>(ports);
        result.sort((a, b) -> {
            Integer pa = PORT_PRIORITY_MAP.get(a);
            Integer pb = PORT_PRIORITY_MAP.get(b);
            if (pa != null && pb != null) {
                return Integer.compare(pa, pb);
            }
            if (pa != null) {
                return -1;
            }
            if (pb != null) {
                return 1;
            }
            return Integer.compare(a, b);
        });
        return result;
    }

    /**
     * 获取尚未确认的端口列表，对应 Go {@code getRemainingPorts}（scan_optimized.go:426）。
     *
     * <p>已存在且状态为 filtered/open|filtered 的要重扫；<b>完全没扫过的也要重扫</b>（Go 的
     * {@code else} 分支）。
     */
    public static List<Integer> getRemainingPorts(List<Integer> allPorts,
                                                  Map<Integer, PortInfo> resultMap) {
        List<Integer> remaining = new ArrayList<>(Math.max(16, allPorts.size() / 4));
        for (int port : allPorts) {
            PortInfo info = resultMap.get(port);
            if (info == null) {
                remaining.add(port);
            } else if (NmapConstants.PORT_STATE_FILTERED.equals(info.state)
                    || NmapConstants.PORT_STATE_OPEN_FILTERED.equals(info.state)) {
                remaining.add(port);
            }
        }
        return remaining;
    }

    /** 获取开放端口列表，对应 Go {@code getOpenPorts}（scan_optimized.go:442）。 */
    public static List<Integer> getOpenPorts(Map<Integer, PortInfo> results) {
        List<Integer> openPorts = new ArrayList<>();
        for (Map.Entry<Integer, PortInfo> e : results.entrySet()) {
            PortInfo info = e.getValue();
            if (info != null && (NmapConstants.PORT_STATE_OPEN.equals(info.state)
                    || NmapConstants.PORT_STATE_OPEN_FILTERED.equals(info.state))) {
                openPorts.add(e.getKey());
            }
        }
        return openPorts;
    }

    // =====================================================================
    // Banner 抓取
    // =====================================================================

    /**
     * 并发抓取 Banner，对应 Go {@code grabBannersConcurrent}（scan_optimized.go:453）。
     *
     * <p>Go 用带缓冲 channel 当信号量（{@code min(concurrency, len(ports))}）；
     * Java 用 {@code Semaphore} 复刻同样的并发上限。
     */
    private static void grabBannersConcurrent(String ip, List<Integer> ports,
                                              Map<Integer, PortInfo> results, Duration timeout,
                                              int concurrency) {
        int limit = Math.max(1, Math.min(concurrency, ports.size()));
        java.util.concurrent.Semaphore sem = new java.util.concurrent.Semaphore(limit);
        ExecutorService pool = ScanEngine.workerPool();
        CountDownLatch done = new CountDownLatch(ports.size());

        for (int p : ports) {
            try {
                sem.acquire();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            final int port = p;
            try {
                pool.execute(() -> {
                    try {
                        String banner = grabBannerFast(ip, port, timeout);
                        if (banner != null && !banner.isEmpty()) {
                            PortInfo info = results.get(port);
                            if (info != null) {
                                info.banner = banner;
                                info.service = ServiceIdentify.identifyService(port, banner);
                                results.put(port, info);
                            }
                        }
                    } finally {
                        sem.release();
                        done.countDown();
                    }
                });
            } catch (java.util.concurrent.RejectedExecutionException e) {
                sem.release();
                done.countDown();
            }
        }

        try {
            done.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 快速抓取 Banner，对应 Go {@code grabBannerFast}（scan_optimized.go:486）：
     * 连接成功后只读一次，读到内容就返回，否则返回空串。
     */
    private static String grabBannerFast(String ip, int port, Duration timeout) {
        Duration t = timeout == null ? Duration.ZERO : timeout;
        long millis = Math.max(1, t.toMillis());
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), (int) millis);
            socket.setSoTimeout((int) millis);
            java.io.InputStream in = socket.getInputStream();
            byte[] buf = new byte[4096];
            int n = in.read(buf);
            if (n > 0) {
                return new String(buf, 0, n, java.nio.charset.StandardCharsets.ISO_8859_1);
            }
            return "";
        } catch (Exception e) {
            return "";
        }
    }

    // =====================================================================
    // hostDiscoveryFast —— 快速主机发现（Go scan_optimized.go:812）
    // =====================================================================

    /**
     * 快速主机发现，对应 Go {@code hostDiscoveryFast}（scan_optimized.go:812）。
     *
     * <p>流程与 Go 一致：① 超时下限钳到 2s → ② ICMP ping → ③ 用 {@code ultraFastTCPConnect}
     * 并发探测 5 个常见端口，<b>open 或 closed 都算存活</b>（收到 RST 即证明主机在线），
     * 只有 filtered/超时才判定不存活。
     *
     * <p><b>有意偏差</b>：Go 第 ② 步的 {@code isAliveByICMPPing} 是调系统 {@code ping -c 1 -W}
     * 命令（scan_optimized.go:850），此处改用 {@link HostDiscovery#icmpPing}——它是 Go
     * {@code icmpPing}（scan.go）的移植、在无原始套接字权限时自动回落到 TCP 探测，避免再引一次
     * {@code exec}。第 ③ 步的 5 端口探测与 Go 逐字相同。
     */
    public static boolean hostDiscoveryFast(String ip, Duration timeout) {
        // 确保超时不会太短
        Duration t = timeout == null ? Duration.ZERO : timeout;
        if (t.compareTo(Duration.ofSeconds(2)) < 0) {
            t = Duration.ofSeconds(2);
        }

        // 优先使用 ICMP ping 检测主机是否存活
        if (HostDiscovery.icmpPing(ip, t)) {
            return true;
        }

        // 快速 TCP ping 常用端口
        // t 曾被重赋值（下限钳到 2s），lambda 要求事实上最终 → 先固化成副本
        final Duration probeTimeout = t;
        int[] commonPorts = {80, 443, 22, 53, 8080};
        String[] states = new String[commonPorts.length];
        CountDownLatch latch = new CountDownLatch(commonPorts.length);
        ExecutorService pool = ScanEngine.workerPool();

        for (int i = 0; i < commonPorts.length; i++) {
            final int idx = i;
            final int p = commonPorts[i];
            try {
                pool.execute(() -> {
                    try {
                        states[idx] = ultraFastTCPConnect(ip, p, probeTimeout);
                    } finally {
                        latch.countDown();
                    }
                });
            } catch (RuntimeException e) {
                states[idx] = NmapConstants.PORT_STATE_FILTERED;
                latch.countDown();
            }
        }

        // Go: 第一个返回 open/closed 即可提前判定存活；全部跑完仍无则 false
        boolean alive = false;
        try {
            // 等全部完成后再判定（Go 是 select 逐个收，此处等价：任一 open/closed 即 true）
            if (!latch.await(t.toMillis() + 500, TimeUnit.MILLISECONDS)) {
                // Go: case <-time.After(timeout): return false —— 有超时即可能 false
                for (String s : states) {
                    if (NmapConstants.PORT_STATE_OPEN.equals(s)
                            || NmapConstants.PORT_STATE_CLOSED.equals(s)) {
                        alive = true;
                        break;
                    }
                }
                return alive;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }

        for (String s : states) {
            // PortStateOpen: 端口开放, PortStateClosed: 收到RST(主机存活)
            // 只有 PortStateFiltered (超时/不可达) 才说明主机可能不存活
            if (NmapConstants.PORT_STATE_OPEN.equals(s)
                    || NmapConstants.PORT_STATE_CLOSED.equals(s)) {
                return true;
            }
        }
        return false;
    }
}

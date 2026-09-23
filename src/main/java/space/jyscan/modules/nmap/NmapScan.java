package space.jyscan.modules.nmap;

import space.jyscan.core.i18n.I18n;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 扫描引擎主入口，移植自 freeclient/internal/nmap/scan.go（NmapScan）与
 * scan_optimized.go（NmapScanOptimized）。
 *
 * <p><b>归属</b>：原 B 号子代理建了壳就停在两个桩上（全树因此编译失败），由集成者接管补齐。
 * 对应源文件 {@code scan.go}(3088) + {@code scan_optimized.go}(961) +
 * {@code scan_optimized_linux.go}(212) + {@code scan_optimized_windows.go}(36)。
 *
 * <p>其余模块只依赖下面两个签名，请勿改动签名，否则 A 号（ScanCommand）编译不过。
 * 实现上的辅助函数、常量、内部类型（{@code UltraFastScanConfig}、{@code ScanResultCache}
 * 等）放在自己的文件里即可。
 *
 * <h2>Go 的调用链</h2>
 * <pre>
 * cmd.go:301/362  →  NmapScan(ctx, config)                    scan.go:338
 *                      ├─ applyTimingTemplate(&amp;config)        scan.go:311
 *                      └─ return NmapScanOptimized(ctx, config) scan.go:342
 *                           └─ applyTimingTemplate(&amp;config)    scan_optimized.go:587  ← 调两次
 * </pre>
 *
 * <h2>有意偏差</h2>
 * <ol>
 *   <li><b>{@code context.Context} 不移植</b>：Go 每个 host 迭代前
 *       {@code select { case <-ctx.Done(): ... default: }}；Java 用
 *       {@link ScanEngine#interrupted}（volatile 标志，对应 Go 的 ctx）+ 线程中断位承担，
 *       取消动作来自 {@link ScanEngine#cancelScan()}。</li>
 *   <li><b>值语义靠 {@link ScanConfig#copy()}</b>：Go 的 {@code NmapScan(ctx, config ScanConfig)}
 *       按值接收，{@code applyTimingTemplate} 改的是副本，调用方 {@code ScanCommand} 的 config
 *       不受影响；Java 按引用传参，故入口处先 {@code copy()} 复刻该语义。</li>
 *   <li><b>host 池</b>：Go 为每个 host 起一个 goroutine（无上限）；Java 提交到
 *       {@link ScanEngine#hostPool()}（未 {@code beginScan} 时退回共享 512 线程池），
 *       并发度仍由 Go 同款的 {@code semaphore(config.Threads)} 控制，
 *       只影响极限并发、不影响结果与输出。</li>
 * </ol>
 */
public final class NmapScan {

    private NmapScan() {
    }

    /**
     * 扫描主入口：应用 -T 速度模板后走超高速引擎。
     *
     * <p>Go 原文（scan.go:338）：
     * <pre>
     * func NmapScan(ctx context.Context, config ScanConfig) []NmapResult {
     *     applyTimingTemplate(&amp;config)
     *     // 所有模式都使用超高速扫描引擎
     *     return NmapScanOptimized(ctx, config)
     * }
     * </pre>
     *
     * <p>Go 的 {@code context.Context} 本项目不移植（由 {@link ScanEngine#interrupted} /
     * {@code ExecutorService.shutdownNow()} 承担取消），故签名不含 ctx。
     *
     * @param config 扫描配置
     * @return 结果列表，永不为 null（Go 的 nil slice 在 Java 侧用空 List 表达）
     */
    public static List<NmapResult> nmapScan(ScanConfig config) {
        // Go 按值接收 config → 此处 copy() 复刻值语义，调用方的 config 不被 -T 覆盖。
        ScanConfig cfg = config.copy();
        applyTimingTemplate(cfg);
        return nmapScanOptimized(cfg);
    }

    /**
     * 按 -T 模板覆盖线程数与超时。
     *
     * <p>对应 Go 的 {@code applyTimingTemplate(config *ScanConfig)}（scan.go:311）。
     * 模板值与常量见 {@link NmapConstants} 的 {@code TIMING_*} / {@code *_THREADS} /
     * {@code *_TIMEOUT}。
     *
     * <p><b>注意</b>：本方法是<b>无条件覆盖</b> {@code threads}/{@code timeout} 的——
     * 这正是 Go 的行为：{@code cmd.go:232} 先把 {@code --threads}/{@code --timeout} 写进
     * config，随后 {@code NmapScan} 里的本方法再按 {@code -T} 覆盖掉。两个 flag 只在
     * 「-T 未改变默认值」时等价起作用，移植时不引入额外的合并逻辑。
     *
     * <p>Go 模板与 -A 联动（cmd.go:274/347 的 {@code if TimingTemplate < 4 → 4}）
     * 已在 {@code ScanCommand.applyAggressiveMode} 中复刻，不在本方法内。
     */
    public static void applyTimingTemplate(ScanConfig config) {
        // Go: 默认使用级别3 (Normal)
        if (config.timingTemplate < NmapConstants.TIMING_PARANOID
                || config.timingTemplate > NmapConstants.TIMING_INSANE) {
            config.timingTemplate = NmapConstants.TIMING_NORMAL;
        }

        // 根据 nmap -T 参数标准设置（Go scan.go:319-336 的 switch）
        switch (config.timingTemplate) {
            case NmapConstants.TIMING_PARANOID -> {
                config.threads = NmapConstants.PARANOID_THREADS;
                config.timeout = NmapConstants.LONG_TIMEOUT;
            }
            case NmapConstants.TIMING_SNEAKY -> {
                // Go 复用 ParanoidThreads（无独立的 Sneaky 线程数）
                config.threads = NmapConstants.PARANOID_THREADS;
                config.timeout = NmapConstants.SLOW_TIMEOUT;
            }
            case NmapConstants.TIMING_POLITE -> {
                config.threads = NmapConstants.POLITE_THREADS;
                config.timeout = NmapConstants.MEDIUM_TIMEOUT;
            }
            case NmapConstants.TIMING_NORMAL -> {
                config.threads = NmapConstants.DEFAULT_THREADS;
                config.timeout = NmapConstants.DEFAULT_TIMEOUT;
            }
            case NmapConstants.TIMING_AGGRESSIVE -> {
                config.threads = NmapConstants.AGGRESSIVE_THREADS;
                config.timeout = NmapConstants.FAST_TIMEOUT;
            }
            case NmapConstants.TIMING_INSANE -> {
                config.threads = NmapConstants.INSANE_THREADS;
                config.timeout = NmapConstants.INSANE_TIMEOUT;
            }
            default -> {
                // Go 的 switch 无 default 分支；上面的 clamp 已保证不会走到这里
            }
        }
    }

    // =========================================================================
    // scan_optimized.go:586 NmapScanOptimized —— 真正的扫描编排
    // =========================================================================

    /**
     * 对应 Go 的 {@code NmapScanOptimized(ctx, config ScanConfig)}（scan_optimized.go:586）。
     *
     * <p>流程：-A 端口默认 → -sn 分支 → 解析目标与端口 → 打印超高速横幅 →
     * 取超高速配置 → 信号量限制 host 并发 → 逐 host（缓存 / 存活探测 / 端口扫描 /
     * 服务识别 / OS 识别 / 内容探测 / TTL 检测）→ 汇总。
     *
     * <p>与 Go 一样本方法也再调一次 {@code applyTimingTemplate}（Go 在 scan_optimized.go:587
     * 同样调用，两次作用于同一个本地副本，结果幂等）。
     */
    private static List<NmapResult> nmapScanOptimized(ScanConfig config) {
        applyTimingTemplate(config);

        if (config.aggressiveScan && (config.ports == null || config.ports.isEmpty())) {
            config.ports = "1-10000";
        }

        // Go: -sn 主机存活探测模式
        if (config.hostDiscovery) {
            System.out.println(I18n.Tf("nmap.log.host_discovery_mode",
                    config.target, config.threads, config.timingTemplate));
            return ScanEngine.hostDiscoveryScan(config);
        }

        // Go: if config.Pn { /* 静默模式 */ } —— 空分支，无行为，不移植

        List<String> hosts = ScanParse.parseTargetWithFamily(config.target, config.ipv6);
        List<Integer> portList = ScanParse.parsePortsOptimized(config.ports);

        // Go: var results []NmapResult（nil slice）；Java 用空 List，永不为 null
        List<NmapResult> results = Collections.synchronizedList(new ArrayList<>());

        // 默认仅扫描 IPv4；若未启用 IPv6 且解析后无主机，则提示并直接返回
        if (!config.ipv6 && hosts.isEmpty()) {
            System.out.println(I18n.T("nmap.err.no_ipv4_host"));
            return results;
        }

        System.out.println(I18n.Tf("nmap.log.ultra_scan", config.target,
                hosts.size(), portList.size(), config.threads,
                protocolFamilyLabel(config.ipv6)));

        // 根据速度模板选择超高速配置
        UltraFastScanConfig ultraConfig = UltraFastScanConfig.forTiming(config.timingTemplate);

        final Object mu = new Object();
        final AtomicInteger completed = new AtomicInteger(0);
        final int totalHosts = hosts.size();

        // Go: semaphore := make(chan struct{}, config.Threads)
        Semaphore semaphore = new Semaphore(Math.max(1, config.threads));
        // Go: NewScanResultCache(5 * time.Minute)
        ScanResultCache cache = ScanResultCache.newCache(Duration.ofMinutes(5));

        ExecutorService pool = ScanEngine.hostPool();
        // Go: var wg sync.WaitGroup —— 只对已启动的 goroutine 计数
        CountDownLatch wg = new CountDownLatch(totalHosts);
        int launched = 0;

        for (int i = 0; i < totalHosts; i++) {
            // Go: select { case <-ctx.Done(): return results; default: }
            if (ScanEngine.interrupted || Thread.currentThread().isInterrupted()) {
                // Go 提前 return 时未 wg.Add 的项不存在；Java 侧要把没启动的名额全数放下，
                // 否则 wg.await() 永远等不完。
                for (int j = launched; j < totalHosts; j++) {
                    wg.countDown();
                }
                break;
            }

            // Go 的信号量在 goroutine 内 acquire；Java 改为提交前 acquire —— 语义等价
            // （在途任务数都不超过 config.Threads），且避免池线程空等信号量。
            try {
                semaphore.acquire();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                for (int j = launched; j < totalHosts; j++) {
                    wg.countDown();
                }
                break;
            }

            final String ip = hosts.get(i);
            launched++;
            try {
                pool.execute(() -> {
                    try {
                        scanOneHost(ip, config, portList, ultraConfig, cache,
                                results, completed, totalHosts, mu);
                    } finally {
                        semaphore.release();
                        wg.countDown();
                    }
                });
            } catch (RejectedExecutionException e) {
                // 池已关闭（Ctrl-C / cancelScan）——等价 Go 的 ctx.Done()
                semaphore.release();
                wg.countDown();
            }
        }

        // Go: wg.Wait()
        try {
            wg.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return results;
    }

    // =========================================================================
    // 单 host 扫描 —— Go NmapScanOptimized 内的匿名 goroutine 体
    // =========================================================================

    /**
     * 对应 Go {@code NmapScanOptimized} 中
     * {@code go func(ip string) {...}(host)} 的整个函数体（scan_optimized.go:632-733）。
     *
     * <p>信号量的 acquire/release 与 wg 计数由调用方负责（Go 用 {@code defer}）。
     */
    private static void scanOneHost(String ip, ScanConfig config, List<Integer> portList,
                                    UltraFastScanConfig ultraConfig, ScanResultCache cache,
                                    List<NmapResult> results, AtomicInteger completed,
                                    int totalHosts, Object mu) {
        // Go: if cached, ok := cache.Get(ip); ok { ...; return }
        NmapResult cached = cache.get(ip);
        if (cached != null) {
            results.add(cached);
            System.out.println(I18n.Tf("nmap.log.cache_hit",
                    ip, completed.incrementAndGet(), totalHosts));
            return;
        }

        System.out.println(I18n.Tf("nmap.log.scanning", ip));

        // Go: nonConnectScan := config.ScanType != "" && config.ScanType != "connect"
        boolean nonConnectScan = config.scanType != null && !config.scanType.isEmpty()
                && !"connect".equals(config.scanType);

        boolean isAlive = true;
        if (!config.pn && !nonConnectScan) {
            isAlive = UltraFastScan.hostDiscoveryFast(ip, config.timeout);
        }

        NmapResult result = new NmapResult();
        result.ip = ip;
        // Go: Ports: make(map[int]PortInfo) —— Java 字段初值 ports() 即带字符串序的空表
        result.status = "down";

        if (!isAlive) {
            results.add(result);
            System.out.println(I18n.Tf("nmap.log.offline",
                    ip, completed.incrementAndGet(), totalHosts));
            return;
        }

        result.status = "up";

        // 指定非默认扫描类型时必须走标准路径：UltraFastScan 仅支持 TCP connect 扫描
        Map<Integer, PortInfo> portResults;
        if (nonConnectScan) {
            portResults = ScanEngine.portScanWithProgress(ip, portList, config, null, mu);
        } else {
            ultraConfig.ip = ip;
            ultraConfig.grabBanner = config.serviceDetection;
            ultraConfig.skipBannerOnAll = true;
            ultraConfig.enableVerbose = false;

            portResults = UltraFastScan.ultraFastScan(ip, portList, ultraConfig);
            if (portResults == null) {
                // Go: fmt.Errorf("没有端口需要扫描") —— 文本与 Go 逐字相同
                System.out.println(I18n.Tf("nmap.err.ultra_scan_failed", "没有端口需要扫描"));
                portResults = ScanEngine.portScanWithProgress(ip, portList, config, null, mu);
            }
        }
        result.ports = portResults;

        // 服务识别 (-sV)
        if (config.serviceDetection && !portResults.isEmpty()
                && !UltraFastScan.getOpenPorts(portResults).isEmpty()) {
            clearLine("nmap.progress.service_detect", ip, "          ");
            result.services = serviceDetectionOptimized(ip, portResults, config.timeout);
        }

        // 操作系统识别 (-O)
        if (config.osDetection && !portResults.isEmpty()) {
            clearLine("nmap.progress.os_detect", ip, "     ");
            // Go scan_optimized.go:705: result.OS = osDetection(ip, portResults) ——
            // 五路加权投票（TCP栈指纹/banner/主动探测/TTL/服务组合），见 OsEngine
            result.os = OsEngine.osDetection(ip, portResults);
        }

        // 内容探测 (-X): 对已开放的端口做内容探测，获取端口回复的内容
        if (config.contentProbe && !portResults.isEmpty()) {
            clearLine("nmap.progress.content_probe", ip, "         ");
            ContentProbe.contentProbeHost(ip, portResults,
                    config.contentProbeTimeout, config.contentProbeConcurrency);
        }

        // TTL 检测: 通过分析响应 TTL 值估算目标网络距离
        if (config.ttlDetection) {
            clearLine("nmap.progress.ttl_detect", ip, "          ");
            result.networkDistance = ScanEngine.detectTTL(ip, config.timeout);
        }

        cache.set(ip, result);
        results.add(result);
        System.out.println(I18n.Tf("nmap.log.complete",
                ip, completed.incrementAndGet(), totalHosts));
    }

    // =========================================================================
    // scan_optimized.go 的局部辅助函数
    // =========================================================================

    /**
     * 对应 Go 的 {@code serviceDetectionOptimized(ip, ports, timeout)}（scan_optimized.go:900）。
     *
     * <p><b>与 {@link ScanEngine#serviceDetection} 不同</b>：后者是 {@code scan.go:1173} 的
     * {@code serviceDetection}，产出 {@code service/port} 且不过滤状态、不去重；本方法只取
     * {@code open}/{@code open|filtered} 端口、空服务名回落到
     * {@link ServiceIdentify#identifyServiceByProtocol}、<b>按服务名去重</b>，产出纯服务名列表。
     *
     * <p>入参 {@code ip}/{@code timeout} 在 Go 实现里同样未被使用（Go 签名即如此），保留以对齐。
     */
    static List<String> serviceDetectionOptimized(String ip, Map<Integer, PortInfo> ports,
                                                   Duration timeout) {
        List<String> services = new ArrayList<>();
        // Go: seen := make(map[string]bool)
        Set<String> seen = new LinkedHashSet<>();

        for (PortInfo info : ports.values()) {
            if (info == null) {
                continue;
            }
            if (!NmapConstants.PORT_STATE_OPEN.equals(info.state)
                    && !NmapConstants.PORT_STATE_OPEN_FILTERED.equals(info.state)) {
                continue;
            }

            String service = info.service;
            if (service == null || service.isEmpty()) {
                service = ServiceIdentify.identifyServiceByProtocol(info.port);
            }

            // Go: if service != "" && !seen[service] { services = append(...); seen[service] = true }
            if (service != null && !service.isEmpty() && seen.add(service)) {
                services.add(service);
            }
        }

        return services;
    }

    /** 对应 Go 的 {@code protocolFamilyLabel(ipv6Enabled)}（scan_optimized.go:511）。 */
    static String protocolFamilyLabel(boolean ipv6Enabled) {
        return ipv6Enabled ? "IPv4+IPv6" : "IPv4";
    }

    /**
     * 打印一行 {@code \r 进度文本 + 填充 + \r}，对应 Go 的
     * {@code fmt.Fprintf(os.Stdout, "\r"+i18n.Tf(key, ip)+"          \r")} + {@code os.Stdout.Sync()}。
     *
     * <p>Java 侧的 {@code System.out.flush()} 是 {@code Sync()} 的等价物；
     * {@code pad} 的空格数与 Go 各调用点逐字相同。
     */
    private static void clearLine(String key, String ip, String pad) {
        System.out.printf("\r%s%s\r", I18n.Tf(key, ip), pad);
        System.out.flush();
    }
}

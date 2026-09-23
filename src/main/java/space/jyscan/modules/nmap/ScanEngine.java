package space.jyscan.modules.nmap;

import space.jyscan.core.i18n.I18n;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadFactory;
import java.util.regex.Pattern;

/**
 * 扫描原语与主机发现扫描，移植自 freeclient/internal/nmap/scan.go 的：
 * {@code portScanWithProgress}(801) / {@code connectScan}(879) / {@code synScan}(917) /
 * {@code udpScan}(924) / {@code detectUDPPortState}(943) / 六个隐蔽扫描转发(973-1000) /
 * {@code connCloseWithoutError}(1003) / {@code getUDPBanner}(1010) /
 * {@code getUDPProbeData}(1039) / {@code tcpConnect}(1089) /
 * {@code tcpConnectFragmented}(1108) / {@code udpConnect}(1126) /
 * {@code getBanner}(1156) / {@code serviceDetection}(1173) /
 * {@code smartLivingDetection}(346) / {@code formatIPForConnection}(793) /
 * {@code getMACAddress}(1980) / {@code isValidMAC}(2015) / {@code getVendorByMAC}(2021) /
 * {@code traceroute}(2079) / {@code performTraceroute}(2138) /
 * {@code isSameSubnet}(2611) / {@code detectTTL}(2661) / {@code getTTLDistance}(2676) /
 * {@code estimateDistanceByIP}(2702) / {@code isLocalNetwork}(2731) /
 * {@code isPrivateNetwork}(2737) / {@code isPublicNetwork}(2761) /
 * {@code estimateGeographicDistance}(2766) / {@code serviceFingerprintDetection}(2789) 及
 * {@code generate*Fingerprint}(2814-2957) / {@code hostDiscoveryScan}(3013)。
 *
 * <p><b>归属</b>：本文件由 B 号子代理新建。
 *
 * <h2>并发与取消</h2>
 * <ul>
 *   <li>取消标志 {@link #interrupted}：对应 Go 的 {@code ctx}。每次扫描开始
 *       （{@link #beginScan}）复位，{@link #cancelScan}（JVM shutdown hook / 调用方）置位；</li>
 *   <li>{@link #hostPool}：每次扫描新建的固定线程池
 *       （{@code min(max(threads,1),128)}），对应 Go 「每个 host 一个 goroutine +
 *       容量为 threads 的 semaphore」；</li>
 *   <li>{@link #workerPool}：静态共享 512 线程池，跑端口批/banner 抓取
 *       （Go 是 goroutine 无限开，Java 侧封顶 —— 只影响极限并发度，不影响输出内容）。</li>
 * </ul>
 */
public final class ScanEngine {

    /** 对应 Go 的 ctx 取消：置位后所有扫描循环提前返回。 */
    public static volatile boolean interrupted;

    /** 每次扫描新建的 host 线程池（Go: 每 host 一个 goroutine）。 */
    private static volatile ExecutorService hostPool;

    /**
     * 端口扫描/banner 的共享池。Go 侧 goroutine 无上限（配合 semaphore=threads），
     * Java 封顶 512 —— 当 {@code threads > 512} 时实际并发为 512（时序差异，输出不变）。
     */
    private static final ExecutorService workerPool = Executors.newFixedThreadPool(512, daemon("jyscan-nmap-worker-"));

    /** 对应 scan.go:73 的 {@code macAddressRegex}。 */
    private static final Pattern MAC_ADDRESS_REGEX =
            Pattern.compile("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");

    /** 对应 scan.go:2026 的 {@code vendorMap}（Go 每次调用重建，这里提为常量）。 */
    private static final Map<String, String> MAC_VENDOR_MAP = buildVendorMap();

    private ScanEngine() {
    }

    private static ThreadFactory daemon(String prefix) {
        AtomicInteger seq = new AtomicInteger(1);
        return r -> {
            Thread t = new Thread(r, prefix + "-" + seq.getAndIncrement());
            t.setDaemon(true);
            return t;
        };
    }

    // =========================================================================
    // 取消 / 池管理（对应 Go 的 context 与 goroutine 生命周期）
    // =========================================================================

    /** 扫描开始：复位取消标志并创建本次扫描的 host 池（对应 Go 的 ctx 新建）。 */
    public static ExecutorService beginScan(int threads) {
        interrupted = false;
        int size = Math.min(Math.max(threads, 1), 128);
        ExecutorService pool = Executors.newFixedThreadPool(size, daemon("jyscan-nmap-host"));
        hostPool = pool;
        return pool;
    }

    /** 取消本次扫描（shutdown hook / 调用方）：置位并中断 host 池。 */
    public static void cancelScan() {
        interrupted = true;
        ExecutorService pool = hostPool;
        if (pool != null) {
            pool.shutdownNow();
        }
    }

    /** 扫描结束：回收 host 池（不复位 interrupted，便于调用方判断是否被取消）。 */
    public static void endScan() {
        ExecutorService pool = hostPool;
        hostPool = null;
        if (pool != null) {
            pool.shutdownNow();
            try {
                pool.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** 本次扫描的 host 池（未 beginScan 时退回共享 worker 池）。 */
    static ExecutorService hostPool() {
        ExecutorService pool = hostPool;
        return pool != null ? pool : workerPool;
    }

    /** 共享端口/banner 池。 */
    static ExecutorService workerPool() {
        return workerPool;
    }

    // =========================================================================
    // 字节 → 字符串（与 Go string([]byte) + json.Marshal 的 U+FFFD 规则对齐）
    // =========================================================================

    /**
     * Go 直接把读到的字节当 string；JSON 序列化时非法 UTF-8 会变成 U+FFFD。
     * Java 用 UTF-8 + REPLACE 解码，两条路径都与 Go 一致。
     */
    static String decodeBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        try {
            return decoder.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    // =========================================================================
    // scan.go:801 portScanWithProgress —— 带并发限制的端口扫描
    // =========================================================================

    /**
     * 对应 Go 的 {@code portScanWithProgress(ctx, ip, ports, config, openPortsCount, muGlobal)}
     * （scan.go:801）。函数名里的 progress 在 Go 中也<b>没有实际打印</b>（三个计数器只自增），
     * 这里保持一致。
     *
     * <p>扫描方式分派（逐字对齐 Go）：{@code tcpScan} → connect；{@code udpScan} → udp；
     * 否则按 {@code scanType} switch（syn/udp/fin/xmas/null/ack/window/maimon，default→connect）。
     *
     * <p>只把 {@code open} 与 {@code filtered/open|filtered} 的端口放进结果（Go 同）。
     *
     * <p>并发：每个端口一个任务 + {@code Semaphore(config.threads)}（Go: goroutine + 有界 chan）。
     * 返回的是<b>字符串序 TreeMap</b>（等价 Go map，序列化顺序由 NmapResult 统一收敛）。
     *
     * @param openPortsCount 全局 open 计数（可为 null，对应 Go 的 nil 指针）
     * @param muGlobal       全局计数锁（可为 null；非空才自增，与 Go 判断一致）
     */
    public static Map<Integer, PortInfo> portScanWithProgress(String ip, List<Integer> ports,
                                                              ScanConfig config, AtomicInteger openPortsCount,
                                                              Object muGlobal) {
        Map<Integer, PortInfo> results = new java.util.concurrent.ConcurrentHashMap<>();
        Object mu = new Object();

        // Go 侧另有 completedPorts/openPorts/filteredPorts 三个计数器（scan.go:806-808），
        // 全程只自增、从不打印也不外传，故此处不再保留无副作用的计数。

        // Go: semaphore := make(chan struct{}, config.Threads)
        Semaphore semaphore = new Semaphore(Math.max(1, config.threads));
        CountDownLatch latch = new CountDownLatch(ports.size());

        for (int port : ports) {
            final int p = port;
            workerPool.submit(() -> {
                try {
                    semaphore.acquire();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    latch.countDown();
                    return;
                }
                try {
                    if (interrupted) {
                        return;
                    }
                    PortInfo portInfo = scanOnePort(ip, p, config);

                    synchronized (mu) {
                        // Go 的三个计数器（completedPorts/openPorts/filteredPorts）同样只自增、不打印
                        switch (portInfo.state) {
                            case NmapConstants.PORT_STATE_OPEN:
                                results.put(p, portInfo);
                                if (muGlobal != null && openPortsCount != null) {
                                    synchronized (muGlobal) {
                                        openPortsCount.incrementAndGet();
                                    }
                                }
                                break;
                            case NmapConstants.PORT_STATE_FILTERED:
                            case NmapConstants.PORT_STATE_OPEN_FILTERED:
                                results.put(p, portInfo);
                                break;
                            default:
                                break;
                        }
                    }
                } finally {
                    semaphore.release();
                    latch.countDown();
                }
            });
        }

        awaitQuietly(latch);
        return orderedCopy(results);
    }

    /** 单端口扫描分派（Go: portScanWithProgress 内的 if/switch）。 */
    private static PortInfo scanOnePort(String ip, int p, ScanConfig config) {
        PortInfo portInfo;
        if (config.tcpScan) {
            portInfo = connectScan(ip, p, config.timeout, config.fragmentedScan);
        } else if (config.udpScan) {
            portInfo = udpScan(ip, p, config.timeout);
        } else {
            String scanType = config.scanType == null ? "" : config.scanType;
            switch (scanType) {
                case "syn":
                    portInfo = synScan(ip, p, config.timeout, config.fragmentedScan);
                    break;
                case "udp":
                    portInfo = udpScan(ip, p, config.timeout);
                    break;
                case "fin":
                    portInfo = plainPort(p, "tcp", finScan(ip, p, config.timeout));
                    break;
                case "xmas":
                    portInfo = plainPort(p, "tcp", xmasScan(ip, p, config.timeout));
                    break;
                case "null":
                    portInfo = plainPort(p, "tcp", nullScan(ip, p, config.timeout));
                    break;
                case "ack":
                    portInfo = plainPort(p, "tcp", ackScan(ip, p, config.timeout));
                    break;
                case "window":
                    portInfo = plainPort(p, "tcp", windowScan(ip, p, config.timeout));
                    break;
                case "maimon":
                    portInfo = plainPort(p, "tcp", maimonScan(ip, p, config.timeout));
                    break;
                default:
                    portInfo = connectScan(ip, p, config.timeout, config.fragmentedScan);
                    break;
            }
        }
        return portInfo;
    }

    /** Go: {@code PortInfo{Port: p, Protocol: "tcp", State: state}}。 */
    private static PortInfo plainPort(int p, String protocol, String state) {
        PortInfo info = new PortInfo();
        info.port = p;
        info.protocol = protocol;
        info.state = state;
        return info;
    }

    /** latch 等待：被取消时也返回（Go 的 wg.Wait 依赖 goroutine 自行退出）。 */
    private static void awaitQuietly(CountDownLatch latch) {
        try {
            while (!latch.await(200, TimeUnit.MILLISECONDS)) {
                if (interrupted) {
                    return;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** 并发收集 → 字符串序 TreeMap（对应 Go map + encoding/json 的键排序）。 */
    static Map<Integer, PortInfo> orderedCopy(Map<Integer, PortInfo> src) {
        Map<Integer, PortInfo> out = NmapResult.ports();
        out.putAll(src);
        return out;
    }

    // =========================================================================
    // scan.go:879-1000 —— 各扫描类型
    // =========================================================================

    /**
     * 对应 Go 的 {@code connectScan}（scan.go:879）。
     *
     * <p>快速通道条件与 Go 完全一致：{@code timeout <= 100ms && !fragmented}
     * 时走 {@link UltraFastScan#ultraFastTCPConnect}，并先套
     * {@link UltraFastScan#OPTIMIZED_SERVICE_PORT_MAP} 的服务名（Go: {@code servicePortMap}）；
     * 否则走 {@code tcpConnect} / {@code tcpConnectFragmented}，开放时抓 banner 并按 banner 重识别服务。
     */
    public static PortInfo connectScan(String ip, int port, Duration timeout, boolean fragmented) {
        PortInfo info = new PortInfo();
        info.port = port;
        info.protocol = "tcp";
        info.state = NmapConstants.PORT_STATE_CLOSED;

        // 使用超高速非阻塞连接检测
        if (!timeout.isNegative() && timeout.compareTo(Duration.ofMillis(100)) <= 0 && !fragmented) {
            String state = UltraFastScan.ultraFastTCPConnect(ip, port, timeout);
            info.state = state;
            String svc = UltraFastScan.OPTIMIZED_SERVICE_PORT_MAP.get(port);
            info.service = svc == null ? "" : svc;
            if (NmapConstants.PORT_STATE_OPEN.equals(state)) {
                info.banner = getBanner(ip, port, timeout);
                if (!info.banner.isEmpty()) {
                    info.service = ServiceIdentify.identifyService(port, info.banner);
                }
            }
            return info;
        }

        boolean isOpen;
        if (fragmented) {
            isOpen = tcpConnectFragmented(ip, port, timeout);
        } else {
            isOpen = tcpConnect(ip, port, timeout);
        }

        if (isOpen) {
            info.state = NmapConstants.PORT_STATE_OPEN;
            info.banner = getBanner(ip, port, timeout);
            info.service = ServiceIdentify.identifyService(port, info.banner);
        }
        return info;
    }

    /** 对应 Go 的 {@code synScan}（scan.go:917）：TODO 原始套接字，暂用 connect。 */
    public static PortInfo synScan(String ip, int port, Duration timeout, boolean fragmented) {
        return connectScan(ip, port, timeout, fragmented);
    }

    /** 对应 Go 的 {@code udpScan}（scan.go:924）。 */
    public static PortInfo udpScan(String ip, int port, Duration timeout) {
        PortInfo info = new PortInfo();
        info.port = port;
        info.protocol = "udp";
        info.state = NmapConstants.PORT_STATE_CLOSED;

        String state = detectUDPPortState(ip, port, timeout);
        info.state = state;

        if (NmapConstants.PORT_STATE_OPEN.equals(state)) {
            String banner = getUDPBanner(ip, port, timeout);
            info.service = ServiceIdentify.identifyUDPService(port, banner);
        }
        return info;
    }

    /**
     * 对应 Go 的 {@code detectUDPPortState}（scan.go:943）：
     * dial → 写探测包 → 读响应。超时 → {@code open|filtered}；读到数据 → {@code open}；
     * 其他错误 → {@code closed}。
     */
    public static String detectUDPPortState(String ip, int port, Duration timeout) {
        try (DatagramSocket sock = new DatagramSocket()) {
            int ms = toMillis(timeout);
            sock.connect(new InetSocketAddress(ip, port));
            sock.setSoTimeout(Math.max(ms, 0));

            byte[] testData = "JYscan-UDP-Probe".getBytes(StandardCharsets.US_ASCII);
            sock.send(new java.net.DatagramPacket(testData, testData.length));
            // 上面的 connect 已隐式设好远端；Go 另外设了 write deadline，UDP 写不阻塞

            byte[] buf = new byte[1024];
            java.net.DatagramPacket pkt = new java.net.DatagramPacket(buf, buf.length);
            try {
                sock.receive(pkt);
                if (pkt.getLength() > 0) {
                    return NmapConstants.PORT_STATE_OPEN;
                }
                return NmapConstants.PORT_STATE_OPEN_FILTERED;
            } catch (SocketTimeoutException e) {
                return NmapConstants.PORT_STATE_OPEN_FILTERED;
            }
        } catch (IOException e) {
            return NmapConstants.PORT_STATE_CLOSED;
        }
    }

    /** 对应 Go 的 {@code finScan}（scan.go:973）→ {@code rawFINScan}。 */
    public static String finScan(String ip, int port, Duration timeout) {
        return RawScan.rawFINScan(ip, port, timeout);
    }

    /** 对应 Go 的 {@code xmasScan}（scan.go:978）。 */
    public static String xmasScan(String ip, int port, Duration timeout) {
        return RawScan.rawXMASScan(ip, port, timeout);
    }

    /** 对应 Go 的 {@code nullScan}（scan.go:983）。 */
    public static String nullScan(String ip, int port, Duration timeout) {
        return RawScan.rawNULLScan(ip, port, timeout);
    }

    /** 对应 Go 的 {@code ackScan}（scan.go:988）。 */
    public static String ackScan(String ip, int port, Duration timeout) {
        return RawScan.rawACKScan(ip, port, timeout);
    }

    /** 对应 Go 的 {@code maimonScan}（scan.go:993）。 */
    public static String maimonScan(String ip, int port, Duration timeout) {
        return RawScan.rawMaimonScan(ip, port, timeout);
    }

    /** 对应 Go 的 {@code windowScan}（scan.go:998）。 */
    public static String windowScan(String ip, int port, Duration timeout) {
        return RawScan.rawWindowScan(ip, port, timeout);
    }

    /** 对应 Go 的 {@code connCloseWithoutError}（scan.go:1003）：Close 错误丢弃。 */
    static void connCloseWithoutError(AutoCloseable conn) {
        if (conn != null) {
            try {
                conn.close();
            } catch (Exception ignored) {
                // Go: _ = conn.Close()
            }
        }
    }

    // =========================================================================
    // scan.go:1010-1170 —— UDP banner / 探测包 / 连接 / banner
    // =========================================================================

    /** 对应 Go 的 {@code getUDPBanner}（scan.go:1010）。 */
    public static String getUDPBanner(String ip, int port, Duration timeout) {
        try (DatagramSocket sock = new DatagramSocket()) {
            int ms = toMillis(timeout);
            sock.connect(new InetSocketAddress(ip, port));
            sock.setSoTimeout(Math.max(ms, 0));

            byte[] probeData = getUDPProbeData(port);
            if (probeData.length > 0) {
                sock.send(new java.net.DatagramPacket(probeData, probeData.length));
                byte[] buf = new byte[1024];
                java.net.DatagramPacket pkt = new java.net.DatagramPacket(buf, buf.length);
                try {
                    sock.receive(pkt);
                    if (pkt.getLength() > 0) {
                        byte[] n = new byte[pkt.getLength()];
                        System.arraycopy(pkt.getData(), pkt.getOffset(), n, 0, pkt.getLength());
                        return decodeBytes(n);
                    }
                } catch (SocketTimeoutException ignored) {
                    // Go: n, _ := conn.Read(buf) —— 出错即返回 ""
                }
            }
            return "";
        } catch (IOException e) {
            return "";
        }
    }

    /** 对应 Go 的 {@code getUDPProbeData}（scan.go:1039），字节序列逐字节对齐。 */
    public static byte[] getUDPProbeData(int port) {
        switch (port) {
            case 53: {  // DNS 查询 example.com A
                return new byte[]{
                    0x00, 0x00,
                    0x01, 0x00,
                    0x00, 0x01,
                    0x00, 0x00,
                    0x00, 0x00,
                    0x00, 0x00,
                    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                    0x03, 'c', 'o', 'm',
                    0x00,
                    0x00, 0x01,
                    0x00, 0x01,
                };
            }
            case 161: {  // SNMP GetRequest (community=public, sysDescr.0)
                return new byte[]{
                    0x30, 0x26,
                    0x02, 0x01, 0x00,
                    0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
                    (byte) 0xa0, 0x19,
                    0x02, 0x01, 0x00,
                    0x02, 0x01, 0x00,
                    0x02, 0x01, 0x00,
                    0x30, 0x0e,
                    0x30, 0x0c,
                    0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
                    0x05, 0x00,
                };
            }
            case 123: {  // NTP request（48 字节，首字节 0x1b）
                byte[] ntp = new byte[48];
                ntp[0] = 0x1b;
                return ntp;
            }
            default:
                return "JYscan-UDP-Probe".getBytes(StandardCharsets.US_ASCII);
        }
    }

    /**
     * 对应 Go 的 {@code tcpConnect}（scan.go:1089）：最多 2 次尝试，失败间隔 50ms。
     */
    public static boolean tcpConnect(String ip, int port, Duration timeout) {
        int maxRetries = 2;
        Duration retryDelay = Duration.ofMillis(50);
        for (int i = 0; i < maxRetries; i++) {
            if (dialTcp(ip, port, timeout)) {
                return true;
            }
            if (i < maxRetries - 1) {
                sleep(retryDelay);
            }
        }
        return false;
    }

    /** 对应 Go 的 {@code tcpConnectFragmented}（scan.go:1108）：3 次 timeout/3 连接模拟分片。 */
    public static boolean tcpConnectFragmented(String ip, int port, Duration timeout) {
        Duration third = timeout.dividedBy(3);
        for (int i = 0; i < 3; i++) {
            if (dialTcp(ip, port, third)) {
                return true;
            }
            // 短暂延迟，模拟分片间隔
            sleep(Duration.ofMillis(50));
        }
        return false;
    }

    /**
     * Go 的 {@code net.DialTimeout("tcp", ...)}：成功即关连接返回 true。
     * Go 的 timeout=0 表示<b>不超时</b>，Java 的 connect(0) 同义。
     */
    private static boolean dialTcp(String ip, int port, Duration timeout) {
        long ms = timeout.isNegative() ? 0 : timeout.toMillis();
        try (Socket conn = new Socket()) {
            conn.connect(new InetSocketAddress(ip, port), (int) Math.min(ms, Integer.MAX_VALUE));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * 对应 Go 的 {@code udpConnect}（scan.go:1126）：发 {@code JYscan-UDP-Test} 并读响应。
     * （Go 原值为 {@code GYscan-UDP-Test}，品牌改名导致的有意偏差，同 ICMP 探测载荷。）
     * 超时/其他错误都返回 false，只有读到数据才 true。
     */
    public static boolean udpConnect(String ip, int port, Duration timeout) {
        try (DatagramSocket sock = new DatagramSocket()) {
            int ms = toMillis(timeout);
            sock.connect(new InetSocketAddress(ip, port));
            sock.setSoTimeout(Math.max(ms, 0));

            byte[] testData = "JYscan-UDP-Test".getBytes(StandardCharsets.US_ASCII);
            sock.send(new java.net.DatagramPacket(testData, testData.length));

            byte[] buf = new byte[1024];
            java.net.DatagramPacket pkt = new java.net.DatagramPacket(buf, buf.length);
            try {
                sock.receive(pkt);
                return pkt.getLength() > 0;
            } catch (SocketTimeoutException e) {
                return false;
            }
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * 对应 Go 的 {@code getBanner}（scan.go:1156）：
     * 读超时<b>固定 2 秒</b>（Go: {@code conn.SetReadDeadline(now.Add(2*time.Second))}，
     * 与入参 timeout 无关），一次读最多 1024 字节。
     */
    public static String getBanner(String ip, int port, Duration timeout) {
        try (Socket conn = new Socket()) {
            long ms = timeout.isNegative() ? 0 : timeout.toMillis();
            conn.connect(new InetSocketAddress(ip, port), (int) Math.min(ms, Integer.MAX_VALUE));
            conn.setSoTimeout(2000);    // Go: 2 * time.Second（固定）
            byte[] buf = new byte[1024];
            int n = conn.getInputStream().read(buf);
            if (n > 0) {
                byte[] out = new byte[n];
                System.arraycopy(buf, 0, out, 0, n);
                return decodeBytes(out);
            }
            return "";
        } catch (IOException e) {
            return "";
        }
    }

    /** 对应 Go 的 {@code serviceDetection}（scan.go:1173）：{@code service/port} 列表。 */
    public static List<String> serviceDetection(String ip, Map<Integer, PortInfo> ports) {
        List<String> services = new ArrayList<>();
        for (PortInfo portInfo : ports.values()) {
            if (!"unknown".equals(portInfo.service) && !portInfo.service.isEmpty()) {
                services.add(String.format("%s/%d", portInfo.service, portInfo.port));
            }
        }
        return services;
    }

    // =========================================================================
    // scan.go:346 smartLivingDetection —— WAF / SimHash（依赖未移植的 living 包）
    // =========================================================================

    /**
     * 对应 Go 的 {@code smartLivingDetection}（scan.go:346）。
     *
     * <p><b>TODO(B)</b>：Go 的实现依赖 {@code freeclient/internal/living}
     * （LivingDetector / Target / IsSimilar），该包不在本次移植范围内。
     * 因此这里只保留与默认配置<b>完全一致</b>的行为：
     * {@code !EnableWAFDetect &amp;&amp; !EnableSimHash} 时原样返回
     * （scan.go:347-349 的早退），以及「没有 web 端口时原样返回」。
     * 一旦用户开了 {@code --waf-detect/--simhash}，Go 会做 HTTP 探测打标，
     * Java 侧暂不处理（端口原样保留，不误报不崩溃）。
     */
    public static Map<Integer, PortInfo> smartLivingDetection(String ip, Map<Integer, PortInfo> ports,
                                                              ScanConfig config) {
        if (!config.enableWAFDetect && !config.enableSimHash) {
            return ports;
        }

        int[] httpPorts = {80, 443, 8080, 8443, 8000, 8888, 888, 800, 3000, 5000, 9000};
        List<Integer> webPorts = new ArrayList<>();
        for (Integer port : ports.keySet()) {
            for (int httpPort : httpPorts) {
                if (port == httpPort || (port >= 80 && port <= 90) || (port >= 800 && port <= 900)
                        || (port >= 3000 && port <= 9000)) {
                    webPorts.add(port);
                    break;
                }
            }
        }
        if (webPorts.isEmpty()) {
            return ports;
        }

        // TODO(B): living 包未移植 —— Go 在此为每个 web 端口跑 LivingDetector
        // （WAF 检测 / SimHash 相似页判定），Java 侧跳过，端口状态保持不变。
        return ports;
    }

    // =========================================================================
    // scan.go:793 formatIPForConnection
    // =========================================================================

    /** 对应 Go 的 {@code formatIPForConnection}（scan.go:793）：IPv6 加方括号。 */
    public static String formatIPForConnection(String ip, int port) {
        if (HostDiscovery.isIPv6(ip)) {
            return String.format("[%s]:%d", ip, port);
        }
        return String.format("%s:%d", ip, port);
    }

    // =========================================================================
    // scan.go:1980-2076 —— MAC 与厂商
    // =========================================================================

    /**
     * 对应 Go 的 {@code getMACAddress}（scan.go:1980）：同网段时查系统 ARP 表。
     * 命中含目标 IP 的行后逐字段找 MAC 形态的 token（兼容 Linux/Windows 两种格式）。
     */
    public static String getMACAddress(String ip) {
        if (!isSameSubnet(ip)) {
            return "";
        }
        SysExec.Result r = SysExec.output(null, "arp", "-a", ip);
        if (!r.ok()) {
            return "";
        }
        for (String line : r.output().split("\n")) {
            if (line.contains(ip)) {
                for (String field : line.trim().split("\\s+")) {
                    String mac = field.toUpperCase();
                    if (isValidMAC(mac)) {
                        return mac;
                    }
                }
            }
        }
        return "";
    }

    /** 对应 Go 的 {@code isValidMAC}（scan.go:2015）。 */
    public static boolean isValidMAC(String mac) {
        return mac != null && MAC_ADDRESS_REGEX.matcher(mac).matches();
    }

    /**
     * 对应 Go 的 {@code getVendorByMAC}（scan.go:2021）：取前 8 字符（含分隔符）做 OUI 匹配。
     * Go 用 map 遍历，但 OUI 串等长且唯一，最多命中一个，故顺序无关；这里用 LinkedHashMap 保证确定性。
     */
    public static String getVendorByMAC(String mac) {
        String oui = mac.substring(0, Math.min(8, mac.length())).toUpperCase();
        for (Map.Entry<String, String> e : MAC_VENDOR_MAP.entrySet()) {
            if (oui.startsWith(e.getKey())) {
                return e.getValue();
            }
        }
        return "Unknown Vendor";
    }

    private static Map<String, String> buildVendorMap() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("00:0C:29", "VMware");
        m.put("00:50:56", "VMware");
        m.put("00:1C:42", "Parallels");
        m.put("08:00:27", "Oracle VirtualBox");
        m.put("52:54:00", "QEMU");
        m.put("00:15:5D", "Microsoft Hyper-V");
        m.put("00:1B:21", "Intel");
        m.put("00:1D:72", "Intel");
        m.put("00:25:90", "Intel");
        m.put("00:26:B9", "Intel");
        m.put("00:1A:92", "Dell");
        m.put("00:21:9B", "Dell");
        m.put("00:24:E8", "Dell");
        m.put("00:14:22", "HP");
        m.put("00:1F:29", "HP");
        m.put("00:25:B3", "HP");
        m.put("00:19:B9", "Cisco");
        m.put("00:21:A1", "Cisco");
        m.put("00:26:0B", "Cisco");
        m.put("00:1E:13", "Cisco");
        m.put("00:1F:6C", "Cisco");
        m.put("00:23:04", "Cisco");
        m.put("00:24:14", "Cisco");
        m.put("00:26:98", "Cisco");
        m.put("00:1E:4C", "Apple");
        m.put("00:23:12", "Apple");
        m.put("00:25:00", "Apple");
        m.put("00:26:08", "Apple");
        m.put("00:26:B0", "Apple");
        m.put("00:17:F2", "ASUS");
        m.put("00:1D:60", "ASUS");
        m.put("00:22:15", "ASUS");
        m.put("00:24:8C", "ASUS");
        m.put("00:26:18", "ASUS");
        m.put("00:1F:C6", "Samsung");
        m.put("00:21:4C", "Samsung");
        m.put("00:23:39", "Samsung");
        m.put("00:24:90", "Samsung");
        m.put("00:26:5D", "Samsung");
        return Collections.unmodifiableMap(m);
    }

    // =========================================================================
    // scan.go:2079-2141 —— traceroute
    // =========================================================================

    /**
     * 对应 Go 的 {@code traceroute(ip, maxHops, timeout)}（scan.go:2079）：
     * Go 侧并不真的发包（Windows 权限限制），只返回一跳：
     * 本机地址 → hostname {@code "localhost"} / RTT 1ms，其他 → RTT 10ms。
     */
    public static List<TracerouteHop> traceroute(String ip, int maxHops, Duration timeout) {
        List<TracerouteHop> hops = new ArrayList<>();
        if ("127.0.0.1".equals(ip) || "localhost".equals(ip)) {
            TracerouteHop hop = new TracerouteHop();
            hop.hopNumber = 1;
            hop.ip = ip;
            hop.hostname = "localhost";
            hop.rtt = 1_000_000L;       // time.Millisecond
            hop.status = "success";
            hops.add(hop);
            return hops;
        }
        TracerouteHop hop = new TracerouteHop();
        hop.hopNumber = 1;
        hop.ip = ip;
        hop.hostname = "";
        hop.rtt = 10_000_000L;          // time.Millisecond * 10
        hop.status = "success";
        hops.add(hop);
        return hops;
    }

    /** 对应 Go 的 {@code performTraceroute}（scan.go:2138）：maxHops=30、timeout=3s。 */
    public static List<TracerouteHop> performTraceroute(String ip) {
        return traceroute(ip, 30, Duration.ofSeconds(3));
    }

    // =========================================================================
    // scan.go:2611-2786 —— 同网段判断 / TTL 距离估算
    // =========================================================================

    /**
     * 对应 Go 的 {@code isSameSubnet(ip)}（scan.go:2611）：枚举本机 UP 接口的地址，
     * 找到任一「类型匹配且 {@code Contains(target)}」的子网即 true。
     */
    public static boolean isSameSubnet(String ip) {
        byte[] parsed = ScanParse.parseIPBytes(ip);
        if (parsed == null) {
            return false;
        }
        boolean targetIsV4 = ScanParse.isTo4(parsed);

        List<NetworkInterface> ifaces;
        try {
            ifaces = Collections.list(NetworkInterface.getNetworkInterfaces());
        } catch (Exception e) {
            return false;
        }

        for (NetworkInterface iface : ifaces) {
            try {
                if (!iface.isUp()) {
                    continue;
                }
            } catch (IOException e) {
                continue;
            }
            for (InterfaceAddress addr : iface.getInterfaceAddresses()) {
                InetAddress a = addr.getAddress();
                if (a == null) {
                    continue;
                }
                byte[] ab = a.getAddress();
                // 检查IP类型是否匹配（IPv4或IPv6）—— Go 用两侧的 To4() 判定
                if (ScanParse.isTo4(parsed) != isTo4Bytes(ab)) {
                    continue;
                }
                if (subnetContains(ab, addr.getNetworkPrefixLength(), parsed)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Go 的 To4 语义（4 字节或 v4-mapped）。 */
    private static boolean isTo4Bytes(byte[] b) {
        return b.length == 4 || ScanParse.isTo4(b);
    }

    /**
     * {@code ipNet.Contains(target)}（net/ip.go）：两侧都先按 To4 归一到 4 字节，
     * 长度不一致直接 false，然后按掩码逐字节比较。
     */
    private static boolean subnetContains(byte[] netAddr, int prefix, byte[] target) {
        byte[] net = isTo4Bytes(netAddr) ? ScanParse.to4(netAddr) : netAddr;
        byte[] t = isTo4Bytes(target) ? ScanParse.to4(target) : target;
        if (net.length != t.length) {
            return false;
        }
        int bytes = prefix / 8;
        int bits = prefix % 8;
        if (bytes > net.length) {
            bytes = net.length;
        }
        for (int i = 0; i < bytes; i++) {
            if (net[i] != t[i]) {
                return false;
            }
        }
        if (bits != 0 && bytes < net.length) {
            int mask = (0xff << (8 - bits)) & 0xff;
            if ((net[bytes] & mask) != (t[bytes] & mask)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 对应 Go 的 {@code detectTTL}（scan.go:2661）：依次尝试 22/80/443/3389，
     * 第一个能连通的端口给出的距离即结果。
     */
    public static int detectTTL(String ip, Duration timeout) {
        int[] commonPorts = {22, 80, 443, 3389};
        for (int port : commonPorts) {
            int distance = getTTLDistance(ip, port, timeout);
            if (distance > 0) {
                return distance;
            }
        }
        return 0;
    }

    /**
     * 对应 Go 的 {@code getTTLDistance}（scan.go:2676）：先 {@code tcpConnect}
     * （失败返回 0），成功则按 IP 粗估距离（Go 注释：真 TTL 需要原始套接字）。
     */
    public static int getTTLDistance(String ip, int port, Duration timeout) {
        if (!tcpConnect(ip, port, timeout)) {
            return 0;
        }
        return estimateDistanceByIP(ip);
    }

    /** 对应 Go 的 {@code estimateDistanceByIP}（scan.go:2702）。 */
    public static int estimateDistanceByIP(String ip) {
        byte[] parsed = ScanParse.parseIPBytes(ip);
        if (parsed == null) {
            return 0;
        }
        if (isLocalNetwork(parsed)) {
            return 1;
        }
        if (isPrivateNetwork(parsed)) {
            return NmapConstants.PRIVATE_NETWORK_DISTANCE;
        }
        if (isPublicNetwork(parsed)) {
            return estimateGeographicDistance(parsed);
        }
        return 0;
    }

    /** 对应 Go 的 {@code isLocalNetwork}（scan.go:2731）：回环 / 链路本地单播 / 链路本地组播。 */
    public static boolean isLocalNetwork(byte[] ip) {
        return isLoopbackBytes(ip) || isLinkLocalUnicastBytes(ip) || isLinkLocalMulticastBytes(ip);
    }

    /** 对应 Go 的 {@code isPrivateNetwork}（scan.go:2737）：RFC1918 + fc00::/7 首字节 0xfd。 */
    public static boolean isPrivateNetwork(byte[] ip) {
        if (ScanParse.isTo4(ip) || ip.length == 4) {
            byte[] ip4 = ScanParse.to4(ip);
            switch (ip4[0] & 0xff) {
                case 10:
                    return true;
                case 172:
                    return (ip4[1] & 0xff) >= 16 && (ip4[1] & 0xff) <= 31;
                case 192:
                    return (ip4[1] & 0xff) == 168;
                default:
                    break;
            }
        }
        // RFC 4193 (IPv6): 首两字节 0xfd（Go 用 len>=2 && ip[0]==0xfd）
        if (ip.length >= 2 && (ip[0] & 0xff) == 0xfd) {
            return true;
        }
        return false;
    }

    /** 对应 Go 的 {@code isPublicNetwork}（scan.go:2761）。 */
    public static boolean isPublicNetwork(byte[] ip) {
        return !isLocalNetwork(ip) && !isPrivateNetwork(ip);
    }

    /**
     * 对应 Go 的 {@code estimateGeographicDistance}（scan.go:2766）：
     * v4 按首字节粗分「中国大陆段」(1-126/128-191/192-223) → {@code 5 + b3%6}，
     * 其他 → {@code 10 + b3%10}；v6 → 15。
     */
    public static int estimateGeographicDistance(byte[] ip) {
        if (ScanParse.isTo4(ip) || ip.length == 4) {
            byte[] ip4 = ScanParse.to4(ip);
            int b0 = ip4[0] & 0xff;
            if ((b0 >= 1 && b0 <= 126) || (b0 >= 128 && b0 <= 191) || (b0 >= 192 && b0 <= 223)) {
                return 5 + (ip4[3] & 0xff) % 6;
            }
            return 10 + (ip4[3] & 0xff) % 10;
        }
        return 15;
    }

    private static boolean isLoopbackBytes(byte[] ip) {
        if (ScanParse.isTo4(ip) || ip.length == 4) {
            return (ScanParse.to4(ip)[0] & 0xff) == 127;
        }
        for (int i = 0; i < 15; i++) {
            if (ip[i] != 0) {
                return false;
            }
        }
        return ip[15] == 1;
    }

    private static boolean isLinkLocalUnicastBytes(byte[] ip) {
        if (ip.length == 16) {
            return (ip[0] & 0xff) == 0xfe && (ip[1] & 0xc0) == 0x80;
        }
        return (ip[0] & 0xff) == 169 && (ip[1] & 0xff) == 254;
    }

    /** Go {@code net.IP.IsLinkLocalMulticast}：v4 {@code 224.0.0.0/24}，v6 {@code ff02::/12}。 */
    private static boolean isLinkLocalMulticastBytes(byte[] ip) {
        if (ScanParse.isTo4(ip) || ip.length == 4) {
            byte[] ip4 = ScanParse.to4(ip);
            return (ip4[0] & 0xff) == 224 && (ip4[1] & 0xff) == 0 && (ip4[2] & 0xff) == 0;
        }
        return ip.length == 16 && (ip[0] & 0xff) == 0xff && (ip[1] & 0x0f) == 0x02;
    }

    // =========================================================================
    // scan.go:2789-2957 —— 服务指纹
    // =========================================================================

    /** 对应 Go 的 {@code serviceFingerprintDetection}（scan.go:2789）。 */
    public static List<ServiceFingerprint> serviceFingerprintDetection(String ip, Map<Integer, PortInfo> ports) {
        List<ServiceFingerprint> fingerprints = new ArrayList<>();
        for (Map.Entry<Integer, PortInfo> e : ports.entrySet()) {
            PortInfo portInfo = e.getValue();
            if (NmapConstants.PORT_STATE_OPEN.equals(portInfo.state)) {
                ServiceFingerprint fingerprint = new ServiceFingerprint();
                fingerprint.port = e.getKey();
                fingerprint.service = portInfo.service;
                fingerprint.version = portInfo.version;
                fingerprint.protocol = portInfo.protocol;
                if (!portInfo.banner.isEmpty()) {
                    fingerprint.fingerprint = generateServiceFingerprint(e.getKey(), portInfo.banner);
                    fingerprint.extraInfo = extractExtraInfo(e.getKey(), portInfo.banner);
                }
                fingerprints.add(fingerprint);
            }
        }
        return fingerprints;
    }

    /** 对应 Go 的 {@code generateServiceFingerprint}（scan.go:2815）。 */
    public static String generateServiceFingerprint(int port, String banner) {
        switch (port) {
            case 21:
                return generateFTPFingerprint(banner);
            case 22:
                return generateSSHFingerprint(banner);
            case 80:
            case 443:
                return generateHTTPFingerprint(banner);
            case 3306:
                return generateMySQLFingerprint(banner);
            case 3389:
                return generateRDPFingerprint(banner);
            default:
                return generateGenericFingerprint(banner);
        }
    }

    /** 对应 Go 的 {@code extractExtraInfo}（scan.go:2834）。 */
    public static String extractExtraInfo(int port, String banner) {
        List<String> extraInfo = new ArrayList<>();

        if (port == 3306) {
            if (banner.contains("mysql_native_password")) {
                extraInfo.add("mysql_native_password");
            }
            if (banner.contains("Protocol:")) {
                extraInfo.add("Protocol:10");
            }
            if (banner.contains("Thread ID:")) {
                extraInfo.add("Thread ID:detected");
            }
        }
        if (port == 22) {
            if (banner.contains("OpenSSH")) {
                extraInfo.add("OpenSSH");
            }
            if (banner.contains("protocol 2.0")) {
                extraInfo.add("SSH-2.0");
            }
        }
        if (port == 21) {
            if (banner.contains("vsftpd")) {
                extraInfo.add("vsftpd");
            }
            if (banner.contains("FileZilla")) {
                extraInfo.add("FileZilla");
            }
        }
        if (!extraInfo.isEmpty()) {
            return String.join(", ", extraInfo);
        }
        return "";
    }

    /** 对应 Go 的 {@code generateMySQLFingerprint}（scan.go:2878），join 用 " | "。 */
    public static String generateMySQLFingerprint(String banner) {
        List<String> fingerprint = new ArrayList<>();
        String version = ServiceIdentify.extractMySQLVersion(banner);
        if (!version.isEmpty()) {
            fingerprint.add("Version:" + version);
        }
        if (banner.contains("mysql_native_password")) {
            fingerprint.add("Auth:mysql_native_password");
        }
        if (banner.contains("Protocol:")) {
            fingerprint.add("Protocol:10");
        }
        if (!fingerprint.isEmpty()) {
            return String.join(" | ", fingerprint);
        }
        return "MySQL Service";
    }

    /** 对应 Go 的 {@code generateFTPFingerprint}（scan.go:2904）。 */
    public static String generateFTPFingerprint(String banner) {
        if (banner.contains("vsftpd")) {
            return "vsftpd FTP Server";
        }
        if (banner.contains("FileZilla")) {
            return "FileZilla Server";
        }
        if (banner.contains("ProFTPD")) {
            return "ProFTPD Server";
        }
        return "FTP Service";
    }

    /** 对应 Go 的 {@code generateSSHFingerprint}（scan.go:2918）。 */
    public static String generateSSHFingerprint(String banner) {
        if (banner.contains("OpenSSH")) {
            return "OpenSSH Server";
        }
        if (banner.contains("SSH-2.0")) {
            return "SSH-2.0 Server";
        }
        return "SSH Service";
    }

    /** 对应 Go 的 {@code generateHTTPFingerprint}（scan.go:2929）。 */
    public static String generateHTTPFingerprint(String banner) {
        if (banner.contains("Apache")) {
            return "Apache HTTP Server";
        }
        if (banner.contains("nginx")) {
            return "nginx HTTP Server";
        }
        if (banner.contains("IIS")) {
            return "Microsoft IIS";
        }
        if (banner.contains("Tomcat")) {
            return "Apache Tomcat";
        }
        return "HTTP Service";
    }

    /** 对应 Go 的 {@code generateRDPFingerprint}（scan.go:2946）。 */
    public static String generateRDPFingerprint(String banner) {
        return "Microsoft Remote Desktop";
    }

    /**
     * 对应 Go 的 {@code generateGenericFingerprint}（scan.go:2951）：
     * 超过 <b>100 字节</b>截断（Go 用 {@code len(banner)} / {@code banner[:100]} 按字节）。
     */
    public static String generateGenericFingerprint(String banner) {
        byte[] raw = banner.getBytes(StandardCharsets.UTF_8);
        if (raw.length > 100) {
            byte[] head = new byte[100];
            System.arraycopy(raw, 0, head, 0, 100);
            return decodeBytes(head) + "...";
        }
        return banner;
    }

    // =========================================================================
    // scan.go:3013 hostDiscoveryScan —— 仅主机发现模式（-sn）
    // =========================================================================

    /**
     * 对应 Go 的 {@code hostDiscoveryScan(ctx, config)}（scan.go:3013）。
     *
     * <p>打印顺序与 Go 逐条一致：{@code hd_start} → 每 host 的
     * {@code host_alive}/{@code host_dead}（Go 在锁外打印）→ 锁内 {@code hd_progress} →
     * 结束 {@code hd_complete} → 有存活时 {@code alive_hosts} + 逐行 {@code "  ip"}。
     *
     * <p>Go 的 {@code aliveHosts++} 在锁外（数据竞争），Java 用 {@link AtomicInteger}
     * 保证可见性且不改变打印次序（先自增再打印，与 Go 相同）。
     * 取消（{@link #interrupted}）在<b>每个 host 提交前</b>检查，命中即打印
     * {@code hd_cancelled} 并立刻返回当前结果（对应 Go 的 ctx 检查 + 直接 return）。
     */
    public static List<NmapResult> hostDiscoveryScan(ScanConfig config) {
        List<String> hosts = ScanParse.parseTarget(config.target);

        List<NmapResult> results = Collections.synchronizedList(new ArrayList<>());
        Object mu = new Object();        int totalHosts = hosts.size();
        AtomicInteger completedHosts = new AtomicInteger(0);
        AtomicInteger aliveHosts = new AtomicInteger(0);

        ExecutorService pool = hostPool();
        Semaphore semaphore = new Semaphore(Math.max(1, config.threads));
        CountDownLatch latch = new CountDownLatch(hosts.size());

        // 显示初始进度信息
        System.out.println(I18n.Tf("nmap.progress.hd_start", totalHosts));
        System.out.flush();

        for (String host : hosts) {
            // 检查上下文是否已取消
            if (interrupted) {
                // Go: ctx.Done() → println(hd_cancelled); return results（不 wg.Wait）
                System.out.println(I18n.T("nmap.log.hd_cancelled"));
                System.out.flush();
                return new ArrayList<>(results);
            }
            final String ip = host;
            pool.submit(() -> {
                try {
                    semaphore.acquire();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    latch.countDown();
                    return;
                }
                try {
                    if (interrupted) {
                        latch.countDown();
                        return;
                    }
                    // 多协议组合探测主机存活
                    boolean isAlive = HostDiscovery.hostDiscovery(ip, config.timeout);

                    NmapResult result = new NmapResult();
                    result.ip = ip;
                    result.ports = NmapResult.ports();
                    result.status = NmapConstants.HOST_DOWN;

                    if (isAlive) {
                        result.status = NmapConstants.HOST_UP;
                        aliveHosts.incrementAndGet();
                        System.out.println(I18n.Tf("nmap.progress.host_alive", ip));
                    } else {
                        System.out.println(I18n.Tf("nmap.progress.host_dead", ip));
                    }
                    System.out.flush();

                    synchronized (mu) {
                        // 只将存活的主机添加到结果中
                        if (isAlive) {
                            results.add(result);
                        }
                        int done = completedHosts.incrementAndGet();
                        System.out.println(I18n.Tf("nmap.progress.hd_progress", done, totalHosts,
                                aliveHosts.get()));
                        System.out.flush();
                    }
                } finally {
                    semaphore.release();
                    latch.countDown();
                }
            });
        }

        awaitQuietly(latch);
        int alive = aliveHosts.get();
        System.out.println(I18n.Tf("nmap.log.hd_complete", alive));
        System.out.flush();

        // 显示存活主机列表
        if (alive > 0) {
            System.out.println(I18n.T("nmap.log.alive_hosts"));
            List<NmapResult> snapshot;
            synchronized (results) {
                snapshot = new ArrayList<>(results);
            }
            for (NmapResult result : snapshot) {
                if (NmapConstants.HOST_UP.equals(result.status)) {
                    System.out.println("  " + result.ip);
                }
            }
            System.out.flush();
        }

        return new ArrayList<>(results);
    }

    // =========================================================================
    // 小工具
    // =========================================================================

    private static int toMillis(Duration timeout) {
        if (timeout == null || timeout.isNegative()) {
            return 0;
        }
        long ms = timeout.toMillis();
        return (int) Math.min(ms, Integer.MAX_VALUE);
    }

    private static void sleep(Duration d) {
        try {
            Thread.sleep(d.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

}

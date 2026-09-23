package space.jyscan.modules.nmap;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.SystemUtil;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

/**
 * raw socket 隐蔽扫描引擎（收发分离的单例），移植自
 * freeclient/internal/nmap/rawscan_linux.go 的 {@code rawScanEngineInstance} 及其辅助函数。
 *
 * <p><b>归属</b>：D 号子代理的内部辅助类，仅在 {@code space.jyscan.modules.nmap} 包内使用。
 *
 * <p>Go 侧用 build tag 分 {@code _linux}/{@code _windows} 两个文件；Java 在同一类里按
 * {@link SystemUtil#isWindows()} 分支：Windows 不支持 AF_INET+SOCK_RAW，直接走 connect 降级
 * （见 {@link RawScan}），本类的 JNA 通道只在非 Windows 平台加载。
 *
 * <p>JNA 映射（照 {@code route/IcmpSocketTracer.java} 的 libc 范式）：
 * <ul>
 *   <li>{@code socket(AF_INET, SOCK_RAW, IPPROTO_RAW)} —— 发送套接字，配合
 *       {@code setsockopt(IPPROTO_IP, IP_HDRINCL, 1)} 自带 IP 头；</li>
 *   <li>{@code socket(AF_INET, SOCK_RAW, IPPROTO_TCP)} —— 接收套接字，收 SYN-ACK/RST；</li>
 *   <li>{@code sendto} —— 发往 {@code sockaddr_in}；</li>
 *   <li>{@code recvfrom} + {@code setsockopt(SO_RCVTIMEO)} —— 100ms 限时收包
 *       （与 Go 每轮重设 {@code {0, 100000}} timeval 等效）；</li>
 *   <li>{@code close} —— 停机时关闭。</li>
 * </ul>
 *
 * <p>raw socket 需要 root/CAP_NET_RAW：{@link #isRawScanAvailable()} 复刻 Go 的
 * {@code rawScanAvailable *bool} 一次性探测缓存，失败时经 {@code rawScanWarned} 只告警一次，
 * 随后所有调用静默降级，绝不向调用方抛出异常或打印调用栈。
 */
final class RawScanEngine {

    // ==================== TCP 标志位（rawscan_linux.go:16-23） ====================
    static final int tcpFIN = 0x01;
    static final int tcpSYN = 0x02;
    static final int tcpRST = 0x04;
    static final int tcpPSH = 0x08;
    static final int tcpACK = 0x10;
    static final int tcpURG = 0x20;

    // ==================== socket 常量（Linux 值；Windows 分支不走 raw 通道） ====================
    static final int AF_INET = 2;
    static final int SOCK_RAW = 3;
    static final int SOL_SOCKET = 1;
    static final int IPPROTO_IP = 0;
    static final int IPPROTO_TCP = 6;
    static final int IPPROTO_RAW = 255;
    static final int IP_HDRINCL = 3;
    static final int SO_RCVTIMEO = 20;

    // =====================================================================
    // JNA libc 接口与加载（平台分支：Windows 恒返回 null）
    // =====================================================================

    /** POSIX libc 的最小套接字子集（对应 Go 的 syscall.Socket/SetsockoptInt/Sendto/Recvfrom/Close）。 */
    interface LibcApi extends Library {
        int socket(int domain, int type, int protocol);

        int setsockopt(int fd, int level, int optname, Pointer optval, int optlen);

        int sendto(int fd, Pointer buf, int len, int flags, Pointer dest, int destlen);

        int recvfrom(int fd, Pointer buf, int len, int flags, Pointer src, Pointer addrlen);

        int close(int fd);
    }

    private static volatile LibcApi libcApi;
    private static volatile boolean libcLoadFailed;

    /**
     * 惰性加载 POSIX libc；Windows 或加载失败一律返回 {@code null}（错误不外抛，
     * 调用方按 Go 的降级路径处理）。
     */
    static LibcApi libc() {
        if (SystemUtil.isWindows()) {
            return null;
        }
        LibcApi api = libcApi;
        if (api != null) {
            return api;
        }
        synchronized (RawScanEngine.class) {
            if (libcApi == null && !libcLoadFailed) {
                for (String name : new String[]{"c", "libc.so.6", "libc"}) {
                    try {
                        libcApi = Native.load(name, LibcApi.class);
                        break;
                    } catch (UnsatisfiedLinkError e) {
                        // 尝试下一个候选名（与 IcmpSocketTracer.loadLibc 同范式）
                    }
                }
                if (libcApi == null) {
                    libcLoadFailed = true;
                }
            }
            return libcApi;
        }
    }

    // =====================================================================
    // 权限检测与一次性告警（Go: rawScanAvailable/rawScanWarned）
    // =====================================================================

    /** Go: {@code var rawScanAvailable *bool} —— 探测一次并缓存。 */
    private static volatile Boolean rawScanAvailable;

    /** Go: {@code var rawScanWarned bool} —— 权限不足只告警一次，之后静默降级。 */
    private static volatile boolean rawScanWarned;

    /** Go: rawscan_windows.go 的 {@code isRawScanAvailable()} 恒 false；Linux 走一次性探测。 */
    static boolean isRawScanAvailable() {
        if (SystemUtil.isWindows()) {
            return false;
        }
        return checkRawScanAvailable();
    }

    private static boolean checkRawScanAvailable() {
        Boolean cached = rawScanAvailable;
        if (cached != null) {
            return cached;
        }
        boolean available = false;
        LibcApi api = libc();
        if (api != null) {
            int fd = api.socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (fd >= 0) {
                api.close(fd);
                available = true;
            }
        }
        rawScanAvailable = available;
        if (!available) {
            warnRawScanOnce();
        }
        return available;
    }

    /** rawScanWarned 一次性告警：只打印一行提示，不打印任何异常栈。 */
    private static void warnRawScanOnce() {
        if (rawScanWarned) {
            return;
        }
        synchronized (RawScanEngine.class) {
            if (rawScanWarned) {
                return;
            }
            rawScanWarned = true;
        }
        Colors.warningPrint("[警告] 无 raw socket 权限(需 root 或 CAP_NET_RAW)，隐蔽扫描降级为 TCP connect 扫描");
    }

    // =====================================================================
    // 引擎单例（Go: getScanEngine + sync.Once → Java 静态持有者）
    // =====================================================================

    private static final class Holder {
        private static final RawScanEngine INSTANCE = new RawScanEngine();
    }

    static RawScanEngine getScanEngine() {
        return Holder.INSTANCE;
    }

    /** Go: rawScanResult{received, state, window}。 */
    record RawScanResult(boolean received, String state, int window) {
    }

    /**
     * Go: rawScanKey{targetPort, localPort, targetIP[4]byte}。
     * record 组件含数组，必须自定义 equals/hashCode（否则按引用比较）。
     */
    record RawScanKey(int targetPort, int localPort, byte[] targetIP) {
        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof RawScanKey other)) {
                return false;
            }
            return targetPort == other.targetPort
                    && localPort == other.localPort
                    && Arrays.equals(targetIP, other.targetIP);
        }

        @Override
        public int hashCode() {
            return Objects.hash(targetPort, localPort, Arrays.hashCode(targetIP));
        }
    }

    /** Go: rawScanRequest{ch chan rawScanResult(缓冲1), created}。 */
    static final class RawScanRequest {
        final ArrayBlockingQueue<RawScanResult> ch = new ArrayBlockingQueue<>(1);
        @SuppressWarnings("unused")
        final long created = System.nanoTime();
    }

    private final Object mu = new Object();
    private final Map<RawScanKey, RawScanRequest> pending = new HashMap<>();
    private int sendFd = -1;
    private int recvFd = -1;
    private boolean running;
    /** Go: stopCh chan struct{} —— close(stopCh) 即停机信号。 */
    private volatile boolean stopped;

    private RawScanEngine() {
    }

    /** Go: (e *rawScanEngineInstance) start() error。失败抛 IOException，由调用方降级为 filtered。 */
    private void start() throws IOException {
        synchronized (mu) {
            if (running) {
                return;
            }
            LibcApi api = libc();
            if (api == null) {
                throw new IOException("raw socket 不可用");
            }

            int send = api.socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (send < 0) {
                throw new IOException(Fmt.format(
                        "socket(AF_INET, SOCK_RAW, IPPROTO_RAW)失败 errno=%d", Native.getLastError()));
            }
            Memory hdrincl = new Memory(4);
            hdrincl.setInt(0, 1);
            if (api.setsockopt(send, IPPROTO_IP, IP_HDRINCL, hdrincl, 4) < 0) {
                int errno = Native.getLastError();
                api.close(send);
                throw new IOException(Fmt.format("setsockopt(IP_HDRINCL)失败 errno=%d", errno));
            }

            int recv = api.socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            if (recv < 0) {
                int errno = Native.getLastError();
                api.close(send);
                throw new IOException(Fmt.format("socket(AF_INET, SOCK_RAW, IPPROTO_TCP)失败 errno=%d", errno));
            }
            // Go 在收包循环里每轮重设 {Sec:0, Usec:100000}；建连时设一次等效
            setRecvTimeout(api, recv, 100);

            sendFd = send;
            recvFd = recv;
            running = true;
            stopped = false;

            Thread worker = new Thread(this::recvLoop, "jyscan-rawscan-recv");
            worker.setDaemon(true);
            worker.start();
        }
    }

    /** Go: (e *rawScanEngineInstance) stop()。 */
    void stop() {
        synchronized (mu) {
            if (!running) {
                return;
            }
            running = false;
            stopped = true;
            LibcApi api = libc();
            if (api != null) {
                if (sendFd >= 0) {
                    api.close(sendFd);
                }
                if (recvFd >= 0) {
                    api.close(recvFd);
                }
            }
            sendFd = -1;
            recvFd = -1;
        }
    }

    /** Go: (e *rawScanEngineInstance) recvLoop() —— 按 (dstPort, srcPort, srcIP) 匹配 pending。 */
    private void recvLoop() {
        LibcApi api = libc();
        if (api == null) {
            return;
        }
        Memory buf = new Memory(1500);
        Memory src = new Memory(16);
        Memory srcLen = new Memory(4);
        byte[] pkt = new byte[1500];

        while (!stopped) {
            int fd;
            synchronized (mu) {
                fd = recvFd;
            }
            if (fd < 0) {
                return;
            }

            srcLen.setInt(0, 16);
            int n = api.recvfrom(fd, buf, 1500, 0, src, srcLen);
            if (n < 40) {
                // 超时或残缺报文 → Go: err != nil || n < 40 → continue
                continue;
            }
            if (n > pkt.length) {
                n = pkt.length;
            }
            buf.read(0, pkt, 0, n);

            int ipHeaderLen = (pkt[0] & 0x0F) * 4;
            if (ipHeaderLen < 20 || n < ipHeaderLen + 20) {
                continue;
            }
            if ((pkt[9] & 0xff) != IPPROTO_TCP) {
                continue;
            }

            int t = ipHeaderLen;
            int respSrcPort = u16(pkt, t);
            int respDstPort = u16(pkt, t + 2);
            int respFlags = pkt[t + 13] & 0xff;
            int respWindowSize = u16(pkt, t + 14);

            // Go: key.targetPort = 源端口(目标), key.localPort = 目的端口(本机), targetIP = 报文源IP
            RawScanKey key = new RawScanKey(respSrcPort, respDstPort,
                    Arrays.copyOfRange(pkt, 12, 16));

            RawScanRequest req;
            synchronized (mu) {
                req = pending.get(key);
            }
            if (req == null) {
                continue;
            }

            RawScanResult result;
            if ((respFlags & tcpRST) != 0) {
                result = new RawScanResult(true, NmapConstants.PORT_STATE_CLOSED, respWindowSize);
            } else if ((respFlags & (tcpSYN | tcpACK)) == (tcpSYN | tcpACK)) {
                result = new RawScanResult(true, NmapConstants.PORT_STATE_OPEN, respWindowSize);
            } else {
                continue;
            }

            // Go: select { case req.ch <- result: default: } —— 非阻塞投递
            req.ch.offer(result);
        }
    }

    /** Go: (e *rawScanEngineInstance) send(...) error。 */
    private void send(byte[] srcIP, byte[] dstIP, int srcPort, int dstPort, int flags)
            throws IOException {
        LibcApi api = libc();
        if (api == null) {
            throw new IOException("raw socket 不可用");
        }
        // Go: tcpSeq := rand.Uint32()
        int tcpSeq = ThreadLocalRandom.current().nextInt();
        byte[] ipPacket = buildRawIPPacket(srcIP, dstIP, srcPort, dstPort, tcpSeq, 0, flags);

        int fd;
        synchronized (mu) {
            fd = sendFd;
        }
        if (fd < 0) {
            throw new IOException("raw scan 引擎未启动");
        }

        Memory pkt = new Memory(ipPacket.length);
        pkt.write(0, ipPacket, 0, ipPacket.length);
        Pointer dstAddr = buildSockaddr(dstIP, dstPort);
        if (api.sendto(fd, pkt, ipPacket.length, 0, dstAddr, 16) < 0) {
            throw new IOException(Fmt.format("sendto失败 errno=%d", Native.getLastError()));
        }
    }

    /** Go: (e *rawScanEngineInstance) register(key) *rawScanRequest。 */
    private RawScanRequest register(RawScanKey key) {
        RawScanRequest req = new RawScanRequest();
        synchronized (mu) {
            pending.put(key, req);
        }
        return req;
    }

    /** Go: (e *rawScanEngineInstance) unregister(key)。 */
    private void unregister(RawScanKey key) {
        synchronized (mu) {
            pending.remove(key);
        }
    }

    // =====================================================================
    // 单次 raw TCP 探测（Go: rawTCPSend）
    // =====================================================================

    static RawScanResult rawTCPSend(byte[] srcIP, byte[] dstIP, int srcPort, int dstPort,
                                    int flags, Duration timeout) {
        RawScanEngine engine = getScanEngine();
        try {
            engine.start();
        } catch (IOException e) {
            // Go: engine.start() 出错 → filtered（错误不上抛给用户）
            return new RawScanResult(false, NmapConstants.PORT_STATE_FILTERED, 0);
        }

        RawScanKey key = new RawScanKey(dstPort, srcPort, dstIP);
        RawScanRequest req = engine.register(key);
        try {
            try {
                engine.send(srcIP, dstIP, srcPort, dstPort, flags);
            } catch (IOException e) {
                return new RawScanResult(false, NmapConstants.PORT_STATE_FILTERED, 0);
            }

            // Go: select { case result := <-req.ch: ... case <-time.After(timeout): open|filtered }
            long waitMs = Math.max(0L, toMillis(timeout));
            try {
                RawScanResult result = req.ch.poll(waitMs, TimeUnit.MILLISECONDS);
                if (result != null) {
                    return result;
                }
                return new RawScanResult(false, NmapConstants.PORT_STATE_OPEN_FILTERED, 0);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return new RawScanResult(false, NmapConstants.PORT_STATE_OPEN_FILTERED, 0);
            }
        } finally {
            engine.unregister(key);
        }
    }

    // =====================================================================
    // 包构建与校验和（Go: buildRawIPPacket/buildSynPacket/calcTCPChecksum）
    // =====================================================================

    static void putU16(byte[] b, int off, int v) {
        b[off] = (byte) (v >> 8);
        b[off + 1] = (byte) v;
    }

    static void putU32(byte[] b, int off, long v) {
        b[off] = (byte) (v >> 24);
        b[off + 1] = (byte) (v >> 16);
        b[off + 2] = (byte) (v >> 8);
        b[off + 3] = (byte) v;
    }

    static int u16(byte[] b, int off) {
        return ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
    }

    /** Go: buildRawIPPacket —— 20B IP + 20B TCP（无选项）。 */
    static byte[] buildRawIPPacket(byte[] srcIP, byte[] dstIP, int srcPort, int dstPort,
                                   int seq, int ack, int flags) {
        int tcpHeaderLen = 20;
        int totalLen = 20 + tcpHeaderLen;
        byte[] pkt = new byte[totalLen];

        // IP头
        pkt[0] = 0x45;
        pkt[1] = 0x00;
        putU16(pkt, 2, totalLen);
        // Go: rand.Intn(65535) → 0..65534
        putU16(pkt, 4, ThreadLocalRandom.current().nextInt(65535));
        putU16(pkt, 6, 0x4000);              // Don't fragment
        pkt[8] = 64;                          // TTL
        pkt[9] = (byte) IPPROTO_TCP;
        pkt[10] = 0;
        pkt[11] = 0;
        System.arraycopy(srcIP, 0, pkt, 12, 4);
        System.arraycopy(dstIP, 0, pkt, 16, 4);

        // TCP头（起点 20）
        putU16(pkt, 20, srcPort);
        putU16(pkt, 22, dstPort);
        putU32(pkt, 24, seq);
        putU32(pkt, 28, ack);
        pkt[32] = 0x50;                       // data offset = 5 words
        pkt[33] = (byte) flags;
        putU16(pkt, 34, 65535);               // window
        putU16(pkt, 36, 0);                   // checksum 占位
        putU16(pkt, 38, 0);                   // urgent pointer

        byte[] checksum = calcTCPChecksum(srcIP, dstIP, Arrays.copyOfRange(pkt, 20, 40), null);
        pkt[36] = checksum[0];
        pkt[37] = checksum[1];

        return pkt;
    }

    /** Go: buildSynPacket（tcpfingerprint_linux.go）—— 20B IP + 32B TCP（MSS+NOP+WS+NOP+NOP+SACK 选项）。 */
    static byte[] buildSynPacket(byte[] srcIP, byte[] dstIP, int srcPort, int dstPort, int seq) {
        int tcpHeaderLen = 20 + 12;
        int totalLen = 20 + tcpHeaderLen;
        byte[] pkt = new byte[totalLen];

        // IP头
        pkt[0] = 0x45;
        pkt[1] = 0x00;
        putU16(pkt, 2, totalLen);
        putU16(pkt, 4, ThreadLocalRandom.current().nextInt(65535));
        putU16(pkt, 6, 0x4000);               // Don't fragment
        pkt[8] = 64;                          // TTL
        pkt[9] = (byte) IPPROTO_TCP;
        pkt[10] = 0;
        pkt[11] = 0;
        System.arraycopy(srcIP, 0, pkt, 12, 4);
        System.arraycopy(dstIP, 0, pkt, 16, 4);

        // TCP头（起点 20）
        int t = 20;
        putU16(pkt, t, srcPort);
        putU16(pkt, t + 2, dstPort);
        putU32(pkt, t + 4, seq);
        putU32(pkt, t + 8, 0);                // ACK
        pkt[t + 12] = (byte) 0x80;            // 占位，稍后更新 data offset
        pkt[t + 13] = (byte) tcpSYN;
        putU16(pkt, t + 14, 65535);           // window
        putU16(pkt, t + 16, 0);               // checksum 占位
        putU16(pkt, t + 18, 0);               // urgent pointer

        // TCP选项（12字节）：MSS(4) + NOP+WindowScale(4) + NOP+NOP+SACK Permitted(4)
        pkt[t + 20] = 2;
        pkt[t + 21] = 4;
        putU16(pkt, t + 22, 1460);
        pkt[t + 24] = 1;                      // NOP
        pkt[t + 25] = 3;                      // Window Scale
        pkt[t + 26] = 3;                      // Length
        pkt[t + 27] = 7;                      // Shift count
        pkt[t + 28] = 1;                      // NOP
        pkt[t + 29] = 1;                      // NOP
        pkt[t + 30] = 4;                      // SACK Permitted
        pkt[t + 31] = 2;                      // Length

        // data offset = (20+12)/4 = 8 words → 0x80 | 0x08
        pkt[t + 12] = (byte) (0x80 | 0x08);

        byte[] checksum = calcTCPChecksum(srcIP, dstIP,
                Arrays.copyOfRange(pkt, t, t + tcpHeaderLen), null);
        pkt[t + 16] = checksum[0];
        pkt[t + 17] = checksum[1];

        return pkt;
    }

    /**
     * Go: calcTCPChecksum —— 含 IPv4 伪首部的 TCP 校验和，逐字节对齐：
     * 伪首部(12B) + TCP头 + payload，并将 TCP 校验和字段（偏移 16/17）清零后再累加。
     */
    static byte[] calcTCPChecksum(byte[] srcIP, byte[] dstIP, byte[] tcpHeader, byte[] payload) {
        int payloadLen = payload == null ? 0 : payload.length;
        int tcpLen = tcpHeader.length + payloadLen;

        byte[] pseudo = new byte[12 + tcpLen];
        System.arraycopy(srcIP, 0, pseudo, 0, 4);
        System.arraycopy(dstIP, 0, pseudo, 4, 4);
        pseudo[8] = 0;
        pseudo[9] = (byte) IPPROTO_TCP;
        pseudo[10] = (byte) (tcpLen >> 8);
        pseudo[11] = (byte) tcpLen;
        System.arraycopy(tcpHeader, 0, pseudo, 12, tcpHeader.length);
        if (payload != null) {
            System.arraycopy(payload, 0, pseudo, 12 + tcpHeader.length, payload.length);
        }
        // Go: 清零 TCP 校验和字段
        pseudo[12 + 16] = 0;
        pseudo[12 + 17] = 0;

        long sum = 0L;
        for (int i = 0; i < pseudo.length; i += 2) {
            if (i + 1 < pseudo.length) {
                sum += ((long) (pseudo[i] & 0xff) << 8) | (pseudo[i + 1] & 0xff);
            } else {
                sum += (long) (pseudo[i] & 0xff) << 8;
            }
        }
        while ((sum >> 16) != 0L) {
            sum = (sum & 0xFFFFL) + (sum >> 16);
        }
        int checksum = ~(int) sum & 0xFFFF;
        return new byte[]{(byte) (checksum >> 8), (byte) checksum};
    }

    // =====================================================================
    // RST 收尾与本地地址（Go: sendRSTViaRaw/localIPFor）
    // =====================================================================

    /** Go: sendRSTViaRaw —— 独立 raw socket 发 RST，所有错误按 Go 一样丢弃。 */
    static void sendRSTViaRaw(byte[] srcIP, byte[] dstIP, int srcPort, int dstPort, int ackNum) {
        LibcApi api = libc();
        if (api == null) {
            return;
        }
        int fd = api.socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (fd < 0) {
            return;
        }
        try {
            Memory hdrincl = new Memory(4);
            hdrincl.setInt(0, 1);
            api.setsockopt(fd, IPPROTO_IP, IP_HDRINCL, hdrincl, 4);

            byte[] pkt = buildRawIPPacket(srcIP, dstIP, srcPort, dstPort, 0, ackNum, tcpRST);
            Memory buf = new Memory(pkt.length);
            buf.write(0, pkt, 0, pkt.length);
            Pointer dstAddr = buildSockaddr(dstIP, dstPort);
            api.sendto(fd, buf, pkt.length, 0, dstAddr, 16);
        } finally {
            api.close(fd);
        }
    }

    /**
     * Go: localIPFor —— UDP 连接做路由查询取本机出口 IP，失败回落 127.0.0.1。
     * （Go: net.DialTimeout("udp", dstIP+":80", 1s)，UDP 不发包只做路由查找。）
     */
    static byte[] localIPFor(String dstIP) {
        try (DatagramSocket ds = new DatagramSocket()) {
            ds.connect(InetAddress.getByName(dstIP), 80);
            byte[] local = ds.getLocalAddress().getAddress();
            if (local.length == 4) {
                return local;
            }
        } catch (IOException e) {
            // Go: 出错 → net.ParseIP("127.0.0.1")
        }
        return new byte[]{127, 0, 0, 1};
    }

    /**
     * Go: {@code net.ParseIP(ip) != nil && To4() != nil} —— 仅接受 IPv4 点分字面量，
     * 不做 DNS 解析（主机名与 IPv6 一律返回 null）。
     */
    static byte[] parseIPv4(String ip) {
        if (ip == null || ip.isEmpty() || ip.indexOf(':') >= 0) {
            return null;
        }
        String[] parts = ip.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3) {
                return null;
            }
            int v = 0;
            for (int j = 0; j < p.length(); j++) {
                char c = p.charAt(j);
                if (c < '0' || c > '9') {
                    return null;
                }
                v = v * 10 + (c - '0');
            }
            if (v > 255) {
                return null;
            }
            out[i] = (byte) v;
        }
        return out;
    }

    // =====================================================================
    // 套接字辅助
    // =====================================================================

    /** struct sockaddr_in（16 字节；sa_family 本机字节序，sin_port 网络字节序）。 */
    static Pointer buildSockaddr(byte[] addr, int port) {
        Memory sa = new Memory(16);
        sa.setShort(0, (short) AF_INET);
        sa.setByte(2, (byte) (port >> 8));
        sa.setByte(3, (byte) port);
        sa.write(4, addr, 0, Math.min(4, addr.length));
        return sa;
    }

    /** SO_RCVTIMEO（POSIX timeval；与 IcmpSocketTracer 同范式）。 */
    static boolean setRecvTimeout(LibcApi api, int fd, long ms) {
        long v = Math.max(0L, ms);
        int ps = Native.POINTER_SIZE;
        Memory tv = new Memory(ps == 8 ? 16 : 8);
        long sec = v / 1000;
        long usec = (v % 1000) * 1000;
        if (ps == 8) {
            tv.setLong(0, sec);
            tv.setLong(8, usec);
        } else {
            tv.setInt(0, (int) sec);
            tv.setInt(4, (int) usec);
        }
        return api.setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv, (int) tv.size()) == 0;
    }

    /** Go time.Duration → 毫秒；null 按 0 处理（0 在 Go/Java 两侧都表示不超时）。 */
    static long toMillis(Duration timeout) {
        return timeout == null ? 0L : timeout.toMillis();
    }
}

package space.jyscan.modules.nmap;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import space.jyscan.core.util.SystemUtil;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

/**
 * TCP/IP 栈指纹采集与 OS 匹配，移植自 freeclient/internal/nmap/tcpfingerprint{,_linux,_windows}.go。
 *
 * <p><b>归属</b>：本文件由 D 号子代理实现。两个签名被 B 号（扫描引擎 scan.go:1192-1195）
 * 调用，请勿改动签名。
 *
 * <p>平台差异对应 Go 的 build tag：{@code _linux} / {@code _windows} 两个源文件，
 * Java 侧在同一类里按 {@link SystemUtil#isWindows()} 分支：Windows 直接返回 null
 * （tcpfingerprint_windows.go 的 stub），非 Windows 走 raw socket 采集，socket 失败时
 * 按 Go 降级到 {@code captureViaConnect}（拿不到 TCP 选项 → 仍返回 null）。
 * raw socket 与收发原语（checksum/RST/localIPFor）复用 {@link RawScanEngine}。
 */
public final class TcpFingerprint {

    private TcpFingerprint() {
    }

    // =====================================================================
    // 指纹数据库（tcpfingerprint.go:19-299）
    // =====================================================================

    /** OSFingerprintDB 操作系统指纹数据库 (参考nmap-os-db)。 */
    static final class OSFingerprintDB {
        final OSFingerprintEntry[] entries;

        OSFingerprintDB(OSFingerprintEntry[] entries) {
            this.entries = entries;
        }
    }

    /**
     * 单个OS指纹条目。Go 的 {@code SACK/Timestamps *bool}：null=不关心；
     * {@code WindowShifts []int}：空=不关心。
     */
    static final class OSFingerprintEntry {
        final String name;
        final int[] ttlRange;
        final int[] windowSizes;
        final int[] mssValues;
        final int[] windowShifts;
        final Boolean sack;
        final Boolean timestamps;
        final double weight;

        OSFingerprintEntry(String name, int ttlMin, int ttlMax, int[] windowSizes,
                           int[] mssValues, int[] windowShifts, Boolean sack,
                           Boolean timestamps, double weight) {
            this.name = name;
            this.ttlRange = new int[]{ttlMin, ttlMax};
            this.windowSizes = windowSizes;
            this.mssValues = mssValues;
            this.windowShifts = windowShifts;
            this.sack = sack;
            this.timestamps = timestamps;
            this.weight = weight;
        }
    }

    /** Go: var defaultOSFingerprintDB *OSFingerprintDB + getOSFingerprintDB() 惰性单次构建。 */
    private static final OSFingerprintDB DEFAULT_OS_FINGERPRINT_DB = buildOSFingerprintDB();

    static OSFingerprintDB getOSFingerprintDB() {
        return DEFAULT_OS_FINGERPRINT_DB;
    }

    static OSFingerprintDB buildOSFingerprintDB() {
        return new OSFingerprintDB(new OSFingerprintEntry[]{
                // ===== Windows 系列 =====
                new OSFingerprintEntry(
                        "Microsoft Windows 10/11",
                        128, 128, new int[]{64240, 65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "Microsoft Windows Server 2016/2019/2022",
                        128, 128, new int[]{8192, 16384, 65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "Microsoft Windows Server 2012 R2",
                        128, 128, new int[]{65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "Microsoft Windows 8.1",
                        128, 128, new int[]{65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "Microsoft Windows 7/Server 2008 R2",
                        128, 128, new int[]{65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "Microsoft Windows XP/Server 2003",
                        128, 128, new int[]{65535}, new int[]{1460},
                        new int[]{}, true, false, 1.0),

                // ===== Linux 系列 =====
                new OSFingerprintEntry(
                        "Linux 5.x/6.x (Ubuntu/Debian/Fedora)",
                        64, 64, new int[]{29200, 28960, 65535, 14600}, new int[]{1460},
                        new int[]{7, 8, 10, 12}, true, true, 1.0),
                new OSFingerprintEntry(
                        "Linux 4.x (Ubuntu/CentOS)",
                        64, 64, new int[]{29200, 14600, 28960}, new int[]{1460},
                        new int[]{7, 8, 10}, true, true, 1.0),
                new OSFingerprintEntry(
                        "Linux 3.x (CentOS/RHEL)",
                        64, 64, new int[]{14600, 28960, 5840, 8760}, new int[]{1460},
                        new int[]{7, 8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "Linux 2.6.x (Old CentOS/RHEL)",
                        64, 64, new int[]{5840, 8760, 14600}, new int[]{1460, 496},
                        new int[]{7, 8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "Linux (Android)",
                        64, 64, new int[]{5840, 29200}, new int[]{1460},
                        new int[]{7, 11}, true, true, 1.0),
                new OSFingerprintEntry(
                        "Linux (Embedded/IoT)",
                        64, 64, new int[]{14600, 29200, 5840}, new int[]{1460, 536},
                        new int[]{7, 8}, true, true, 0.8),

                // ===== BSD/macOS 系列 =====
                new OSFingerprintEntry(
                        "Apple macOS 11/12/13",
                        64, 64, new int[]{65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "FreeBSD 12/13",
                        64, 64, new int[]{65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "OpenBSD 7.x",
                        64, 64, new int[]{16384, 65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),

                // ===== 网络设备 =====
                new OSFingerprintEntry(
                        "Cisco IOS/IOS-XE",
                        255, 255, new int[]{4128, 8192, 16384, 4160}, new int[]{1460, 536},
                        new int[]{}, false, false, 1.0),
                new OSFingerprintEntry(
                        "Cisco IOS-XR/NX-OS",
                        255, 255, new int[]{65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "Juniper JunOS",
                        64, 255, new int[]{16384, 65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "Huawei VRP",
                        64, 255, new int[]{16384, 65535, 8192}, new int[]{1460, 1440},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "MikroTik RouterOS",
                        64, 128, new int[]{16384, 65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),

                // ===== 其他 =====
                new OSFingerprintEntry(
                        "Solaris/illumos",
                        255, 255, new int[]{24820, 65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "AIX",
                        255, 255, new int[]{16384, 65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "HP-UX",
                        255, 255, new int[]{32768, 65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
                new OSFingerprintEntry(
                        "VMware ESXi",
                        64, 128, new int[]{65535}, new int[]{1460},
                        new int[]{8}, true, true, 1.0),
        });
    }

    // =====================================================================
    // SYN 抓包采集（tcpfingerprint_linux.go；Windows stub → null）
    // =====================================================================

    /**
     * 发送 SYN 抓取目标端口的 TCP/IP 栈指纹。
     *
     * @return 指纹；不可采集（非 IPv4 / 权限不足 / 超时）时返回 {@code null}
     */
    public static TCPStackFingerprint captureSynFingerprint(String ip, int port,
                                                            Duration timeout) {
        if (SystemUtil.isWindows()) {
            // tcpfingerprint_windows.go: Windows 无 raw socket → 恒 nil
            return null;
        }

        // Go: dstIP := net.ParseIP(ip); if dstIP == nil || dstIP.To4() == nil → nil
        byte[] dstIP = RawScanEngine.parseIPv4(ip);
        if (dstIP == null) {
            return null;
        }

        byte[] srcIP = RawScanEngine.localIPFor(ip);
        // Go: srcPort := uint16(rand.Intn(50000) + 10000)
        int srcPort = ThreadLocalRandom.current().nextInt(50000) + 10000;

        RawScanEngine.LibcApi api = RawScanEngine.libc();
        if (api == null) {
            return captureViaConnect(ip, port, timeout);
        }

        // raw socket 发送 SYN（IPPROTO_RAW + IP_HDRINCL）
        int sendFd = api.socket(RawScanEngine.AF_INET, RawScanEngine.SOCK_RAW,
                RawScanEngine.IPPROTO_RAW);
        if (sendFd < 0) {
            return captureViaConnect(ip, port, timeout);
        }
        try {
            Memory hdrincl = new Memory(4);
            hdrincl.setInt(0, 1);
            api.setsockopt(sendFd, RawScanEngine.IPPROTO_IP, RawScanEngine.IP_HDRINCL,
                    hdrincl, 4);

            // raw socket 接收 SYN-ACK
            int recvFd = api.socket(RawScanEngine.AF_INET, RawScanEngine.SOCK_RAW,
                    RawScanEngine.IPPROTO_TCP);
            if (recvFd < 0) {
                return captureViaConnect(ip, port, timeout);
            }
            try {
                // Go 每轮重设 {Sec:0, Usec:200000}；建连时设一次等效
                RawScanEngine.setRecvTimeout(api, recvFd, 200);

                // Go: tcpSeq := rand.Uint32()
                int tcpSeq = ThreadLocalRandom.current().nextInt();
                byte[] synPkt = RawScanEngine.buildSynPacket(srcIP, dstIP, srcPort, port, tcpSeq);

                Memory pkt = new Memory(synPkt.length);
                pkt.write(0, synPkt, 0, synPkt.length);
                Pointer dstAddr = RawScanEngine.buildSockaddr(dstIP, port);
                if (api.sendto(sendFd, pkt, synPkt.length, 0, dstAddr, 16) < 0) {
                    return captureViaConnect(ip, port, timeout);
                }

                // 等待 SYN-ACK 响应
                byte[] buf = new byte[1500];
                Memory recvBuf = new Memory(1500);
                Memory srcAddr = new Memory(16);
                Memory srcLen = new Memory(4);
                long deadline = System.nanoTime()
                        + Math.max(0L, RawScanEngine.toMillis(timeout)) * 1_000_000L;

                while (System.nanoTime() < deadline) {
                    srcLen.setInt(0, 16);
                    int n = api.recvfrom(recvFd, recvBuf, 1500, 0, srcAddr, srcLen);
                    if (n < 40) {
                        // 超时或残缺 → Go: err != nil || n < 40 → continue
                        continue;
                    }
                    if (n > buf.length) {
                        n = buf.length;
                    }
                    recvBuf.read(0, buf, 0, n);

                    // 解析 IP 头
                    int ipHeaderLen = (buf[0] & 0x0F) * 4;
                    if (n < ipHeaderLen + 20) {
                        continue;
                    }
                    int ttl = buf[8] & 0xff;

                    // 验证源 IP
                    if (buf[12] != dstIP[0] || buf[13] != dstIP[1]
                            || buf[14] != dstIP[2] || buf[15] != dstIP[3]) {
                        continue;
                    }

                    // 解析 TCP 头
                    int t = ipHeaderLen;
                    int respSrcPort = RawScanEngine.u16(buf, t);
                    int respDstPort = RawScanEngine.u16(buf, t + 2);
                    int respFlags = buf[t + 13] & 0xff;
                    int respWindow = RawScanEngine.u16(buf, t + 14);

                    // 验证是 SYN-ACK 响应
                    if (respSrcPort != (port & 0xffff) || respDstPort != srcPort) {
                        continue;
                    }
                    if ((respFlags & (RawScanEngine.tcpSYN | RawScanEngine.tcpACK))
                            != (RawScanEngine.tcpSYN | RawScanEngine.tcpACK)) {
                        continue;
                    }

                    // 发送 RST 关闭连接
                    RawScanEngine.sendRSTViaRaw(srcIP, dstIP, srcPort, port, tcpSeq + 1);

                    // 构建指纹
                    TCPStackFingerprint fp = new TCPStackFingerprint();
                    fp.ttl = ttl;
                    fp.windowSize = respWindow;

                    // 解析 TCP 选项
                    int tcpDataOffset = ((buf[t + 12] >> 4) & 0x0F) * 4;
                    if (tcpDataOffset > 20 && n >= ipHeaderLen + tcpDataOffset) {
                        byte[] tcpOptions = Arrays.copyOfRange(buf, t + 20, t + tcpDataOffset);
                        parseTCPOptions(tcpOptions, fp);
                    }
                    return fp;
                }

                // 超时：发送 RST 清理
                RawScanEngine.sendRSTViaRaw(srcIP, dstIP, srcPort, port, tcpSeq + 1);
                return null;
            } finally {
                api.close(recvFd);
            }
        } finally {
            api.close(sendFd);
        }
    }

    /**
     * Go: captureViaConnect —— raw socket 不可用时的降级方案。
     * 普通 TCP 连接拿不到 TCP 选项，因此 dial 成功与否都返回 null，
     * 让调用方降级到其他检测方法。
     */
    private static TCPStackFingerprint captureViaConnect(String ip, int port, Duration timeout) {
        try (Socket conn = new Socket()) {
            long ms = RawScanEngine.toMillis(timeout);
            if (ms < 0) {
                // Go: 过期 deadline → DialTimeout 立刻报错 → nil
                return null;
            }
            conn.connect(new InetSocketAddress(ip, port),
                    (int) Math.min(ms, Integer.MAX_VALUE));
        } catch (IOException e) {
            // Go: DialTimeout 出错 → nil
            return null;
        }
        return null;
    }

    // =====================================================================
    // TCP 选项解析（tcpfingerprint.go:305-353）
    // =====================================================================

    /** parseTCPOptions 解析TCP选项字段。 */
    static void parseTCPOptions(byte[] options, TCPStackFingerprint fp) {
        int i = 0;
        while (i < options.length) {
            int optionType = options[i] & 0xff;

            switch (optionType) {
                case 0: // End of Options
                    return;
                case 1: // NOP
                    i++;
                    continue;
                case 2: { // MSS
                    if (i + 4 > options.length) {
                        return;
                    }
                    fp.mss = RawScanEngine.u16(options, i + 2);
                    i += 4;
                    break;
                }
                case 3: { // Window Scaling
                    if (i + 3 > options.length) {
                        return;
                    }
                    fp.windowShift = options[i + 2] & 0xff;
                    i += 3;
                    break;
                }
                case 4: { // SACK Permitted
                    fp.sackPermitted = true;
                    if (i + 2 > options.length) {
                        return;
                    }
                    i += 2;
                    break;
                }
                case 8: { // Timestamps
                    fp.timestamps = true;
                    if (i + 10 > options.length) {
                        return;
                    }
                    i += 10;
                    break;
                }
                default: {
                    // 未知选项, 尝试跳过
                    if (i + 1 >= options.length) {
                        return;
                    }
                    int optLen = options[i + 1] & 0xff;
                    if (optLen < 2 || i + optLen > options.length) {
                        return;
                    }
                    i += optLen;
                    break;
                }
            }
        }
    }

    // =====================================================================
    // 指纹匹配（tcpfingerprint.go:355-466）
    // =====================================================================

    /**
     * 按指纹库匹配操作系统。
     *
     * @return {@code [0]=OS 名，[1]=匹配度}；未知返回 {@code ["Unknown", 0]}。
     *         对应 Go 的 {@code MatchOSFingerprint(fp) (string, float64)}，
     *         Java 用二元数组以贴合 Go 的多返回值（见 scan.go:1194 的用法）。
     */
    public static Object[] matchOSFingerprint(TCPStackFingerprint fp) {
        if (fp == null) {
            return new Object[]{"Unknown", 0.0};
        }

        OSFingerprintDB db = getOSFingerprintDB();
        String bestName = "Unknown";
        double bestScore = 0.0;

        for (OSFingerprintEntry entry : db.entries) {
            double score = calculateFingerprintScore(fp, entry);
            if (score > bestScore) {
                bestScore = score;
                bestName = entry.name;
            }
        }

        return new Object[]{bestName, bestScore};
    }

    /** 便捷取值：{@code matchOSFingerprint}[0]，null-safe。 */
    public static String matchOSFingerprintName(TCPStackFingerprint fp) {
        Object[] r = matchOSFingerprint(fp);
        return r == null || r[0] == null ? "Unknown" : (String) r[0];
    }

    /** 便捷取值：{@code matchOSFingerprint}[1]，null-safe。 */
    public static double matchOSFingerprintScore(TCPStackFingerprint fp) {
        Object[] r = matchOSFingerprint(fp);
        return r == null || !(r[1] instanceof Double) ? 0d : (Double) r[1];
    }

    /** Go: calculateFingerprintScore —— 计算指纹匹配分数 (0.0 - 1.0)。 */
    static double calculateFingerprintScore(TCPStackFingerprint fp, OSFingerprintEntry entry) {
        double score = 0.0;
        double totalWeight = 0.0;

        // TTL匹配 (权重: 0.30)
        totalWeight += 0.30;
        if (fp.ttl >= entry.ttlRange[0] && fp.ttl <= entry.ttlRange[1]) {
            score += 0.30;
        } else {
            // TTL接近也算部分分
            int diff = fp.ttl - entry.ttlRange[0];
            if (diff < 0) {
                diff = -diff;
            }
            if (diff <= 32) {
                score += 0.10 * (1.0 - diff / 32.0);
            }
        }

        // 窗口大小匹配 (权重: 0.25)
        totalWeight += 0.25;
        if (entry.windowSizes.length > 0) {
            for (int ws : entry.windowSizes) {
                if (fp.windowSize == ws) {
                    score += 0.25;
                    break;
                }
            }
            // 如果精确匹配失败, 看范围接近。
            // 注意：Go 侧的判断是「累计得分 < 0.30」（含 TTL 已得分），
            // 此处逐行保留该行为（TTL 精确命中时会跳过范围判定）。
            if (score < 0.30) {
                int minWs = entry.windowSizes[0];
                int maxWs = entry.windowSizes[0];
                for (int w : entry.windowSizes) {
                    if (w < minWs) {
                        minWs = w;
                    }
                    if (w > maxWs) {
                        maxWs = w;
                    }
                }
                if (fp.windowSize >= minWs && fp.windowSize <= maxWs) {
                    score += 0.15;
                }
            }
        }

        // MSS匹配 (权重: 0.20)
        totalWeight += 0.20;
        if (entry.mssValues.length > 0) {
            for (int mss : entry.mssValues) {
                if (fp.mss == mss) {
                    score += 0.20;
                    break;
                }
            }
        }

        // 窗口缩放匹配 (权重: 0.10)
        totalWeight += 0.10;
        if (entry.windowShifts.length > 0 && fp.windowShift >= 0) {
            for (int ws : entry.windowShifts) {
                if (fp.windowShift == ws) {
                    score += 0.10;
                    break;
                }
            }
        }

        // SACK匹配 (权重: 0.075)
        totalWeight += 0.075;
        if (entry.sack != null && fp.sackPermitted == entry.sack) {
            score += 0.075;
        }

        // 时间戳匹配 (权重: 0.075)
        totalWeight += 0.075;
        if (entry.timestamps != null && fp.timestamps == entry.timestamps) {
            score += 0.075;
        }

        if (totalWeight > 0) {
            score = score / totalWeight * entry.weight;
        }

        return score;
    }
}

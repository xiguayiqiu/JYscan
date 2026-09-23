package space.jyscan.modules.nmap;

import space.jyscan.core.util.Fmt;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 操作系统识别引擎，移植自 freeclient/internal/nmap/scan.go：
 * {@code osDetection}(1184) / {@code normalizeOSFamily}(1268) /
 * {@code CaptureSynFingerprintByPort}(1296) / {@code detectOSByTTL}(1319) /
 * {@code getTTLByPing}(1329) / {@code getTTLByRawICMP}(1348) / {@code classifyTTL}(1391) /
 * {@code detectOSByServiceCombination}(1406) / {@code detectSMBVersion}(1464) /
 * {@code negotiateSMB}(1494) / {@code negotiateSMB1}(1594) /
 * {@code detectWindowsVersion}(1691) / {@code detectLinuxVersion}(1747) /
 * {@code detectOSByBanner}(1785) / {@code detectWindowsVersionFromBanner}(1813) /
 * {@code detectLinuxVersionFromBanner}(1843) / {@code detectBSDVersionFromBanner}(1872) /
 * {@code detectIISVersionFromBanner}(1889) / {@code aggressiveOSDetection}(1915) /
 * {@code detectOSByTCPFingerprint}(1943) / {@code removeDuplicateOSGuesses}(1965) /
 * {@code calculateChecksum}(2119)。
 *
 * <p><b>归属</b>：本文件由 B 号子代理新建。只被
 * {@code NmapScan.scanOneHost} 的 {@code osDetection} 分支调用
 * （对应 Go {@code NmapScanOptimized} → {@code osDetection}，
 * scan_optimized.go:705 {@code result.OS = osDetection(ip, portResults)}）。
 *
 * <p><b>与 Go 的差异（已记录）</b>：
 * <ul>
 *   <li>{@code getTTLByRawICMP} 依赖 raw {@code ip4:icmp} socket（JVM 不可移植），
 *       恒返回失败 —— {@link #detectOSByTTL} 因此只剩系统 ping 一条路
 *       （对应 Go 的优先路径，raw ICMP 在 Go 侧也只是降级兜底）；</li>
 *   <li>{@code osDetection} 的加权投票 Go 用随机序 map 遍历（平局结果随机会变），
 *       Java 用 {@link LinkedHashMap} 固定为「首个达到该分数的猜测」胜出
 *       —— 确定性输出，属记录在案的偏差；</li>
 *   <li>{@code detectOSByBanner} 的端口遍历 Go 是随机序 map，Java 按端口升序
 *       （{@link ScanEngine#orderedCopy}）；</li>
 *   <li>SMB 探测失败/超时语义与 Go 一致（3s dial + 3s deadline），
 *       但 TCP 栈无「半开连接」概念 —— Go 侧同样是普通 dial，行为等价。</li>
 * </ul>
 */
final class OsEngine {

    private OsEngine() {
    }

    // =========================================================================
    // scan.go:1184 osDetection —— 加权投票主流程
    // =========================================================================

    /** 对应 Go 的 {@code osGuess}（scan.go:1186）。 */
    private record Guess(String name, double score) {
    }

    /** 对应 Go 的 {@code osVote}（scan.go:1226）。 */
    private static final class OsVote {
        final String family;
        String name;
        double score;
        int count;

        OsVote(String family, String name, double score, int count) {
            this.family = family;
            this.name = name;
            this.score = score;
            this.count = count;
        }
    }

    /**
     * 对应 Go 的 {@code osDetection(ip, ports)}（scan.go:1184）：五路猜测加权投票。
     *
     * <p>顺序固定为：TCP/IP 栈指纹 → banner → 主动探测 → TTL → 服务组合，
     * 分别记  {@code MatchOSFingerprint 得分} / 0.85 / 0.80 / 0.50 / 0.40。
     *
     * <p><b>Go 怪癖逐条保留</b>：
     * <ul>
     *   <li>代表名替换条件 {@code g.score > v.score - (v.count-1)*0.5} 中的
     *       {@code v.score} <b>已含本条 g.score</b>（Go 先累加再判断），照抄；</li>
     *   <li>综合得分平局时 {@code v.score+bonus > best...} 是<b>严格大于</b>，
     *       首个达到该值的族胜出（Go 为随机序，Java 取插入序第一个）。</li>
     * </ul>
     */
    static String osDetection(String ip, Map<Integer, PortInfo> ports) {
        List<Guess> guesses = new ArrayList<>();

        // 1. TCP/IP栈指纹 (最准确: TTL+窗口大小+MSS+TCP选项)
        TCPStackFingerprint fp = CaptureSynFingerprintByPort(ip, ports);
        if (fp != null) {
            Object[] r = TcpFingerprint.matchOSFingerprint(fp);
            String name = r == null || r.length == 0 ? null : (String) r[0];
            if (name != null && !"Unknown".equals(name)) {
                double score = r.length > 1 && r[1] instanceof Number ? ((Number) r[1]).doubleValue() : 0;
                guesses.add(new Guess(name, score));
            }
        }

        // 2. 基于banner信息进行识别
        String os = detectOSByBanner(ports);
        if (!"Unknown".equals(os)) {
            guesses.add(new Guess(os, 0.85));
        }

        // 3. 主动探测 HTTP Server 头和 SSH banner
        os = OsDetect.probeOSByActiveProbe(ip, ports);
        if (!"Unknown".equals(os)) {
            guesses.add(new Guess(os, 0.80));
        }

        // 4. 基于TTL值进行操作系统识别
        os = detectOSByTTL(ip);
        if (!"Unknown".equals(os)) {
            guesses.add(new Guess(os, 0.50));
        }

        // 5. 基于服务组合进行识别 (仅作为兜底)
        os = detectOSByServiceCombination(ip, ports);
        if (!"Unknown".equals(os)) {
            guesses.add(new Guess(os, 0.40));
        }

        if (guesses.isEmpty()) {
            return "Unknown";
        }

        // 加权投票: 多种方法指向同一OS族时提高置信度
        // Go: map[string]*osVote —— 随机序；Java: LinkedHashMap（插入序，见类注释）
        Map<String, OsVote> votes = new LinkedHashMap<>();
        for (Guess g : guesses) {
            String family = normalizeOSFamily(g.name);
            OsVote v = votes.get(family);
            if (v != null) {
                v.score += g.score;
                v.count++;
                // 保留最高分的名称作为代表（Go 先累加后判断，v.score 已含 g.score）
                if (g.score > v.score - (v.count - 1) * 0.5) {
                    v.name = g.name;
                }
            } else {
                votes.put(family, new OsVote(family, g.name, g.score, 1));
            }
        }

        // 选择综合得分最高的OS族
        OsVote best = null;
        for (OsVote v : votes.values()) {
            // 多种方法一致时加成
            double bonus = (v.count - 1) * 0.15;
            if (best == null || v.score + bonus > best.score + (best.count - 1) * 0.15) {
                best = v;
            }
        }

        return best == null ? "Unknown" : best.name;
    }

    /**
     * 对应 Go 的 {@code normalizeOSFamily(name)}（scan.go:1268）：
     * 归一化为 OS 族（Windows/Linux/BSD/macOS/Cisco/Juniper/Huawei/Solaris），
     * 未命中时原样返回 name（Go 的 {@code default: return name}）。
     */
    static String normalizeOSFamily(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.contains("windows")) {
            return "Windows";
        }
        if (lower.contains("linux") || lower.contains("ubuntu")
                || lower.contains("centos") || lower.contains("debian")
                || lower.contains("fedora") || lower.contains("red hat")
                || lower.contains("android")) {
            return "Linux";
        }
        if (lower.contains("freebsd") || lower.contains("openbsd")
                || lower.contains("netbsd") || lower.contains("macos")
                || lower.contains("mac os")) {
            return "BSD/macOS";
        }
        if (lower.contains("cisco")) {
            return "Cisco";
        }
        if (lower.contains("juniper")) {
            return "Juniper";
        }
        if (lower.contains("huawei")) {
            return "Huawei";
        }
        if (lower.contains("solaris")) {
            return "Solaris";
        }
        return name;
    }

    // =========================================================================
    // scan.go:1296-1403 —— TCP 指纹采集与 TTL 识别
    // =========================================================================

    /** 对应 Go 的 {@code priorityPorts} 切片（scan.go:1298）。 */
    private static final int[] FINGERPRINT_PRIORITY_PORTS = {
        443, 80, 22, 8080, 445, 3389, 21, 25, 53, 110, 143, 3306, 5432, 6379,
    };

    /**
     * 对应 Go 的 {@code CaptureSynFingerprintByPort(ip, ports)}（scan.go:1296）：
     * 先在<b>已扫出的端口</b>里按优先级用 2s 超时采集，全部失败再对同一批端口
     * 用 1s 超时兜底一轮，仍失败返回 null（Go: nil）。
     */
    static TCPStackFingerprint CaptureSynFingerprintByPort(String ip, Map<Integer, PortInfo> ports) {
        for (int port : FINGERPRINT_PRIORITY_PORTS) {
            if (ports.containsKey(port)) {
                TCPStackFingerprint fp =
                        TcpFingerprint.captureSynFingerprint(ip, port, Duration.ofSeconds(2));
                if (fp != null) {
                    return fp;
                }
            }
        }

        // 如果所有已知开放端口都失败, 尝试常见端口
        for (int port : FINGERPRINT_PRIORITY_PORTS) {
            TCPStackFingerprint fp = TcpFingerprint.captureSynFingerprint(ip, port, Duration.ofSeconds(1));
            if (fp != null) {
                return fp;
            }
        }
        return null;
    }

    /**
     * 对应 Go 的 {@code detectOSByTTL(ip)}（scan.go:1319）：
     * 优先系统 ping，降级 raw ICMP。<b>raw ICMP 不移植</b>（JVM 无 ip4:icmp socket），
     * 故只剩 ping 路径 —— 记录在案的偏差（见类注释）。
     */
    static String detectOSByTTL(String ip) {
        Integer ttl = getTTLByPing(ip);
        if (ttl != null) {
            return classifyTTL(ttl);
        }
        // Go: if ttl, ok := getTTLByRawICMP(ip); ok { ... } —— Java 恒不可用
        Integer ttlRaw = getTTLByRawICMP(ip);
        if (ttlRaw != null) {
            return classifyTTL(ttlRaw);
        }
        return "Unknown";
    }

    /**
     * 对应 Go 的 {@code getTTLByPing(ip)}（scan.go:1329）：
     * {@code ping -c 1 -W 2 <ip>}（固定 2s，<b>不是</b> config.timeout），
     * 在输出里找小写 {@code ttl=}（Go: {@code strings.Index(line, "ttl=")}，
     * <b>大小写敏感</b> —— Windows ping 的 {@code TTL=} 不会命中，与 Go 相同），
     * 解析 1..255 的十进制数字。返回 null 表示 {@code ok == false}。
     */
    static Integer getTTLByPing(String ip) {
        SysExec.Result r = SysExec.output(null, "ping", "-c", "1", "-W", "2", ip);
        if (!r.ok()) {
            return null;
        }
        for (String line : r.output().split("\n", -1)) {
            int idx = line.indexOf("ttl=");
            if (idx == -1) {
                continue;
            }
            String ttlStr = line.substring(idx + 4);
            int end = 0;
            while (end < ttlStr.length() && ttlStr.charAt(end) >= '0' && ttlStr.charAt(end) <= '9') {
                end++;
            }
            if (end > 0) {
                try {
                    int ttlVal = Integer.parseInt(ttlStr.substring(0, end));
                    if (ttlVal > 0 && ttlVal <= 255) {
                        return ttlVal;
                    }
                } catch (NumberFormatException e) {
                    // Go: strconv.Atoi 失败继续（数字串全为数字，实际不触发）
                    continue;
                }
            }
        }
        return null;
    }

    /**
     * 对应 Go 的 {@code getTTLByRawICMP(ip)}（scan.go:1348）。
     *
     * <p><b>不移植</b>：Go 用 {@code net.DialTimeout("ip4:icmp", ...)} 发 raw ICMP
     * Echo 并解析 TTL，JVM 无对应 API（需 raw socket / NIO icmp unsupported）。
     * 恒返回 null（= Go 的 {@code ok == false}），调用方自动走 {@code "Unknown"}。
     * {@link #calculateChecksum} 按 Go 原样保留，供后续接 JNI/原生实现时使用。
     */
    static Integer getTTLByRawICMP(String ip) {
        // TODO(B): raw ICMP 未移植 —— Go 的 ip4:icmp socket 在 JVM 不可用
        return null;
    }

    /**
     * 对应 Go 的 {@code classifyTTL(ttl)}（scan.go:1391）：
     * {@code <=64 → Linux/Unix}、{@code <=128 → Windows}、{@code <=255 → Solaris/FreeBSD}、
     * 其余 {@code Unknown}（Go 参数是 uint8，default 分支实际不可达；
     * Java 侧入参已由 {@link #getTTLByPing} 夹在 1..255，语义相同）。
     */
    static String classifyTTL(int ttl) {
        if (ttl <= 64) {
            return "Linux/Unix";
        }
        if (ttl <= 128) {
            return "Windows";
        }
        if (ttl <= 255) {
            return "Solaris/FreeBSD";
        }
        return "Unknown";
    }

    // =========================================================================
    // scan.go:1406-1782 —— 服务组合 / SMB 协商 / Windows、Linux 版本
    // =========================================================================

    /**
     * 对应 Go 的 {@code detectOSByServiceCombination(ip, ports)}（scan.go:1406）。
     *
     * <p>判定顺序照抄：RDP 强特征 → (SMB+NetBIOS+MSRPC)|(SMB+MSRPC) →
     * SSH 且无 RDP → (HTTP|HTTPS) 且无 RDP/SSH → Unknown。
     * 注释同 Go：避免 Linux Samba 误判为 Windows。
     */
    static String detectOSByServiceCombination(String ip, Map<Integer, PortInfo> ports) {
        boolean hasHttp = false;
        boolean hasHttps = false;
        boolean hasSsh = false;
        boolean hasRdp = false;
        boolean hasSmb = false;
        boolean hasNetbios = false;
        boolean hasMsrpc = false;

        for (Integer port : ports.keySet()) {
            switch (port) {
                case 80 -> hasHttp = true;
                case 443 -> hasHttps = true;
                case 22 -> hasSsh = true;
                case 3389 -> hasRdp = true;
                case 445 -> hasSmb = true;
                case 139 -> hasNetbios = true;
                case 135 -> hasMsrpc = true;
                default -> {
                    // Go: default 空分支
                }
            }
        }

        // Windows系统特征识别: RDP(3389)是Windows的强特征
        if (hasRdp) {
            return detectWindowsVersion(ip, ports);
        }
        // 多个Windows特有端口同时开放时才判定为Windows (避免Linux Samba误判)
        if ((hasSmb && hasNetbios && hasMsrpc) || (hasSmb && hasMsrpc)) {
            return detectWindowsVersion(ip, ports);
        }

        // Linux/Unix系统特征识别
        if (hasSsh && !hasRdp) {
            return detectLinuxVersion(ports);
        }

        // Web服务器通常运行在Linux上
        if ((hasHttp || hasHttps) && !hasRdp && !hasSsh) {
            return "Linux/Unix (Web Server)";
        }

        return "Unknown";
    }

    /** 对应 Go 的 {@code detectSMBVersion} 返回值语义（{@code (string, error)}）。 */
    private record SmbOutcome(String version, String error) {
    }

    /**
     * 对应 Go 的 {@code detectSMBVersion(ip, ports)}（scan.go:1464）：
     * 仅当 445 在扫描结果里才协商；先 SMB2 失败再 SMB1；
     * 方言 → Windows 版本映射照抄（SMB 2.0.2→Vista … 3.1.1→Win10/11），
     * 未知方言返回 "Windows"。
     */
    static String detectSMBVersion(String ip, Map<Integer, PortInfo> ports) {
        if (!ports.containsKey(445)) {
            return "";
        }

        SmbOutcome out = negotiateSMB(ip, 445);
        String smbVer = out.version();
        String err = out.error();
        if (err != null || smbVer == null || smbVer.isEmpty()) {
            out = negotiateSMB1(ip, 445);
            smbVer = out.version();
            err = out.error();
        }
        if (err != null || smbVer == null || smbVer.isEmpty()) {
            return "";
        }

        switch (smbVer) {
            case "3.1.1":
                return "Windows 10/11/Server 2016+";
            case "3.0.2":
                return "Windows 8.1/Server 2012 R2";
            case "3.0":
                return "Windows 8/Server 2012";
            case "2.1":
                return "Windows 7/Server 2008 R2";
            case "2.0.2":
                return "Windows Vista/Server 2008";
            default:
                return "Windows";
        }
    }

    /** Go: {@code net.DialTimeout(..., 3*time.Second)}。 */
    private static final int SMB_DIAL_TIMEOUT_MS = 3000;

    /**
     * 对应 Go 的 {@code negotiateSMB(ip, port)}（scan.go:1494）：发 SMB2 Negotiate、
     * 解析响应 dialect。
     *
     * <p><b>Go 怪癖逐条保留</b>：
     * <ul>
     *   <li>地址用 {@code fmt.Sprintf("%s:%d", ip, port)}（<b>IPv6 不加方括号</b>，
     *       与 {@link ScanEngine#formatIPForConnection} 相反 —— IPv6 下 Go 的
     *       Dial 直接失败走 SMB1/返回空，Java 侧用同样的不带方括号拼接做
     *       host，让解析失败语义等价）；</li>
     *   <li>请求 110 字节：SMB2 header(64) + body，dialect 5 组写在 body[32..41]，
     *       其中 SMB 2.1 那组 Go 写的是 {@code 0x21,0x02}（LE 值 0x0221，
     *       注释却说 0x0210 —— 照抄该错误字节）；</li>
     *   <li>响应解析：dialect 在 {@code offset+68}，未知方言返回
     *       {@code fmt.Sprintf("SMB2-%d.%d", dialect&0xff, dialect>>8)}
     *       （低字节在前，同样是 Go 的原始行为）。</li>
     * </ul>
     */
    static SmbOutcome negotiateSMB(String ip, int port) {
        try (Socket conn = new Socket()) {
            conn.connect(dialAddress(ip, port), SMB_DIAL_TIMEOUT_MS);
            conn.setSoTimeout(SMB_DIAL_TIMEOUT_MS);

            // 构建 SMB2 Negotiate Request（SMB2 header 64 + Negotiate body 36+10 = 110）
            byte[] pkt = new byte[110];

            // --- SMB2 header (64 bytes, offset 0..63) ---
            pkt[0] = (byte) 0xfe;
            pkt[1] = 0x53;  // 'S'
            pkt[2] = 0x4d;  // 'M'
            pkt[3] = 0x42;  // 'B'
            pkt[4] = 64;    // HeaderLength
            pkt[12] = 0x01; // Command = Negotiate
            // 其余（CreditCharge/Status/Flags/MessageId/TreeId/SessionId/Signature）全 0

            // --- Negotiate body (46 bytes from offset 64) ---
            pkt[64] = 0x24; // StructureSize (36)
            pkt[65] = 0x00;
            pkt[66] = 5;    // DialectCount
            pkt[67] = 0x00;
            pkt[68] = 0x01; // SecurityMode: Signing
            pkt[69] = 0x00;
            // body[6..31] 保留 0（Reserved/Capabilities/GUID/contexts）
            // Dialects at body[32..41] → pkt[96..105]
            pkt[96] = 0x02;
            pkt[97] = 0x02; // SMB 2.0.2
            pkt[98] = 0x21; // Go 写 0x21,0x02（注释称 SMB 2.1，LE 值实为 0x0221）—— 照抄
            pkt[99] = 0x02;
            pkt[100] = 0x00;
            pkt[101] = 0x03; // SMB 3.0
            pkt[102] = 0x02;
            pkt[103] = 0x03; // SMB 3.0.2
            pkt[104] = 0x11;
            pkt[105] = 0x03; // SMB 3.1.1

            conn.getOutputStream().write(pkt);

            byte[] buf = new byte[4096];
            int n = conn.getInputStream().read(buf);
            if (n < 4) {
                return new SmbOutcome("", "no SMB response");
            }

            // 跳过NetBIOS头 (仅端口139有, 端口445没有)
            int offset = 0;
            if (buf[0] == 0x00 && n >= 8 && (buf[4] & 0xff) == 0xfe && (buf[5] & 0xff) == 0x53) {
                offset = 4; // 有NetBIOS头
            }
            if ((buf[offset] & 0xff) == 0xfe && (buf[offset + 1] & 0xff) == 0x53
                    && (buf[offset + 2] & 0xff) == 0x4d && (buf[offset + 3] & 0xff) == 0x42) {
                // SMB2 Response: Dialect at header(64) + body_start(4) = offset + 68
                int dialectOffset = offset + 68;
                if (n >= dialectOffset + 2) {
                    int dialect = (buf[dialectOffset] & 0xff) | ((buf[dialectOffset + 1] & 0xff) << 8);
                    switch (dialect) {
                        case 0x0202:
                            return new SmbOutcome("2.0.2", null);
                        case 0x0210:
                            return new SmbOutcome("2.1", null);
                        case 0x0300:
                            return new SmbOutcome("3.0", null);
                        case 0x0302:
                            return new SmbOutcome("3.0.2", null);
                        case 0x0311:
                            return new SmbOutcome("3.1.1", null);
                        default:
                            return new SmbOutcome(
                                    Fmt.format("SMB2-%d.%d", dialect & 0xff, dialect >>> 8), null);
                    }
                }
            }
            // SMB1 signature: \xffSMB
            if ((buf[offset] & 0xff) == 0xff && buf[offset + 1] == 'S'
                    && buf[offset + 2] == 'M' && buf[offset + 3] == 'B') {
                return new SmbOutcome("1.0", null);
            }
            return new SmbOutcome("", "invalid SMB response");
        } catch (IOException e) {
            return new SmbOutcome("", e.getMessage() == null ? e.toString() : e.getMessage());
        }
    }

    /**
     * 对应 Go 的 {@code negotiateSMB1(ip, port)}（scan.go:1594）：
     * SMB1 Negotiate（不需要签名）。
     *
     * <p><b>Go 怪癖逐条保留</b>：
     * <ul>
     *   <li>包长固定 {@code 4+32+28 = 64}，但 {@code copy(pkt[31:], dialects)}
     *       只会拷入 {@code min(64-31, 125) = 33} 字节 —— 125 字节方言表
     *       <b>只发出前 33 字节</b>；</li>
     *   <li>{@code pkt[29] = byte(len(dialects))} 写的是 <b>125</b>（与实际
     *       拷贝量不符的 ByteCount）；</li>
     *   <li>方言表第二个赋值覆盖第一个（首版 "PC NETWORK PROGRAM 1.0"
     *       是死代码，照抄不执行）；</li>
     *   <li>找到 {@code \xffSMB} 签名一律返回 "1.0"（两分支相同）。</li>
     * </ul>
     */
    static SmbOutcome negotiateSMB1(String ip, int port) {
        try (Socket conn = new Socket()) {
            conn.connect(dialAddress(ip, port), SMB_DIAL_TIMEOUT_MS);
            conn.setSoTimeout(SMB_DIAL_TIMEOUT_MS);

            // SMB1 Negotiate Protocol Request: NetBIOS header (4) + SMB header (32) + dialects
            byte[] pkt = new byte[4 + 32 + 28];

            // NetBIOS Session Message
            pkt[0] = 0x00;
            pkt[1] = 0x00;
            pkt[2] = 0x00;
            pkt[3] = (byte) (pkt.length - 4);

            // SMB1 header
            pkt[4] = (byte) 0xff;
            pkt[5] = 'S';
            pkt[6] = 'M';
            pkt[7] = 'B';
            pkt[8] = 0x72; // Command: Negotiate Protocol
            pkt[9] = 0x00; // Status
            pkt[10] = 0x00;
            pkt[11] = 0x00;
            pkt[12] = (byte) 0x98; // Flags: canonicalized paths
            pkt[13] = (byte) 0xc3;
            pkt[14] = 0x01;
            pkt[15] = 0x28;
            // Reserved(4) at 16..19: zeros
            // TID(2) at 20..21: 0xffff
            pkt[20] = (byte) 0xff;
            pkt[21] = (byte) 0xff;
            // PID(2) at 22..23: 0xfe 0xff
            pkt[22] = (byte) 0xfe;
            pkt[23] = (byte) 0xff;
            // UID(2) at 24..25: zeros; MID(2) at 26..27: zeros

            // WordCount = 0
            pkt[28] = 0x00;
            // ByteCount（先写 0x0c，随后被 len(dialects)=125 覆盖 —— 与 Go 相同顺序）
            pkt[29] = 0x0c;
            pkt[30] = 0x00;

            // Dialects（Go: 第一个字面量被第二个覆盖 —— 死代码，此处直接用最终值）
            byte[] dialects = {
                0x02, 'L', 'M', '1', '.', '0', 'X', '0', '0', 0x00,
                0x02, 'S', 'a', 'm', 'b', 'a', 0x00,
                0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00,
                0x02, 'P', 'C', ' ', 'N', 'E', 'T', 'W', 'O', 'R', 'K', ' ',
                'P', 'R', 'O', 'G', 'R', 'A', 'M', ' ', '1', '.', '0', 0x00,
                0x02, 'M', 'S', 'N', 'E', 'T', 'W', 'O', 'R', 'K', ' ', '3', '.', '0', 0x00,
                0x02, 'L', 'A', 'N', 'M', 'A', 'N', '1', '.', '0', 0x00,
                0x02, 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'f', 'o', 'r', ' ',
                'W', 'o', 'r', 'k', 'g', 'r', 'o', 'u', 'p', 's', ' ', '3', '.', '1', 'a', 0x00,
                0x02, 'O', 'S', '/', '2', ' ', 'L', 'A', 'N', 'M', 'A', 'N', ' ',
                '1', '.', '0', 0x00,
            };
            // Go: copy(pkt[31:], dialects) —— dst 只有 33 字节，方言表被截断
            int copyLen = Math.min(pkt.length - 31, dialects.length);
            System.arraycopy(dialects, 0, pkt, 31, copyLen);
            // Update ByteCount: byte(len(dialects)) = 125（与实际拷贝 33 字节不符 —— Go 原样）
            pkt[29] = (byte) dialects.length;
            pkt[30] = 0x00;
            // Update NetBIOS length
            pkt[3] = (byte) (pkt.length - 4);

            conn.getOutputStream().write(pkt);

            byte[] buf = new byte[4096];
            int n = conn.getInputStream().read(buf);
            if (n < 36) {
                return new SmbOutcome("", "no SMB1 response");
            }

            // 查找SMB1签名 \xffSMB
            for (int i = 0; i <= n - 4; i++) {
                if ((buf[i] & 0xff) == 0xff && buf[i + 1] == 'S'
                        && buf[i + 2] == 'M' && buf[i + 3] == 'B') {
                    // Go 读了 DialectIndex（i+37）但不用，两分支都返回 "1.0"
                    return new SmbOutcome("1.0", null);
                }
            }
            return new SmbOutcome("", "no SMB1 signature in response");
        } catch (IOException e) {
            return new SmbOutcome("", e.getMessage() == null ? e.toString() : e.getMessage());
        }
    }

    /**
     * 对应 Go 的 {@code net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 3s)}：
     * <b>IPv6 不加方括号</b>（Go 原文如此，{@code formatIPForConnection} 只用于
     * connect/ttl 等处）。Java 侧 {@link InetSocketAddress} 接受裸 IPv6 字面量，
     * 与 Go 的「不加方括号导致 Dial 失败」不完全等价 —— 若目标是 IPv6，
     * Go 会直接走错误分支，Java 则真的连了过去；<b>记录在案的偏差</b>
     * （IPv6+SMB 组合极罕见，且 Go 行为本身也是 bug）。
     */
    private static InetSocketAddress dialAddress(String ip, int port) {
        return new InetSocketAddress(ip, port);
    }

    /**
     * 对应 Go 的 {@code detectWindowsVersion(ip, ports)}（scan.go:1691）。
     *
     * <p><b>Go 死代码照抄</b>：{@code if (hasRdp) return "Windows"} 之后的
     * XP/2003 与通用 Windows 分支在 Go 中同样不可达（hasRDP 已在前面返回），
     * 这里保留原顺序以保证逐行对应。
     */
    static String detectWindowsVersion(String ip, Map<Integer, PortInfo> ports) {
        boolean hasRdp = false;
        boolean hasSmb = false;
        boolean hasNetbios = false;
        boolean hasMsrpc = false;

        for (Integer port : ports.keySet()) {
            switch (port) {
                case 3389 -> hasRdp = true;
                case 445 -> hasSmb = true;
                case 139 -> hasNetbios = true;
                case 135 -> hasMsrpc = true;
                default -> {
                    // Go: default 空分支
                }
            }
        }

        // 通过SMB协商获取实际协议版本 (最准确)
        if (hasSmb) {
            String smbVer = detectSMBVersion(ip, ports);
            if (!smbVer.isEmpty()) {
                return smbVer;
            }
        }

        // 无RDP时, 无法确定具体Windows版本, 只能判断是Windows
        if (!hasRdp) {
            return "Windows";
        }

        // 有RDP时, 尝试根据端口组合推测
        if (hasRdp && hasSmb && !hasNetbios) {
            return "Windows 10/11/Server 2016+";
        }
        if (hasRdp && hasSmb && hasNetbios) {
            return "Windows 8/Server 2012";
        }
        if (hasRdp) {
            return "Windows";
        }

        // 老版本Windows系统（Go 中为死代码：hasRDP 刚被上面的分支返回）
        if (hasNetbios && hasMsrpc && !hasSmb) {
            return "Windows XP/2003";
        }

        // 通用Windows识别（同上，死代码照抄）
        if (hasSmb || hasRdp || hasNetbios || hasMsrpc) {
            return "Windows";
        }

        return "Unknown";
    }

    /**
     * 对应 Go 的 {@code detectLinuxVersion(ports)}（scan.go:1747）：
     * SSH+特定端口 → Server；仅 SSH → Desktop；Web+SSH → Web Server；否则 Linux/Unix。
     */
    static String detectLinuxVersion(Map<Integer, PortInfo> ports) {
        boolean hasSsh = false;
        boolean hasHttp = false;
        boolean hasHttps = false;
        boolean hasSpecificPorts = false;

        for (Integer port : ports.keySet()) {
            switch (port) {
                case 22 -> hasSsh = true;
                case 80 -> hasHttp = true;
                case 443 -> hasHttps = true;
                case 111, 2049, 3306, 5432, 6379, 27017 ->
                    // RPC, NFS, MySQL, PostgreSQL, Redis, MongoDB
                    hasSpecificPorts = true;
                default -> {
                    // Go: default 空分支
                }
            }
        }

        // 服务器版本（通常有数据库服务）
        if (hasSsh && hasSpecificPorts) {
            return "Linux Server (Ubuntu/CentOS/Debian)";
        }
        // 桌面版本（通常只有基本服务）
        if (hasSsh && !hasSpecificPorts) {
            return "Linux Desktop (Ubuntu/Fedora)";
        }
        // Web服务器
        if ((hasHttp || hasHttps) && hasSsh) {
            return "Linux Web Server (Ubuntu/CentOS)";
        }
        return "Linux/Unix";
    }

    // =========================================================================
    // scan.go:1785-1912 —— banner 系 OS 识别
    // =========================================================================

    /**
     * 对应 Go 的 {@code detectOSByBanner(ports)}（scan.go:1785）：
     * banner 先整体小写再按<b>首个命中</b>分支返回（Go switch-case 顺序：windows/microsoft →
     * linux 系 → freebsd/openbsd → cisco → apache/nginx → iis）。
     *
     * <p>Go 遍历 map 是随机序（多个端口同时命中会随机选一个）；
     * Java 按端口升序（{@link ScanEngine#orderedCopy}）—— 记录在案的偏差。
     */
    static String detectOSByBanner(Map<Integer, PortInfo> ports) {
        for (PortInfo portInfo : ScanEngine.orderedCopy(ports).values()) {
            String banner = portInfo.banner == null
                    ? "" : portInfo.banner.toLowerCase(Locale.ROOT);

            if (banner.contains("windows") || banner.contains("microsoft")) {
                return detectWindowsVersionFromBanner(banner);
            }
            if (banner.contains("linux") || banner.contains("ubuntu")
                    || banner.contains("centos") || banner.contains("debian")
                    || banner.contains("fedora") || banner.contains("redhat")) {
                return detectLinuxVersionFromBanner(banner);
            }
            if (banner.contains("freebsd") || banner.contains("openbsd")) {
                return detectBSDVersionFromBanner(banner);
            }
            if (banner.contains("cisco")) {
                return "Cisco IOS";
            }
            if (banner.contains("apache") || banner.contains("nginx")) {
                // Web服务器多为Linux
                return "Linux/Unix (Web Server)";
            }
            if (banner.contains("iis")) {
                return detectIISVersionFromBanner(banner);
            }
        }
        return "Unknown";
    }

    /**
     * 对应 Go 的 {@code detectWindowsVersionFromBanner(banner)}（scan.go:1813）。
     * Go 传入的已是小写串，函数内再 {@code ToLower} 一次（冗余但照抄语义）。
     */
    static String detectWindowsVersionFromBanner(String banner) {
        String bannerLower = banner.toLowerCase(Locale.ROOT);

        if (bannerLower.contains("windows 11") || bannerLower.contains("windows 10")) {
            return "Windows 10/11";
        }
        if (bannerLower.contains("windows 8")) {
            return "Windows 8/8.1";
        }
        if (bannerLower.contains("windows 7")) {
            return "Windows 7";
        }
        if (bannerLower.contains("windows server 2016") || bannerLower.contains("windows server 2019")
                || bannerLower.contains("windows server 2022")) {
            return "Windows Server 2016+";
        }
        if (bannerLower.contains("windows server 2012")) {
            return "Windows Server 2012";
        }
        if (bannerLower.contains("windows server 2008")) {
            return "Windows Server 2008";
        }
        if (bannerLower.contains("windows xp") || bannerLower.contains("windows 2003")) {
            return "Windows XP/2003";
        }
        return "Windows";
    }

    /** 对应 Go 的 {@code detectLinuxVersionFromBanner(banner)}（scan.go:1843）。 */
    static String detectLinuxVersionFromBanner(String banner) {
        String bannerLower = banner.toLowerCase(Locale.ROOT);

        if (bannerLower.contains("ubuntu")) {
            return "Ubuntu Linux";
        }
        if (bannerLower.contains("centos")) {
            return "CentOS Linux";
        }
        if (bannerLower.contains("debian")) {
            return "Debian Linux";
        }
        if (bannerLower.contains("fedora")) {
            return "Fedora Linux";
        }
        if (bannerLower.contains("red hat") || bannerLower.contains("rhel")) {
            return "Red Hat Enterprise Linux";
        }
        if (bannerLower.contains("arch linux")) {
            return "Arch Linux";
        }
        if (bannerLower.contains("opensuse") || bannerLower.contains("suse")) {
            return "openSUSE/SUSE Linux";
        }
        return "Linux/Unix";
    }

    /** 对应 Go 的 {@code detectBSDVersionFromBanner(banner)}（scan.go:1872）。 */
    static String detectBSDVersionFromBanner(String banner) {
        String bannerLower = banner.toLowerCase(Locale.ROOT);

        if (bannerLower.contains("freebsd")) {
            return "FreeBSD";
        }
        if (bannerLower.contains("openbsd")) {
            return "OpenBSD";
        }
        if (bannerLower.contains("netbsd")) {
            return "NetBSD";
        }
        return "BSD";
    }

    /** 对应 Go 的 {@code detectIISVersionFromBanner(banner)}（scan.go:1889）。 */
    static String detectIISVersionFromBanner(String banner) {
        String bannerLower = banner.toLowerCase(Locale.ROOT);

        if (bannerLower.contains("iis 10")) {
            return "IIS 10.0 (Windows Server 2016/2019/2022)";
        }
        if (bannerLower.contains("iis 8.5")) {
            return "IIS 8.5 (Windows Server 2012 R2)";
        }
        if (bannerLower.contains("iis 8")) {
            return "IIS 8.0 (Windows Server 2012)";
        }
        if (bannerLower.contains("iis 7.5")) {
            return "IIS 7.5 (Windows Server 2008 R2)";
        }
        if (bannerLower.contains("iis 7")) {
            return "IIS 7.0 (Windows Server 2008)";
        }
        if (bannerLower.contains("iis 6")) {
            return "IIS 6.0 (Windows Server 2003)";
        }
        return "Microsoft IIS";
    }

    // =========================================================================
    // scan.go:1915-1979 —— 增强检测 / TCP 栈 / 去重
    // =========================================================================

    /**
     * 对应 Go 的 {@code aggressiveOSDetection(ip, ports)}（scan.go:1915，nmap -A 风格）：
     * TTL → 端口组合 → banner → TCP 栈指纹，最后去重。顺序与过滤条件照抄。
     */
    static List<String> aggressiveOSDetection(String ip, Map<Integer, PortInfo> ports) {
        List<String> osGuesses = new ArrayList<>();

        // 基于TTL的猜测
        String ttlGuess = detectOSByTTL(ip);
        if (!"Unknown".equals(ttlGuess)) {
            osGuesses.add(ttlGuess);
        }

        // 基于端口组合的猜测
        String portGuess = detectOSByServiceCombination(ip, ports);
        if (!"Unknown".equals(portGuess)) {
            osGuesses.add(portGuess);
        }

        // 基于banner的猜测
        String bannerGuess = detectOSByBanner(ports);
        if (!"Unknown".equals(bannerGuess)) {
            osGuesses.add(bannerGuess);
        }

        // 基于TCP/IP栈指纹的猜测（简化实现）
        String tcpGuess = detectOSByTCPFingerprint(ip);
        if (!"Unknown".equals(tcpGuess)) {
            osGuesses.add(tcpGuess);
        }

        // 去重
        return removeDuplicateOSGuesses(osGuesses);
    }

    /**
     * 对应 Go 的 {@code detectOSByTCPFingerprint(ip)}（scan.go:1943）：
     * 简化实现 —— 试连 22（成功 → Linux 固定串），再试 3389（成功 → Windows 固定串），
     * 否则 Unknown。连接用 {@code formatIPForConnection(ip, port)} 的语义
     * （IPv6 加方括号），Java 侧拆成 host+port 等价表达。
     */
    static String detectOSByTCPFingerprint(String ip) {
        if (dialSucceeds(ip, 22)) {
            // SSH端口开放，可能是Linux/Unix系统
            return "Linux 2.6.32 - 4.9 (96%)";
        }
        if (dialSucceeds(ip, 3389)) {
            // RDP端口开放，可能是Windows系统
            return "Windows 10/11/Server 2016+ (96%)";
        }
        return "Unknown";
    }

    /**
     * Go: {@code conn, err := net.DialTimeout("tcp", formatIPForConnection(ip, port), 3*time.Second)}。
     * IPv6 的方括号在 {@link ScanEngine#formatIPForConnection} 里处理，
     * 这里还原成 host（去括号）+ port 交给 {@link InetSocketAddress}，目标等价。
     */
    private static boolean dialSucceeds(String ip, int port) {
        String host = ScanEngine.formatIPForConnection(ip, port);
        // formatIPForConnection 返回 "ip:port" / "[ip]:port"，取回裸主机名
        String bare = host;
        if (bare.startsWith("[")) {
            int close = bare.indexOf(']');
            bare = close > 0 ? bare.substring(1, close) : bare;
        } else {
            int colon = bare.lastIndexOf(':');
            if (colon > 0 && bare.indexOf(':') == colon) {
                bare = bare.substring(0, colon);
            }
        }
        try (Socket conn = new Socket()) {
            conn.connect(new InetSocketAddress(bare, port), SMB_DIAL_TIMEOUT_MS);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** 对应 Go 的 {@code removeDuplicateOSGuesses(guesses)}（scan.go:1965）：保序去重。 */
    static List<String> removeDuplicateOSGuesses(List<String> guesses) {
        return new ArrayList<>(new LinkedHashSet<>(guesses));
    }

    // =========================================================================
    // scan.go:2119 calculateChecksum
    // =========================================================================

    /**
     * 对应 Go 的 {@code calculateChecksum(data)}（scan.go:2119）：ICMP 校验和。
     * 当前唯一调用方是未移植的 {@link #getTTLByRawICMP}，按 Go 原样保留
     * （返回 0..65535 的 unsigned 值，对应 Go 的 {@code uint16}）。
     */
    static int calculateChecksum(byte[] data) {
        long sum = 0;

        for (int i = 0; i < data.length - 1; i += 2) {
            sum += ((long) (data[i] & 0xff) << 8) | (data[i + 1] & 0xff);
        }

        if (data.length % 2 == 1) {
            sum += (long) (data[data.length - 1] & 0xff) << 8;
        }

        while ((sum >>> 16) != 0) {
            sum = (sum & 0xffff) + (sum >>> 16);
        }

        return ~((int) sum) & 0xffff;
    }
}

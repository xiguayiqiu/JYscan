package space.jyscan.modules.nmap;

import space.jyscan.core.i18n.I18n;
import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.GoJson;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * nmap 结果的打印与工具函数，移植自 freeclient/internal/nmap/utils.go。
 *
 * <p><b>归属</b>：本文件由 E 号子代理实现（源文件 utils.go，435 行）。
 * 下面的签名被 A 号（ScanCommand）与 B 号（扫描引擎）调用，请勿改动。
 *
 * <p>{@code SaveNmapResult} 的 JSON 输出必须用 {@link space.jyscan.core.util.GoJson}
 * 而非 {@link space.jyscan.core.util.JsonUtil}，否则空容器/数组换行/冒号空格会与 Go 不符
 *（已实测：GoJson 输出与 Go 逐字节一致）。
 *
 * <p>格式化一律走 {@link Fmt#format}（复刻 Go {@code fmt.Sprintf}），不使用
 * {@code String.format}。Go 的 map 迭代是随机序，Java 侧端口遍历统一按
 * <b>端口号数值升序</b>（{@code TreeMap<Integer>}）固定下来：输出内容与 Go 一致，
 * 仅把 Go 的随机轮转变为确定序（该差异已实证为 Go 输出本身的不确定性）。
 */
public final class NmapUtils {

    private NmapUtils() {
    }

    /** Go {@code isValidDomainFormat} 中 {@code regexp.MustCompile} 的原文。 */
    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
            "^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)*"
                    + "[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z]{2,})$");

    /** {@code SaveNmapResult} 默认文件名时间戳，对应 Go 的 {@code 20060102_150405}。 */
    private static final DateTimeFormatter SAVE_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss", Locale.ROOT);

    /** Go {@code isVulnerablePort} 的常见脆弱端口表。 */
    private static final int[] VULNERABLE_PORTS = {21, 23, 445, 3389, 5900, 6379};

    // =====================================================================
    // IP / CIDR 字面量判定（复刻 Go net.ParseIP / net.ParseCIDR / net.IP.To4）
    // =====================================================================

    /** IP 分类结果，对应 Go 的 {@code ParseIP != nil} 与 {@code To4() != nil}。 */
    private enum IpKind {
        /** 不是合法 IP 字面量（Go：{@code ParseIP == nil}）。 */
        NONE,
        /** 合法 IPv4（或 Go {@code To4() != nil} 的 v4-mapped 形式）。 */
        V4,
        /** 合法 IPv6（{@code To4() == nil}）。 */
        V6
    }

    /**
     * 严格 IPv4 点分校验，对齐 Go {@code net.ParseIP}（Go ≥1.17 起<b>拒绝前导零</b>，
     * 已实测 {@code "010.1.1.1"} / {@code "1.2.3.04"} 均判非法）。
     */
    private static boolean isStrictIPv4(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) {
                return false;
            }
            if (p.length() > 1 && p.charAt(0) == '0') {
                return false; // Go 拒绝前导零
            }
            int v = 0;
            for (int i = 0; i < p.length(); i++) {
                char c = p.charAt(i);
                if (c < '0' || c > '9') {
                    return false;
                }
                v = v * 10 + (c - '0');
            }
            if (v > 255) {
                return false;
            }
        }
        return true;
    }

    /**
     * IPv6 字面量校验（前置条件：含 {@code ':'}）。
     *
     * <p>先做字符集（hex / {@code ':'} / {@code '.'}）与内嵌 IPv4 严格性检查，再交给
     * {@link InetAddress#getByName}——该入口对含冒号输入<b>只走字面量解析、不触发 DNS</b>，
     * 解析失败抛 {@link java.net.UnknownHostException}。字符集前置检查同时挡住 JDK 接受、
     * Go 拒绝的形态：{@code [::1]}（方括号）、{@code fe80::1%eth0}（zone）、
     * {@code ::ffff:010.1.1.1}（内嵌 v4 前导零，已实测 Go 判非法）。
     */
    private static boolean isIPv6Literal(String s) {
        if (s == null || s.isEmpty() || s.length() > 45) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!(hex || c == ':' || c == '.')) {
                return false;
            }
        }
        if (s.indexOf(':') < 0) {
            return false;
        }
        if (s.indexOf('.') >= 0) {
            // 内嵌 IPv4 必须位于最后一个 ':' 之后且是严格 v4（对齐 Go parseIPv4 的前导零拒绝）
            int lastColon = s.lastIndexOf(':');
            if (!isStrictIPv4(s.substring(lastColon + 1))) {
                return false;
            }
        }
        try {
            InetAddress.getByName(s);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** 是否为合法 IP 字面量（对齐 {@code net.ParseIP(target) != nil}）。 */
    private static boolean isIpLiteral(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        if (s.indexOf(':') >= 0) {
            return isIPv6Literal(s);
        }
        return isStrictIPv4(s);
    }

    /**
     * 是否为合法 CIDR（对齐 {@code net.ParseCIDR}）。
     *
     * <p>掩码族按<b>字面量形态</b>判定（已实测：点分四段 → 上限 32，含
     * {@code ::ffff:1.2.3.4} 的冒号形态 → 上限 128，Go 用的是 ParseIP 产物的字节长而非
     * {@code To4()}）；掩码只接受纯十进制数字（{@code "+24"} 判非法，对齐 Go 实测）。
     */
    private static boolean isCidrLiteral(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        int slash = s.indexOf('/');
        if (slash < 0) {
            return false;
        }
        String addr = s.substring(0, slash);
        String mask = s.substring(slash + 1);
        int maxBits;
        if (isStrictIPv4(addr)) {
            maxBits = 32;
        } else if (isIPv6Literal(addr)) {
            maxBits = 128;
        } else {
            return false;
        }
        if (mask.isEmpty()) {
            return false;
        }
        for (int i = 0; i < mask.length(); i++) {
            char c = mask.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        int n;
        try {
            n = Integer.parseInt(mask);
        } catch (NumberFormatException e) {
            return false; // 溢出即非法（任何溢出值必然 > 上限）
        }
        return n <= maxBits;
    }

    /**
     * IP 分类，复刻 Go 的 {@code ParseIP} + {@code To4()} 语义：
     * v4-mapped（{@code ::ffff:a.b.c.d} / 十六进制等价写法）判为 V4（对齐
     * {@code filterIPv4Results} 保留这类主机的行为）。
     */
    private static IpKind classifyIp(String s) {
        if (s == null || s.isEmpty()) {
            return IpKind.NONE;
        }
        if (s.indexOf(':') < 0) {
            return isStrictIPv4(s) ? IpKind.V4 : IpKind.NONE;
        }
        if (!isIPv6Literal(s)) {
            return IpKind.NONE;
        }
        try {
            byte[] b = InetAddress.getByName(s).getAddress();
            if (b.length == 4) {
                // JDK 把 v4-mapped 字面量归一为 4 字节地址，等价 Go To4() != nil
                return IpKind.V4;
            }
            if (b.length == 16) {
                boolean zeros = true;
                for (int i = 0; i < 10; i++) {
                    if (b[i] != 0) {
                        zeros = false;
                        break;
                    }
                }
                if (zeros && b[10] == (byte) 0xff && b[11] == (byte) 0xff) {
                    return IpKind.V4; // Go net.IP.To4 的 v4-mapped 判定
                }
                return IpKind.V6;
            }
            return IpKind.NONE;
        } catch (Exception e) {
            return IpKind.NONE;
        }
    }

    // =====================================================================
    // 14 个公开方法（签名已定，勿改；与 utils.go 的 14 个函数一一对应）
    // =====================================================================

    /**
     * 去重：按 hostname（为空则 IP）保留首个。
     *
     * 对应 Go 的 {@code deduplicateResults}
     */
    public static List<NmapResult> deduplicateResults(List<NmapResult> results) {
        if (results == null || results.isEmpty()) {
            return results == null ? new ArrayList<>() : results;
        }

        Set<String> seen = new HashSet<>();
        List<NmapResult> unique = new ArrayList<>();

        for (NmapResult result : results) {
            String ip = result.ip == null ? "" : result.ip;
            String key = ip;
            String hostname = result.hostname;
            if (hostname != null && !hostname.isEmpty()) {
                key = hostname;
            }
            if (seen.add(key)) {
                unique.add(result);
            }
        }

        return unique;
    }

    /**
     * 保存为 Go 格式 JSON。
     *
     * <p>{@code filePath} 为空时用默认名
     * {@code JYscan_scan_yyyyMMdd_HHmmss.json}（格式与 Go 的 {@code GYscan_scan_} 一致，
     * 前缀随项目改名 —— 品牌改名导致的有意偏差，见 freeclient/internal/nmap/utils.go:47）。
     * 成功时自行打印 {@code nmap.log.result_saved}，返回 null；
     * 失败返回错误信息（调用方打印 {@code nmap.err.save_failed}）。
     *
     * <p>文件权限按 Go {@code os.WriteFile(path, data, 0644)} 语义：仅在<b>新建</b>时以
     * 0644 创建（经 open(2) 受 umask 掩码，与 Go 相同），已存在的文件不动权限。
     *
     * 对应 Go 的 {@code SaveNmapResult(results, filePath) error}
     *
     * @return 错误信息；成功返回 {@code null}
     */
    public static String saveNmapResult(List<NmapResult> results, String filePath) {
        String path = filePath;
        if (path == null || path.isEmpty()) {
            path = Fmt.format("JYscan_scan_%s.json",
                    LocalDateTime.now().format(SAVE_TIMESTAMP));
        }

        // 创建JSON格式的结果（对应 json.MarshalIndent(results, "", "  ")）
        String jsonData;
        try {
            jsonData = GoJson.marshalIndent(results);
        } catch (Exception e) {
            // Go：return fmt.Errorf(i18n.Tf("nmap.err.serialize_failed", err))
            return I18n.Tf("nmap.err.serialize_failed", e);
        }

        // 写入文件（对应 os.WriteFile(filePath, jsonData, 0644)）
        try {
            Path p = Paths.get(path);
            if (!Files.exists(p)) {
                try {
                    // 0644 仅作用于创建（umask 仍生效，与 Go 的 open 语义一致）
                    Files.createFile(p, PosixFilePermissions.asFileAttribute(
                            PosixFilePermissions.fromString("rw-r--r--")));
                } catch (UnsupportedOperationException e) {
                    Files.createFile(p); // 非 POSIX 文件系统：0644 无对应概念
                } catch (IOException e) {
                    // 创建失败交由下面的写入步骤统一报告（写入同样会失败）
                }
            }
            Files.write(p, jsonData.getBytes(StandardCharsets.UTF_8));
        } catch (IOException | InvalidPathException e) {
            // Go：return fmt.Errorf(i18n.Tf("nmap.err.write_file_failed", err))
            return I18n.Tf("nmap.err.write_file_failed", e);
        }

        System.out.println(I18n.Tf("nmap.log.result_saved", path));
        return null;
    }

    /**
     * 打印扫描结果（含 dedup、IPv4 过滤、开放端口着色）。
     *
     * <p>逐行对照 utils.go:67-173。着色方案（全部经 {@link Colors}，受 {@code --no-color}
     * 的 {@code Colors.useColor} 控制）：标题 {@code titlePrint}（粗体白）、主机行
     * {@code successPrint}（绿）、主机名后缀 {@code progressPrint}（品红）、
     * 活跃数/开放端口/链接/OS/距离走 {@code infoPrint}（与 Go 的 {@code InfoPrint} 一致：<b>纯文本不着色</b>）、
     * 端口号蓝、协议青、状态 {@code open|filtered} 黄 / {@code open} 绿
     * （用 {@code Colors.wrap} + 对应 ANSI 码）。
     *
     * 对应 Go 的 {@code PrintNmapResult(results, config)}
     */
    public static void printNmapResult(List<NmapResult> results, ScanConfig config) {
        Colors.titlePrint("\n" + I18n.T("nmap.result.title"));

        List<NmapResult> list = deduplicateResults(results);

        // 默认仅显示 IPv4 主机 (除非显式启用 IPv6)
        if (config == null || !config.ipv6) {
            list = filterIPv4Results(list);
        }

        int activeHosts = 0;
        for (NmapResult result : list) {
            if (NmapConstants.HOST_UP.equals(result.status)) {
                activeHosts++;
            }
        }

        if (activeHosts > 0) {
            Colors.infoPrint(I18n.Tf("nmap.result.hosts_active", activeHosts) + "\n");
        }

        for (NmapResult result : list) {
            if (NmapConstants.HOST_UP.equals(result.status)) {
                // 收集 open / open|filtered 端口（TreeMap 数值序，见类注释）
                Map<Integer, PortInfo> openPorts = new TreeMap<>();
                if (result.ports != null) {
                    for (Map.Entry<Integer, PortInfo> entry : result.ports.entrySet()) {
                        PortInfo portInfo = entry.getValue();
                        if (portInfo != null && portInfo.isOpenOrOpenFiltered()) {
                            openPorts.put(entry.getKey(), portInfo);
                        }
                    }
                }

                if (openPorts.isEmpty()) {
                    continue;
                }

                String ip = result.ip == null ? "" : result.ip;

                // 使用不同颜色标记主机信息
                Colors.successPrint(I18n.Tf("nmap.result.host", ip));
                String hostname = result.hostname;
                if (hostname != null && !hostname.isEmpty()) {
                    Colors.progressPrint(" (%s)", hostname);
                }
                System.out.println();

                Colors.infoPrint(I18n.T("nmap.result.open_ports"));
                for (PortInfo portInfo : openPorts.values()) {
                    System.out.print("  ");
                    System.out.print(Colors.wrap(Fmt.format("%d", portInfo.port), Colors.FG_BLUE));
                    System.out.print("/");
                    System.out.print(Colors.wrap(Fmt.format("%s", portInfo.protocol), Colors.FG_CYAN));
                    System.out.print(" ");
                    if (NmapConstants.PORT_STATE_OPEN_FILTERED.equals(portInfo.state)) {
                        System.out.print(Colors.wrap("open|filtered", Colors.FG_YELLOW));
                    } else {
                        System.out.print(Colors.wrap("open", Colors.FG_GREEN));
                    }
                    String service = portInfo.service == null ? "" : portInfo.service;
                    if (!service.isEmpty()) {
                        System.out.print(Fmt.format(" %s", service));
                        String version = portInfo.version == null ? "" : portInfo.version;
                        if (!version.isEmpty()) {
                            System.out.print(Fmt.format(" %s", version));
                        }
                    }
                    System.out.println();
                }

                // 默认不显示 HTTP/HTTPS 访问链接 (除非显式启用全面扫描 -A 或 WAF 检测)
                if (config != null && (config.aggressiveScan || config.enableWAFDetect)) {
                    List<Integer> httpPorts = new ArrayList<>();
                    List<Integer> httpsPorts = new ArrayList<>();
                    for (Map.Entry<Integer, PortInfo> entry : openPorts.entrySet()) {
                        int port = entry.getKey();
                        switch (port) {
                            case 80 -> httpPorts.add(port);
                            case 443 -> httpsPorts.add(port);
                            default -> {
                                String svc = entry.getValue().service;
                                String lower = (svc == null ? "" : svc).toLowerCase(Locale.ROOT);
                                if (lower.contains("http")) {
                                    httpPorts.add(port);
                                }
                                if (lower.contains("https")) {
                                    httpsPorts.add(port);
                                }
                            }
                        }
                    }

                    if (!httpPorts.isEmpty() || !httpsPorts.isEmpty()) {
                        Colors.infoPrint(I18n.T("nmap.result.links"));
                        for (int port : httpsPorts) {
                            System.out.print(Fmt.format("  https://%s:%d\n", ip, port));
                        }
                        for (int port : httpPorts) {
                            System.out.print(Fmt.format("  http://%s:%d\n", ip, port));
                        }
                    }
                }

                // 操作系统检测结果
                String os = result.os;
                if (os != null && !os.isEmpty()) {
                    Colors.infoPrint(I18n.Tf("nmap.result.os", os) + "\n");
                }

                // 网络距离 (TTL检测结果)
                if (result.networkDistance > 0) {
                    Colors.infoPrint(I18n.Tf("nmap.result.distance", result.networkDistance) + "\n");
                }

                System.out.println();
            }
        }
    }

    /**
     * 过滤掉 IPv6 主机。
     *
     * <p>对齐 Go：{@code ParseIP} 失败的（如域名占位）保留；{@code To4() != nil}
     *（含 v4-mapped）保留；其余 IPv6 丢弃。
     *
     * 对应 Go 的 {@code filterIPv4Results}
     */
    public static List<NmapResult> filterIPv4Results(List<NmapResult> results) {
        List<NmapResult> filtered = new ArrayList<>();
        if (results == null) {
            return filtered;
        }
        for (NmapResult r : results) {
            IpKind kind = classifyIp(r.ip);
            if (kind != IpKind.V6) {
                // 解析失败的 (例如域名占位) 保留
                filtered.add(r);
            }
        }
        return filtered;
    }

    /**
     * 反向解析 hostname。
     *
     * <p>对齐 Go {@code net.LookupAddr}（反向解析）：失败或与入参相同（JDK 反查不到时
     * 返回 IP 本串）返回 {@code ""}。
     *
     * <p><b>已知 1 字符差异</b>：Go 对 DNS PTR 结果保留结尾点（{@code "dns.google."}），
     * JDK 的 {@code getHostName} 会剥掉；hosts 文件结果两边一致（{@code "localhost"}）。
     * 该函数在 Go 全库无调用方，此差异无下游影响。
     *
     * 对应 Go 的 {@code GetHostname(ip)}
     */
    public static String getHostname(String ip) {
        if (ip == null || ip.isEmpty()) {
            return "";
        }
        try {
            String name = InetAddress.getByName(ip).getHostName();
            if (name == null || name.equals(ip)) {
                return "";
            }
            return name;
        } catch (Exception e) {
            // Go：err != nil || len(names) == 0 → ""
            return "";
        }
    }

    /**
     * 校验目标格式（IP / CIDR / IP范围 / 域名）。
     *
     * <p>内部先调 {@link #removeProtocolPrefix}，再依次判 IP、CIDR、IP 范围，
     * 之后走 {@code Resolver.resolveHostIPs}（DNS）与 {@link #isValidDomainFormat} 兜底。
     *
     * 对应 Go 的 {@code ValidateTarget(target) bool}
     */
    public static boolean validateTarget(String target) {
        // 移除可能的协议前缀和端口号
        String t = removeProtocolPrefix(target);

        // 检查是否为IP地址
        if (isIpLiteral(t)) {
            return true;
        }

        // 检查是否为CIDR格式
        if (isCidrLiteral(t)) {
            return true;
        }

        // 检查是否为IP范围格式
        if (t.indexOf('-') >= 0) {
            String[] parts = t.split("-", -1);
            if (parts.length == 2 && isIpLiteral(parts[0].strip()) && isIpLiteral(parts[1].strip())) {
                return true;
            }
        }

        // 检查是否为域名（DNS解析，兼容 Termux/Android 缺少 resolv.conf 的环境）
        List<String> ips;
        try {
            ips = Resolver.resolveHostIPs(t);
        } catch (UnsupportedOperationException e) {
            // B 号桩未就绪：按 Go 的 err != nil 处理，落到下面的正则兜底
            ips = null;
        }
        if (ips != null && !ips.isEmpty()) {
            return true;
        }

        // DNS解析失败时，使用正则表达式验证域名格式（兼容Termux等无DNS环境）
        return isValidDomainFormat(t);
    }

    /**
     * 判定域名格式是否合法。
     *
     * <p>长度按 <b>UTF-8 字节数</b>（Go {@code len(string)}）在 {@code "*."} 剥离<b>之前</b>判定，
     * 与 Go 源码顺序一致。
     *
     * 对应 Go 的 {@code isValidDomainFormat(domain)}
     */
    public static boolean isValidDomainFormat(String domain) {
        if (domain == null) {
            return false;
        }
        int byteLen = domain.getBytes(StandardCharsets.UTF_8).length;
        if (byteLen < 1 || byteLen > 253) {
            return false;
        }
        // 支持通配符域名如 *.example.com
        String d = domain.startsWith("*.") ? domain.substring(2) : domain;
        return DOMAIN_PATTERN.matcher(d).matches();
    }

    /**
     * 去掉 {@code http://}/{@code https://} 前缀、端口号和路径。
     *
     * <p>C 号（contentProbeHostname）与 B 号都依赖本方法。
     * <b>CIDR 网段必须保留掩码位</b>（utils.go:260 注释），在剥路径逻辑之前提前返回。
     *
     * 对应 Go 的 {@code RemoveProtocolPrefix(url)}
     */
    public static String removeProtocolPrefix(String url) {
        String u = url == null ? "" : url;
        u = u.strip();

        // 移除http://或https://前缀
        if (u.startsWith("http://")) {
            u = u.substring("http://".length());
        } else if (u.startsWith("https://")) {
            u = u.substring("https://".length());
        }

        // CIDR 网段(如 192.168.1.0/24)不是URL，必须保留掩码位，
        // 否则会被下面的“移除路径”逻辑破坏，导致整个网段只剩一个地址
        if (isCidrLiteral(u)) {
            return u;
        }

        // 尝试直接解析为IP地址（支持IPv4和IPv6）
        if (isIpLiteral(u)) {
            // 是IP地址，可能包含端口号
            // IPv6地址用方括号包裹
            if (u.startsWith("[")) {
                // [IPv6]:port 格式
                int idx = u.lastIndexOf(']');
                if (idx != -1) {
                    u = u.substring(1, idx); // 移除[和]
                }
            } else if (countChar(u, ':') == 1) {
                // IPv4:port 格式
                int idx = u.lastIndexOf(':');
                if (idx != -1) {
                    u = u.substring(0, idx);
                }
            }
            // 如果是纯IPv6地址（无端口），保持原样
            //（注：能走到这里的字面量不含方括号、冒号数必为 0 或 ≥2，两分支与 Go 一样是
            // 保真移植的防御性代码——Go 对 "[::1]"/"1.2.3.4:80" 在 ParseIP 处即判失败，
            // 走下方域名分支，Java 行为完全一致）
            return u;
        }

        // 不是IP地址，作为域名处理
        // 移除端口号
        int colon = u.indexOf(':');
        if (colon >= 0) {
            u = u.substring(0, colon);
        }

        // 移除路径部分
        int slash = u.indexOf('/');
        if (slash >= 0) {
            u = u.substring(0, slash);
        }

        return u;
    }

    /** Go {@code strings.Count} 的最小实现（仅在保真移植的分支里用到）。 */
    private static int countChar(String s, char target) {
        int count = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == target) {
                count++;
            }
        }
        return count;
    }

    /**
     * 规范化扫描类型串。
     *
     * 对应 Go 的 {@code ParseScanType(scanType)}
     */
    public static String parseScanType(String scanType) {
        if (scanType == null) {
            return "connect"; // Go 的 switch default
        }
        return switch (scanType) {
            case "syn", "SYN" -> "syn";
            case "udp", "UDP" -> "udp";
            case "connect", "tcp" -> "connect";
            default -> "connect";
        };
    }

    /**
     * 默认扫描配置。
     *
     * <p>未显式列出的字段保持 Java 默认值——与 Go 结构体零值一致。
     *
     * 对应 Go 的 {@code DefaultScanConfig()}
     */
    public static ScanConfig defaultScanConfig() {
        ScanConfig config = new ScanConfig();
        config.target = "";
        config.ports = "";
        config.threads = NmapConstants.DEFAULT_THREADS; // 50（Go 字面量同值）
        config.timeout = Duration.ofSeconds(3);
        config.scanType = "connect";
        config.osDetection = false;
        config.serviceDetection = false;
        return config;
    }

    /**
     * 统计扫描结果。
     *
     * <p>注意 Go 侧 {@code state == "open"} <b>不含</b> {@code open|filtered}；
     * {@code Vulnerable} 只按端口号判定、<b>不看状态</b>（与 Go 一致）。
     *
     * 对应 Go 的 {@code AnalyzeResults(results) ScanAnalysis}
     */
    public static ScanAnalysis analyzeResults(List<NmapResult> results) {
        ScanAnalysis analysis = new ScanAnalysis();
        analysis.totalHosts = results == null ? 0 : results.size();

        if (results == null) {
            return analysis;
        }

        for (NmapResult result : results) {
            if (NmapConstants.HOST_UP.equals(result.status)) {
                analysis.activeHosts++;
            }

            if (result.ports != null) {
                for (Map.Entry<Integer, PortInfo> entry : result.ports.entrySet()) {
                    PortInfo portInfo = entry.getValue();
                    if (portInfo == null) {
                        continue;
                    }
                    if (NmapConstants.PORT_STATE_OPEN.equals(portInfo.state)) {
                        analysis.openPorts.merge(entry.getKey(), 1, Integer::sum);
                        analysis.totalOpenPorts++;
                        String service = portInfo.service == null ? "" : portInfo.service;
                        analysis.services.merge(service, 1, Integer::sum);
                        if ("unknown".equals(service) || service.isEmpty()) {
                            analysis.unknownServices++;
                        }
                    }
                }
            }

            String os = result.os;
            if (os != null && !os.isEmpty()) {
                analysis.os.merge(os, 1, Integer::sum);
            }

            if (result.ports != null) {
                for (PortInfo port : result.ports.values()) {
                    if (port != null && isVulnerablePort(port.port)) {
                        String service = port.service == null ? "" : port.service;
                        analysis.vulnerable.add(
                                Fmt.format("%s:%d (%s)", result.ip, port.port, service));
                    }
                }
            }
        }

        return analysis;
    }

    /**
     * 判定是否为常见脆弱端口。
     *
     * 对应 Go 的 {@code isVulnerablePort(port)}
     */
    public static boolean isVulnerablePort(int port) {
        for (int p : VULNERABLE_PORTS) {
            if (p == port) {
                return true;
            }
        }
        return false;
    }

    /**
     * 对 CIDR 做一轮发现。
     *
     * <p>参数与 Go 逐项对齐：默认配置 → target=cidr、ports=&quot;&quot;（仅主机发现）、
     * threads=200、timeout=1s，再交给扫描引擎。Go 的 {@code context.Context} 不移植。
     *
     * 对应 Go 的 {@code NetworkDiscovery(ctx, cidr) []NmapResult}
     */
    public static List<NmapResult> networkDiscovery(String cidr) {
        ScanConfig config = defaultScanConfig();
        config.target = cidr == null ? "" : cidr;
        config.ports = ""; // 仅主机发现
        config.threads = 200;
        config.timeout = Duration.ofSeconds(1);

        try {
            List<NmapResult> results = NmapScan.nmapScan(config);
            return results == null ? new ArrayList<>() : results;
        } catch (UnsupportedOperationException e) {
            // B 号桩未就绪：按「无结果」返回，避免异常泄漏到输出
            return new ArrayList<>();
        }
    }

    /**
     * 从文件读取目标列表（每行一个，跳过空行/注释）。
     *
     * <p>A 号的 {@code -iL} 分支依赖本方法。失败信息/空文件警告直接 {@code println}
     *（Go 侧是 {@code fmt.Println}，无颜色、不受静默模式抑制）。
     * 对应 Go 的 {@code LoadTargetsFromFile(filename) []string}
     *
     * @return 读取失败或文件为空时返回<b>空列表</b>（Go 返回 nil/空 slice，调用方判 len）
     */
    public static List<String> loadTargetsFromFile(String filename) {
        List<String> targets = new ArrayList<>();
        String fn = filename == null ? "" : filename;

        // 检查文件扩展名
        String lowerName = fn.toLowerCase(Locale.ROOT);
        if (!lowerName.endsWith(".txt") && !lowerName.endsWith(".lst")) {
            System.out.println(I18n.Tf("nmap.warn.file_format", fn));
        }

        String content;
        try {
            content = Files.readString(Paths.get(fn), StandardCharsets.UTF_8);
        } catch (IOException | InvalidPathException e) {
            System.out.println(I18n.Tf("nmap.err.read_file_failed", e));
            return targets;
        }

        for (String rawLine : content.split("\n", -1)) {
            String line = rawLine.strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            // 移除http/https前缀
            line = removeProtocolPrefix(line);
            if (!line.isEmpty()) {
                targets.add(line);
            }
        }

        if (targets.isEmpty()) {
            System.out.println(I18n.Tf("nmap.warn.no_valid_target", fn));
        }

        return targets;
    }
}

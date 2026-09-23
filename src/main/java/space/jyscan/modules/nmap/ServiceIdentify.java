package space.jyscan.modules.nmap;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 服务识别，移植自 freeclient/internal/nmap/scan.go 的：
 * {@code identifyService}(2144) / {@code identifyServiceByBanner}(2224) /
 * {@code extractMySQLVersion}(2323) / {@code identifyServiceByProtocol}(2343) /
 * {@code identifyUDPService}(2352) / {@code identifyUDPServiceByBanner}(2382)，
 * 以及顶部的 {@code mysqlVersionRegexes}(64-71)。
 *
 * <p><b>归属</b>：本文件由 B 号子代理新建。
 *
 * <p>Go 的 {@code serviceMap}（scan.go:2145）是<b>函数内局部变量</b>，
 * 每次调用都重建；这里提成静态常量 {@link #TCP_SERVICE_MAP}（内容逐项一致，
 * 含 {@code 3389 → "rdp"}、{@code 2049 → "nfs"}），行为不变。
 * <b>注意与 {@link UltraFastScan#OPTIMIZED_SERVICE_PORT_MAP} 不是同一张表</b>
 * —— 那张来自 scan_optimized.go:85（{@code 3389 → "ms-wbt-server"} 等）。
 *
 * <p>Go 源码中的运算符优先级陷阱已原样保留：
 * <pre>
 * if strings.Contains(l, "ftp") || strings.Contains(l, "220 ") &amp;&amp; (...) {  // &amp;&amp; 先结合
 *     // 等价于  ftp || ("220 " &amp;&amp; filezilla/vsftpd/proftpd)
 * }
 * if strings.HasPrefix(banner, "220 ") &amp;&amp; (...)   // 用的是原始 banner（大小写敏感）
 * </pre>
 */
public final class ServiceIdentify {

    /** 对应 scan.go:64-71 的 {@code mysqlVersionRegexes}（顺序敏感，逐条对齐）。 */
    private static final List<Pattern> MYSQL_VERSION_REGEXES = List.of(
            Pattern.compile("(\\d+\\.\\d+\\.\\d+)-MariaDB"),
            Pattern.compile("MariaDB[\\s\\-]*(\\d+\\.\\d+\\.\\d+)"),
            Pattern.compile("(\\d+\\.\\d+\\.\\d+)[\\s\\-]*MySQL"),
            Pattern.compile("MySQL[\\s\\-]*(\\d+\\.\\d+\\.\\d+)"),
            Pattern.compile("\\b(\\d+\\.\\d+\\.\\d+)\\b"),
            Pattern.compile("\\b(\\d+\\.\\d+)\\b"));

    /**
     * 对应 scan.go:2145 的 {@code serviceMap}（identifyService 用）。
     * Go 是函数内 map 字面量，这里提为常量，键值逐项一致。
     */
    public static final Map<Integer, String> TCP_SERVICE_MAP = Map.ofEntries(
            Map.entry(21, "ftp"),
            Map.entry(22, "ssh"),
            Map.entry(23, "telnet"),
            Map.entry(25, "smtp"),
            Map.entry(53, "dns"),
            Map.entry(80, "http"),
            Map.entry(110, "pop3"),
            Map.entry(111, "rpcbind"),
            Map.entry(135, "msrpc"),
            Map.entry(139, "netbios-ssn"),
            Map.entry(143, "imap"),
            Map.entry(443, "https"),
            Map.entry(445, "microsoft-ds"),
            Map.entry(993, "imaps"),
            Map.entry(995, "pop3s"),
            Map.entry(1433, "ms-sql-s"),
            Map.entry(1521, "oracle"),
            Map.entry(2049, "nfs"),
            Map.entry(3306, "mysql"),
            Map.entry(3389, "rdp"),
            Map.entry(5432, "postgresql"),
            Map.entry(5900, "vnc"),
            Map.entry(6379, "redis"),
            Map.entry(8080, "http-proxy"),
            Map.entry(27017, "mongodb"));

    /** 对应 scan.go:2174 的 {@code strictPorts}（邮件类端口必须有 banner 才认）。 */
    private static final Set<Integer> STRICT_PORTS = Set.of(25, 110, 143, 993, 995);

    /** 对应 scan.go:2183 的 {@code highConfidencePorts}（无 banner 也可按端口号认）。 */
    private static final Set<Integer> HIGH_CONFIDENCE_PORTS = Set.of(80, 443, 135, 139, 445, 3389, 8080);

    /**
     * 对应 scan.go:2353 的 {@code serviceMap}（identifyUDPService 用），
     * 与 scan.go:169 的 {@code commonUDPPorts} 内容完全相同（Go 定义了两份）。
     */
    public static final Map<Integer, String> UDP_SERVICE_MAP = Map.ofEntries(
            Map.entry(53, "dns"),
            Map.entry(67, "dhcps"),
            Map.entry(68, "dhcpc"),
            Map.entry(69, "tftp"),
            Map.entry(123, "ntp"),
            Map.entry(161, "snmp"),
            Map.entry(162, "snmptrap"),
            Map.entry(514, "syslog"),
            Map.entry(520, "rip"),
            Map.entry(1434, "ms-sql-m"),
            Map.entry(1900, "upnp"),
            Map.entry(5353, "mdns"));

    private ServiceIdentify() {
    }

    /**
     * 对应 Go 的 {@code identifyService(port, banner)}（scan.go:2144）。
     *
     * <p>判定顺序：banner 深度识别 → 严格端口（无 banner 直接 unknown）→
     * 端口号映射 → 协议特征（Go 恒返回 unknown）→ unknown。
     */
    public static String identifyService(int port, String banner) {
        // 优先尝试基于 banner 的深度识别（最准确）
        if (banner != null && !banner.isEmpty()) {
            String service = identifyServiceByBanner(banner);
            if (!"unknown".equals(service)) {
                return service;
            }
        }

        // 需要严格验证的端口：没有 banner 就标记为 unknown
        if (STRICT_PORTS.contains(port)) {
            return "unknown";
        }

        // 尝试基于端口号的识别
        String service = TCP_SERVICE_MAP.get(port);
        if (service != null) {
            // 对于高置信度端口或没有严格要求的端口，可以基于端口号识别
            if (HIGH_CONFIDENCE_PORTS.contains(port) || !STRICT_PORTS.contains(port)) {
                return service;
            }
        }

        // 尝试协议特征识别
        return identifyServiceByProtocol(port);
    }

    /**
     * 对应 Go 的 {@code identifyServiceByBanner(banner)}（scan.go:2224）。
     *
     * <p>Go 里 FTP/SMTP 两支是 {@code A || B &amp;&amp; C}（{@code &&} 优先级更高），
     * 且 SMTP 的前缀判断用<b>原始</b> banner（大小写敏感），已逐字保留。
     */
    public static String identifyServiceByBanner(String banner) {
        if (banner == null) {
            banner = "";
        }
        String bannerLower = banner.toLowerCase();

        // 优先识别 HTTP 服务（最常见）—— 包括 Web 防火墙/拦截页面
        if (bannerLower.contains("http")
                || bannerLower.contains("server:")
                || bannerLower.contains("apache")
                || bannerLower.contains("nginx")
                || bannerLower.contains("iis")
                || bannerLower.contains("tomcat")
                || bannerLower.contains("lighttpd")
                || bannerLower.contains("cloudflare")
                || bannerLower.contains("cloudfront")
                || bannerLower.contains("akamai")
                || bannerLower.contains("aliyun")
                || bannerLower.contains("tencent")
                || bannerLower.contains("403 forbidden")
                || bannerLower.contains("404 not found")
                || bannerLower.contains("502 bad gateway")
                || bannerLower.contains("503 service unavailable")
                || bannerLower.contains("<!doctype")
                || bannerLower.contains("<html")
                || bannerLower.contains("<head")
                || bannerLower.contains("<body")) {
            return "http";
        }

        // SSH 服务识别（支持非标准端口）
        if (bannerLower.contains("ssh")
                || bannerLower.contains("openssh")
                || banner.startsWith("SSH-")) {
            return "ssh";
        }

        // FTP 服务识别：  ftp || ("220 " && (filezilla|vsftpd|proftpd))
        if (bannerLower.contains("ftp")
                || bannerLower.contains("220 ") && (bannerLower.contains("filezilla")
                        || bannerLower.contains("vsftpd") || bannerLower.contains("proftpd"))) {
            return "ftp";
        }

        // SMTP 服务识别：  smtp || (HasPrefix(banner,"220 ") && (esmtp|sendmail|postfix))
        if (bannerLower.contains("smtp")
                || banner.startsWith("220 ") && (bannerLower.contains("esmtp")
                        || bannerLower.contains("sendmail") || bannerLower.contains("postfix"))) {
            return "smtp";
        }

        // 数据库服务识别
        if (bannerLower.contains("mysql")) {
            String version = extractMySQLVersion(bannerLower);
            if (!version.isEmpty()) {
                return "mysql " + version;
            }
            return "mysql";
        }
        if (bannerLower.contains("postgres") || bannerLower.contains("postgresql")) {
            return "postgresql";
        }
        if (bannerLower.contains("redis")) {
            return "redis";
        }
        if (bannerLower.contains("mongodb") || bannerLower.contains("mongod")) {
            return "mongodb";
        }
        if (bannerLower.contains("oracle")) {
            return "oracle";
        }
        if (bannerLower.contains("microsoft sql") || bannerLower.contains("sql server")) {
            return "ms-sql-s";
        }

        // 远程桌面服务识别
        if (bannerLower.contains("rdp") || bannerLower.contains("remote desktop")) {
            return "rdp";
        }

        // Telnet 服务识别
        if (bannerLower.contains("telnet")) {
            return "telnet";
        }

        // DNS 服务识别
        if (bannerLower.contains("dns") || bannerLower.contains("bind")) {
            return "dns";
        }

        // 邮件服务识别
        if (bannerLower.contains("pop3")) {
            return "pop3";
        }
        if (bannerLower.contains("imap")) {
            return "imap";
        }

        return "unknown";
    }

    /**
     * 对应 Go 的 {@code extractMySQLVersion(banner)}（scan.go:2323）。
     *
     * <p>调用方传的是 <b>bannerLower</b>（scan.go:2275），因此末尾
     * {@code strings.Contains(banner, "MariaDB")} 这一支在 Go 里恒不成立
     * （入参已全小写）—— 这是 Go 原文的死分支，此处<b>原样保留</b>，
     * 以保证任何输入下与 Go 的返回值一致。
     */
    public static String extractMySQLVersion(String banner) {
        if (banner == null) {
            banner = "";
        }
        for (Pattern re : MYSQL_VERSION_REGEXES) {
            java.util.regex.Matcher m = re.matcher(banner);
            if (m.find() && m.groupCount() >= 1) {
                return m.group(1);
            }
        }
        // Go: if strings.Contains(banner, "MariaDB") { return "MariaDB" }
        // 入参是小写化后的 banner，故此条件与 Go 一样不会命中
        if (banner.contains("MariaDB")) {
            return "MariaDB";
        }
        return "";
    }

    /**
     * 对应 Go 的 {@code identifyServiceByProtocol(port)}（scan.go:2343）：
     * Go 目前是占位实现，恒返回 {@code "unknown"}。
     */
    public static String identifyServiceByProtocol(int port) {
        return "unknown";
    }

    /** 对应 Go 的 {@code identifyUDPService(port, banner)}（scan.go:2352）。 */
    public static String identifyUDPService(int port, String banner) {
        // 首先尝试基于端口号的识别
        String service = UDP_SERVICE_MAP.get(port);
        if (service != null) {
            return service;
        }
        // 端口不是标准端口，尝试基于 banner 识别
        if (banner != null && !banner.isEmpty()) {
            return identifyUDPServiceByBanner(banner);
        }
        return "unknown";
    }

    /** 对应 Go 的 {@code identifyUDPServiceByBanner(banner)}（scan.go:2382）。 */
    public static String identifyUDPServiceByBanner(String banner) {
        String bannerLower = (banner == null ? "" : banner).toLowerCase();

        if (bannerLower.contains("dns") || bannerLower.contains("bind")) {
            return "dns";
        }
        if (bannerLower.contains("snmp")) {
            return "snmp";
        }
        if (bannerLower.contains("ntp")) {
            return "ntp";
        }
        if (bannerLower.contains("tftp")) {
            return "tftp";
        }
        if (bannerLower.contains("syslog")) {
            return "syslog";
        }
        if (bannerLower.contains("dhcp")) {
            return "dhcps";
        }
        if (bannerLower.contains("sql") || bannerLower.contains("microsoft")) {
            return "ms-sql-m";
        }
        return "unknown";
    }

    /**
     * 便捷方法：返回 TCP 服务映射的<b>副本</b>（供需要可变 map 的调用方使用）。
     * Go 侧没有对应函数，此处仅为 Java 侧便利提供。
     */
    public static Map<Integer, String> newTcpServiceMapCopy() {
        return new HashMap<>(TCP_SERVICE_MAP);
    }
}

package space.jyscan.modules.nmap;

import space.jyscan.core.util.Fmt;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;

/**
 * 操作系统主动探测，移植自 freeclient/internal/nmap/osdetect.go。
 *
 * <p><b>归属</b>：本文件由 D 号子代理实现。签名被 B 号（扫描引擎 scan.go:1205）
 * 调用，请勿改动签名。
 *
 * <p>思路与 Go 一致：先看 SSH 端口的 banner，再看常见 HTTP 端口的 Server 头。
 * Go 侧用 net.DialTimeout 裸 TCP 读写（HEAD / HTTP/1.0 单次读、SSH banner 单次读），
 * Java 同样用 {@link Socket} 逐行复刻，而非 HttpURLConnection（后者会改写请求行、
 * 追加头部并自动处理重定向，行为会偏离 Go）。
 */
public final class OsDetect {

    private OsDetect() {
    }

    /** Go: httpPorts := []int{80, 443, 8080, 8443, 8000, 8888}。 */
    private static final int[] HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888};

    /**
     * 通过主动探测 HTTP Server 头和 SSH banner 来识别操作系统。
     *
     * @param ip    目标 IP
     * @param ports 已知开放端口（用于挑选要探测的端口）
     * @return OS 猜测；无法判定时返回 {@code "Unknown"}
     */
    public static String probeOSByActiveProbe(String ip, Map<Integer, PortInfo> ports) {
        // Go: probeTimeout := 3 * time.Second
        Duration probeTimeout = Duration.ofSeconds(3);

        if (ports != null && ports.containsKey(22)) {
            String os = probeSSHForOS(ip, 22, probeTimeout);
            if (!os.isEmpty()) {
                return os;
            }
        }

        if (ports != null) {
            for (int port : HTTP_PORTS) {
                if (ports.containsKey(port)) {
                    String os = probeHTTPServerForOS(ip, port, probeTimeout);
                    if (!os.isEmpty()) {
                        return os;
                    }
                }
            }
        }

        return "Unknown";
    }

    // =====================================================================
    // Go: probeHTTPServerForOS（osdetect.go:32-112）
    // =====================================================================

    static String probeHTTPServerForOS(String ip, int port, Duration timeout) {
        long ms = RawScanEngine.toMillis(timeout);
        if (ms < 0) {
            return "";
        }
        try (Socket conn = new Socket()) {
            conn.connect(new InetSocketAddress(ip, port), (int) Math.min(ms, Integer.MAX_VALUE));
            // Go: conn.SetDeadline(time.Now().Add(timeout))
            conn.setSoTimeout((int) Math.min(Math.max(ms, 1L), Integer.MAX_VALUE));

            OutputStream out = conn.getOutputStream();
            out.write(Fmt.format("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
                    .getBytes(StandardCharsets.UTF_8));
            out.flush();

            InputStream in = conn.getInputStream();
            byte[] buf = new byte[4096];
            // Go: 单次 Read，读到什么算什么
            int n = in.read(buf);
            if (n <= 0) {
                return "";
            }

            String text = new String(buf, 0, n, StandardCharsets.UTF_8);
            for (String line : text.split("\r\n", -1)) {
                String lower = line.toLowerCase(Locale.ROOT);
                if (!lower.startsWith("server:")) {
                    continue;
                }
                // Go: server := strings.TrimSpace(line[7:])（保留原始大小写）
                String server = line.substring(7).strip();
                String serverLower = server.toLowerCase(Locale.ROOT);

                if (serverLower.contains("cloudflare")) {
                    return "Linux/Unix (Cloudflare CDN)";
                }
                if (serverLower.contains("cloudfront")) {
                    return "Linux/Unix (AWS CloudFront)";
                }
                if (serverLower.contains("akamai")) {
                    return "Linux/Unix (Akamai CDN)";
                }
                if (serverLower.contains("aliyun") || serverLower.contains("yunjiasu")) {
                    return "Linux/Unix (Alibaba Cloud)";
                }
                if (serverLower.contains("tencent") || serverLower.contains("yunjian")) {
                    return "Linux/Unix (Tencent Cloud)";
                }
                if (serverLower.contains("openresty")) {
                    return "Linux/Unix (OpenResty)";
                }
                if (serverLower.contains("nginx")) {
                    String ver = extractVersion(server, "nginx/");
                    if (!ver.isEmpty()) {
                        return Fmt.format("Linux/Unix (nginx %s)", ver);
                    }
                    return "Linux/Unix (nginx)";
                }
                if (serverLower.contains("apache")) {
                    String ver = extractVersion(server, "Apache/");
                    if (!ver.isEmpty()) {
                        return Fmt.format("Linux/Unix (Apache %s)", ver);
                    }
                    return "Linux/Unix (Apache)";
                }
                if (serverLower.contains("iis")) {
                    String ver = extractVersion(server, "Microsoft-IIS/");
                    if (!ver.isEmpty()) {
                        return Fmt.format("Windows (IIS %s)", ver);
                    }
                    return "Windows (IIS)";
                }
                if (serverLower.contains("tomcat")) {
                    return "Linux/Unix (Tomcat)";
                }
                if (serverLower.contains("litespeed")) {
                    return "Linux/Unix (LiteSpeed)";
                }
                if (serverLower.contains("caddy")) {
                    return "Linux/Unix (Caddy)";
                }
                // Go: 有 Server 头但无法归类 → 直接返回 ""（不继续看后面的行）
                return "";
            }

            return "";
        } catch (IOException e) {
            // Go: Dial/Write/Read 出错 → ""
            return "";
        }
    }

    // =====================================================================
    // Go: probeSSHForOS（osdetect.go:114-154）
    // =====================================================================

    static String probeSSHForOS(String ip, int port, Duration timeout) {
        long ms = RawScanEngine.toMillis(timeout);
        if (ms < 0) {
            return "";
        }
        try (Socket conn = new Socket()) {
            conn.connect(new InetSocketAddress(ip, port), (int) Math.min(ms, Integer.MAX_VALUE));
            conn.setSoTimeout((int) Math.min(Math.max(ms, 1L), Integer.MAX_VALUE));

            InputStream in = conn.getInputStream();
            byte[] buf = new byte[256];
            // Go: 单次 Read 256 字节
            int n = in.read(buf);
            if (n <= 0) {
                return "";
            }

            String banner = new String(buf, 0, n, StandardCharsets.UTF_8)
                    .toLowerCase(Locale.ROOT);

            if (banner.contains("ubuntu")) {
                return "Ubuntu Linux";
            }
            if (banner.contains("debian")) {
                return "Debian Linux";
            }
            if (banner.contains("centos")) {
                return "CentOS Linux";
            }
            if (banner.contains("fedora")) {
                return "Fedora Linux";
            }
            if (banner.contains("red hat") || banner.contains("rhel")) {
                return "Red Hat Enterprise Linux";
            }
            if (banner.contains("openssh")) {
                return "Linux/Unix";
            }
            if (banner.contains("cisco")) {
                return "Cisco IOS";
            }

            return "";
        } catch (IOException e) {
            // Go: Dial/Read 出错 → ""
            return "";
        }
    }

    // =====================================================================
    // Go: extractVersion（osdetect.go:156-169）
    // =====================================================================

    /** 从 Server 头里取前缀后的数字段（允许 '.' 与 '-'），本包内部使用。 */
    static String extractVersion(String server, String prefix) {
        int idx = server.indexOf(prefix);
        if (idx == -1) {
            return "";
        }
        String rest = server.substring(idx + prefix.length()).strip();
        for (int i = 0; i < rest.length(); i++) {
            char ch = rest.charAt(i);
            if (ch != '.' && ch != '-' && (ch < '0' || ch > '9')) {
                return rest.substring(0, i);
            }
        }
        return rest;
    }
}

package space.jyscan.modules.waf;

import java.util.ArrayList;
import java.util.List;

/**
 * 目标URL规范化与候选URL生成，移植自 freeclient/internal/waf/detector.go 的
 * normalizeTarget / candidateURLs / switchScheme / dropDefaultPort / splitHostPortLoose。
 *
 * <p>行为与 detector_test.go 断言一致，例如：
 * <ul>
 *   <li>104.18.5.159 -&gt; https://104.18.5.159（无端口默认尝试HTTPS）</li>
 *   <li>example.com:8080 -&gt; http://example.com:8080（非443端口使用HTTP）</li>
 *   <li>http://a:80/x 的候选为 [http://a:80/x, https://a/x]（切换协议时去掉默认端口）</li>
 * </ul>
 */
public final class TargetUrls {

    private TargetUrls() {
    }

    /** 规范化目标URL格式，对应 Go 的 normalizeTarget。 */
    public static String normalizeTarget(String target) {
        if (target == null) {
            target = "";
        }
        target = target.trim();
        if (!target.startsWith("http://") && !target.startsWith("https://")) {
            // 尝试HTTPS
            String[] hp = splitHostPortLoose(target);
            String host = hp[0];
            String port = hp[1];
            if ("443".equals(port)) {
                target = "https://" + target;
            } else if (!port.isEmpty()) {
                target = "http://" + target;
            } else {
                // 默认尝试HTTPS
                target = "https://" + host;
            }
        }
        return target;
    }

    /**
     * 返回按优先级排序的候选URL列表，对应 Go 的 candidateURLs。
     *
     * <p>默认优先HTTPS；当目标为 IP 直连等场景时 HTTPS 会因缺少 SNI 而握手失败
     * (Cloudflare 等 CDN 会直接返回 tls: handshake failure)，
     * 此时自动回退到 HTTP，避免整个探测直接失败。
     */
    public static List<String> candidateURLs(String target) {
        String primary = normalizeTarget(target);
        if (primary.isEmpty()) {
            return new ArrayList<>(0); // 对应 Go 的 nil 切片
        }
        List<String> urls = new ArrayList<>(2);
        urls.add(primary);
        String alt = switchScheme(primary);
        if (!alt.isEmpty() && !alt.equals(primary)) {
            urls.add(alt);
        }
        return urls;
    }

    /** 切换URL协议(http &lt;-&gt; https)，并去掉与协议对应的默认端口，对应 Go 的 switchScheme。 */
    public static String switchScheme(String url) {
        if (url != null && url.startsWith("https://")) {
            return "http://" + dropDefaultPort(url.substring("https://".length()), "443");
        }
        if (url != null && url.startsWith("http://")) {
            return "https://" + dropDefaultPort(url.substring("http://".length()), "80");
        }
        return "";
    }

    /**
     * 移除与目标协议默认端口一致的端口号(避免 http://host:443 这类错误URL)，
     * 对应 Go 的 dropDefaultPort。
     */
    public static String dropDefaultPort(String hostPort, String port) {
        if (hostPort == null || hostPort.isEmpty()) {
            return hostPort == null ? "" : hostPort;
        }
        String[] hp = splitHostPort(hostPort);
        String host = hp == null ? null : hp[0];
        String p = hp == null ? null : hp[1];
        if (hp == null || !port.equals(p)) {
            return hostPort;
        }
        if (host.contains(":")) {
            // IPv6 字面量需要重新加上方括号
            return "[" + host + "]";
        }
        return host;
    }

    /**
     * 宽松解析 host[:port]，对应 Go 的 splitHostPortLoose。
     * 无端口、IPv6 字面量等情况返回 (原值, "")，不报错。
     */
    public static String[] splitHostPortLoose(String target) {
        if (target == null) {
            target = "";
        }
        String[] hp = splitHostPort(target);
        if (hp != null) {
            return hp;
        }
        return new String[]{target, ""};
    }

    /**
     * 严格解析 host[:port]，语义对应 Go 的 net.SplitHostPort。
     * 解析失败（缺端口、冒号过多、括号不匹配等）返回 null。
     */
    public static String[] splitHostPort(String hostPort) {
        if (hostPort == null) {
            return null;
        }
        // 端口位于最后一个冒号之后
        int i = hostPort.lastIndexOf(':');
        if (i < 0) {
            return null; // missing port in address
        }
        int j = 0;
        int k = 0;
        String host;
        if (!hostPort.isEmpty() && hostPort.charAt(0) == '[') {
            // 期望最后一个 ']' 恰好位于最后一个 ':' 之前
            int end = hostPort.indexOf(']');
            if (end < 0) {
                return null; // missing ']' in address
            }
            if (end + 1 == hostPort.length() || end + 1 != i) {
                // ']' 后没有冒号，或 ']' 后的冒号不是最后一个 —— 对应 Go 的 missing port / too many colons
                return null;
            }
            host = hostPort.substring(1, end);
            j = 1;
            k = end + 1; // '[' / ']' 不可能出现在这些位置之前
        } else {
            host = hostPort.substring(0, i);
            if (host.indexOf(':') >= 0) {
                return null; // too many colons in address
            }
        }
        if (hostPort.substring(j).indexOf('[') >= 0) {
            return null; // missing '[' in address
        }
        if (hostPort.substring(k).indexOf(']') >= 0) {
            return null; // missing ']' in address
        }
        return new String[]{host, hostPort.substring(i + 1)};
    }
}

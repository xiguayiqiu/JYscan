package space.jyscan.modules.whois;

/**
 * Whois 模块内部工具方法：IP/域名判定、TLD 提取、Go 风格耗时格式化、错误文本提取。
 */
public final class WhoisUtil {

    private WhoisUtil() {
    }

    // =====================================================================
    // IP / TLD 判定
    // =====================================================================

    /**
     * 判断查询目标是否为 IP 字面量（IPv4/IPv6）。
     * 支持带 CIDR 后缀的形式（如 203.0.113.0/24），按斜杠前的部分判定。
     */
    public static boolean isIpLiteral(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        String v = s.trim();
        int slash = v.indexOf('/');
        if (slash >= 0) {
            v = v.substring(0, slash);
        }
        if (v.isEmpty()) {
            return false;
        }
        if (v.indexOf(':') >= 0) {
            return isIpv6(v);
        }
        return isIpv4(v);
    }

    private static boolean isIpv4(String v) {
        String[] parts = v.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) {
                return false;
            }
            for (int i = 0; i < p.length(); i++) {
                char c = p.charAt(i);
                if (c < '0' || c > '9') {
                    return false;
                }
            }
            if (Integer.parseInt(p) > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean isIpv6(String v) {
        int colons = 0;
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == ':') {
                colons++;
            } else if (Character.digit(c, 16) < 0) {
                return false;
            }
        }
        // IPv6 至少包含两个冒号（IPv4 映射形式也满足）
        return colons >= 2;
    }

    /**
     * 提取查询目标的 TLD（最后一个标签，小写），用于向 whois.iana.org 查询注册局服务器。
     * 例如 example.com -> com，example.co.uk -> uk，www.example.com. -> com。
     */
    public static String tldOf(String query) {
        if (query == null || query.isEmpty()) {
            return "";
        }
        String s = query.trim();
        int slash = s.indexOf('/');
        if (slash >= 0) {
            s = s.substring(0, slash);
        }
        while (s.endsWith(".")) {
            s = s.substring(0, s.length() - 1);
        }
        if (s.isEmpty()) {
            return "";
        }
        int dot = s.lastIndexOf('.');
        if (dot >= 0 && dot < s.length() - 1) {
            s = s.substring(dot + 1);
        }
        return s.toLowerCase(java.util.Locale.ROOT);
    }

    // =====================================================================
    // Go time.Duration.String() 风格格式化
    // =====================================================================

    /**
     * 把纳秒时长格式化为 Go {@code time.Duration.String()} 的形式，
     * 如 {@code 1.234567891s}、{@code 456.7ms}、{@code 1.5µs}、{@code 1m30s}。
     * 用于渲染 FormatResult 的「耗时: %v」行。
     */
    public static String goDuration(long nanos) {
        if (nanos == 0) {
            return "0s";
        }
        String sign = "";
        long u = nanos;
        if (u < 0) {
            sign = "-";
            u = -u;
        }
        if (u < 1_000L) {
            return sign + u + "ns";
        }
        if (u < 1_000_000L) {
            // 微秒为最大单位（最多 3 位小数）
            return sign + frac(u / 1_000L, u % 1_000L, 3) + "µs";
        }
        if (u < 1_000_000_000L) {
            // 毫秒为最大单位（最多 6 位小数）
            return sign + frac(u / 1_000_000L, u % 1_000_000L, 6) + "ms";
        }
        // 秒及以上：按 h/m/s 组合，Go 不输出天单位
        long sec = u / 1_000_000_000L;
        long rem = u % 1_000_000_000L;
        long hours = sec / 3600;
        sec %= 3600;
        long mins = sec / 60;
        sec %= 60;

        StringBuilder sb = new StringBuilder(sign);
        if (hours > 0) {
            sb.append(hours).append('h');
        }
        if (hours != 0 || mins > 0) {
            // 有小时位时 Go 保留 0m（如 1h0m0s）
            sb.append(mins).append('m');
        }
        if (rem == 0) {
            sb.append(sec).append('s');
        } else {
            sb.append(sec).append('.').append(stripZeros(padLeft(Long.toString(rem), 9, '0'))).append('s');
        }
        return sb.toString();
    }

    /** 整数部分 + 去掉尾随零的小数部分。 */
    private static String frac(long intPart, long fracPart, int width) {
        String f = stripZeros(padLeft(Long.toString(fracPart), width, '0'));
        return f.isEmpty() ? Long.toString(intPart) : intPart + "." + f;
    }

    private static String stripZeros(String s) {
        int end = s.length();
        while (end > 0 && s.charAt(end - 1) == '0') {
            end--;
        }
        return s.substring(0, end);
    }

    private static String padLeft(String s, int width, char fill) {
        if (s.length() >= width) {
            return s;
        }
        StringBuilder sb = new StringBuilder(width);
        for (int i = s.length(); i < width; i++) {
            sb.append(fill);
        }
        return sb.append(s).toString();
    }

    // =====================================================================
    // 错误文本
    // =====================================================================

    /**
     * 提取异常的可读文本（只输出消息，不打印堆栈，与 Go 的 {@code %v} 打印 error 一致）。
     */
    public static String errorText(Throwable t) {
        if (t == null) {
            return "<nil>";
        }
        String msg = t.getMessage();
        if (msg == null || msg.isEmpty()) {
            String cls = t.getClass().getSimpleName();
            return cls.isEmpty() ? t.getClass().getName() : cls;
        }
        return msg;
    }
}

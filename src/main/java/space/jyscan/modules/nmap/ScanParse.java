package space.jyscan.modules.nmap;

import space.jyscan.core.i18n.I18n;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Port / target / IP-range parsing and IP-literal helpers.
 *
 * <p>Java port of the parsing helpers in {@code freeclient/internal/nmap/scan.go}
 * （{@code parseTargetWithFamily} / {@code parseCIDR} / {@code parseIPRange} /
 * {@code parsePorts}）与 {@code scan_optimized.go}（{@code parsePortsOptimized}）。
 *
 * <p>逐条对齐 Go 的语义与怪癖（均以 Go golden 实测为准）：
 * <ul>
 *   <li>{@code net.ParseIP} 对点分四段<b>拒绝前导零</b>、拒绝 {@code %zone}；
 *       IPv6 十六进制组允许前导零（≤4 位）；<b>恒返回 16 字节</b>
 *       （点分形式即 v4-mapped，因此 {@code "1.2.3.4"} 与 {@code "::ffff:1.2.3.4"}
 *       字节完全相同，跨形态 IP 范围可正常比较）；</li>
 *   <li>{@code IP.String()}：v4-mapped 打点分；v4-兼容（{@code ::1.2.3.4}）打 v6
 *       压缩十六进制（{@code ::102:304}）；最长零串压缩（≥2 位，平手取首段）；</li>
 *   <li>{@code IP.To4()} 仅 v4-<b>mapped</b> 为真，v4-兼容为假 →
 *       {@link #filterByIPFamily} 只保留 mapped/4 字节与解析失败项（域名）；</li>
 *   <li>CIDR 展开含网络号与广播地址；掩码允许前导零（{@code /024}）、拒绝 {@code +}；</li>
 *   <li>{@code parseIPRange}：Split 必须恰 2 段，两端都须是完整 IP，否则打印
 *       {@code nmap.err.invalid_ip_range} / {@code nmap.err.invalid_ip}；</li>
 *   <li>{@code parsePorts}：<b>无</b>排序<b>无</b>去重；范围填充<b>无</b>边界检查
 *       （{@code 70000-70005} 原样保留）；{@code start>end} / {@code "80-"} /
 *       {@code "-80"} / {@code "1-2-3"} / {@code "0"} / {@code "65536"} 全部<b>静默跳过</b>
 *       （不报错、不交换）；{@code "+80"} / {@code "0080"} 接受；
 *       {@code parsePortsOptimized} 仅在范围填充处多一道 1..65535 边界检查；</li>
 *   <li>Go 侧 {@code start>end} 的 IP 范围会死循环、超大 CIDR 会撑爆内存，
 *       Java 侧以「返回空列表」守卫（deviation，见各方法注释）。</li>
 * </ul>
 */
final class ScanParse {

    private ScanParse() {
    }

    /** 单次展开上限 2^20（deviation：阻止 /8 等超大网段 OOM）。 */
    private static final long MAX_EXPANSION = 1L << 20;

    // =====================================================================
    // Target parsing
    // =====================================================================

    /**
     * 解析目标（等价 {@code parseTargetWithFamily(target, false)}）。
     *
     * <p>Go: {@code parseTarget}。
     */
    static List<String> parseTarget(String target) {
        return parseTargetWithFamily(target, false);
    }

    /**
     * 解析目标（hostname / 单 IP / IP 范围 / CIDR），必要时按协议族过滤。
     *
     * <p>Go: {@code parseTargetWithFamily(target string, ipv6Enabled bool) []string}。
     * 顺序与 Go 逐分支一致：
     * <ol>
     *   <li>{@code RemoveProtocolPrefix}（调 {@link NmapUtils#removeProtocolPrefix}）；</li>
     *   <li>含 {@code /} → {@link #parseCIDR} → 去重 → 过滤；</li>
     *   <li>含 {@code -} → {@link #parseIPRange} → 去重 → 过滤；</li>
     *   <li>IP 字面量 → <b>原样返回</b>该字符串（Go 不重格式化）→ 过滤（不过滤自身）；</li>
     *   <li>域名 → {@link #resolveHostOnly}：失败时打印
     *       {@code nmap.log.resolve_failed}（错误来自二次解析
     *       {@link #lastResolveError}）并返回 {@code [target]}（<b>不</b>过滤、
     *       <b>不</b>去重）；成功且走了公共 DNS 回退时打印
     *       {@code nmap.log.dns_fallback}，再去重、过滤。</li>
     * </ol>
     *
     * @return 永不为 {@code null}（Go 各分支返回的都是非 nil 切片或空切片）
     */
    static List<String> parseTargetWithFamily(String target, boolean ipv6Enabled) {
        String t = target == null ? "" : target;
        t = NmapUtils.removeProtocolPrefix(t);

        if (t.contains("/")) {
            return filterByIPFamily(removeDuplicateIPs(parseCIDR(t)), ipv6Enabled);
        }
        if (t.contains("-")) {
            return filterByIPFamily(removeDuplicateIPs(parseIPRange(t)), ipv6Enabled);
        }

        // IP 字面量：原样透传（Go 直接返回入参字符串本身）
        if (parseIPBytes(t) != null) {
            List<String> single = new ArrayList<>(1);
            single.add(t);
            return filterByIPFamily(single, ipv6Enabled);
        }

        // 域名
        List<String> ips = resolveHostOnly(t);
        if (ips == null || ips.isEmpty()) {
            System.out.println(I18n.Tf("nmap.log.resolve_failed", t, lastResolveError(t)));
            System.out.flush();
            List<String> fallback = new ArrayList<>(1);
            fallback.add(t); // 解析失败时返回原域名（Go：不经过滤）
            return fallback;
        }
        return filterByIPFamily(removeDuplicateIPs(ips), ipv6Enabled);
    }

    /**
     * 解析域名为 IP 列表并报告是否走了公共 DNS 回退。
     *
     * <p>Go: {@code resolveHostOnly} —— 回退成功时打印 {@code nmap.log.dns_fallback}。
     */
    private static List<String> resolveHostOnly(String target) {
        Resolver.ResolveResult r = Resolver.resolveHostIPsWithFlag(target);
        if (!r.ok() || r.ips().isEmpty()) {
            return null;
        }
        if (r.usedFallback()) {
            System.out.println(I18n.Tf("nmap.log.dns_fallback", target));
            System.out.flush();
        }
        return r.ips();
    }

    /**
     * 二次解析取最终错误文本（Go: {@code lastResolveError}）。
     *
     * <p>Go 侧错误为 {@code *net.DNSError}，{@code %v} 渲染为
     * {@code lookup <host>: <detail>}；Java 侧 {@link Resolver} 已按该形态合成错误串。
     * 二次解析反而成功时，Go 返回 {@code no such host} 错误 —— 此处保持一致。
     */
    private static String lastResolveError(String target) {
        Resolver.ResolveResult r = Resolver.resolveHostIPsWithFlag(target);
        if (r.ok()) {
            return "lookup " + target + ": no such host";
        }
        return r.error();
    }

    /**
     * 按协议族过滤（Go: {@code filterByIPFamily}）。
     *
     * <p>{@code ipv6Enabled=true} 原样返回；否则保留 {@code To4() != nil}（含
     * v4-mapped）与解析失败项（域名，保留待后续解析），过滤纯 IPv6。
     */
    static List<String> filterByIPFamily(List<String> ips, boolean ipv6Enabled) {
        if (ips == null) {
            return new ArrayList<>();
        }
        if (ipv6Enabled) {
            return ips;
        }
        List<String> v4 = new ArrayList<>(ips.size());
        for (String ip : ips) {
            byte[] parsed = parseIPBytes(ip);
            if (parsed == null || isTo4(parsed)) {
                v4.add(ip);
            }
        }
        return v4;
    }

    /** 去重，保序（Go: {@code removeDuplicateIPs}）。 */
    static List<String> removeDuplicateIPs(List<String> ips) {
        if (ips == null) {
            return new ArrayList<>();
        }
        Set<String> seen = new LinkedHashSet<>(ips.size());
        for (String ip : ips) {
            if (ip != null) {
                seen.add(ip);
            }
        }
        return new ArrayList<>(seen);
    }

    // =====================================================================
    // CIDR
    // =====================================================================

    /**
     * 展开 CIDR（Go: {@code parseCIDR}），含网络号与广播地址。
     *
     * <p>解析失败打印 {@code nmap.log.cidr_parse_failed}（错误文本
     * {@code invalid CIDR address: <cidr>}，与 Go {@code net.ParseCIDR} 逐字一致）并返回空列表。
     * 掩码允许前导零（{@code /024}→24），拒绝非数字（{@code +24}）。
     *
     * <p><b>deviation</b>：host 位数 &gt;20（如 {@code /8}）在 Go 会完整展开
     * （千万级条目，极易 OOM），此处按解析失败处理并打印同一错误提示。
     */
    static List<String> parseCIDR(String cidr) {
        if (cidr == null) {
            return cidrError(cidr);
        }
        int slash = cidr.lastIndexOf('/');
        if (slash <= 0 || slash == cidr.length() - 1) {
            return cidrError(cidr);
        }
        String addrPart = cidr.substring(0, slash);
        String maskPart = cidr.substring(slash + 1);

        // 族由字面量形态决定：点分 → 32 位，含冒号 → 128 位（对齐 Go 用解析产物字节长）
        boolean v6Form = addrPart.indexOf(':') >= 0;
        int bits = v6Form ? 128 : 32;

        // 掩码：纯十进制数字（Go dtoi 拒 '+'、拒空、拒溢出）
        if (maskPart.isEmpty()) {
            return cidrError(cidr);
        }
        for (int i = 0; i < maskPart.length(); i++) {
            char c = maskPart.charAt(i);
            if (c < '0' || c > '9') {
                return cidrError(cidr);
            }
        }
        int prefix;
        try {
            prefix = Integer.parseInt(maskPart); // 前导零合法：/024 = 24
        } catch (NumberFormatException e) {
            return cidrError(cidr);
        }
        if (prefix > bits) {
            return cidrError(cidr);
        }

        byte[] addr = parseIPBytes(addrPart);
        if (addr == null) {
            return cidrError(cidr);
        }

        int hostBits = bits - prefix;
        if (hostBits > 20) {
            // deviation：超大网段拒绝展开
            return cidrError(cidr);
        }

        // Go net.IP.Mask 语义：点分 CIDR 会把 v4-mapped 归一为 4 字节后再掩码
        byte[] network = v6Form ? addr.clone() : to4(addr);
        network = maskBytes(network, prefix);

        long count = 1L << hostBits;
        List<String> out = new ArrayList<>((int) count);
        for (long i = 0; i < count; i++) {
            out.add(formatIP(network, i));
        }
        return out;
    }

    /** 打印统一的 CIDR 解析失败并返回空列表。 */
    private static List<String> cidrError(String cidr) {
        System.out.println(I18n.Tf("nmap.log.cidr_parse_failed",
                "invalid CIDR address: " + (cidr == null ? "" : cidr)));
        System.out.flush();
        return new ArrayList<>();
    }

    /** {@code addr & mask}（prefix 位全 1，其余置 0）。 */
    private static byte[] maskBytes(byte[] addr, int prefix) {
        byte[] out = addr.clone();
        int fullBytes = prefix / 8;
        int remBits = prefix % 8;
        if (remBits > 0 && fullBytes < out.length) {
            out[fullBytes] = (byte) ((out[fullBytes] & 0xFF) & (0xFF << (8 - remBits)));
            fullBytes++;
        }
        for (int i = fullBytes; i < out.length; i++) {
            out[i] = 0;
        }
        return out;
    }

    // =====================================================================
    // IP range
    // =====================================================================

    /**
     * 展开 IP 范围 {@code "a.b.c.d-e.f.g.h"}（Go: {@code parseIPRange}）。
     *
     * <p>Split 必须恰 2 段（否则打印 {@code nmap.err.invalid_ip_range}）；两端去空白后
     * 都必须是完整 IP（否则打印 {@code nmap.err.invalid_ip}）；闭区间全含。
     *
     * <p><b>deviation</b>：Go 对 {@code start>end}、异族（纯 v6 ↔ v4-mapped）会死循环，
     * 对超大范围会耗尽内存；此处分别以「返回空列表」与 2^20 上限守卫。
     */
    static List<String> parseIPRange(String spec) {
        if (spec == null) {
            spec = "";
        }
        String[] parts = spec.split("-", -1);
        if (parts.length != 2) {
            System.out.println(I18n.Tf("nmap.err.invalid_ip_range", spec));
            System.out.flush();
            return new ArrayList<>();
        }

        byte[] start = parseIPBytes(parts[0].strip());
        byte[] end = parseIPBytes(parts[1].strip());
        if (start == null || end == null) {
            System.out.println(I18n.T("nmap.err.invalid_ip"));
            System.out.flush();
            return new ArrayList<>();
        }

        // Go ParseIP 恒 16 字节：点分即 v4-mapped，天然可比；异族/倒序在 Go 是死循环 → 守卫返回空
        if (isV4Mapped(start) != isV4Mapped(end)) {
            return new ArrayList<>();
        }
        int cmp = compareUnsigned(start, end);
        if (cmp > 0) {
            return new ArrayList<>();
        }

        BigInteger span = new BigInteger(1, end).subtract(new BigInteger(1, start)).add(BigInteger.ONE);
        if (span.bitLength() > 20) {
            return new ArrayList<>(); // deviation：2^20 上限
        }
        long count = span.longValue();

        List<String> out = new ArrayList<>((int) count);
        byte[] cur = start.clone();
        for (long i = 0; i < count; i++) {
            out.add(formatIP(cur));
            incBytes(cur);
        }
        return out;
    }

    // =====================================================================
    // Port parsing
    // =====================================================================

    /**
     * 解析端口列表（Go: {@code parsePorts}）。
     *
     * <p>默认：{@code ""} → 1..1000；{@code "-"} → 1..65535。逗号分段、整段去空白；
     * 段内含 {@code -} 时 {@code Split("-")} 必须恰 2 段且两端都能 {@code Atoi}
     * （不额外去空白）且 {@code start<=end} 才填充 —— <b>无边界检查</b>
     * （{@code 70000-70005} 保留），其余情况静默跳过（不报错、不交换）。
     * 单端口须在 1..65535。{@code "+80}/{@code 0080} 接受。<b>不排序、不去重。</b>
     */
    static List<Integer> parsePorts(String ports) {
        return parsePortsImpl(ports, false);
    }

    /**
     * 优化版端口解析（Go: {@code parsePortsOptimized}）。
     *
     * <p>与 {@link #parsePorts} 唯一差异：范围填充额外要求
     * {@code start >= 1 && end <= 65535}（仍不排序、不去重、不报错）。
     */
    static List<Integer> parsePortsOptimized(String ports) {
        return parsePortsImpl(ports, true);
    }

    private static List<Integer> parsePortsImpl(String ports, boolean boundsChecked) {
        String spec = ports == null ? "" : ports;

        if (spec.isEmpty()) {
            List<Integer> out = new ArrayList<>(1000);
            for (int p = NmapConstants.MIN_PORT; p <= 1000; p++) {
                out.add(p);
            }
            return out;
        }
        if ("-".equals(spec)) {
            List<Integer> out = new ArrayList<>(NmapConstants.MAX_PORT);
            for (int p = NmapConstants.MIN_PORT; p <= NmapConstants.MAX_PORT; p++) {
                out.add(p);
            }
            return out;
        }

        List<Integer> portList = new ArrayList<>();
        for (String rawPart : spec.split(",", -1)) {
            String part = rawPart.strip();
            if (part.indexOf('-') >= 0) {
                String[] rangeParts = part.split("-", -1);
                if (rangeParts.length == 2) {
                    Integer start = atoi(rangeParts[0]);
                    Integer end = atoi(rangeParts[1]);
                    if (start != null && end != null && start <= end
                            && (!boundsChecked
                            || (start >= NmapConstants.MIN_PORT && end <= NmapConstants.MAX_PORT))) {
                        // Go 无边界检查分支：start..end 原样填充
                        for (int p = start; p <= end; p++) {
                            portList.add(p);
                        }
                    }
                    // 其余（Atoi 失败 / start>end / 越界）→ 静默跳过
                }
                // Split 结果非 2 段（"1-2-3" / "" / "-"）→ 静默跳过
            } else {
                Integer port = atoi(part);
                if (port != null && port >= NmapConstants.MIN_PORT && port <= NmapConstants.MAX_PORT) {
                    portList.add(port);
                }
            }
        }
        return portList;
    }

    /**
     * Go {@code strconv.Atoi}：接受可选符号与前导零，整串必须是十进制数字；
     * 溢出（超出 Java int）返回 {@code null}（Go 同样报错跳过；Go int 为 64 位，
     * 但 2^31..2^64 的值会因超出 1..65535 被过滤，结果一致）。
     */
    private static Integer atoi(String s) {
        if (s.isEmpty()) {
            return null;
        }
        int i = 0;
        boolean neg = false;
        char c0 = s.charAt(0);
        if (c0 == '+' || c0 == '-') {
            neg = c0 == '-';
            i = 1;
            if (s.length() == 1) {
                return null;
            }
        }
        long v = 0;
        for (; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return null;
            }
            v = v * 10 + (c - '0');
            if (v > Integer.MAX_VALUE + (neg ? 1L : 0L)) {
                return null;
            }
        }
        return (int) (neg ? -v : v);
    }

    // =====================================================================
    // IP literal parsing / formatting（复刻 net.ParseIP / net.IP.String）
    // =====================================================================

    /**
     * 解析 IP 字面量，恒返回 <b>16 字节</b>（点分形式转换为 v4-mapped，
     * 与 Go {@code net.ParseIP} 一致），失败返回 {@code null}。
     *
     * <p>拒绝：点分前导零（{@code 010.1.1.1}）、{@code %zone}、超过 4 位的 v6 组、
     * 多于一个 {@code ::}、非 hex 字符 —— 与 Go 逐条一致。
     */
    static byte[] parseIPBytes(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        if (s.indexOf('%') >= 0) {
            return null; // Go ParseIP 拒绝 zone
        }
        if (s.indexOf(':') >= 0) {
            return parseIPv6Bytes(s);
        }
        byte[] v4 = parseIPv4Bytes(s);
        if (v4 == null) {
            return null;
        }
        // 点分 → v4-mapped 16 字节（与 Go ParseIP 一致）
        byte[] out = new byte[16];
        out[10] = (byte) 0xFF;
        out[11] = (byte) 0xFF;
        System.arraycopy(v4, 0, out, 12, 4);
        return out;
    }

    /**
     * 解析为 {@link InetAddress}（{@code net.ParseIP} 的 nil 判定用途）。
     *
     * <p>v4-ish 返回 {@link java.net.Inet4Address}（保证 127.x 的
     * {@code isLoopbackAddress()} 为真，供 Resolver 的 isLocalhost 使用）。
     */
    static InetAddress parseIP(String s) {
        byte[] b = parseIPBytes(s);
        if (b == null) {
            return null;
        }
        try {
            if (isV4Mapped(b)) {
                return InetAddress.getByAddress(to4(b));
            }
            return InetAddress.getByAddress(b);
        } catch (UnknownHostException e) {
            return null;
        }
        // InetAddress.getByAddress 仅在地址长度非法时抛出，这里不会发生
    }

    /** 严格 IPv4 点分校验（Go 拒绝前导零）。返回 4 字节。 */
    private static byte[] parseIPv4Bytes(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3) {
                return null;
            }
            if (p.length() > 1 && p.charAt(0) == '0') {
                return null; // Go 拒绝前导零
            }
            int v = 0;
            for (int c = 0; c < p.length(); c++) {
                char ch = p.charAt(c);
                if (ch < '0' || ch > '9') {
                    return null;
                }
                v = v * 10 + (ch - '0');
            }
            if (v > 255) {
                return null;
            }
            out[i] = (byte) v;
        }
        return out;
    }

    /** IPv6 字面量解析（含内嵌点分尾段），恒返回 16 字节。 */
    private static byte[] parseIPv6Bytes(String s) {
        if (s.isEmpty()) {
            return null;
        }
        String work = s;
        byte[] v4tail = null;
        int lastColon = s.lastIndexOf(':');
        if (lastColon >= 0 && s.indexOf('.', lastColon) >= 0) {
            // 最后一个 ':' 之后有点分尾段
            String v4part = s.substring(lastColon + 1);
            byte[] v4 = parseIPv4Bytes(v4part);
            if (v4 == null) {
                return null;
            }
            v4tail = v4;
            work = s.substring(0, lastColon + 1) + "0:0";
        }

        int dbl = work.indexOf("::");
        if (dbl >= 0 && dbl != work.lastIndexOf("::")) {
            return null; // 多于一个 "::"
        }

        String[] segs = new String[8];
        boolean hasDbl = dbl >= 0;
        if (hasDbl) {
            String left = work.substring(0, dbl);
            String right = work.substring(dbl + 2);
            String[] l = left.isEmpty() ? new String[0] : left.split(":", -1);
            String[] r = right.isEmpty() ? new String[0] : right.split(":", -1);
            if (l.length + r.length > 8) {
                return null;
            }
            int idx = 0;
            for (String x : l) {
                segs[idx++] = x;
            }
            int gap = 8 - l.length - r.length;
            for (int i = 0; i < gap; i++) {
                segs[idx++] = "0";
            }
            for (String x : r) {
                segs[idx++] = x;
            }
        } else {
            String[] split = work.split(":", -1);
            if (split.length != 8) {
                return null;
            }
            System.arraycopy(split, 0, segs, 0, 8);
        }

        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            String seg = segs[i];
            if (seg == null || seg.isEmpty() || seg.length() > 4) {
                return null;
            }
            int v = 0;
            for (int c = 0; c < seg.length(); c++) {
                char ch = seg.charAt(c);
                int d;
                if (ch >= '0' && ch <= '9') {
                    d = ch - '0';
                } else if (ch >= 'a' && ch <= 'f') {
                    d = ch - 'a' + 10;
                } else if (ch >= 'A' && ch <= 'F') {
                    d = ch - 'A' + 10;
                } else {
                    return null;
                }
                v = (v << 4) | d;
            }
            out[i * 2] = (byte) (v >> 8);
            out[i * 2 + 1] = (byte) v;
        }

        if (v4tail != null) {
            System.arraycopy(v4tail, 0, out, 12, 4);
        }
        return out;
    }

    /** {@code net.IP.To4()}：仅 v4-mapped（或 4 字节）为真，v4-兼容为假。 */
    static boolean isTo4(byte[] b) {
        return b != null && (b.length == 4 || isV4Mapped(b));
    }

    /** 前 10 字节为 0 且 [10..11] = 0xffff（Go 的 v4-in-v6 形态）。 */
    private static boolean isV4Mapped(byte[] b) {
        if (b == null || b.length != 16) {
            return false;
        }
        for (int i = 0; i < 10; i++) {
            if (b[i] != 0) {
                return false;
            }
        }
        return (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF;
    }

    /** v4-mapped → 4 字节；否则原样返回副本。 */
    static byte[] to4(byte[] b) {
        if (b.length == 4) {
            return b.clone();
        }
        if (isV4Mapped(b)) {
            byte[] out = new byte[4];
            System.arraycopy(b, 12, out, 0, 4);
            return out;
        }
        return b.clone();
    }

    /**
     * 格式化 IP（{@code net.IP.String()} 的逐字节复刻）。
     *
     * <p>4 字节 / v4-mapped → 点分；其余 16 字节 → RFC 5952 压缩十六进制
     * （最长零串、≥2 位才压缩、平手取首段、全小写）。
     */
    static String formatIP(byte[] addr) {
        return formatIP(addr, 0);
    }

    /** 格式化 {@code addr + offset}（CIDR 批量展开用，进位为大端无符号加法）。 */
    private static String formatIP(byte[] addr, long offset) {
        byte[] b = addr.clone();
        if (offset > 0) {
            addToBytes(b, offset);
        }
        if (b.length == 4) {
            return (b[0] & 0xFF) + "." + (b[1] & 0xFF) + "." + (b[2] & 0xFF) + "." + (b[3] & 0xFF);
        }
        if (b.length != 16) {
            StringBuilder hex = new StringBuilder("?");
            for (byte x : b) {
                hex.append(String.format("%02x", x));
            }
            return hex.toString();
        }
        if (isV4Mapped(b)) {
            return (b[12] & 0xFF) + "." + (b[13] & 0xFF) + "." + (b[14] & 0xFF) + "." + (b[15] & 0xFF);
        }
        return formatIPv6(b);
    }

    /** RFC 5952：最长零串压缩（≥2，平手取首段），小写十六进制。 */
    private static String formatIPv6(byte[] a) {
        int[] groups = new int[8];
        for (int g = 0; g < 8; g++) {
            groups[g] = ((a[g * 2] & 0xFF) << 8) | (a[g * 2 + 1] & 0xFF);
        }
        int best = -1;
        int bestLen = 0;
        int i = 0;
        while (i < 8) {
            if (groups[i] != 0) {
                i++;
                continue;
            }
            int next = i;
            int len = 0;
            while (next < 8 && groups[next] == 0) {
                next++;
                len++;
            }
            if (len > bestLen) {
                best = i;
                bestLen = len;
            }
            i = next;
        }
        if (bestLen < 2) {
            best = -1;
        }

        StringBuilder sb = new StringBuilder(39);
        for (int g = 0; g < 8; g++) {
            if (best >= 0 && g == best) {
                sb.append("::");
                g += bestLen - 1; // for 循环还会 g++
                continue;
            }
            if (sb.length() > 0 && !sb.toString().endsWith("::")) {
                sb.append(':');
            }
            sb.append(Integer.toHexString(groups[g]));
        }
        return sb.toString();
    }

    /** 大端无符号 +delta（进位传播，对应 Go 的 {@code inc} 反向应用）。 */
    private static void addToBytes(byte[] b, long delta) {
        for (int i = b.length - 1; i >= 0 && delta > 0; i--) {
            long sum = (b[i] & 0xFFL) + (delta & 0xFF);
            b[i] = (byte) sum;
            delta = (delta >>> 8) + (sum >>> 8);
        }
    }

    /** Go {@code inc(ip)}：末字节起逐位 +1，遇非零进位即停。 */
    private static void incBytes(byte[] ip) {
        for (int j = ip.length - 1; j >= 0; j--) {
            ip[j]++;
            if (ip[j] != 0) {
                break;
            }
        }
    }

    /** 无符号字节串比较。 */
    private static int compareUnsigned(byte[] a, byte[] b) {
        for (int i = 0; i < a.length && i < b.length; i++) {
            int x = a[i] & 0xFF;
            int y = b[i] & 0xFF;
            if (x != y) {
                return Integer.compare(x, y);
            }
        }
        return Integer.compare(a.length, b.length);
    }
}

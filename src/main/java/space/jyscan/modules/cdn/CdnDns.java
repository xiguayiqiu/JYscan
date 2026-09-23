package space.jyscan.modules.cdn;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * CDN 模块使用的 DNS 查询，对应 freeclient/internal/cdn/cdn.go 的
 * {@code lookupCNAME} / {@code lookupA} / {@code lookupNS} / {@code lookupPTR}。
 *
 * <p>实现映射：Go 用 miekg/dns 直连 {@code 8.8.8.8:53}（{@code dns.Client.Timeout = 3s}、
 * {@code RecursionDesired = true}），这里用 dnsjava 的 {@link SimpleResolver} 等价实现：
 * 固定服务器 8.8.8.8、超时 3 秒、{@code Message.newQuery} 默认 RD=1。
 *
 * <p>失败统一返回 {@code null}（对应 Go 的 {@code err != nil}）；
 * 「无记录」也按 Go 的语义返回 null / 空列表：
 * {@code lookupCNAME} 与 {@code lookupPTR} 无匹配记录时返回 null（Go 报 "no CNAME/PTR record"），
 * {@code lookupA} 与 {@code lookupNS} 无记录时返回空列表（Go 返回 nil slice + nil error）。
 */
public final class CdnDns {

    /** 固定使用的公共 DNS（与 Go 的 "8.8.8.8:53" 一致）。 */
    private static final String DNS_SERVER = "8.8.8.8";

    /** 与 Go 的 {@code dns.Client.Timeout = 3 * time.Second} 一致。 */
    private static final Duration DNS_TIMEOUT = Duration.ofSeconds(3);

    private CdnDns() {
    }

    /** 查询 CNAME 记录，对应 Go 的 {@code lookupCNAME}（无记录返回 null）。 */
    public static String lookupCNAME(String target) {
        Message resp = exchange(target, Type.CNAME);
        if (resp == null) {
            return null;
        }
        for (Record r : resp.getSectionArray(Section.ANSWER)) {
            if (r instanceof CNAMERecord c) {
                return trimDot(c.getTarget().toString());
            }
        }
        return null;
    }

    /** 查询 A 记录，对应 Go 的 {@code lookupA}。 */
    public static List<String> lookupA(String target) {
        List<String> ips = new ArrayList<>();
        Message resp = exchange(target, Type.A);
        if (resp == null) {
            return ips;
        }
        for (Record r : resp.getSectionArray(Section.ANSWER)) {
            // Go 只取 *dns.A（忽略 AAAA），这里保持同样语义
            if (r instanceof ARecord a) {
                ips.add(a.getAddress().getHostAddress());
            }
        }
        return ips;
    }

    /** 查询 NS 记录，对应 Go 的 {@code lookupNS}。 */
    public static List<String> lookupNS(String target) {
        List<String> ns = new ArrayList<>();
        Message resp = exchange(target, Type.NS);
        if (resp == null) {
            return ns;
        }
        for (Record r : resp.getSectionArray(Section.ANSWER)) {
            if (r instanceof NSRecord n) {
                ns.add(trimDot(n.getTarget().toString()));
            }
        }
        return ns;
    }

    /** 反向查询 PTR 记录，对应 Go 的 {@code lookupPTR}（无记录返回 null）。 */
    public static String lookupPTR(String ip) {
        String arpa;
        try {
            arpa = ReverseMap.fromAddress(ip).toString();
        } catch (Exception e) {
            return null;
        }
        Message resp = exchange(arpa, Type.PTR);
        if (resp == null) {
            return null;
        }
        for (Record r : resp.getSectionArray(Section.ANSWER)) {
            if (r instanceof PTRRecord p) {
                return trimDot(p.getTarget().toString());
            }
        }
        return null;
    }

    /**
     * 直连 {@link #DNS_SERVER} 查询指定类型。
     *
     * @return 响应消息；查询失败返回 null（对应 Go 的 err != nil）
     */
    private static Message exchange(String target, int type) {
        try {
            SimpleResolver resolver = new SimpleResolver(DNS_SERVER);
            resolver.setTimeout(DNS_TIMEOUT);
            resolver.setPort(53);
            Message query = Message.newQuery(
                    Record.newRecord(org.xbill.DNS.Name.fromString(target, org.xbill.DNS.Name.root),
                            type, DClass.IN));
            return resolver.send(query);
        } catch (Exception e) {
            return null;
        }
    }

    /** Go 的 {@code strings.TrimSuffix(s, ".")}。 */
    private static String trimDot(String s) {
        if (s == null) {
            return "";
        }
        return s.endsWith(".") ? s.substring(0, s.length() - 1) : s;
    }
}

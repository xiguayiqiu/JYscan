package space.jyscan.modules.dns;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.ReverseMap;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;
import org.xbill.DNS.TextParseException;
import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;

import java.io.IOException;
import java.time.Duration;
import java.util.List;

/**
 * DNS 查询核心，移植自 freeclient/internal/dns/dns.go。
 *
 * <p>实现映射：
 * <ul>
 *   <li>Go 的 {@code dns.Client{ReadTimeout} + Exchange} → dnsjava
 *       {@link SimpleResolver}（UDP、同服务器端口、同超时）；</li>
 *   <li>Go 默认<b>不</b>发送 EDNS0 OPT 记录，dnsjava 默认会发；因此这里显式
 *       {@code setEDNS(null)} 关闭，保证应答附加区与 Go 一致（影响 PrintFullResult
 *       是否输出「OPT 伪部分」）；</li>
 *   <li>{@code QueryDNSFull} 的三条路径（反向 / 单类型 / ANY 合并）逐一对应。</li>
 * </ul>
 *
 * <p>输出与翻译函数见 {@link DnsPrint}。
 */
public final class DnsQuery {

    /** ANY 模式下逐个查询的记录类型，对应 Go queryAllTypesIndividually 的切片。 */
    private static final String[] ALL_TYPES =
            {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"};

    /** ANY 合并模式查询的类型码，对应 queryAllTypesCombined 的切片。 */
    private static final int[] ALL_TYPE_CODES = {
            Type.A, Type.AAAA, Type.MX, Type.NS, Type.TXT, Type.CNAME, Type.SOA
    };

    private DnsQuery() {
    }

    // =====================================================================
    // 查询入口
    // =====================================================================

    /**
     * 执行一次完整 DNS 查询，对应 Go 的 {@code QueryDNSFull}。
     *
     * @throws IOException 查询失败（消息形如 {@code DNS 查询失败: xxx} / {@code 无效的 IP 地址: xxx}）
     */
    public static FullDnsResult queryDnsFull(DnsConfig config) throws IOException {
        String serverAddr = joinHostPort(config.server, config.port);

        if ("ANY".equals(config.recordType) && !config.reverse) {
            return queryAllTypesCombined(config.domain, serverAddr, config.timeout, config.trace);
        }

        String domain;
        int qtype;
        if (config.reverse) {
            try {
                domain = ReverseMap.fromAddress(config.domain).toString();
            } catch (Exception e) {
                throw new IOException(Fmt.format("无效的 IP 地址: %v",
                        e.getMessage() == null ? e : e.getMessage()));
            }
            qtype = Type.PTR;
        } else {
            domain = fqdn(config.domain);
            qtype = parseRecordType(config.recordType);
        }

        if (config.trace) {
            Colors.infoPrint("[TRACE] 查询 %s 记录 %s @ %s", Type.string(qtype), domain, serverAddr);
        }

        long start = System.nanoTime();
        Message in = exchange(domain, qtype, serverAddr, config.timeout);
        Duration queryTime = Duration.ofNanos(Math.max(0L, System.nanoTime() - start));

        if (in == null) {
            throw new IOException("DNS 查询失败: 超时或无响应");
        }

        if (config.trace) {
            Colors.infoPrint("[TRACE] 响应时间: %v", queryTime);
        }

        return new FullDnsResult(queryTime, serverAddr, in);
    }

    /**
     * 逐类型合并为单条结果，对应 Go 的 {@code queryAllTypesCombined}。
     *
     * <p>Go 在进入 ANY 分支前会被 cmd.go 的 {@code queryAllTypesIndividually} 拦下，
     * 因此本方法与 Go 相同：仅作为包级 API 存在，不在命令路径上被调用。
     *
     * <p>Go 用 {@code dns.Msg{Response: true, RecursionDesired: true}} 手工构造消息，
     * 而 dnsjava 的 {@code Header} 不暴露 QR/RD 标志位的公开写入口；
     * 这里改为「newQuery（自动置 RD）→ 序列化 → 在 flags 高字节置 QR → 回读」，
     * 结果与 Go 构造出的消息逐位一致。
     */
    private static FullDnsResult queryAllTypesCombined(String domain, String server,
                                                       Duration timeout, boolean trace)
            throws IOException {
        Message template = Message.newQuery(
                Record.newRecord(fqdnName(domain), Type.ANY, DClass.IN));
        byte[] wire = template.toWire();
        wire[2] |= (byte) 0x80; // QR = 1（flags 第 1 字节的最高位）
        Message combined;
        try {
            combined = new Message(wire);
        } catch (IOException e) {
            combined = template;
        }

        long start = System.nanoTime();
        for (int qtype : ALL_TYPE_CODES) {
            if (trace) {
                Colors.infoPrint("[TRACE] 查询 %s 记录", Type.string(qtype));
            }
            Message in = exchange(fqdn(domain), qtype, server, timeout);
            if (in != null && in.getRcode() == org.xbill.DNS.Rcode.NOERROR) {
                for (Record r : in.getSection(Section.ANSWER)) {
                    combined.addRecord(r, Section.ANSWER);
                }
                for (Record r : in.getSection(Section.AUTHORITY)) {
                    combined.addRecord(r, Section.AUTHORITY);
                }
                for (Record r : in.getSection(Section.ADDITIONAL)) {
                    combined.addRecord(r, Section.ADDITIONAL);
                }
            }
        }
        Duration queryTime = Duration.ofNanos(Math.max(0L, System.nanoTime() - start));

        return new FullDnsResult(queryTime, server, combined);
    }

    // =====================================================================
    // ANY 模式逐类型查询（对应 cmd.go 的 queryAllTypesIndividually）
    // =====================================================================

    /**
     * 逐类型单独查询并打印，对应 Go 的 {@code queryAllTypesIndividually}。
     *
     * @param shortOutput 对应 Go 的 {@code short} 参数
     * @return 总耗时
     */
    public static Duration queryAllTypesIndividually(String domain, String server, int port,
                                                     Duration timeout, boolean trace,
                                                     boolean shortOutput) {
        String serverAddr = joinHostPort(server, port);
        long start = System.nanoTime();

        if (!shortOutput) {
            System.out.println();
            DnsPrint.cyanBold("; <<>> JYscan DNS <<>> %s\n", fqdn(domain));
            DnsPrint.cyanBold(";; Querying all record types individually...\n");
            System.out.println();
        }

        for (String rt : ALL_TYPES) {
            DnsConfig config = new DnsConfig();
            config.domain = domain;
            config.server = server;
            config.port = port;
            config.recordType = rt;
            config.timeout = timeout;
            config.trace = trace;
            config.reverse = false;
            config.shortOutput = shortOutput;

            FullDnsResult result;
            try {
                result = queryDnsFull(config);
            } catch (IOException e) {
                continue;
            }

            if (result.msg == null || result.msg.getSection(Section.ANSWER).isEmpty()) {
                continue;
            }

            if (shortOutput) {
                DnsPrint.printShortResult(result.msg);
            } else {
                printSimpleResult(result.msg, rt);
            }
        }

        Duration totalTime = Duration.ofNanos(Math.max(0L, System.nanoTime() - start));
        if (!shortOutput) {
            DnsPrint.cyanBold(";; Total query time: %d msec\n", totalTime.toMillis());
            DnsPrint.cyanBold(";; SERVER: %s\n", serverAddr);
            DnsPrint.cyanBold(";; WHEN: %s\n", DnsPrint.whenNow());
            System.out.println();
        }
        return totalTime;
    }

    /** 单一类型的简洁打印，对应 Go 的 {@code printSimpleResult}。 */
    private static void printSimpleResult(Message msg, String recordType) {
        DnsPrint.cyanBold(";; %s 记录:\n", DnsPrint.translateType(recordType));
        for (Record ans : msg.getSection(Section.ANSWER)) {
            System.out.println(DnsPrint.translateRecord(ans));
        }
        System.out.println();
    }

    // =====================================================================
    // 底层
    // =====================================================================

    /**
     * 向指定服务器发送一次查询。
     *
     * @return 应答消息；失败返回 {@code null}（对应 Go 的 {@code err != nil}）
     */
    private static Message exchange(String name, int qtype, String serverAddr, Duration timeout) {
        try {
            SimpleResolver resolver = buildResolver(serverAddr, timeout);
            Message query = Message.newQuery(Record.newRecord(fqdnName(name), qtype, DClass.IN));
            return resolver.send(query);
        } catch (Exception e) {
            return null;
        }
    }

    /** 构造解析器：服务器 / 端口 / 超时对齐 Go，并关闭 dnsjava 默认的 EDNS0。 */
    static SimpleResolver buildResolver(String serverAddr, Duration timeout) throws IOException {
        HostPort hp = splitHostPort(serverAddr);
        SimpleResolver resolver = new SimpleResolver(hp.host);
        resolver.setPort(hp.port);
        if (timeout != null && !timeout.isZero() && !timeout.isNegative()) {
            resolver.setTimeout(timeout);
        }
        // Go 的 miekg/dns 默认不带 OPT；dnsjava 默认带 payload=512 的 EDNS0，这里显式关闭
        resolver.setEDNS(null);
        return resolver;
    }

    /** 记录类型解析，对应 Go 的 {@code parseRecordType}（未知类型回退 A）。 */
    public static int parseRecordType(String rt) {
        if (rt == null) {
            return Type.A;
        }
        int v = Type.value(rt.trim(), false);
        if (v < 0) {
            return Type.A;
        }
        return v;
    }

    /** Go 的 {@code dns.Fqdn}：确保以点结尾。 */
    public static String fqdn(String name) {
        if (name == null || name.isEmpty()) {
            return ".";
        }
        return name.endsWith(".") ? name : name + ".";
    }

    /** 解析为绝对 {@link Name}。 */
    static Name fqdnName(String name) throws IOException {
        try {
            return Name.fromString(fqdn(name), Name.root);
        } catch (TextParseException e) {
            throw new IOException(e.getMessage(), e);
        }
    }

    /** Go 的 {@code net.JoinHostPort}（IPv6 自动加方括号）。 */
    public static String joinHostPort(String host, int port) {
        String h = host == null ? "" : host;
        if (h.contains(":") && !h.startsWith("[")) {
            return "[" + h + "]:" + port;
        }
        return h + ":" + port;
    }

    /** 简易 host:port 拆分（输入形如 {@code 8.8.8.8:53} / {@code [::1]:53}）。 */
    private static HostPort splitHostPort(String addr) {
        String host = addr;
        int port = 53;
        if (addr.startsWith("[")) {
            int end = addr.indexOf(']');
            if (end > 0) {
                host = addr.substring(1, end);
                if (end + 1 < addr.length() && addr.charAt(end + 1) == ':') {
                    port = Integer.parseInt(addr.substring(end + 2));
                }
            }
        } else {
            int colon = addr.lastIndexOf(':');
            if (colon > 0 && addr.indexOf(':') == colon) {
                host = addr.substring(0, colon);
                port = Integer.parseInt(addr.substring(colon + 1));
            }
        }
        return new HostPort(host, port);
    }

    private record HostPort(String host, int port) {
    }

    /** ANY 模式使用的类型串列表（供测试与调试复用）。 */
    public static List<String> allTypes() {
        return List.of(ALL_TYPES);
    }
}


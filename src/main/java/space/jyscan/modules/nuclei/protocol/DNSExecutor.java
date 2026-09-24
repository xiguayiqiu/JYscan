package space.jyscan.modules.nuclei.protocol;

import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import space.jyscan.modules.nuclei.model.DNSRequest;
import space.jyscan.modules.nuclei.variable.Engine;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * DNS 协议执行器，对应 Go 的 {@code protocol.DNSExecutor}。
 *
 * <p>跨包契约：runner 持有字段 {@code dnsExec} 并调用
 * {@link #execute(DNSRequest, String, Map)}。
 *
 * <p>Go 侧 {@code NewDNSExecutor()} 构造 {@code variable.NewEngine()} 作为 {@code varEngine}；
 * {@code Execute} 用它渲染 {@code req.Name}（渲染后为空则回退 {@code target}），
 * 记录类型 {@code strings.ToUpper(req.Type)}，为空则取 {@code A}。
 *
 * <p>Java 侧对应依赖 dnsjava（已在 pom 中，版本 3.6.3）：
 * <ul>
 *   <li>Go {@code dns.Client{Timeout: 5s}.Exchange(msg, "8.8.8.8:53")} →
 *       {@code SimpleResolver("8.8.8.8") + setTimeout(5s) + send()}（UDP、同上游同超时）；</li>
 *   <li>Go 无答案且无错时回退 {@code net.Lookup*} → A/AAAA 用 {@code InetAddress.getAllByName}，
 *       CNAME/MX/NS/TXT 用 dnsjava {@code Lookup}（系统解析器）；</li>
 *   <li>{@code dnsTypeToInt}/{@code dnsClassToInt}/{@code rrToString} 逐条对照 miekg/dns 常量移植。</li>
 * </ul>
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/protocol/protocol.go}。
 */
public class DNSExecutor {

    /** 对应 Go 的 {@code NewDNSExecutor() *DNSExecutor}。 */
    public DNSExecutor() {
        this.varEngine = new Engine();
    }

    private final Engine varEngine;

    /**
     * 执行一次 DNS 查询。
     *
     * <p>对应 Go 的 {@code (e *DNSExecutor) Execute(req *model.DNSRequest, target string, vars map[string]interface{}) *ProtocolResult}。
     * 错误按 Go 的方式放在 {@link ProtocolResult#error} 字段内。
     */
    public ProtocolResult execute(DNSRequest req, String target, Map<String, Object> vars) {
        long start = System.nanoTime();

        String domain = varEngine.render(req.name == null ? "" : req.name, vars);
        if (domain.isEmpty()) {
            domain = target;
        }
        String qtype = (req.type == null ? "" : req.type).toUpperCase(Locale.ROOT);
        if (qtype.isEmpty()) {
            qtype = "A";
        }

        List<String> records = new ArrayList<>();
        String answer = "";
        String rcode = "";
        Throwable err = null;
        Message response = null;

        try {
            Message msg = new Message();
            msg.getHeader().setID(ThreadLocalRandom.current().nextInt(1 << 16));
            // Go: msg.RecursionDesired = req.Recursion; if !req.Recursion { msg.RecursionDesired = true }
            // —— 即 RD 恒为 true，照抄该行为
            msg.getHeader().setFlag(Flags.RD);
            Name qname = Name.fromConstantString(domain.endsWith(".") ? domain : domain + ".");
            msg.addRecord(Record.newRecord(qname, dnsTypeToInt(qtype), dnsClassToInt(req.clazz), 0),
                    Section.QUESTION);
            SimpleResolver resolver = new SimpleResolver("8.8.8.8");
            resolver.setTimeout(Duration.ofSeconds(5)); // Go: client.Timeout = 5 * time.Second
            response = resolver.send(msg);              // Go: client.Exchange(msg, "8.8.8.8:53")
        } catch (IOException e) {
            err = e; // Go: exErr != nil → err = exErr
        }

        if (response != null) {
            answer = rrToString(response.getSection(Section.ANSWER));
            rcode = Rcode.string(response.getHeader().getRcode()); // Go: dns.RcodeToString[response.Rcode]
            for (Record rr : response.getSection(Section.ANSWER)) {
                records.add(rr.toString()); // Go: rr.String()
            }
        }
        if (records.isEmpty() && err == null) {
            try {
                // 对应 Go 的 net.Lookup* 回退分支（switch qtype）
                switch (qtype) {
                    case "A" -> {
                        try {
                            for (InetAddress ip : InetAddress.getAllByName(domain)) {
                                if (ip instanceof Inet4Address v4) {
                                    records.add(v4.getHostAddress());
                                }
                            }
                        } catch (UnknownHostException e) {
                            err = e;
                        }
                    }
                    case "AAAA" -> {
                        try {
                            for (InetAddress ip : InetAddress.getAllByName(domain)) {
                                if (ip instanceof Inet6Address v6) {
                                    records.add(v6.getHostAddress());
                                }
                            }
                        } catch (UnknownHostException e) {
                            err = e;
                        }
                    }
                    case "CNAME" -> {
                        Record[] answers = new Lookup(domain, Type.CNAME).run();
                        if (answers == null || answers.length == 0) {
                            err = new UnknownHostException(domain); // Go: LookupCNAME 查不到 → err
                        } else {
                            for (Record rr : answers) {
                                if (rr instanceof CNAMERecord c) {
                                    records.add(c.getTarget().toString());
                                }
                            }
                        }
                    }
                    case "MX" -> {
                        Record[] answers = new Lookup(domain, Type.MX).run();
                        if (answers == null || answers.length == 0) {
                            err = new UnknownHostException(domain);
                        } else {
                            for (Record rr : answers) {
                                if (rr instanceof MXRecord mx) {
                                    // Go: fmt.Sprintf("%d %s", mx.Pref, mx.Host)
                                    records.add(mx.getPriority() + " " + mx.getTarget().toString());
                                }
                            }
                        }
                    }
                    case "NS" -> {
                        Record[] answers = new Lookup(domain, Type.NS).run();
                        if (answers == null || answers.length == 0) {
                            err = new UnknownHostException(domain);
                        } else {
                            for (Record rr : answers) {
                                if (rr instanceof NSRecord ns) {
                                    records.add(ns.getTarget().toString());
                                }
                            }
                        }
                    }
                    case "TXT" -> {
                        Record[] answers = new Lookup(domain, Type.TXT).run();
                        if (answers == null || answers.length == 0) {
                            err = new UnknownHostException(domain);
                        } else {
                            for (Record rr : answers) {
                                if (rr instanceof TXTRecord txt) {
                                    // Go 的 LookupTXT 将单条记录的各字符串片段合并
                                    StringBuilder joined = new StringBuilder();
                                    for (Object part : txt.getStrings()) {
                                        joined.append(part);
                                    }
                                    records.add(joined.toString());
                                }
                            }
                        }
                    }
                    default -> {
                        // Go switch 无 default：SOA/PTR/SRV/CAA 等不回退
                    }
                }
            } catch (TextParseException e) {
                // Go: net.Lookup* 对非法域名返回 err
                err = e;
            }
        }

        String raw = String.join("\n", records); // Go: strings.Join(records, "\n")
        if (raw.isEmpty() && response != null) {
            raw = response.toString(); // Go: response.String()
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("host", domain);
        data.put("matched", domain);
        data.put("type", qtype);
        data.put("rcode", rcode);
        data.put("answer", answer);
        data.put("raw", raw);
        data.put("body", raw);
        data.put("all", raw);
        data.put("records", records);
        data.put("question", domain);
        if (vars != null) {
            for (Map.Entry<String, Object> e : vars.entrySet()) {
                if (!data.containsKey(e.getKey())) { // Go: if _, ok := data[k]; !ok
                    data.put(e.getKey(), e.getValue());
                }
            }
        }
        if (err != null) {
            data.put("error", err.toString()); // Go: err.Error()
        }

        ProtocolResult result = new ProtocolResult();
        result.protocol = "dns";
        result.data = data;
        result.raw = raw;
        result.error = err;
        result.duration = Duration.ofNanos(System.nanoTime() - start);
        return result;
    }

    /**
     * 对应 Go 的 {@code dnsTypeToInt(t string) uint16}， miekg/dns 常量 → dnsjava {@link Type} 常量。
     */
    static int dnsTypeToInt(String t) {
        switch (t) {
            case "A":
                return Type.A;
            case "NS":
                return Type.NS;
            case "CNAME":
                return Type.CNAME;
            case "SOA":
                return Type.SOA;
            case "PTR":
                return Type.PTR;
            case "MX":
                return Type.MX;
            case "TXT":
                return Type.TXT;
            case "AAAA":
                return Type.AAAA;
            case "SRV":
                return Type.SRV;
            case "CAA":
                return Type.CAA;
            default:
                return Type.A;
        }
    }

    /**
     * 对应 Go 的 {@code dnsClassToInt(c string) uint16}， miekg/dns 常量 → dnsjava {@link DClass} 常量。
     */
    static int dnsClassToInt(String c) {
        String upper = (c == null ? "" : c).toUpperCase(Locale.ROOT);
        switch (upper) {
            case "IN":
                return DClass.IN;
            case "CS":
                return 2; // miekg/dns 的 dns.ClassCSNET；dnsjava 未提供该常量
            case "CH":
                return DClass.CHAOS;
            case "HS":
                return DClass.HESIOD;
            default:
                return DClass.IN;
        }
    }

    /**
     * 对应 Go 的 {@code rrToString(rrs []dns.RR) string}：
     * 逐条 {@code rr.String()} 追加、<strong>无分隔符</strong>（照抄 Go 原样）。
     */
    static String rrToString(List<Record> rrs) {
        StringBuilder b = new StringBuilder();
        if (rrs != null) {
            for (Record rr : rrs) {
                b.append(rr.toString());
            }
        }
        return b.toString();
    }
}

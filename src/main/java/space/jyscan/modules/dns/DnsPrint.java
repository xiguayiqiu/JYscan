package space.jyscan.modules.dns;

import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Header;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;
import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

/**
 * DNS 结果的翻译与打印，移植自 freeclient/internal/dns/dns.go 的
 * {@code PrintFullResult / PrintShortResult / TranslateXxx}。
 *
 * <p>布局与 Go 逐行对齐；颜色映射：{@code cyanBold = FgHiCyan+Bold}、
 * {@code yellow = FgYellow}、{@code green = FgGreen}。
 *
 * <p>{@code ; <<>> ... DNS <<>>} 头部在 Go 侧是 {@code GYscan}，按移植约定改为 JYscan。
 */
public final class DnsPrint {

    private static final DateTimeFormatter WHEN_FMT =
            DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss z yyyy", Locale.ENGLISH)
                    .withZone(ZoneId.systemDefault());

    private static final DateTimeFormatter NOW_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private DnsPrint() {
    }

    // =====================================================================
    // 颜色输出原语（对应 color.Color.Printf）
    // =====================================================================

    /** 青色加粗输出，对应 Go 的 {@code color.New(FgHiCyan, Bold).Printf}。 */
    static void cyanBold(String fmt, Object... args) {
        System.out.print(Colors.wrap(Fmt.format(fmt, args), Colors.FG_HI_CYAN, Colors.BOLD));
    }

    /** 黄色输出，对应 Go 的 {@code color.New(FgYellow).Printf}。 */
    static void yellow(String fmt, Object... args) {
        System.out.print(Colors.wrap(Fmt.format(fmt, args), Colors.FG_YELLOW));
    }

    /** 绿色输出，对应 Go 的 {@code color.New(FgGreen).Printf}。 */
    static void green(String fmt, Object... args) {
        System.out.print(Colors.wrap(Fmt.format(fmt, args), Colors.FG_GREEN));
    }

    /** 对应 Go 的 {@code time.Now().Format("Mon Jan 2 15:04:05 MST 2006")}。 */
    static String whenNow() {
        return WHEN_FMT.format(Instant.now());
    }

    /** 对应 Go 的 {@code time.Now().Format("2006-01-02 15:04:05")}。 */
    static String now() {
        return NOW_FMT.format(java.time.LocalDateTime.now());
    }

    // =====================================================================
    // PrintFullResult / PrintShortResult（对应 dns.go 同名函数）
    // =====================================================================

    /** 完整格式输出，逐行对应 Go 的 {@code PrintFullResult}。 */
    public static void printFullResult(FullDnsResult result, boolean shortOutput) {
        if (result == null || result.msg == null) {
            return;
        }
        Message msg = result.msg;

        if (shortOutput) {
            printShortResult(msg);
            return;
        }

        Record question = msg.getQuestion();
        String qname = question == null ? "" : question.getName().toString();
        cyanBold("; <<>> JYscan DNS <<>> %s\n", qname);
        System.out.println(";; 收到应答:");

        Header h = msg.getHeader();
        /*
         * Go 的 flags 逻辑：Response→qr、Opcode==QUERY→rd、RecursionAvailable→ra。
         * dnsjava 只提供 Header.printFlags()（按标志位降序输出），对真实应答而言
         * 与 Go 的三条判断等价（应答必然置 QR，且必然回显 RD）。
         */
        String flags = h.printFlags().trim();

        yellow(";; ->>头部<<- 操作码: %s, 状态: %s, ID: %d\n",
                translateOpcode(Opcode.string(h.getOpcode())),
                translateRcode(Rcode.string(msg.getRcode())),
                h.getID());
        yellow(";; 标志: %s; 查询: %d, 回答: %d, 权威: %d, 附加: %d\n",
                flags,
                msg.getSection(Section.QUESTION).size(),
                msg.getSection(Section.ANSWER).size(),
                msg.getSection(Section.AUTHORITY).size(),
                msg.getSection(Section.ADDITIONAL).size());
        System.out.println();

        List<Record> extra = msg.getSection(Section.ADDITIONAL);
        if (!extra.isEmpty()) {
            cyanBold(";; OPT 伪部分:\n");
            for (Record r : extra) {
                if (r instanceof OPTRecord opt) {
                    yellow("; EDNS: 版本: %d, 标志:", opt.getVersion());
                    // dnsjava 的 DO 位在 flags 的最高位
                    if ((opt.getFlags() & 0x8000) != 0) {
                        System.out.print(" do");
                    }
                    System.out.print("; UDP: " + opt.getPayloadSize() + "\n");
                }
            }
        }

        cyanBold(";; 查询部分:\n");
        for (Record q : msg.getSection(Section.QUESTION)) {
            green(";%s\t\t%s\t%s\n",
                    q.getName().toString(),
                    translateClass(DClass.string(q.getDClass())),
                    translateType(Type.string(q.getType())));
        }
        System.out.println();

        List<Record> answers = msg.getSection(Section.ANSWER);
        if (!answers.isEmpty()) {
            cyanBold(";; 回答部分:\n");
            for (Record ans : answers) {
                System.out.println(translateRecord(ans));
            }
            System.out.println();
        }

        List<Record> authority = msg.getSection(Section.AUTHORITY);
        if (!authority.isEmpty()) {
            cyanBold(";; 权威部分:\n");
            for (Record ns : authority) {
                System.out.println(translateRecord(ns));
            }
            System.out.println();
        }

        boolean hasNonOPT = false;
        for (Record r : extra) {
            if (!(r instanceof OPTRecord)) {
                hasNonOPT = true;
                break;
            }
        }
        if (hasNonOPT) {
            cyanBold(";; 附加部分:\n");
            for (Record r : extra) {
                if (!(r instanceof OPTRecord)) {
                    System.out.println(translateRecord(r));
                }
            }
            System.out.println();
        }

        cyanBold(";; 查询时间: %s\n", result.queryTimeStr);
        cyanBold(";; 服务器: %s\n", result.server);
        cyanBold(";; 时间: %s\n", now());
        // Go 的 msg.Len() 即编码后的字节数
        cyanBold(";; 消息大小: %d 字节\n", msg.toWire().length);
        System.out.println();
    }

    /** 简洁输出，逐分支对应 Go 的 {@code PrintShortResult}。 */
    public static void printShortResult(Message msg) {
        if (msg == null) {
            return;
        }
        for (Record ans : msg.getSection(Section.ANSWER)) {
            if (ans instanceof ARecord a) {
                System.out.println(a.getAddress().getHostAddress());
            } else if (ans instanceof AAAARecord aaaa) {
                System.out.println(aaaa.getAddress().getHostAddress());
            } else if (ans instanceof MXRecord mx) {
                System.out.println(mx.getPriority() + " " + mx.getTarget());
            } else if (ans instanceof NSRecord ns) {
                System.out.println(ns.getTarget());
            } else if (ans instanceof TXTRecord txt) {
                System.out.println(String.join(" ", txt.getStrings()));
            } else if (ans instanceof CNAMERecord cname) {
                System.out.println(cname.getTarget());
            } else if (ans instanceof SOARecord soa) {
                System.out.printf("%s %s %d %d %d %d %d%n",
                        soa.getHost(), soa.getAdmin(), soa.getSerial(), soa.getRefresh(),
                        soa.getRetry(), soa.getExpire(), soa.getMinimum());
            } else if (ans instanceof PTRRecord ptr) {
                System.out.println(ptr.getTarget());
            } else {
                System.out.println(ans.toString());
            }
        }
    }


    // =====================================================================
    // TranslateXxx（对应 dns.go 的同名函数）
    // =====================================================================

    /** 操作码翻译，对应 Go 的 {@code TranslateOpcode}。 */
    public static String translateOpcode(String op) {
        return switch (op == null ? "" : op) {
            case "QUERY" -> "查询";
            case "IQUERY" -> "反向查询";
            case "STATUS" -> "状态";
            case "NOTIFY" -> "通知";
            case "UPDATE" -> "更新";
            default -> op;
        };
    }

    /** 响应码翻译，对应 Go 的 {@code TranslateRcode}。 */
    public static String translateRcode(String rc) {
        return switch (rc == null ? "" : rc) {
            case "NOERROR" -> "无错误";
            case "FORMERR" -> "格式错误";
            case "SERVFAIL" -> "服务器失败";
            case "NXDOMAIN" -> "域名不存在";
            case "NOTIMP" -> "未实现";
            case "REFUSED" -> "拒绝";
            case "YXDOMAIN" -> "域名已存在";
            case "YXRRSET" -> "记录集已存在";
            case "NXRRSET" -> "记录集不存在";
            case "NOTAUTH" -> "未授权";
            case "NOTZONE" -> "非本区";
            default -> rc;
        };
    }

    /** 类别翻译，对应 Go 的 {@code TranslateClass}。 */
    public static String translateClass(String c) {
        return switch (c == null ? "" : c) {
            case "IN" -> "互联网";
            case "CS" -> "CSNET";
            case "CH" -> "CHAOS";
            case "HS" -> "HESIOD";
            default -> c;
        };
    }

    /** 记录类型翻译，对应 Go 的 {@code TranslateType}。 */
    public static String translateType(String t) {
        return switch (t == null ? "" : t) {
            case "A" -> "A(IPv4)";
            case "AAAA" -> "AAAA(IPv6)";
            case "NS" -> "NS(域名服务器)";
            case "CNAME" -> "CNAME(别名)";
            case "SOA" -> "SOA(起始授权)";
            case "MX" -> "MX(邮件交换)";
            case "TXT" -> "TXT(文本)";
            case "PTR" -> "PTR(指针)";
            default -> t;
        };
    }

    /**
     * 资源记录的可读串，对应 Go 的 {@code TranslateRecord}：
     * 布局为 {@code 名称\tTTL\t中文类别\t类型\t值}，未识别的类型走 {@code rr.String()}。
     */
    public static String translateRecord(Record rr) {
        if (rr == null) {
            return "";
        }
        String name = rr.getName().toString();
        long ttl = rr.getTTL();
        String classStr = translateClass(DClass.string(rr.getDClass()));

        if (rr instanceof ARecord a) {
            return Fmt.format("%s\t%d\t%s\t%s\t%s",
                    name, ttl, classStr, "A", a.getAddress().getHostAddress());
        }
        if (rr instanceof AAAARecord aaaa) {
            return Fmt.format("%s\t%d\t%s\t%s\t%s",
                    name, ttl, classStr, "AAAA", aaaa.getAddress().getHostAddress());
        }
        if (rr instanceof CNAMERecord cname) {
            return Fmt.format("%s\t%d\t%s\t%s\t%s",
                    name, ttl, classStr, "CNAME", cname.getTarget());
        }
        if (rr instanceof NSRecord ns) {
            return Fmt.format("%s\t%d\t%s\t%s\t%s",
                    name, ttl, classStr, "NS", ns.getTarget());
        }
        if (rr instanceof MXRecord mx) {
            return Fmt.format("%s\t%d\t%s\t%s\t%d\t%s",
                    name, ttl, classStr, "MX", mx.getPriority(), mx.getTarget());
        }
        if (rr instanceof TXTRecord txt) {
            return Fmt.format("%s\t%d\t%s\t%s\t\"%s\"",
                    name, ttl, classStr, "TXT", String.join(" ", txt.getStrings()));
        }
        if (rr instanceof SOARecord soa) {
            return Fmt.format("%s\t%d\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d",
                    name, ttl, classStr, "SOA", soa.getHost(), soa.getAdmin(), soa.getSerial(),
                    soa.getRefresh(), soa.getRetry(), soa.getExpire(), soa.getMinimum());
        }
        if (rr instanceof PTRRecord ptr) {
            return Fmt.format("%s\t%d\t%s\t%s\t%s",
                    name, ttl, classStr, "PTR", ptr.getTarget());
        }
        if (rr instanceof SRVRecord srv) {
            // Go 的 TranslateRecord 未列 SRV，落到 default 的 rr.String()；
            // 这里对齐 sniffer 侧的 extractAnswerValue 风格会改变格式，故同样走 String()
            return rr.toString();
        }
        return rr.toString();
    }

}

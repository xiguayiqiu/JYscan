package space.jyscan.modules.nmap;

import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * 内容探测（{@code -X}）入口，移植自 freeclient/internal/nmap/content_probe.go（1742 行）。
 *
 * <p><b>归属</b>：本文件由 C 号子代理实现（源文件 content_probe.go，1742 行）。
 * 其余模块只依赖下面两个签名，请勿改动签名，否则 B 号（扫描引擎）编译不过。
 *
 * <p><b>{@link ContentProbeResult#content} 的表示</b>：统一为 latin1（ISO-8859-1）字节视图——
 * 第 {@code i} 个 char 的低 8 位即回复的第 {@code i} 个字节，于是
 * {@code content.length()} == Go 的 {@code len(reply)}，回复判定 / hexdump / 二进制占比 /
 * 可视字符串提取全部逐字节等价。回填 {@link PortInfo#content} 时再按 UTF-8 解码
 * （非法序列替换为 U+FFFD，等价 Go {@code encoding/json} 对 string 的强制转换）；
 * 终端打印经 {@link #printGo}（{@code encodeGoOutput}：{@code <= 0xFF} 的 char 按单字节写出，
 * 其余按 UTF-8）直接写原始字节，与 Go {@code fmt.Print} 一致。
 *
 * <p><b>与 Go 的差异</b>（均已尽量收敛到不影响输出的层面）：
 * <ul>
 *   <li>{@code context.Context} 不移植：Go 的 {@code ctx.Done()} 检查由 Java 侧
 *       线程池生命周期承担；</li>
 *   <li>{@code progressMu}（scan_optimized.go 的进度锁）无 Java 对应物，只保留
 *       本文件自己的 {@code contentProbePrintMu}；</li>
 *   <li>Socket 无写超时（Go 的 {@code SetWriteDeadline} 无对应 API），写请求不设截止；</li>
 *   <li>无 {@code sync.Pool}：读缓冲每次调用分配 4KB；</li>
 *   <li>TLS 走 JSSE + 信任所有证书（等价 {@code InsecureSkipVerify}），SNI 显式设置
 *       （IP 字面量不发 SNI，等价 Go {@code hostnameInSNI}）；下划线主机名被
 *       {@code SNIHostName} 拒绝时省略 SNI；</li>
 *   <li>配色本地复刻 fatih/color v1.18.0 的 wrap/Print/Println 语义，受
 *       {@link Colors#useColor}（对应 Go {@code color.NoColor}）控制。</li>
 * </ul>
 */
public final class ContentProbe {

    private ContentProbe() {
    }

    // =====================================================================
    // 常量（对应 Go contentProbe*.go 顶部 const 块）
    // =====================================================================

    /** 单次内容探测最多读取的字节数 (防止无限读取) */
    static final int CONTENT_PROBE_MAX_BYTES = 64 * 1024;
    /** 单端口最多尝试的探测器数量 (控制探测噪声与耗时) */
    static final int CONTENT_PROBE_MAX_ATTEMPTS = 5;
    /** 被动读取 banner 的最长等待时间 */
    static final Duration CONTENT_PROBE_PASSIVE_READ_TIMEOUT = Duration.ofSeconds(2);
    /** 文本内容展示的最大行数 */
    static final int CONTENT_PROBE_MAX_DISPLAY_LINES = 100;
    /** 文本内容展示的最大字符（rune）数 */
    static final int CONTENT_PROBE_MAX_DISPLAY_BYTES = 8192;
    /** 二进制内容 hexdump 的最大行数 */
    static final int CONTENT_PROBE_HEX_DUMP_MAX_LINES = 64;
    /** 不可打印字符占比超过该值即视为二进制内容 */
    static final double CONTENT_PROBE_BINARY_RATIO = 0.30;
    /** 二进制内容中提取可视字符串的最大条数 */
    static final int CONTENT_PROBE_MAX_STRINGS = 40;
    /** 可视字符串的最小长度 */
    static final int CONTENT_PROBE_MIN_STRING_LEN = 4;
    /** 默认内容探测超时 */
    static final Duration CONTENT_PROBE_DEFAULT_TIMEOUT = Duration.ofSeconds(5);
    /** 默认内容探测并发数 */
    static final int CONTENT_PROBE_DEFAULT_CONCURRENCY = 32;
    /** 内容探测使用的 User-Agent */
    static final String CONTENT_PROBE_USER_AGENT = "Mozilla/5.0 (compatible; JYscan/1.0; ContentProbe)";

    // =====================================================================
    // 嵌套类型（对应 Go 的 contentProbeSpec / serviceProbeHints 匿名结构 / ContentDedupEntry）
    // =====================================================================

    /** 请求构造器，对应 Go {@code Build func(ip string, port int) []byte}；nil 表示仅被动读取。 */
    interface RequestBuilder {
        byte[] build(String host, int port);
    }

    /**
     * 回复判定，对应 Go {@code Match func(reply string) bool}；null 表示任何非空回复都接受。
     * {@code reply} 为 latin1 字节视图（见类注释），逐字节操作与 Go 逐位等价。
     */
    interface ReplyMatcher {
        boolean matches(String reply);
    }

    /** 单个协议探测器，对应 Go {@code contentProbeSpec}。 */
    static final class ContentProbeSpec {
        /** 探测器名称 */
        public final String name;
        /** 协议名 */
        public final String protocol;
        /** 请求构造器；null 表示仅被动读取 */
        public final RequestBuilder build;
        /** 是否在 TLS 通道内探测 */
        public final boolean useTLS;
        /** 回复判定；null 表示任何非空回复都接受 */
        public final ReplyMatcher match;

        ContentProbeSpec(String name, String protocol, RequestBuilder build,
                         boolean useTLS, ReplyMatcher match) {
            this.name = name;
            this.protocol = protocol;
            this.build = build;
            this.useTLS = useTLS;
            this.match = match;
        }
    }

    /** 服务名关键字到候选协议的映射项，对应 Go {@code serviceProbeHints} 的匿名结构。 */
    static final class ServiceHint {
        public final String keyword;
        public final String[] protocols;

        ServiceHint(String keyword, String[] protocols) {
            this.keyword = keyword;
            this.protocols = protocols;
        }
    }

    /** 记录某个内容指纹已在哪个 IP 上打印过，对应 Go {@code ContentDedupEntry}。 */
    static final class ContentDedupEntry {
        public final String firstIP;
        public final int count;

        ContentDedupEntry(String firstIP, int count) {
            this.firstIP = firstIP;
            this.count = count;
        }
    }

    /** 协议回复行的语义分类 (用于着色)，对应 Go {@code contentProbeReplyKind}。 */
    static final int CONTENT_PROBE_REPLY_PLAIN = 0;
    static final int CONTENT_PROBE_REPLY_OK = 1;
    static final int CONTENT_PROBE_REPLY_ERROR = 2;

    // =====================================================================
    // fatih/color v1.18.0 本地复刻
    //
    // open   = "\x1b[" + params 以 ";" 连接 + "m"（对应 Color.format/sequence）
    // unformat = 逐参数复位：1/2→22, 3→23, 4→24, 5/6→25, 7→27, 8→28, 9→29，其余 0
    //            （对应 Color.unformat + mapResetAttributes）
    // Print/Printf   = open + 文本 + "\x1b[0m"（Set + defer unset）
    // Println        = open + 文本 + unformat + "\n"（Fprintln(wrap(sprintln(a...))))
    // Sprint/Sprintf = open + 文本 + unformat（Color.wrap）
    // 全部受 Colors.useColor（对应 Go color.NoColor）控制。
    // =====================================================================

    private static final String ESC = "\u001b[";
    private static final String RESET_SEQ = "\u001b[0m";

    /** 对应 fatih Color.format()：{@code "\x1b[36;1m"}。 */
    static String goOpen(int... attrs) {
        StringBuilder sb = new StringBuilder(ESC);
        for (int i = 0; i < attrs.length; i++) {
            if (i > 0) {
                sb.append(';');
            }
            sb.append(attrs[i]);
        }
        return sb.append('m').toString();
    }

    /** 单个参数的复位码（对应 fatih mapResetAttributes，缺省为 Reset=0）。 */
    static int goResetCode(int attr) {
        return switch (attr) {
            case 1, 2 -> 22;   // Bold / Faint  -> ResetBold
            case 3 -> 23;      // Italic         -> ResetItalic
            case 4 -> 24;      // Underline      -> ResetUnderline
            case 5, 6 -> 25;   // BlinkSlow/Rapid-> ResetBlinking
            case 7 -> 27;      // ReverseVideo   -> ResetReversed
            case 8 -> 28;      // Concealed      -> ResetConcealed
            case 9 -> 29;      // CrossedOut     -> ResetCrossedOut
            default -> 0;      // 颜色等无专属复位码 → 通用 Reset
        };
    }

    /** 对应 fatih Color.unformat()：逐参数复位、以 ";" 连接。 */
    static String goUnformat(int... attrs) {
        StringBuilder sb = new StringBuilder(ESC);
        for (int i = 0; i < attrs.length; i++) {
            if (i > 0) {
                sb.append(';');
            }
            sb.append(goResetCode(attrs[i]));
        }
        return sb.append('m').toString();
    }

    /** 对应 fatih Color.wrap（Sprint/Sprintf/Println 的包裹语义）。 */
    static String goWrap(String s, int... attrs) {
        if (!Colors.useColor || s == null || attrs.length == 0) {
            return s;
        }
        return goOpen(attrs) + s + goUnformat(attrs);
    }

    /** 对应 fatih Color.Sprint。 */
    static String goSprint(Object obj, int... attrs) {
        return goWrap(String.valueOf(obj), attrs);
    }

    /** 对应 fatih Color.Sprintf。 */
    static String goSprintf(String fmt, Object[] args, int... attrs) {
        return goWrap(Fmt.format(fmt, args), attrs);
    }

    /** 对应 fatih Color.Print（open + 文本 + RESET，且不带换行）。 */
    static void goPrint(Object obj, int... attrs) {
        String text = String.valueOf(obj);
        if (Colors.useColor && attrs.length > 0) {
            printGo(goOpen(attrs) + text + RESET_SEQ);
        } else {
            printGo(text);
        }
    }

    /** 对应 fatih Color.Printf（与 Print 相同的复位语义）。 */
    static void goPrintf(String fmt, Object[] args, int... attrs) {
        goPrint(Fmt.format(fmt, args), attrs);
    }

    /** 对应 fatih Color.Println：wrap 后由 Fprintln 追加换行。 */
    static void goPrintln(Object obj, int... attrs) {
        printGo(goWrap(String.valueOf(obj), attrs) + "\n");
    }

    // =====================================================================
    // 终端原始字节输出
    //
    // Go 的 fmt.Print 直接写 Go string 的底层字节，而 Go string 恒为 UTF-8：
    //   - 源码里的中文串面量本身就是 UTF-8 字节；
    //   - 展示文本经 formatContentForDisplay 的 decodeViewUtf8 解码后是合法
    //     Unicode 文本（Go 侧 range+WriteRune 同样得到合法 UTF-8），打印时按
    //     UTF-8 重编码即可逐字节一致；
    //   - latin1 字节视图（ContentProbeResult.content）在打印前总会先经过
    //     formatContentForDisplay 解码，不会以原始高位字节形态到达这里；
    //   - ANSI 控制符与 ASCII 均 <= 0x7F，单字节写出即原样。
    // 故：char <= 0x7F 单字节写出；否则按 UTF-8 编码（与 Go 写 UTF-8 一致）。
    // =====================================================================

    /** 把字符串编码为「Go 会写出的字节」（见上方说明）。 */
    static byte[] encodeGoOutput(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c <= 0x7f) {
                out.write(c);
            } else if (Character.isHighSurrogate(c) && i + 1 < s.length()
                    && Character.isLowSurrogate(s.charAt(i + 1))) {
                writeUtf8(out, s.codePointAt(i));
                i++;
            } else {
                writeUtf8(out, c);
            }
        }
        return out.toByteArray();
    }

    private static void writeUtf8(ByteArrayOutputStream out, int cp) {
        if (cp < 0x80) {
            out.write(cp);
        } else if (cp < 0x800) {
            out.write(0xc0 | (cp >> 6));
            out.write(0x80 | (cp & 0x3f));
        } else if (cp < 0x10000) {
            out.write(0xe0 | (cp >> 12));
            out.write(0x80 | ((cp >> 6) & 0x3f));
            out.write(0x80 | (cp & 0x3f));
        } else {
            out.write(0xf0 | (cp >> 18));
            out.write(0x80 | ((cp >> 12) & 0x3f));
            out.write(0x80 | ((cp >> 6) & 0x3f));
            out.write(0x80 | (cp & 0x3f));
        }
    }

    /** 以 Go 字节序写出并刷新，保证与其它 stdout 写入的相对顺序。 */
    static void printGo(String s) {
        if (s == null || s.isEmpty()) {
            return;
        }
        try {
            System.out.write(encodeGoOutput(s));
        } catch (java.io.IOException e) {
            // Go 侧忽略 os.Stdout 写错误
        }
        System.out.flush();
    }

    // =====================================================================
    // 字节 / 字符串基础工具
    // =====================================================================

    /** 由 int 列表构造字节数组（请求构造里大量 {@code 0xNN} 字面量用）。 */
    static byte[] b(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return out;
    }

    /** 拼接多个字节数组（对应 Go 的多次 append）。 */
    static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) {
            total += p.length;
        }
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    /**
     * ASCII 小写化（对应回复判定里 Go {@code strings.ToLower} 的效果）。
     *
     * <p>匹配用的子串（needle）与键名全部为 ASCII，因此只小写 {@code A-Z} 即与 Go 结果一致：
     * 对非 ASCII 的非法 UTF-8 字节 Go 保持原样，本实现同样保持原样；
     * 唯一差异是有效 UTF-8 中的非 ASCII 大写字母（如 U+00C9）Go 会小写而本实现不会，
     * 但这不影响任何含 ASCII needle 的 {@code Contains} 判定。
     */
    static String asciiLower(String s) {
        char[] chars = s.toCharArray();
        boolean changed = false;
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] >= 'A' && chars[i] <= 'Z') {
                chars[i] = (char) (chars[i] + 32);
                changed = true;
            }
        }
        return changed ? new String(chars) : s;
    }

    /** Go {@code unicode.IsSpace}（White_Space 属性）的码点判定。 */
    static boolean goIsSpace(int cp) {
        return (cp >= 0x09 && cp <= 0x0d)
                || cp == 0x20 || cp == 0x85 || cp == 0xa0
                || cp == 0x1680
                || (cp >= 0x2000 && cp <= 0x200a)
                || cp == 0x2028 || cp == 0x2029 || cp == 0x202f
                || cp == 0x205f || cp == 0x3000;
    }

    /** Go {@code strings.TrimSpace}（按 rune、按 White_Space 集合）。 */
    static String goTrimSpace(String s) {
        if (s == null || s.isEmpty()) {
            return s == null ? "" : s;
        }
        int start = 0;
        int end = s.length();
        while (start < end && goIsSpace(s.codePointAt(start))) {
            start += Character.charCount(s.codePointAt(start));
        }
        while (end > start && goIsSpace(s.codePointBefore(end))) {
            end -= Character.charCount(s.codePointBefore(end));
        }
        return s.substring(start, end);
    }

    /** Go {@code strings.TrimRight(raw, " \t")}。 */
    static String trimRightSpaceTab(String s) {
        int end = s.length();
        while (end > 0) {
            char c = s.charAt(end - 1);
            if (c == ' ' || c == '\t') {
                end--;
            } else {
                break;
            }
        }
        return s.substring(0, end);
    }

    /** Go {@code strings.SplitN(s, string(sep), limit)}。 */
    static String[] splitN(String s, char sep, int limit) {
        List<String> parts = new ArrayList<>();
        int start = 0;
        while (parts.size() < limit - 1) {
            int idx = s.indexOf(sep, start);
            if (idx < 0) {
                break;
            }
            parts.add(s.substring(start, idx));
            start = idx + 1;
        }
        parts.add(s.substring(start));
        return parts.toArray(new String[0]);
    }

    /** 手写小写十六进制（对应 Go {@code %x} 对 []byte 的输出）。 */
    static String hexLower(byte[] bytes) {
        char[] digits = "0123456789abcdef".toCharArray();
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            sb.append(digits[(value >> 4) & 0x0f]).append(digits[value & 0x0f]);
        }
        return sb.toString();
    }

    /** Duration → 毫秒（向上取整，避免把超时截短为 0）。 */
    static int ceilMs(Duration d) {
        long ns = d.isNegative() ? 0 : d.toNanos();
        long ms = (ns + 999_999L) / 1_000_000L;
        if (ms < 1) {
            ms = 1;
        }
        if (ms > Integer.MAX_VALUE) {
            ms = Integer.MAX_VALUE;
        }
        return (int) ms;
    }

    /** 静默关闭连接（对应 Go 的 defer conn.Close()）。 */
    static void closeQuiet(Socket conn) {
        if (conn == null) {
            return;
        }
        try {
            conn.close();
        } catch (IOException ignored) {
            // 关闭失败无影响
        }
    }

    /** 不可中断地等待（Go 的 wg.Wait() 不响应取消）。 */
    static void awaitUninterruptible(CountDownLatch latch) {
        boolean interrupted = false;
        while (true) {
            try {
                if (latch.await(1, java.util.concurrent.TimeUnit.DAYS)) {
                    break;
                }
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    /** 空安全取串（Go 的字段是 string 零值 ""）。 */
    static String str(String s) {
        return s == null ? "" : s;
    }

    // =====================================================================
    // 端口 / 服务名线索表（逐行对照 Go 的 webProbePorts / tlsWebProbePorts /
    // tlsRawProbePorts / portProbeHints / serviceProbeHints）
    // =====================================================================

    static Set<Integer> intSet(int... values) {
        Set<Integer> set = new HashSet<>(Math.max(16, values.length * 2));
        for (int v : values) {
            set.add(v);
        }
        return set;
    }

    /** 常见明文 Web/HTTP 端口 */
    static final Set<Integer> WEB_PROBE_PORTS = intSet(
            80, 81, 82, 83, 84, 85, 86,
            88, 280, 515, 591, 800, 888,
            1000, 2000, 3000, 3333, 5000, 5601,
            5800, 5984, 6080, 7000, 7001, 7002,
            8000, 8001, 8008, 8010, 8020, 8030,
            8040, 8042, 8069, 8080, 8081, 8082,
            8083, 8085, 8086, 8087, 8088, 8090,
            8091, 8099, 8161, 8180, 8181, 8200,
            8300, 8404, 8500, 8834, 8880, 8888,
            8983, 9000, 9001, 9002, 9080, 9090,
            9091, 9200, 9300, 9418, 9999, 10000,
            10080, 15672, 18080, 28017, 28080,
            50000, 50070, 50090);

    /** 常见 HTTPS (HTTP over TLS) 端口 */
    static final Set<Integer> TLS_WEB_PROBE_PORTS = intSet(
            443, 2376, 4430, 4443, 4444, 5443,
            5986, 6443, 7443, 8443, 8444, 9443,
            10443);

    /** 仅 TLS 握手后读取服务数据的端口 (imaps/pop3s/smtps/ldaps 等) */
    static final Set<Integer> TLS_RAW_PROBE_PORTS = intSet(
            465, 636, 990, 992, 993, 994,
            995, 5061, 5671);

    static Map<Integer, String[]> newPortProbeHints() {
        Map<Integer, String[]> m = new HashMap<>();
        m.put(21, new String[]{"ftp"});
        m.put(22, new String[]{"ssh"});
        m.put(23, new String[]{"telnet"});
        m.put(25, new String[]{"smtp"});
        m.put(43, new String[]{"whois"});
        m.put(53, new String[]{"dns"});
        m.put(111, new String[]{"rpcbind"});
        m.put(135, new String[]{"dcerpc"});
        m.put(139, new String[]{"smb"});
        m.put(143, new String[]{"imap"});
        m.put(389, new String[]{"ldap"});
        m.put(445, new String[]{"smb"});
        m.put(465, new String[]{"smtps"});
        m.put(554, new String[]{"rtsp"});
        m.put(587, new String[]{"smtp"});
        m.put(631, new String[]{"http"});
        m.put(636, new String[]{"ldaps"});
        m.put(873, new String[]{"rsync"});
        m.put(990, new String[]{"ftps"});
        m.put(992, new String[]{"tls-raw"});
        m.put(993, new String[]{"imaps"});
        m.put(995, new String[]{"pop3s"});
        m.put(1080, new String[]{"socks5"});
        m.put(1099, new String[]{"java-rmi"});
        m.put(1433, new String[]{"mssql"});
        m.put(1521, new String[]{"oracle"});
        m.put(1883, new String[]{"mqtt"});
        m.put(2049, new String[]{"nfs"});
        m.put(2181, new String[]{"zookeeper"});
        m.put(2375, new String[]{"http"});
        m.put(3260, new String[]{"raw"});
        m.put(3306, new String[]{"mysql"});
        m.put(3389, new String[]{"rdp"});
        m.put(5060, new String[]{"sip"});
        m.put(5222, new String[]{"xmpp"});
        m.put(5432, new String[]{"postgres"});
        m.put(5672, new String[]{"amqp"});
        m.put(5900, new String[]{"vnc"});
        m.put(5985, new String[]{"http"});
        m.put(6379, new String[]{"redis"});
        m.put(6667, new String[]{"irc"});
        m.put(8009, new String[]{"ajp13"});
        m.put(9042, new String[]{"raw"});
        m.put(9092, new String[]{"kafka"});
        m.put(11211, new String[]{"memcached"});
        m.put(27017, new String[]{"mongodb"});
        m.put(10050, new String[]{"zabbix"});
        m.put(10051, new String[]{"zabbix"});
        return m;
    }

    /** 常见端口对应的候选协议 (按优先级排序) */
    static final Map<Integer, String[]> PORT_PROBE_HINTS = newPortProbeHints();

    /** 服务名关键字到候选协议的映射 (按顺序匹配，先命中的优先) */
    static final ServiceHint[] SERVICE_PROBE_HINTS = {
            new ServiceHint("https", new String[]{"https"}),
            new ServiceHint("ssl", new String[]{"https"}),
            new ServiceHint("imaps", new String[]{"imaps", "tls-raw"}),
            new ServiceHint("pop3s", new String[]{"pop3s", "tls-raw"}),
            new ServiceHint("smtps", new String[]{"smtps", "tls-raw"}),
            new ServiceHint("ldaps", new String[]{"ldaps", "tls-raw"}),
            new ServiceHint("ftps", new String[]{"ftps", "tls-raw"}),
            new ServiceHint("http", new String[]{"http"}),
            new ServiceHint("ftp", new String[]{"ftp"}),
            new ServiceHint("smtp", new String[]{"smtp"}),
            new ServiceHint("pop3", new String[]{"pop3"}),
            new ServiceHint("imap", new String[]{"imap"}),
            new ServiceHint("ssh", new String[]{"ssh"}),
            new ServiceHint("telnet", new String[]{"telnet"}),
            new ServiceHint("mysql", new String[]{"mysql"}),
            new ServiceHint("mariadb", new String[]{"mysql"}),
            new ServiceHint("ms-sql", new String[]{"mssql"}),
            new ServiceHint("postgres", new String[]{"postgres"}),
            new ServiceHint("mongo", new String[]{"mongodb"}),
            new ServiceHint("redis", new String[]{"redis"}),
            new ServiceHint("memcache", new String[]{"memcached"}),
            new ServiceHint("vnc", new String[]{"vnc"}),
            new ServiceHint("rdp", new String[]{"rdp"}),
            new ServiceHint("ms-wbt", new String[]{"rdp"}),
            new ServiceHint("microsoft-ds", new String[]{"smb"}),
            new ServiceHint("netbios", new String[]{"smb"}),
            new ServiceHint("smb", new String[]{"smb"}),
            new ServiceHint("ldap", new String[]{"ldap"}),
            new ServiceHint("amqp", new String[]{"amqp"}),
            new ServiceHint("zookeeper", new String[]{"zookeeper"}),
            new ServiceHint("sip", new String[]{"sip"}),
            new ServiceHint("rtsp", new String[]{"rtsp"}),
            new ServiceHint("irc", new String[]{"irc"}),
            new ServiceHint("xmpp", new String[]{"xmpp"}),
            new ServiceHint("jabber", new String[]{"xmpp"}),
            new ServiceHint("domain", new String[]{"dns"}),
            new ServiceHint("dns", new String[]{"dns"}),
            new ServiceHint("rsync", new String[]{"rsync"}),
            new ServiceHint("socks", new String[]{"socks5"}),
            new ServiceHint("ajp", new String[]{"ajp13"}),
            new ServiceHint("mqtt", new String[]{"mqtt"}),
            new ServiceHint("stomp", new String[]{"stomp"}),
            new ServiceHint("nntp", new String[]{"nntp"}),
            new ServiceHint("whois", new String[]{"whois"}),
            new ServiceHint("git", new String[]{"git"}),
            new ServiceHint("zabbix", new String[]{"zabbix"}),
            new ServiceHint("rmi", new String[]{"java-rmi"}),
            new ServiceHint("oracle", new String[]{"oracle"}),
            new ServiceHint("nfs", new String[]{"nfs"}),
            new ServiceHint("rpcbind", new String[]{"rpcbind"}),
            new ServiceHint("msrpc", new String[]{"dcerpc"}),
            new ServiceHint("kafka", new String[]{"kafka"}),
    };

    // =====================================================================
    // 回复判定辅助（逐个对应 Go 的 replyHasPrefix / replyContains / ... 工厂）
    // =====================================================================

    /** 回复以指定字符串开头 */
    static ReplyMatcher replyHasPrefix(String prefix) {
        return reply -> reply.startsWith(prefix);
    }

    /** 回复包含指定子串 (区分大小写，兼容二进制) */
    static ReplyMatcher replyContains(String sub) {
        return reply -> reply.contains(sub);
    }

    /** 回复包含任一子串 (忽略大小写) */
    static ReplyMatcher replyContainsAny(String... subs) {
        String[] lowered = new String[subs.length];
        for (int i = 0; i < subs.length; i++) {
            lowered[i] = asciiLower(subs[i]);
        }
        return reply -> {
            String low = asciiLower(reply);
            for (String s : lowered) {
                if (low.contains(s)) {
                    return true;
                }
            }
            return false;
        };
    }

    /** 回复首字节属于给定集合 (用于二进制协议握手判定) */
    static ReplyMatcher replyFirstByteIn(int... values) {
        return reply -> {
            if (reply.isEmpty()) {
                return false;
            }
            int first = reply.charAt(0) & 0xff;
            for (int v : values) {
                if (first == (v & 0xff)) {
                    return true;
                }
            }
            return false;
        };
    }

    /** 回复以指定字节序列开头 */
    static ReplyMatcher replyStartsWithBytes(int... prefix) {
        StringBuilder sb = new StringBuilder(prefix.length);
        for (int v : prefix) {
            sb.append((char) (v & 0xff));
        }
        String p = sb.toString();
        return reply -> reply.startsWith(p);
    }

    /** 回复中出现指定字节 (用于 BER/TLV 类协议) */
    static ReplyMatcher replyByteExists(int value) {
        char c = (char) (value & 0xff);
        return reply -> reply.indexOf(c) >= 0;
    }

    /** 组合多个判定，任一命中即视为匹配 */
    static ReplyMatcher replyAny(ReplyMatcher... matchers) {
        return reply -> {
            for (ReplyMatcher m : matchers) {
                if (m != null && m.matches(reply)) {
                    return true;
                }
            }
            return false;
        };
    }

    /** 回复指定偏移处的字节等于给定值 */
    static ReplyMatcher replyByteAt(int index, int value) {
        char c = (char) (value & 0xff);
        return reply -> index < reply.length() && reply.charAt(index) == c;
    }

    /** 回复长度不小于指定值 (用于二进制协议的结构性判定) */
    static ReplyMatcher replyMinLen(int n) {
        return reply -> reply.length() >= n;
    }

    /** 固定请求内容的构造器（对应 Go staticRequest；按 latin1 逐字节复刻 Go 的 []byte(s)）。 */
    static RequestBuilder staticRequest(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.ISO_8859_1);
        return (host, port) -> bytes;
    }

    // =====================================================================
    // 请求构造（逐个对照 Go 的请求构造函数；含 0x80+ 字节的串一律按
    // latin1 编码为原始字节，等价 Go 字符串字面量 \xNN 的底层字节）
    // =====================================================================

    /** 构造 HTTP GET 请求 */
    static byte[] httpProbeRequest(String host, int port) {
        String h = host;
        if (port != 80 && port != 443) {
            h = Fmt.format("%s:%d", host, port);
        }
        return Fmt.format(
                "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                h, CONTENT_PROBE_USER_AGENT).getBytes(StandardCharsets.UTF_8);
    }

    /** 构造 Telnet 选项协商 (触发服务回显)：IAC WILL ECHO / IAC WILL SUPPRESS-GO-AHEAD / IAC DO TERMINAL-TYPE */
    static byte[] telnetNegotiationRequest() {
        return b(0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03, 0xff, 0xfd, 0x18);
    }

    /** 构造 MQTT CONNECT 报文 */
    static byte[] mqttConnectRequest() {
        return b(
                0x10, 0x0c,                        // CONNECT + 剩余长度 12
                0x00, 0x04, 'M', 'Q', 'T', 'T',    // 协议名
                0x04,                              // 协议级别
                0x02,                              // 连接标志 (clean session)
                0x00, 0x3c,                        // keepalive 60s
                0x00, 0x00);                       // 客户端 ID 长度 0
    }

    /** 构造 STOMP CONNECT 帧 */
    static byte[] stompConnectRequest() {
        return ("CONNECT\naccept-version:1.0,1.1,1.2\nhost:jyscan\n\n\u0000")
                .getBytes(StandardCharsets.ISO_8859_1);
    }

    /** 构造 SOCKS5 问候 (无认证) */
    static byte[] socks5Greeting() {
        return b(0x05, 0x01, 0x00);
    }

    /** 构造 IRC 注册命令 */
    static byte[] ircRegistrationRequest() {
        return "NICK jyscan\r\nUSER jyscan 0 * :jyscan content probe\r\n"
                .getBytes(StandardCharsets.UTF_8);
    }

    /** 构造 XMPP 流开启 */
    static byte[] xmppStreamRequest(String host, int port) {
        return Fmt.format(
                "<?xml version='1.0'?><stream:stream xmlns='jabber:client' "
                        + "xmlns:stream='http://etherx.jabber.org/streams' to='%s' version='1.0'>",
                host).getBytes(StandardCharsets.UTF_8);
    }

    /** 构造 SIP OPTIONS 请求 */
    static byte[] sipOptionsRequest(String host, int port) {
        return Fmt.format(
                "OPTIONS sip:%s SIP/2.0\r\nVia: SIP/2.0/TCP %s;branch=z9hG4bK-jyscan\r\n"
                        + "Max-Forwards: 70\r\nTo: <sip:%s>\r\nFrom: <sip:jyscan@%s>;tag=jyscan\r\n"
                        + "Call-ID: jyscan@%s\r\nCSeq: 1 OPTIONS\r\nUser-Agent: JYscan\r\nContent-Length: 0\r\n\r\n",
                host, host, host, host, host).getBytes(StandardCharsets.UTF_8);
    }

    /** 构造 RTSP OPTIONS 请求 */
    static byte[] rtspOptionsRequest(String host, int port) {
        return Fmt.format("OPTIONS rtsp://%s RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: JYscan\r\n\r\n", host)
                .getBytes(StandardCharsets.UTF_8);
    }

    /** 构造 Git 智能协议 upload-pack 请求 (pkt-line) */
    static byte[] gitUploadPackRequest(String host, int port) {
        String payload = Fmt.format("git-upload-pack /jyscan.git\u0000host=%s\u0000", host);
        int total = payload.getBytes(StandardCharsets.UTF_8).length + 4;
        return Fmt.format("%04x%s", total, payload).getBytes(StandardCharsets.UTF_8);
    }

    /** 构造 Zabbix agent 协议请求 (ZBXD + JSON) */
    static byte[] zabbixAgentRequest() {
        byte[] payload = "{\"request\":\"agent.version\"}".getBytes(StandardCharsets.UTF_8);
        byte[] buf = b('Z', 'B', 'X', 'D', 0x01, 0, 0, 0, 0, 0, 0, 0, 0);
        long len = payload.length;
        for (int i = 0; i < 8; i++) {
            buf[5 + i] = (byte) (len >> (8 * i));
        }
        return concat(buf, payload);
    }

    /** 追加 AJP13 字符串 (2 字节大端长度 + 内容) */
    static byte[] appendAJPString(byte[] dst, String s) {
        byte[] content = s.getBytes(StandardCharsets.UTF_8);
        return concat(dst, b(content.length >> 8, content.length), content);
    }

    /** 构造 AJP13 Forward Request */
    static byte[] ajpForwardRequest(String host, int port) {
        byte[] p = b(0x02, 0x02); // Forward Request + GET
        p = appendAJPString(p, "HTTP/1.1");
        p = appendAJPString(p, "/");
        p = appendAJPString(p, host); // remote addr
        p = appendAJPString(p, host); // remote host
        p = appendAJPString(p, host); // server name
        p = concat(p, b(0x00, 0x50));  // server port 80
        p = concat(p, b(0x00));        // is_ssl
        p = concat(p, b(0x00, 0x00));  // 请求头数量
        p = concat(p, b(0xff));        // 属性结束标记
        byte[] packet = concat(b(0x12, 0x34, p.length >> 8, p.length), p, b(0x00));
        return packet;
    }

    /** 构造 SMB1 Negotiate Protocol 请求 (NetBIOS 会话服务封装) */
    static byte[] smbNegotiateRequest() {
        byte[] smb = b(
                0xff, 'S', 'M', 'B',             // SMB1 魔数
                0x72,                            // NEGOTIATE_PROTOCOL
                0x00, 0x00, 0x00, 0x00,          // status
                0x18,                            // flags
                0x53, 0xc8,                      // flags2
                0x00, 0x00,                      // pid high
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // signature
                0x00, 0x00,                      // reserved
                0x00, 0x00,                      // tid
                0x00, 0x00,                      // pid
                0x00, 0x00,                      // uid
                0x00, 0x00,                      // mid
                0x00,                            // word count
                0xfe, 0xff);                     // byte count
        return concat(b(0x00, 0x00, smb.length >> 8, smb.length & 0xff), smb);
    }

    /** 构造 MSSQL TDS PRELOGIN 请求 */
    static byte[] mssqlPreloginRequest() {
        byte[] payload = b(
                0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20, 0x00, 0x01,
                0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04,
                0x04, 0x00, 0x26, 0x00, 0x01, 0xff);
        int total = 8 + payload.length;
        byte[] header = b(
                0x12,                  // TDS 类型 PRELOGIN
                0x01,                  // 状态 EOM
                total >> 8, total,     // 长度
                0x00, 0x00,            // SPID
                0x01,                  // 包序号
                0x00);                 // 窗口
        return concat(header, payload);
    }

    /** 构造 PostgreSQL StartupMessage (协议 3.0) */
    static byte[] postgresStartupRequest() {
        byte[] payload = "user\u0000jyscan\u0000database\u0000jyscan\u0000\u0000"
                .getBytes(StandardCharsets.ISO_8859_1);
        int total = 4 + 4 + payload.length;
        byte[] p = b(total >> 24, total >> 16, total >> 8, total);
        p = concat(p, b(0x00, 0x03, 0x00, 0x00)); // 协议版本 196608 (3.0)
        return concat(p, payload);
    }

    /** 构造 MongoDB isMaster 探测 (legacy OP_QUERY) */
    static byte[] mongoIsMasterRequest() {
        return b(
                0x3a, 0x00, 0x00, 0x00,       // messageLength = 58
                0x01, 0x00, 0x00, 0x00,       // requestID = 1
                0x00, 0x00, 0x00, 0x00,       // responseTo = 0
                0xd4, 0x07, 0x00, 0x00,       // opCode = 2004 (OP_QUERY)
                0x00, 0x00, 0x00, 0x00,       // flags
                'a', 'd', 'm', 'i', 'n', '.', '$', 'c', 'm', 'd', 0x00, // 集合名
                0x00, 0x00, 0x00, 0x00,       // numberToSkip
                0xff, 0xff, 0xff, 0xff,       // numberToReturn
                0x13, 0x00, 0x00, 0x00,       // 查询文档长度 = 19
                0x10,                         // int32 类型
                'i', 's', 'm', 'a', 's', 't', 'e', 'r', 0x00, // "ismaster"
                0x01, 0x00, 0x00, 0x00,       // 值 = 1
                0x00);                        // 文档结束
    }

    /** 构造 RDP X.224 连接请求 */
    static byte[] rdpConnectionRequest() {
        return b(
                0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00);
    }

    /** 构造 LDAP 匿名 Bind 请求 */
    static byte[] ldapBindRequest() {
        return b(
                0x30, 0x0c,       // LDAPMessage (SEQUENCE)
                0x02, 0x01, 0x01, // messageID = 1
                0x60, 0x07,       // bindRequest
                0x02, 0x01, 0x03, // version = 3
                0x04, 0x00,       // 空 DN
                0x80, 0x00);      // 简单认证 (空密码)
    }

    /** 构造 DCE/RPC Bind PDU (Endpoint Mapper 抽象语法) */
    static byte[] dceRPCBindRequest() {
        // e1af8308-5d1f-11c9-91a4-08002b14a0fa (Endpoint Mapper)
        byte[] epmUUID = b(
                0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
                0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa);
        // 8a885d04-1ceb-11c9-9fe8-08002b104860 (NDR 32-bit)
        byte[] ndrUUID = b(
                0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
                0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60);
        byte[] p = b(
                0x05, 0x00,          // 版本 5.0
                0x0b,                // PDU 类型: BIND
                0x03,                // flags: first + last fragment
                0x10,                // 数据表示: 小端
                0x00, 0x00,          // fragment length (稍后回填)
                0x00, 0x00,          // auth length
                0x01, 0x00, 0x00, 0x00, // call id
                0xb8, 0x10,          // max xmit frag
                0xb8, 0x10,          // max recv frag
                0x00, 0x00, 0x00, 0x00, // assoc group
                0x01,                // context 数量
                0x00,                // 保留
                0x00, 0x00,          // 保留
                0x00, 0x00,          // context id
                0x01,                // transfer syntax 数量
                0x00);               // 保留
        p = concat(p, epmUUID);
        p = concat(p, b(0x02, 0x00, 0x00, 0x00)); // 抽象语法版本
        p = concat(p, ndrUUID);
        p = concat(p, b(0x02, 0x00, 0x00, 0x00)); // 传输语法版本
        p[8] = (byte) (p.length >> 8);            // fragment length 回填
        p[9] = (byte) p.length;
        return p;
    }

    /** 构造 DNS version.bind CH TXT 查询 (TCP 长度前缀) */
    static byte[] dnsVersionBindQuery() {
        byte[] name = b(7, 'v', 'e', 'r', 's', 'i', 'o', 'n', 4, 'b', 'i', 'n', 'd', 0);
        byte[] q = b(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
        q = concat(q, name);
        q = concat(q, b(0x00, 0x10, 0x00, 0x03)); // QTYPE=TXT, QCLASS=CHAOS
        return concat(b(q.length >> 8, q.length), q);
    }

    /** 构造 RPC over TCP CALL 请求 (含 4 字节记录标记) */
    static byte[] rpcCallRequest(long prog, long vers, long proc) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        writeBE(body, 1);        // xid
        writeBE(body, 0);        // CALL
        writeBE(body, 2);        // RPC 版本
        writeBE(body, prog);     // 程序号
        writeBE(body, vers);     // 版本
        writeBE(body, proc);     // 过程号
        writeBE(body, 0);        // cred flavor
        writeBE(body, 0);        // cred length
        writeBE(body, 0);        // verf flavor
        writeBE(body, 0);        // verf length

        int length = body.size();
        byte[] mark = b(0x80 | (length >> 24), length >> 16, length >> 8, length);
        return concat(mark, body.toByteArray());
    }

    private static void writeBE(ByteArrayOutputStream out, long v) {
        out.write((int) (v >> 24));
        out.write((int) (v >> 16));
        out.write((int) (v >> 8));
        out.write((int) v);
    }

    /** 构造 Java RMI 传输层握手 */
    static byte[] javaRMIHandshake() {
        return b('J', 'R', 'M', 'I', 0x00, 0x02, 0x4b);
    }

    /**
     * 构造 Oracle TNS CONNECT 探测包 (best-effort)。
     * 即使 CONNECT_DATA 不被接受，Oracle 通常也会返回带原因说明的 TNS 错误包，
     * 该内容正是我们想看到的信息。
     */
    static byte[] oracleTNSConnectRequest() {
        byte[] connectData = ("(DESCRIPTION=(CONNECT_DATA=(COMMAND=version))"
                + "(ADDRESS=(PROTOCOL=TCP)(HOST=jyscan)(PORT=1521)))")
                .getBytes(StandardCharsets.UTF_8);
        byte[] p = b(
                0x00, 0x00,       // [0-1]  数据包长度
                0x00, 0x00,       // [2-3]  校验和
                0x01,             // [4]    包类型 CONNECT
                0x00,             // [5]    保留
                0x00, 0x00,       // [6-7]  头校验和
                0x01, 0x36,       // [8-9]  版本
                0x01, 0x2c,       // [10-11] 兼容版本
                0x00, 0x00,       // [12-13] 服务选项
                0x08, 0x00,       // [14-15] 会话数据单元
                0x7f, 0xff,       // [16-17] 最大传输数据单元
                0x7f, 0x08,       // [18-19] NT 协议特性
                0x00, 0x00,       // [20-21] 线路切换
                0x01, 0x00,       // [22-23] 硬件
                0x00, 0x1d,       // [24-25] 兼容 1
                0x00, 0x3a,       // [26-27] 兼容 2
                0x00, 0x00, 0x00, 0x00, // [28-31] 最大接收连接数据
                0x00, 0x00,       // [32-33] 连接数据长度
                0x00, 0x00);      // [34-35] 连接数据偏移
        int total = p.length + connectData.length;
        p[0] = (byte) (total >> 8);
        p[1] = (byte) total;
        p[32] = (byte) (connectData.length >> 8);
        p[33] = (byte) connectData.length;
        p[34] = (byte) (p.length >> 8);
        p[35] = (byte) p.length;
        return concat(p, connectData);
    }

    // =====================================================================
    // 协议探测器注册表
    //
    // 每个协议可包含多个探测器，按顺序执行：
    //   1. 被动读取服务主动返回的 banner (build 为 null)
    //   2. 发送协议特征请求并校验回复特征
    // 命中即返回该协议的服务回复内容。
    // =====================================================================

    static Map<String, ContentProbeSpec[]> contentProbeRegistry() {
        Map<String, ContentProbeSpec[]> registry = new HashMap<>();

        // ---- 通用兜底 ----
        registry.put("raw", new ContentProbeSpec[]{
                new ContentProbeSpec("tcp-banner", "raw", null, false, null)});
        registry.put("http", new ContentProbeSpec[]{
                new ContentProbeSpec("http-get", "http", ContentProbe::httpProbeRequest, false,
                        replyHasPrefix("HTTP/"))});
        registry.put("https", new ContentProbeSpec[]{
                new ContentProbeSpec("https-get", "https", ContentProbe::httpProbeRequest, true,
                        replyHasPrefix("HTTP/")),
                new ContentProbeSpec("tls-banner", "tls", null, true, null)});
        registry.put("tls-raw", new ContentProbeSpec[]{
                new ContentProbeSpec("tls-banner", "tls", null, true, null)});

        // ---- 文件传输 ----
        registry.put("ftp", new ContentProbeSpec[]{
                new ContentProbeSpec("ftp-banner", "ftp", null, false, replyHasPrefix("220")),
                new ContentProbeSpec("ftp-feat", "ftp", staticRequest("FEAT\r\n"), false,
                        replyHasPrefix("211")),
                new ContentProbeSpec("ftp-syst", "ftp", staticRequest("SYST\r\n"), false,
                        replyHasPrefix("215"))});
        registry.put("ftps", new ContentProbeSpec[]{
                new ContentProbeSpec("ftps-banner", "ftps", null, true, replyHasPrefix("220")),
                new ContentProbeSpec("ftps-feat", "ftps", staticRequest("FEAT\r\n"), true,
                        replyHasPrefix("211"))});
        registry.put("rsync", new ContentProbeSpec[]{
                new ContentProbeSpec("rsync-banner", "rsync", null, false,
                        replyHasPrefix("@RSYNCD:"))});
        registry.put("git", new ContentProbeSpec[]{
                new ContentProbeSpec("git-upload-pack", "git", ContentProbe::gitUploadPackRequest,
                        false, replyContainsAny("git-upload-pack", "# service="))});

        // ---- 邮件 ----
        registry.put("smtp", new ContentProbeSpec[]{
                new ContentProbeSpec("smtp-banner", "smtp", null, false, replyHasPrefix("220")),
                new ContentProbeSpec("smtp-ehlo", "smtp", staticRequest("EHLO jyscan.local\r\n"),
                        false, replyHasPrefix("250"))});
        registry.put("smtps", new ContentProbeSpec[]{
                new ContentProbeSpec("smtps-banner", "smtps", null, true, replyHasPrefix("220")),
                new ContentProbeSpec("smtps-ehlo", "smtps", staticRequest("EHLO jyscan.local\r\n"),
                        true, replyHasPrefix("250"))});
        registry.put("pop3", new ContentProbeSpec[]{
                new ContentProbeSpec("pop3-banner", "pop3", null, false, replyHasPrefix("+OK")),
                new ContentProbeSpec("pop3-capa", "pop3", staticRequest("CAPA\r\n"), false,
                        replyContainsAny("+OK", "CAPA"))});
        registry.put("pop3s", new ContentProbeSpec[]{
                new ContentProbeSpec("pop3s-banner", "pop3s", null, true, replyHasPrefix("+OK")),
                new ContentProbeSpec("pop3s-capa", "pop3s", staticRequest("CAPA\r\n"), true,
                        replyContainsAny("+OK", "CAPA"))});
        registry.put("imap", new ContentProbeSpec[]{
                new ContentProbeSpec("imap-banner", "imap", null, false, replyHasPrefix("* OK")),
                new ContentProbeSpec("imap-capability", "imap", staticRequest("a1 CAPABILITY\r\n"),
                        false, replyContainsAny("* CAPABILITY", "* OK", "* PREAUTH", "* BYE"))});
        registry.put("imaps", new ContentProbeSpec[]{
                new ContentProbeSpec("imaps-banner", "imaps", null, true, replyHasPrefix("* OK")),
                new ContentProbeSpec("imaps-capability", "imaps",
                        staticRequest("a1 CAPABILITY\r\n"), true,
                        replyContainsAny("* CAPABILITY", "* OK", "* PREAUTH", "* BYE"))});
        registry.put("nntp", new ContentProbeSpec[]{
                new ContentProbeSpec("nntp-banner", "nntp", null, false,
                        replyContainsAny("200 ", "201 ")),
                new ContentProbeSpec("nntp-list", "nntp", staticRequest("LIST\r\n"), false,
                        replyHasPrefix("215"))});

        // ---- 远程登录 ----
        registry.put("ssh", new ContentProbeSpec[]{
                new ContentProbeSpec("ssh-banner", "ssh", null, false, replyContains("SSH-"))});
        registry.put("telnet", new ContentProbeSpec[]{
                new ContentProbeSpec("telnet-banner", "telnet", null, false, null),
                new ContentProbeSpec("telnet-negotiation", "telnet",
                        (host, port) -> telnetNegotiationRequest(), false, null)});

        // ---- 数据库与缓存 ----
        registry.put("mysql", new ContentProbeSpec[]{
                new ContentProbeSpec("mysql-handshake", "mysql", null, false,
                        replyAny(replyContainsAny("mysql", "mariadb"),
                                replyFirstByteIn(0x0a)))});
        registry.put("mssql", new ContentProbeSpec[]{
                new ContentProbeSpec("mssql-prelogin", "mssql",
                        (host, port) -> mssqlPreloginRequest(), false,
                        replyFirstByteIn(0x04, 0x12))});
        registry.put("postgres", new ContentProbeSpec[]{
                new ContentProbeSpec("postgres-sslrequest", "postgres",
                        staticRequest("\u0000\u0000\u0000\u0008\u0004\u00d2\u0016\u002f"), false,
                        replyFirstByteIn('S', 'N')),
                new ContentProbeSpec("postgres-startup", "postgres",
                        (host, port) -> postgresStartupRequest(), false,
                        replyFirstByteIn('R', 'E'))});
        registry.put("mongodb", new ContentProbeSpec[]{
                new ContentProbeSpec("mongodb-ismaster", "mongodb",
                        (host, port) -> mongoIsMasterRequest(), false,
                        replyContainsAny("ismaster", "maxBsonObjectSize", "topologyVersion"))});
        registry.put("redis", new ContentProbeSpec[]{
                new ContentProbeSpec("redis-ping", "redis", staticRequest("PING\r\n"), false,
                        replyContainsAny("+PONG", "-NOAUTH", "-ERR", "-DENIED")),
                new ContentProbeSpec("redis-info", "redis", staticRequest("INFO server\r\n"),
                        false, replyContainsAny("redis_version", "# Server"))});
        registry.put("memcached", new ContentProbeSpec[]{
                new ContentProbeSpec("memcached-stats", "memcached", staticRequest("stats\r\n"),
                        false, replyHasPrefix("STAT "))});
        registry.put("oracle", new ContentProbeSpec[]{
                new ContentProbeSpec("oracle-tns-connect", "oracle",
                        (host, port) -> oracleTNSConnectRequest(), false, null)});

        // ---- 远程桌面 / 图形 ----
        registry.put("rdp", new ContentProbeSpec[]{
                new ContentProbeSpec("rdp-connection", "rdp",
                        (host, port) -> rdpConnectionRequest(), false,
                        replyStartsWithBytes(0x03, 0x00))});
        registry.put("vnc", new ContentProbeSpec[]{
                new ContentProbeSpec("vnc-banner", "vnc", null, false, replyHasPrefix("RFB "))});

        // ---- 目录 / 共享 ----
        registry.put("smb", new ContentProbeSpec[]{
                new ContentProbeSpec("smb-negotiate", "smb",
                        (host, port) -> smbNegotiateRequest(), false,
                        replyAny(replyContains("\u00ffSMB"), replyContains("\u00feSMB")))});
        registry.put("ldap", new ContentProbeSpec[]{
                new ContentProbeSpec("ldap-anonymous-bind", "ldap",
                        (host, port) -> ldapBindRequest(), false, replyByteExists(0x61))});
        registry.put("ldaps", new ContentProbeSpec[]{
                new ContentProbeSpec("ldaps-anonymous-bind", "ldaps",
                        (host, port) -> ldapBindRequest(), true, replyByteExists(0x61))});
        registry.put("dcerpc", new ContentProbeSpec[]{
                new ContentProbeSpec("dcerpc-bind", "dcerpc",
                        (host, port) -> dceRPCBindRequest(), false, replyByteAt(2, 0x0c))});
        registry.put("nfs", new ContentProbeSpec[]{
                new ContentProbeSpec("nfs-null", "nfs",
                        (host, port) -> rpcCallRequest(100003, 3, 0), false, replyMinLen(8))});
        registry.put("rpcbind", new ContentProbeSpec[]{
                new ContentProbeSpec("rpcbind-dump", "rpcbind",
                        (host, port) -> rpcCallRequest(100000, 2, 4), false, replyMinLen(8))});

        // ---- 消息 / 中间件 ----
        registry.put("amqp", new ContentProbeSpec[]{
                new ContentProbeSpec("amqp-banner", "amqp", null, false, replyHasPrefix("AMQP"))});
        registry.put("zookeeper", new ContentProbeSpec[]{
                new ContentProbeSpec("zookeeper-ruok", "zookeeper", staticRequest("ruok"), false,
                        replyContainsAny("imok", "not running")),
                new ContentProbeSpec("zookeeper-srvr", "zookeeper", staticRequest("srvr\r\n"),
                        false, replyContainsAny("zookeeper version", "mode:", "latency"))});
        registry.put("mqtt", new ContentProbeSpec[]{
                new ContentProbeSpec("mqtt-connect", "mqtt",
                        (host, port) -> mqttConnectRequest(), false,
                        replyStartsWithBytes(0x20))});
        registry.put("stomp", new ContentProbeSpec[]{
                new ContentProbeSpec("stomp-connect", "stomp",
                        (host, port) -> stompConnectRequest(), false,
                        replyContainsAny("CONNECTED", "ERROR", "version:"))});
        registry.put("kafka", new ContentProbeSpec[]{
                new ContentProbeSpec("kafka-apiversions", "kafka",
                        staticRequest("\u0000\u0000\u0000\u0010\u0000\u0012\u0000\u0000\u0000"
                                + "\u0000\u0000\u0001\u0000\u0006jyscan"),
                        false, replyMinLen(8))});

        // ---- Web / 应用服务 ----
        registry.put("ajp13", new ContentProbeSpec[]{
                new ContentProbeSpec("ajp-forward", "ajp13", ContentProbe::ajpForwardRequest,
                        false, replyStartsWithBytes('A', 'B'))});
        registry.put("dns", new ContentProbeSpec[]{
                new ContentProbeSpec("dns-version-bind", "dns",
                        (host, port) -> dnsVersionBindQuery(), false, replyContains("version"))});
        registry.put("sip", new ContentProbeSpec[]{
                new ContentProbeSpec("sip-options", "sip", ContentProbe::sipOptionsRequest, false,
                        replyHasPrefix("SIP/2.0"))});
        registry.put("rtsp", new ContentProbeSpec[]{
                new ContentProbeSpec("rtsp-options", "rtsp", ContentProbe::rtspOptionsRequest,
                        false, replyHasPrefix("RTSP/1.0"))});
        registry.put("irc", new ContentProbeSpec[]{
                new ContentProbeSpec("irc-register", "irc",
                        (host, port) -> ircRegistrationRequest(), false,
                        replyContainsAny("NOTICE", " 001 ", "AUTH", "PRIVMSG", "ERROR"))});
        registry.put("xmpp", new ContentProbeSpec[]{
                new ContentProbeSpec("xmpp-stream", "xmpp", ContentProbe::xmppStreamRequest,
                        false, replyContainsAny("<?xml", "stream:", "<stream"))});
        registry.put("socks5", new ContentProbeSpec[]{
                new ContentProbeSpec("socks5-greeting", "socks5",
                        (host, port) -> socks5Greeting(), false, replyStartsWithBytes(0x05))});
        registry.put("java-rmi", new ContentProbeSpec[]{
                new ContentProbeSpec("java-rmi-handshake", "java-rmi",
                        (host, port) -> javaRMIHandshake(), false,
                        replyStartsWithBytes('J', 'R', 'M', 'I'))});
        registry.put("zabbix", new ContentProbeSpec[]{
                new ContentProbeSpec("zabbix-agent", "zabbix",
                        (host, port) -> zabbixAgentRequest(), false, replyHasPrefix("ZBXD"))});
        registry.put("whois", new ContentProbeSpec[]{
                new ContentProbeSpec("whois-query", "whois", staticRequest("jyscan\r\n"),
                        false, null)});

        return registry;
    }

    /** 协议探测器注册表，对应 Go {@code contentProbeRegistry}（47 个协议组 / 62 个探测器）。 */
    static final Map<String, ContentProbeSpec[]> CONTENT_PROBE_REGISTRY = contentProbeRegistry();

    // =====================================================================
    // 协议 / 探测器解析
    // =====================================================================

    /**
     * 根据端口服务名与端口号解析候选探测协议，
     * 按优先级返回：服务名线索 &gt; 端口线索 &gt; 端口集合 &gt; 通用兜底 (raw/http/https)。
     *
     * <p>服务名线索按 {@link #SERVICE_PROBE_HINTS} 的顺序「先命中优先」：一旦命中即停止继续匹配，
     * 避免 https 同时命中 http、imaps 同时命中 imap 这类前缀包含关系，
     * 从而不再为 TLS 服务重复安排明文协议的探测。
     *
     * <p>对应 Go 的 {@code resolveContentProbeProtocols(info PortInfo) []string}。
     */
    static List<String> resolveContentProbeProtocols(PortInfo info) {
        List<String> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        String svc = str(info.service).toLowerCase(Locale.ROOT);
        svc = goTrimSpace(svc).toLowerCase(Locale.ROOT);
        if (!svc.isEmpty()) {
            for (ServiceHint hint : SERVICE_PROBE_HINTS) {
                if (svc.contains(hint.keyword)) {
                    for (String p : hint.protocols) {
                        if (!p.isEmpty() && seen.add(p)) {
                            out.add(p);
                        }
                    }
                    break; // 先命中优先，避免 TLS 变体再叠加明文协议
                }
            }
        }

        String[] portHint = PORT_PROBE_HINTS.get(info.port);
        if (portHint != null) {
            for (String p : portHint) {
                if (!p.isEmpty() && seen.add(p)) {
                    out.add(p);
                }
            }
        }
        if (TLS_RAW_PROBE_PORTS.contains(info.port)) {
            if (seen.add("tls-raw")) {
                out.add("tls-raw");
            }
        }
        if (TLS_WEB_PROBE_PORTS.contains(info.port)) {
            // HTTPS 端口上也可能跑非 HTTP 的 TLS 服务，故补充 tls-raw 兜底，
            // 保证 HTTP 请求失败时仍能拿到 TLS 服务的回复内容。
            // 另外在末尾加入 plain HTTP 作为最终兜底：当 TLS 握手/SNI 探测全部失败时，
            // 仍能拿到服务器的最低应答（例如 "400 Bad Request"），
            // 避免因为 TLS 全失败而得到空内容。
            for (String p : new String[]{"https", "tls-raw", "http"}) {
                if (seen.add(p)) {
                    out.add(p);
                }
            }
        }
        if (WEB_PROBE_PORTS.contains(info.port) && seen.add("http")) {
            out.add("http");
        }

        // 兜底顺序：先被动读取 banner，再试明文 HTTP，最后试 TLS。
        // 已知的 TLS 端口 (HTTPS/IMAPS/SMTPS/...) 不再回退明文 HTTP：
        // 向该类端口发送明文请求只会得到 "plain HTTP request was sent to HTTPS port"
        // 之类的协议错误，属于误导性结果。
        if (seen.add("raw")) {
            out.add("raw");
        }
        if (!tlsOnlyProbePort(info.port) && seen.add("http")) {
            out.add("http");
        }
        if (seen.add("https")) {
            out.add("https");
        }
        return out;
    }

    /** 判断端口是否为已知的 TLS 端口 (HTTPS/IMAPS/SMTPS/...)，对应 Go {@code tlsOnlyProbePort}。 */
    static boolean tlsOnlyProbePort(int port) {
        return TLS_WEB_PROBE_PORTS.contains(port) || TLS_RAW_PROBE_PORTS.contains(port);
    }

    /**
     * 将候选协议展开为最终要执行的探测器列表：
     * <ol>
     *   <li>去重：不同协议组可能包含同一探测器 (如 https 与 tls-raw 都含 tls-banner)，
     *       同一探测器在同一端口只执行一次，避免重复建连与等待；</li>
     *   <li>截断：最多 {@link #CONTENT_PROBE_MAX_ATTEMPTS} 个，控制单个端口的探测噪声与耗时。</li>
     * </ol>
     * 对应 Go 的 {@code resolveContentProbeSpecs(info PortInfo) []contentProbeSpec}。
     */
    static List<ContentProbeSpec> resolveContentProbeSpecs(PortInfo info) {
        List<ContentProbeSpec> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (String protocol : resolveContentProbeProtocols(info)) {
            ContentProbeSpec[] specs = CONTENT_PROBE_REGISTRY.get(protocol);
            if (specs == null) {
                continue;
            }
            for (ContentProbeSpec spec : specs) {
                String key = Fmt.format("%s|%s|%b", spec.name, spec.protocol, spec.useTLS);
                if (!seen.add(key)) {
                    continue;
                }
                out.add(spec);
                if (out.size() >= CONTENT_PROBE_MAX_ATTEMPTS) {
                    return out;
                }
            }
        }
        return out;
    }

    // =====================================================================
    // 主机名 / IP 字面量判定 / 内容指纹
    // =====================================================================

    /**
     * 从扫描目标中提取可用于 TLS SNI / HTTP Host 的主机名。
     * 目标为 IP/CIDR/IP范围/通配时返回空串（此时沿用 IP 作为主机名）。
     * 目标为域名时返回去协议前缀后的裸域名，供内容探测使用以提升 SNI/Host 匹配度。
     *
     * <p>对应 Go 的 {@code contentProbeHostname(target string) string}
     *（内部先调 {@link NmapUtils#removeProtocolPrefix}）。
     */
    static String contentProbeHostname(String target) {
        String host = goTrimSpace(NmapUtils.removeProtocolPrefix(target == null ? "" : target));
        if (host.isEmpty() || isIpLiteral(host)) {
            return "";
        }
        // IP 范围 (192.168.1.1-100) 与通配 (192.168.1.*) 不是可用主机名
        int i = host.indexOf('-');
        if (i > 0 && isIpLiteral(host.substring(0, i))) {
            return "";
        }
        if (host.contains("*")) {
            return "";
        }
        // 仅接受 DNS 主机名允许的字符，避免把异常输入当作 SNI
        for (int j = 0; j < host.length(); j++) {
            char c = host.charAt(j);
            boolean alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            if (!alnum && c != '-' && c != '.' && c != '_') {
                return "";
            }
        }
        return host;
    }

    /**
     * 是否为合法 IP 字面量（对齐 Go {@code net.ParseIP}，且不触发 DNS）。
     * 含冒号的输入只走 IPv6 字面量解析，JDK 对该形态不做域名解析。
     */
    static boolean isIpLiteral(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        if (s.indexOf(':') >= 0) {
            return isIPv6Literal(s);
        }
        return isStrictIPv4(s);
    }

    /** 严格 IPv4 点分校验（对齐 Go {@code net.ParseIP}：拒绝前导零、拒绝 >255）。 */
    static boolean isStrictIPv4(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            if (part.length() > 1 && part.charAt(0) == '0') {
                return false;
            }
            int v = 0;
            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);
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
     * 字符集前置检查先挡住 JDK 接受、Go 拒绝的形态：{@code [::1]}（方括号）、
     * {@code fe80::1%eth0}（zone）；内嵌 IPv4 必须是严格 v4。
     */
    static boolean isIPv6Literal(String s) {
        if (s.isEmpty() || s.length() > 45) {
            return false;
        }
        boolean hasColon = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (hex) {
                continue;
            }
            if (c == ':') {
                hasColon = true;
                continue;
            }
            if (c == '.') {
                continue;
            }
            return false;
        }
        if (!hasColon) {
            return false;
        }
        if (s.indexOf('.') >= 0) {
            int lastColon = s.lastIndexOf(':');
            if (!isStrictIPv4(s.substring(lastColon + 1))) {
                return false;
            }
        }
        try {
            InetAddress.getByName(s);
            return true;
        } catch (UnknownHostException | IllegalArgumentException e) {
            return false;
        } catch (SecurityException e) {
            return false;
        }
    }

    /**
     * 对探测内容做规范化指纹，用于 CDN 跨 IP 去重：
     * <ul>
     *   <li>忽略时间/随机性强的响应头（Date、CF-RAY 等）</li>
     *   <li>忽略请求相关/多 IP 不敏感的头（Host、Connection 等）</li>
     * </ul>
     * 两份内容若指纹相同，则视为同一个"服务应答语义"，来自不同 IP 的重复块会合并显示。
     *
     * <p>对应 Go 的 {@code contentFingerprint(content string) []byte}（sha256）。
     */
    static byte[] contentFingerprint(String content) {
        if (content == null || content.isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (String raw : content.split("\n", -1)) {
            String line = trimRightSpaceTab(raw);
            if (line.isEmpty()) {
                continue;
            }
            String low = asciiLower(line);
            // 忽略时间/随机性强的响应头（CDN 多 IP 场景下常见）
            if (low.startsWith("date:") || low.startsWith("cf-ray:")) {
                continue;
            }
            // 忽略请求相关/多 IP 不敏感的头
            if (low.startsWith("host:") || low.startsWith("connection:")) {
                continue;
            }
            sb.append(line).append('\n');
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            // Go sha256.Sum256([]byte(s)) 取的是字符串底层字节 → latin1 还原字节视图
            return digest.digest(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    /**
     * 返回用于跨 IP 去重的缓存键 {@code "<port>:<sha256hex>"}。
     * 为空串时不入缓存。对应 Go 的 {@code contentDedupKey(port int, content string) string}。
     */
    static String contentDedupKey(int port, String content) {
        byte[] fp = contentFingerprint(content);
        if (fp == null || fp.length == 0) {
            return "";
        }
        return Fmt.format("%d:%s", port, hexLower(fp));
    }

    /** 跨 IP 内容去重缓存（包级别，本次扫描周期内有效），对应 Go 的 {@code contentProbeDedupMap}。 */
    static final ConcurrentHashMap<String, ContentDedupEntry> CONTENT_PROBE_DEDUP_MAP =
            new ConcurrentHashMap<>();

    /** 内容探测输出互斥锁，避免多主机并发扫描时输出交错（对应 Go {@code contentProbePrintMu}）。 */
    static final Object CONTENT_PROBE_PRINT_LOCK = new Object();

    // =====================================================================
    // 探测执行引擎
    // =====================================================================

    /**
     * 执行单个探测器，返回服务回复的原始内容（latin1 字节视图）。
     * {@code ip} 用于建立连接，{@code host} 为协议载荷中使用的主机名 (HTTP Host / TLS SNI 等)；
     * {@code host} 为空时退化为 {@code ip}。目标为域名时传入真实主机名，可避免共享 IP
     * (CDN 等) 因缺少 SNI/Host 而拒绝握手或返回默认站点内容。
     *
     * <p>对应 Go 的 {@code execProbeSpec(ip, host string, port int, spec contentProbeSpec,
     * timeout time.Duration) string}。
     */
    static String execProbeSpec(String ip, String host, int port, ContentProbeSpec spec,
                                Duration timeout) {
        String h = (host == null || host.isEmpty()) ? ip : host;

        Socket conn;
        try {
            conn = spec.useTLS
                    ? dialTls(ip, h, port, timeout)
                    : dialPlain(ip, port, timeout);
        } catch (IOException | RuntimeException e) {
            return "";
        }

        try {
            if (spec.build != null) {
                byte[] request = spec.build.build(h, port);
                if (request.length > 0) {
                    try {
                        // Go: conn.SetWriteDeadline(time.Now().Add(timeout)) —— Java Socket 无写超时
                        OutputStream os = conn.getOutputStream();
                        os.write(request);
                        os.flush();
                    } catch (IOException e) {
                        return "";
                    }
                }
            }

            Duration readTimeout = timeout;
            if (spec.build == null && readTimeout.compareTo(CONTENT_PROBE_PASSIVE_READ_TIMEOUT) > 0) {
                // 被动读取时服务通常立即返回 banner，无需等待完整超时
                readTimeout = CONTENT_PROBE_PASSIVE_READ_TIMEOUT;
            }
            return readConnContent(conn, readTimeout);
        } finally {
            closeQuiet(conn);
        }
    }

    /** 明文 TCP 连接（对应 Go {@code dialer.Dial("tcp", ...)}）。 */
    static Socket dialPlain(String ip, int port, Duration timeout) throws IOException {
        Socket sock = new Socket();
        try {
            sock.connect(new InetSocketAddress(ip, port), ceilMs(timeout));
            return sock;
        } catch (IOException | RuntimeException e) {
            closeQuiet(sock);
            if (e instanceof IOException io) {
                throw io;
            }
            throw new IOException("connect " + ip + ":" + port + " failed", e);
        }
    }

    /**
     * 信任所有证书的 TrustManager，等价 Go {@code InsecureSkipVerify: true}。
     * 复用 SslScanner 的模式（自建 SSLContext，避免修改共享状态）。
     */
    private static final X509TrustManager TRUST_ALL = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // 不校验证书链（与 Go 的 InsecureSkipVerify 行为一致）
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // 不校验证书链（与 Go 的 InsecureSkipVerify 行为一致）
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };

    /** 惰性构建信任所有证书的 SSLContext（等价 Go tls.Config{InsecureSkipVerify: true}）。 */
    static SSLContext trustAllContext() throws IOException {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{TRUST_ALL}, null);
            return ctx;
        } catch (Exception e) {
            throw new IOException("init tls context failed", e);
        }
    }

    /**
     * 建立 TLS 连接并完成握手：先 TCP 连接（超时 = timeout），再 JSSE 握手
     * （受 SoTimeout 约束），关闭端点标识（主机名校验）。
     *
     * <p>SNI：显式 {@code setServerNames}（已实测 JDK 不会自动从 peerHost 发送 SNI）；
     * {@code host} 为 IP 字面量时不发（等价 Go {@code hostnameInSNI}）；
     * 下划线等 JSSE 拒绝的主机名省略 SNI（偏差已记录于类注释）。
     */
    static Socket dialTls(String ip, String host, int port, Duration timeout) throws IOException {
        int timeoutMs = ceilMs(timeout);
        SSLContext ctx = trustAllContext();

        Socket plain = new Socket();
        SSLSocket tls = null;
        boolean ok = false;
        try {
            plain.connect(new InetSocketAddress(ip, port), timeoutMs);
            plain.setSoTimeout(timeoutMs);
            // 第二个参数 ip 作为 peerHost（仅用于记录，SNI 由下面显式设置）
            tls = (SSLSocket) ctx.getSocketFactory().createSocket(plain, ip, port, true);
            tls.setUseClientMode(true);
            SSLParameters params = tls.getSSLParameters();
            // 关闭端点标识（主机名校验），配合 TRUST_ALL 等价 InsecureSkipVerify
            params.setEndpointIdentificationAlgorithm(null);
            if (host != null && !host.isEmpty() && !isIpLiteral(host)) {
                try {
                    params.setServerNames(java.util.List.of(new SNIHostName(host)));
                } catch (IllegalArgumentException e) {
                    // JSSE 拒绝的 SNI 主机名（如下划线）：省略 SNI，其余照常握手
                }
            }
            tls.setSSLParameters(params);
            tls.startHandshake();
            ok = true;
            return tls;
        } catch (IOException | RuntimeException e) {
            if (e instanceof IOException io) {
                throw io;
            }
            throw new IOException("tls handshake " + ip + ":" + port + " failed", e);
        } finally {
            if (!ok) {
                if (tls != null) {
                    // autoClose=true，关闭 TLS 套接字会连带关闭底层 socket
                    closeQuiet(tls);
                } else {
                    closeQuiet(plain);
                }
            }
        }
    }

    /**
     * 读取连接返回的内容，直到超时、EOF 或达到大小上限，返回 latin1 字节视图。
     *
     * <p>截止时间是绝对的（对齐 Go 的单次 {@code SetReadDeadline(now+timeout)}），
     * 每轮读取按剩余时间向上取整设置 SoTimeout。Go 的 {@code sync.Pool} 读缓冲
     * 不移植，每次调用分配 4KB。
     */
    static String readConnContent(Socket conn, Duration timeout) {
        long deadline = System.nanoTime() + (timeout.isNegative() ? 0 : timeout.toNanos());
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[4096];
        try {
            while (buf.size() < CONTENT_PROBE_MAX_BYTES) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    break;
                }
                long ms = (remaining + 999_999L) / 1_000_000L;
                conn.setSoTimeout((int) Math.min(ms, Integer.MAX_VALUE));
                int n = conn.getInputStream().read(tmp);
                if (n < 0) {
                    break;
                }
                if (n > 0) {
                    buf.write(tmp, 0, n);
                }
            }
        } catch (IOException e) {
            // Go：Read 出错即 break，返回已读到的内容
        }
        return buf.toString(StandardCharsets.ISO_8859_1);
    }

    // =====================================================================
    // 单端口内容探测
    // =====================================================================

    /**
     * 对单个开放端口执行内容探测 (以 IP 作为协议载荷中的主机名)。
     * 按 {@link #resolveContentProbeSpecs} 给出的顺序 (已去重并截断) 依次探测，
     * 命中即返回对应协议与回复内容；若所有探测器均未命中，
     * 则返回首个非空回复 (通常已足以判断服务)。
     *
     * <p>对应 Go 的 {@code ProbePortContent(ip string, info PortInfo,
     * timeout time.Duration) ContentProbeResult}。
     *
     * @return 探测结果；无任何回复时为零值结果（空串内容）
     */
    public static ContentProbeResult probePortContent(String ip,
                                                      PortInfo info,
                                                      Duration timeout) {
        return probePortContent(ip, ip, info, timeout);
    }

    /**
     * 内容探测内部实现。
     * {@code ip} 用于建立连接，{@code host} 为协议载荷中使用的主机名 (HTTP Host / TLS SNI)，
     * 目标为域名时传入真实域名可获得站点真实内容 (CDN/共享 IP 场景尤为重要)。
     *
     * <p>对应 Go 的 {@code probePortContent(ip, host string, info PortInfo,
     * timeout time.Duration) ContentProbeResult}。
     */
    public static ContentProbeResult probePortContent(String ip, String host, PortInfo info,
                                                      Duration timeout) {
        Duration t = timeout;
        if (t == null || t.isZero() || t.isNegative()) {
            t = CONTENT_PROBE_DEFAULT_TIMEOUT;
        }

        List<ContentProbeSpec> specs = resolveContentProbeSpecs(info);
        if (specs.isEmpty()) {
            return new ContentProbeResult();
        }

        ContentProbeResult fallback = new ContentProbeResult();
        for (ContentProbeSpec spec : specs) {
            String reply = execProbeSpec(ip, host, info.port, spec, t);
            if (reply.isEmpty()) {
                continue;
            }
            if (spec.match == null || spec.match.matches(reply)) {
                return new ContentProbeResult(spec.protocol, spec.name, reply);
            }
            if (fallback.content.isEmpty()) {
                fallback = new ContentProbeResult("unknown", spec.name, reply);
            }
        }

        return fallback;
    }

    // =====================================================================
    // 内容展示格式化
    // =====================================================================

    /**
     * 把 latin1 字节视图还原文本（对应 Go 对 string 直接 {@code range} 的逐 rune 解码）。
     *
     * <p>手写解码以逐字节复刻 Go {@code utf8.DecodeRune} 的判定（overlong、代理区、
     * 越界、非法序列均与 JDK 默认解码器的替换粒度不同）：合法序列消费对应字节数并产出
     * 真实 rune；非法字节产出 U+FFFD 且<b>只前进 1 字节</b>（Go 对坏序列逐字节产出
     * RuneError 的行为）。
     */
    static String decodeViewUtf8(String view) {
        byte[] b = new byte[view.length()];
        for (int i = 0; i < view.length(); i++) {
            b[i] = (byte) view.charAt(i);
        }
        StringBuilder sb = new StringBuilder(b.length);
        int i = 0;
        while (i < b.length) {
            int x = b[i] & 0xff;
            if (x <= 0x7f) {
                sb.append((char) x);
                i++;
                continue;
            }
            int n = 0;      // 序列总字节数
            int cp = 0;
            if (x >= 0xc2 && x <= 0xdf) {
                n = 2;
                cp = x & 0x1f;
            } else if (x >= 0xe0 && x <= 0xef) {
                n = 3;
                cp = x & 0x0f;
            } else if (x >= 0xf0 && x <= 0xf4) {
                n = 4;
                cp = x & 0x07;
            } else {
                sb.append('�');
                i++;
                continue;
            }
            if (i + n > b.length) {
                sb.append('�');
                i++;
                continue;
            }
            boolean ok = true;
            for (int j = 1; j < n; j++) {
                int t = b[i + j] & 0xff;
                if (t < 0x80 || t > 0xbf) {
                    ok = false;
                    break;
                }
                cp = (cp << 6) | (t & 0x3f);
            }
            // Go 的额外范围约束（overlong / 代理区 / > U+10FFFF）
            if (ok) {
                if ((n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000)
                        || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
                    ok = false;
                }
            }
            if (!ok) {
                sb.append('�');
                i++;
                continue;
            }
            sb.appendCodePoint(cp);
            i += n;
        }
        return sb.toString();
    }

    /** Go {@code len([]rune(s))}。 */
    static int runeCount(String s) {
        return s == null ? 0 : s.codePointCount(0, s.length());
    }

    /** Go {@code string(runes[:n])}：取前 n 个 rune。 */
    static String runeSubstring(String s, int n) {
        int i = 0;
        int count = 0;
        while (i < s.length() && count < n) {
            i += Character.charCount(s.codePointAt(i));
            count++;
        }
        return s.substring(0, i);
    }

    /** 判断内容是否以二进制为主，对应 Go {@code isBinaryContent}。 */
    static boolean isBinaryContent(String content) {
        if (content == null || content.isEmpty()) {
            return false;
        }
        int nonPrintable = 0;
        int total = 0;
        for (int i = 0; i < content.length(); i++) {
            char b = content.charAt(i);
            if (b == '\n' || b == '\r' || b == '\t') {
                continue;
            }
            total++;
            if (b < 0x20 || b > 0x7e) {
                nonPrintable++;
            }
        }
        if (total == 0) {
            return false;
        }
        return (double) nonPrintable / (double) total > CONTENT_PROBE_BINARY_RATIO;
    }

    /** 将原始响应内容转换为适合终端展示的文本，对应 Go {@code formatContentForDisplay}。 */
    static String formatContentForDisplay(String content) {
        if (content == null || content.isEmpty()) {
            return "(无响应内容)";
        }
        if (isBinaryContent(content)) {
            return formatBinaryContentForDisplay(content);
        }
        return formatTextContentForDisplay(content);
    }

    /** 文本内容：统一换行、过滤控制字符并限制长度，对应 Go {@code formatTextContentForDisplay}。 */
    static String formatTextContentForDisplay(String content) {
        // 统一换行符（先按字节视图做，再按 rune 过滤，与 Go 顺序一致）
        String s = content.replace("\r\n", "\n").replace("\r", "\n");
        s = decodeViewUtf8(s);

        // 过滤不可见控制字符，保留换行与制表符
        StringBuilder filtered = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            if (cp == '\n' || cp == '\t') {
                filtered.appendCodePoint(cp);
            } else if (cp >= 0x20 && cp != 0x7f) {
                filtered.appendCodePoint(cp);
            } else {
                filtered.append('.');
            }
        }

        String[] lines = filtered.toString().split("\n", -1);
        // 去除末尾空行
        int end = lines.length;
        while (end > 0 && goTrimSpace(lines[end - 1]).isEmpty()) {
            end--;
        }

        boolean truncated = false;
        if (CONTENT_PROBE_MAX_DISPLAY_LINES > 0 && end > CONTENT_PROBE_MAX_DISPLAY_LINES) {
            end = CONTENT_PROBE_MAX_DISPLAY_LINES;
            truncated = true;
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < end; i++) {
            if (i > 0) {
                sb.append('\n');
            }
            sb.append(lines[i]);
        }
        String out = sb.toString();
        if (runeCount(out) > CONTENT_PROBE_MAX_DISPLAY_BYTES) {
            out = runeSubstring(out, CONTENT_PROBE_MAX_DISPLAY_BYTES);
            truncated = true;
        }
        if (truncated) {
            out += "\n[... 内容过长，已截断 ...]";
        }
        return out;
    }

    /** 二进制内容：先提取可读字符串，再给出十六进制预览，对应 Go {@code formatBinaryContentForDisplay}。 */
    static String formatBinaryContentForDisplay(String content) {
        StringBuilder sb = new StringBuilder();
        sb.append(Fmt.format("(二进制内容，共 %d 字节)", content.length()));

        List<String> strs = extractPrintableStrings(content, CONTENT_PROBE_MIN_STRING_LEN);
        if (!strs.isEmpty()) {
            if (strs.size() > CONTENT_PROBE_MAX_STRINGS) {
                strs = strs.subList(0, CONTENT_PROBE_MAX_STRINGS);
            }
            sb.append("\n\n[可读字符串]\n");
            for (String s : strs) {
                sb.append(Fmt.format("  %s\n", s));
            }
        }

        sb.append("\n[十六进制预览]\n");
        sb.append(hexDumpContent(content, CONTENT_PROBE_HEX_DUMP_MAX_LINES));
        return sb.toString();
    }

    /** 从二进制内容中提取长度达标的可读字符串，对应 Go {@code extractPrintableStrings}。 */
    static List<String> extractPrintableStrings(String content, int minLen) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder(64);

        for (int i = 0; i < content.length(); i++) {
            char b = content.charAt(i);
            if (b == '\n' || b == '\r' || b == '\t') {
                cur.append(' ');
            } else if (b >= 0x20 && b <= 0x7e) {
                cur.append(b);
            } else {
                if (cur.length() >= minLen) {
                    out.add(cur.toString());
                }
                cur.setLength(0);
            }
        }
        if (cur.length() >= minLen) {
            out.add(cur.toString());
        }
        return out;
    }

    /** 生成十六进制预览 (每行 16 字节，右侧附 ASCII 视图)，对应 Go {@code hexDumpContent}。 */
    static String hexDumpContent(String content, int maxLines) {
        int len = content.length();
        StringBuilder sb = new StringBuilder();

        for (int offset = 0; offset < len; offset += 16) {
            if (maxLines > 0 && offset / 16 >= maxLines) {
                sb.append(Fmt.format("... (剩余 %d 字节未显示)\n", len - offset));
                break;
            }

            int end = Math.min(offset + 16, len);
            sb.append(Fmt.format("%08x  ", offset));
            for (int i = offset; i < offset + 16; i++) {
                if (i < end) {
                    sb.append(Fmt.format("%02x ", content.charAt(i) & 0xff));
                } else {
                    sb.append("   ");
                }
                if (i == offset + 7) {
                    sb.append(' ');
                }
            }

            sb.append(" |");
            for (int i = offset; i < end; i++) {
                char c = content.charAt(i);
                if (c >= 0x20 && c <= 0x7e) {
                    sb.append(c);
                } else {
                    sb.append('.');
                }
            }
            sb.append("|\n");
        }
        return sb.toString();
    }

    /**
     * 生成内容探测结果的协议标签，例如 "http / http-get"。
     * 便于在终端输出中直接看出命中/推断出的协议与探测器名称。
     * 对应 Go 的 {@code formatContentProbeTag(result ContentProbeResult) string}。
     */
    static String formatContentProbeTag(ContentProbeResult result) {
        String protocol = str(result.protocol);
        String probe = str(result.probe);
        if (!protocol.isEmpty() && !probe.isEmpty()) {
            return Fmt.format("%s / %s", protocol, probe);
        }
        if (!protocol.isEmpty()) {
            return protocol;
        }
        if (!probe.isEmpty()) {
            return probe;
        }
        return "未识别";
    }

    // =====================================================================
    // 彩色输出
    //
    // 所有配色均通过本地复刻的 fatih/color 输出，自动遵循全局
    // Colors.useColor（由 --no-color 控制；仅影响终端展示，JSON/文件输出始终为纯文本）。
    // 纯文本结果仍由 formatContentForDisplay 生成，用于 JSON 与日志，保证数据干净。
    // =====================================================================

    /** 汇总行 "[X] ... 内容探测完成"（FgCyan+Bold） */
    static final int[] STYLE_SUMMARY = {36, 1};
    /** 目标主机 IP（FgWhite+Bold） */
    static final int[] STYLE_IP = {37, 1};
    /** 端口号（FgBlue+Bold） */
    static final int[] STYLE_PORT = {34, 1};
    /** 弱化提示行 / 分隔线 / 截断提示（FgHiBlack） */
    static final int[] STYLE_PROMPT = {90};
    /** 命中探测器的协议标签（FgGreen+Bold） */
    static final int[] STYLE_MATCH = {32, 1};
    /** 未确认命中的协议标签（FgYellow） */
    static final int[] STYLE_GUESS = {33};
    /** 响应头名称 / 键名（FgCyan） */
    static final int[] STYLE_HEADER = {36};
    /** 响应头内容 / 键值（FgWhite+Bold） */
    static final int[] STYLE_VALUE = {37, 1};
    /** 协议成功回复行 (+OK / 220 ...)（FgGreen） */
    static final int[] STYLE_REPLY_OK = {32};
    /** 协议错误回复行 (-ERR / 530 ...)（FgRed+Bold） */
    static final int[] STYLE_REPLY_ERR = {31, 1};
    /** 二进制内容中提取出的可读字符串（FgHiGreen） */
    static final int[] STYLE_STRING = {92};
    /** 二进制内容的说明与十六进制预览（FgHiBlack） */
    static final int[] STYLE_BINARY = {90};

    /**
     * 依据 HTTP 状态码返回配色，与 dirscan 的状态码配色语义保持一致
     * (2xx 绿 / 3xx 青 / 4xx 黄 / 5xx 红)。对应 Go {@code contentProbeStatusCodeStyle}。
     */
    static int[] contentProbeStatusCodeStyle(int code) {
        if (code >= 200 && code < 300) {
            return new int[]{32, 1};
        }
        if (code >= 300 && code < 400) {
            return new int[]{36};
        }
        if (code >= 400 && code < 500) {
            return new int[]{33};
        }
        if (code >= 500) {
            return new int[]{31, 1};
        }
        return new int[]{35};
    }

    /**
     * 为展示用内容着色。
     * 文本内容先经 formatContentForDisplay 统一换行、过滤控制字符并截断，再按行着色；
     * 二进制内容与空内容单独处理。对应 Go {@code colorizeContentProbeDisplay}。
     */
    static String colorizeContentProbeDisplay(String content) {
        if (content == null || content.isEmpty()) {
            return goWrap("(无响应内容)", STYLE_PROMPT);
        }
        if (isBinaryContent(content)) {
            return colorizeContentProbeBinary(content);
        }
        return colorizeContentProbeText(formatContentForDisplay(content));
    }

    /**
     * 按行着色已格式化的文本内容，着色规则:
     * <ol>
     *   <li>HTTP 状态行 (HTTP/1.1 200 OK) 按状态码类别着色</li>
     *   <li>HTTP 响应头 / 键值行 (Name: Value) 键名青色、值加粗</li>
     *   <li>协议成功回复行 (+OK / 220 ...) 绿色，错误回复行 (-ERR / 530 ...) 红色</li>
     *   <li>截断提示行暗灰</li>
     *   <li>其余正文保持默认色，避免长正文整段着色后难以阅读</li>
     * </ol>
     * 对应 Go {@code colorizeContentProbeText}。
     */
    static String colorizeContentProbeText(String display) {
        if (!Colors.useColor) {
            return display;
        }

        String[] lines = display.split("\n", -1);
        StringBuilder sb = new StringBuilder();
        boolean htmlBody = false;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (i > 0) {
                sb.append('\n');
            }
            if (line.isEmpty()) {
                continue;
            }

            // HTML/XML 正文开始后关闭键值着色，避免误判 <style>/<script> 内的 CSS/JS 声明
            if (line.startsWith("<")) {
                htmlBody = true;
                sb.append(line);
                continue;
            }

            int code = parseHTTPStatusCode(line);
            if (code > 0) {
                sb.append(goWrap(line, contentProbeStatusCodeStyle(code)));
                continue;
            }

            if (!htmlBody) {
                String[] kv = splitContentProbeKeyValue(line);
                if (kv != null) {
                    sb.append(goSprintf("%s:", new Object[]{kv[0]}, STYLE_HEADER));
                    if (!kv[1].isEmpty()) {
                        sb.append(' ');
                        sb.append(goWrap(kv[1], STYLE_VALUE));
                    }
                    continue;
                }
            }

            if (line.startsWith("[... ")) {
                sb.append(goWrap(line, STYLE_PROMPT));
                continue;
            }

            switch (classifyContentProbeReplyLine(line)) {
                case CONTENT_PROBE_REPLY_OK -> sb.append(goWrap(line, STYLE_REPLY_OK));
                case CONTENT_PROBE_REPLY_ERROR -> sb.append(goWrap(line, STYLE_REPLY_ERR));
                default -> sb.append(line);
            }
        }
        return sb.toString();
    }

    /**
     * 为二进制内容着色: 说明行与十六进制预览使用暗色，
     * 提取出的可读字符串使用绿色。对应 Go {@code colorizeContentProbeBinary}。
     */
    static String colorizeContentProbeBinary(String content) {
        String display = formatContentForDisplay(content);
        if (!Colors.useColor) {
            return display;
        }

        StringBuilder sb = new StringBuilder();
        boolean inStrings = false;
        String[] lines = display.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (i > 0) {
                sb.append('\n');
            }
            if (line.startsWith("(二进制内容")) {
                sb.append(goWrap(line, STYLE_PROMPT));
            } else if (line.equals("[可读字符串]")) {
                inStrings = true;
                sb.append(goWrap(line, STYLE_HEADER));
            } else if (line.equals("[十六进制预览]")) {
                inStrings = false;
                sb.append(goWrap(line, STYLE_PROMPT));
            } else if (inStrings && line.startsWith("  ")) {
                sb.append(goWrap(line, STYLE_STRING));
            } else {
                sb.append(goWrap(line, STYLE_BINARY));
            }
        }
        return sb.toString();
    }

    /**
     * 从 HTTP 状态行中提取状态码，非状态行返回 0。
     * 对应 Go {@code parseHTTPStatusCode}（SplitN(line, " ", 3) 语义）。
     */
    static int parseHTTPStatusCode(String line) {
        if (!line.startsWith("HTTP/")) {
            return 0;
        }
        String[] parts = splitN(line, ' ', 3);
        if (parts.length < 2 || parts[1].length() != 3) {
            return 0;
        }
        int code = 0;
        for (int i = 0; i < 3; i++) {
            char c = parts[1].charAt(i);
            if (c < '0' || c > '9') {
                return 0;
            }
            code = code * 10 + (c - '0');
        }
        return code;
    }

    /**
     * 拆分 "Name: Value" 形式的响应头/键值行，返回 {@code {name, value}}；
     * 不是键值行时返回 {@code null}。
     * 仅接受不含空白、长度合理的 token 作为键名，避免误判 HTML/CSS 等正文。
     * 对应 Go {@code splitContentProbeKeyValue(line) (name, value string, ok bool)}。
     */
    static String[] splitContentProbeKeyValue(String line) {
        int idx = line.indexOf(':');
        if (idx <= 0 || idx > 32) {
            return null;
        }
        // Go 的 len(line) 是字节数：按 UTF-8 字节数判定
        if (line.getBytes(StandardCharsets.UTF_8).length > 200) {
            return null;
        }
        String name = line.substring(0, idx);
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean alnum = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            if (!alnum && c != '-' && c != '_') {
                return null;
            }
        }
        return new String[]{name, goTrimSpace(line.substring(idx + 1))};
    }

    /** 常见服务 banner 前缀，读取到即视为成功应答 (绿色) */
    static final String[] CONTENT_PROBE_BANNER_PREFIXES = {
            "SSH-", "RFB ", "AMQP", "ZBXD", "* OK",
    };

    /**
     * 判定协议回复行的语义，用于着色:
     * <ul>
     *   <li>成功: 以 "+" 开头 (如 +OK/+PONG) 或 3 位数字码 &lt; 400 (如 220/250/200)
     *       或命中常见服务 banner 前缀 (如 SSH-/RFB)</li>
     *   <li>失败: 以 "-" 开头 (如 -ERR/-NOAUTH) 或 3 位数字码 &gt;= 400 (如 530/500)</li>
     * </ul>
     * 对应 Go {@code classifyContentProbeReplyLine}。
     */
    static int classifyContentProbeReplyLine(String line) {
        if (line.isEmpty()) {
            return CONTENT_PROBE_REPLY_PLAIN;
        }
        char c = line.charAt(0);
        if (c == '+') {
            return CONTENT_PROBE_REPLY_OK;
        }
        if (c == '-') {
            return CONTENT_PROBE_REPLY_ERROR;
        }
        for (String prefix : CONTENT_PROBE_BANNER_PREFIXES) {
            if (line.startsWith(prefix)) {
                return CONTENT_PROBE_REPLY_OK;
            }
        }
        int code = parseContentProbeReplyCode(line);
        if (code >= 0) {
            if (code >= 400) {
                return CONTENT_PROBE_REPLY_ERROR;
            }
            return CONTENT_PROBE_REPLY_OK;
        }
        return CONTENT_PROBE_REPLY_PLAIN;
    }

    /**
     * 解析 "220 ..." / "530 ..." 形式的协议回复码，失败返回 {@code -1}
     * （Go 返回 {@code (int, bool)}，码值 0 与失败靠 bool 区分，这里用 -1 兜底）。
     * 对应 Go {@code parseContentProbeReplyCode}。
     */
    static int parseContentProbeReplyCode(String line) {
        if (line.length() < 3) {
            return -1;
        }
        int code = 0;
        for (int i = 0; i < 3; i++) {
            char c = line.charAt(i);
            if (c < '0' || c > '9') {
                return -1;
            }
            code = code * 10 + (c - '0');
        }
        if (line.length() > 3) {
            char c = line.charAt(3);
            if (c != ' ' && c != '-') {
                return -1;
            }
        }
        return code;
    }

    /**
     * 彩色打印汇总行: {@code [X] 1.2.3.4 内容探测完成: 2/3 个端口返回内容}。
     * 对应 Go {@code printContentProbeSummary}。
     */
    static void printContentProbeSummary(String ip, int responded, int total) {
        goPrint("[X] ", STYLE_SUMMARY);
        goPrint(ip, STYLE_IP);
        printGo(" 内容探测完成: ");
        if (responded > 0) {
            goPrint(String.valueOf(responded), STYLE_REPLY_OK);
        } else {
            goPrint(String.valueOf(responded), STYLE_GUESS);
        }
        printGo(Fmt.format("/%d 个端口返回内容\n", total));
    }

    /**
     * 按结果可信度着色打印协议标签：
     * 命中为绿色、未确认命中为黄色、无响应为暗灰色。
     * 对应 Go {@code printContentProbeTag}。
     */
    static void printContentProbeTag(ContentProbeResult result) {
        String tag = formatContentProbeTag(result);
        if (str(result.content).isEmpty()) {
            goPrint(tag, STYLE_PROMPT);
        } else if ("unknown".equals(result.protocol)) {
            goPrint(tag, STYLE_GUESS);
        } else {
            goPrint(tag, STYLE_MATCH);
        }
    }

    /**
     * 彩色打印单个端口的内容探测结果:
     * <pre>
     * [*] 端口80
     * [+] 正在详细探测中...
     * ----- 80 端口 [http / http-get]
     * &lt;端口回复的内容&gt;
     * </pre>
     * 对应 Go {@code printContentProbePortBlock}。
     */
    static void printContentProbePortBlock(String ip, int port, ContentProbeResult result) {
        goPrint("[*] 端口", STYLE_PROMPT);
        goPrintln(String.valueOf(port), STYLE_PORT);

        goPrintln("[+] 正在详细探测中...", STYLE_PROMPT);

        goPrint("----- ", STYLE_PROMPT);
        goPrint(String.valueOf(port), STYLE_PORT);
        printGo(" 端口 [");
        printContentProbeTag(result);
        goPrintln("]", STYLE_PROMPT);

        printGo(Fmt.format("%s\n", colorizeContentProbeDisplay(str(result.content))));
    }

    // =====================================================================
    // 主机级内容探测
    // =====================================================================

    /**
     * 对单个主机的全部开放端口执行内容探测：
     * <ol>
     *   <li>并发探测各开放端口，结果回填到 {@link PortInfo} (JSON 输出可见)；</li>
     *   <li>打印汇总后按端口升序打印探测到的内容，格式:
     *       <pre>
     *       [X] 1.2.3.4 内容探测完成: 2/3 个端口返回内容
     *       [*] 端口80
     *       [+] 正在详细探测中...
     *       ----- 80 端口 [http / http-get]
     *       xxx</pre></li>
     * </ol>
     *
     * <p>回填字段：{@link PortInfo#content}、{@link PortInfo#contentProtocol}、
     * {@link PortInfo#contentProbe}。调用点在 scan_optimized.go:712。
     *
     * <p><b>与 Go 的差异</b>：Go 的 {@code ctx.Done()} 检查由线程池生命周期承担；
     * Go 打印前还会拿 scan_optimized.go 的 {@code progressMu}，Java 侧无对应锁。
     *
     * @param ip          目标 IP
     * @param ports       开放端口表（被就地修改）
     * @param timeout     单端口探测超时
     * @param concurrency 并发数
     */
    public static void contentProbeHost(String ip,
                                        Map<Integer, PortInfo> ports,
                                        Duration timeout,
                                        int concurrency) {
        if (ports == null || ports.isEmpty()) {
            return;
        }

        List<PortInfo> targetPorts = new ArrayList<>();
        for (PortInfo info : ports.values()) {
            if (info == null) {
                continue;
            }
            if (info.isOpenOrOpenFiltered()) {
                targetPorts.add(info);
            }
        }
        if (targetPorts.isEmpty()) {
            return;
        }
        targetPorts.sort(Comparator.comparingInt(p -> p.port));

        Duration t = timeout;
        if (t == null || t.isZero() || t.isNegative()) {
            t = CONTENT_PROBE_DEFAULT_TIMEOUT;
        }
        int conc = concurrency <= 0 ? CONTENT_PROBE_DEFAULT_CONCURRENCY : concurrency;
        if (conc > targetPorts.size()) {
            conc = targetPorts.size();
        }

        Map<Integer, ContentProbeResult> results = new ConcurrentHashMap<>();
        CountDownLatch latch = new CountDownLatch(targetPorts.size());
        ExecutorService pool = Executors.newFixedThreadPool(conc);
        final Duration ft = t;
        try {
            for (PortInfo info : targetPorts) {
                // Go: select { case <-ctx.Done(): return; default: } —— Java 无 ctx，
                // 取消语义由线程池（shutdownNow / 进程退出）承担
                final PortInfo pi = info;
                pool.execute(() -> {
                    try {
                        ContentProbeResult result;
                        try {
                            result = probePortContent(ip, ip, pi, ft);
                        } catch (RuntimeException e) {
                            // Go 侧不会走到这里；Java 兜底为空结果，避免异常影响扫描
                            result = new ContentProbeResult();
                        }
                        results.put(pi.port, result);
                    } finally {
                        latch.countDown();
                    }
                });
            }
            awaitUninterruptible(latch);
        } finally {
            pool.shutdown();
        }

        // 回填探测结果 (仅非空内容)，保证结果 JSON 中包含端口回复内容
        for (PortInfo info : targetPorts) {
            ContentProbeResult result = results.get(info.port);
            if (result == null || str(result.content).isEmpty()) {
                continue;
            }
            PortInfo updated = ports.get(info.port);
            if (updated == null) {
                continue;
            }
            // Go 把原始字节写入 PortInfo.Content，序列化时由 encoding/json 强制转 UTF-8
            //（非法序列 → U+FFFD）；这里在回填时做同样的转换。
            updated.content = new String(
                    result.content.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
            updated.contentProtocol = str(result.protocol);
            updated.contentProbe = str(result.probe);
        }

        // 打印内容探测结果 (整块输出，避免多主机/多端口输出交错)
        synchronized (CONTENT_PROBE_PRINT_LOCK) {
            printGo("\n");
            int responded = 0;
            for (PortInfo info : targetPorts) {
                ContentProbeResult r = results.get(info.port);
                if (r != null && !str(r.content).isEmpty()) {
                    responded++;
                }
            }
            printContentProbeSummary(ip, responded, targetPorts.size());

            // CDN 内容去重：相同内容指纹的端口块仅首次打印完整内容，
            // 后续 IP 仅打印简短提示，避免同一服务应答语义在多个 CDN IP 下重复罗列。
            for (PortInfo info : targetPorts) {
                ContentProbeResult result = results.get(info.port);
                if (result == null || str(result.content).isEmpty()) {
                    continue;
                }
                String key = contentDedupKey(info.port, result.content);
                if (key.isEmpty()) {
                    printContentProbePortBlock(ip, info.port, result);
                    continue;
                }
                ContentDedupEntry existing = CONTENT_PROBE_DEDUP_MAP.get(key);
                if (existing != null) {
                    // 已有相同语义内容，仅提示此 IP 也返回了相同内容
                    goPrintf("\n[*] %s:%d 与 %s:%d 内容相同 (共 %d 个 IP)\n",
                            new Object[]{ip, info.port, existing.firstIP, info.port,
                                    existing.count + 1},
                            STYLE_PROMPT);
                    // 更新计数
                    CONTENT_PROBE_DEDUP_MAP.put(key,
                            new ContentDedupEntry(existing.firstIP, existing.count + 1));
                } else {
                    // 首次出现，打印完整内容块并记录
                    CONTENT_PROBE_DEDUP_MAP.put(key, new ContentDedupEntry(ip, 1));
                    printContentProbePortBlock(ip, info.port, result);
                }
            }
        }
    }
}

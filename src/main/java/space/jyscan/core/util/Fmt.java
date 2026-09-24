package space.jyscan.core.util;

import java.lang.reflect.Array;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Duration;
import java.util.Iterator;
import java.util.Map;

/**
 * Go {@code fmt.Sprintf} 兼容层。
 *
 * <p>Java 的 {@link String#format} 与 Go 的 {@code fmt} 存在多处语义差异，直接套用会出错：
 * <ul>
 *   <li>Go 的 {@code %v} 是"默认格式"，Java 没有对应动词；</li>
 *   <li>Go 的 {@code %q}/{@code %T} Java 不支持；</li>
 *   <li>Go 的 {@code %d} 遇到浮点会报错、Java 抛 {@link java.util.IllegalFormatConversionException}；</li>
 *   <li>Java 的 {@code %b} 对非布尔值输出 {@code true}，Go 的 {@code %b} 是二进制；</li>
 *   <li>Java 的 {@code %s} 对 null 输出 {@code null}，Go 输出 {@code <nil>}；</li>
 *   <li>Java 的 {@code %g} 与 Go 的 {@code %g} 规则不同。</li>
 * </ul>
 *
 * <p>因此这里自行解析格式串并逐参数渲染，保证与 Go 输出一致。
 * 移植 Go 代码时可直接把 {@code fmt.Sprintf(...)} 换成 {@code Fmt.format(...)}。
 */
public final class Fmt {

    private Fmt() {
    }

    /** 等价于 Go 的 fmt.Sprintf。 */
    public static String format(String fmt, Object... args) {
        if (fmt == null) {
            return "<nil>";
        }
        if (fmt.isEmpty()) {
            return fmt;
        }
        if (args == null) {
            args = new Object[0];
        }

        StringBuilder out = new StringBuilder(fmt.length() + 32);
        int idx = 0;   // 下一个要消费的参数下标
        int i = 0;
        final int n = fmt.length();

        while (i < n) {
            char c = fmt.charAt(i);
            if (c != '%') {
                out.append(c);
                i++;
                continue;
            }

            // "%%" -> 字面百分号
            if (i + 1 < n && fmt.charAt(i + 1) == '%') {
                out.append('%');
                i += 2;
                continue;
            }

            int start = i;
            i++; // 跳过 '%'

            // ---- 标志位 ----
            boolean leftAlign = false;
            boolean plusSign = false;
            boolean spaceSign = false;
            boolean altForm = false;
            boolean zeroPad = false;
            while (i < n) {
                char f = fmt.charAt(i);
                switch (f) {
                    case '-' -> leftAlign = true;
                    case '+' -> plusSign = true;
                    case ' ' -> spaceSign = true;
                    case '#' -> altForm = true;
                    case '0' -> zeroPad = true;
                    default -> {
                        break;
                    }
                }
                if ("+- #0".indexOf(f) >= 0) {
                    i++;
                } else {
                    break;
                }
            }

            // ---- 宽度 ----
            int width = -1;
            int wstart = i;
            while (i < n && Character.isDigit(fmt.charAt(i))) {
                i++;
            }
            if (i > wstart) {
                width = Integer.parseInt(fmt.substring(wstart, i));
            }

            // ---- 精度 ----
            int precision = -1;
            if (i < n && fmt.charAt(i) == '.') {
                i++;
                int pstart = i;
                while (i < n && Character.isDigit(fmt.charAt(i))) {
                    i++;
                }
                precision = (i > pstart) ? Integer.parseInt(fmt.substring(pstart, i)) : 0;
            }

            if (i >= n) {
                // 格式串截断：原样输出剩余部分
                out.append(fmt, start, n);
                break;
            }

            char verb = fmt.charAt(i);
            i++;

            // Go 的语义：参数用尽后仍遇到动词时渲染为 %!<verb>(MISSING)
            if (idx >= args.length) {
                out.append("%!").append(verb).append("(MISSING)");
                continue;
            }

            Object arg = args[idx];
            idx++;

            // "%%" 之外的动词，渲染时不应再把 % 当作格式串处理
            String rendered = render(verb, arg, leftAlign, plusSign, spaceSign, altForm, zeroPad,
                    width, precision);
            out.append(rendered);
        }

        // Go 的语义：格式串消费完毕后仍有剩余参数时追加 %!(EXTRA type=value, ...)
        // （对应 fmt/print.go 中 doPrintf 收尾处，与上面的 (MISSING) 成对）。
        // Go 仅在未使用显式下标 %[1]v 时输出该后缀（`!p.reordered` 条件），
        // 而本格式层不支持显式下标，故等价于无条件输出。
        // 值本身按 %v 渲染，其中的 % 不会被二次解释（Go 实测：string=100% sure）。
        if (idx < args.length) {
            out.append("%!(EXTRA ");
            for (int k = idx; k < args.length; k++) {
                if (k > idx) {
                    out.append(", ");
                }
                if (args[k] == null) {
                    // Go 对 nil 实参只输出裸 <nil>，不带 "=" 和值
                    out.append("<nil>");
                    continue;
                }
                out.append(goTypeName(args[k]));
                out.append('=');
                out.append(goDefault(args[k], -1));
            }
            out.append(')');
        }

        return out.toString();
    }

    // =====================================================================
    // 动词渲染
    // =====================================================================

    private static String render(char verb, Object arg,
                                 boolean leftAlign, boolean plusSign, boolean spaceSign,
                                 boolean altForm, boolean zeroPad,
                                 int width, int precision) {
        switch (verb) {
            case 'v':
                return pad(goDefault(arg, precision), leftAlign, zeroPad, width, ' ');
            case 's': {
                String s = arg == null ? "<nil>" : String.valueOf(arg);
                if (precision >= 0 && s.length() > precision) {
                    s = s.substring(0, precision);
                }
                return pad(s, leftAlign, zeroPad, width, ' ');
            }
            case 'q':
                return pad(goQuote(arg), leftAlign, zeroPad, width, ' ');
            case 'T':
                return pad(goTypeName(arg), leftAlign, zeroPad, width, ' ');
            case 'd':
            case 'b':
            case 'o':
            case 'O':
            case 'x':
            case 'X': {
                String s = goRadix(verb, arg, altForm);
                return padSigned(s, leftAlign, zeroPad, width, plusSign, spaceSign, ' ');
            }
            case 'c': {
                String s = toChar(arg);
                return pad(s, leftAlign, zeroPad, width, ' ');
            }
            case 'e':
            case 'E':
            case 'f':
            case 'F':
            case 'g':
            case 'G': {
                String s = goFloat(verb, arg, precision, altForm);
                return padSigned(s, leftAlign, zeroPad, width, plusSign, spaceSign, ' ');
            }
            case 'U':
                return pad("U+" + goRadix('X', arg, false), leftAlign, zeroPad, width, ' ');
            case '%':
                return "%";
            default:
                // 未知动词：Go 会打印 %!x(...)，这里保持原样以免吞掉内容
                return "%" + verb;
        }
    }

    // =====================================================================
    // Go 默认格式 (%v)
    // =====================================================================

    private static String goDefault(Object arg, int precision) {
        if (arg == null) {
            return "<nil>";
        }
        if (arg instanceof Duration d) {
            return goDuration(d);
        }
        if (arg instanceof String s) {
            if (precision >= 0 && s.length() > precision) {
                return s.substring(0, precision);
            }
            return s;
        }
        if (arg instanceof Boolean || arg instanceof Character || arg instanceof Enum<?>) {
            return String.valueOf(arg);
        }
        if (arg instanceof Number) {
            return goNumberDefault((Number) arg);
        }
        if (arg.getClass().isArray()) {
            return goSlice(arg);
        }
        if (arg instanceof Iterable<?> it) {
            return goIterable(it);
        }
        if (arg instanceof Map<?, ?> m) {
            return goMap(m);
        }
        if (arg instanceof Throwable t) {
            return t.getMessage() == null ? t.toString() : t.getMessage();
        }
        return String.valueOf(arg);
    }

    private static String goNumberDefault(Number num) {
        if (num instanceof Double || num instanceof Float) {
            // Go 的 %v 对浮点等价于 %g
            return goFloat('g', num, -1, false);
        }
        return String.valueOf(num.longValue());
    }

    /**
     * Go 的 {@code time.Duration.String()}（{@code time/time.go} 的 {@code Duration.format}），逐分支照抄：
     * <ul>
     *   <li>0 → {@code "0s"}；</li>
     *   <li>亚秒按量级用 {@code ns}/{@code µs}/{@code ms}（小数分别 0/3/6 位、尾零裁剪、全零不出小数点），
     *       {@code µ} 为 U+00B5（Go 源注释明确 {@code 0xC2 0xB5}）；</li>
     *   <li>≥1s 秒部<b>恒打印</b>（小数 9 位、尾零裁剪），分钟仅在总分钟数&gt;0 时出现
     *       （分钟为 0 时写 {@code 0m}），小时仅在&gt;0 时出现；<b>没有</b> {@code d} 天单位
     *       （Go 源注释：Stop at hours because days can be different lengths）。</li>
     * </ul>
     * 如 "1.5s"、"2m3.5s"、"500ms"、"394.774619ms"、"24h0m0s"。
     *
     * <p>对拍依据：{@code /tmp/opencode/durcheck}（34 个纳秒值的 Go 地面真值）。
     */
    private static String goDuration(Duration d) {
        long nanos = d.toNanos();
        if (nanos == 0) {
            return "0s";
        }
        boolean neg = nanos < 0;
        // Go: u := uint64(d); if neg { u = -u }。两补码下 Long.MIN_VALUE 取负仍为
        // Long.MIN_VALUE，其无符号值恰为 |d|，配合下面的无符号除/余运算语义与 Go 一致。
        long u = neg ? -nanos : nanos;

        StringBuilder sb = new StringBuilder();
        if (neg) {
            sb.append('-');
        }
        if (Long.compareUnsigned(u, 1_000_000_000L) < 0) {
            // 亚秒：Go 的 u < Second 分支
            if (u < 1_000L) {
                return sb.append(u).append("ns").toString();
            }
            if (u < 1_000_000L) {
                appendFrac(sb, u / 1_000L, u % 1_000L, 3);
                return sb.append('µ').append('s').toString();
            }
            appendFrac(sb, u / 1_000_000L, u % 1_000_000L, 6);
            return sb.append("ms").toString();
        }
        long secs = Long.divideUnsigned(u, 1_000_000_000L);
        long frac = Long.remainderUnsigned(u, 1_000_000_000L);
        long hours = secs / 3600;
        long mins = secs / 60 % 60;
        long s = secs % 60;
        if (hours > 0) {
            sb.append(hours).append('h');
        }
        if (secs / 60 > 0) {
            sb.append(mins).append('m');
        }
        appendFrac(sb, s, frac, 9);
        return sb.append('s').toString();
    }

    /**
     * Go 的 {@code fmtFrac} + {@code fmtInt} 组合：整数部，小数非零时再追加
     * {@code "." + 去尾零的 prec 位小数}（全零则不出小数点）。
     */
    private static void appendFrac(StringBuilder sb, long ip, long frac, int prec) {
        sb.append(ip);
        if (frac != 0) {
            sb.append('.').append(stripTrailingZeros(padLeft(Long.toString(frac), prec, '0')));
        }
    }

    /** 左侧补字符（Java 标准库没有 String.padStart）。 */
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

    private static String stripTrailingZeros(String s) {
        int end = s.length();
        while (end > 1 && s.charAt(end - 1) == '0') {
            end--;
        }
        return s.substring(0, end);
    }

    private static String goSlice(Object arr) {
        StringBuilder sb = new StringBuilder("[");
        int len = Array.getLength(arr);
        for (int i = 0; i < len; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(goDefault(Array.get(arr, i), -1));
        }
        return sb.append(']').toString();
    }

    private static String goIterable(Iterable<?> it) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Object o : it) {
            if (!first) {
                sb.append(' ');
            }
            first = false;
            sb.append(goDefault(o, -1));
        }
        return sb.append(']').toString();
    }

    private static String goMap(Map<?, ?> m) {
        StringBuilder sb = new StringBuilder("map[");
        boolean first = true;
        for (Iterator<? extends Map.Entry<?, ?>> e = m.entrySet().iterator(); e.hasNext(); ) {
            Map.Entry<?, ?> entry = e.next();
            if (!first) {
                sb.append(' ');
            }
            first = false;
            sb.append(goDefault(entry.getKey(), -1)).append(':').append(goDefault(entry.getValue(), -1));
        }
        return sb.append(']').toString();
    }

    // =====================================================================
    // %q / %T
    // =====================================================================

    private static String goQuote(Object arg) {
        if (arg == null) {
            return "<nil>";
        }
        if (arg instanceof Character c) {
            // Go 的 %q 对单个字符走 strconv.QuoteRune，输出单引号字面量（'A'）
            return "'" + runeEscaped(c) + "'";
        }
        return quoteString(String.valueOf(arg));
    }

    /** 单引号字面量内部的转义（引号与双引号字符串不同，' 要转义、" 不转义）。 */
    private static String runeEscaped(char c) {
        return switch (c) {
            case '\'' -> "\\'";
            case '\\' -> "\\\\";
            case '\n' -> "\\n";
            case '\r' -> "\\r";
            case '\t' -> "\\t";
            default -> (c < 0x20 || c == 0x7f) ? String.format("\\x%02x", (int) c) : String.valueOf(c);
        };
    }

    /** Go 风格双引号字符串字面量。 */
    public static String quoteString(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x7f) {
                        sb.append(String.format("\\x%02x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }

    /**
     * Go 的类型名，对应 {@code reflect.TypeOf(x).String()}，供 {@code %T} 与
     * {@code %!(EXTRA …)} 共用。
     *
     * <p>把 Java 装箱类型映射到 Go 的基本类型名（{@code string}/{@code int}/{@code int64}/
     * {@code float64}/{@code bool}/{@code rune}），{@link Duration} 映射到
     * {@code time.Duration}；数组按 Go 切片写作 {@code []elem}（前缀，不是 Java 的
     * {@code elem[]}），其中 {@code byte[]} 对应 Go 的 {@code []byte} 别名 {@code []uint8}。
     * 其余类型回退到 Java 简单类名 —— Go/Java 类型体系不同，无法诚实对应。
     *
     * <p><b>已知偏差：</b>Go 的错误值会带 Go 侧具体类型（{@code *fs.PathError}、
     * {@code *errors.errorString}）与 Go 文案，Java 异常对象没有可诚实对应的映射，
     * 只能给出 Java 类名 + {@link Throwable#getMessage()}，故含错误参数的
     * {@code %!(EXTRA …)} 段与 Go 逐字不同。这是 Go/Java 异常表示差异，非格式化缺陷。
     */
    private static String goTypeName(Object arg) {
        if (arg == null) {
            return "<nil>";
        }
        return goTypeOf(arg.getClass());
    }

    /** {@link #goTypeName} 的按类型实现，数组走类型而非首元素，空数组不会越界。 */
    private static String goTypeOf(Class<?> cls) {
        if (cls == null) {
            return "<nil>";
        }
        if (cls == String.class) {
            return "string";
        }
        if (cls == int.class || cls == Integer.class
                || cls == short.class || cls == Short.class
                || cls == byte.class || cls == Byte.class) {
            return "int";
        }
        if (cls == long.class || cls == Long.class) {
            return "int64";
        }
        if (cls == double.class || cls == Double.class || cls == float.class || cls == Float.class) {
            return "float64";
        }
        if (cls == boolean.class || cls == Boolean.class) {
            return "bool";
        }
        if (cls == char.class || cls == Character.class) {
            return "rune";
        }
        if (cls == Duration.class) {
            return "time.Duration";
        }
        if (cls == byte[].class) {
            return "[]uint8";   // Go 的 []byte 就是 []uint8
        }
        if (cls.isArray()) {
            return "[]" + goTypeOf(cls.getComponentType());
        }
        // Go 里包名带路径，Java 侧返回简单类名即可
        String name = cls.getName();
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot + 1) : name;
    }

    // =====================================================================
    // 整数 / 进制
    // =====================================================================

    private static String goRadix(char verb, Object arg, boolean altForm) {
        if (arg == null) {
            return "<nil>";
        }
        if (arg instanceof Boolean b) {
            // Go 的 %b 对 bool 输出 true/false
            return b ? "true" : "false";
        }
        if (arg instanceof Number num) {
            long v = num.longValue();
            int radix = 10;
            boolean upper = false;
            switch (verb) {
                case 'b' -> radix = 2;
                case 'o', 'O' -> radix = 8;
                case 'x' -> radix = 16;
                case 'X' -> {
                    radix = 16;
                    upper = true;
                }
                default -> {
                }
            }
            String s;
            if (v < 0 && radix != 10) {
                // Go 对负数的非十进制按无符号位宽处理
                s = Long.toUnsignedString(v, radix);
            } else {
                s = Long.toString(v, radix);
            }
            if (upper) {
                s = s.toUpperCase();
            }
            if (altForm) {
                if (radix == 16 && !s.startsWith("0") && !s.startsWith("O")) {
                    s = "0" + (upper ? "X" : "x") + s;
                } else if (radix == 8 && !s.startsWith("0")) {
                    s = "0" + s;
                } else if (radix == 2 && verb == 'O') {
                    s = "0b" + s;
                }
            }
            if (verb == 'O' && !altForm) {
                s = "0o" + s;
            }
            return s;
        }
        if (arg instanceof Character c) {
            return goRadix(verb, (int) c, false);
        }
        if (arg instanceof String str) {
            // Go 对字符串用 %d 会报错，这里退化为原样输出，避免移植后丢失内容
            return str;
        }
        return String.valueOf(arg);
    }

    private static String toChar(Object arg) {
        if (arg == null) {
            return "<nil>";
        }
        if (arg instanceof Character c) {
            return String.valueOf(c);
        }
        if (arg instanceof Number num) {
            return String.valueOf((char) num.intValue());
        }
        return String.valueOf(arg);
    }

    // =====================================================================
    // 浮点
    // =====================================================================

    private static String goFloat(char verb, Object arg, int precision, boolean altForm) {
        if (arg == null) {
            return "<nil>";
        }
        double d;
        if (arg instanceof Number num) {
            d = num.doubleValue();
        } else if (arg instanceof Character c) {
            d = c;
        } else {
            try {
                d = Double.parseDouble(String.valueOf(arg));
            } catch (NumberFormatException e) {
                return String.valueOf(arg);
            }
        }

        if (Double.isNaN(d)) {
            return "NaN";
        }
        if (Double.isInfinite(d)) {
            return d > 0 ? "+Inf" : "-Inf";
        }

        char lower = Character.toLowerCase(verb);
        switch (lower) {
            case 'f': {
                int p = precision < 0 ? 6 : precision;
                String s = goFFormat(d, p);
                if (altForm && p == 0) {
                    s += ".";
                }
                return s;
            }
            case 'e': {
                int p = precision < 0 ? 6 : precision;
                // Go 输出 e+09 形式（指数两位），goEFormat 内部已归一化
                return goEFormat(d, p, verb == 'E');
            }
            case 'g': {
                return goG(d, precision, verb == 'G', altForm);
            }
            default:
                return String.valueOf(d);
        }
    }

    /** Go 的 %e 指数固定两位（e+09），Java 只给一位或不补零。 */
    private static String normalizeExponent(String s, boolean upper) {
        char marker = upper ? 'E' : 'e';
        int pos = s.indexOf(marker);
        if (pos < 0) {
            return s;
        }
        String mantissa = s.substring(0, pos);
        String exp = s.substring(pos + 1);
        boolean neg = exp.startsWith("-");
        if (neg) {
            exp = exp.substring(1);
        } else if (exp.startsWith("+")) {
            exp = exp.substring(1);
        }
        if (exp.length() < 2) {
            exp = "0" + exp;
        }
        return mantissa + marker + (neg ? "-" : "+") + exp;
    }

    /**
     * Go 的 %g：在 %e 与 %f 中选择更紧凑的那个。
     *
     * <p><b>未指定精度</b>（{@code precision < 0}，即 {@code %v} 与无精度的 {@code %g}）时，
     * Go 交给 {@code strconv.FormatFloat(v, 'g', -1, 64)}：取最短往返表示，并按
     * 「指数 &lt; -4 或 &gt;= 6」选型 —— strconv 在 shortest 分支把 eprec 固定为 6。
     * 指数由十进制串精确解析得出，不用 {@code Math.log10}，避免边界上的浮点误差。
     *
     * <p><b>指定精度</b>时：{@code %g} 的 {@code prec == 0} 视为 1；且无论走 %e 还是 %f
     * 分支都去掉尾随零（{@code #} 除外）—— 这是 %g 本身的性质，与精度无关。
     *
     * <p>已知偏差：指定精度时 Go 会用"舍入后的位数"再判一次 %e/%f 边界，本实现用原始
     * 指数判定，只在舍入恰好跨过 10 的幂时可能不同；项目内无显式 {@code %g} 调用。
     */
    private static String goG(double d, int precision, boolean upper, boolean altForm) {
        boolean neg = isNeg(d);
        double abs = Math.abs(d);
        ShortestDec dec = parseShortest(abs);
        int exp10 = dec.dp() - 1;

        // 未指定精度：最短往返表示 + eprec == 6
        if (precision < 0) {
            String s;
            if (altForm) {
                // %#g（未指定精度）：按 prec=6 渲染；但最短表示本身需要更多有效数字时
                // 直接用最短表示，绝不四舍五入（Go 实测：12345.678 保持 8 位而非 12345.7）
                s = sigDigits(dec) > 6
                        ? ((exp10 < -4 || exp10 >= 6) ? gExp(dec, upper) : gFixed(dec))
                        : gPrec(abs, exp10, 6, upper, true);
            } else {
                s = (exp10 < -4 || exp10 >= 6) ? gExp(dec, upper) : gFixed(dec);
            }
            return neg ? "-" + s : s;
        }

        int p = precision == 0 ? 1 : precision;
        String s = gPrec(abs, exp10, p, upper, altForm);
        return neg ? "-" + s : s;
    }

    /**
     * 按显式精度 {@code p} 渲染 %g：选型规则与 shortest 相同（指数 &lt; -4 或 &gt;= p 走 %e），
     * 且 %e/%f 两支都去掉尾随零；{@code altForm} 时反过来保留尾随零，且结果没有小数点就补一个。
     */
    private static String gPrec(double abs, int exp10, int p, boolean upper, boolean altForm) {
        if (exp10 < -4 || exp10 >= p) {
            String s = goEFormat(abs, p - 1, upper);
            return altForm ? ensureExpPoint(s, upper) : trimExpMantissa(s, upper);
        }
        int frac = Math.max(0, p - 1 - exp10);
        String s = goFFormat(abs, frac);
        if (altForm) {
            return s.indexOf('.') < 0 ? s + "." : s;
        }
        return trimFloat(s);
    }

    /**
     * Go 的 %f：对<b>精确二进制值</b>按<b>半到偶</b>（银行家）舍入。
     *
     * <p>Java 的 {@link String#format} 是半到上（half-up），两者只在恰好 .5 时不同：
     * 实测 {@code %.0f} of {@code 1234.5} → Go {@code 1234}、Java 原为 {@code 1235}。
     * 用精确值而非最短十进制串也是必须的：{@code %.2f} of {@code 2.675} 的精确值是
     * 2.67499999…，故 Go 给 {@code 2.67}；若按最短串 2.675 当平局处理会错成 2.68。
     *
     * <p>负零（{@code -0.0}）保留符号，与 Go 用 {@code math.Signbit} 的行为一致。
     */
    private static String goFFormat(double d, int p) {
        boolean neg = isNeg(d);
        String s = new BigDecimal(Math.abs(d)).setScale(p, RoundingMode.HALF_EVEN).toPlainString();
        return neg ? "-" + s : s;
    }

    /** 负号判定：与 Go 的 {@code v < 0 || math.Signbit(v)} 一致，负零也要带符号。 */
    private static boolean isNeg(double d) {
        return d < 0 || (d == 0 && Double.doubleToRawLongBits(d) < 0);
    }

    /**
     * Go 的 %e：尾数按精确二进制值半到偶舍入到 {@code p} 位小数，指数补足两位。
     *
     * <p>舍入后尾数进位到 10 时重新归一化（如 9.9999995 → 1.000000e+01）。
     */
    private static String goEFormat(double d, int p, boolean upper) {
        boolean neg = isNeg(d);
        BigDecimal exact = new BigDecimal(Math.abs(d));
        int e = 0;
        BigDecimal mant = BigDecimal.ZERO;
        if (exact.signum() != 0) {
            e = exact.precision() - exact.scale() - 1;   // 科学记数法的十进制指数
            mant = exact.scaleByPowerOfTen(-e).setScale(p, RoundingMode.HALF_EVEN);
            if (mant.compareTo(BigDecimal.TEN) >= 0) {
                // movePointLeft 会保值增位（10.000000 → 1.0000000），需复原到 p 位小数
                e++;
                mant = mant.movePointLeft(1).setScale(p, RoundingMode.HALF_EVEN);
            }
        } else {
            mant = mant.setScale(p, RoundingMode.HALF_EVEN);
        }
        String s = mant.toPlainString();
        if (neg) {
            s = "-" + s;
        }
        return normalizeExponent(s + (upper ? 'E' : 'e') + (e < 0 ? '-' : '+') + Math.abs(e), upper);
    }

    /** 有效数字个数（跳过前导零；全为零时为 0）。 */
    private static int sigDigits(ShortestDec dec) {
        String ds = dec.digits();
        int i = 0;
        while (i < ds.length() && ds.charAt(i) == '0') {
            i++;
        }
        return ds.length() - i;
    }

    /** Go 的 {@code #} 对 %e 分支：尾数没有小数点时补一个（如 4e+01 → 4.e+01）。 */
    private static String ensureExpPoint(String s, boolean upper) {
        char marker = upper ? 'E' : 'e';
        int pos = s.indexOf(marker);
        if (pos < 0) {
            return s;
        }
        String mant = s.substring(0, pos);
        return mant.indexOf('.') >= 0 ? s : mant + "." + s.substring(pos);
    }

    /** 最短往返十进制分解，满足 {@code 值 = 0.<digits> × 10^dp}。 */
    private record ShortestDec(String digits, int dp) {
    }

    /**
     * 把 {@link Double#toString} 的结果拆成（有效数字, 指数）。
     *
     * <p>{@code Double.toString} 保证给出唯一区分该值的最短十进制串，与 Go shortest 往返
     * 表示一致；Java 的串里小数点前至少有一位数字，故需去掉整数部分的前导零才能定位小数点。
     */
    private static ShortestDec parseShortest(double abs) {
        if (abs == 0) {
            // Go 把 0 表示成 digits="0", dp=1（即 exp10 == 0），据此 %.6g 才得到 0.00000
            return new ShortestDec("0", 1);
        }
        String s = Double.toString(abs);
        long e = 0;
        int eIdx = s.indexOf('E');
        if (eIdx >= 0) {
            e = Long.parseLong(s.substring(eIdx + 1));
            s = s.substring(0, eIdx);
        }
        String intPart;
        String fracPart;
        int dot = s.indexOf('.');
        if (dot >= 0) {
            intPart = s.substring(0, dot);
            fracPart = s.substring(dot + 1);
        } else {
            intPart = s;
            fracPart = "";
        }
        int lead = 0;
        while (lead < intPart.length() && intPart.charAt(lead) == '0') {
            lead++;
        }
        int dp = (intPart.length() - lead) + (int) e;

        StringBuilder sb = new StringBuilder(intPart.length() + fracPart.length());
        sb.append(intPart, lead, intPart.length()).append(fracPart);
        int end = sb.length();
        while (end > 1 && sb.charAt(end - 1) == '0') {
            end--;   // 去掉尾随零，至少保留一位
        }
        String digits = sb.substring(0, end);
        if (digits.isEmpty()) {
            digits = "0";
            dp = 0;
        }
        return new ShortestDec(digits, dp);
    }

    /** %e 形态：{@code D[.ddd]e±dd}，指数固定两位。 */
    private static String gExp(ShortestDec dec, boolean upper) {
        String digits = dec.digits();
        StringBuilder mant = new StringBuilder();
        mant.append(digits.charAt(0));
        if (digits.length() > 1) {
            mant.append('.').append(digits, 1, digits.length());
        }
        int exp = dec.dp() - 1;
        String raw = mant.toString() + (upper ? 'E' : 'e') + (exp < 0 ? '-' : '+') + Math.abs(exp);
        return normalizeExponent(raw, upper);
    }

    /** %f 形态，按 {@code 0.<digits> × 10^dp} 还原整数与小数部分。 */
    private static String gFixed(ShortestDec dec) {
        String digits = dec.digits();
        int dp = dec.dp();
        if (dp <= 0) {
            StringBuilder sb = new StringBuilder("0.");
            for (int i = 0; i < -dp; i++) {
                sb.append('0');
            }
            return sb.append(digits).toString();
        }
        int nd = digits.length();
        if (dp >= nd) {
            StringBuilder sb = new StringBuilder(digits);
            for (int i = nd; i < dp; i++) {
                sb.append('0');
            }
            return sb.toString();
        }
        return digits.substring(0, dp) + "." + digits.substring(dp);
    }

    /** 去掉 %e 尾串里尾数部分的尾随零（Go 的 %g 性质），指数位不动。 */
    private static String trimExpMantissa(String s, boolean upper) {
        char marker = upper ? 'E' : 'e';
        int pos = s.indexOf(marker);
        if (pos < 0) {
            return s;
        }
        String mant = s.substring(0, pos);
        if (mant.indexOf('.') < 0) {
            return s;
        }
        int end = mant.length();
        while (end > 1 && mant.charAt(end - 1) == '0') {
            end--;
        }
        if (mant.charAt(end - 1) == '.') {
            end--;
        }
        return mant.substring(0, end) + s.substring(pos);
    }

    private static String trimFloat(String s) {
        if (s.indexOf('.') < 0) {
            return s;
        }
        String t = s;
        while (t.length() > 1 && t.endsWith("0")) {
            t = t.substring(0, t.length() - 1);
        }
        if (t.endsWith(".")) {
            t = t.substring(0, t.length() - 1);
        }
        return t;
    }

    // =====================================================================
    // 宽度 / 对齐 / 补零
    // =====================================================================

    private static String pad(String s, boolean leftAlign, boolean zeroPad, int width, char fill) {
        if (width < 0 || s.length() >= width) {
            return s;
        }
        int padLen = width - s.length();
        StringBuilder sb = new StringBuilder(width);
        if (leftAlign) {
            sb.append(s);
            sb.append(" ".repeat(padLen));
        } else if (zeroPad) {
            // 零填充对字符串无意义（Go 只对数值生效），用空格
            sb.append(" ".repeat(padLen)).append(s);
        } else {
            sb.append(" ".repeat(padLen)).append(s);
        }
        return sb.toString();
    }

    /** 数值型：零填充要落在符号之后（Go 语义）。 */
    private static String padSigned(String s, boolean leftAlign, boolean zeroPad, int width,
                                    boolean plusSign, boolean spaceSign, char fill) {
        String sign = "";
        if (s.startsWith("-")) {
            sign = "-";
            s = s.substring(1);
        } else if (plusSign) {
            sign = "+";
        } else if (spaceSign) {
            sign = " ";
        }

        if (width < 0 || (sign.length() + s.length()) >= width) {
            return sign + s;
        }

        int padLen = width - sign.length() - s.length();
        StringBuilder sb = new StringBuilder(width);
        if (leftAlign) {
            sb.append(sign).append(s);
            sb.append(" ".repeat(padLen));
        } else if (zeroPad) {
            sb.append(sign).append("0".repeat(padLen)).append(s);
        } else {
            sb.append(sign).append(" ".repeat(padLen)).append(s);
        }
        return sb.toString();
    }

    // =====================================================================
    // 便捷方法
    // =====================================================================

    /** Go 风格的 Println(fmt, args...)，返回带换行的字符串由调用方决定是否输出。 */
    public static String sprint(String fmt, Object... args) {
        return format(fmt, args);
    }

    /** 截取字符串（Go 的 s[:n]，按 rune 处理以避免拆坏中文）。 */
    public static String slice(String s, int start, int end) {
        if (s == null) {
            return "";
        }
        int len = s.codePointCount(0, s.length());
        int from = start < 0 ? Math.max(0, len + start) : Math.min(start, len);
        int to = end < 0 ? Math.max(0, len + end) : Math.min(end, len);
        if (from >= to) {
            return "";
        }
        int i = s.offsetByCodePoints(0, from);
        int j = s.offsetByCodePoints(0, to);
        return s.substring(i, j);
    }

    /** Go 的 len(s)，返回 rune 数。 */
    public static int length(String s) {
        return s == null ? 0 : s.codePointCount(0, s.length());
    }
}

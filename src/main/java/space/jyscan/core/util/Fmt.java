package space.jyscan.core.util;

import java.lang.reflect.Array;
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

    /** Go 的 Duration.String()：如 "1.5s"、"2m3.5s"、"500ms"。 */
    private static String goDuration(Duration d) {
        long nanos = d.toNanos();
        if (nanos == 0) {
            return "0s";
        }
        String sign = "";
        if (nanos < 0) {
            sign = "-";
            nanos = -nanos;
        }
        long sec = nanos / 1_000_000_000L;
        long rem = nanos % 1_000_000_000L;

        long days = sec / 86400;
        sec %= 86400;
        long hours = sec / 3600;
        sec %= 3600;
        long mins = sec / 60;
        sec %= 60;

        StringBuilder sb = new StringBuilder(sign);
        if (days > 0) {
            sb.append(days).append('d');
        }
        if (hours > 0) {
            sb.append(hours).append("h");
        }
        if (mins > 0) {
            sb.append(mins).append("m");
        }
        boolean needSeconds = sb.length() == 0 || rem != 0 || sec != 0;
        if (needSeconds) {
            if (sb.length() > 0 && (rem != 0 || sb.charAt(sb.length() - 1) == 'm')) {
                // 分钟之后带秒
            }
            if (rem == 0) {
                sb.append(sec).append("s");
            } else {
                String frac = padLeft(Long.toString(rem), 9, '0');
                frac = stripTrailingZeros(frac);
                sb.append(sec).append('.').append(frac).append('s');
            }
        }
        return sb.toString();
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
        return quoteString(String.valueOf(arg));
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

    private static String goTypeName(Object arg) {
        if (arg == null) {
            return "<nil>";
        }
        Class<?> cls = arg.getClass();
        if (arg.getClass().isArray()) {
            return goTypeName(Array.get(arg, 0)) + "[]";
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
                String s = String.format("%." + p + "f", d);
                if (altForm && p == 0) {
                    s += ".";
                }
                return s;
            }
            case 'e': {
                int p = precision < 0 ? 6 : precision;
                String s = String.format("%." + p + (verb == 'E' ? "E" : "e"), d);
                // Go 输出 e+09 形式，Java 输出 E+9，补齐指数位宽
                return normalizeExponent(s, verb == 'E');
            }
            case 'g': {
                return goG(d, precision, verb == 'G');
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

    /** Go 的 %g：在 %e 与 %f 中选择更紧凑的那个。 */
    private static String goG(double d, int precision, boolean upper) {
        int p = precision;
        boolean hasPrecision = p >= 0;
        if (p < 0 || p == 0) {
            p = 1;
        }

        // 按 Go 规则：指数 < -4 或 >= precision 时用 %e
        double abs = Math.abs(d);
        int exp10 = 0;
        if (abs != 0) {
            exp10 = (int) Math.floor(Math.log10(abs));
        }
        boolean useExp = exp10 < -4 || exp10 >= p;

        String s;
        if (useExp) {
            s = normalizeExponent(String.format("%." + (p - 1) + (upper ? "E" : "e"), d), upper);
        } else {
            int frac = Math.max(0, p - 1 - exp10);
            if (!hasPrecision) {
                // 未指定精度时去掉多余的尾随零
                s = trimFloat(String.format("%." + frac + "f", d));
            } else {
                s = String.format("%." + frac + "f", d);
            }
        }
        return s;
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

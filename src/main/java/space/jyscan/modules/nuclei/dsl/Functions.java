package space.jyscan.modules.nuclei.dsl;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * DSL 内置函数注册表与实现，对应 Go 的 {@code freeclient/pkg/nuclei/dsl/functions.go}：
 * {@code ExpressionFunction} 类型（见 {@link ExpressionFunction}）、
 * {@code HelperFunctions}/{@code FunctionNames} 注册表、{@code init()} 注册的全部
 * {@code dsl*} 内置函数，以及 {@code toStringArg}/{@code toIntArg} 转换辅助。
 *
 * <p>Go 的 {@code func(args ...interface{}) (interface{}, error)} 映射为
 * {@code static Object[] dslXxx(Object[] args)}，二元返回按项目惯例为
 * {@code Object[]{值, Throwable}}，{@code [1] == null} 表示成功；
 * 错误值按 Go 原样保留在 {@code [0]}，由包级 {@code Eval.evaluate} 出口归一化。
 *
 * <p>注：Go 侧 {@code init()} 注册 54 个函数（源文件中 {@code register} 调用共 54 行）。
 */
public final class Functions {

    private Functions() {}

    /** 对应 Go 的 {@code var HelperFunctions = make(map[string]ExpressionFunction)}。 */
    public static final Map<String, ExpressionFunction> helperFunctions = new LinkedHashMap<>();

    /** 对应 Go 的 {@code var FunctionNames []string}（注册顺序）。 */
    public static final List<String> functionNames = new ArrayList<>();

    /** 对应 Go 的 {@code func register(name string, fn ExpressionFunction)}。 */
    static void register(String name, ExpressionFunction fn) {
        helperFunctions.put(name, fn);
        functionNames.add(name);
    }

    /** 对应 Go 的 {@code func init()}，按 Go 源文件顺序注册全部内置函数。 */
    static {
        register("contains", Functions::dslContains);
        register("icontains", Functions::dslIContains);
        register("starts_with", Functions::dslStartsWith);
        register("istarts_with", Functions::dslIStartsWith);
        register("ends_with", Functions::dslEndsWith);
        register("iends_with", Functions::dslIEndsWith);
        register("regex", Functions::dslRegex);
        register("iregex", Functions::dslIRegex);
        register("regex_extract", Functions::dslRegexExtract);
        register("replace", Functions::dslReplace);
        register("replace_regex", Functions::dslReplaceRegex);
        register("tolower", Functions::dslToLower);
        register("toupper", Functions::dslToUpper);
        register("trim", Functions::dslTrim);
        register("trim_left", Functions::dslTrimLeft);
        register("trim_right", Functions::dslTrimRight);
        register("trim_space", Functions::dslTrimSpace);
        register("trim_prefix", Functions::dslTrimPrefix);
        register("trim_suffix", Functions::dslTrimSuffix);
        register("substr", Functions::dslSubstr);
        register("len", Functions::dslLength);
        register("split", Functions::dslSplit);
        register("join", Functions::dslJoin);
        register("concat", Functions::dslConcat);
        register("repeat", Functions::dslRepeat);
        register("reverse", Functions::dslReverse);
        register("base64", Functions::dslBase64);
        register("base64_decode", Functions::dslBase64Decode);
        register("hex_encode", Functions::dslHexEncode);
        register("hex_decode", Functions::dslHexDecode);
        register("url_encode", Functions::dslURLEncode);
        register("url_decode", Functions::dslURLDecode);
        register("html_escape", Functions::dslHTMLEscape);
        register("html_unescape", Functions::dslHTMLUnescape);
        register("md5", Functions::dslMD5);
        register("sha1", Functions::dslSHA1);
        register("sha256", Functions::dslSHA256);
        register("int", Functions::dslToInt);
        register("float", Functions::dslToFloat);
        register("str", Functions::dslToStr);
        register("print_debug", Functions::dslPrintDebug);
        register("rand", Functions::dslRand);
        register("rand_int", Functions::dslRandInt);
        register("rand_alpha", Functions::dslRandAlpha);
        register("rand_alphanumeric", Functions::dslRandAlphaNumeric);
        register("rand_numeric", Functions::dslRandNumeric);
        register("equals", Functions::dslEquals);
        register("iequals", Functions::dslIEquals);
        register("greater_than", Functions::dslGreaterThan);
        register("less_than", Functions::dslLessThan);
        register("greater_than_or_equal", Functions::dslGreaterThanOrEqual);
        register("less_than_or_equal", Functions::dslLessThanOrEqual);
        register("unix_time", Functions::dslUnixTime);
        register("wait_for", Functions::dslWaitFor);
    }

    // ------------------------------------------------------------------
    // 转换辅助（对应 functions.go / eval.go 的包级辅助函数）
    // ------------------------------------------------------------------

    /**
     * 对应 Go 的 {@code func toStringArg(arg interface{}) string}：
     * nil → 空串；整数 → 十进制；float64 → Go {@code strconv.FormatFloat(v, 'f', -1, 64)}
     * 风格的最短非指数形式；bool → {@code "true"/"false"}；{@code []byte} → UTF-8 文本；
     * 切片 → {@code "[a b]"}（空格分隔）；map → {@code "map[k:v k2:v2]"}（按键排序）；
     * 其余类型对应 Go 的 {@code fmt.Sprintf("%v", v)}。
     */
    static String toStringArg(Object arg) {
        if (arg == null) {
            return "";
        }
        if (arg instanceof String s) {
            return s;
        }
        if (arg instanceof byte[] b) {
            return new String(b, StandardCharsets.UTF_8);
        }
        if (arg instanceof Integer i) {
            return Integer.toString(i);
        }
        if (arg instanceof Long l) {
            return Long.toString(l);
        }
        if (arg instanceof Double d) {
            return formatGoFloat(d);
        }
        if (arg instanceof Boolean b) {
            return b ? "true" : "false";
        }
        if (arg instanceof List<?> list) {
            return goListToString(list);
        }
        if (arg instanceof Object[] arr) {
            return goListToString(Arrays.asList(arr));
        }
        if (arg instanceof Map<?, ?> map) {
            return goMapToString(map);
        }
        return String.valueOf(arg);
    }

    private static String goListToString(List<?> list) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Object item : list) {
            if (!first) {
                sb.append(' ');
            }
            first = false;
            sb.append(toStringArg(item));
        }
        return sb.append(']').toString();
    }

    private static String goMapToString(Map<?, ?> map) {
        List<Map.Entry<?, ?>> entries = new ArrayList<>(map.entrySet());
        // Go fmt 自 Go 1.12 起按键排序输出 map（此处按键的字符串形式排序）
        entries.sort((a, b) -> toStringArg(a.getKey()).compareTo(toStringArg(b.getKey())));
        StringBuilder sb = new StringBuilder("map[");
        boolean first = true;
        for (Map.Entry<?, ?> e : entries) {
            if (!first) {
                sb.append(' ');
            }
            first = false;
            sb.append(toStringArg(e.getKey())).append(':').append(toStringArg(e.getValue()));
        }
        return sb.append(']').toString();
    }

    /**
     * 对应 Go 的 {@code strconv.FormatFloat(v, 'f', -1, 64)}（最短可往返的非指数十进制）
     * 与 {@code NaN}/{@code +Inf} 的文本表示；负零（如 {@code 0.0 * -1.0}）按 Go 输出 {@code "-0"}。
     */
    static String formatGoFloat(double d) {
        if (Double.isNaN(d)) {
            return "NaN";
        }
        if (Double.isInfinite(d)) {
            return d > 0 ? "+Inf" : "-Inf";
        }
        if (d == 0.0 && Double.doubleToRawLongBits(d) < 0) {
            return "-0"; // Go strconv.FormatFloat 对带符号的负零返回 "-0"（对 +0 返回 "0"）
        }
        return BigDecimal.valueOf(d).stripTrailingZeros().toPlainString();
    }

    /**
     * 对应 Go 的 {@code func toIntArg(arg interface{}) (int, error)}。
     * Go 的 {@code int} 为 64 位，这里统一以 {@code long} 表示（映射为 {@code Long}）。
     *
     * @return {@code Object[]{Long, Throwable}}；失败时值为 {@code 0L}、{@code [1]} 为异常
     */
    static Object[] toIntArg(Object arg) {
        if (arg instanceof Integer i) {
            return new Object[]{(long) i, null};
        }
        if (arg instanceof Long l) {
            return new Object[]{l, null};
        }
        if (arg instanceof Double d) {
            return new Object[]{(long) (double) d, null}; // Go: int(float64)，向零截断
        }
        if (arg instanceof String s) {
            try {
                return new Object[]{Long.parseLong(s), null}; // Go: strconv.Atoi
            } catch (NumberFormatException e) {
                return new Object[]{0L, e};
            }
        }
        return new Object[]{0L, new IllegalArgumentException("cannot convert to int")};
    }

    /** 对应 Go 的 {@code strconv.ParseFloat(s, 64)} 近似：成功返回数值（含 NaN/±Inf 字面量），
     * 语法非法或超出 float64 范围（Go 的 ErrRange）时返回 null。
     *
     * <p>已与 {@code Double.parseDouble} 的已知差异对齐：Java 接受首尾空白与
     * {@code d}/{@code f} 后缀而 Go 不接受（在此拒绝）；Java 溢出静默返回 Infinity
     * 而 Go 报错（在此视为失败）；Go 接受 {@code Inf}/{@code nan} 而 Java 不接受
     * （在此特判）。
     *
     * <p>已知残留差异：Go 还接受 {@code 1_0} 这类下划线分组（Java 拒绝）。
     */
    static Double parseGoFloat(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        for (int i = 0; i < s.length(); i++) {
            if (Character.isWhitespace(s.charAt(i))) {
                return null; // Go 不接受任何空白
            }
        }
        String body = s;
        boolean negative = false;
        if (body.startsWith("+")) {
            body = body.substring(1);
        } else if (body.startsWith("-")) {
            body = body.substring(1);
            negative = true;
        }
        if (body.equalsIgnoreCase("inf") || body.equalsIgnoreCase("infinity")) {
            return negative ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY;
        }
        if (body.equalsIgnoreCase("nan")) {
            return Double.NaN;
        }
        char last = s.charAt(s.length() - 1);
        if (last == 'd' || last == 'D' || last == 'f' || last == 'F') {
            return null; // Java 独有的 d/f 后缀，Go 不接受
        }
        if (!GO_FLOAT_PATTERN.matcher(s).matches()) {
            return null;
        }
        try {
            double d = Double.parseDouble(s);
            return Double.isInfinite(d) ? null : d; // Go 溢出时报 ErrRange
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** 对应 Go {@code strconv.ParseFloat} 接受的十进制/十六进制浮点与 Inf/NaN 文本。 */
    private static final Pattern GO_FLOAT_PATTERN = Pattern.compile(
            "[+-]?(?:\\d+(?:\\.\\d*)?|\\.\\d+)(?:[eE][+-]?\\d+)?"
                    + "|[+-]?0[xX][0-9a-fA-F]*(?:\\.[0-9a-fA-F]*)?[pP][+-]?\\d+"
                    + "|[+-]?(?:[iI][nN][fF](?:[iI][nN][iI][tT][yY])?)"
                    + "|[+-]?(?:[nN][aA][nN])");

    /** 构造参数个数错误（对应 Go 的 {@code fmt.Errorf("xxx() requires ...")}）。 */
    private static Object[] argError(String message) {
        return new Object[]{null, new IllegalArgumentException(message)};
    }

    // ------------------------------------------------------------------
    // 内置函数（对应 functions.go 的 dsl* 函数，逐个移植）
    // ------------------------------------------------------------------

    /** 对应 Go 的 {@code dslContains}。 */
    private static Object[] dslContains(Object[] args) {
        if (args.length != 2) {
            return argError("contains() requires 2 arguments");
        }
        return new Object[]{toStringArg(args[0]).contains(toStringArg(args[1])), null};
    }

    /** 对应 Go 的 {@code dslIContains}。 */
    private static Object[] dslIContains(Object[] args) {
        if (args.length != 2) {
            return argError("icontains() requires 2 arguments");
        }
        return new Object[]{
                toStringArg(args[0]).toLowerCase(Locale.ROOT).contains(toStringArg(args[1]).toLowerCase(Locale.ROOT)),
                null};
    }

    /** 对应 Go 的 {@code dslStartsWith}。 */
    private static Object[] dslStartsWith(Object[] args) {
        if (args.length != 2) {
            return argError("starts_with() requires 2 arguments");
        }
        return new Object[]{toStringArg(args[0]).startsWith(toStringArg(args[1])), null};
    }

    /** 对应 Go 的 {@code dslIStartsWith}。 */
    private static Object[] dslIStartsWith(Object[] args) {
        if (args.length != 2) {
            return argError("istarts_with() requires 2 arguments");
        }
        return new Object[]{
                toStringArg(args[0]).toLowerCase(Locale.ROOT).startsWith(toStringArg(args[1]).toLowerCase(Locale.ROOT)),
                null};
    }

    /** 对应 Go 的 {@code dslEndsWith}。 */
    private static Object[] dslEndsWith(Object[] args) {
        if (args.length != 2) {
            return argError("ends_with() requires 2 arguments");
        }
        return new Object[]{toStringArg(args[0]).endsWith(toStringArg(args[1])), null};
    }

    /** 对应 Go 的 {@code dslIEndsWith}。 */
    private static Object[] dslIEndsWith(Object[] args) {
        if (args.length != 2) {
            return argError("iends_with() requires 2 arguments");
        }
        return new Object[]{
                toStringArg(args[0]).toLowerCase(Locale.ROOT).endsWith(toStringArg(args[1]).toLowerCase(Locale.ROOT)),
                null};
    }

    /** 对应 Go 的 {@code dslRegex}。注意 Go 侧参数顺序：{@code regex(输入, 模式)}。 */
    private static Object[] dslRegex(Object[] args) {
        if (args.length != 2) {
            return new Object[]{false, new IllegalArgumentException("regex() requires 2 arguments")};
        }
        return Utils.globMatch(toStringArg(args[1]), toStringArg(args[0]));
    }

    /** 对应 Go 的 {@code dslIRegex}：模式前加 {@code (?i)} 忽略大小写。 */
    private static Object[] dslIRegex(Object[] args) {
        if (args.length != 2) {
            return new Object[]{false, new IllegalArgumentException("iregex() requires 2 arguments")};
        }
        return Utils.globMatch("(?i)" + toStringArg(args[1]), toStringArg(args[0]));
    }

    /** 对应 Go 的 {@code dslRegexExtract}。注意 Go 侧参数顺序：{@code regex_extract(模式, 输入)}。 */
    private static Object[] dslRegexExtract(Object[] args) {
        if (args.length != 2) {
            return argError("regex_extract() requires 2 arguments");
        }
        return Utils.regexExtract(toStringArg(args[0]), toStringArg(args[1]));
    }

    /** 对应 Go 的 {@code dslReplace}（{@code strings.ReplaceAll} 字面替换）。 */
    private static Object[] dslReplace(Object[] args) {
        if (args.length != 3) {
            return argError("replace() requires 3 arguments");
        }
        return new Object[]{
                toStringArg(args[0]).replace(toStringArg(args[1]), toStringArg(args[2])), null};
    }

    /** 对应 Go 的 {@code dslReplaceRegex}（参数顺序：输入、模式、替换）。 */
    private static Object[] dslReplaceRegex(Object[] args) {
        if (args.length != 3) {
            return argError("replace_regex() requires 3 arguments");
        }
        return Utils.regexReplace(toStringArg(args[0]), toStringArg(args[1]), toStringArg(args[2]));
    }

    /** 对应 Go 的 {@code dslToLower}。 */
    private static Object[] dslToLower(Object[] args) {
        if (args.length != 1) {
            return argError("tolower() requires 1 argument");
        }
        return new Object[]{toStringArg(args[0]).toLowerCase(Locale.ROOT), null};
    }

    /** 对应 Go 的 {@code dslToUpper}。 */
    private static Object[] dslToUpper(Object[] args) {
        if (args.length != 1) {
            return argError("toupper() requires 1 argument");
        }
        return new Object[]{toStringArg(args[0]).toUpperCase(Locale.ROOT), null};
    }

    /** 对应 Go 的 {@code dslTrim}（{@code strings.Trim} 的 cutset 字符集合语义）。 */
    private static Object[] dslTrim(Object[] args) {
        if (args.length != 2) {
            return argError("trim() requires 2 arguments");
        }
        return new Object[]{goTrim(toStringArg(args[0]), toStringArg(args[1])), null};
    }

    /** 对应 Go 的 {@code dslTrimLeft}。 */
    private static Object[] dslTrimLeft(Object[] args) {
        if (args.length != 2) {
            return argError("trim_left() requires 2 arguments");
        }
        return new Object[]{goTrimLeft(toStringArg(args[0]), toStringArg(args[1])), null};
    }

    /** 对应 Go 的 {@code dslTrimRight}。 */
    private static Object[] dslTrimRight(Object[] args) {
        if (args.length != 2) {
            return argError("trim_right() requires 2 arguments");
        }
        return new Object[]{goTrimRight(toStringArg(args[0]), toStringArg(args[1])), null};
    }

    /** 对应 Go 的 {@code dslTrimSpace}（{@code strings.TrimSpace} / {@code unicode.IsSpace}）。 */
    private static Object[] dslTrimSpace(Object[] args) {
        if (args.length != 1) {
            return argError("trim_space() requires 1 argument");
        }
        return new Object[]{goTrimSpace(toStringArg(args[0])), null};
    }

    /** 对应 Go 的 {@code dslTrimPrefix}。 */
    private static Object[] dslTrimPrefix(Object[] args) {
        if (args.length != 2) {
            return argError("trim_prefix() requires 2 arguments");
        }
        String s = toStringArg(args[0]);
        String prefix = toStringArg(args[1]);
        return new Object[]{s.startsWith(prefix) ? s.substring(prefix.length()) : s, null};
    }

    /** 对应 Go 的 {@code dslTrimSuffix}。 */
    private static Object[] dslTrimSuffix(Object[] args) {
        if (args.length != 2) {
            return argError("trim_suffix() requires 2 arguments");
        }
        String s = toStringArg(args[0]);
        String suffix = toStringArg(args[1]);
        return new Object[]{s.endsWith(suffix) ? s.substring(0, s.length() - suffix.length()) : s, null};
    }

    /**
     * 对应 Go 的 {@code dslSubstr}：按 UTF-8 字节索引切片（Go 的 {@code len(s)}/{@code s[a:b]}
     * 均为字节语义）。负 start 从末尾计数、负 length 从末尾截断；
     * Go 侧若干越界组合会 panic（如 {@code s[start:0]} 且 {@code start != 0}），
     * Java 侧以 {@link StringIndexOutOfBoundsException} 表达，由包级
     * {@code Eval.evaluate} 归一为求值失败。
     */
    private static Object[] dslSubstr(Object[] args) {
        if (args.length < 2 || args.length > 3) {
            return argError("substr() requires 2 or 3 arguments");
        }
        String s = toStringArg(args[0]);
        Object[] startRes = toIntArg(args[1]);
        if (startRes[1] != null) {
            return new Object[]{null, startRes[1]};
        }
        long start = (Long) startRes[0];
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        if (start < 0) {
            start = b.length + start;
        }
        if (start > b.length) {
            return new Object[]{"", null};
        }
        if (args.length == 3) {
            Object[] lenRes = toIntArg(args[2]);
            if (lenRes[1] != null) {
                return new Object[]{null, lenRes[1]};
            }
            long length = (Long) lenRes[0];
            if (length < 0) {
                if (b.length + length < 0) {
                    // Go: s[start:0] —— start != 0 时 panic（slice bounds out of range）
                    if (start != 0) {
                        return new Object[]{null,
                                new StringIndexOutOfBoundsException("slice bounds out of range")};
                    }
                    return new Object[]{"", null};
                }
                long end = b.length + length;
                if (start < 0 || start > end) {
                    // Go: s[start:end] 且 start > end 时 panic
                    return new Object[]{null,
                            new StringIndexOutOfBoundsException("slice bounds out of range")};
                }
                return new Object[]{sliceBytes(b, start, end), null};
            }
            long end = start + length;
            if (end > b.length) {
                end = b.length;
            }
            if (start < 0 || start > end) {
                // 负 start 或 start+length 溢出时，Go 侧切片 panic
                return new Object[]{null,
                        new StringIndexOutOfBoundsException("slice bounds out of range")};
            }
            return new Object[]{sliceBytes(b, start, end), null};
        }
        if (start < 0) {
            // Go: s[start:]（负索引）panic
            return new Object[]{null,
                    new StringIndexOutOfBoundsException("slice bounds out of range")};
        }
        return new Object[]{sliceBytes(b, start, b.length), null};
    }

    private static String sliceBytes(byte[] b, long start, long end) {
        return new String(Arrays.copyOfRange(b, (int) start, (int) end), StandardCharsets.UTF_8);
    }

    /**
     * 对应 Go 的 {@code dslLength}：字符串按字节数（Go {@code len(string)}）、
     * 列表/数组/映射按元素数，其余取 {@code toStringArg} 后的字节数。
     */
    private static Object[] dslLength(Object[] args) {
        if (args.length != 1) {
            return argError("len() requires 1 argument");
        }
        Object v = args[0];
        if (v instanceof String s) {
            return new Object[]{s.getBytes(StandardCharsets.UTF_8).length, null};
        }
        if (v instanceof List<?> list) {
            return new Object[]{list.size(), null};
        }
        if (v instanceof Object[] arr) {
            return new Object[]{arr.length, null}; // 对应 Go case []interface{}
        }
        if (v instanceof Map<?, ?> map) {
            return new Object[]{map.size(), null};
        }
        if (v instanceof byte[] b) {
            return new Object[]{b.length, null}; // Go 落入默认分支 len(string([]byte)) = 原字节数
        }
        return new Object[]{toStringArg(v).getBytes(StandardCharsets.UTF_8).length, null};
    }

    /**
     * 对应 Go 的 {@code dslSplit}（{@code strings.Split}）：sep 为空串时按码点切分，
     * 否则按字面量 sep 切分并保留末尾空串。
     */
    private static Object[] dslSplit(Object[] args) {
        if (args.length != 2) {
            return argError("split() requires 2 arguments");
        }
        String s = toStringArg(args[0]);
        String sep = toStringArg(args[1]);
        List<String> parts = new ArrayList<>();
        if (sep.isEmpty()) {
            // Go strings.Split(s, "")：逐 rune 切分（空串输入返回空切片，与 Go 一致）
            for (int i = 0; i < s.length(); ) {
                int cp = s.codePointAt(i);
                int n = Character.charCount(cp);
                parts.add(s.substring(i, i + n));
                i += n;
            }
            return new Object[]{parts, null};
        }
        int from = 0;
        while (true) {
            int idx = s.indexOf(sep, from);
            if (idx < 0) {
                break;
            }
            parts.add(s.substring(from, idx));
            from = idx + sep.length();
        }
        parts.add(s.substring(from));
        return new Object[]{parts, null};
    }

    /** 对应 Go 的 {@code dslJoin}：列表/切片按 sep 连接（元素经 toStringArg），其余返回其字符串形式。 */
    private static Object[] dslJoin(Object[] args) {
        if (args.length != 2) {
            return argError("join() requires 2 arguments");
        }
        String sep = toStringArg(args[1]);
        Object v = args[0];
        Object[] items = null;
        if (v instanceof List<?> list) {
            items = list.toArray(); // 对应 Go case []string 与 []interface{}
        } else if (v instanceof Object[] arr) {
            items = arr;
        }
        if (items != null) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < items.length; i++) {
                if (i > 0) {
                    sb.append(sep);
                }
                sb.append(toStringArg(items[i]));
            }
            return new Object[]{sb.toString(), null};
        }
        return new Object[]{toStringArg(v), null};
    }

    /** 对应 Go 的 {@code dslConcat}（任意个参数拼接）。 */
    private static Object[] dslConcat(Object[] args) {
        StringBuilder sb = new StringBuilder();
        for (Object a : args) {
            sb.append(toStringArg(a));
        }
        return new Object[]{sb.toString(), null};
    }

    /** 对应 Go 的 {@code dslRepeat}；负次数对应 Go {@code strings.Repeat} 的 panic。 */
    private static Object[] dslRepeat(Object[] args) {
        if (args.length != 2) {
            return argError("repeat() requires 2 arguments");
        }
        Object[] nRes = toIntArg(args[1]);
        if (nRes[1] != null) {
            return new Object[]{null, nRes[1]};
        }
        long n = (Long) nRes[0];
        String s = toStringArg(args[0]);
        if (n < 0) {
            // 对应 Go strings.Repeat 的 panic("strings: negative Repeat count")
            throw new IllegalArgumentException("strings: negative Repeat count");
        }
        if (s.length() > 0 && n > Integer.MAX_VALUE / (long) s.length()) {
            // 对应 Go strings.Repeat 的溢出 panic("strings: repeated total length overflow")
            throw new IllegalArgumentException("strings: repeated total length overflow");
        }
        StringBuilder sb = new StringBuilder();
        for (long i = 0; i < n; i++) {
            sb.append(s);
        }
        return new Object[]{sb.toString(), null};
    }

    /** 对应 Go 的 {@code dslReverse}：按 rune（码点）反转。 */
    private static Object[] dslReverse(Object[] args) {
        if (args.length != 1) {
            return argError("reverse() requires 1 argument");
        }
        int[] cps = toStringArg(args[0]).codePoints().toArray();
        for (int i = 0, j = cps.length - 1; i < j; i++, j--) {
            int t = cps[i];
            cps[i] = cps[j];
            cps[j] = t;
        }
        return new Object[]{new String(cps, 0, cps.length), null};
    }

    /** 对应 Go 的 {@code dslBase64}。 */
    private static Object[] dslBase64(Object[] args) {
        if (args.length != 1) {
            return argError("base64() requires 1 argument");
        }
        return new Object[]{Utils.base64EncodeStr(toStringArg(args[0])), null};
    }

    /** 对应 Go 的 {@code dslBase64Decode}。 */
    private static Object[] dslBase64Decode(Object[] args) {
        if (args.length != 1) {
            return argError("base64_decode() requires 1 argument");
        }
        return new Object[]{Utils.base64DecodeStr(toStringArg(args[0])), null};
    }

    /** 对应 Go 的 {@code dslHexEncode}。 */
    private static Object[] dslHexEncode(Object[] args) {
        if (args.length != 1) {
            return argError("hex_encode() requires 1 argument");
        }
        return new Object[]{Utils.hexEncodeStr(toStringArg(args[0])), null};
    }

    /** 对应 Go 的 {@code dslHexDecode}。 */
    private static Object[] dslHexDecode(Object[] args) {
        if (args.length != 1) {
            return argError("hex_decode() requires 1 argument");
        }
        return new Object[]{Utils.hexDecodeStr(toStringArg(args[0])), null};
    }

    /** 对应 Go 的 {@code dslURLEncode}。 */
    private static Object[] dslURLEncode(Object[] args) {
        if (args.length != 1) {
            return argError("url_encode() requires 1 argument");
        }
        return new Object[]{Utils.urlEncodeStr(toStringArg(args[0])), null};
    }

    /** 对应 Go 的 {@code dslURLDecode}。 */
    private static Object[] dslURLDecode(Object[] args) {
        if (args.length != 1) {
            return argError("url_decode() requires 1 argument");
        }
        return new Object[]{Utils.urlDecodeStr(toStringArg(args[0])), null};
    }

    /** 对应 Go 的 {@code dslHTMLEscape}（替换顺序与 Go 逐字一致）。 */
    private static Object[] dslHTMLEscape(Object[] args) {
        if (args.length != 1) {
            return argError("html_escape() requires 1 argument");
        }
        String s = toStringArg(args[0]);
        s = s.replace("&", "&amp;");
        s = s.replace("<", "&lt;");
        s = s.replace(">", "&gt;");
        s = s.replace("\"", "&quot;");
        s = s.replace("'", "&#39;");
        return new Object[]{s, null};
    }

    /** 对应 Go 的 {@code dslHTMLUnescape}（替换顺序与 Go 逐字一致）。 */
    private static Object[] dslHTMLUnescape(Object[] args) {
        if (args.length != 1) {
            return argError("html_unescape() requires 1 argument");
        }
        String s = toStringArg(args[0]);
        s = s.replace("&amp;", "&");
        s = s.replace("&lt;", "<");
        s = s.replace("&gt;", ">");
        s = s.replace("&quot;", "\"");
        s = s.replace("&#39;", "'");
        return new Object[]{s, null};
    }

    /** 对应 Go 的 {@code dslMD5}。 */
    private static Object[] dslMD5(Object[] args) {
        if (args.length != 1) {
            return argError("md5() requires 1 argument");
        }
        return new Object[]{Utils.md5HashStr(toStringArg(args[0])), null};
    }

    /** 对应 Go 的 {@code dslSHA1}。 */
    private static Object[] dslSHA1(Object[] args) {
        if (args.length != 1) {
            return argError("sha1() requires 1 argument");
        }
        return new Object[]{Utils.sha1HashStr(toStringArg(args[0])), null};
    }

    /** 对应 Go 的 {@code dslSHA256}。 */
    private static Object[] dslSHA256(Object[] args) {
        if (args.length != 1) {
            return argError("sha256() requires 1 argument");
        }
        return new Object[]{Utils.sha256HashStr(toStringArg(args[0])), null};
    }

    /** 对应 Go 的 {@code dslToInt}（直接返回 {@code toIntArg} 的二元组）。 */
    private static Object[] dslToInt(Object[] args) {
        if (args.length != 1) {
            return argError("int() requires 1 argument");
        }
        return toIntArg(args[0]);
    }

    /**
     * 对应 Go 的 {@code dslToFloat}：float64 原样返回、int 转 float、string 走
     * {@code strconv.ParseFloat}（失败返回 0 值+error），其余类型返回 0.0。
     * Go 的 {@code int}/{@code int64} 此处统一按 {@link Integer}/{@link Long} 处理。
     */
    private static Object[] dslToFloat(Object[] args) {
        if (args.length != 1) {
            return argError("float() requires 1 argument");
        }
        Object v = args[0];
        if (v instanceof Double d) {
            return new Object[]{d, null};
        }
        if (v instanceof Integer i) {
            return new Object[]{(double) i, null};
        }
        if (v instanceof Long l) {
            return new Object[]{(double) l, null};
        }
        if (v instanceof String str) {
            Double d = parseGoFloat(str);
            if (d == null) {
                return new Object[]{0.0, new NumberFormatException(str)};
            }
            return new Object[]{d, null};
        }
        return new Object[]{0.0, null};
    }

    /** 对应 Go 的 {@code dslToStr}。 */
    private static Object[] dslToStr(Object[] args) {
        if (args.length != 1) {
            return argError("str() requires 1 argument");
        }
        return new Object[]{toStringArg(args[0]), null};
    }

    /** 对应 Go 的 {@code dslPrintDebug}：打印 {@code [print_debug] <args>} 并返回第一个参数（无参返回 nil）。 */
    private static Object[] dslPrintDebug(Object[] args) {
        System.out.println("[print_debug] " + toStringArg(args));
        if (args.length > 0) {
            return new Object[]{args[0], null};
        }
        return new Object[]{null, null};
    }

    /** 对应 Go 的 {@code dslRand}：可选长度，默认 0（返回空串）；转换失败时按 Go 取默认值。 */
    private static Object[] dslRand(Object[] args) {
        int n = 0;
        if (args.length >= 1) {
            Object[] r = toIntArg(args[0]);
            if (r[1] == null) {
                n = (int) (long) (Long) r[0];
            }
        }
        return new Object[]{Utils.randomString(n), null};
    }

    /** 对应 Go 的 {@code dslRandInt}：默认 [0, 100)，min >= max 时返回 min。 */
    private static Object[] dslRandInt(Object[] args) {
        long min = 0;
        long max = 100;
        if (args.length >= 2) {
            Object[] r0 = toIntArg(args[0]);
            if (r0[1] == null) {
                min = (Long) r0[0];
            }
            Object[] r1 = toIntArg(args[1]);
            if (r1[1] == null) {
                max = (Long) r1[0];
            }
        }
        if (min >= max) {
            return new Object[]{min, null};
        }
        return new Object[]{min + Utils.randomInt((int) (max - min)), null};
    }

    /** 对应 Go 的 {@code dslRandAlpha}：默认长度 8。 */
    private static Object[] dslRandAlpha(Object[] args) {
        int n = 8;
        if (args.length >= 1) {
            Object[] r = toIntArg(args[0]);
            if (r[1] == null) {
                n = (int) (long) (Long) r[0];
            }
        }
        return new Object[]{Utils.randomStringAlpha(n), null};
    }

    /** 对应 Go 的 {@code dslRandAlphaNumeric}：默认长度 8。 */
    private static Object[] dslRandAlphaNumeric(Object[] args) {
        int n = 8;
        if (args.length >= 1) {
            Object[] r = toIntArg(args[0]);
            if (r[1] == null) {
                n = (int) (long) (Long) r[0];
            }
        }
        return new Object[]{Utils.randomStringAlphaNumeric(n), null};
    }

    /** 对应 Go 的 {@code dslRandNumeric}：默认长度 8。 */
    private static Object[] dslRandNumeric(Object[] args) {
        int n = 8;
        if (args.length >= 1) {
            Object[] r = toIntArg(args[0]);
            if (r[1] == null) {
                n = (int) (long) (Long) r[0];
            }
        }
        return new Object[]{Utils.randomStringNumeric(n), null};
    }

    /** 对应 Go 的 {@code dslEquals}（按字符串形式比较）。 */
    private static Object[] dslEquals(Object[] args) {
        if (args.length != 2) {
            return argError("equals() requires 2 arguments");
        }
        return new Object[]{toStringArg(args[0]).equals(toStringArg(args[1])), null};
    }

    /** 对应 Go 的 {@code dslIEquals}（{@code strings.EqualFold}，大小写不敏感）。 */
    private static Object[] dslIEquals(Object[] args) {
        if (args.length != 2) {
            return argError("iequals() requires 2 arguments");
        }
        return new Object[]{toStringArg(args[0]).equalsIgnoreCase(toStringArg(args[1])), null};
    }

    /** 对应 Go 的 {@code dslGreaterThan}（整数比较；转换失败返回 {@code (false, err)}）。 */
    private static Object[] dslGreaterThan(Object[] args) {
        if (args.length != 2) {
            return argError("greater_than() requires 2 arguments");
        }
        Object[] a = toIntArg(args[0]);
        if (a[1] != null) {
            return new Object[]{false, a[1]};
        }
        Object[] b = toIntArg(args[1]);
        if (b[1] != null) {
            return new Object[]{false, b[1]};
        }
        return new Object[]{(Long) a[0] > (Long) b[0], null};
    }

    /** 对应 Go 的 {@code dslLessThan}。 */
    private static Object[] dslLessThan(Object[] args) {
        if (args.length != 2) {
            return argError("less_than() requires 2 arguments");
        }
        Object[] a = toIntArg(args[0]);
        if (a[1] != null) {
            return new Object[]{false, a[1]};
        }
        Object[] b = toIntArg(args[1]);
        if (b[1] != null) {
            return new Object[]{false, b[1]};
        }
        return new Object[]{(Long) a[0] < (Long) b[0], null};
    }

    /** 对应 Go 的 {@code dslGreaterThanOrEqual}。 */
    private static Object[] dslGreaterThanOrEqual(Object[] args) {
        if (args.length != 2) {
            return argError("greater_than_or_equal() requires 2 arguments");
        }
        Object[] a = toIntArg(args[0]);
        if (a[1] != null) {
            return new Object[]{false, a[1]};
        }
        Object[] b = toIntArg(args[1]);
        if (b[1] != null) {
            return new Object[]{false, b[1]};
        }
        return new Object[]{(Long) a[0] >= (Long) b[0], null};
    }

    /** 对应 Go 的 {@code dslLessThanOrEqual}。 */
    private static Object[] dslLessThanOrEqual(Object[] args) {
        if (args.length != 2) {
            return argError("less_than_or_equal() requires 2 arguments");
        }
        Object[] a = toIntArg(args[0]);
        if (a[1] != null) {
            return new Object[]{false, a[1]};
        }
        Object[] b = toIntArg(args[1]);
        if (b[1] != null) {
            return new Object[]{false, b[1]};
        }
        return new Object[]{(Long) a[0] <= (Long) b[0], null};
    }

    /** 对应 Go 的 {@code dslUnixTime}（忽略参数，返回 float64 秒级时间戳）。 */
    private static Object[] dslUnixTime(Object[] args) {
        return new Object[]{(double) Utils.unixTimeNow(), null};
    }

    /** 对应 Go 的 {@code dslWaitFor}：至少 1 个参数，阻塞等待指定秒数后返回 true。 */
    private static Object[] dslWaitFor(Object[] args) {
        if (args.length < 1) {
            return argError("wait_for() requires at least 1 argument");
        }
        Object[] d = toIntArg(args[0]);
        if (d[1] != null) {
            return new Object[]{null, d[1]};
        }
        Utils.waitN((int) (long) (Long) d[0]);
        return new Object[]{true, null};
    }

    // ------------------------------------------------------------------
    // strings.* 语义的本地实现（对应 Go 标准库 strings / unicode）
    // ------------------------------------------------------------------

    /**
     * 对应 Go 的 {@code strings.Trim(s, cutset)}：cutset 视作“rune 集合”（非字符区间），
     * 删除字符串两端所有属于该集合的码点。
     */
    private static String goTrim(String s, String cutset) {
        int start = 0;
        int end = s.length();
        while (start < end && cutsetContains(cutset, s.codePointAt(start))) {
            start += Character.charCount(s.codePointAt(start));
        }
        while (end > start && cutsetContains(cutset, s.codePointBefore(end))) {
            end -= Character.charCount(s.codePointBefore(end));
        }
        return s.substring(start, end);
    }

    /** 对应 Go 的 {@code strings.TrimLeft(s, cutset)}。 */
    private static String goTrimLeft(String s, String cutset) {
        int start = 0;
        while (start < s.length() && cutsetContains(cutset, s.codePointAt(start))) {
            start += Character.charCount(s.codePointAt(start));
        }
        return s.substring(start);
    }

    /** 对应 Go 的 {@code strings.TrimRight(s, cutset)}。 */
    private static String goTrimRight(String s, String cutset) {
        int end = s.length();
        while (end > 0 && cutsetContains(cutset, s.codePointBefore(end))) {
            end -= Character.charCount(s.codePointBefore(end));
        }
        return s.substring(0, end);
    }

    private static boolean cutsetContains(String cutset, int cp) {
        for (int i = 0; i < cutset.length(); ) {
            int c = cutset.codePointAt(i);
            if (c == cp) {
                return true;
            }
            i += Character.charCount(c);
        }
        return false;
    }

    /** 对应 Go 的 {@code strings.TrimSpace(s)}（{@code unicode.IsSpace} 语义）。 */
    private static String goTrimSpace(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && isGoSpace(s.codePointAt(start))) {
            start += Character.charCount(s.codePointAt(start));
        }
        while (end > start && isGoSpace(s.codePointBefore(end))) {
            end -= Character.charCount(s.codePointBefore(end));
        }
        return s.substring(start, end);
    }

    /** 对应 Go 的 {@code unicode.IsSpace}：ASCII 空白 + U+0085/U+00A0 + Unicode 空白分隔符。 */
    private static boolean isGoSpace(int cp) {
        if (cp <= 0xFF) {
            return cp == '\t' || cp == '\n' || cp == 0x0B || cp == '\f' || cp == '\r'
                    || cp == ' ' || cp == 0x85 || cp == 0xA0;
        }
        return cp == 0x1680 || (cp >= 0x2000 && cp <= 0x200A)
                || cp == 0x2028 || cp == 0x2029 || cp == 0x202F || cp == 0x205F || cp == 0x3000;
    }
}

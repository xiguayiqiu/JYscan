package space.jyscan.modules.nuclei.variable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 变量渲染引擎，对应 Go 的 {@code variable.Engine}（{@code variable.go}）。
 *
 * <p>跨包契约：protocol 与 runner 两包持有本类型字段 {@code varEngine}，调用
 * {@link #registerFunction(String, UnaryOperator)} 与 {@link #render(String, Map)}。
 *
 * <p>Go 的 {@code RegisterFunction(name string, fn func(string) string)} 映射为
 * {@code UnaryOperator<String>}（入参类型同为 String、返回同为 String）。
 *
 * <p>runner 的 {@code registerVariableFunctions} 会注册
 * {@code base64}/{@code url_encode}/{@code url_decode}/{@code md5}/{@code sha256}/
 * {@code hex_encode}/{@code hex_decode} 七个函数，其函数体调用 protocol 包的静态编解码方法。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/variable/variable.go}。
 */
public class Engine {

    /** 对应 Go 的 {@code Engine.Functions map[string]func(string) string}（Go 为导出字段）。 */
    private final Map<String, UnaryOperator<String>> functions = new HashMap<>();

    /**
     * 对应 Go 的包级变量 {@code variableRegex = regexp.MustCompile(`\{\{([^}]+)\}\}`)}。
     */
    private static final Pattern VARIABLE_REGEX = Pattern.compile("\\{\\{([^}]+)\\}\\}");

    /** 对应 Go 的 {@code NewEngine() *Engine}。 */
    public Engine() {
    }

    /** 对应 Go 的 {@code (e *Engine) RegisterFunction(name string, fn func(string) string)}。 */
    public void registerFunction(String name, UnaryOperator<String> fn) {
        functions.put(name, fn);
    }

    /**
     * 渲染带 {@code {{...}}} 的模板串。
     *
     * <p>对应 Go 的 {@code (e *Engine) Render(s string, vars map[string]interface{}) string}。
     * Go 侧不返回错误，无法解析时按 Go 的降级行为返回：
     * <ul>
     *   <li>{@code expr} 中含 {@code (} 且括号前的函数名已注册 → 调用该函数
     *       （参数为去掉一对外层括号的原文，同 Go 的 {@code TrimPrefix/(}/ {@code TrimSuffix/)}）；</li>
     *   <li>否则查变量表，命中则按 Go 的 {@code fmt.Sprintf("%v", v)} 格式化（见 {@link #fmtGoV}）；</li>
     *   <li>都未命中 → 原样保留整个 {@code {{...}}} 片段。</li>
     * </ul>
     *
     * <p>替换实现用逐段追加的 {@link Matcher} 循环，对应 Go 的
     * {@code ReplaceAllStringFunc}——经实测（go1.27）该函数对回调返回值不做 {@code $} 展开，
     * 故 Java 侧也按字面量拼接（不用 {@code Matcher.appendReplacement} 的替换语法）。
     */
    public String render(String s, Map<String, Object> vars) {
        if (s == null || s.isEmpty()) {
            // Go: if s == "" { return s }
            return s;
        }
        Matcher matcher = VARIABLE_REGEX.matcher(s);
        StringBuilder sb = new StringBuilder();
        int last = 0;
        while (matcher.find()) {
            sb.append(s, last, matcher.start());
            String match = matcher.group();
            String expr = match.substring(2, match.length() - 2).strip(); // Go: strings.TrimSpace

            // Go: if idx := strings.Index(expr, "("); idx > 0
            int idx = expr.indexOf('(');
            if (idx > 0) {
                String fnName = expr.substring(0, idx).strip(); // Go: strings.TrimSpace
                UnaryOperator<String> fn = functions.get(fnName);
                if (fn != null) {
                    // Go: args := strings.TrimSuffix(strings.TrimPrefix(expr[idx:], "("), ")")
                    String args = expr.substring(idx + 1);
                    if (args.endsWith(")")) {
                        args = args.substring(0, args.length() - 1);
                    }
                    sb.append(fn.apply(args));
                    last = matcher.end();
                    continue;
                }
            }

            // Go: if v, ok := vars[expr]; ok { return fmt.Sprintf("%v", v) }
            if (vars != null && vars.containsKey(expr)) {
                sb.append(fmtGoV(vars.get(expr)));
                last = matcher.end();
                continue;
            }

            // Go: return match（未解析的占位符原样保留）
            sb.append(match);
            last = matcher.end();
        }
        sb.append(s, last, s.length());
        return sb.toString();
    }

    /**
     * 递归渲染任意值。
     *
     * <p>对应 Go 的 {@code (e *Engine) RenderValue(v interface{}, vars map[string]interface{}) interface{}}：
     * 字符串走 {@link #render}，map/list 递归重建，其余类型原样返回。
     *
     * <p>类型分支说明：Go 的 {@code case map[string]interface{}} / {@code case []interface{}}
     * 对应 snakeyaml 解出的 {@link Map} / {@link List}（键按 {@code String.valueOf} 归一，
     * snakeyaml 的键类型是 {@code Object}，而 yaml.v3 恒为 {@code string}）。
     */
    public Object renderValue(Object v, Map<String, Object> vars) {
        if (v instanceof String s) {
            return render(s, vars);
        }
        if (v instanceof Map<?, ?> map) {
            Map<String, Object> result = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                result.put(String.valueOf(e.getKey()), renderValue(e.getValue(), vars));
            }
            return result;
        }
        if (v instanceof List<?> list) {
            List<Object> result = new ArrayList<>(list.size());
            for (Object item : list) {
                result.add(renderValue(item, vars));
            }
            return result;
        }
        // Go: default: return v
        return v;
    }

    // =====================================================================
    // Go fmt.Sprintf("%v", ...) 的近似实现
    // =====================================================================

    /**
     * 对应 Go 的 {@code fmt.Sprintf("%v", v)}（variable.go:39 的变量字符串化）。
     *
     * <p>覆盖 Go 常见取值：{@code nil}→{@code <nil>}、布尔/整数原样、浮点按 Go 的
     * {@code %g} 精简风格（整数值不带 {@code .0}、{@code NaN}/{@code ±Inf}）、
     * map→{@code map[k:v ...]}（键按字面排序，同 Go fmt 对 map 键的排序）、
     * list→{@code [a b ...]}。指数形式与嵌套结构的极端排版细节与 Go fmt 不完全一致
     * （Go-parity 优先于复刻 fmt 的全部排版规则）。
     */
    private static String fmtGoV(Object v) {
        if (v == null) {
            return "<nil>";
        }
        if (v instanceof Boolean || v instanceof String) {
            return v.toString();
        }
        if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d)) {
                return "NaN";
            }
            if (d == Double.POSITIVE_INFINITY) {
                return "+Inf";
            }
            if (d == Double.NEGATIVE_INFINITY) {
                return "-Inf";
            }
            // Go %v 打印整数值的 float64 不带小数点: 3 → "3"
            if (d == Math.rint(d) && Math.abs(d) < 1e15) {
                return Long.toString((long) d);
            }
            String s = String.valueOf(d);
            int e = s.indexOf('E');
            if (e >= 0) {
                String mantissa = s.substring(0, e);
                if (mantissa.endsWith(".0")) {
                    mantissa = mantissa.substring(0, mantissa.length() - 2);
                }
                String exp = s.substring(e + 1);
                char sign = exp.charAt(0);
                if (sign == '-') {
                    return mantissa + "e" + exp;
                }
                return mantissa + "e+" + exp;
            }
            return s;
        }
        if (v instanceof Number) {
            return v.toString();
        }
        if (v instanceof Map<?, ?> map) {
            // Go fmt 对 map 按键排序后输出 "map[k:v k2:v2]"
            Map<String, Object> sorted = new GoFmtSortedMap(map);
            StringBuilder sb = new StringBuilder("map[");
            boolean first = true;
            for (Map.Entry<String, Object> e : sorted.entrySet()) {
                if (!first) {
                    sb.append(' ');
                }
                first = false;
                sb.append(e.getKey()).append(':').append(fmtGoV(e.getValue()));
            }
            return sb.append(']').toString();
        }
        if (v instanceof List<?> list) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    sb.append(' ');
                }
                sb.append(fmtGoV(list.get(i)));
            }
            return sb.append(']').toString();
        }
        return v.toString();
    }

    /** 把任意 map 的键按 {@link #fmtGoV} 结果排序收集（对应 Go fmt 对 map 键的字节序排序）。 */
    private static final class GoFmtSortedMap extends java.util.TreeMap<String, Object> {
        private static final long serialVersionUID = 1L;

        GoFmtSortedMap(Map<?, ?> source) {
            for (Map.Entry<?, ?> e : source.entrySet()) {
                put(fmtGoV(e.getKey()), e.getValue());
            }
        }
    }
}

package space.jyscan.modules.nuclei.operators;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import space.jyscan.core.util.Fmt;
import space.jyscan.modules.nuclei.matcher.MatchResult;
import space.jyscan.modules.nuclei.model.Extractor;
import space.jyscan.modules.nuclei.model.Info;
import space.jyscan.modules.nuclei.model.Matcher;
import space.jyscan.modules.nuclei.model.Template;
import space.jyscan.modules.nuclei.protocol.ProtocolResult;

/**
 * operators 引擎，对应 Go 的 {@code operators.Engine}。
 *
 * <p>跨包契约：runner 持有字段 {@code engine}，只调用
 * {@link #processWithMatcher(List, String, Map, Info)} 与
 * {@link #extract(List, ProtocolResult)} 两个方法（runner.go / flow.go 共 6 处）。
 *
 * <p>Go 侧 {@code NewEngine()} 组装三个子引擎：{@code matchEngine}（matcher）、
 * {@code extractEngine}（extractor）、{@code dslEval}（dsl），本类按同一结构持有它们
 * （{@code dslEval} 在 Go 的 operators.go 中组装后未被引用，按 Go 结构保留）。
 *
 * <p><b>二元返回映射：</b>Go 的 {@code (bool, string)} 按项目既有惯例
 * （见 {@code TcpFingerprint.matchOSFingerprint → Object[]{String, Double}}）
 * 映射为 {@code Object[]{Boolean, String}}：{@code [0]} 为是否命中、{@code [1]} 为命中的
 * matcher 名称（Go 注释：nuclei 官方 {@code [template-id:matcher-name]} 格式）。
 *
 * <p>包级助手 {@code matchResult}/{@code matchStatusCode}/{@code matchSize}/
 * {@code toStatusCode}/{@code extractTarget}（operators.go 的小写包级函数）
 * 以包私有静态方法放在本类内。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/operators/operators.go}
 */
public class Engine {

    /** 对应 Go 的 {@code matchEngine *matcher.Engine}。 */
    private final space.jyscan.modules.nuclei.matcher.Engine matchEngine;
    /** 对应 Go 的 {@code extractEngine *extractor.Engine}。 */
    private final space.jyscan.modules.nuclei.extractor.Engine extractEngine;
    /** 对应 Go 的 {@code dslEval *dsl.Evaluator}。 */
    private final space.jyscan.modules.nuclei.dsl.Evaluator dslEval;

    /**
     * 对应 Go 的 {@code NewEngine() *Engine}：依次构造 matcher、extractor、dsl 三个子引擎。
     */
    public Engine() {
        this.matchEngine = new space.jyscan.modules.nuclei.matcher.Engine();
        this.extractEngine = new space.jyscan.modules.nuclei.extractor.Engine();
        this.dslEval = new space.jyscan.modules.nuclei.dsl.Evaluator();
    }

    /**
     * 依次跑 matchers，只关心是否命中。
     *
     * <p>对应 Go 的 {@code (e *Engine) Process(matchers []*model.Matcher, condition string, data map[string]interface{}, info model.Info) bool}，
     * 其实现为 {@code matched, _ := e.ProcessWithMatcher(...)}。
     */
    public boolean process(List<Matcher> matchers, String condition,
                           Map<String, Object> data, Info info) {
        Object[] r = processWithMatcher(matchers, condition, data, info);
        return (Boolean) r[0];
    }

    /**
     * 同时返回命中的 matcher 名称（nuclei 官方风格）。
     *
     * <p>对应 Go 的 {@code (e *Engine) ProcessWithMatcher(...) (bool, string)}。
     * condition 为空补 {@code "or"}，随后 {@code strings.ToLower} 分发
     * and / or / default（default 走 or，与 Go 的 {@code getCondition} 语义一致）。
     * Go 侧入参 {@code info} 在函数体内未使用，按 Go 签名保留。
     *
     * @return {@code Object[]{Boolean, String}}
     */
    public Object[] processWithMatcher(List<Matcher> matchers, String condition,
                                       Map<String, Object> data, Info info) {
        if (matchers == null || matchers.isEmpty()) {
            return new Object[]{Boolean.TRUE, ""};
        }

        if (condition == null || condition.isEmpty()) {
            condition = "or";
        }
        condition = condition.toLowerCase(Locale.ROOT);

        switch (condition) {
            case "and":
                return processAndWithMatcher(matchers, data);
            case "or":
                return processOrWithMatcher(matchers, data);
            default:
                return processOrWithMatcher(matchers, data);
        }
    }

    // nuclei 官方: 每个 matcher 的 Result() 函数处理 Negative 翻转
    // 不要在这里额外处理 negative, 让 match() 内部统一处理

    /**
     * AND 分发，对应 Go 的 {@code (e *Engine) processAndWithMatcher}：
     * 全部命中才 true，名称取最后一个命中的 matcher。
     */
    Object[] processAndWithMatcher(List<Matcher> matchers, Map<String, Object> data) {
        String lastName = "";
        for (Matcher m : matchers) {
            if (!match(m, data)) {
                return new Object[]{Boolean.FALSE, ""};
            }
            lastName = m.getName();
        }
        return new Object[]{Boolean.TRUE, lastName};
    }

    /**
     * OR 分发，对应 Go 的 {@code (e *Engine) processOrWithMatcher}：
     * 第一个命中即返回其名称。
     */
    Object[] processOrWithMatcher(List<Matcher> matchers, Map<String, Object> data) {
        for (Matcher m : matchers) {
            if (match(m, data)) {
                return new Object[]{Boolean.TRUE, m.getName()};
            }
        }
        return new Object[]{Boolean.FALSE, ""};
    }

    /**
     * 统一匹配入口: 处理所有 matcher 类型 + Negative 翻转，对应 Go 的
     * {@code (e *Engine) match(m *model.Matcher, data map[string]interface{}) bool}。
     *
     * <p>完全遵循 nuclei 官方逻辑：
     * <ul>
     *   <li>matcher.Result() 根据 Negative 标志翻转结果；</li>
     *   <li>对 status 类型特殊处理, 直接从 data 取 status_code；</li>
     *   <li>对其他类型, 从 data 提取 part 文本进行匹配。</li>
     * </ul>
     */
    boolean match(Matcher m, Map<String, Object> data) {
        // 空数据检查: 避免空响应误报
        if (data == null) {
            return false;
        }

        switch (m.getType()) {
            case "status": {
                // nuclei 官方: status 匹配, Result() 处理 negative
                Object[] statusCode = toStatusCode(data.get("status_code"));
                if (!(Boolean) statusCode[1]) {
                    return false;
                }
                return matchResult(m, matchStatusCode(m, (Integer) statusCode[0]));
            }
            case "size": {
                String target = extractTarget(m.getPart(), data);
                return matchResult(m, matchSize(m, target));
            }
            default: {
                // word, regex, binary, dsl, xpath 等
                String target = extractTarget(m.getPart(), data);
                if (!"dsl".equals(m.getType()) && target.isEmpty()) {
                    // nuclei 官方: 空数据不匹配 (非 DSL 类型)
                    return false;
                }
                MatchResult matched = matchEngine.match(m, target, data);
                return matchResult(m, matched.matched);
            }
        }
    }

    /**
     * nuclei 官方: matcher.Result() 根据 Negative 翻转结果。
     * 对应 Go 的包级函数 {@code matchResult}。
     */
    static boolean matchResult(Matcher m, boolean matched) {
        if (m.negative) {
            return !matched;
        }
        return matched;
    }

    /**
     * nuclei 官方: 状态码匹配 (不含 Negative 翻转)。对应 Go 的包级函数 {@code matchStatusCode}。
     */
    static boolean matchStatusCode(Matcher m, int statusCode) {
        if (m.status == null) {
            return false;
        }
        for (Integer s : m.status) {
            if (statusCode == s) {
                return true;
            }
        }
        return false;
    }

    /**
     * nuclei 官方: 大小匹配 (不含 Negative 翻转)。对应 Go 的包级函数 {@code matchSize}。
     * {@code size := len(target)} 是 Go 的字节数，Java 侧同按 UTF-8 字节数计算。
     */
    static boolean matchSize(Matcher m, String target) {
        if (m.size == null) {
            return false;
        }
        int size = target.getBytes(StandardCharsets.UTF_8).length;
        for (Integer s : m.size) {
            if (size == s) {
                return true;
            }
        }
        return false;
    }

    /**
     * 从 data 中提取状态码为 int，对应 Go 的包级函数 {@code toStatusCode}。
     *
     * <p>返回 {@code Object[]{Integer, Boolean}}（Go 的 {@code (int, bool)}），
     * {@code [1] == Boolean.FALSE} 表示无法解析。
     *
     * <p>类型分支对应 Go：int/int64/int32/float64/string；string 走
     * {@code fmt.Sscanf(x, "%d", &n)} 语义（已用 go1.27 实测：跳过前导空白、
     * 允许尾部残留输入，如 {@code "200 OK"} → 200 成功、{@code "abc"} 报错）。
     */
    static Object[] toStatusCode(Object v) {
        if (v instanceof Integer i) {
            return new Object[]{i, Boolean.TRUE};
        }
        if (v instanceof Long l) {
            return new Object[]{(int) (long) l, Boolean.TRUE};
        }
        if (v instanceof Short s) {
            return new Object[]{s.intValue(), Boolean.TRUE};
        }
        if (v instanceof Byte b) {
            return new Object[]{b.intValue(), Boolean.TRUE};
        }
        if (v instanceof Float f) {
            return new Object[]{f.intValue(), Boolean.TRUE};
        }
        if (v instanceof Double d) {
            return new Object[]{d.intValue(), Boolean.TRUE};
        }
        if (v instanceof String x) {
            int[] r = scanInt(x);
            if (r[1] == 0) {
                return new Object[]{0, Boolean.FALSE};
            }
            return new Object[]{r[0], Boolean.TRUE};
        }
        return new Object[]{0, Boolean.FALSE};
    }

    /**
     * 对应 Go {@code fmt.Sscanf(x, "%d", &n)} 的整数扫描：跳过前导空白，
     * 解析可选符号 + 十进制数字前缀；无数字或溢出视为失败（Go 侧 err != nil）。
     *
     * @return {@code int[]{值, ok}}，{@code [1]==0} 表示失败
     */
    private static int[] scanInt(String x) {
        int i = 0;
        final int n = x.length();
        while (i < n && Character.isWhitespace(x.charAt(i))) {
            i++;
        }
        int start = i;
        if (i < n && (x.charAt(i) == '+' || x.charAt(i) == '-')) {
            i++;
        }
        int digits = i;
        while (i < n && x.charAt(i) >= '0' && x.charAt(i) <= '9') {
            i++;
        }
        if (i == digits) {
            return new int[]{0, 0};
        }
        try {
            return new int[]{Integer.parseInt(x.substring(start, i)), 1};
        } catch (NumberFormatException e) {
            return new int[]{0, 0};
        }
    }

    /**
     * nuclei 官方: 根据 part 从 data 中提取要匹配的文本，对应 Go 的包级函数
     * {@code extractTarget}。重要: {@code "all"} 类型组合 body + all_headers。
     *
     * <p>part 分支逐一对应 Go：{@code ""}（默认 part 是 body，Go 的 fallthrough 并入
     * body 分支）/ body / all / header、headers、all_headers / status、status_code /
     * url / hostname / host / matched / default（data[part] 原样取字符串）。
     */
    static String extractTarget(String part, Map<String, Object> data) {
        if (data == null) {
            return "";
        }
        switch (part) {
            case "":
                // nuclei 官方: 默认 part 是 body（Go: part = "body"; fallthrough）
            case "body": {
                Object v = data.get("body");
                if (v instanceof String s) {
                    return s;
                }
                Object raw = data.get("raw");
                if (raw instanceof String s) {
                    return s;
                }
                break;
            }
            case "all": {
                // nuclei 官方: "all" 组合 body + headers
                StringBuilder b = new StringBuilder();
                Object v = data.get("body");
                if (v instanceof String s) {
                    b.append(s);
                }
                Object h = data.get("all_headers");
                if (h instanceof String s) {
                    b.append(s);
                }
                return b.toString();
            }
            case "header":
            case "headers":
            case "all_headers": {
                Object v = data.get("all_headers");
                if (v instanceof String s) {
                    return s;
                }
                break;
            }
            case "status":
            case "status_code": {
                if (data.containsKey("status_code")) {
                    return Fmt.format("%v", data.get("status_code"));
                }
                break;
            }
            case "url": {
                Object v = data.get("url");
                if (v instanceof String s) {
                    return s;
                }
                break;
            }
            case "hostname": {
                Object v = data.get("hostname");
                if (v instanceof String s) {
                    return s;
                }
                break;
            }
            case "host": {
                Object v = data.get("host");
                if (v instanceof String s) {
                    return s;
                }
                break;
            }
            case "matched": {
                Object v = data.get("matched");
                if (v instanceof String s) {
                    return s;
                }
                break;
            }
            default: {
                Object v = data.get(part);
                if (v instanceof String s) {
                    return s;
                }
                break;
            }
        }
        return "";
    }

    /**
     * 对应 Go 的 {@code (e *Engine) Extract(extractors []*model.Extractor, result *protocol.ProtocolResult) map[string]string}。
     * Go 在 extractors 为空时返回 nil；Java 返回非 null 的空 map（{@code len()} 语义一致）。
     *
     * <p>每个 extractor 先按 part 取目标串（body/all/"" → {@code result.Raw}，
     * status → 去空格的状态码，其余从 {@code result.Data} 取），再交给子引擎；
     * 提取值 {@code TrimSpace} 后为空的丢弃（nuclei 官方: 空提取值不加入结果）。
     *
     * <p><b>nuclei-dev 对齐(误报修复)：</b>{@code internal: true} 的提取器被整体跳过 ——
     * 其值在 nuclei 中只进入 {@code DynamicValues}、不进入结果输出（{@code operators.Execute}
     * 仅非 internal 计入 {@code Extracts/OutputExtracts}）；freeclient 未区分 internal，
     * 其值会并入输出并被「无 matcher 发射门」放行 → 误报。
     */
    public Map<String, String> extract(List<Extractor> extractors, ProtocolResult result) {
        if (extractors == null || extractors.isEmpty()) {
            return new LinkedHashMap<>();
        }

        Map<String, String> combined = new LinkedHashMap<>();
        // Go 对 nil map 的读取是安全的（零值/缺失），Java 侧以空 map 等价承接
        Map<String, Object> data = result.data == null ? Map.of() : result.data;

        for (Extractor ex : extractors) {
            // nuclei-dev 对齐(误报修复): internal 提取器只产出 dynamic values，不进入
            // 结果输出（nuclei operators.Execute: internal → DynamicValues，仅非 internal
            // 计入 Extracts/OutputExtracts）。freeclient 未区分 internal，其值会并入输出、
            // 并被「无 matcher 发射门」放行 → 误报，此处按 nuclei 语义过滤。
            if (ex.internal) {
                continue;
            }
            String target = "";
            String part = ex.getPart();
            switch (part) {
                case "body":
                case "all":
                case "":
                    target = result.raw;
                    break;
                case "header":
                case "headers": {
                    Object raw = data.get("all_headers");
                    if (raw instanceof String s) {
                        target = s;
                    }
                    break;
                }
                case "status":
                case "status_code": {
                    Object code = data.get("status_code");
                    if (code != null) {
                        // 对应 Go: strings.TrimSpace(strings.ReplaceAll(fmt.Sprintf("%v", code), " ", ""))
                        target = Fmt.format("%v", code).replace(" ", "").trim();
                    }
                    break;
                }
                case "url": {
                    Object u = data.get("url");
                    if (u instanceof String s) {
                        target = s;
                    }
                    break;
                }
                case "hostname": {
                    Object h = data.get("hostname");
                    if (h instanceof String s) {
                        target = s;
                    }
                    break;
                }
                case "host": {
                    Object h = data.get("host");
                    if (h instanceof String s) {
                        target = s;
                    }
                    break;
                }
                case "matched": {
                    Object m = data.get("matched");
                    if (m instanceof String s) {
                        target = s;
                    }
                    break;
                }
                default: {
                    Object v = data.get(part);
                    if (v != null) {
                        target = Fmt.format("%v", v);
                    }
                    break;
                }
            }

            Map<String, String> extracted = extractEngine.extract(ex, target, result.data);
            for (Map.Entry<String, String> entry : extracted.entrySet()) {
                String v = entry.getValue();
                // 跳过空值提取 (nuclei 官方: 空提取值不加入结果)
                if (v == null || v.trim().isEmpty()) {
                    continue;
                }
                combined.put(entry.getKey(), v);
            }
        }

        return combined;
    }

    /**
     * 模板级提取，对应 Go 的
     * {@code (e *Engine) ExtractTemplateLevel(template *model.Template, result *protocol.ProtocolResult) map[string]string}。
     * extractors 为空时 Go 返回 nil，Java 返回非 null 空 map。
     */
    public Map<String, String> extractTemplateLevel(Template template, ProtocolResult result) {
        List<Extractor> extractors = template.extractors;
        if (extractors == null || extractors.isEmpty()) {
            return new LinkedHashMap<>();
        }
        return extract(extractors, result);
    }

    /**
     * 模板级匹配，对应 Go 的
     * {@code (e *Engine) MatchTemplateLevel(template *model.Template, data map[string]interface{}) bool}。
     * 无 matchers → true；condition 为空补 {@code "or"}。
     */
    public boolean matchTemplateLevel(Template template, Map<String, Object> data) {
        List<Matcher> matchers = template.matchers;
        if (matchers == null || matchers.isEmpty()) {
            return true;
        }

        String condition = template.matchersCondition;
        if (condition == null || condition.isEmpty()) {
            condition = "or";
        }

        return process(matchers, condition, data, template.info);
    }
}

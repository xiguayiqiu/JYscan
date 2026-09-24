package space.jyscan.modules.nuclei.matcher;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import space.jyscan.modules.nuclei.dsl.Evaluator;
import space.jyscan.modules.nuclei.model.Matcher;

/**
 * 匹配器引擎，对应 Go 的 {@code matcher.Engine}。
 *
 * <p>跨包契约：operators 持有字段 {@code matchEngine}，只调用
 * {@link #match(Matcher, String, Map)}。
 *
 * <p>Go 侧 {@code NewEngine()} 构造 {@code dsl.NewEvaluator()} 作为 {@code dslEvaluator}，
 * 供 {@code matchDSL} 分支使用。Go 的分发类型见 {@code Match} 内 switch：
 * word / regex / binary / dsl / xpath（status、size 两个类型由 operators 层处理，
 * 不进入本引擎）。
 *
 * <p>包级助手 {@code getCondition}/{@code containsBytes}（matcher.go 的小写包级函数）
 * 以包私有静态方法形式放在本类内；{@code literalPrefix}/{@code decodeHex} 是为移植
 * {@code regexp.LiteralPrefix}/{@code hex.DecodeString} 而加的 Java 侧等价助手。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/matcher/matcher.go}
 */
public class Engine {

    /** 对应 Go 的 {@code dslEvaluator *dsl.Evaluator}。 */
    private final Evaluator dslEvaluator;

    /** 对应 Go 的 {@code NewEngine() *Engine}：{@code dsl.NewEvaluator()}。 */
    public Engine() {
        this.dslEvaluator = new Evaluator();
    }

    /**
     * 执行匹配（nuclei 官方：根据类型分发）。
     *
     * <p>对应 Go 的 {@code (e *Engine) Match(m *model.Matcher, target string, data map[string]interface{}) *MatchResult}。
     *
     * <p>契约注记：Go 的实现<b>从不返回 nil</b>（正则编译失败在 {@code matchRegex} 内
     * 以 {@code continue} 处理、未知类型返回 {@code &MatchResult{Matched:false}}），
     * 故 Java 侧恒返回非 null，失败场景一律以 {@code matched == false} 表达。
     */
    public MatchResult match(Matcher m, String target, Map<String, Object> data) {
        String t = m.getType();
        switch (t) {
            case "word":
                return matchWord(m, target, data);
            case "regex":
                return matchRegex(m, target);
            case "binary":
                return matchBinary(m, target);
            case "dsl":
                return matchDSL(m, data);
            case "xpath":
                return matchXPath(m, target);
            default:
                return new MatchResult();
        }
    }

    /**
     * nuclei 官方 MatchWords 逻辑：
     * 支持 AND/OR condition、CaseInsensitive、MatchAll、变量渲染。
     *
     * <p>对应 Go 的 {@code (e *Engine) matchWord(m *model.Matcher, target string, data map[string]interface{}) *MatchResult}。
     * 注：Go 侧入参 {@code data} 在函数体内未使用（“变量渲染”仅见于注释），按 Go 签名保留。
     */
    MatchResult matchWord(Matcher m, String target, Map<String, Object> data) {
        MatchResult result = new MatchResult();
        MatcherCondition cond = getCondition(m);

        if (m.caseInsensitive) {
            target = target.toLowerCase(Locale.ROOT);
        }

        List<String> matchedWords = new ArrayList<>();
        if (m.words != null) {
            for (int i = 0; i < m.words.size(); i++) {
                String word = m.words.get(i);
                String wc = word;
                if (m.caseInsensitive) {
                    wc = wc.toLowerCase(Locale.ROOT);
                }

                // 空词不匹配 (nuclei 官方: 空字符串不参与匹配)
                if (wc.isEmpty()) {
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    continue;
                }

                if (!target.contains(wc)) {
                    // nuclei 官方: AND 条件任何一个不匹配就返回 false
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    // OR 条件继续下一个词
                    continue;
                }

                // nuclei 官方: OR 条件 + 非 MatchAll 时, 第一个匹配立即返回
                if (cond == MatcherCondition.OR && !m.matchAll) {
                    return hitOne(word);
                }

                matchedWords.add(word);

                // nuclei 官方: 最后一个词且非 MatchAll 时返回 true
                if (m.words.size() - 1 == i && !m.matchAll) {
                    return hit(matchedWords);
                }
            }
        }

        // nuclei 官方: MatchAll 模式, 所有词都匹配才返回 true
        if (!matchedWords.isEmpty() && m.matchAll) {
            return hit(matchedWords);
        }

        return result;
    }

    /**
     * nuclei 官方 MatchRegex 逻辑：LiteralPrefix 短路优化、AND/OR condition、MatchAll。
     *
     * <p>对应 Go 的 {@code (e *Engine) matchRegex(m *model.Matcher, target string) *MatchResult}。
     * Go 侧注释提及 {@code (?i)} 与 Encoding，但实际代码未做处理，按 Go 实现照抄（不加）。
     */
    MatchResult matchRegex(Matcher m, String target) {
        MatchResult result = new MatchResult();
        MatcherCondition cond = getCondition(m);

        // 空 target 不匹配任何正则
        if (target.isEmpty()) {
            return result;
        }

        List<String> matchedRegexes = new ArrayList<>();
        if (m.regex != null) {
            for (int i = 0; i < m.regex.size(); i++) {
                String p = m.regex.get(i);

                // 空模式跳过
                if (p.isEmpty()) {
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    continue;
                }

                // 编译正则 (nuclei 官方: 默认不区分大小写用 (?i))；编译错等价于 Go 的 regexp.Compile err
                Pattern re;
                try {
                    re = Pattern.compile(p);
                } catch (PatternSyntaxException ex) {
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    continue;
                }

                // nuclei 官方: LiteralPrefix 短路优化
                // 如果正则有一个确定的前缀且不在 target 中, 跳过匹配
                String prefix = literalPrefix(p);
                if (!prefix.isEmpty() && !target.contains(prefix)) {
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    continue;
                }

                // nuclei 官方: OR 条件 + 非 MatchAll 时, 第一个匹配立即返回
                if (cond == MatcherCondition.OR && !m.matchAll) {
                    java.util.regex.Matcher rm = re.matcher(target);
                    if (!rm.find()) {
                        continue;
                    }
                    // 返回第一个匹配的完整字符串
                    return hitOne(rm.group());
                }

                // 收集所有匹配（对应 Go 的 re.FindString(target, -1)，非重叠全量）
                List<String> currentMatches = findAll(re, target);
                if (currentMatches.isEmpty()) {
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    continue;
                }

                matchedRegexes.addAll(currentMatches);

                // 最后一个正则且非 MatchAll 时返回 true
                if (m.regex.size() - 1 == i && !m.matchAll) {
                    return hit(matchedRegexes);
                }
            }
        }

        // MatchAll 模式: 所有正则都匹配才返回 true
        if (!matchedRegexes.isEmpty() && m.matchAll) {
            return hit(matchedRegexes);
        }

        return result;
    }

    /**
     * nuclei 官方 MatchBinary 逻辑。
     *
     * <p>对应 Go 的 {@code (e *Engine) matchBinary(m *model.Matcher, target string) *MatchResult}。
     */
    MatchResult matchBinary(Matcher m, String target) {
        MatchResult result = new MatchResult();
        MatcherCondition cond = getCondition(m);

        if (target.isEmpty()) {
            return result;
        }

        byte[] body = target.getBytes(StandardCharsets.UTF_8);
        List<String> matchedBinary = new ArrayList<>();
        if (m.binary != null) {
            for (int i = 0; i < m.binary.size(); i++) {
                String b = m.binary.get(i);
                // 对应 Go: hex.DecodeString(strings.ReplaceAll(b, " ", ""))
                byte[] pattern = decodeHex(b.replace(" ", ""));
                if (pattern == null || pattern.length == 0) {
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    continue;
                }
                if (!containsBytes(body, pattern)) {
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    continue;
                }

                // OR 条件: 第一个匹配返回
                if (cond == MatcherCondition.OR) {
                    return hitOne(b);
                }

                matchedBinary.add(b);

                // 最后一个
                if (m.binary.size() - 1 == i) {
                    return hit(matchedBinary);
                }
            }
        }
        return result;
    }

    /**
     * nuclei 官方 MatchDSL 逻辑：表达式求值出错即视为不命中。
     *
     * <p>对应 Go 的 {@code (e *Engine) matchDSL(m *model.Matcher, data map[string]interface{}) *MatchResult}。
     *
     * <p>值→命中的判定逐条对应 Go 的类型断言：{@code bool} 真值；{@code string} 非空且非
     * {@code "false"}/{@code "0"}；{@code float64}（reflect Kind == Float64）非 0。
     * Go 对 {@code int} 等其它类型一律判不命中（reflect Kind 非 Float64），Java 侧同理
     * 只认 {@link Double} —— dsl.Evaluator 的数值返回类型以 Go eval.go 为准
     * （整型字面量 → int，浮点/算术 → float64）。
     */
    MatchResult matchDSL(Matcher m, Map<String, Object> data) {
        MatchResult result = new MatchResult();
        MatcherCondition cond = getCondition(m);

        if (m.dsl != null) {
            for (int i = 0; i < m.dsl.size(); i++) {
                String expr = m.dsl.get(i);
                if (expr.isEmpty()) {
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    continue;
                }

                // val, err := e.dslEvaluator.Evaluate(expr, data)；err != nil 即判不命中
                Object[] ev = dslEvaluator.evaluate(expr, data);
                Object val = ev[0];
                Throwable err = (Throwable) ev[1];
                if (err != null) {
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    continue;
                }

                boolean matched = false;
                if (val instanceof Boolean b && b) {
                    matched = true;
                } else if (val instanceof String s && !s.isEmpty()
                        && !s.equals("false") && !s.equals("0")) {
                    matched = true;
                } else if (val instanceof Double d && d != 0.0) {
                    // Go: reflect.ValueOf(val).Kind() == reflect.Float64 && val.(float64) != 0
                    matched = true;
                }

                if (!matched) {
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    continue;
                }

                // OR 条件: 第一个匹配返回
                if (cond == MatcherCondition.OR) {
                    return hitOne(expr);
                }

                // 最后一个 DSL 表达式
                if (m.dsl.size() - 1 == i) {
                    return hitOne(expr);
                }
            }
        }
        return result;
    }

    /**
     * 简化 xpath 匹配（字符串包含判定，与 Go 实现一致）。
     *
     * <p>对应 Go 的 {@code (e *Engine) matchXPath(m *model.Matcher, target string) *MatchResult}。
     * 注意 Go 在 AND 分支命中“最后一个”时返回的是整个 {@code m.XPath} 列表（非仅命中的项），
     * 且与 {@code m.XPath} 共享底层数组 —— Java 侧同样直接持有 {@code m.xpath} 引用以保持别名语义。
     */
    MatchResult matchXPath(Matcher m, String target) {
        MatchResult result = new MatchResult();
        MatcherCondition cond = getCondition(m);

        if (target.isEmpty()) {
            return result;
        }

        if (m.xpath != null) {
            for (int i = 0; i < m.xpath.size(); i++) {
                String xp = m.xpath.get(i);
                if (xp.isEmpty()) {
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    continue;
                }
                if (!target.contains(xp)) {
                    if (cond == MatcherCondition.AND) {
                        return new MatchResult();
                    }
                    continue;
                }

                if (cond == MatcherCondition.OR) {
                    return hitOne(xp);
                }

                if (m.xpath.size() - 1 == i) {
                    // Go: MatchedStrings: m.XPath（整个列表）
                    return hit(m.xpath);
                }
            }
        }
        return result;
    }

    // =====================================================================
    // 包级助手（对应 matcher.go 的小写包级函数/类型）
    // =====================================================================

    /** 内部条件类型 (nuclei 官方: ConditionType)，对应 Go 的 {@code matcherCondition}。 */
    enum MatcherCondition {
        /** 对应 Go 的 {@code conditionOR}（iota+1 首项）。 */
        OR,
        /** 对应 Go 的 {@code conditionAND}。 */
        AND
    }

    /**
     * 解析 matcher 的 condition 字段 (nuclei 官方: 解析 ConditionType)。
     *
     * <p>对应 Go 的包级函数 {@code getCondition}：{@code strings.ToLower(m.Condition)}
     * 为 {@code "and"} → AND，<b>其余（default 分支）一律 OR</b>。
     */
    static MatcherCondition getCondition(Matcher m) {
        String cond = m.condition;
        if (cond != null && cond.toLowerCase(Locale.ROOT).equals("and")) {
            return MatcherCondition.AND;
        }
        return MatcherCondition.OR;
    }

    /**
     * 字节切片包含检查，对应 Go 的包级函数 {@code containsBytes}：
     * {@code strings.Contains(string(body), string(pattern))}（按原始字节比较，空模式恒含）。
     */
    static boolean containsBytes(byte[] body, byte[] pattern) {
        if (pattern.length == 0) {
            return true;
        }
        if (pattern.length > body.length) {
            return false;
        }
        outer:
        for (int i = 0; i <= body.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (body[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /**
     * 对应 Go 的 {@code hex.DecodeString}：返回解码后的字节；非法字符或奇数长度
     * （Go 的 err != nil）返回 {@code null}；空串返回空数组（Go：零长度、无错误，
     * 由调用方的 {@code len(pattern) == 0} 判定承接）。大小写十六进制均接受，与 Go 一致。
     */
    static byte[] decodeHex(String s) {
        int n = s.length();
        if (n % 2 != 0) {
            return null;
        }
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) {
            int hi = Character.digit(s.charAt(i), 16);
            int lo = Character.digit(s.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                return null;
            }
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /**
     * 对应 Go 的 {@code re.LiteralPrefix()}（模式的确定字面前缀）。
     *
     * <p>Java 正则 API 不暴露字面前缀，这里做<b>保守</b>扫描：取从头起连续的非元字符，
     * 遇元字符或转义即停。所得前缀恒为 Go 真实前缀的“前缀的前缀”，因此只会少做短路、
     * 不会把本可匹配的正则误跳过（若 target 不含该保守前缀，则必然也不含 Go 前缀，
     * 正则同样不可能命中 —— 最终结果与 Go 恒一致，仅可能少一层优化）。
     */
    static String literalPrefix(String pattern) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (c == '\\' || ".+*?[]()|^${}".indexOf(c) >= 0) {
                break;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    /**
     * 对应 Go 的 {@code re.FindAllString(target, -1)}：非重叠全量匹配。
     */
    private static List<String> findAll(Pattern re, String target) {
        List<String> out = new ArrayList<>();
        java.util.regex.Matcher m = re.matcher(target);
        while (m.find()) {
            out.add(m.group());
        }
        return out;
    }

    /**
     * 对应 Go 的 {@code &MatchResult{Matched: true, MatchedStrings: ...}} 字面量构造。
     */
    static MatchResult hit(List<String> strings) {
        MatchResult r = new MatchResult();
        r.matched = true;
        r.matchedStrings = strings;
        return r;
    }

    /** 对应 Go 的 {@code &MatchResult{Matched: true, MatchedStrings: []string{s}}}。 */
    static MatchResult hitOne(String s) {
        List<String> l = new ArrayList<>(1);
        l.add(s);
        return hit(l);
    }
}

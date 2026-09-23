package space.jyscan.modules.dns;

import java.util.ArrayList;
import java.util.List;

/**
 * 域名过滤规则，对应 Go 的 {@code dns.FilterRule}。
 *
 * <p>{@code pattern} 支持通配符 {@code *} / {@code ?}（{@code regex=false}）或原生正则
 * （{@code regex=true}），语义与 Go 的 {@code wildcardToRegex} 一致。
 */
public final class FilterRule {

    /** 匹配模式，支持通配符 * 和 ?（或正则）。 */
    public String pattern = "";

    /** 是否为正则表达式。 */
    public boolean regex;

    public FilterRule() {
    }

    public FilterRule(String pattern, boolean regex) {
        this.pattern = pattern == null ? "" : pattern;
        this.regex = regex;
    }

    /**
     * 从逗号分隔的字符串解析规则，对应 Go 的 {@code ParseFilterRules}：
     * 空片段被跳过；{@code isRegex} 作用于全部规则。
     */
    public static List<FilterRule> parseRules(List<String> patterns, boolean isRegex) {
        List<FilterRule> rules = new ArrayList<>();
        if (patterns == null) {
            return rules;
        }
        for (String p : patterns) {
            if (p == null || p.isEmpty()) {
                continue;
            }
            rules.add(new FilterRule(p, isRegex));
        }
        return rules;
    }

    /** 同 Go 的逗号切分语义（{@code strings.Split}，跳过空串）。 */
    public static List<String> splitComma(String rules) {
        List<String> out = new ArrayList<>();
        if (rules == null || rules.isEmpty()) {
            return out;
        }
        for (String p : rules.split(",", -1)) {
            if (!p.isEmpty()) {
                out.add(p);
            }
        }
        return out;
    }
}

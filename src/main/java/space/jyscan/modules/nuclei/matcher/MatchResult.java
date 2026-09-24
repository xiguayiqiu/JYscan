package space.jyscan.modules.nuclei.matcher;

import java.util.List;

/**
 * 匹配结果，对应 Go 的 {@code matcher.MatchResult}。
 *
 * <p>跨包契约：operators 包经 {@code matchEngine.match(...)} 拿到本类型并读取
 * {@link #matched}（随后按 {@code Negative} 标志翻转，见 operators 的
 * {@code matchResult} 助手）与 {@link #matchedStrings}。
 *
 * <p>字段默认值与 Go 零值一致：{@code Matched=false}、{@code MatchedStrings=nil}
 * （Java 为 {@code null}）、{@code Description=""}、{@code Debug=""}。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/matcher/matcher.go}
 */
public class MatchResult {

    /** Go {@code Matched}。 */
    public boolean matched;
    /** Go {@code MatchedStrings}（Go 零值 nil → Java null）。 */
    public List<String> matchedStrings = null;
    /** Go {@code Description}。 */
    public String description = "";
    /** Go {@code Debug}。 */
    public String debug = "";
}

package space.jyscan.modules.nuclei.model;

import java.util.List;

/**
 * WHOIS 请求模型，对应 Go 的 {@code model.WhoisRequest}。
 *
 * <p>Go 侧的 {@code WhoisExecutor.Execute} 是桩（返回 {@code host}/{@code raw=""}），
 * 本类型仅作为模板解析与类型系统的一环。
 */
public final class WhoisRequest implements Request {

    /** {@code query}。 */
    public String query = "";
    /** {@code server}。 */
    public String server = "";

    /** {@code matchers}。 */
    public List<Matcher> matchers = null;
    /** {@code matchers-condition}。 */
    public String matchersCondition = "";
    /** {@code extractors}。 */
    public List<Extractor> extractors = null;

    @Override
    public List<Matcher> getMatchers() {
        return matchers;
    }

    @Override
    public List<Extractor> getExtractors() {
        return extractors;
    }

    @Override
    public String getMatchersCondition() {
        return matchersCondition;
    }
}

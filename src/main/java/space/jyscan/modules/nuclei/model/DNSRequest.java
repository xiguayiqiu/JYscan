package space.jyscan.modules.nuclei.model;

import java.util.List;

/**
 * DNS 请求模型，对应 Go 的 {@code model.DNSRequest}。
 */
public final class DNSRequest implements Request {

    /** {@code name}。 */
    public String name = "";
    /** {@code type}（记录类型，如 A/AAAA/CNAME）。 */
    public String type = "";
    /** {@code class}。 */
    public String clazz = "";
    /** {@code recursion}。 */
    public boolean recursion;

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

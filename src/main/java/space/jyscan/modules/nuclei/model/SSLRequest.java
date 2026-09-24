package space.jyscan.modules.nuclei.model;

import java.util.List;

/**
 * SSL/TLS 请求模型，对应 Go 的 {@code model.SSLRequest}。
 *
 * <p>Go 的 {@code tls-version} yaml 键映射到 {@link #tlsVersions}，与
 * {@code min-version}/{@code max-version} 是两个不同字段。
 */
public final class SSLRequest implements Request {

    /** {@code address}。 */
    public String address = "";
    /** {@code min-version}。 */
    public String minVersion = "";
    /** {@code max-version}。 */
    public String maxVersion = "";
    /** {@code cipher-suites}。 */
    public List<String> cipherSuites = null;
    /** {@code tls-version}。 */
    public List<String> tlsVersions = null;

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

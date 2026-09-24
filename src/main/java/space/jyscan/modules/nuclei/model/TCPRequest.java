package space.jyscan.modules.nuclei.model;

import java.util.List;
import java.util.Map;

/**
 * TCP 请求模型，对应 Go 的 {@code model.TCPRequest}。
 */
public final class TCPRequest implements Request {

    /** {@code host}。 */
    public List<String> host = null;
    /** {@code ports}。 */
    public List<String> ports = null;
    /** {@code inputs}。 */
    public List<String> inputs = null;
    /** {@code read-size}。 */
    public int readSize;
    /** {@code data}。 */
    public String data = "";
    /** {@code payloads}。 */
    public Map<String, String> payloads = null;

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

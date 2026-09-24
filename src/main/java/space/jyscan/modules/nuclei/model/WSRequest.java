package space.jyscan.modules.nuclei.model;

import java.util.List;
import java.util.Map;

/**
 * WebSocket 请求模型，对应 Go 的 {@code model.WSRequest}。
 *
 * <p>Go 侧的 {@code WSExecutor.Execute} 是桩（返回 {@code "websocket protocol not yet
 * fully implemented"}），本类型仅作为模板解析与类型系统的一环。
 */
public final class WSRequest implements Request {

    /** {@code url}。 */
    public String url = "";
    /** {@code headers}。 */
    public Map<String, String> headers = null;
    /** {@code payload}。 */
    public String payload = "";

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

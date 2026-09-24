package space.jyscan.modules.nuclei.model;

import java.util.List;
import java.util.Map;

/**
 * HTTP 请求模型，对应 Go 的 {@code model.HTTPRequest}（注释："对应 nuclei 的 http.Request"）。
 *
 * <p>字段与 Go 逐一对应；带连字符的 yaml 键（{@code max-redirects}/{@code attack}/
 * {@code stop-at-first-match} 等）由 loader 按字面量取用。
 */
public final class HTTPRequest implements Request {

    /** {@code method}。 */
    public String method = "";
    /** {@code path}。 */
    public List<String> path = null;
    /** {@code body}。 */
    public String body = "";
    /** {@code raw}。 */
    public String raw = "";
    /** {@code headers}。 */
    public Map<String, String> headers = null;
    /** {@code cookies}。 */
    public Map<String, String> cookies = null;
    /** {@code query}。 */
    public Map<String, String> query = null;

    /** {@code redirects}。 */
    public int redirects;
    /** {@code max-redirects}。 */
    public int maxRedirects;
    /** {@code redirect-eval}。 */
    public boolean redirectEval;

    /** {@code attack}（攻击模式）。 */
    public String attackType = "";
    /** {@code payloads}。 */
    public Map<String, String> payloads = null;

    /** {@code payloads-path}。 */
    public List<String> payloadsPath = null;
    /** {@code payloads-body}。 */
    public List<String> payloadsBody = null;
    /** {@code payloads-header}。 */
    public List<String> payloadsHeader = null;
    /** {@code payloads-cookie}。 */
    public List<String> payloadsCookie = null;
    /** {@code payloads-query}。 */
    public List<String> payloadsQuery = null;

    /** {@code max-size}，字节。 */
    public int maxSize;

    /** 请求级 {@code matchers}。 */
    public List<Matcher> matchers = null;
    /** 请求级 {@code matchers-condition}。 */
    public String matchersCondition = "";
    /** 请求级 {@code extractors}。 */
    public List<Extractor> extractors = null;

    /** {@code skip-variables-check}。 */
    public boolean skipVariablesCheck;

    /** {@code pre-condition}。 */
    public String preCondition = "";
    /** {@code post-condition}。 */
    public String postCondition = "";

    /** {@code host-redirects}（nuclei 兼容字段）。 */
    public boolean hostRedirects;
    /** {@code cookie-reuse}（nuclei 兼容字段）。 */
    public boolean cookieReuse;

    /**
     * 获取方法名，默认 {@code GET}。
     *
     * <p>对应 Go 的 {@code (r *HTTPRequest) GetMethod() string}。
     */
    public String getMethod() {
        if (method == null || method.isEmpty()) {
            return "GET";
        }
        return method;
    }

    /**
     * 获取最大响应大小，Go 默认 10MB。
     *
     * <p>对应 Go 的 {@code (r *HTTPRequest) GetMaxSize() int}：{@code MaxSize <= 0} 时返回
     * {@code 10 * 1024 * 1024}。
     */
    public int getMaxSize() {
        if (maxSize <= 0) {
            return 10 * 1024 * 1024;
        }
        return maxSize;
    }

    /**
     * 获取最大重定向次数。
     *
     * <p>对应 Go 的 {@code (r *HTTPRequest) GetRedirects() int}：优先
     * {@code MaxRedirects}，其次 {@code Redirects}，都为 0 时返回 5。
     */
    public int getRedirects() {
        if (maxRedirects > 0) {
            return maxRedirects;
        }
        if (redirects > 0) {
            return redirects;
        }
        return 5;
    }

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

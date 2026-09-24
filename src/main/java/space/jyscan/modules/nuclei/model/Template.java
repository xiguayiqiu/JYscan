package space.jyscan.modules.nuclei.model;

import java.util.List;
import java.util.Map;

/**
 * 模板结构，对应 Go 的 {@code model.Template}（注释："对应 nuclei 的 templates.Template"）。
 *
 * <p>Go 的 {@code Info} 是值类型（非指针），故本类 {@link #info} 恒为非 null，
 * 与 Go 的零值语义一致 —— loader 中 {@code t.Info.Name == t.ID} 的兜底写法依赖这一点。
 */
public final class Template {

    /** {@code id}。 */
    public String id = "";
    /** {@code info}，Go 侧为值类型。 */
    public Info info = new Info();
    /** {@code flow}。 */
    public String flow = "";
    /** {@code self-contained}。 */
    public boolean selfContained;
    /** {@code stop-at-first-match}。 */
    public boolean stopAtFirstMatch;

    /** 协议请求段：{@code requests}（旧式 http 写法）。 */
    public List<HTTPRequest> requestsHTTP = null;
    /** 协议请求段：{@code http}（新式写法）。 */
    public List<HTTPRequest> http = null;
    /** 协议请求段：{@code dns}。 */
    public List<DNSRequest> dns = null;
    /** 协议请求段：{@code tcp}。 */
    public List<TCPRequest> tcp = null;
    /** 协议请求段：{@code ssl}。 */
    public List<SSLRequest> ssl = null;
    /** 协议请求段：{@code websocket}。 */
    public List<WSRequest> websocket = null;
    /** 协议请求段：{@code whois}。 */
    public List<WhoisRequest> whois = null;
    /** 协议请求段：{@code file}。 */
    public List<FileRequest> file = null;
    /** 协议请求段：{@code code}。 */
    public List<CodeRequest> code = null;

    /** {@code variables}。 */
    public Map<String, Object> variables = null;
    /** {@code constants}。 */
    public Map<String, Object> constants = null;

    /** 模板级 {@code matchers}。 */
    public List<Matcher> matchers = null;
    /** 模板级 {@code extractors}。 */
    public List<Extractor> extractors = null;
    /** {@code matchers-condition}。 */
    public String matchersCondition = "";

    /** 工作流支持，{@code workflows}。 */
    public List<String> workflows = null;

    /**
     * 获取所有 HTTP 请求。
     *
     * <p>对应 Go 的 {@code (t *Template) GetAllHTTP() []*HTTPRequest}：
     * {@code RequestsHTTP} 非空时返回它，否则返回 {@code HTTP}。
     * 两者的区别见上方 {@link #requestsHTTP}/{@link #http} 注释。
     */
    public List<HTTPRequest> getAllHTTP() {
        if (requestsHTTP != null && !requestsHTTP.isEmpty()) {
            return requestsHTTP;
        }
        return http;
    }

    /**
     * 获取所有 TCP 请求，对应 Go 的 {@code (t *Template) GetAllTCP() []*TCPRequest}。
     */
    public List<TCPRequest> getAllTCP() {
        return tcp;
    }
}

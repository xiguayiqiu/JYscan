package space.jyscan.modules.nmap;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * 单个端口的扫描信息，移植自 freeclient/internal/nmap/scan.go 的 PortInfo。
 *
 * <p><b>JSON 保真度规则</b>：必须逐字段对照 Go 的 tag，不能用类级 {@code @JsonInclude}——
 * 类级 {@code NON_DEFAULT} 会拿「无参构造出的默认实例」逐属性比较，从而把 Go 并未标注
 * {@code omitempty} 的字段也一并省掉。Go 的规则是：
 * <ul>
 *   <li>无 {@code omitempty}（port/protocol/service/state）→ 始终输出，字段上不加注解；</li>
 *   <li>字符串带 {@code omitempty} → 为空即省，用 {@link JsonInclude.Include#NON_EMPTY}；</li>
 *   <li>int/float64/bool 带 {@code omitempty} → 为零即省，用
 *       {@link JsonInclude.Include#NON_DEFAULT}（Jackson 的 NON_EMPTY 不会省略 0/false）。</li>
 * </ul>
 */
public class PortInfo {

    /** 无 omitempty —— 始终输出。 */
    @JsonProperty("port")
    public int port;

    /** 无 omitempty —— 始终输出。 */
    @JsonProperty("protocol")
    public String protocol = "";

    /** 无 omitempty —— 始终输出（未识别服务时 Go 输出 ""）。 */
    @JsonProperty("service")
    public String service = "";

    @JsonProperty("banner")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String banner = "";

    /** 无 omitempty —— 始终输出。open/closed/filtered/unfiltered/open|filtered/closed|filtered */
    @JsonProperty("state")
    public String state = "";

    @JsonProperty("version")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String version = "";

    /** WAF类型 */
    @JsonProperty("waf_type")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String wafType = "";

    /** WAF置信度 */
    @JsonProperty("waf_confidence")
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public double wafConfidence;

    /** 是否被过滤(假死) */
    @JsonProperty("is_filtered")
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public boolean isFiltered;

    /** 过滤原因 */
    @JsonProperty("filter_reason")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String filterReason = "";

    /** 响应内容长度 */
    @JsonProperty("content_length")
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public int contentLength;

    /** 响应时间(秒) */
    @JsonProperty("response_time")
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public double responseTime;

    /** HTTP状态码 */
    @JsonProperty("status_code")
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public int statusCode;

    /** 内容探测(-X)获取的端口回复内容 */
    @JsonProperty("content")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String content = "";

    /** 内容探测识别出的协议 */
    @JsonProperty("content_protocol")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String contentProtocol = "";

    /** 命中的内容探测器名称 */
    @JsonProperty("content_probe")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String contentProbe = "";

    /** 是否为「可展示」的开放端口（open 或 open|filtered），与 PrintNmapResult 的过滤一致。 */
    @JsonIgnore
    public boolean isOpenOrOpenFiltered() {
        return NmapConstants.PORT_STATE_OPEN.equals(state)
                || NmapConstants.PORT_STATE_OPEN_FILTERED.equals(state);
    }

    /**
     * 新建一个与 Go {@code map[int]PortInfo} 序列化顺序一致的空端口表。
     *
     * <p>等价于 {@link NmapResult#ports()}，仅为调用方语义清晰（此处 key 恰为端口号）而提供别名。
     */
    public static Map<Integer, PortInfo> newPorts() {
        return NmapResult.ports();
    }

    public PortInfo copy() {
        PortInfo p = new PortInfo();
        p.port = port;
        p.protocol = protocol;
        p.service = service;
        p.banner = banner;
        p.state = state;
        p.version = version;
        p.wafType = wafType;
        p.wafConfidence = wafConfidence;
        p.isFiltered = isFiltered;
        p.filterReason = filterReason;
        p.contentLength = contentLength;
        p.responseTime = responseTime;
        p.statusCode = statusCode;
        p.content = content;
        p.contentProtocol = contentProtocol;
        p.contentProbe = contentProbe;
        return p;
    }
}

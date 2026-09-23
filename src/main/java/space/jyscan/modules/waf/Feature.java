package space.jyscan.modules.waf;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 特征定义，移植自 freeclient/internal/waf/waf.go 的 Feature 结构体。
 *
 * <p>type 取值：response_header, ssl_certificate, response_content, active_detect；
 * match_type 取值：exists, contains, exact, regex。
 */
public class Feature {

    /** 特征类型：response_header / ssl_certificate / response_content / active_detect */
    @JsonProperty("type")
    public String type;

    /** 响应头名称（type=response_header 时使用） */
    @JsonProperty("key")
    public String key;

    /** 证书字段：issuer / subject / serial（type=ssl_certificate 时使用） */
    @JsonProperty("field")
    public String field;

    /** 匹配值 */
    @JsonProperty("value")
    public String value;

    /** 匹配方式：exists / contains / exact / regex */
    @JsonProperty("match_type")
    public String matchType;

    /** 权重 */
    @JsonProperty("weight")
    public int weight;

    /** 主动探测请求定义（type=active_detect 时使用） */
    @JsonProperty("request")
    public Request request;

    /** 主动探测响应检查定义（type=active_detect 时使用） */
    @JsonProperty("response_check")
    public RespCheck respCheck;
}

package space.jyscan.modules.waf;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * 探测结果，移植自 freeclient/internal/waf/waf.go 的 WAFResult 结构体。
 *
 * <p>字段顺序与 Go 结构体声明顺序一致，保证 JSON 输出与 json.MarshalIndent 相同。
 */
@JsonPropertyOrder({"target", "detected", "waf_name", "vendor", "confidence", "description", "error_message"})
public class WAFResult {

    /** 检测目标 */
    @JsonProperty("target")
    public String target = "";

    /** 是否检测到WAF */
    @JsonProperty("detected")
    public boolean detected;

    /** WAF名称 */
    @JsonProperty("waf_name")
    public String wafName = "";

    /** 厂商 */
    @JsonProperty("vendor")
    public String vendor = "";

    /** 置信度 */
    @JsonProperty("confidence")
    public int confidence;

    /** 描述 */
    @JsonProperty("description")
    public String description = "";

    /** 错误信息（探测失败时保留失败原因） */
    @JsonProperty("error_message")
    public String errorMessage = "";
}

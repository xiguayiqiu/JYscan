package space.jyscan.modules.waf;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * WAF规则配置，移植自 freeclient/internal/waf/waf.go 的 WAFConfig 结构体。
 */
public class WAFConfig {

    /** WAF规则列表 */
    @JsonProperty("waf_list")
    public List<WAF> wafList;
}

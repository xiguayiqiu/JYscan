package space.jyscan.modules.waf;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * WAF特征定义，移植自 freeclient/internal/waf/waf.go 的 WAF 结构体。
 */
public class WAF {

    /** WAF名称 */
    @JsonProperty("name")
    public String name = "";

    /** 厂商 */
    @JsonProperty("vendor")
    public String vendor = "";

    /** 置信度阈值 */
    @JsonProperty("confidence_threshold")
    public int confidenceThreshold;

    /** 特征列表 */
    @JsonProperty("features")
    public List<Feature> features = new ArrayList<>();
}

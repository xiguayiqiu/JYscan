package space.jyscan.modules.waf;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 主动探测请求定义，移植自 freeclient/internal/waf/waf.go 的 Request 结构体。
 */
public class Request {

    /** 请求方法（Go 实际执行时固定使用 GET，与 Go 行为一致） */
    @JsonProperty("method")
    public String method;

    /** 请求路径 */
    @JsonProperty("path")
    public String path;

    /** User-Agent */
    @JsonProperty("user_agent")
    public String userAgent;
}

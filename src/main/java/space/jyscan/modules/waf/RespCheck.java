package space.jyscan.modules.waf;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 主动探测响应检查定义，移植自 freeclient/internal/waf/waf.go 的 RespCheck 结构体。
 */
public class RespCheck {

    /** 期望状态码（0 表示不检查） */
    @JsonProperty("status_code")
    public int statusCode;

    /** 响应体需包含的内容（空表示不检查） */
    @JsonProperty("content_contains")
    public String contentContains;

    /** 必须存在的响应头（空表示不检查） */
    @JsonProperty("header_exists")
    public String headerExists;
}

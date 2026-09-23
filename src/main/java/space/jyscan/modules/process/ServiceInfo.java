package space.jyscan.modules.process;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 服务信息结构体，移植自 freeclient/internal/process/process.go 的 ServiceInfo。
 *
 * <p>字段与 Go 结构体一一对应，JSON 标签保持 Go 的 snake_case。
 */
public class ServiceInfo {

    /** 服务名称。 */
    @JsonProperty("name")
    public String name = "";

    /** 显示名称。 */
    @JsonProperty("display_name")
    public String displayName = "";

    /** 服务状态。 */
    @JsonProperty("status")
    public String status = "";

    /** 启动类型。 */
    @JsonProperty("start_type")
    public String startType = "";

    /** 运行用户。 */
    @JsonProperty("user")
    public String user = "";

    /** 可执行文件路径。 */
    @JsonProperty("path")
    public String path = "";

    /** 权限级别。 */
    @JsonProperty("privilege")
    public String privilege = "";
}

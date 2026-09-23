package space.jyscan.modules.process;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 进程信息结构体，移植自 freeclient/internal/process/process.go 的 ProcessInfo。
 *
 * <p>字段与 Go 结构体一一对应，JSON 标签保持 Go 的 snake_case，
 * 保证 --output json 输出与 Go 版一致。
 */
public class ProcessInfo {

    /** 进程ID。 */
    @JsonProperty("pid")
    public int pid;

    /** 进程名称。 */
    @JsonProperty("name")
    public String name = "";

    /** 运行用户。 */
    @JsonProperty("user")
    public String user = "";

    /** CPU使用率。 */
    @JsonProperty("cpu_usage")
    public double cpuUsage;

    /** 内存使用量(字节)。 */
    @JsonProperty("memory_usage")
    public long memoryUsage;

    /** 权限级别。 */
    @JsonProperty("privilege")
    public String privilege = "";

    /** 可执行文件路径。 */
    @JsonProperty("path")
    public String path = "";

    /** 命令行参数。 */
    @JsonProperty("command_line")
    public String commandLine = "";
}

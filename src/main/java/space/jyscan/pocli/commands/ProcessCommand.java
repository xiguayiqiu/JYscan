package space.jyscan.pocli.commands;

import com.fasterxml.jackson.core.JsonProcessingException;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.JsonUtil;
import space.jyscan.core.util.SystemUtil;
import space.jyscan.modules.process.ProcessAnalyzer;
import space.jyscan.modules.process.ProcessException;
import space.jyscan.modules.process.ProcessInfo;
import space.jyscan.modules.process.ServiceInfo;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * process 命令，移植自 freeclient/internal/cli/process.go。
 *
 * <p>参数与 Go 版一致：-H/--high（仅高权限）、-p/--process（仅进程）、
 * -S/--service（仅服务）、--output（text|json，默认 text）。
 * 首个位置参数为 {@code help} 时显示帮助（对应 cobra 的 args[0] == "help"）。
 */
@Command(
        name = "process",
        description = "进程与服务信息收集工具",
        header = {
                "进程与服务信息收集工具 - 分析运行中的进程和系统服务，识别高权限运行的软件",
                "",
                "支持功能:",
                "- 跨平台进程分析 (Windows/Linux)",
                "- 系统服务信息收集",
                "- 高权限进程和服务识别",
                "- 详细的权限级别分类",
                "",
                "权限级别说明:",
                "- 系统权限: 操作系统核心组件，具有最高权限",
                "- 高权限: 网络服务、数据库服务等关键应用",
                "- 中权限: 普通系统服务和应用",
                "- 低权限: 普通用户应用",
                "",
                "使用示例:",
                "  ./JYscan process                    # 显示所有进程和服务信息",
                "  ./JYscan process -H                  # 仅显示高权限进程和服务",
                "  ./JYscan process -p                  # 仅显示进程信息",
                "  ./JYscan process -S                  # 仅显示服务信息",
                "  ./JYscan process --output json       # 以JSON格式输出",
                "",
                "警告: 仅用于授权测试和安全评估，严禁未授权使用！"
        },
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true
)
public class ProcessCommand implements Callable<Integer> {

    /** picocli 注入的命令规格，用于打印帮助（等价 cobra 的 cmd.Help()）。 */
    @Spec
    CommandSpec spec;

    /** 仅显示高权限进程和服务（对应 Go 的 -H/--high，默认 false）。 */
    @Option(names = {"-H", "--high"}, description = "仅显示高权限进程和服务")
    boolean high;

    /** 仅显示进程信息（对应 Go 的 -p/--process，默认 false）。 */
    @Option(names = {"-p", "--process"}, description = "仅显示进程信息")
    boolean processesOnly;

    /** 仅显示服务信息（对应 Go 的 -S/--service，默认 false）。 */
    @Option(names = {"-S", "--service"}, description = "仅显示服务信息")
    boolean servicesOnly;

    /** 输出格式（对应 Go 的 --output，默认 "text"）。 */
    @Option(names = {"--output"}, description = "输出格式 (text|json)")
    String outputFormat = "text";

    /** 位置参数：首个参数为 help 时显示帮助（对应 cobra 的 args[0] == "help"）。 */
    @Parameters(arity = "0..*", paramLabel = "ARGS",
            description = "位置参数，首项为 help 时显示帮助")
    List<String> args;

    /** 分析结果（对应 Go runProcessAnalysis 中的局部变量，未赋值时保持 nil → JSON null）。 */
    private List<ProcessInfo> processes;
    private List<ServiceInfo> services;

    @Override
    public Integer call() {
        try {
            // 检查是否请求帮助
            if (args != null && !args.isEmpty() && "help".equals(args.get(0))) {
                spec.commandLine().usage(System.out);
                return 0;
            }

            // 验证参数
            if (processesOnly && servicesOnly) {
                Colors.errorPrint("不能同时指定 -p/--process 和 -s/--service");
                spec.commandLine().usage(System.out);
                return 1;
            }

            // 执行进程与服务分析
            String err = runProcessAnalysis();
            if (err != null) {
                Colors.errorPrint("进程与服务分析失败: %v", err);
                return 1;
            }
            return 0;
        } catch (Exception e) {
            // 兜底：任何意外异常都只输出 Go 风格错误，绝不打印 Java 堆栈
            Colors.errorPrint("进程与服务分析失败: %v", e);
            return 1;
        }
    }

    // =====================================================================
    // 主流程（对应 cli/process.go 的 runProcessAnalysis）
    // =====================================================================

    /** 执行进程与服务分析，返回错误文本（null 表示成功）。 */
    private String runProcessAnalysis() {
        Colors.infoPrint("开始进程与服务分析...");
        Colors.infoPrint("操作系统: %s", getOSInfo());
        Colors.infoPrint("");

        processes = null;
        services = null;

        // 分析进程
        if (!servicesOnly) {
            Colors.infoPrint("正在分析运行中的进程...");
            boolean processFailed = false;
            try {
                if (high) {
                    processes = ProcessAnalyzer.getHighPrivilegeProcesses();
                } else {
                    processes = ProcessAnalyzer.analyzeProcesses();
                }
            } catch (ProcessException e) {
                Colors.warningPrint("进程分析失败: %v", e);
                processes = null;
                processFailed = true;
            }
            if (!processFailed) {
                Colors.infoPrint("发现 %d 个进程", sizeOf(processes));
            }
        }

        // 分析服务
        if (!processesOnly) {
            Colors.infoPrint("正在分析系统服务...");
            boolean serviceFailed = false;
            try {
                if (high) {
                    services = ProcessAnalyzer.getHighPrivilegeServices();
                } else {
                    services = ProcessAnalyzer.analyzeServices();
                }
            } catch (ProcessException e) {
                Colors.warningPrint("服务分析失败: %v", e);
                services = null;
                serviceFailed = true;
            }
            if (!serviceFailed) {
                Colors.infoPrint("发现 %d 个服务", sizeOf(services));
            }
        }

        Colors.infoPrint("");

        // 输出结果
        return outputResults();
    }

    // =====================================================================
    // 输出（对应 cli/process.go 的 outputResults / outputText / outputJSON）
    // =====================================================================

    /** 输出分析结果，返回错误文本（null 表示成功）。 */
    private String outputResults() {
        if ("json".equals(outputFormat)) {
            return outputJSON();
        }
        return outputText();
    }

    /** 以文本格式输出结果。 */
    private String outputText() {
        if (high) {
            // 高权限模式
            String result = ProcessAnalyzer.formatHighPrivilegeInfo(processes, services);
            printlnRaw(result);
        } else {
            // 完整模式
            if (!servicesOnly && processes != null && !processes.isEmpty()) {
                String result = ProcessAnalyzer.formatProcessInfo(processes);
                printlnRaw(result);
            }

            if (!processesOnly && services != null && !services.isEmpty()) {
                if (!servicesOnly) {
                    printlnRaw("");
                }
                String result = ProcessAnalyzer.formatServiceInfo(services);
                printlnRaw(result);
            }

            // 如果没有数据
            if (sizeOf(processes) == 0 && sizeOf(services) == 0) {
                if (processesOnly) {
                    Colors.infoPrint("未发现任何进程");
                } else if (servicesOnly) {
                    Colors.infoPrint("未发现任何服务");
                } else {
                    Colors.infoPrint("未发现任何进程或服务");
                }
            }
        }

        return null;
    }

    /** 以JSON格式输出结果，返回错误文本（null 表示成功）。 */
    private String outputJSON() {
        // 创建结果结构（字段顺序与 Go 结构体一致：processes 在前）
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("processes", processes);
        result.put("services", services);

        // 转换为JSON
        try {
            String jsonData = JsonUtil.toJSON(result);
            printlnRaw(jsonData);
            return null;
        } catch (JsonProcessingException e) {
            return Fmt.format("JSON转换失败: %v", e);
        }
    }

    // =====================================================================
    // 小工具
    // =====================================================================

    /** 对应 Go 的 fmt.Println(x)：走 Colors 输出但不受静默模式抑制。 */
    private static void printlnRaw(String text) {
        Colors.colorPrint("", "%s", text);
    }

    /** Go 的 len(slice)：nil 视为 0。 */
    private static int sizeOf(List<?> list) {
        return list == null ? 0 : list.size();
    }

    /** 获取操作系统信息（对应 getOSInfo：runtime.GOOS + "/" + runtime.GOARCH）。 */
    private static String getOSInfo() {
        return Fmt.format("%s/%s", getOSName(), getArchitecture());
    }

    /** 获取操作系统名称（对应 Go 的 runtime.GOOS）。 */
    private static String getOSName() {
        return SystemUtil.osName();
    }

    /** 获取系统架构（对应 Go 的 runtime.GOARCH）。 */
    private static String getArchitecture() {
        return SystemUtil.architecture();
    }
}

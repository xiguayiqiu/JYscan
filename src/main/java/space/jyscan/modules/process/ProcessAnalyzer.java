package space.jyscan.modules.process;

import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.SystemUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * 进程与服务分析入口与输出格式化，移植自 freeclient/internal/process/process.go。
 *
 * <p>平台分支（Go 的 runtime.GOOS switch 与 linux_windows_stubs.go）在 Java 侧
 * 统一折叠为 {@link SystemUtil#isWindows()} / {@link SystemUtil#isLinux()} 判断。
 */
public final class ProcessAnalyzer {

    private ProcessAnalyzer() {
    }

    // =====================================================================
    // 分析入口（对应 Go 的 AnalyzeProcesses / AnalyzeServices）
    // =====================================================================

    /** 分析运行中的进程。 */
    public static List<ProcessInfo> analyzeProcesses() throws ProcessException {
        if (SystemUtil.isWindows()) {
            return WindowsProcesses.analyzeWindowsProcesses();
        }
        if (SystemUtil.isLinux()) {
            return LinuxProcesses.analyzeLinuxProcesses();
        }
        throw new ProcessException(Fmt.format("不支持的操作系统: %s", SystemUtil.osName()));
    }

    /** 分析系统服务。 */
    public static List<ServiceInfo> analyzeServices() throws ProcessException {
        if (SystemUtil.isWindows()) {
            return WindowsServices.analyzeWindowsServices();
        }
        if (SystemUtil.isLinux()) {
            return LinuxServices.analyzeLinuxServices();
        }
        throw new ProcessException(Fmt.format("不支持的操作系统: %s", SystemUtil.osName()));
    }

    // =====================================================================
    // 高权限过滤（对应 Go 的 GetHighPrivilegeProcesses / GetHighPrivilegeServices）
    // =====================================================================

    /** 获取高权限运行的进程。 */
    public static List<ProcessInfo> getHighPrivilegeProcesses() throws ProcessException {
        List<ProcessInfo> processes = analyzeProcesses();

        // Go 侧为 var 声明的切片，无匹配时保持 nil（JSON 序列化为 null）
        if (processes == null) {
            return null;
        }
        List<ProcessInfo> highPrivilegeProcesses = new ArrayList<>();
        for (ProcessInfo process : processes) {
            if (isHighPrivilege(process.privilege)) {
                highPrivilegeProcesses.add(process);
            }
        }

        return highPrivilegeProcesses.isEmpty() ? null : highPrivilegeProcesses;
    }

    /** 获取高权限运行的服务。 */
    public static List<ServiceInfo> getHighPrivilegeServices() throws ProcessException {
        List<ServiceInfo> services = analyzeServices();

        // Go 侧为 var 声明的切片，无匹配时保持 nil（JSON 序列化为 null）
        if (services == null) {
            return null;
        }
        List<ServiceInfo> highPrivilegeServices = new ArrayList<>();
        for (ServiceInfo service : services) {
            if (isHighPrivilege(service.privilege)) {
                highPrivilegeServices.add(service);
            }
        }

        return highPrivilegeServices.isEmpty() ? null : highPrivilegeServices;
    }

    /** 判断是否为高权限。 */
    static boolean isHighPrivilege(String privilege) {
        if (privilege == null) {
            return false;
        }
        String[] highPrivileges = {
                PrivilegeLevel.HIGH,
                PrivilegeLevel.SYSTEM
        };

        for (String highPriv : highPrivileges) {
            if (privilege.contains(highPriv)) {
                return true;
            }
        }

        return false;
    }

    // =====================================================================
    // 文本格式化（对应 Go 的 FormatProcessInfo / FormatServiceInfo /
    // FormatHighPrivilegeInfo，制表符与列宽完全一致）
    // =====================================================================

    /** 格式化进程信息输出。 */
    public static String formatProcessInfo(List<ProcessInfo> processes) {
        StringBuilder result = new StringBuilder();

        result.append("运行中的进程信息:\n");
        result.append("================================================================================\n");
        result.append("PID\t名称\t\t用户\t\tCPU使用率\t内存使用\t权限级别\n");
        result.append("================================================================================\n");

        if (processes != null) {
            for (ProcessInfo process : processes) {
                double memoryMB = (double) process.memoryUsage / 1024 / 1024;
                result.append(Fmt.format("%d\t%-15s\t%-10s\t%.1f%%\t\t%.1fMB\t%s\n",
                        process.pid, process.name, process.user, process.cpuUsage, memoryMB, process.privilege));
            }
        }

        return result.toString();
    }

    /** 格式化服务信息输出。 */
    public static String formatServiceInfo(List<ServiceInfo> services) {
        StringBuilder result = new StringBuilder();

        result.append("系统服务信息:\n");
        result.append("================================================================================\n");
        result.append("名称\t\t\t状态\t\t启动类型\t\t用户\t\t权限级别\n");
        result.append("================================================================================\n");

        if (services != null) {
            for (ServiceInfo service : services) {
                result.append(Fmt.format("%-20s\t%-8s\t%-10s\t%-10s\t%s\n",
                        service.name, service.status, service.startType, service.user, service.privilege));
            }
        }

        return result.toString();
    }

    /** 格式化高权限信息输出。 */
    public static String formatHighPrivilegeInfo(List<ProcessInfo> processes, List<ServiceInfo> services) {
        StringBuilder result = new StringBuilder();

        result.append("高权限运行的进程和服务:\n");
        result.append("================================================================================\n");

        if (processes != null && !processes.isEmpty()) {
            result.append("高权限进程:\n");
            for (ProcessInfo process : processes) {
                double memoryMB = (double) process.memoryUsage / 1024 / 1024;
                result.append(Fmt.format("  PID: %d, 名称: %s, 用户: %s, CPU: %.1f%%, 内存: %.1fMB, 权限: %s\n",
                        process.pid, process.name, process.user, process.cpuUsage, memoryMB, process.privilege));
            }
        }

        if (services != null && !services.isEmpty()) {
            result.append("\n高权限服务:\n");
            for (ServiceInfo service : services) {
                result.append(Fmt.format("  名称: %s, 状态: %s, 用户: %s, 权限: %s\n",
                        service.name, service.status, service.user, service.privilege));
            }
        }

        boolean noProcesses = processes == null || processes.isEmpty();
        boolean noServices = services == null || services.isEmpty();
        if (noProcesses && noServices) {
            result.append("未发现高权限运行的进程或服务\n");
        }

        return result.toString();
    }
}

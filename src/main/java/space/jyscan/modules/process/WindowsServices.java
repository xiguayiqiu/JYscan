package space.jyscan.modules.process;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Windows 服务采集，移植自 freeclient/internal/process/windows_services.go。
 *
 * <p>三条数据源按 Go 的顺序采集并合并：net start（运行中服务）→ sc query（全量）→
 * wmic service（路径与用户），全部通过 ProcessBuilder 外部命令实现。
 */
final class WindowsServices {

    private WindowsServices() {
    }

    /**
     * 分析Windows系统服务。
     *
     * @return 服务列表；三条数据源都失败时返回空列表（Go 侧同样返回空切片）
     */
    static List<ServiceInfo> analyzeWindowsServices() {
        List<ServiceInfo> services = new ArrayList<>();

        // 方法1: 使用net start命令获取运行中的服务
        List<ServiceInfo> runningServices = getServicesFromNetStart();
        if (runningServices != null) {
            services.addAll(runningServices);
        }

        // 方法2: 使用sc query命令获取所有服务详细信息
        List<ServiceInfo> allServices = getServicesFromSC();
        if (allServices != null) {
            services = mergeServiceInfo(services, allServices);
        }

        // 方法3: 使用wmic命令获取服务路径和用户信息
        List<ServiceInfo> detailedServices = getServicesFromWMIC();
        if (detailedServices != null) {
            services = mergeServiceInfo(services, detailedServices);
        }

        return services;
    }

    /**
     * 使用net start命令获取运行中的服务。
     *
     * @return 服务列表；net start 执行失败返回 null（Go：执行net start命令失败）
     */
    static List<ServiceInfo> getServicesFromNetStart() {
        String output = ProcessUtil.runOutput("net", "start");
        if (output == null) {
            return null;
        }

        List<ServiceInfo> services = new ArrayList<>();
        boolean inServiceList = false;

        for (String rawLine : output.split("\n")) {
            String line = rawLine.trim();
            if (line.endsWith("\r")) {
                line = line.substring(0, line.length() - 1).trim();
            }

            if (line.isEmpty()) {
                continue;
            }

            // 跳过标题行
            if (line.contains("已经启动以下 Windows 服务")
                    || line.contains("The following Windows services are started")) {
                inServiceList = true;
                continue;
            }

            if (line.contains("命令成功完成")
                    || line.contains("The command completed successfully")) {
                break;
            }

            if (inServiceList && !line.contains("---")) {
                ServiceInfo service = new ServiceInfo();
                service.name = extractServiceName(line);
                service.displayName = line;
                service.status = "Running";
                service.startType = "Auto"; // net start只显示运行中的服务，通常是自动启动
                service.user = "SYSTEM"; // 默认系统用户
                service.path = "";
                service.privilege = PrivilegeLevel.SYSTEM;
                services.add(service);
            }
        }

        return services;
    }

    /**
     * 使用sc query命令获取所有服务信息。
     *
     * @return 服务列表；sc query 执行失败返回 null（Go：执行sc query命令失败）
     */
    static List<ServiceInfo> getServicesFromSC() {
        String output = ProcessUtil.runOutput(
                "sc", "query", "type=", "service", "state=", "all");
        if (output == null) {
            return null;
        }

        List<ServiceInfo> services = new ArrayList<>();
        ServiceInfo currentService = null;

        for (String rawLine : output.split("\n")) {
            String line = rawLine.trim();
            if (line.endsWith("\r")) {
                line = line.substring(0, line.length() - 1).trim();
            }

            if (line.isEmpty()) {
                continue;
            }

            // 新服务开始
            if (line.startsWith("SERVICE_NAME:")) {
                if (currentService != null) {
                    services.add(currentService);
                }

                String name = line.substring("SERVICE_NAME:".length()).trim();
                currentService = new ServiceInfo();
                currentService.name = name;
                currentService.displayName = name;
                currentService.status = "Unknown";
                currentService.startType = "Unknown";
                currentService.user = "Unknown";
                currentService.path = "";
                currentService.privilege = PrivilegeLevel.UNKNOWN;
                continue;
            }

            if (currentService == null) {
                continue;
            }

            // 解析服务状态
            if (line.startsWith("STATE:")) {
                if (line.contains("RUNNING")) {
                    currentService.status = "Running";
                } else if (line.contains("STOPPED")) {
                    currentService.status = "Stopped";
                } else if (line.contains("PAUSED")) {
                    currentService.status = "Paused";
                }
            }

            // 解析启动类型
            if (line.startsWith("START_TYPE:")) {
                if (line.contains("AUTO_START")) {
                    currentService.startType = "Auto";
                } else if (line.contains("DEMAND_START")) {
                    currentService.startType = "Manual";
                } else if (line.contains("DISABLED")) {
                    currentService.startType = "Disabled";
                }
            }

            // 解析显示名称
            if (line.startsWith("DISPLAY_NAME:")) {
                String displayName = line.substring("DISPLAY_NAME:".length()).trim();
                currentService.displayName = displayName;
            }
        }

        // 添加最后一个服务
        if (currentService != null) {
            services.add(currentService);
        }

        return services;
    }

    /**
     * 使用wmic命令获取服务详细信息。
     *
     * @return 服务列表；wmic 执行失败返回 null（Go：执行wmic service命令失败）
     */
    static List<ServiceInfo> getServicesFromWMIC() {
        String output = ProcessUtil.runOutput(
                "wmic", "service", "get", "Name,PathName,StartName,State,StartMode", "/format:csv");
        if (output == null) {
            return null;
        }

        List<ServiceInfo> services = new ArrayList<>();
        // 跳过标题行
        boolean firstLine = true;

        for (String rawLine : output.split("\n")) {
            String line = rawLine.trim();
            if (line.endsWith("\r")) {
                line = line.substring(0, line.length() - 1).trim();
            }

            if (line.isEmpty() || line.startsWith("Node,")) {
                firstLine = false;
                continue;
            }

            if (firstLine) {
                firstLine = false;
                continue;
            }

            String[] fields = line.split(",", -1);
            if (fields.length < 6) {
                continue;
            }

            // CSV格式: Node,Name,PathName,StartName,State,StartMode
            String name = fields[1];
            String pathName = fields[2];
            String startName = fields[3];
            String state = fields[4];
            String startMode = fields[5];

            ServiceInfo service = new ServiceInfo();
            service.name = name;
            service.displayName = name;
            service.status = mapServiceState(state);
            service.startType = mapServiceStartMode(startMode);
            service.user = startName;
            service.path = pathName;
            service.privilege = getServicePrivilege(startName, pathName);

            services.add(service);
        }

        return services;
    }

    /** 从显示名称中提取服务名称。 */
    static String extractServiceName(String displayName) {
        // 尝试从显示名称中提取简短的服务名称
        String[] parts = ProcessUtil.fields(displayName);
        if (parts.length > 0) {
            // 取第一个单词作为服务名称
            return parts[0];
        }
        return displayName;
    }

    /** 映射服务状态。 */
    static String mapServiceState(String state) {
        if (state == null) {
            return "Unknown";
        }
        return switch (state.toUpperCase()) {
            case "RUNNING" -> "Running";
            case "STOPPED" -> "Stopped";
            case "PAUSED" -> "Paused";
            case "START_PENDING" -> "Starting";
            case "STOP_PENDING" -> "Stopping";
            default -> "Unknown";
        };
    }

    /** 映射服务启动模式。 */
    static String mapServiceStartMode(String startMode) {
        if (startMode == null) {
            return "Unknown";
        }
        return switch (startMode.toUpperCase()) {
            case "AUTO" -> "Auto";
            case "MANUAL" -> "Manual";
            case "DISABLED" -> "Disabled";
            case "BOOT" -> "Boot";
            case "SYSTEM" -> "System";
            default -> "Unknown";
        };
    }

    /** 根据服务用户和路径判断权限级别。 */
    static String getServicePrivilege(String user, String path) {
        String lowerUser = user == null ? "" : user.toLowerCase();
        String lowerPath = path == null ? "" : path.toLowerCase();

        // 系统服务
        if (lowerUser.contains("localsystem")
                || lowerUser.contains("nt authority\\system")) {
            return PrivilegeLevel.SYSTEM;
        }

        // 网络服务
        if (lowerUser.contains("networkservice")
                || lowerUser.contains("nt authority\\networkservice")) {
            return PrivilegeLevel.HIGH;
        }

        // 本地服务
        if (lowerUser.contains("localservice")
                || lowerUser.contains("nt authority\\localservice")) {
            return PrivilegeLevel.MEDIUM;
        }

        // 特定用户服务
        if (user != null && !user.isEmpty() && !lowerUser.contains("nt authority")) {
            return PrivilegeLevel.MEDIUM;
        }

        // 关键系统服务路径判断
        String[] criticalPaths = {
                "C:\\Windows\\System32",
                "C:\\Windows\\SysWOW64",
                "%SystemRoot%",
                "system32"
        };

        for (String criticalPath : criticalPaths) {
            if (lowerPath.contains(criticalPath.toLowerCase())) {
                return PrivilegeLevel.SYSTEM;
            }
        }

        return PrivilegeLevel.UNKNOWN;
    }

    /** 合并服务信息。 */
    static List<ServiceInfo> mergeServiceInfo(List<ServiceInfo> existing, List<ServiceInfo> newer) {
        List<ServiceInfo> result = existing == null ? new ArrayList<>() : new ArrayList<>(existing);

        // 创建现有服务的名称映射
        Map<String, Integer> existingMap = new HashMap<>();
        for (int i = 0; i < result.size(); i++) {
            existingMap.put(result.get(i).name, i);
        }

        // 合并或添加新信息
        if (newer != null) {
            for (ServiceInfo newService : newer) {
                Integer idx = existingMap.get(newService.name);
                if (idx != null) {
                    // 合并信息
                    ServiceInfo target = result.get(idx);
                    if (!"Unknown".equals(newService.status)) {
                        target.status = newService.status;
                    }
                    if (!"Unknown".equals(newService.startType)) {
                        target.startType = newService.startType;
                    }
                    if (!"Unknown".equals(newService.user) && !isEmpty(newService.user)) {
                        target.user = newService.user;
                    }
                    if (!isEmpty(newService.path)) {
                        target.path = newService.path;
                    }
                    if (!PrivilegeLevel.UNKNOWN.equals(newService.privilege)) {
                        target.privilege = newService.privilege;
                    }
                    if (!newService.name.equals(newService.displayName)) {
                        target.displayName = newService.displayName;
                    }
                } else {
                    // 添加新服务
                    result.add(newService);
                    existingMap.put(newService.name, result.size() - 1);
                }
            }
        }

        return result;
    }

    /** 获取服务对应的进程信息。 */
    @SuppressWarnings("unused")
    static int getServiceProcessInfo(String serviceName) {
        String output = ProcessUtil.runOutput("wmic", "service", "where",
                String.format("Name='%s'", serviceName), "get", "ProcessId", "/value");
        if (output == null) {
            return 0; // Go：返回 error
        }

        for (String line : output.split("\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("ProcessId=")) {
                String pidStr = trimmed.substring("ProcessId=".length()).trim();
                try {
                    return Integer.parseInt(pidStr);
                } catch (NumberFormatException ignored) {
                    // 继续查找
                }
            }
        }

        return 0; // Go：无法获取服务进程ID
    }

    private static boolean isEmpty(String s) {
        return s == null || s.isEmpty();
    }
}

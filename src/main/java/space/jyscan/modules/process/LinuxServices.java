package space.jyscan.modules.process;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Linux 服务采集，移植自 freeclient/internal/process/linux_services.go。
 *
 * <p>四种数据源按 Go 的顺序采集：systemctl → /etc/init.d(带状态探测) →
 * /etc/init.d(仅可执行文件) → 运行中的进程识别；后两者经
 * mergeLinuxServiceInfo 覆盖式合并。
 */
final class LinuxServices {

    private LinuxServices() {
    }

    /**
     * 分析Linux系统服务。
     *
     * <p>各方法失败只跳过该数据源；全部失败时返回 null（对应 Go 的 nil 切片）。
     */
    static List<ServiceInfo> analyzeLinuxServices() {
        List<ServiceInfo> services = null;

        // 方法1: 使用systemctl命令（systemd系统）
        List<ServiceInfo> systemdServices = getServicesFromSystemctl();
        if (systemdServices != null) {
            services = new ArrayList<>(systemdServices);
        }

        // 方法2: 使用service命令（SysV系统）
        List<ServiceInfo> sysvServices = getServicesFromService();
        if (sysvServices != null) {
            if (services == null) {
                services = new ArrayList<>();
            }
            services.addAll(sysvServices); // Go：append，不去重
        }

        // 方法3: 检查/etc/init.d目录
        List<ServiceInfo> initdServices = getServicesFromInitD();
        if (initdServices != null) {
            services = mergeLinuxServiceInfo(services, initdServices);
        }

        // 方法4: 检查运行中的进程，识别服务进程
        List<ServiceInfo> processServices = getServicesFromProcesses();
        if (processServices != null) {
            services = mergeLinuxServiceInfo(services, processServices);
        }

        return services;
    }

    /**
     * 使用systemctl命令获取服务信息。
     *
     * @return 服务列表；systemctl 执行失败返回 null（Go：执行systemctl命令失败）
     */
    static List<ServiceInfo> getServicesFromSystemctl() {
        // 获取所有服务列表
        String output = ProcessUtil.runOutput(
                "systemctl", "list-units", "--type=service", "--all", "--no-legend");
        if (output == null) {
            return null;
        }

        List<ServiceInfo> services = new ArrayList<>();
        for (String rawLine : output.split("\n")) {
            String line = rawLine.trim();
            if (line.isEmpty()) {
                continue;
            }

            // 解析systemctl输出格式
            String[] fields = ProcessUtil.fields(line);
            if (fields.length < 5) {
                continue;
            }

            String name = fields[0];
            String status = fields[3];
            String description = String.join(" ",
                    java.util.Arrays.copyOfRange(fields, 4, fields.length));

            // 获取服务的详细信息（Go：该函数恒返回 nil error，全部追加）
            services.add(getSystemctlServiceDetails(name, status, description));
        }

        return services;
    }

    /** 获取systemd服务的详细信息。 */
    static ServiceInfo getSystemctlServiceDetails(String name, String status, String description) {
        ServiceInfo service = new ServiceInfo();
        service.name = name;
        service.displayName = description;
        service.status = mapSystemdStatus(status);
        service.startType = getSystemdStartType(name);
        service.user = getSystemdServiceUser(name);
        service.path = getSystemdServicePath(name);
        service.privilege = getLinuxServicePrivilege(name);
        return service;
    }

    /**
     * 使用service命令获取服务信息（实际遍历 /etc/init.d 并逐个探测状态）。
     *
     * @return 服务列表；/etc/init.d 不可读返回 null
     */
    static List<ServiceInfo> getServicesFromService() {
        // 检查/etc/init.d目录
        Path initdDir = Path.of("/etc/init.d");
        List<Path> files = listDir(initdDir);
        if (files == null) {
            return null;
        }

        List<ServiceInfo> services = new ArrayList<>();
        for (Path file : files) {
            if (Files.isDirectory(file, LinkOption.NOFOLLOW_LINKS)) {
                continue;
            }

            String name = file.getFileName().toString();

            // 检查服务状态
            String status = getServiceStatus(name);

            ServiceInfo service = new ServiceInfo();
            service.name = name;
            service.displayName = name;
            service.status = status;
            service.startType = getSysVStartType(name);
            service.user = "root"; // SysV服务通常以root运行
            service.path = initdDir.resolve(name).toString();
            service.privilege = getLinuxServicePrivilege(name);

            services.add(service);
        }

        return services;
    }

    /**
     * 检查/etc/init.d目录获取服务信息（仅可执行文件，状态置 Unknown）。
     *
     * @return 服务列表；/etc/init.d 不可读返回 null
     */
    static List<ServiceInfo> getServicesFromInitD() {
        Path initdDir = Path.of("/etc/init.d");
        List<Path> files = listDir(initdDir);
        if (files == null) {
            return null;
        }

        List<ServiceInfo> services = new ArrayList<>();
        for (Path file : files) {
            if (Files.isDirectory(file, LinkOption.NOFOLLOW_LINKS)) {
                continue;
            }

            String name = file.getFileName().toString();

            // 检查是否为可执行文件（Go：file.Mode()&0111 == 0 则跳过）
            if (!hasAnyExecuteBit(file)) {
                continue;
            }

            ServiceInfo service = new ServiceInfo();
            service.name = name;
            service.displayName = name;
            service.status = "Unknown";
            service.startType = getSysVStartType(name);
            service.user = "root";
            service.path = initdDir.resolve(name).toString();
            service.privilege = getLinuxServicePrivilege(name);

            services.add(service);
        }

        return services;
    }

    /** 从运行中的进程识别服务。 */
    static List<ServiceInfo> getServicesFromProcesses() {
        // 获取所有进程
        List<ProcessInfo> processes = LinuxProcesses.analyzeLinuxProcesses();
        if (processes == null) {
            return null;
        }

        // 常见服务进程模式（Go 侧为 map，遍历顺序随机；这里按源码书写顺序固定）
        Map<String, String> servicePatterns = new LinkedHashMap<>();
        servicePatterns.put("sshd", "SSH服务");
        servicePatterns.put("apache2", "Apache Web服务器");
        servicePatterns.put("nginx", "Nginx Web服务器");
        servicePatterns.put("mysql", "MySQL数据库");
        servicePatterns.put("postgres", "PostgreSQL数据库");
        servicePatterns.put("docker", "Docker容器服务");
        servicePatterns.put("cron", "定时任务服务");
        servicePatterns.put("rsyslog", "系统日志服务");
        servicePatterns.put("dbus", "D-Bus消息总线");
        servicePatterns.put("NetworkManager", "网络管理服务");

        List<ServiceInfo> services = new ArrayList<>();
        for (ProcessInfo process : processes) {
            String lowerName = process.name == null ? "" : process.name.toLowerCase();
            for (Map.Entry<String, String> entry : servicePatterns.entrySet()) {
                if (lowerName.contains(entry.getKey().toLowerCase())) {
                    ServiceInfo service = new ServiceInfo();
                    service.name = process.name;
                    service.displayName = entry.getValue();
                    service.status = "Running";
                    service.startType = "Auto";
                    service.user = process.user;
                    service.path = process.path;
                    service.privilege = process.privilege;
                    services.add(service);
                    break;
                }
            }
        }

        return services;
    }

    /** 映射systemd服务状态。 */
    static String mapSystemdStatus(String status) {
        if (status == null) {
            return "Unknown";
        }
        return switch (status) {
            case "active" -> "Running";
            case "inactive" -> "Stopped";
            case "failed" -> "Failed";
            case "activating" -> "Starting";
            case "deactivating" -> "Stopping";
            default -> "Unknown";
        };
    }

    /** 获取systemd服务启动类型。 */
    static String getSystemdStartType(String serviceName) {
        String output = ProcessUtil.runOutput("systemctl", "is-enabled", serviceName);
        if (output == null) {
            return "Unknown";
        }

        String status = output.trim();
        return switch (status) {
            case "enabled" -> "Auto";
            case "disabled" -> "Manual";
            case "static" -> "Static";
            default -> "Unknown";
        };
    }

    /** 获取systemd服务运行用户。 */
    static String getSystemdServiceUser(String serviceName) {
        String output = ProcessUtil.runOutput("systemctl", "show", serviceName, "--property=User");
        if (output == null) {
            return "root";
        }

        for (String line : output.split("\n")) {
            if (line.startsWith("User=")) {
                String user = line.substring("User=".length()).trim();
                if (!user.isEmpty()) {
                    return user;
                }
            }
        }

        return "root";
    }

    /** 获取systemd服务可执行文件路径。 */
    static String getSystemdServicePath(String serviceName) {
        String output = ProcessUtil.runOutput("systemctl", "show", serviceName, "--property=ExecStart");
        if (output == null) {
            return "";
        }

        for (String line : output.split("\n")) {
            if (line.startsWith("ExecStart=")) {
                String path = line.substring("ExecStart=".length()).trim();
                // 提取可执行文件路径
                int idx = path.indexOf(' ');
                if (idx != -1) {
                    path = path.substring(0, idx);
                }
                return path;
            }
        }

        return "";
    }

    /** 获取SysV服务状态。 */
    static String getServiceStatus(String serviceName) {
        String output = ProcessUtil.runOutput("service", serviceName, "status");
        if (output == null) {
            return "Unknown";
        }

        String statusOutput = output.toLowerCase();
        if (statusOutput.contains("running") || statusOutput.contains("active")) {
            return "Running";
        } else if (statusOutput.contains("stopped") || statusOutput.contains("inactive")) {
            return "Stopped";
        }

        return "Unknown";
    }

    /** 获取SysV服务启动类型。 */
    static String getSysVStartType(String serviceName) {
        // 检查运行级别目录
        String[] runlevelDirs = {
                "/etc/rc0.d", "/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d",
                "/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d", "/etc/rcS.d"
        };

        for (String dir : runlevelDirs) {
            List<Path> files = listDir(Path.of(dir));
            if (files == null) {
                continue;
            }

            for (Path file : files) {
                String filename = file.getFileName().toString();
                // 检查是否以S开头（启动）或K开头（停止）
                if (filename.startsWith("S") && filename.contains(serviceName)) {
                    return "Auto";
                }
            }
        }

        return "Manual";
    }

    /** 判断Linux服务权限级别。 */
    static String getLinuxServicePrivilege(String serviceName) {
        String lowerName = serviceName == null ? "" : serviceName.toLowerCase();

        // 系统关键服务
        String[] systemServices = {
                "systemd", "init", "udev", "dbus", "syslog", "rsyslog",
                "network", "networking", "NetworkManager", "systemd-logind",
                "systemd-journald", "systemd-udevd", "cron", "atd",
        };

        for (String sysService : systemServices) {
            if (lowerName.contains(sysService.toLowerCase())) {
                return PrivilegeLevel.SYSTEM;
            }
        }

        // 网络服务
        String[] networkServices = {
                "sshd", "apache", "nginx", "mysql", "postgres", "docker",
                "iptables", "firewalld", "ufw", "fail2ban",
        };

        for (String netService : networkServices) {
            if (lowerName.contains(netService.toLowerCase())) {
                return PrivilegeLevel.HIGH;
            }
        }

        // 普通服务
        return PrivilegeLevel.MEDIUM;
    }

    /**
     * 合并Linux服务信息。
     *
     * @param existing 已有列表（可为 null，对应 Go 的 nil 切片）
     * @param newer    新采集的列表
     */
    static List<ServiceInfo> mergeLinuxServiceInfo(List<ServiceInfo> existing, List<ServiceInfo> newer) {
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
                    if (newService.user != null && !newService.user.isEmpty()) {
                        target.user = newService.user;
                    }
                    if (newService.path != null && !newService.path.isEmpty()) {
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

    // =====================================================================
    // 小工具
    // =====================================================================

    /** 列出目录条目；目录不可读返回 null（对应 Go 的 ioutil.ReadDir 返回 error）。 */
    private static List<Path> listDir(Path dir) {
        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path file : stream) {
                files.add(file);
            }
        } catch (IOException e) {
            return null;
        }
        return files;
    }

    /** 检查是否设置了任意执行位（Go：file.Mode()&0111 != 0）。 */
    private static boolean hasAnyExecuteBit(Path file) {
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS);
            return perms.contains(PosixFilePermission.OWNER_EXECUTE)
                    || perms.contains(PosixFilePermission.GROUP_EXECUTE)
                    || perms.contains(PosixFilePermission.OTHERS_EXECUTE);
        } catch (IOException | UnsupportedOperationException e) {
            return false;
        }
    }
}

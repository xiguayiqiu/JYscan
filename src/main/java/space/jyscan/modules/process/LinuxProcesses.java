package space.jyscan.modules.process;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Linux 进程采集，移植自 freeclient/internal/process/linux_processes.go。
 *
 * <p>三种数据源按 Go 的顺序合并：ps 命令 → /proc 文件系统 → top 命令，
 * 后两者通过 mergeLinuxProcessInfo 覆盖式合并进已有列表。
 */
final class LinuxProcesses {

    private static final String PROC_DIR = "/proc";

    private LinuxProcesses() {
    }

    /**
     * 分析Linux系统进程。
     *
     * <p>各方法失败（Go 的 err != nil 分支）只跳过该数据源；
     * 全部失败时返回 null（对应 Go 的 nil 切片，JSON 序列化为 null）。
     */
    static List<ProcessInfo> analyzeLinuxProcesses() {
        List<ProcessInfo> processes = null;

        // 方法1: 使用ps命令获取进程信息
        List<ProcessInfo> psProcesses = getProcessesFromPS();
        if (psProcesses != null) {
            processes = new ArrayList<>(psProcesses);
        }

        // 方法2: 解析/proc文件系统
        List<ProcessInfo> procProcesses = getProcessesFromProc();
        if (procProcesses != null) {
            processes = mergeLinuxProcessInfo(processes, procProcesses);
        }

        // 方法3: 使用top命令获取CPU和内存使用率
        List<ProcessInfo> topProcesses = getProcessesFromTop();
        if (topProcesses != null) {
            processes = mergeLinuxProcessInfo(processes, topProcesses);
        }

        return processes;
    }

    /**
     * 使用ps命令获取进程信息。
     *
     * @return 进程列表；ps 执行失败返回 null（Go：执行ps命令失败）
     */
    static List<ProcessInfo> getProcessesFromPS() {
        // 使用ps命令获取详细的进程信息
        String output = ProcessUtil.runOutput("ps", "-eo", "pid,user,pcpu,pmem,comm,args", "--no-headers");
        if (output == null) {
            return null;
        }

        List<ProcessInfo> processes = new ArrayList<>();
        for (String rawLine : output.split("\n")) {
            String line = rawLine.trim();
            if (line.isEmpty()) {
                continue;
            }

            // 解析ps输出格式
            String[] fields = line.split("\\s+");
            if (fields.length < 6) {
                continue;
            }

            int pid;
            try {
                pid = Integer.parseInt(fields[0]);
            } catch (NumberFormatException e) {
                continue;
            }

            String user = fields[1];
            double cpuUsage = parseDouble(fields[2]);
            double memoryUsage = parseDouble(fields[3]);
            String name = fields[4];
            String commandLine = String.join(" ", java.util.Arrays.copyOfRange(fields, 5, fields.length));

            // 获取进程路径和权限信息
            String path = getProcessPath(pid);
            String privilege = getLinuxProcessPrivilege(user, name);

            // 计算内存使用量（字节）
            long memoryBytes = (long) (memoryUsage * 1024 * 1024); // 转换为字节

            ProcessInfo process = new ProcessInfo();
            process.pid = pid;
            process.name = name;
            process.user = user;
            process.cpuUsage = cpuUsage;
            process.memoryUsage = memoryBytes;
            process.privilege = privilege;
            process.path = path;
            process.commandLine = commandLine;

            processes.add(process);
        }

        return processes;
    }

    /**
     * 解析/proc文件系统获取进程信息。
     *
     * @return 进程列表；/proc 不可读返回 null
     */
    static List<ProcessInfo> getProcessesFromProc() {
        List<ProcessInfo> processes = new ArrayList<>();

        Path procPath = Path.of(PROC_DIR);
        List<Path> dirs = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(procPath)) {
            for (Path file : stream) {
                // 检查是否为数字目录（进程ID）
                if (!Files.isDirectory(file, LinkOption.NOFOLLOW_LINKS)) {
                    continue;
                }
                dirs.add(file);
            }
        } catch (IOException e) {
            return null;
        }

        for (Path file : dirs) {
            String pidStr = file.getFileName().toString();
            int pid;
            try {
                pid = Integer.parseInt(pidStr);
            } catch (NumberFormatException e) {
                continue;
            }

            // 获取进程信息（失败的进程直接跳过，与 Go 的 err == nil 判断一致）
            ProcessInfo process = getProcessInfoFromProc(pid);
            if (process != null) {
                processes.add(process);
            }
        }

        return processes;
    }

    /**
     * 从/proc文件系统获取单个进程信息。
     *
     * @return 进程信息；任何读取失败返回 null（Go：返回 error 由调用方跳过）
     */
    static ProcessInfo getProcessInfoFromProc(int pid) {
        String procPathStr = String.format("/proc/%d", pid);
        Path procPath = Path.of(procPathStr);

        // 检查进程目录是否存在
        if (Files.notExists(procPath)) {
            return null;
        }

        // 读取进程状态文件
        String statusContent = readFile(procPath.resolve("status"));
        // 读取进程命令行
        String cmdlineContent = readFile(procPath.resolve("cmdline"));
        if (statusContent == null || cmdlineContent == null) {
            return null;
        }

        // 读取进程可执行文件链接
        String exePath = readExeLink(procPath);

        // 解析进程状态信息
        String name = "";
        String user = "";
        long memoryUsage = 0;

        String[] lines = statusContent.split("\n");
        for (String line : lines) {
            if (line.startsWith("Name:")) {
                name = line.substring("Name:".length()).trim();
            } else if (line.startsWith("Uid:")) {
                String[] uidFields = ProcessUtil.fields(line.substring("Uid:".length()));
                if (uidFields.length > 0) {
                    // 获取用户名
                    user = getUsernameFromUID(uidFields[0]);
                }
            } else if (line.startsWith("VmRSS:")) {
                // 获取内存使用量
                String[] memoryFields = ProcessUtil.fields(line.substring("VmRSS:".length()));
                if (memoryFields.length > 0) {
                    try {
                        long memoryKB = Long.parseLong(memoryFields[0]);
                        memoryUsage = memoryKB * 1024; // 转换为字节
                    } catch (NumberFormatException ignored) {
                        // Go 侧忽略解析错误，保持 0
                    }
                }
            }
        }

        // 解析命令行参数
        String commandLine = cmdlineContent.replace('\0', ' ').trim();

        // 获取CPU使用率（需要计算）
        double cpuUsage = getProcessCPUUsage(pid);

        // 判断权限级别
        String privilege = getLinuxProcessPrivilege(user, name);

        ProcessInfo process = new ProcessInfo();
        process.pid = pid;
        process.name = name;
        process.user = user;
        process.cpuUsage = cpuUsage;
        process.memoryUsage = memoryUsage;
        process.privilege = privilege;
        process.path = exePath;
        process.commandLine = commandLine;

        return process;
    }

    /**
     * 使用top命令获取进程CPU和内存使用率。
     *
     * @return 进程列表；top 执行失败返回 null（Go：执行top命令失败）
     */
    static List<ProcessInfo> getProcessesFromTop() {
        // 使用top命令获取进程信息
        String output = ProcessUtil.runOutput("top", "-b", "-n", "1", "-o", "%CPU");
        if (output == null) {
            return null;
        }

        List<ProcessInfo> processes = new ArrayList<>();
        boolean inProcessSection = false;

        for (String rawLine : output.split("\n")) {
            String line = rawLine.trim();

            // 跳过空行和标题行
            if (line.isEmpty()) {
                continue;
            }

            // 检查是否进入进程信息部分
            if (line.startsWith("PID") && line.contains("USER")) {
                inProcessSection = true;
                continue;
            }

            if (inProcessSection) {
                String[] fields = line.split("\\s+");
                if (fields.length < 12) {
                    continue;
                }

                int pid;
                try {
                    pid = Integer.parseInt(fields[0]);
                } catch (NumberFormatException e) {
                    continue;
                }

                String user = fields[1];
                double cpuUsage = parseDouble(fields[8]);
                double memoryUsage = parseDouble(fields[9]);
                String name = fields[11];

                // 获取进程路径和权限信息
                String path = getProcessPath(pid);
                String privilege = getLinuxProcessPrivilege(user, name);

                // 计算内存使用量（字节）
                long memoryBytes = (long) (memoryUsage * 1024 * 1024); // 转换为字节

                ProcessInfo process = new ProcessInfo();
                process.pid = pid;
                process.name = name;
                process.user = user;
                process.cpuUsage = cpuUsage;
                process.memoryUsage = memoryBytes;
                process.privilege = privilege;
                process.path = path;
                process.commandLine = ""; // top命令不提供完整命令行

                processes.add(process);
            }
        }

        return processes;
    }

    /** 获取进程可执行文件路径。 */
    static String getProcessPath(int pid) {
        Path exeLink = Path.of(String.format("/proc/%d/exe", pid));
        try {
            return Files.readSymbolicLink(exeLink).toString();
        } catch (IOException e) {
            return "";
        }
    }

    /** 获取进程CPU使用率。 */
    static double getProcessCPUUsage(int pid) {
        Path statFile = Path.of(String.format("/proc/%d/stat", pid));
        String content = readFile(statFile);
        if (content == null) {
            return 0.0;
        }

        // 解析stat文件内容
        String[] fields = ProcessUtil.fields(content);
        if (fields.length < 17) {
            return 0.0;
        }

        // 获取进程时间信息
        long utime = parseUnsignedLong(fields[13]);
        long stime = parseUnsignedLong(fields[14]);

        // 获取系统总时间
        long totalTime = getSystemTotalTime();
        if (totalTime == 0) {
            return 0.0;
        }

        // 计算CPU使用率
        long processTime = utime + stime;
        return ((double) processTime / (double) totalTime) * 100.0;
    }

    /** 获取系统总CPU时间。 */
    static long getSystemTotalTime() {
        String content = readFile(Path.of("/proc/stat"));
        if (content == null) {
            return 0;
        }

        String[] lines = content.split("\n");
        for (String line : lines) {
            if (line.startsWith("cpu ")) {
                String[] fields = ProcessUtil.fields(line);
                if (fields.length >= 8) {
                    long total = 0;
                    for (int i = 1; i <= 7; i++) {
                        total += parseUnsignedLong(fields[i]);
                    }
                    return total;
                }
            }
        }

        return 0;
    }

    /** 根据UID获取用户名。 */
    static String getUsernameFromUID(String uidStr) {
        int uid;
        try {
            uid = Integer.parseInt(uidStr.trim());
        } catch (NumberFormatException e) {
            return "";
        }

        // 尝试从/etc/passwd获取用户名
        String content = readFile(Path.of("/etc/passwd"));
        if (content == null) {
            return String.format("uid_%d", uid);
        }

        String needle = String.format(":%d:", uid);
        String[] lines = content.split("\n");
        for (String line : lines) {
            if (line.contains(needle)) {
                String[] fields = line.split(":", -1);
                if (fields.length >= 3 && fields[2].equals(uidStr)) {
                    return fields[0];
                }
            }
        }

        return String.format("uid_%d", uid);
    }

    /** 判断Linux进程权限级别。 */
    static String getLinuxProcessPrivilege(String user, String processName) {
        String lowerName = processName == null ? "" : processName.toLowerCase();

        // 系统进程（以root用户运行的系统关键进程）
        if ("root".equals(user)) {
            String[] systemProcesses = {
                    "systemd", "init", "udev", "dbus", "syslog", "rsyslog",
                    "kthreadd", "ksoftirqd", "kworker", "migration", "rcu",
                    "cron", "atd", "sshd", "NetworkManager"
            };

            for (String sysProc : systemProcesses) {
                if (lowerName.contains(sysProc.toLowerCase())) {
                    return PrivilegeLevel.SYSTEM;
                }
            }

            // 网络服务进程
            String[] networkProcesses = {
                    "apache", "nginx", "mysql", "postgres", "docker",
                    "iptables", "firewalld", "ufw", "fail2ban"
            };

            for (String netProc : networkProcesses) {
                if (lowerName.contains(netProc.toLowerCase())) {
                    return PrivilegeLevel.HIGH;
                }
            }

            return PrivilegeLevel.HIGH; // root用户运行的其他进程
        }

        // 普通用户进程
        if ("nobody".equals(user) || "www-data".equals(user)
                || "mysql".equals(user) || "postgres".equals(user)) {
            return PrivilegeLevel.MEDIUM;
        }

        // 其他用户进程
        return PrivilegeLevel.LOW;
    }

    /**
     * 合并Linux进程信息。
     *
     * @param existing 已有列表（可为 null，对应 Go 的 nil 切片）
     * @param newer    新采集的列表
     */
    static List<ProcessInfo> mergeLinuxProcessInfo(List<ProcessInfo> existing, List<ProcessInfo> newer) {
        List<ProcessInfo> result = existing == null ? new ArrayList<>() : new ArrayList<>(existing);

        // 创建现有进程的PID映射
        Map<Integer, Integer> existingMap = new HashMap<>();
        for (int i = 0; i < result.size(); i++) {
            existingMap.put(result.get(i).pid, i);
        }

        // 合并或添加新信息
        if (newer != null) {
            for (ProcessInfo newProcess : newer) {
                Integer idx = existingMap.get(newProcess.pid);
                if (idx != null) {
                    // 合并信息
                    ProcessInfo target = result.get(idx);
                    if (newProcess.cpuUsage > 0) {
                        target.cpuUsage = newProcess.cpuUsage;
                    }
                    if (newProcess.memoryUsage > 0) {
                        target.memoryUsage = newProcess.memoryUsage;
                    }
                    if (newProcess.user != null && !newProcess.user.isEmpty()) {
                        target.user = newProcess.user;
                    }
                    if (newProcess.path != null && !newProcess.path.isEmpty()) {
                        target.path = newProcess.path;
                    }
                    if (!PrivilegeLevel.UNKNOWN.equals(newProcess.privilege)) {
                        target.privilege = newProcess.privilege;
                    }
                    if (newProcess.commandLine != null && !newProcess.commandLine.isEmpty()) {
                        target.commandLine = newProcess.commandLine;
                    }
                } else {
                    // 添加新进程
                    result.add(newProcess);
                    existingMap.put(newProcess.pid, result.size() - 1);
                }
            }
        }

        return result;
    }

    // =====================================================================
    // 小工具
    // =====================================================================

    /**
     * 读取整个文件为字符串，失败返回 null（对应 Go 的 ioutil.ReadFile 返回 error）。
     *
     * <p>用 new String(bytes, UTF_8) 而非 Files.readString：与 Go 的 string(bytes) 一致，
     * 非法字节替换为 U+FFFD 而不是抛异常（cmdline 可能含任意二进制参数）。
     */
    private static String readFile(Path path) {
        try {
            return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    /** 读取 /proc/<pid>/exe 符号链接，失败返回空串（Go：os.Readlink 错误被忽略）。 */
    private static String readExeLink(Path procPath) {
        try {
            return Files.readSymbolicLink(procPath.resolve("exe")).toString();
        } catch (IOException e) {
            return "";
        }
    }

    /** strconv.ParseFloat 语义：失败返回 0。 */
    private static double parseDouble(String s) {
        try {
            return Double.parseDouble(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** strconv.ParseUint 语义：失败返回 0。 */
    private static long parseUnsignedLong(String s) {
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}

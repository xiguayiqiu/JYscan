package space.jyscan.modules.process;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Psapi;
import com.sun.jna.platform.win32.Tlhelp32;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinNT;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Windows 进程采集，移植自 freeclient/internal/process/windows.go。
 *
 * <p>与 Go 版一致分两条数据源：方法1 走 tasklist/wmic 外部命令（ProcessBuilder），
 * 方法2 走 Windows API（Go 的 golang.org/x/sys/windows，这里改用 JNA 的
 * Kernel32/Advapi32/Psapi），最后 mergeProcessInfo 覆盖式合并。
 *
 * <p>仅在 {@code SystemUtil.isWindows()} 分支被调用，Linux 上不会触发
 * JNA 的 kernel32/advapi32 加载。
 */
final class WindowsProcesses {

    // Windows API 常量（对应 Go 侧的 const 定义）
    private static final int PROCESS_QUERY_INFORMATION = 0x0400;
    private static final int PROCESS_VM_READ = 0x0010;
    private static final int MAX_PATH = 260;

    private WindowsProcesses() {
    }

    /**
     * 分析Windows系统进程。
     *
     * @return 进程列表；两条数据源都失败时返回空列表（Go 侧同样返回空切片）
     */
    static List<ProcessInfo> analyzeWindowsProcesses() {
        List<ProcessInfo> processes = new ArrayList<>();

        // 方法1: 使用tasklist命令
        List<ProcessInfo> tasklistProcesses = getProcessesFromTasklist();
        if (tasklistProcesses != null) {
            processes.addAll(tasklistProcesses);
        }

        // 方法2: 使用Windows API获取更详细信息
        List<ProcessInfo> apiProcesses = getProcessesFromAPI();
        if (apiProcesses != null) {
            // 合并或替换信息
            processes = mergeProcessInfo(processes, apiProcesses);
        }

        return processes;
    }

    /**
     * 使用tasklist命令获取进程信息。
     *
     * @return 进程列表；tasklist 执行失败返回 null（Go：执行tasklist命令失败）
     */
    static List<ProcessInfo> getProcessesFromTasklist() {
        String output = ProcessUtil.runOutput("tasklist", "/fo", "csv", "/nh");
        if (output == null) {
            return null;
        }

        List<ProcessInfo> processes = new ArrayList<>();
        for (String line : output.split("\n")) {
            if (line.isEmpty()) {
                continue;
            }
            if (line.endsWith("\r")) {
                line = line.substring(0, line.length() - 1);
            }

            // 解析CSV格式
            String[] fields = parseCSVLine(line);
            if (fields.length < 5) {
                continue;
            }

            // 解析进程信息
            int pid;
            try {
                pid = Integer.parseInt(fields[1].trim());
            } catch (NumberFormatException e) {
                continue;
            }

            String name = trimQuotes(fields[0].trim());
            String sessionName = trimQuotes(fields[2].trim());
            int sessionNum = 0;
            try {
                sessionNum = Integer.parseInt(fields[3].trim());
            } catch (NumberFormatException ignored) {
                // Go 侧忽略解析错误，保持 0
            }

            // 解析内存使用量
            long memoryUsage = parseMemoryUsage(trimQuotes(fields[4].trim()));

            // 获取用户和权限信息
            String[] userPrivilege = getUserAndPrivilege(pid, sessionName, sessionNum);

            ProcessInfo process = new ProcessInfo();
            process.pid = pid;
            process.name = name;
            process.user = userPrivilege[0];
            process.cpuUsage = 0.0; // tasklist不提供CPU使用率
            process.memoryUsage = memoryUsage;
            process.privilege = userPrivilege[1];
            process.path = ""; // 需要额外获取
            process.commandLine = ""; // 需要额外获取

            processes.add(process);
        }

        return processes;
    }

    /**
     * 使用Windows API（Toolhelp32进程快照）获取进程信息。
     *
     * @return 进程列表；快照或首个进程获取失败返回 null（Go：返回 error）
     */
    static List<ProcessInfo> getProcessesFromAPI() {
        // 创建进程快照
        WinNT.HANDLE snapshot = Kernel32.INSTANCE
                .CreateToolhelp32Snapshot(Tlhelp32.TH32CS_SNAPPROCESS, new WinDef.DWORD(0));
        if (!isValidHandle(snapshot)) {
            return null; // Go：创建进程快照失败
        }

        try {
            List<ProcessInfo> processes = new ArrayList<>();
            Tlhelp32.PROCESSENTRY32 entry = new Tlhelp32.PROCESSENTRY32();
            entry.dwSize = new WinDef.DWORD(entry.size());

            if (!Kernel32.INSTANCE.Process32First(snapshot, entry)) {
                return null; // Go：获取第一个进程失败
            }

            while (true) {
                String processName = fromWideString(entry.szExeFile);

                // 获取进程详细信息
                ProcessInfo process = getProcessDetails(entry.th32ProcessID.intValue(), processName);
                if (process != null) {
                    processes.add(process);
                }

                // 获取下一个进程
                if (!Kernel32.INSTANCE.Process32Next(snapshot, entry)) {
                    break;
                }
            }

            return processes;
        } finally {
            Kernel32.INSTANCE.CloseHandle(snapshot);
        }
    }

    /**
     * 获取进程详细信息（打开句柄后逐项采集，单项失败只丢弃该项）。
     *
     * @return 进程信息；OpenProcess 失败返回 null（Go：返回 error 由调用方跳过）
     */
    static ProcessInfo getProcessDetails(int pid, String name) {
        ProcessInfo process = new ProcessInfo();
        process.pid = pid;
        process.name = name == null ? "" : name;

        // 打开进程句柄
        WinNT.HANDLE processHandle = Kernel32.INSTANCE
                .OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (!isValidHandle(processHandle)) {
            return null; // Go：OpenProcess 失败，调用方跳过
        }

        try {
            // 获取进程路径
            String path = getWindowsProcessPath(processHandle);
            if (path != null) {
                process.path = path;
            }

            // 获取命令行参数
            String cmdLine = getCommandLine(pid);
            if (cmdLine != null) {
                process.commandLine = cmdLine;
            }

            // 获取用户信息
            String user = getProcessUser(processHandle);
            if (user != null) {
                process.user = user;
            }

            // 获取内存使用量
            Long memory = getProcessMemory(pid);
            if (memory != null) {
                process.memoryUsage = memory;
            }

            // 判断权限级别
            process.privilege = getPrivilegeLevel(process.user, process.name);

            return process;
        } finally {
            Kernel32.INSTANCE.CloseHandle(processHandle);
        }
    }

    /** 获取Windows进程可执行文件路径（GetModuleFileNameEx）。 */
    static String getWindowsProcessPath(WinNT.HANDLE processHandle) {
        char[] path = new char[MAX_PATH];
        int length = Psapi.INSTANCE.GetModuleFileNameExW(processHandle, null, path, MAX_PATH);
        if (length <= 0) {
            return null; // Go：返回 error 由调用方忽略
        }
        return new String(path, 0, length);
    }

    /**
     * 获取进程命令行参数（WMI）。
     *
     * <p>Go 版此处误传了句柄值（wmic 恒查不到，永远返回空），这里传入真实 PID。
     */
    static String getCommandLine(int pid) {
        String output = ProcessUtil.runOutput("wmic", "process", "where",
                String.format("ProcessId=%d", pid), "get", "CommandLine");
        if (output == null) {
            return null;
        }

        String[] lines = output.split("\n", -1);
        if (lines.length > 1) {
            return lines[1].trim();
        }
        return null; // Go：无法获取命令行参数
    }

    /** 获取进程运行用户（OpenProcessToken + LookupAccount）。 */
    static String getProcessUser(WinNT.HANDLE processHandle) {
        WinNT.HANDLEByReference tokenRef = new WinNT.HANDLEByReference();
        if (!Advapi32.INSTANCE.OpenProcessToken(processHandle, WinNT.TOKEN_QUERY, tokenRef)) {
            return null; // Go：错误由调用方忽略
        }

        try {
            // 获取用户SID对应的账户名
            Advapi32Util.Account account = Advapi32Util.getTokenAccount(tokenRef.getValue());
            if (account.domain != null && !account.domain.isEmpty()) {
                return String.format("%s\\%s", account.domain, account.name);
            }
            return account.name;
        } catch (Exception e) {
            return null; // LookupAccount 失败，Go 侧同样由调用方忽略
        } finally {
            Kernel32.INSTANCE.CloseHandle(tokenRef.getValue());
        }
    }

    /**
     * 获取进程内存使用量（tasklist）。
     *
     * <p>Go 版此处同样误传了句柄值，这里传入真实 PID。
     *
     * @return 内存字节数；查不到该进程时返回 null（Go：返回 error）
     */
    static Long getProcessMemory(int pid) {
        String output = ProcessUtil.runOutput("tasklist", "/fi",
                String.format("PID eq %d", pid), "/fo", "csv", "/nh");
        if (output == null) {
            return null;
        }

        for (String line : output.split("\n")) {
            if (line.contains(String.valueOf(pid))) {
                String[] fields = parseCSVLine(line);
                if (fields.length >= 5) {
                    String memoryStr = trimQuotes(fields[4].trim());
                    return parseMemoryUsage(memoryStr);
                }
            }
        }

        return null; // Go：无法获取进程内存使用量
    }

    /** 根据会话信息获取用户和权限，返回 {user, privilege}。 */
    static String[] getUserAndPrivilege(int pid, String sessionName, int sessionNum) {
        String user = "未知用户";
        String privilege = PrivilegeLevel.UNKNOWN;

        // 根据会话判断权限
        if ("Services".equals(sessionName)) {
            user = "SYSTEM";
            privilege = PrivilegeLevel.SYSTEM;
        } else if (sessionNum == 0) {
            user = "SYSTEM";
            privilege = PrivilegeLevel.SYSTEM;
        } else {
            // 尝试获取具体用户名
            String currentUser = getCurrentUser();
            if (currentUser != null) {
                user = currentUser;
            }
            privilege = PrivilegeLevel.MEDIUM;
        }

        // 特殊进程权限判断
        if (isSystemProcess(pid, sessionName)) {
            privilege = PrivilegeLevel.SYSTEM;
        }

        return new String[]{user, privilege};
    }

    /** 获取当前用户名（对应 Go 的 os.Getenv("USERNAME")）。 */
    static String getCurrentUser() {
        String user = System.getenv("USERNAME");
        return user == null ? "" : user;
    }

    /** 判断是否为系统进程（Go 侧 pid 参数未参与判断，保持一致）。 */
    @SuppressWarnings("unused")
    static boolean isSystemProcess(int pid, String sessionName) {
        if (sessionName == null) {
            return false;
        }
        String[] systemProcesses = {
                "System", "smss.exe", "csrss.exe", "wininit.exe",
                "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe"
        };

        for (String sysProc : systemProcesses) {
            if (sessionName.contains(sysProc)) {
                return true;
            }
        }

        return false;
    }

    /** 根据用户和进程名判断权限级别。 */
    static String getPrivilegeLevel(String user, String processName) {
        String lowerUser = user == null ? "" : user.toLowerCase();

        // 系统用户
        if (lowerUser.contains("system") || lowerUser.contains("nt authority")) {
            return PrivilegeLevel.SYSTEM;
        }

        // 管理员用户
        if (lowerUser.contains("administrator")) {
            return PrivilegeLevel.HIGH;
        }

        // 系统关键进程
        String[] systemProcesses = {
                "csrss.exe", "lsass.exe", "services.exe", "winlogon.exe",
                "smss.exe", "wininit.exe", "spoolsv.exe", "taskhost.exe"
        };

        if (processName != null) {
            for (String sysProc : systemProcesses) {
                if (processName.equalsIgnoreCase(sysProc)) {
                    return PrivilegeLevel.SYSTEM;
                }
            }
        }

        // 普通用户进程
        return PrivilegeLevel.MEDIUM;
    }

    /** 解析CSV格式的行（与 Go 的 parseCSVLine 逐分支一致）。 */
    static String[] parseCSVLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char ch = line.charAt(i);
            if (ch == '"') {
                inQuotes = !inQuotes;
            } else if (ch == ',') {
                if (!inQuotes) {
                    fields.add(field.toString());
                    field.setLength(0);
                } else {
                    field.append(ch);
                }
            } else {
                field.append(ch);
            }
        }

        // 添加最后一个字段（Go：field.Len() > 0 才追加）
        if (field.length() > 0) {
            fields.add(field.toString());
        }

        return fields.toArray(new String[0]);
    }

    /** 解析内存使用量字符串（Go：ParseUint 成功后 *1024 转字节）。 */
    static long parseMemoryUsage(String memoryStr) {
        if (memoryStr == null) {
            return 0;
        }
        // 移除逗号和单位
        String s = memoryStr.replace(",", "").replace(" K", "");
        if (s.isEmpty() || s.startsWith("-")) {
            return 0; // Go 的 ParseUint 不接受负数
        }
        try {
            return Long.parseLong(s) * 1024; // 转换为字节
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** 合并进程信息（只覆盖 Path/CommandLine/User/MemoryUsage，与 Go 一致）。 */
    static List<ProcessInfo> mergeProcessInfo(List<ProcessInfo> existing, List<ProcessInfo> newer) {
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
                    if (newProcess.path != null && !newProcess.path.isEmpty()) {
                        target.path = newProcess.path;
                    }
                    if (newProcess.commandLine != null && !newProcess.commandLine.isEmpty()) {
                        target.commandLine = newProcess.commandLine;
                    }
                    if (newProcess.user != null && !newProcess.user.isEmpty()) {
                        target.user = newProcess.user;
                    }
                    if (newProcess.memoryUsage > 0) {
                        target.memoryUsage = newProcess.memoryUsage;
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

    /** 判断句柄是否有效（非 NULL 且非 INVALID_HANDLE_VALUE）。 */
    private static boolean isValidHandle(WinNT.HANDLE handle) {
        if (handle == null || handle.getPointer() == null) {
            return false;
        }
        long value = Pointer.nativeValue(handle.getPointer());
        return value != 0 && value != -1L;
    }

    /** Windows 错误码转文本（供 "xxx失败: %v" 消息拼接）。 */
    @SuppressWarnings("unused")
    private static String lastErrorMessage() {
        try {
            return new Win32Exception(Native.getLastError()).getMessage();
        } catch (Exception e) {
            return "错误代码 " + Native.getLastError();
        }
    }

    /** 宽字符数组转字符串（对应 Go 的 windows.UTF16ToString，遇 NUL 截断）。 */
    private static String fromWideString(char[] chars) {
        if (chars == null) {
            return "";
        }
        int len = 0;
        while (len < chars.length && chars[len] != '\0') {
            len++;
        }
        return new String(chars, 0, len);
    }

    /** 去掉首尾的双引号字符（对应 Go 的 strings.Trim(s, "\"")）。 */
    private static String trimQuotes(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && s.charAt(start) == '"') {
            start++;
        }
        while (end > start && s.charAt(end - 1) == '"') {
            end--;
        }
        return s.substring(start, end);
    }
}

package space.jyscan.core.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 系统命令与平台判断，对应 internal/utils/system.go 与 exec.go。
 */
public final class SystemUtil {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static volatile String osNameCache;

    private SystemUtil() {
    }

    /** 执行系统命令并返回合并输出（stdout+stderr），对应 Go 的 utils.RunCommand。 */
    public static String runCommand(String command) throws IOException, InterruptedException {
        List<String> shell = new ArrayList<>();
        if (isWindows()) {
            shell.add("cmd");
            shell.add("/C");
        } else {
            shell.add("sh");
            shell.add("-c");
        }
        shell.add(command);

        ProcessBuilder pb = new ProcessBuilder(shell);
        pb.redirectErrorStream(true);
        Process proc = pb.start();

        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(line);
            }
        }
        proc.waitFor(60, TimeUnit.SECONDS);
        return sb.toString().trim();
    }

    /** 执行命令，忽略异常时返回空串。 */
    public static String runCommandQuietly(String command) {
        try {
            return runCommand(command);
        } catch (Exception e) {
            return "";
        }
    }

    /** 执行命令数组，返回输出（不经过 shell）。 */
    public static String exec(String... argv) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(argv);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(line);
            }
        }
        proc.waitFor(60, TimeUnit.SECONDS);
        return sb.toString().trim();
    }

    /** 执行命令数组，异常返回 null。 */
    public static String execQuietly(String... argv) {
        try {
            return exec(argv);
        } catch (Exception e) {
            return null;
        }
    }

    /** 当前时间字符串，格式与 Go 的 "2006-01-02 15:04:05" 一致。 */
    public static String getCurrentTime() {
        return LocalDateTime.now().format(TIME_FMT);
    }

    public static String osName() {
        if (osNameCache == null) {
            String n = System.getProperty("os.name", "").toLowerCase();
            if (n.contains("win")) {
                osNameCache = "windows";
            } else if (n.contains("mac") || n.contains("darwin")) {
                osNameCache = "darwin";
            } else {
                osNameCache = "linux";
            }
        }
        return osNameCache;
    }

    public static boolean isLinux() {
        return "linux".equals(osName());
    }

    public static boolean isWindows() {
        return "windows".equals(osName());
    }

    public static boolean isMacOS() {
        return "darwin".equals(osName());
    }

    /** 对应 Go 的 runtime.GOARCH。 */
    public static String architecture() {
        String arch = System.getProperty("os.arch", "").toLowerCase();
        return switch (arch) {
            case "amd64", "x86_64" -> "amd64";
            case "aarch64", "arm64" -> "arm64";
            case "x86", "i386", "i686" -> "386";
            default -> arch;
        };
    }

    /** 当前用户名，对应 Go 的 utils.GetCurrentUser。 */
    public static String getCurrentUser() {
        String user = System.getenv("USER");
        if (user != null && !user.isEmpty()) {
            return user;
        }
        user = System.getenv("USERNAME");
        if (user != null && !user.isEmpty()) {
            return user;
        }
        user = System.getProperty("user.name");
        return (user == null || user.isEmpty()) ? "unknown" : user;
    }

    /** 判断命令是否在 PATH 中（对应 Go 的 utils.LookPathSafe）。 */
    public static boolean isCommandAvailable(String command) {
        if (command == null || command.isEmpty()) {
            return false;
        }
        String pathVar = System.getenv("PATH");
        if (pathVar == null) {
            return false;
        }
        String[] dirs = pathVar.split(java.io.File.pathSeparator);
        String[] suffixes = isWindows()
                ? new String[]{".exe", ".bat", ".cmd", ""}
                : new String[]{""};
        for (String dir : dirs) {
            for (String suffix : suffixes) {
                Path p = Path.of(dir, command + suffix);
                if (Files.isRegularFile(p) && Files.isExecutable(p)) {
                    return true;
                }
            }
        }
        return false;
    }
}

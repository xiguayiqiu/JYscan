package space.jyscan.modules.process;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * 进程模块内部的系统命令封装，对应 Go 侧的 utils.Command(...).Output() 语义：
 *
 * <ul>
 *   <li>只捕获 stdout（Go 的 cmd.Output 在 Stderr 为 nil 时把 stderr 接到 /dev/null）；</li>
 *   <li>命令无法启动或退出码非 0 一律视为失败，返回 null（Go 返回 error）；</li>
 *   <li>不经过 shell，参数按 argv 原样传递（与 exec.Command 一致）。</li>
 * </ul>
 */
final class ProcessUtil {

    /** 等待命令结束的最长时间（秒），避免外部命令挂死拖住整个分析。 */
    private static final long TIMEOUT_SECONDS = 60;

    private ProcessUtil() {
    }

    /**
     * 执行外部命令并返回 stdout 原文。
     *
     * @return stdout 内容；失败（启动失败/非 0 退出/超时）返回 null
     */
    static String runOutput(String... argv) {
        try {
            ProcessBuilder pb = new ProcessBuilder(argv);
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            Process proc = pb.start();
            String out = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (!proc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                proc.destroyForcibly();
                return null;
            }
            if (proc.exitValue() != 0) {
                // Go 的 cmd.Output() 在退出码非 0 时返回 error
                return null;
            }
            return out;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return null;
        }
    }

    /** 等价 Go 的 strings.Fields：按任意空白切分并丢弃空段。 */
    static String[] fields(String s) {
        if (s == null) {
            return new String[0];
        }
        String trimmed = s.trim();
        if (trimmed.isEmpty()) {
            return new String[0];
        }
        return trimmed.split("\\s+");
    }
}

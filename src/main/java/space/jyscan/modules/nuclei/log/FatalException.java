package space.jyscan.modules.nuclei.log;

/**
 * 致命错误异常，配合 {@link Logger#fatal(String, Object...)} 使用，对应 Go 的
 * {@code log.Fatal} 中「打印 {@code [FAT]} 后 {@code os.Exit(1)}」的终止语义。
 *
 * <p>Java 侧不在库代码里直接 {@code System.exit}（进程退出权在 CLI 层）：
 * {@code Logger.fatal} 打印完日志后抛出本异常，CLI 应捕获本异常并
 * {@code System.exit(1)}；若无人捕获，JVM 默认以退出码 1 终止，
 * 与 Go 的 {@code os.Exit(1)} 退出码一致。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/log/logger.go}（该文件无对应 Go 类型，
 * 仅为 Java 化 {@code os.Exit} 语义而新增）。
 */
public class FatalException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** @param message 已按 Go 格式化好的日志正文（不含 {@code [FAT]} 前缀） */
    public FatalException(String message) {
        super(message);
    }
}

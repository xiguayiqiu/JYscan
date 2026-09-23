package space.jyscan.modules.process;

/**
 * 进程与服务分析错误，对应 Go 侧各分析函数返回的 error。
 *
 * <p>message 即 Go 的 error 文本（如 "不支持的操作系统: darwin"），
 * 命令层用 {@code Colors.warningPrint("进程分析失败: %v", e)} 输出，
 * %v 走 Fmt 的 Throwable 分支，只会打印 message，不会带出 Java 堆栈。
 */
public class ProcessException extends Exception {

    public ProcessException(String message) {
        super(message);
    }

    public ProcessException(String message, Throwable cause) {
        super(message, cause);
    }
}

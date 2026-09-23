package space.jyscan.modules.webshell;

/**
 * WebShell生成失败异常，对应 Go 的 fmt.Errorf 返回的 error。
 *
 * <p>message 与 Go 错误文本逐字一致，因此 {@code Colors.errorPrint("生成WebShell失败: %v", e)}
 * 经 {@link space.jyscan.core.util.Fmt} 渲染后与 Go 的 {@code %v}（即 err.Error()）相同。
 */
public final class WebShellException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public WebShellException(String message) {
        super(message);
    }
}

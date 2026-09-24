package space.jyscan.modules.nuclei.protocol;

import java.time.Duration;
import java.util.Map;

/**
 * 协议执行结果，对应 Go 的 {@code protocol.ProtocolResult}（{@code protocol.go:26}）。
 *
 * <p>Go 的错误放在字段 {@code Error error} 内而非返回值，本类照抄该形态：
 * {@link #error} 非 null 即表示该次执行失败。四个执行器（HTTP/DNS/TCP/SSL）
 * 的 {@code Execute} 均返回本类型。
 *
 * <p>Go 的 {@code Duration time.Duration} 对应 {@link java.time.Duration}（项目既有用法，
 * 见 {@code SitemapConfig.timeout}、{@code WhoisResult.cost}）。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/protocol/protocol.go}。
 */
public class ProtocolResult {

    /** Go {@code Protocol}。 */
    public String protocol = "";
    /** Go {@code Data}。 */
    public Map<String, Object> data = null;
    /** Go {@code Raw}。 */
    public String raw = "";
    /** Go {@code Error}。 */
    public Throwable error = null;
    /** Go {@code Duration}。 */
    public Duration duration = Duration.ZERO;

    /**
     * 构造带数据的成功结果，对应四个执行器里的
     * {@code &ProtocolResult{Protocol: ..., Data: ..., Raw: ..., Duration: time.Since(start)}}。
     *
     * <p>包内使用（Go 侧 {@code Error} 为 nil，本工厂不设置该字段）。
     *
     * @param startNanos 执行开始时刻（{@code System.nanoTime()}）
     */
    static ProtocolResult success(String protocol, Map<String, Object> data, String raw, long startNanos) {
        ProtocolResult r = new ProtocolResult();
        r.protocol = protocol;
        r.data = data;
        r.raw = raw;
        r.duration = Duration.ofNanos(System.nanoTime() - startNanos);
        return r;
    }

    /**
     * 构造失败结果，对应 Go 的
     * {@code &ProtocolResult{Protocol: ..., Error: err, Duration: time.Since(start)}}：
     * {@code Data} 为 nil、{@code Raw} 为空串，只有 {@code Error} 非 nil。
     *
     * <p>包内使用。
     *
     * @param startNanos 执行开始时刻（{@code System.nanoTime()}）
     */
    static ProtocolResult failure(String protocol, Throwable error, long startNanos) {
        ProtocolResult r = new ProtocolResult();
        r.protocol = protocol;
        r.error = error;
        r.duration = Duration.ofNanos(System.nanoTime() - startNanos);
        return r;
    }
}

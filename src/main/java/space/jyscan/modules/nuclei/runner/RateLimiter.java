package space.jyscan.modules.nuclei.runner;

import java.time.Duration;
import java.time.Instant;

/**
 * 按秒补 token 的限速器，对应 Go 的 {@code runner.RateLimiter}（{@code runner.go:68}）。
 *
 * <p>语义与 Go 逐条对应：初始 {@code tokens = max = rate}，每过一个 {@code refill}（1 秒）
 * 窗口把 {@code tokens} 补满到 {@code max}；{@code Allow} 命中扣一个 token，
 * {@code Wait} 则以 10ms 轮询直到拿到 token。
 *
 * <p>Go 的构造函数 {@code NewRateLimiter(rate int) *RateLimiter} 映射为本类构造器。
 *
 * <p>Go 的 {@code Wait()} 方法名在 Java 中写作 {@code await()}——
 * {@code Object.wait()} 不可遮蔽。
 *
 * <p>Go 侧 {@code time.Sleep} 不可被中断；Java 的 {@code Thread.sleep} 可被中断，
 * 中断时 {@link #await()} 恢复中断标志并提前返回（Java 无法表达「不可中断的 Sleep」，
 * 属项目约定的既有差异项）。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/runner/runner.go}
 */
public class RateLimiter {

    /** 对应 Go 的 {@code mu sync.Mutex}（本类全部临界区均在 {@code synchronized (mu)} 内）。 */
    private final Object mu = new Object();
    /** 对应 Go 的 {@code tokens int}。 */
    private int tokens;
    /** 对应 Go 的 {@code max int}。 */
    private final int max;
    /** 对应 Go 的 {@code refillAt time.Time}；Go 零值 time.Time 早于当前时刻，故用 {@link Instant#EPOCH} 等价表达。 */
    private Instant refillAt = Instant.EPOCH;
    /** 对应 Go 的 {@code refill time.Duration}（{@code time.Second}）。 */
    private final Duration refill = Duration.ofSeconds(1);

    /** 对应 Go 的 {@code NewRateLimiter(rate int) *RateLimiter}。 */
    public RateLimiter(int rate) {
        this.tokens = rate;
        this.max = rate;
    }

    /**
     * 尝试取一个 token。
     *
     * <p>对应 Go 的 {@code (r *RateLimiter) Allow() bool}：
     * 当前时刻晚于 {@code refillAt} 则先补满并顺延窗口；无 token 返回 {@code false}，否则扣一个返回 {@code true}。
     */
    public boolean allow() {
        synchronized (mu) {
            Instant now = Instant.now();
            if (now.isAfter(refillAt)) {
                tokens = max;
                refillAt = now.plus(refill);
            }
            if (tokens <= 0) {
                return false;
            }
            tokens--;
            return true;
        }
    }

    /**
     * 阻塞直到拿到一个 token（10ms 轮询）。
     *
     * <p>对应 Go 的 {@code (r *RateLimiter) Wait()}。方法名规避 {@code Object.wait()}。
     */
    public void await() {
        while (!allow()) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                // Java sleep 可中断；恢复中断标志并提前返回（Go 的 time.Sleep 不可中断）
                Thread.currentThread().interrupt();
                return;
            }
        }
    }
}

package space.jyscan.modules.nuclei.runner;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import space.jyscan.modules.nuclei.model.Progress;

/**
 * 扫描进度跟踪器，对应 Go 的 {@code runner.ProgressTracker}（{@code runner.go:105}）。
 *
 * <p>Go 侧用 {@code atomic.Int64} 计数 + {@code sync.RWMutex} 保护
 * {@code lastUpdate} 与快照读取，Java 侧对应 {@link AtomicLong} + {@link ReentrantReadWriteLock}。
 *
 * <p>Go 的构造函数 {@code NewProgressTracker() *ProgressTracker} 映射为本类构造器。
 *
 * <p>注：Go 的 {@code runner.GetProgress()}（返回本类型指针）在 Go 全树 0 调用方，
 * 按项目死代码约定未移植；本类型自身的 {@code GetProgress() model.Progress}
 * 被 {@code PrintProgress} 使用，随 {@code Run} 链路一并移植。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/runner/runner.go}
 */
public class ProgressTracker {

    /** 对应 Go 的 {@code totalTemplates atomic.Int64}。 */
    private final AtomicLong totalTemplates = new AtomicLong();
    /** 对应 Go 的 {@code executedTemplates atomic.Int64}。 */
    private final AtomicLong executedTemplates = new AtomicLong();
    /** 对应 Go 的 {@code totalRequests atomic.Int64}。 */
    private final AtomicLong totalRequests = new AtomicLong();
    /** 对应 Go 的 {@code executedRequests atomic.Int64}。 */
    private final AtomicLong executedRequests = new AtomicLong();
    /** 对应 Go 的 {@code matchedCount atomic.Int64}。 */
    private final AtomicLong matchedCount = new AtomicLong();
    /** 对应 Go 的 {@code errorsCount atomic.Int64}。 */
    private final AtomicLong errorsCount = new AtomicLong();
    /** 对应 Go 的 {@code startTime time.Time}；Go 用 {@code time.Since(startTime)}，Java 用单调纳秒时钟等价表达。 */
    private final long startNanos = System.nanoTime();
    /** 对应 Go 的 {@code lock sync.RWMutex}。 */
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    /**
     * 对应 Go 的 {@code lastUpdate time.Time}。
     *
     * <p>Go 侧该字段只在 {@code IncrementTemplates} 中写入、从未被读取（写而不读），
     * 为结构对齐原样保留。
     */
    private Instant lastUpdate = Instant.now();

    /** 对应 Go 的 {@code NewProgressTracker() *ProgressTracker}。 */
    public ProgressTracker() {
        // Go: startTime/lastUpdate 均为 time.Now()（字段初始化器已表达）
    }

    /** 对应 Go 的 {@code (p *ProgressTracker) IncrementTemplates()}：计数 +1 并在写锁内刷新 lastUpdate。 */
    public void incrementTemplates() {
        executedTemplates.incrementAndGet();
        lock.writeLock().lock();
        try {
            lastUpdate = Instant.now();
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 对应 Go 的 {@code (p *ProgressTracker) IncrementRequests()}。 */
    public void incrementRequests() {
        executedRequests.incrementAndGet();
    }

    /** 对应 Go 的 {@code (p *ProgressTracker) IncrementMatched()}。 */
    public void incrementMatched() {
        matchedCount.incrementAndGet();
    }

    /** 对应 Go 的 {@code (p *ProgressTracker) IncrementErrors()}。 */
    public void incrementErrors() {
        errorsCount.incrementAndGet();
    }

    /** 对应 Go 的 {@code (p *ProgressTracker) SetTotalTemplates(n int64)}。 */
    public void setTotalTemplates(long n) {
        totalTemplates.set(n);
    }

    /** 对应 Go 的 {@code (p *ProgressTracker) SetTotalRequests(n int64)}。 */
    public void setTotalRequests(long n) {
        totalRequests.set(n);
    }

    /**
     * 读取进度快照。
     *
     * <p>对应 Go 的 {@code (p *ProgressTracker) GetProgress() model.Progress}
     * （读锁下组装；{@code TotalDuration} 为自启动起的纳秒数）。
     */
    public Progress getProgress() {
        lock.readLock().lock();
        try {
            Progress progress = new Progress();
            progress.totalTemplates = (int) totalTemplates.get();
            progress.executedTemplates = (int) executedTemplates.get();
            progress.totalRequests = (int) totalRequests.get();
            progress.executedRequests = (int) executedRequests.get();
            progress.matchedCount = (int) matchedCount.get();
            progress.errorsCount = (int) errorsCount.get();
            progress.totalDurationNanos = System.nanoTime() - startNanos;
            return progress;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * 打印一行进度（输出到 stderr）。
     *
     * <p>对应 Go 的 {@code (p *ProgressTracker) PrintProgress()}：Go 用标准库
     * {@code log.Printf}（带日期前缀），Java 侧直接 {@code System.err.printf} 同一格式串。
     */
    public void printProgress() {
        Progress progress = getProgress();
        Duration elapsed = Duration.ofNanos(System.nanoTime() - startNanos);
        double templatesPct;
        if (progress.totalTemplates == 0) {
            templatesPct = 0;
        } else {
            templatesPct = (double) progress.executedTemplates / (double) progress.totalTemplates * 100;
        }
        System.err.printf("[%s] [Progress: %d templates, %d requests] [Matches: %d] [Errors: %d] [%.1f%%] [%s]%n",
                LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")),
                progress.executedTemplates,
                progress.executedRequests,
                progress.matchedCount,
                progress.errorsCount,
                templatesPct,
                formatGoDuration(roundToSecond(elapsed)));
    }

    /** Go 的 {@code elapsed.Round(time.Second)}：四舍五入到最近整秒。 */
    private static Duration roundToSecond(Duration d) {
        return d.plusNanos(500_000_000L).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    }

    /**
     * 按 Go {@code time.Duration.String()} 的形态渲染<b>整秒</b>时长
     * （如 {@code 0s}/{@code 5s}/{@code 1m5s}/{@code 1h0m0s}），
     * 对应 Go {@code PrintProgress} 中 {@code elapsed.Round(time.Second)} 的 {@code %s} 参数。
     */
    static String formatGoDuration(Duration d) {
        long totalSeconds = d.getSeconds();
        if (totalSeconds < 0) {
            totalSeconds = 0;
        }
        long hours = totalSeconds / 3600;
        long minutes = (totalSeconds % 3600) / 60;
        long seconds = totalSeconds % 60;
        if (hours > 0) {
            return hours + "h" + minutes + "m" + seconds + "s";
        }
        if (minutes > 0) {
            return minutes + "m" + seconds + "s";
        }
        return seconds + "s";
    }
}

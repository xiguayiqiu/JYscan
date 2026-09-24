package space.jyscan.modules.nuclei.runner;

import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * 自适应并发闸门，对应 Go 的 {@code runner.AdaptiveWaitGroup}（{@code workpool.go:9}）。
 *
 * <p>Go 侧用「容量 = size 的带缓冲 channel」做并发闸门：{@code Add} 往里塞（塞满即阻塞）、
 * {@code Done} 从里取、{@code Wait} 先塞满再取空（等价于等待全部在飞任务结束的屏障）。
 * Java 侧一一对应地用 {@link Semaphore} 复刻该语义：
 * <ul>
 *   <li>{@link #add()} = {@code Semaphore.acquireUninterruptibly()}（Go 的 channel 发送不可中断，故用 uninterruptible）；</li>
 *   <li>{@link #done()} = {@code Semaphore.release()}；</li>
 *   <li>{@link #await()} = 先 acquire size 次（阻塞至全部 Done、闸门空），再 release size 次（恢复空闸门）——
 *       与 Go 的「先塞满再取空」逐步对应。</li>
 * </ul>
 *
 * <p>Go 的 {@code Resize(ctx, newSize)} 按项目既定约定省略 {@code ctx} 首参（{@link #resize(int)}）。
 *
 * <p><b>Go 侧缺陷（Java 侧处理见 {@link #resize(int)} 注释）：</b>Go 的 {@code Resize} 在
 * {@code newSize > 2 * oldSize} 时会在空 channel 上永久阻塞（死锁）。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/runner/workpool.go}
 */
public class AdaptiveWaitGroup {

    /** 对应 Go 的 {@code size int}（读写经 {@link #mu}）。 */
    private int size;
    /** 对应 Go 的 {@code current atomic.Int64}。 */
    private final AtomicLong current = new AtomicLong();
    /** 对应 Go 的 {@code ch chan struct{}}；Go 在 Resize 时整体换 channel，故此字段可变。 */
    private volatile Semaphore ch;
    /** 对应 Go 的 {@code mu sync.RWMutex}。 */
    private final ReentrantReadWriteLock mu = new ReentrantReadWriteLock();

    /**
     * 对应 Go 的 {@code NewAdaptiveWaitGroup(size int) *AdaptiveWaitGroup}。
     * {@code size <= 0} 时按 Go 取默认值 10。
     */
    public AdaptiveWaitGroup(int size) {
        if (size <= 0) {
            size = 10;
        }
        this.size = size;
        this.ch = new Semaphore(size);
    }

    /**
     * 占用一个并发位（满了则阻塞）。
     *
     * <p>对应 Go 的 {@code (w *AdaptiveWaitGroup) Add()}：{@code w.ch <- struct{}{}} 后 {@code current.Add(1)}。
     */
    public void add() {
        ch.acquireUninterruptibly();
        current.incrementAndGet();
    }

    /**
     * 释放一个并发位。
     *
     * <p>对应 Go 的 {@code (w *AdaptiveWaitGroup) Done()}：{@code <-w.ch} 后 {@code current.Add(-1)}。
     *
     * <p>差异说明：Go 在闸门已空时 {@code <-w.ch} 会永久阻塞（Add/Done 不配对时的缺陷行为），
     * Java 的 {@code release} 只会令许可数超出上限、不阻塞——仅在误用（Done 多于 Add）时表现不同。
     */
    public void done() {
        ch.release();
        current.decrementAndGet();
    }

    /**
     * 等待全部在飞任务结束（屏障）。
     *
     * <p>对应 Go 的 {@code (w *AdaptiveWaitGroup) Wait()}：先向 channel 塞满 {@code size} 个
     * （阻塞至所有占用释放），再取空 {@code size} 个（恢复空闸门）。
     * 方法名取 {@code await()} 而非 {@code wait()}——Java 的 {@code Object.wait()} 不可遮蔽。
     * {@code current} 与 Go 一致不被本方法改动。
     */
    public void await() {
        int n = size();
        Semaphore s = this.ch;
        for (int i = 0; i < n; i++) {
            s.acquireUninterruptibly();
        }
        for (int i = 0; i < n; i++) {
            s.release();
        }
    }

    /**
     * 当前容量。
     *
     * <p>对应 Go 的 {@code (w *AdaptiveWaitGroup) Size() int}（读锁）。
     * Go 的 {@code Wait} 循环边界对 {@code size} 的读取未加锁（与 Resize 有数据竞争），
     * Java 侧统一经本方法加读锁读取，消除该竞争。
     */
    public int size() {
        mu.readLock().lock();
        try {
            return size;
        } finally {
            mu.readLock().unlock();
        }
    }

    /**
     * 调整容量（仅当 {@code newSize} 生效且变大时实际扩容；{@code newSize <= 0} 时按 Go 直接返回）。
     *
     * <p>对应 Go 的 {@code (w *AdaptiveWaitGroup) Resize(ctx context.Context, newSize int) error}
     * （{@code ctx} 按项目约定省略；Go 恒返回 {@code nil}，Java 侧恒返回 {@code null}）。
     *
     * <p><b>对 Go 算术的逐步复刻：</b>Go 扩容时新建容量 {@code newSize} 的 channel、预填
     * {@code oldSize} 个占用、再取走 {@code delta = newSize - oldSize} 个占用；
     * Java 用 Semaphore 精确复刻同一算术（{@code tryAcquire(oldSize)} 预填、{@code release(delta)} 取走），
     * 因此 {@code delta <= oldSize}（即 {@code newSize <= 2 * oldSize}）时剩余占用数与 Go 完全一致
     * ——包括 Go 会残留 {@code oldSize - delta} 个「幻影占用」（真实可用容量并不等于 {@code newSize}）的缺陷。
     *
     * <p><b>Go 死锁修正：</b>当 {@code delta > oldSize}（即 {@code newSize > 2 * oldSize}）时，
     * Go 会试图从仅含 {@code oldSize} 个占用的 channel 中再取 {@code delta} 个而<b>永久阻塞</b>
     * （例：初始 size 10、SetWorkPoolConfig 传入 TypeConcurrency ≥ 21 时 CLI 启动即挂死）。
     * Java 侧把取走数量截断为 {@code min(delta, oldSize)}，此时闸门置空（可用容量 = {@code newSize}），
     * 仅在 Go 会挂死的区间与 Go 行为不同——不复刻永久阻塞。
     */
    public Throwable resize(int newSize) {
        if (newSize <= 0) {
            return null;
        }
        mu.writeLock().lock();
        int oldSize;
        try {
            oldSize = this.size;
            this.size = newSize;
            if (newSize > oldSize) {
                int delta = newSize - oldSize;
                Semaphore newCh = new Semaphore(newSize);
                // Go: for i := 0; i < oldSize; i++ { newCh <- struct{}{} }（预填 oldSize 个占用）
                boolean preFilled = newCh.tryAcquire(oldSize);
                if (!preFilled) {
                    // 不可达：newSize > oldSize 时 newCh 恰有 newSize 个许可，预填 oldSize 必成功
                    return null;
                }
                // Go: for i := 0; i < delta; i++ { <-newCh }（取走 delta 个占用；delta > oldSize 时 Go 在此死锁）
                int drain = Math.min(delta, oldSize);
                newCh.release(drain);
                this.ch = newCh;
            }
        } finally {
            mu.writeLock().unlock();
        }
        return null;
    }
}

package space.jyscan.modules.nuclei.runner;

/**
 * 工作池，对应 Go 的 {@code runner.WorkPool}（{@code workpool.go:82}）。
 *
 * <p>持有 headless / 默认两条并发闸门；Go 侧 {@code InputPool} 会按模板类型
 * 新建一条 {@link AdaptiveWaitGroup}（{@code workpool.go:101}）。
 *
 * <p>Go 的构造函数 {@code NewWorkPool(config WorkPoolConfig) *WorkPool} 映射为本类构造器。
 * Go 的 {@code Default} 字段名在 Java 中写作 {@code defaultGroup}（{@code default} 是 Java 关键字）。
 *
 * <p>注：Go 全树中 {@code WorkPool.InputPool}/{@code WorkPool.Wait} 无调用方
 * （{@code workPool} 字段仅在 New/SetWorkPoolConfig 中被构造与刷新），属导出面的一部分，
 * 仍按类型完整实现移植。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/runner/workpool.go}
 */
public class WorkPool {

    /** 对应 Go 的 {@code Headless *AdaptiveWaitGroup}。 */
    public final AdaptiveWaitGroup headless;
    /** 对应 Go 的 {@code Default *AdaptiveWaitGroup}（Java 关键字规避改名）。 */
    public final AdaptiveWaitGroup defaultGroup;
    /** 对应 Go 的 {@code config WorkPoolConfig}（Go 侧为值类型，Java 按字段拷贝保持值语义）。 */
    private WorkPoolConfig config;

    /** 对应 Go 的 {@code NewWorkPool(config WorkPoolConfig) *WorkPool}。 */
    public WorkPool(WorkPoolConfig config) {
        WorkPoolConfig cfg = copyOf(config);
        this.config = cfg;
        this.headless = new AdaptiveWaitGroup(cfg.headlessTypeConcurrency);
        this.defaultGroup = new AdaptiveWaitGroup(cfg.typeConcurrency);
    }

    /** 对应 Go 的 {@code (w *WorkPool) Wait()}：先等默认闸门、再等 headless 闸门。 */
    public void await() {
        defaultGroup.await();
        headless.await();
    }

    /**
     * 按模板类型返回一条<b>新建</b>的输入闸门（Go 每次调用都新建，非复用）。
     *
     * <p>对应 Go 的 {@code (w *WorkPool) InputPool(templateType string) *AdaptiveWaitGroup}。
     */
    public AdaptiveWaitGroup inputPool(String templateType) {
        int count;
        if ("headless".equals(templateType)) {
            count = config.headlessInputConcurrency;
        } else {
            count = config.inputConcurrency;
        }
        return new AdaptiveWaitGroup(count);
    }

    /**
     * 用新配置刷新工作池。
     *
     * <p>对应 Go 的 {@code (w *WorkPool) RefreshWithConfig(config WorkPoolConfig)}：
     * 记下配置后对两条闸门分别 {@code Resize}（Go 侧 {@code context.Background()} 已按约定省略）。
     */
    public void refreshWithConfig(WorkPoolConfig config) {
        this.config = copyOf(config);
        this.defaultGroup.resize(config.typeConcurrency);
        this.headless.resize(config.headlessTypeConcurrency);
    }

    /** Go 的 {@code WorkPoolConfig} 是值类型：拷贝四个字段以保持「调用方后续修改不影响池」的语义。 */
    private static WorkPoolConfig copyOf(WorkPoolConfig config) {
        WorkPoolConfig copy = new WorkPoolConfig();
        if (config != null) {
            copy.inputConcurrency = config.inputConcurrency;
            copy.typeConcurrency = config.typeConcurrency;
            copy.headlessInputConcurrency = config.headlessInputConcurrency;
            copy.headlessTypeConcurrency = config.headlessTypeConcurrency;
        }
        return copy;
    }
}

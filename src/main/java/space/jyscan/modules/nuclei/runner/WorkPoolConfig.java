package space.jyscan.modules.nuclei.runner;

/**
 * 工作池并发配置，对应 Go 的 {@code runner.WorkPoolConfig}（{@code workpool.go:75}）。
 *
 * <p>跨包契约：CLI 用 {@code nucleiConcurrency * 2}、{@code nucleiConcurrency}、
 * {@code nucleiConcurrency}、{@code nucleiConcurrency / 2} 四个值填充本类型，
 * 再经 {@code Runner.setWorkPoolConfig(...)} 交给 runner。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/runner/workpool.go}
 */
public class WorkPoolConfig {

    /** Go {@code InputConcurrency}。 */
    public int inputConcurrency;
    /** Go {@code TypeConcurrency}。 */
    public int typeConcurrency;
    /** Go {@code HeadlessInputConcurrency}。 */
    public int headlessInputConcurrency;
    /** Go {@code HeadlessTypeConcurrency}。 */
    public int headlessTypeConcurrency;
}

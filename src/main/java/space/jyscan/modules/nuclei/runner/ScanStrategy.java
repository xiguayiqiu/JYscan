package space.jyscan.modules.nuclei.runner;

/**
 * runner 层的扫描策略，对应 Go 的 {@code runner.ScanStrategy}（{@code runner.go:23}）。
 *
 * <p><b>注意与 {@link space.jyscan.modules.nuclei.model.ScanStrategy} 是两个不同的类型：</b>
 * Go 侧 {@code model.ScanStrategy} 与 {@code runner.ScanStrategy} 并存、取值串相同但分属两包，
 * CLI（{@code cli/nuclei.go}）用的是 {@code runner.StrategyAuto} 等常量，故两包各留一份以对齐 Go。
 */
public enum ScanStrategy {

    /** {@code StrategyAuto = "auto"}。 */
    AUTO("auto"),
    /** {@code StrategyTemplateSpray = "template-spray"}。 */
    TEMPLATE_SPRAY("template-spray"),
    /** {@code StrategyHostSpray = "host-spray"}。 */
    HOST_SPRAY("host-spray");

    private final String label;

    ScanStrategy(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    @Override
    public String toString() {
        return label;
    }
}

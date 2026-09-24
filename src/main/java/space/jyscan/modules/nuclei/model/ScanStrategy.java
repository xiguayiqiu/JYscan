package space.jyscan.modules.nuclei.model;

/**
 * 扫描策略，对应 Go 的 {@code model.ScanStrategy}（{@code type ScanStrategy string} 常量组）。
 *
 * <p>Go 侧的三个取值串即本枚举的 {@link #label()}，比较时以 label 为准而非 name。
 */
public enum ScanStrategy {

    /** {@code ScanStrategyAuto = "auto"}。 */
    AUTO("auto"),
    /** {@code ScanStrategyTemplateSpray = "template-spray"}。 */
    TEMPLATE_SPRAY("template-spray"),
    /** {@code ScanStrategyHostSpray = "host-spray"}。 */
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

    /**
     * 按 Go 的取值串解析，未匹配时返回 {@link #AUTO}。
     *
     * <p>对应 {@code cli/nuclei.go} 里 {@code switch nucleiStrategy} 的
     * {@code default} 分支走 {@code StrategyAuto}（Go 的 CLI 用的是
     * {@code runner.StrategyAuto}，两者取值串相同）。
     */
    public static ScanStrategy fromLabel(String label) {
        if (label == null) {
            return AUTO;
        }
        for (ScanStrategy s : values()) {
            if (s.label.equals(label)) {
                return s;
            }
        }
        return AUTO;
    }
}

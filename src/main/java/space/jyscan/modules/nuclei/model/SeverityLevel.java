package space.jyscan.modules.nuclei.model;

/**
 * 漏洞等级，对应 Go 的 {@code model.SeverityLevel}（{@code type SeverityLevel int} + iota 常量）。
 *
 * <p>Go 侧 {@code SeverityUnknown SeverityLevel = iota} 从 0 起，本枚举的声明顺序
 * 与之逐一对应，以保证 {@link #ordinal()} 的数值语义与 Go 一致。
 */
public enum SeverityLevel {

    /** {@code SeverityUnknown}，iota 序号 0。 */
    UNKNOWN("unknown", -1),
    /** {@code SeverityInfo}，iota 序号 1。 */
    INFO("info", 0),
    /** {@code SeverityLow}，iota 序号 2。 */
    LOW("low", 1),
    /** {@code SeverityMedium}，iota 序号 3。 */
    MEDIUM("medium", 2),
    /** {@code SeverityHigh}，iota 序号 4。 */
    HIGH("high", 3),
    /** {@code SeverityCritical}，iota 序号 5。 */
    CRITICAL("critical", 4);

    private final String label;
    private final int weight;

    SeverityLevel(String label, int weight) {
        this.label = label;
        this.weight = weight;
    }

    /** 对应 Go 的 {@code (s SeverityLevel) String()}。 */
    public String label() {
        return label;
    }

    /** 对应 Go 的 {@code (s SeverityLevel) Weight()}，未知时返回 -1。 */
    public int weight() {
        return weight;
    }

    @Override
    public String toString() {
        return label;
    }

    /**
     * 对应 Go 的 {@code ParseSeverity(severity string) SeverityLevel}。
     *
     * <p>先经 {@link #normalize(String)} 归一，再按 Go 的 switch 分支映射；
     * Go 的 {@code case "info", "informational"} 等写法在此原样保留（其中
     * {@code informational}/{@code moderate} 已在归一阶段改写，属不可达分支，
     * 仅为与 Go 的 case 列表逐字对齐）。
     */
    public static SeverityLevel parseSeverity(String severity) {
        switch (normalize(severity)) {
            case "info":
            case "informational":
                return INFO;
            case "low":
                return LOW;
            case "medium":
            case "moderate":
                return MEDIUM;
            case "high":
                return HIGH;
            case "critical":
                return CRITICAL;
            default:
                return UNKNOWN;
        }
    }

    /** 对应 Go 的 {@code normalizeSeverity(s string) string}。 */
    private static String normalize(String s) {
        if (s == null) {
            return "";
        }
        switch (s) {
            case "informational":
                return "info";
            case "moderate":
                return "medium";
            default:
                return s;
        }
    }
}

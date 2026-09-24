package space.jyscan.modules.nuclei.model;

/**
 * 扫描进度，对应 Go 的 {@code model.Progress}。
 *
 * <p>Go 的 {@code TotalDuration} json 标签为 {@code total_duration_ns}（纳秒）。
 */
public final class Progress {

    /** {@code total_templates}。 */
    public int totalTemplates;
    /** {@code executed_templates}。 */
    public int executedTemplates;
    /** {@code total_requests}。 */
    public int totalRequests;
    /** {@code executed_requests}。 */
    public int executedRequests;
    /** {@code matched_count}。 */
    public int matchedCount;
    /** {@code errors_count}。 */
    public int errorsCount;
    /** {@code total_duration_ns}，纳秒。 */
    public long totalDurationNanos;

    /**
     * 完成百分比。
     *
     * <p>对应 Go 的 {@code (p *Progress) PercentComplete() float64}：
     * {@code TotalTemplates == 0} 时返回 0，否则为 {@code ExecutedTemplates / TotalTemplates * 100}。
     */
    public double percentComplete() {
        if (totalTemplates == 0) {
            return 0;
        }
        return (double) executedTemplates / (double) totalTemplates * 100;
    }
}

package space.jyscan.modules.nuclei.model;

import java.util.List;

/**
 * 模板分类信息，对应 Go 的 {@code model.Classification}。
 *
 * <p>Go 的 yaml/json 标签为 {@code cve-id}/{@code cwe-id}/{@code cvss-score}/{@code cvss-metrics}，
 * 这些带连字符的键名由 {@link space.jyscan.modules.nuclei.loader} 解析时按字面量取用。
 */
public final class Classification {

    /** {@code cve-id}。 */
    public List<String> cveId = null;
    /** {@code cwe-id}。 */
    public List<String> cweId = null;
    /** {@code cvss-score}。 */
    public double cvssScore;
    /** {@code cvss-metrics}。 */
    public String cvssMetrics = "";
}

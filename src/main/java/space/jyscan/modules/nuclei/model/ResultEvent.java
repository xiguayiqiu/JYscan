package space.jyscan.modules.nuclei.model;

import java.util.List;
import java.util.Map;

/**
 * 扫描结果事件，对应 Go 的 {@code model.ResultEvent}。
 *
 * <p>字段名与 Go 的 json 标签语义对应（{@code template_id}/{@code extracted_results} 等），
 * 这些带下划线的键名由输出侧按字面量取用。
 *
 * <p>注：Go 的 {@code pkg/nuclei/output} 包在本项目中判定为死代码未移植，
 * 本类型作为 model 类型面的一部分保留。
 */
public final class ResultEvent {

    /** Go 字段 {@code Template *Template}，标签 {@code json:"-"}。 */
    public Template template = null;
    /** {@code template_id}。 */
    public String templateId = "";
    /** {@code template_url}。 */
    public String templateUrl = "";
    /** {@code info}，Go 侧为值类型。 */
    public Info info = new Info();
    /** {@code protocol}。 */
    public String protocol = "";
    /** {@code host}。 */
    public String host = "";
    /** {@code matched}。 */
    public String matched = "";
    /** {@code extracted_results}。 */
    public List<String> extractedResults = null;
    /** {@code extracted_map}，保留 extractor name -> value 映射（nuclei 官方风格）。 */
    public Map<String, String> extractedMap = null;
    /** {@code matcher_name}。 */
    public String matcherName = "";
    /** {@code severity}。 */
    public SeverityLevel severity = SeverityLevel.UNKNOWN;
    /** {@code data}。 */
    public Map<String, Object> data = null;
    /** {@code timestamp}。 */
    public String timestamp = "";
    /** {@code type}。 */
    public String type = "";
    /** {@code info_priority}。 */
    public int infoPriority;
}

package space.jyscan.modules.nuclei.model;

import java.util.List;

/**
 * 模板索引项，对应 Go 的 {@code model.TemplateIndex}。
 *
 * <p>{@code Types} 的元素类型 {@link TemplateType} 对应 Go 的包内私有 {@code templateTypes}，
 * 故本类的 {@link #types} 也是包内可见，与 Go 的可见性一致。
 */
public final class TemplateIndex {

    /** Go {@code ID}。 */
    public String id = "";
    /** Go {@code Path}。 */
    public String path = "";
    /** Go {@code Tags}。 */
    public List<String> tags = null;
    /** Go {@code Authors}。 */
    public List<String> authors = null;
    /** Go {@code Severity}。 */
    public SeverityLevel severity = SeverityLevel.UNKNOWN;
    /** Go {@code Types}（元素类型为包内私有 {@link TemplateType}）。 */
    List<TemplateType> types = null;
    /** Go {@code MatchersCount}。 */
    public int matchersCount;
    /** Go {@code ExtractorsCount}。 */
    public int extractorsCount;
}

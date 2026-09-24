package space.jyscan.modules.nuclei.model;

import java.util.List;
import java.util.Map;

/**
 * 模板元信息，对应 Go 的 {@code model.Info}（注释："对应 nuclei 的 info.Info"）。
 *
 * <p>字段名与 Go 逐一对应；Go 的 {@code yaml}/{@code json} 标签在本类以
 * {@link space.jyscan.modules.nuclei.loader} 的手工取值方式体现，字段本身不带序列化注解。
 */
public final class Info {

    /** {@code name}。 */
    public String name = "";
    /** {@code author}。 */
    public String author = "";
    /** {@code description}。 */
    public String description = "";
    /** {@code reference}。 */
    public List<String> reference = null;
    /** {@code severity}。 */
    public String severity = "";
    /** {@code tags}。 */
    public List<String> tags = null;
    /** {@code metadata}。 */
    public Map<String, Object> metadata = null;

    /**
     * 分类信息，{@code classification}。
     *
     * <p>Go 侧为 {@code *Classification}（指针，可为 nil）。
     */
    public Classification classification = null;

    /**
     * 模板动态信息，Go 侧标签为 {@code yaml:"-"}，即不参与 YAML 解析。
     *
     * <p>Go 类型为 {@code *Info}，自引用指针。
     */
    public Info infoQueue = null;
}

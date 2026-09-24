package space.jyscan.modules.nuclei.model;

import java.util.List;

/**
 * 提取器模型，对应 Go 的 {@code model.Extractor}（注释："对应 nuclei 的 extractors.Extractor"）。
 *
 * <p>Go 的 yaml 标签含带连字符键 {@code case-insensitive}，由 loader 按字面量取用。
 */
public final class Extractor {

    /** {@code type}。 */
    public String type = "";
    /** {@code part}。 */
    public String part = "";
    /** {@code name}。 */
    public String name = "";
    /** {@code group}。 */
    public String group = "";
    /** {@code attribute}。 */
    public String attribute = "";
    /** {@code internal}。 */
    public boolean internal;
    /** {@code case-insensitive}。 */
    public boolean caseInsensitive;
    /** {@code regex}。 */
    public List<String> regex = null;
    /** {@code kval}。 */
    public List<String> kval = null;
    /** {@code xpath}。 */
    public List<String> xpath = null;
    /** {@code json}。 */
    public List<String> json = null;
    /** {@code dsl}。 */
    public List<String> dsl = null;

    /**
     * 获取提取器类型，Go 默认 {@code regex}。
     *
     * <p>对应 Go 的 {@code (e *Extractor) GetType() string}。
     */
    public String getType() {
        if (type == null || type.isEmpty()) {
            return "regex";
        }
        return type;
    }

    /**
     * 获取提取部分，Go 默认 {@code body}。
     *
     * <p>对应 Go 的 {@code (e *Extractor) GetPart() string}。
     */
    public String getPart() {
        if (part == null || part.isEmpty()) {
            return "body";
        }
        return part;
    }
}

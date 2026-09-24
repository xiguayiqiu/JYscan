package space.jyscan.modules.nuclei.model;

import java.util.List;
import java.util.Map;

/**
 * 匹配器模型，对应 Go 的 {@code model.Matcher}（注释："对应 nuclei 的 matchers.Matcher"）。
 *
 * <p>Go 的 yaml 标签含带连字符键（{@code case-insensitive}/{@code match-all}），
 * 由 {@link space.jyscan.modules.nuclei.loader} 解析时按字面量取用。
 */
public final class Matcher {

    /** {@code type}。 */
    public String type = "";
    /** {@code condition}（and/or）。 */
    public String condition = "";
    /** {@code part}。 */
    public String part = "";
    /** {@code negative}。 */
    public boolean negative;
    /** {@code name}。 */
    public String name = "";
    /** {@code case-insensitive}。 */
    public boolean caseInsensitive;
    /** {@code match-all}。 */
    public boolean matchAll;
    /** {@code internal}。 */
    public boolean internal;
    /** {@code encoding}。 */
    public String encoding = "";

    /** {@code status}。 */
    public List<Integer> status = null;
    /** {@code size}。 */
    public List<Integer> size = null;
    /** {@code words}。 */
    public List<String> words = null;
    /** {@code regex}。 */
    public List<String> regex = null;
    /** {@code binary}。 */
    public List<String> binary = null;
    /** {@code dsl}。 */
    public List<String> dsl = null;
    /** {@code xpath}。 */
    public List<String> xpath = null;

    /** 复杂条件表达式，Go yaml 标签 {@code raw}。 */
    public List<Map<String, Object>> rawExpressions = null;

    /**
     * 获取匹配器类型，Go 默认 {@code word}。
     *
     * <p>对应 Go 的 {@code (m *Matcher) GetType() string}。
     */
    public String getType() {
        if (type == null || type.isEmpty()) {
            return "word";
        }
        return type;
    }

    /**
     * 获取匹配部分，Go 默认 {@code body}。
     *
     * <p>对应 Go 的 {@code (m *Matcher) GetPart() string}。
     */
    public String getPart() {
        if (part == null || part.isEmpty()) {
            return "body";
        }
        return part;
    }

    /**
     * 返回 matcher 名称，对应 Go 的 {@code (m *Matcher) GetName() string}。
     *
     * <p>Go 注释：nuclei 官方用于 {@code [template-id:matcher-name]} 格式。
     */
    public String getName() {
        return name == null ? "" : name;
    }
}

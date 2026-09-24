package space.jyscan.modules.nuclei.model;

import java.util.List;
import java.util.Map;

/**
 * 代码执行请求模型，对应 Go 的 {@code model.CodeRequest}。
 *
 * <p>注意 Go 的结构体里**没有** {@code MatchersCondition} 字段，因此
 * {@link #getMatchersCondition()} 按 Go 的实现固定返回 {@code ""} 而非读取字段。
 *
 * <p>Go 侧的 {@code CodeExecutor.Execute} 是桩（返回 {@code host}/{@code raw=""}）。
 */
public final class CodeRequest implements Request {

    /** {@code engine}。 */
    public String engine = "";
    /** {@code args}。 */
    public List<String> args = null;
    /** {@code source}。 */
    public Map<String, Object> source = null;

    /** {@code matchers}。 */
    public List<Matcher> matchers = null;
    /** {@code extractors}。 */
    public List<Extractor> extractors = null;

    @Override
    public List<Matcher> getMatchers() {
        return matchers;
    }

    @Override
    public List<Extractor> getExtractors() {
        return extractors;
    }

    /** 对应 Go 的 {@code (r *CodeRequest) GetMatchersCondition() string { return "" }}。 */
    @Override
    public String getMatchersCondition() {
        return "";
    }
}

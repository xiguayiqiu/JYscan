package space.jyscan.modules.nuclei.model;

import java.util.List;

/**
 * File 请求模型，对应 Go 的 {@code model.FileRequest}。
 *
 * <p>Go 注释：用于 file 协议，实际是 network file。Go 侧的 {@code FileExecutor.Execute}
 * 是桩（返回 {@code host}/{@code raw=""}）。
 */
public final class FileRequest implements Request {

    /** {@code host}。 */
    public List<String> host = null;
    /** {@code port}。 */
    public String port = "";
    /** {@code inputs}。 */
    public List<String> inputs = null;
    /** {@code path}。 */
    public List<String> path = null;

    /** {@code matchers}。 */
    public List<Matcher> matchers = null;
    /** {@code matchers-condition}。 */
    public String matchersCondition = "";
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

    @Override
    public String getMatchersCondition() {
        return matchersCondition;
    }
}

package space.jyscan.modules.nuclei.runner;

import java.time.Duration;
import java.util.Map;

import space.jyscan.modules.nuclei.model.Template;

/**
 * 扫描结果，对应 Go 的 {@code runner.ScanResult}（{@code runner.go:31}）。
 *
 * <p>跨包契约：CLI（{@code cli/nuclei.go}）经回调接收本类型，读取
 * {@link #matched}、{@link #template}（及其 {@code Info.Severity}/{@code ID}/{@code Info.Name}/
 * {@code Info.Tags}/{@code Info.Description}）、{@link #matchedByProtocol}、
 * {@link #target}、{@link #matchedAt}、{@link #duration}、{@link #protocol}、
 * {@link #extracted}、{@link #matcherName}；并经 {@code Runner.formatResult(...)} 格式化。
 *
 * <p>Go 的 {@code Duration time.Duration} 对应 {@link java.time.Duration}。
 * Go 的 {@code MatchedByProtocol map[string]bool} 对应 {@code Map<String, Boolean>}。
 *
 * 移植自 {@code freeclient/pkg/nuclei/runner/runner.go}
 */
public class ScanResult {

    /** Go {@code Template *model.Template}。 */
    public Template template = null;
    /** Go {@code Target}。 */
    public String target = "";
    /** Go {@code Matched}。 */
    public boolean matched;
    /** Go {@code MatchedAt}。 */
    public String matchedAt = "";
    /** Go {@code Duration}。 */
    public Duration duration = Duration.ZERO;
    /** Go {@code MatchedByProtocol map[string]bool}。 */
    public Map<String, Boolean> matchedByProtocol = null;
    /** Go {@code Extracted map[string]string}。 */
    public Map<String, String> extracted = null;
    /** Go {@code Protocol}。 */
    public String protocol = "";
    /** Go {@code Data map[string]interface{}}。 */
    public Map<String, Object> data = null;
    /**
     * Go {@code MatcherName}。
     *
     * <p>Go 注释：命中匹配器名称，nuclei 官方 {@code [template-id:matcher-name]} 格式。
     */
    public String matcherName = "";
}

package space.jyscan.modules.nuclei.model;

import java.util.List;

/**
 * 扫描选项，对应 Go 的 {@code model.Options}。
 *
 * <p>Go 侧该结构体由 {@code runner.New(options model.Options)} 接收，
 * 而 CLI（{@code cli/nuclei.go}）走的是 {@code runner.NewRunner()}，不经过本类型。
 */
public final class Options {

    /** Go {@code Templates}。 */
    public List<String> templates = null;
    /** Go {@code Workflows}。 */
    public List<String> workflows = null;
    /** Go {@code ExcludeTags}。 */
    public List<String> excludeTags = null;
    /** Go {@code Tags}。 */
    public List<String> tags = null;
    /** Go {@code Severities}。 */
    public List<SeverityLevel> severities = null;
    /** Go {@code Protocols}。 */
    public List<String> protocols = null;
    /** Go {@code Authors}。 */
    public List<String> authors = null;

    /** Go {@code RateLimit}。 */
    public int rateLimit;
    /** Go {@code Threads}。 */
    public int threads;
    /** Go {@code Timeout}。 */
    public int timeout;
    /** Go {@code Retries}。 */
    public int retries;

    /** Go {@code ScanStrategy}。 */
    public ScanStrategy scanStrategy = ScanStrategy.AUTO;

    /** Go {@code FollowRedirects}。 */
    public boolean followRedirects;
    /** Go {@code MaxRedirects}。 */
    public int maxRedirects;

    /** Go {@code ProxyURL}。 */
    public String proxyUrl = "";

    /** Go {@code JSON}。 */
    public boolean json;
    /** Go {@code JSONL}。 */
    public boolean jsonl;
    /** Go {@code CSV}。 */
    public boolean csv;
    /** Go {@code Markdown}。 */
    public boolean markdown;
    /** Go {@code MarkdownFilename}。 */
    public String markdownFilename = "";

    /** Go {@code Silent}。 */
    public boolean silent;
    /** Go {@code Verbose}。 */
    public boolean verbose;
    /** Go {@code Debug}。 */
    public boolean debug;

    /** Go {@code NoColor}。 */
    public boolean noColor;

    /** Go {@code Project}。 */
    public boolean project;
    /** Go {@code ProjectPath}。 */
    public String projectPath = "";

    /** Go {@code UpdateTemplates}。 */
    public boolean updateTemplates;

    /** Go {@code Resume}。 */
    public String resume = "";
}

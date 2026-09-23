package space.jyscan.modules.sitemap;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Sitemap 扫描配置，对应 Go 的 {@code sitemap.ScanConfig}。
 *
 * <p>字段与默认值对齐 {@code cli/sitemap.go} 的 flag 注册：
 * timeout=10s、user-agent="JYscan SitemapAnalyzer/1.0"、maxDepth=3、threads=10、
 * followRedirect=true（Go 侧在命令里写死 true）。
 */
public final class SitemapConfig {

    public String targetURL = "";
    public Duration timeout = Duration.ofSeconds(10);
    public String userAgent = "JYscan SitemapAnalyzer/1.0";
    public String outputFile = "";
    public boolean recursive;
    public int maxDepth = 3;
    public List<String> customPaths = new ArrayList<>();
    public boolean showAll;
    public boolean followRedirect = true;
    public int threads = 10;

    /** 目标 URL，与 Go 的 {@code -u/--url} 对应。 */
    public SitemapConfig targetURL(String v) {
        this.targetURL = v == null ? "" : v;
        return this;
    }

    /** 请求超时，与 Go 的 {@code --timeout}（秒）对应。 */
    public SitemapConfig timeout(Duration v) {
        this.timeout = v;
        return this;
    }

    /** 自定义 User-Agent，与 Go 的 {@code --user-agent} 对应。 */
    public SitemapConfig userAgent(String v) {
        this.userAgent = v == null ? "" : v;
        return this;
    }

    /** 结果输出文件，与 Go 的 {@code -o/--output} 对应。 */
    public SitemapConfig outputFile(String v) {
        this.outputFile = v == null ? "" : v;
        return this;
    }

    /** 是否递归解析 sitemap index，与 Go 的 {@code -r/--recursive} 对应。 */
    public SitemapConfig recursive(boolean v) {
        this.recursive = v;
        return this;
    }

    /** 递归最大深度，与 Go 的 {@code --max-depth} 对应。 */
    public SitemapConfig maxDepth(int v) {
        this.maxDepth = v;
        return this;
    }

    /** 自定义 sitemap 路径（逗号分隔展开后），与 Go 的 {@code -p/--path} 对应。 */
    public SitemapConfig customPaths(List<String> v) {
        this.customPaths = v == null ? new ArrayList<>() : v;
        return this;
    }

    /** 显示所有发现的页面，与 Go 的 {@code --show-all} 对应。 */
    public SitemapConfig showAll(boolean v) {
        this.showAll = v;
        return this;
    }

    /** 是否跟随重定向，与 Go 的 {@code FollowRedirect} 对应。 */
    public SitemapConfig followRedirect(boolean v) {
        this.followRedirect = v;
        return this;
    }

    /** 并发线程数，与 Go 的 {@code -t/--threads} 对应。 */
    public SitemapConfig threads(int v) {
        this.threads = v;
        return this;
    }
}

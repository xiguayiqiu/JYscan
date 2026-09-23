package space.jyscan.modules.sitemap;

import java.util.ArrayList;
import java.util.List;

/**
 * 单个 sitemap 源文件的解析结果，对应 Go 的 {@code sitemap.ScanResult}。
 *
 * <p>Go 的 {@code Error error} 在 Java 侧用错误消息字符串表示（null 表示无错误），
 * 与 {@code whois.WhoisResult} 的处理方式保持一致。
 */
public final class SitemapResult {

    /** 来源 sitemap 地址。 */
    public String sourceURL = "";

    /** 解析出的页面列表。 */
    public List<SitemapUrl> pageURLs = new ArrayList<>();

    /** 页面数量（Go 侧等于 len(PageURLs)，递归时累加子结果）。 */
    public int totalCount;

    /** 错误消息；null 表示成功（对应 Go 的 Error 字段）。 */
    public String error;

    public SitemapResult() {
    }

    public SitemapResult(String sourceURL) {
        this.sourceURL = sourceURL == null ? "" : sourceURL;
    }
}

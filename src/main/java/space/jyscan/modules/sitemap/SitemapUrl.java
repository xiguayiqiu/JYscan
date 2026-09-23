package space.jyscan.modules.sitemap;

/**
 * sitemap 中的单条 URL 记录，对应 Go 的 {@code sitemap.URL}。
 *
 * <p>Go 用 {@code encoding/xml} 标签 {@code loc/lastmod/changefreq/priority}
 * 反序列化，这里在 {@link SitemapScanner} 里手工按标签取值，字段语义一致。
 */
public final class SitemapUrl {

    /** {@code <loc>}：页面地址。 */
    public String loc = "";

    /** {@code <lastmod>}：最后修改时间（原样字符串）。 */
    public String lastMod = "";

    /** {@code <changefreq>}：更新频率。 */
    public String changeFreq = "";

    /** {@code <priority>}：优先级，0 表示未提供（与 Go 的零值一致）。 */
    public double priority;

    public SitemapUrl() {
    }

    public SitemapUrl(String loc) {
        this(loc, "", "", 0);
    }

    public SitemapUrl(String loc, String lastMod, String changeFreq, double priority) {
        this.loc = loc == null ? "" : loc;
        this.lastMod = lastMod == null ? "" : lastMod;
        this.changeFreq = changeFreq == null ? "" : changeFreq;
        this.priority = priority;
    }
}

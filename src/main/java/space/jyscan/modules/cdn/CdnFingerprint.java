package space.jyscan.modules.cdn;

import java.util.Arrays;
import java.util.List;

/**
 * CDN / 云厂商 / 注册商指纹，对应 Go 的 {@code cdn.CDNFingerprint}。
 *
 * <p>{@code type} 取值与 Go 一致：{@code "cname"}、{@code "header"}、{@code "ip"}。
 */
public final class CdnFingerprint {

    /** 指纹名称（如 "Cloudflare"）。 */
    public String name = "";

    /** 厂商名（如 "Cloudflare, Inc."）。 */
    public String vendor = "";

    /** 匹配模式列表（大小写不敏感的子串匹配）。 */
    public List<String> patterns = List.of();

    /** 指纹类型：cname / header / ip。 */
    public String type = "";

    public CdnFingerprint() {
    }

    public CdnFingerprint(String name, String vendor, String type, String... patterns) {
        this.name = name;
        this.vendor = vendor;
        this.type = type;
        this.patterns = Arrays.asList(patterns);
    }
}

package space.jyscan.modules.dns;

/**
 * 过滤模式，对应 Go 的 {@code dns.FilterMode}。
 *
 * <p>Go 用 {@code iota} 常量 + {@code String()} 方法；Java 用枚举的 {@link #key}
 * 保持同样的字符串表示（{@code disabled} / {@code whitelist} / {@code blacklist}）。
 */
public enum FilterMode {

    /** 不启用过滤。 */
    DISABLED("disabled"),

    /** 白名单模式，只记录匹配的域名。 */
    WHITELIST("whitelist"),

    /** 黑名单模式，排除匹配的域名。 */
    BLACKLIST("blacklist");

    private final String key;

    FilterMode(String key) {
        this.key = key;
    }

    /** 对应 Go 的 {@code FilterMode.String()}。 */
    public String key() {
        return key;
    }

    /**
     * 解析过滤模式，对应 Go 的 {@code ParseFilterMode}：
     * whitelist/white/w → whitelist；blacklist/black/b → blacklist；其余（含空）→ disabled。
     */
    public static FilterMode parse(String mode) {
        String m = mode == null ? "" : mode.trim().toLowerCase(java.util.Locale.ROOT);
        return switch (m) {
            case "whitelist", "white", "w" -> WHITELIST;
            case "blacklist", "black", "b" -> BLACKLIST;
            default -> DISABLED;
        };
    }
}

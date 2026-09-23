package space.jyscan.pocli;

/**
 * 命令分组，对应 Go 的 cli.CommandGroup。
 *
 * <p>值即 i18n key 中 {@code group.xxx} 的 {@code xxx} 部分，运行时由
 * {@link space.jyscan.core.i18n.I18n#T} 翻译。
 */
public enum CommandGroup {

    GENERAL("general"),
    PASSWORD("password"),
    NETWORK("network"),
    INFO("info"),
    WEB("web"),
    PRIVESC("privesc"),
    TESTING("testing");

    private final String key;

    CommandGroup(String key) {
        this.key = key;
    }

    public String key() {
        return key;
    }

    /** i18n key，如 {@code group.general}。 */
    public String i18nKey() {
        return "group." + key;
    }

    /** 对应 Go 的 CommandRegistry.GetGroupsInOrder。 */
    public static CommandGroup[] inOrder() {
        return new CommandGroup[]{
                GENERAL, PASSWORD, NETWORK, INFO, WEB, PRIVESC, TESTING
        };
    }
}

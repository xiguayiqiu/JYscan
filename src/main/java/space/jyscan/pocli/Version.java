package space.jyscan.pocli;

/**
 * 全局版本号，对应 Go 的 cli.Version。
 */
public final class Version {

    public static final String VERSION = "v3.6-free";

    private Version() {
    }

    /** 对应 Go main.isVersionOnly 的输出：{@code jyscan-free version v3.6-free}。 */
    public static String versionLine() {
        return "jyscan-free version " + VERSION;
    }
}

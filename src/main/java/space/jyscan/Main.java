package space.jyscan;

import space.jyscan.core.config.AppConfig;
import space.jyscan.core.util.Colors;
import space.jyscan.pocli.Cli;

/**
 * 程序入口，对应 Go 的 freeclient/main.go。
 */
public class Main {

    public static void main(String[] args) {
        setupEncoding();

        // 配置初始化失败只告警，不阻断（与 Go 一致）
        try {
            AppConfig.initConfig();
        } catch (Throwable t) {
            Colors.logWarning("配置加载失败，使用默认配置: %v", t.getMessage());
        }

        int code = Cli.run(args);
        if (code != 0) {
            System.exit(code);
        }
    }

    /** Windows 下保证子进程 UTF-8，对应 Go 的 setupEncoding。 */
    private static void setupEncoding() {
        if (space.jyscan.core.util.SystemUtil.isWindows()) {
            System.setProperty("file.encoding", "UTF-8");
        }
    }
}

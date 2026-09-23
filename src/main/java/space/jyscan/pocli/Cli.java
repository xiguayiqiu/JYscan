package space.jyscan.pocli;

import picocli.CommandLine;

import java.util.ArrayList;
import java.util.List;

/**
 * 命令行入口编排，对应 Go 的 cli.Execute() 与 main.go 的前置处理。
 *
 * <p>处理顺序与 Go 版对齐：
 * <ol>
 *   <li>仅 {@code -v}/{@code --version}（唯一参数）时打印版本并退出；</li>
 *   <li>从原始参数提取 {@code --lang}，缺省走 JYSCAN_LANG/LANG 探测；</li>
 *   <li>消费并剥离全局 flag（--no-banner/--no-color/-q/-v/-V/--lang）；</li>
 *   <li>nuclei 兼容：{@code -td} 重写为 {@code --td}；</li>
 *   <li>无子命令 / 根级 {@code -h} / {@code help} → 横幅 + 分组帮助；</li>
 *   <li>{@code help <cmd>} → 打印该命令帮助；</li>
 *   <li>其余交给 picocli 分发。</li>
 * </ol>
 */
public final class Cli {

    private Cli() {
    }

    public static int run(String[] rawArgs) {
        String[] args = rawArgs == null ? new String[0] : rawArgs;

        // 1. 仅版本参数（对应 main.isVersionOnly / cli.showVersion）
        if (args.length == 1 && isVersionFlag(args[0])) {
            System.out.println(Version.versionLine());
            return 0;
        }

        // 2. 语言：优先 --lang，缺省环境探测
        String lang = extractLang(args);
        if (lang != null) {
            String parsed = I18nParse(lang);
            if (parsed != null) {
                space.jyscan.core.i18n.I18n.setLang(parsed);
            }
        } else {
            space.jyscan.core.i18n.I18n.setLang(space.jyscan.core.i18n.I18n.detect());
        }

        // 3/4. 剥离全局 flag + nuclei -td 兼容
        boolean versionFlag = false;
        List<String> rest = new ArrayList<>(args.length);
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--no-banner" -> {
                    RootOptions.noBanner = true;
                    continue;
                }
                case "--no-color" -> {
                    space.jyscan.core.util.Colors.setColor(false);
                    continue;
                }
                case "-q", "--silent" -> {
                    space.jyscan.core.util.Colors.setSilent(true);
                    continue;
                }
                case "-v", "--verbose" -> {
                    space.jyscan.core.util.Colors.setVerbose(true);
                    continue;
                }
                case "-V" -> {
                    versionFlag = true;
                    continue;
                }
                case "--version" -> {
                    versionFlag = true;
                    continue;
                }
                case "--lang" -> {
                    if (i + 1 < args.length) {
                        i++;
                    }
                    continue;
                }
                case "-td" -> {
                    rest.add("--td");
                    continue;
                }
                default -> {
                }
            }
            if (a.startsWith("--lang=")) {
                continue;
            }
            if (a.startsWith("-td=")) {
                rest.add("--td=" + a.substring(4));
                continue;
            }
            rest.add(a);
        }

        // 裸 -V（无子命令）等价于显示版本
        if (versionFlag && firstSubCommand(rest) == null) {
            System.out.println(Version.versionLine());
            return 0;
        }

        String[] argv = rest.toArray(new String[0]);

        // 5. 无子命令 → 横幅 + 分组帮助
        if (argv.length == 0) {
            return rootHelp();
        }

        // 6. 根级 -h/--help（尚未进入任何子命令）
        String first = firstNonFlag(argv);
        if (first == null && hasHelpFlag(argv)) {
            return rootHelp();
        }

        // 7. help [命令...]
        if (first != null && "help".equals(first)) {
            int idx = indexOf(argv, "help");
            if (idx + 1 >= argv.length) {
                return rootHelp();
            }
            String[] path = new String[argv.length - idx - 1];
            System.arraycopy(argv, idx + 1, path, 0, path.length);
            if (!HelpPrinter.printCommandHelp(path)) {
                space.jyscan.core.util.Colors.errorPrint(
                        space.jyscan.core.i18n.I18n.T("help.cmd_failed"), "unknown help topic");
                return 1;
            }
            return 0;
        }

        // 8. 交由 picocli 分发
        CommandLine root = RootCommand.build();
        root.setParameterExceptionHandler((ex, args1) -> {
            String msg = ex.getMessage();
            // cobra 风格：未知子命令单独报 unknown command，其余原样报错
            if (msg != null && msg.startsWith("Unmatched argument")
                    && args1 != null && args1.length > 0 && firstNonFlagOf(args1) >= 0) {
                space.jyscan.core.util.Colors.errorPrint("unknown command %q for %q",
                        args1[firstNonFlagOf(args1)], RootCommand.NAME);
            } else {
                space.jyscan.core.util.Colors.errorPrint("%v", msg);
            }
            return 1;
        });
        root.setExecutionExceptionHandler((ex, cmd, parseResult) -> {
            space.jyscan.core.util.Colors.errorPrint(
                    space.jyscan.core.i18n.I18n.T("help.cmd_failed"), ex.getMessage());
            space.jyscan.core.util.Colors.errorPrint("%v", ex.getMessage());
            return 1;
        });
        return root.execute(argv);
    }

    private static int rootHelp() {
        if (!RootOptions.noBanner) {
            HelpPrinter.printBanner();
        }
        HelpPrinter.printCustomHelp();
        return 0;
    }

    private static boolean isVersionFlag(String a) {
        return "-v".equals(a) || "--version".equals(a) || "-V".equals(a);
    }

    private static String extractLang(String[] args) {
        for (int i = 0; i < args.length; i++) {
            if ("--lang".equals(args[i])) {
                return i + 1 < args.length ? args[i + 1] : null;
            }
            if (args[i].startsWith("--lang=")) {
                return args[i].substring("--lang=".length());
            }
        }
        return null;
    }

    private static String I18nParse(String v) {
        return space.jyscan.core.i18n.I18n.parseLang(v);
    }

    /** 第一个不以 '-' 开头的参数（即子命令名），没有则返回 null。 */
    private static String firstNonFlag(String[] argv) {
        for (String a : argv) {
            if (a == null || a.isEmpty()) {
                continue;
            }
            if (a.charAt(0) != '-') {
                return a;
            }
        }
        return null;
    }

    private static String firstSubCommand(List<String> argv) {
        for (String a : argv) {
            if (a != null && !a.isEmpty() && a.charAt(0) != '-') {
                return a;
            }
        }
        return null;
    }

    private static boolean hasHelpFlag(String[] argv) {
        for (String a : argv) {
            if ("-h".equals(a) || "--help".equals(a)) {
                return true;
            }
        }
        return false;
    }

    private static int indexOf(String[] argv, String v) {
        for (int i = 0; i < argv.length; i++) {
            if (v.equals(argv[i])) {
                return i;
            }
        }
        return -1;
    }

    /** 未匹配参数里第一个非 flag 项的下标，没有则 -1。 */
    private static int firstNonFlagOf(String[] argv) {
        for (int i = 0; i < argv.length; i++) {
            if (argv[i] != null && !argv[i].isEmpty() && argv[i].charAt(0) != '-') {
                return i;
            }
        }
        return -1;
    }

    /** 根级全局选项状态，供 RootCommand / HelpPrinter 读取。 */
    public static final class RootOptions {
        public static boolean noBanner = false;

        private RootOptions() {
        }
    }
}

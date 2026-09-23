package space.jyscan.pocli;

import space.jyscan.core.i18n.I18n;
import space.jyscan.core.util.Colors;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import picocli.CommandLine;

/**
 * 启动横幅与自定义分组帮助，对应 Go 的 printBanner / printCustomHelp。
 */
public final class HelpPrinter {

    /** ASCII 艺术字，HiBlue + Bold，逐行与 Go 版一致。 */
    private static final String[] FIGLET = {
            "       _  __   __                             ",
            "      | | \\ \\ / /  ___    ___    __ _   _ __  ",
            "   _  | |  \\ V /  / __|  / __|  / _` | | '_ \\ ",
            "  | |_| |   | |   \\__ \\ | (__  | (_| | | | | |",
            "   \\___/    |_|   |___/  \\___|  \\__,_| |_| |_|",
            "                                              ",
    };

    private HelpPrinter() {
    }

    /** 对应 Go 的 printBanner()。 */
    public static void printBanner() {
        System.out.println();
        for (String line : FIGLET) {
            System.out.println(Colors.wrap(line, Colors.FG_HI_BLUE, Colors.BOLD));
        }
        System.out.println();

        boldInfo("==============================================");
        boldInfo(I18n.T("app.banner_title"));
        boldInfo(I18n.T("app.author"));
        boldInfo(I18n.Tf("app.version", Version.VERSION));
        boldInfo(I18n.T("app.desc"));

        System.out.println(Colors.wrap(I18n.T("app.warning"), Colors.FG_HI_RED, Colors.BOLD));

        boldInfo("==============================================");
        boldInfo(I18n.T("app.get_help"));
    }

    private static void boldInfo(String s) {
        System.out.println(Colors.wrap(s, Colors.BOLD, Colors.FG_BLUE));
    }

    /** 对应 Go 的 printCustomHelp()。 */
    public static void printCustomHelp() {
        printCustomHelp(System.out);
    }

    public static void printCustomHelp(PrintStream out) {
        out.println(I18n.T("help.usage"));
        out.println("  jyscan [help] [flags]");
        out.println("  jyscan [command]");
        out.println();

        out.println(I18n.T("help.available"));
        out.println();

        for (CommandGroup group : CommandGroup.inOrder()) {
            List<Registry.Entry> entries = Registry.getGroupEntries(group);
            if (entries.isEmpty()) {
                continue;
            }
            out.printf("  ==== %s ====%n", I18n.T(group.i18nKey()));
            entries.sort(Comparator.comparing(Registry.Entry::name));
            for (Registry.Entry e : entries) {
                out.printf("  %-15s %s%n", e.name(), shortDesc(e));
            }
            out.println();
        }

        out.println(I18n.T("help.flags"));
        out.print(rootFlagUsages());
        out.println();
        out.println();
        out.println(I18n.T("help.get_cmd_help"));
    }

    /**
     * 取命令一句话描述：优先 i18n 的 {@code cmd.xxx.short}，缺失时回退到
     * picocli 注解里的 description —— 与 Go 版的回退逻辑一致。
     */
    public static String shortDesc(Registry.Entry e) {
        String key = "cmd." + e.name() + ".short";
        if (I18n.has(key)) {
            return I18n.T(key);
        }
        String[] d = CommandLine.Model.CommandSpec.forAnnotatedObject(e.command())
                .usageMessage().description();
        if (d != null && d.length > 0 && !d[0].isEmpty()) {
            return d[0];
        }
        return "";
    }

    /**
     * 渲染根命令持久 flag 列表，风格对齐 pflag 的 FlagUsages：
     * 按 flag 名字母序，左对齐描述。
     */
    public static String rootFlagUsages() {
        record Row(String sortKey, String names, String type, String usage) {
        }

        List<Row> rows = new ArrayList<>();
        rows.add(new Row("silent", "-q, --silent", "", I18n.T("root.flag.silent")));
        rows.add(new Row("version", "-V, --version", "", I18n.T("root.flag.version")));
        rows.add(new Row("no-banner", "    --no-banner", "", I18n.T("root.flag.noBanner")));
        rows.add(new Row("no-color", "    --no-color", "", I18n.T("root.flag.noColor")));
        rows.add(new Row("verbose", "-v, --verbose", "", I18n.T("root.flag.verbose")));
        rows.add(new Row("lang", "    --lang", "string", I18n.T("root.flag.lang")));

        rows.sort(Comparator.comparing(Row::sortKey));

        int width = 0;
        for (Row r : rows) {
            width = Math.max(width, r.names().length() + r.type().length());
        }

        StringBuilder sb = new StringBuilder();
        for (Row r : rows) {
            String left = "  " + r.names();
            if (!r.type().isEmpty()) {
                left += " " + r.type();
            }
            int pad = width - r.names().length() - r.type().length() + 2;
            sb.append(left).append(" ".repeat(Math.max(1, pad)))
                    .append(r.usage()).append('\n');
        }
        return sb.toString();
    }

    /**
     * {@code jyscan help <cmd> [sub]}：打印指定命令的 picocli 用法。
     *
     * @return 找到了返回 true
     */
    public static boolean printCommandHelp(String[] path) {
        if (path == null || path.length == 0) {
            return false;
        }
        Object cmd = Registry.getCommand(path[0]);
        if (cmd == null) {
            return false;
        }
        CommandLine line = new CommandLine(cmd);
        for (int i = 1; i < path.length; i++) {
            CommandLine sub = line.getSubcommands().get(path[i]);
            if (sub == null) {
                Colors.errorPrint("Unknown help topic %s", path[i]);
                return false;
            }
            line = sub;
        }
        line.usage(System.out);
        return true;
    }
}

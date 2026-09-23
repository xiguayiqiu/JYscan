package space.jyscan.pocli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * 根命令，对应 Go 的 cli.rootCmd。
 *
 * <p>全局 flag（-q/-v/-V/--no-banner/--no-color/--lang）由 {@link Cli} 在原始
 * 参数阶段就已消费并剥离（与 Go 的 Execute() 先于 cobra 解析的处理方式一致），
 * 因此这里不再声明这些选项，子命令也能像 cobra persistent flag 一样接收它们。
 *
 * <p>无子命令时输出启动横幅 + 分组帮助，与 Go 的 Run 一致。
 */
@Command(
        name = RootCommand.NAME,
        sortOptions = false,
        showDefaultValues = false
)
public class RootCommand implements Runnable {

    public static final String NAME = "jyscan";

    @Override
    public void run() {
        HelpPrinter.printBanner();
        HelpPrinter.printCustomHelp();
    }

    /** 把注册表里的全部命令挂到根命令下。 */
    static CommandLine build() {
        CommandLine root = new CommandLine(new RootCommand());
        for (Registry.Entry e : Registry.entries()) {
            root.addSubcommand(e.name(), e.command());
        }
        return root;
    }
}

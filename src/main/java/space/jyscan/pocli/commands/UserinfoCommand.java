package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import space.jyscan.core.util.Colors;
import space.jyscan.modules.userinfo.GroupInfo;
import space.jyscan.modules.userinfo.UserInfo;
import space.jyscan.modules.userinfo.Userinfo;

import java.util.List;
import java.util.concurrent.Callable;

/**
 * userinfo 命令，移植自 freeclient/internal/cli/userinfo.go。
 *
 * <p>分析本地系统的用户和组信息：默认（未指定 --users-only / --groups-only）
 * 时两者都显示；首个位置参数为 {@code help} 时显示帮助。
 *
 * <p>Go 的 {@code Long:} 多行文案放在 header，{@code Example:} 放在 footer，
 * description 保持单行 Short 文案（分组帮助读 description[0]）。
 *
 * <p>{@code -d/--detailed} 在 Go 侧定义了 flag 但 Run 中从未读取，
 * 这里按原样保留同名选项（同样不改变行为）。
 */
@Command(
        name = "userinfo",
        description = "本地用户和组分析",
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true,
        header = {
                "分析本地系统的用户和组信息，支持Windows和Linux系统",
                "",
                "功能特性：",
                "• 自动检测操作系统类型（Windows/Linux）",
                "• 显示本地用户账户信息",
                "• 显示本地用户组信息",
                "• 支持详细的权限和属性信息",
                "• 跨平台兼容，支持多种系统",
                "",
                "支持的平台：",
                "• Windows: 支持本地用户和组分析",
                "• Linux: 支持本地用户和组分析"
        },
        footer = {
                "",
                "示例:",
                "  # 显示本地用户和组信息",
                "  JYscan.exe userinfo",
                "  ",
                "  # 仅显示用户信息",
                "  JYscan.exe userinfo --users-only",
                "  ",
                "  # 仅显示组信息",
                "  JYscan.exe userinfo --groups-only",
                "  ",
                "  # 显示详细信息",
                "  JYscan.exe userinfo --detailed",
                "  ",
                "  # 显示帮助信息",
                "  JYscan.exe userinfo help"
        }
)
public class UserinfoCommand implements Callable<Integer> {

    /** picocli 注入的命令规格，用于打印帮助（等价 cobra 的 cmd.Help()）。 */
    @Spec
    CommandSpec spec;

    /** 仅显示用户信息（对应 Go：--users-only，无短选项）。 */
    @Option(names = "--users-only", description = "仅显示用户信息")
    boolean usersOnly;

    /** 仅显示组信息（对应 Go：--groups-only，无短选项）。 */
    @Option(names = "--groups-only", description = "仅显示组信息")
    boolean groupsOnly;

    /** 显示详细信息（对应 Go：-d/--detailed；Go 的 Run 中未读取该 flag）。 */
    @Option(names = {"-d", "--detailed"}, description = "显示详细信息")
    boolean detailed;

    /** 位置参数：与 Go 版一致，第一个参数为 "help" 时显示帮助。 */
    @Parameters(arity = "0..*", paramLabel = "ARGS", description = "位置参数（help 显示帮助）")
    List<String> args;

    @Override
    public Integer call() {
        // 检查是否请求帮助（对应 Go：args[0] == "help" → cmd.Help()）
        if (args != null && !args.isEmpty() && "help".equals(args.get(0))) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        // 获取命令行参数
        boolean users = usersOnly;
        boolean groups = groupsOnly;

        Colors.bannerPrint("本地用户和组分析工具");

        // 默认显示用户和组信息
        if (!users && !groups) {
            users = true;
            groups = true;
        }

        boolean failed = false;

        // 分析用户信息
        if (users) {
            Colors.infoPrint("正在分析本地用户信息...");
            try {
                List<UserInfo> usersList = Userinfo.analyzeLocalUsers();
                // 总是使用带颜色的格式化输出
                Colors.infoPrint("%s", Userinfo.formatUserInfo(usersList));
            } catch (Exception e) {
                Colors.errorPrint("分析用户信息失败: %v", e);
                failed = true;
            }
        }

        // 分析组信息
        if (groups) {
            Colors.infoPrint("正在分析本地组信息...");
            try {
                List<GroupInfo> groupsList = Userinfo.analyzeLocalGroups();
                // 总是使用带颜色的格式化输出
                Colors.infoPrint("%s", Userinfo.formatGroupInfo(groupsList));
            } catch (Exception e) {
                Colors.errorPrint("分析组信息失败: %v", e);
                failed = true;
            }
        }

        Colors.successPrint("用户和组分析完成");

        // Go 版 cobra Run 不设置退出码；这里按项目约定在分析失败时返回非零
        return failed ? 1 : 0;
    }
}

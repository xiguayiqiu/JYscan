package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

import space.jyscan.core.util.Colors;
import space.jyscan.modules.ssl.SSLResult;
import space.jyscan.modules.ssl.SslPrinter;
import space.jyscan.modules.ssl.SslScanner;

import java.util.List;
import java.util.concurrent.Callable;

/**
 * ssl 命令，移植自 freeclient/internal/cli/ssl.go。
 *
 * <p>默认模式 = {@code ssl.ScanSSL} + {@code ssl.PrintResults}；
 * {@code -a/--all} 全面检测模式 = {@code ssl.ScanAllSSL} + {@code ssl.PrintFullResults}。
 * 与 cobra 一致：最多接受 1 个位置参数（位置参数覆盖 -t），首个参数为
 * {@code help} 时显示帮助。
 */
@Command(
        name = "ssl",
        description = "SSL/TLS配置检测工具",
        header = {
                "SSL/TLS配置检测工具 - 检测目标主机的SSL/TLS配置信息",
                "",
                "支持功能:",
                "- 检测SSL/TLS版本支持",
                "- 获取密码套件信息",
                "- 检查证书有效期",
                "- 显示证书颁发者和主题",
                "- 自定义超时设置",
                "",
                "使用示例:",
                "  ./JYscan ssl example.com -p 443                    # 检测默认HTTPS端口",
                "  ./JYscan ssl example.com -p 8443 -T 10             # 自定义端口和超时",
                "  ./JYscan ssl 192.168.1.1 -p 443                    # 检测IP地址",
                "  ./JYscan ssl -t example.com -p 443                 # 兼容旧格式",
                "",
                "警告: 仅用于授权测试和安全评估，严禁未授权使用！"
        },
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true
)
public class SslCommand implements Callable<Integer> {

    /** picocli 注入的命令规格，用于打印帮助（等价 cobra 的 cmd.Help()）。 */
    @Spec
    CommandSpec spec;

    @Option(names = {"-t", "--target"}, description = "目标主机（域名或IP地址）")
    String target;

    @Option(names = {"-p", "--port"}, description = "目标端口")
    int port = 443;

    @Option(names = {"-T", "--timeout"}, description = "超时时间（秒）")
    int timeout = 5;

    @Option(names = {"-a", "--all"}, description = "全面检测模式，检测所有支持的协议和密码套件")
    boolean allMode;

    /** 位置参数：对应 cobra 的 MaximumNArgs(1)，位置参数优先于 -t。 */
    @Parameters(arity = "0..1", index = "0", paramLabel = "TARGET",
            description = "目标主机（域名或IP地址）")
    String targetArg;

    @Override
    public Integer call() {
        // 检查是否请求帮助（对应 Go：args[0] == "help" → cmd.Help()）
        if ("help".equals(targetArg)) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        // 设置详细模式（对应 ssl.SetVerbose(rootCmd 的 --verbose)）
        SslScanner.setVerbose(Colors.isVerbose);

        // 处理位置参数（位置参数覆盖 -t）
        String t = targetArg != null ? targetArg : (target == null ? "" : target);

        // 验证参数
        if (t.isEmpty()) {
            Colors.errorPrint("必须指定目标主机，可以使用位置参数或 -t 参数");
            spec.commandLine().usage(System.out);
            return 1;
        }

        // 设置全面检测模式
        if (allMode) {
            Colors.logInfo("全面检测模式已启用...");
            // 调用全面检测函数
            List<SSLResult> results = SslScanner.scanAllSSL(t, port, timeout);
            return SslPrinter.printFullResults(results) ? 0 : 1;
        }

        if (port == 0) {
            port = 443; // 默认HTTPS端口
        }

        if (timeout == 0) {
            timeout = 5; // 默认超时5秒
        }

        // 执行SSL检测
        Colors.logInfo("正在检测 %s:%d 的SSL配置...", t, port);
        SSLResult result = SslScanner.scanSSL(t, port, timeout);

        // 打印结果（失败时已打印错误信息，返回非零退出码）
        return SslPrinter.printResults(result) ? 0 : 1;
    }
}

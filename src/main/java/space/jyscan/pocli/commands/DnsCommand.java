package space.jyscan.pocli.commands;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import space.jyscan.core.util.Colors;
import space.jyscan.modules.dns.DnsConfig;
import space.jyscan.modules.dns.DnsQuery;
import space.jyscan.modules.dns.DnsPrint;
import space.jyscan.modules.dns.FullDnsResult;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * dns 命令，移植自 freeclient/internal/dns/cmd.go。
 *
 * <p>flag 与默认值对齐：
 * -s/--server(8.8.8.8)、-p/--port(53)、-t/--type(A)、
 * -o/--timeout(5)、--trace、-x/--reverse、--short、--all。
 *
 * <p>目标位置参数既是正向查询的域名，也是反向查询时的 IP（配合 -x）。
 */
@Command(
        name = "dns",
        description = "DNS 查询工具，支持多种记录类型和反向查询",
        header = {
                "",
                "jyscan DNS查询模块 - 功能强大的DNS查询工具",
                "",
                "支持功能:",
                "- 查询多种DNS记录类型 (A, AAAA, MX, NS, TXT, CNAME, SOA, ANY)",
                "- 反向DNS查询 (PTR记录)，使用 -x 参数",
                "- 指定自定义DNS服务器",
                "- 查询所有可用记录类型 (--all)",
                "- 追踪查询路径 (--trace)",
                "",
                "用法:",
                "  1. 查询域名A记录: jyscan dns 域名 [选项]",
                "  2. 反向查询IP: jyscan dns -x IP地址 [选项]",
                "  3. 获取帮助: jyscan dns help",
                "",
                "示例用法:",
                "  ./jyscan dns example.com",
                "  ./jyscan dns example.com -t AAAA",
                "  ./jyscan dns example.com -t ANY",
                "  ./jyscan dns -x 8.8.8.8",
                "  ./jyscan dns example.com -s 1.1.1.1 -p 53",
                "  ./jyscan dns example.com --trace",
                "  ./jyscan dns example.com --short",
                "  ./jyscan dns example.com --all",
                "",
                "警告: 仅用于授权测试，严禁未授权使用！"
        },
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true
)
public class DnsCommand implements Callable<Integer> {

    @Spec
    private CommandSpec spec;

    /** 目标域名/IP，对应 Go 的位置参数。 */
    @Parameters(arity = "0..1", paramLabel = "TARGET",
                 description = "查询目标（域名或IP地址）")
    private String target;

    /** DNS服务器地址，对应 Go 的 -s/--server。 */
    @Option(names = {"-s", "--server"}, description = "指定DNS服务器地址")
    private String server = "8.8.8.8";

    /** DNS服务器端口，对应 Go 的 -p/--port。 */
    @Option(names = {"-p", "--port"}, description = "指定DNS服务器端口")
    private int port = 53;

    /** DNS记录类型，对应 Go 的 -t/--type。 */
    @Option(names = {"-t", "--type"}, description = "DNS记录类型 (A/AAAA/MX/NS/TXT/CNAME/SOA/ANY)")
    private String recordType = "A";

    /** 查询超时时间(秒)，对应 Go 的 -o/--timeout。 */
    @Option(names = {"-o", "--timeout"}, description = "查询超时时间(秒)")
    private int timeout = 5;

    /** 显示查询追踪信息，对应 Go 的 --trace。 */
    @Option(names = {"--trace"}, description = "显示查询追踪信息")
    private boolean trace;

    /** 反向DNS查询，对应 Go 的 -x/--reverse。 */
    @Option(names = {"-x", "--reverse"}, description = "反向DNS查询 (PTR记录)")
    private boolean reverse;

    /** 简洁输出格式，对应 Go 的 --short。 */
    @Option(names = {"--short"}, description = "简洁输出格式 (类似 dig +short)")
    private boolean shortOutput;

    /** 查询所有记录类型，对应 Go 的 --all。 */
    @Option(names = {"--all"}, description = "查询所有可用记录类型")
    private boolean allTypes;

    @Override
    public Integer call() throws Exception {
        // 位置参数首个为 "help" 时打印帮助
        if (target != null && "help".equals(target)) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        // 位置参数作为目标（优先于 --target，因为 Go 是位置参数优先）
        String domain = target;

        if (domain == null || domain.isEmpty()) {
            Colors.errorPrint("请指定查询目标");
            spec.commandLine().usage(System.out);
            return 1;
        }

        if (allTypes) {
            // --all 模式：逐个类型查询
            Colors.infoPrint("[JYscan-DNS] 开始查询目标: %s", domain);
            Colors.infoPrint("[JYscan-DNS] 记录类型: ALL");
            Colors.infoPrint("[JYscan-DNS] DNS服务器: %s:%d", server, port);
            System.out.println();
            DnsQuery.queryAllTypesIndividually(domain, server, port,
                    Duration.ofSeconds(timeout), trace, shortOutput);
            Colors.successPrint("查询完成!");
            return 0;
        }

        DnsConfig config = new DnsConfig();
        config.domain = domain;
        config.server = server;
        config.port = port;
        config.recordType = recordType.toUpperCase();
        config.timeout = Duration.ofSeconds(timeout);
        config.trace = trace;
        config.reverse = reverse;
        config.shortOutput = shortOutput;

        Colors.infoPrint("[JYscan-DNS] 开始查询目标: %s", domain);
        if (!shortOutput && !reverse) {
            Colors.infoPrint("[JYscan-DNS] 记录类型: %s", recordType);
        }
        if (reverse && !shortOutput) {
            Colors.infoPrint("[JYscan-DNS] 模式: 反向DNS查询 (PTR)");
        }
        Colors.infoPrint("[JYscan-DNS] DNS服务器: %s:%d", server, port);
        System.out.println();

        try {
            FullDnsResult result = DnsQuery.queryDnsFull(config);
            if (result != null && result.msg != null) {
                if (shortOutput) {
                    DnsPrint.printShortResult(result.msg);
                } else {
                    DnsPrint.printFullResult(result, shortOutput);
                }
            } else {
                Colors.errorPrint("查询失败: 无响应或无效响应");
                return 1;
            }
        } catch (IOException e) {
            Colors.errorPrint("查询失败: %s", e.getMessage());
            return 1;
        }

        Colors.successPrint("查询完成!");
        return 0;
    }
}

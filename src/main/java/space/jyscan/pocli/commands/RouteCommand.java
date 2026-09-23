package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.modules.route.RouteHop;
import space.jyscan.modules.route.RouteTracer;

import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * route 命令，移植自 freeclient/internal/cli/route.go。
 *
 * <p>路由跳数检测：逐跳设置 TTL 发送 ICMP Echo 请求，
 * 统计每一跳的响应 IP、主机名、平均延时与丢包率。
 */
@Command(
        name = "route",
        description = "路由跳数检测",
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true,
        header = {
                "路由跳数检测工具，用于追踪网络数据包从源到目标的路径。",
                "",
                "示例:",
                "  JYscan route 8.8.8.8                    # 检测到Google DNS的路由",
                "  JYscan route google.com --max-hops 10   # 检测到Google的路由，最大10跳",
                "  JYscan route 192.168.1.1 --count 5      # 每个跳数探测5次",
                "  JYscan route example.com --timeout 5    # 设置5秒超时"
        }
)
public class RouteCommand implements Callable<Integer> {

    @Option(names = {"-m", "--max-hops"}, defaultValue = "30", description = "最大跳数")
    int maxHops;

    @Option(names = {"-t", "--timeout"}, defaultValue = "3", description = "超时时间（秒）")
    int timeout;

    @Option(names = {"-c", "--count"}, defaultValue = "3", description = "每个跳数的探测次数")
    int count;

    /**
     * 位置参数放宽为 0..*，由 call() 里的校验复刻 Go 的 Args 函数
     * （少于 1 个参数要报 Go 的原文错误），多余参数与 Go 一样只取第一个、忽略其余。
     */
    @Parameters(arity = "0..*", paramLabel = "目标", description = "目标IP或域名")
    List<String> args;

    @Spec
    CommandSpec spec;

    @Override
    public Integer call() {
        // 检查是否请求帮助（Go: args[0] == "help" 时 cmd.Help()）
        if (args != null && !args.isEmpty() && "help".equals(args.get(0))) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        // 检查是否指定目标（Go Args: len(args) < 1 -> 需要指定目标IP或域名）
        if (args == null || args.isEmpty()) {
            Colors.errorPrint("%s", "需要指定目标IP或域名");
            return 1;
        }

        String target = args.get(0);

        // 验证目标地址（支持IP和域名）（Go Args: net.ResolveIPAddr / net.LookupHost）
        try {
            RouteTracer.resolveIPv4(target);
        } catch (Exception e) {
            Colors.errorPrint("无效的目标地址或域名: %v", e);
            return 1;
        }

        return runRouteDetection(target);
    }

    // =====================================================================
    // 运行路由检测（对应 route.go 的 runRouteDetection）
    // =====================================================================

    private int runRouteDetection(String target) {
        Colors.infoPrint("[+] 开始路由检测到目标: %s", target);
        System.out.print(Fmt.format("    - 最大跳数: %d\n", maxHops));
        System.out.print(Fmt.format("    - 超时时间: %d秒\n", timeout));
        System.out.print(Fmt.format("    - 探测次数: %d\n", count));

        // 解析目标IP（Go 在 RunE 中再次 net.ResolveIPAddr）
        InetAddress targetIP;
        try {
            targetIP = RouteTracer.resolveIPv4(target);
        } catch (Exception e) {
            Colors.errorPrint("解析目标地址失败: %v", e);
            return 1;
        }

        Colors.infoPrint("[+] 目标IP: %s\n", targetIP.getHostAddress());

        // 执行路由检测
        List<RouteHop> hops;
        try {
            hops = RouteTracer.traceRoute(targetIP, maxHops, timeout, count);
        } catch (Exception e) {
            Colors.errorPrint("路由检测失败: %v", e);
            return 1;
        }

        // 显示结果
        Colors.infoPrint("[+] 路由检测结果:");
        System.out.println("跳数\tIP地址\t\t主机名\t\t延时(ms)\t丢包率");
        System.out.println("----\t-------\t\t------\t\t--------\t------");

        for (RouteHop hop : hops) {
            String hostname = hop.hostname;
            if (hostname == null || hostname.isEmpty()) {
                hostname = "未知";
            }

            String ipStr = hop.ip == null ? "*" : hop.ip;

            String packetLoss = Fmt.format("%.1f%%", hop.lossRate);

            System.out.print(Fmt.format("%s\t%s\t%s\t%.2f\t%s\n",
                    hop.hop,
                    ipStr,
                    hostname,
                    hop.avgDelay,
                    packetLoss));
        }

        Colors.successPrint("\n[+] 路由检测完成！共检测到 %d 跳", hops.size());

        return 0;
    }
}

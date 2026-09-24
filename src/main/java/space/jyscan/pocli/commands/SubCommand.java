package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import space.jyscan.core.util.Colors;
import space.jyscan.modules.subdomain.SubdomainConfig;
import space.jyscan.modules.subdomain.SubdomainResult;
import space.jyscan.modules.subdomain.SubdomainScanner;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * sub 命令，移植自 freeclient/internal/subdomain/cmd.go。
 *
 * <p>flag 与默认值对齐：-d/--domain、-w/--wordlist、-t/--threads(50)、
 * -o/--timeout(3)、-f/--output、-T/--type(A)、-H/--http(true)、--no-http(false)。
 *
 * <p>与 Go 一致的两处「flag 实际不生效」语义（保持原样，不擅自改动）：
 * <ul>
 *   <li>位置参数缺失或首个是 {@code help} 时直接打印帮助，因此 -d 实际取不到值
 *       （Go 在赋值前就 return，且随后无条件 {@code domain = args[0]}）；</li>
 *   <li>中断：收到信号后取消扫描并最多等 2 秒取回结果，与 Go 的 select 分支一致。</li>
 * </ul>
 */
@Command(
        name = "sub",
        description = "子域名挖掘工具，支持字典爆破和DNS查询",
        header = {
                "",
                "jyscan Subdomain模块 - 子域名挖掘工具",
                "",
                "支持功能:",
                "- 字典爆破 (基于DNS查询)",
                "- DNS记录查询 (A/CNAME/MX/TXT/NS)",
                "- 并发扫描 (支持高并发)",
                "- 自动通配符检测和过滤",
                "- 实时进度显示",
                "",
                "用法:",
                "  1. 直接传递目标: jyscan sub 目标域名 [选项]",
                "  2. 使用--domain标志: jyscan sub --domain 目标域名 [选项]",
                "  3. 获取帮助: jyscan sub help",
                "",
                "示例用法:",
                "  ./jyscan sub example.com",
                "  ./jyscan sub example.com -w subdomains.txt",
                "  ./jyscan sub example.com -w subdomains.txt -t 100",
                "  ./jyscan sub example.com -T CNAME",
                "",
                "DNS查询类型说明:",
                "  A:     IPv4地址记录",
                "  CNAME: 别名记录",
                "",
                "选项说明:",
                "  -H, --http:   验证HTTP响应，确认子域名是否真正可用",
                "                 (默认启用，可使用 --no-http 禁用)",
                "",
                "输出文件说明:",
                "  -f, --output:  指定输出文件路径，保存扫描结果",
                "",
                "DNS查询类型:",
                "  -T, --type: DNS查询类型 (默认: A)，可选 A/CNAME",
                "",
                "常用选项:",
                "  -d, --domain:   目标域名",
                "  -w, --wordlist: 子域名字典文件路径",
                "  -t, --threads:  并发线程数 (默认: 50)",
                "  -o, --timeout:  超时时间(秒) (默认: 3)",
                "  -f, --output:   结果输出文件",
                "  -H, --http:     验证HTTP响应，过滤无效子域名 (默认启用)"
        },
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true
)
public class SubCommand implements Callable<Integer> {

    /** 目标域名，对应 Go 的 -d/--domain（Go 里会被位置参数覆盖，见类注释）。 */
    @Option(names = {"-d", "--domain"}, description = "目标域名")
    private String domain;

    /** 子域名字典文件路径，对应 Go 的 -w/--wordlist。 */
    @Option(names = {"-w", "--wordlist"}, description = "子域名字典文件路径")
    private String wordlist;

    /** 并发线程数，对应 Go 的 -t/--threads。 */
    @Option(names = {"-t", "--threads"}, description = "并发线程数")
    private int threads = 50;

    /** 超时时间(秒)，对应 Go 的 -o/--timeout。 */
    @Option(names = {"-o", "--timeout"}, description = "超时时间(秒)")
    private int timeout = 3;

    /** 结果输出文件，对应 Go 的 -f/--output。 */
    @Option(names = {"-f", "--output"}, description = "结果输出文件")
    private String output;

    /** DNS查询类型，对应 Go 的 -T/--type。 */
    @Option(names = {"-T", "--type"}, description = "DNS查询类型 (A/CNAME)")
    private String queryType = "A";

    /** 验证HTTP响应，对应 Go 的 -H/--http（默认启用）。 */
    @Option(names = {"-H", "--http"}, description = "验证HTTP响应，过滤无效子域名")
    private boolean verifyHTTP = true;

    /** 禁用HTTP验证，对应 Go 的 --no-http。 */
    @Option(names = {"--no-http"}, description = "禁用HTTP验证")
    private boolean noVerifyHTTP;

    /** 位置参数：Go 要求第一个位置参数就是目标域名（或 help）。 */
    @Parameters(arity = "0..*", paramLabel = "ARGS", description = "位置参数：目标域名 / help")
    private List<String> params;

    @Spec
    private CommandSpec spec;

    /** 当前扫描器实例，供中断钩子调用 {@link SubdomainScanner#cancel()}。 */
    private volatile SubdomainScanner scanner;
    @Override
    public Integer call() {
        // 位置参数缺失或首个为 "help" → 打印帮助（对应 Go 的 len(args) == 0 || args[0] == "help"）
        if (params == null || params.isEmpty() || "help".equals(params.get(0))) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        // Go: domain = args[0]（无条件覆盖 -d/--domain 的值）
        domain = params.get(0);

        if (domain == null || domain.isEmpty()) {
            System.out.println("请指定目标域名 (直接传递目标参数或使用 --domain 标志)");
            System.out.println("用法: jyscan sub 目标域名 [选项] 或 jyscan sub --target 目标域名 [选项]");
            return 1;
        }

        domain = domain.toLowerCase(Locale.ROOT);
        if (!SubdomainScanner.isValidDomain(domain)) {
            System.out.printf("域名格式无效: %s%n", domain);
            System.out.println("支持格式: example.com, sub.example.com");
            return 1;
        }

        SubdomainConfig config = new SubdomainConfig();
        config.domain = domain;
        config.wordlist = wordlist == null ? "" : wordlist;
        config.threads = threads;
        config.timeout = Duration.ofSeconds(timeout);
        config.output = output == null ? "" : output;
        config.queryType = queryType == null ? "A" : queryType;
        config.verifyHTTP = verifyHTTP && !noVerifyHTTP;

        Colors.infoPrint("[JYscan-Subdomain] 开始扫描目标: %s", domain);

        // 初始化扫描器（含字典加载 + 通配符检测），对应 Go 的 NewScanner 失败分支
        try {
            scanner = new SubdomainScanner(config);
        } catch (Exception e) {
            Colors.errorPrint("初始化扫描器失败: %v", message(e));
            return 1;
        }

        AtomicReference<List<SubdomainResult>> resultsRef = new AtomicReference<>();
        AtomicReference<String> scanError = new AtomicReference<>();
        CountDownLatch done = new CountDownLatch(1);

        Thread worker = new Thread(() -> {
            try {
                resultsRef.set(scanner.start());
            } catch (Exception e) {
                scanError.set(message(e));
            } finally {
                done.countDown();
            }
        }, "jyscan-sub");
        worker.setDaemon(true);

        // 中断钩子：对应 Go 的 sigChan 分支
        Thread hook = new Thread(() -> {
            Colors.warningPrint("\n\n[!] 检测到中断信号 (%v)", "interrupt");
            Colors.infoPrint("等待扫描线程停止...");
            if (scanner != null) {
                scanner.cancel();
            }
            try {
                if (done.await(2, TimeUnit.SECONDS)) {
                    List<SubdomainResult> results =
                            resultsRef.get() == null ? List.of() : resultsRef.get();
                    // 命中行已在扫描过程中实时打印，这里只报统计
                    Colors.successPrint("\n扫描中断，共发现 %d 个子域名", results.size());
                } else {
                    Colors.errorPrint("扫描线程未能及时停止");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                Colors.errorPrint("扫描线程未能及时停止");
            }
        }, "jyscan-sub-sigint");
        Runtime.getRuntime().addShutdownHook(hook);

        worker.start();

        try {
            done.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        try {
            Runtime.getRuntime().removeShutdownHook(hook);
        } catch (IllegalStateException ignored) {
            // JVM 正在关闭：中断钩子负责输出
            return 0;
        }

        if (scanError.get() != null) {
            Colors.errorPrint("扫描失败: %v", scanError.get());
            return 1;
        }

        List<SubdomainResult> results = resultsRef.get();
        if (results == null) {
            return 1;
        }

        // 命中行已在扫描过程中实时打印（发现即显示），收尾只报统计，不再重复列表
        Colors.successPrint("\n扫描完成! 共发现 %d 个子域名 (耗时: %v)",
                results.size(), SubdomainScanner.getScanDuration());
        return 0;
    }

    /** 取异常消息（空消息回退到类名），对应 Go 的 err.Error()。 */
    private static String message(Exception e) {
        String msg = e.getMessage();
        return (msg == null || msg.isEmpty()) ? e.getClass().getSimpleName() : msg;
    }

}

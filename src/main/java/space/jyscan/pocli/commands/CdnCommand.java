package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import space.jyscan.core.util.Colors;
import space.jyscan.modules.cdn.Cdn;
import space.jyscan.modules.cdn.CdnConfig;
import space.jyscan.modules.cdn.CdnResult;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * cdn 命令，移植自 freeclient/internal/cdn/cmd.go。
 *
 * <p>flag 与默认值对齐：-t/--target、-o/--timeout(5)、--no-cdn、--no-cloud、--no-registrar。
 * 目标可来自位置参数或 --target（位置参数优先规则同 Go：仅当 --target 为空时取 args[0]）。
 *
 * <p>中断语义与 Go 一致：收到 SIGINT/SIGTERM 后先提示中断，再最多等 2 秒取回结果，
 * 超时则报「识别未能及时停止」。Java 侧用关闭钩子（与 DirscanCommand 的 Scanner 同范式）复现。
 */
@Command(
        name = "cdn",
        description = "CDN和云服务识别工具，识别CDN、云服务商和域名注册商",
        header = {
                "",
                "jyscan CDN模块 - CDN和云服务识别工具",
                "",
                "支持功能:",
                "- CDN识别（基于CNAME、HTTP响应头）",
                "- 云服务提供商识别（AWS、Azure、GCP、阿里云等）",
                "- 域名注册商识别（基于NS记录和WHOIS）",
                "- DNS记录查询（CNAME、A、NS、PTR）",
                "",
                "用法:",
                "  1. 直接传递目标: jyscan cdn 目标域名 [选项]",
                "  2. 使用--target标志: jyscan cdn --target 目标域名 [选项]",
                "  3. 获取帮助: jyscan cdn help",
                "",
                "示例用法:",
                "  ./jyscan cdn example.com",
                "  ./jyscan cdn example.com --timeout 10",
                "  ./jyscan cdn example.com --no-cdn --no-cloud",
                "  ./jyscan cdn example.com --only-registrar",
                "",
                "选项说明:",
                "  -t, --target:         目标域名",
                "  -o, --timeout:        超时时间(秒) (默认: 5)",
                "      --no-cdn:         禁用CDN检测",
                "      --no-cloud:       禁用云服务商检测",
                "      --no-registrar:   禁用注册商检测",
                "",
                "支持的CDN:",
                "  全球公有云巨头: Amazon CloudFront, Google Cloud CDN, Microsoft Azure CDN",
                "  专业/独立 CDN 厂商: Cloudflare, Akamai, Fastly, Bunny.net",
                "  国内云厂商: 阿里云CDN, 腾讯云CDN, 百度智能云CDN, 华为云CDN",
                "  国内独立厂商: 又拍云, 七牛云, 网宿科技CDN, 蓝汛ChinaCache",
                "  其他: 灵境云EdgeCDN, 火山引擎CDN, 美团云CDN, 京东云CDN, StackPath, Sucuri, Incapsula 等",
                "",
                "支持的云服务商: AWS, Google Cloud, Microsoft Azure, 阿里云, 腾讯云, 华为云, Oracle Cloud 等",
                "",
                "支持的注册商: GoDaddy, Namecheap, 阿里云, 腾讯云, Cloudflare, Name.com, Gandi, OVH 等"
        },
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true
)
public class CdnCommand implements Callable<Integer> {

    /** 目标域名，对应 Go 的 -t/--target。 */
    @Option(names = {"-t", "--target"}, description = "目标域名")
    private String target;

    /** 超时时间(秒)，对应 Go 的 -o/--timeout。 */
    @Option(names = {"-o", "--timeout"}, description = "超时时间(秒)")
    private int timeout = 5;

    /** 禁用CDN检测，对应 Go 的 --no-cdn。 */
    @Option(names = {"--no-cdn"}, description = "禁用CDN检测")
    private boolean noCdnCheck;

    /** 禁用云服务商检测，对应 Go 的 --no-cloud。 */
    @Option(names = {"--no-cloud"}, description = "禁用云服务商检测")
    private boolean noCloudCheck;

    /** 禁用注册商检测，对应 Go 的 --no-registrar。 */
    @Option(names = {"--no-registrar"}, description = "禁用注册商检测")
    private boolean noRegistrarCheck;

    /** 位置参数：首个为 "help" 时打印帮助；否则作为目标域名（当 --target 为空时）。 */
    @Parameters(arity = "0..*", paramLabel = "ARGS", description = "位置参数（目标域名 / help）")
    private List<String> params;

    @Spec
    private CommandSpec spec;

    @Override
    public Integer call() {
        // 位置参数首个为 "help" 时打印帮助（对应 Go 的 cmd.Help()）
        if (params != null && !params.isEmpty() && "help".equals(params.get(0))) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        // 仅当 --target 为空时取位置参数（与 Go 的赋值顺序一致）
        if ((target == null || target.isEmpty()) && params != null && !params.isEmpty()) {
            target = params.get(0);
        }

        if (target == null || target.isEmpty()) {
            System.out.println("请指定目标域名 (直接传递目标参数或使用 --target 标志)");
            System.out.println("用法: jyscan cdn 目标域名 [选项] 或 jyscan cdn --target 目标域名 [选项]");
            return 0;
        }

        target = target.toLowerCase();

        CdnConfig config = new CdnConfig();
        config.target = target;
        config.timeout = Duration.ofSeconds(timeout);
        config.enableCdnCheck = !noCdnCheck;
        config.enableCloudCheck = !noCloudCheck;
        config.enableRegistrarCheck = !noRegistrarCheck;

        Colors.infoPrint("[JYscan-CDN] 开始识别目标: %s", target);

        AtomicReference<CdnResult> resultRef = new AtomicReference<>();
        CountDownLatch done = new CountDownLatch(1);

        Thread worker = new Thread(() -> {
            try {
                resultRef.set(Cdn.cdnScan(config));
            } finally {
                done.countDown();
            }
        }, "jyscan-cdn");
        worker.setDaemon(true);

        // 中断处理：与 Go 的 select { resultChan / sigChan } 等价
        Thread hook = new Thread(() -> {
            Colors.warningPrint("\n\n[!] 检测到中断信号 (SIGINT/SIGTERM)");
            Colors.infoPrint("等待识别停止...");
            try {
                if (done.await(2, TimeUnit.SECONDS) && resultRef.get() != null) {
                    System.out.println();
                    System.out.println(Cdn.formatResult(resultRef.get()));
                    Colors.warningPrint("\n识别中断");
                } else {
                    Colors.errorPrint("识别未能及时停止");
                }
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                Colors.errorPrint("识别未能及时停止");
            }
        }, "jyscan-cdn-sigint");
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
            // JVM 正在关闭，钩子已在执行：此时它负责输出中断结果
            return 0;
        }

        CdnResult result = resultRef.get();
        if (result == null) {
            return 1;
        }
        System.out.println();
        System.out.println(Cdn.formatResult(result));
        Colors.successPrint("\n识别完成!");
        return 0;
    }
}

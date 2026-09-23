package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import space.jyscan.core.util.Colors;
import space.jyscan.modules.sitemap.SitemapConfig;
import space.jyscan.modules.sitemap.SitemapScanner;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * sitemap 命令，移植自 freeclient/internal/cli/sitemap.go。
 *
 * <p>flag 与默认值逐项对齐：-u/--url、-o/--output、--timeout(10)、
 * --user-agent("JYscan SitemapAnalyzer/1.0")、-r/--recursive、--max-depth(3)、
 * --show-all、-t/--threads(10)、-p/--path（逗号分隔）。
 *
 * <p>品牌改名：Go 的 {@code GYscan SitemapAnalyzer/1.0} 与 {@code [GYscan-Sitemap]}
 * 日志前缀统一为 JYscan（同 DirscanCommand 的做法）。
 */
@Command(
        name = "sitemap",
        description = "Sitemap分析工具",
        header = {
                "",
                "Sitemap分析工具 - 分析网站地图，发现更多页面",
                "",
                "支持功能:",
                "- 自动探测常见 sitemap 路径",
                "- 从 robots.txt 提取 sitemap 地址",
                "- 解析 XML sitemap 和 sitemap index",
                "- 支持 sitemap.txt 文本格式",
                "- 递归解析 sitemap index",
                "- 结果导出",
                "",
                "使用示例:",
                "  ./jyscan sitemap -u http://example.com                    # 基本扫描",
                "  ./jyscan sitemap -u https://example.com -r                # 递归解析 sitemap index",
                "  ./jyscan sitemap -u http://example.com -o results.txt     # 保存结果",
                "  ./jyscan sitemap -u http://example.com --show-all          # 显示所有页面",
                "",
                "警告: 仅用于授权测试和安全评估，严禁未授权使用！"
        },
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true
)
public class SitemapCommand implements Callable<Integer> {

    /** 目标URL（必需），对应 Go 的 -u/--url。 */
    @Option(names = {"-u", "--url"}, description = "目标URL (必需)")
    private String targetURL;

    /** 结果输出文件，对应 Go 的 -o/--output。 */
    @Option(names = {"-o", "--output"}, description = "结果输出文件")
    private String outputFile;

    /** 请求超时时间(秒)，对应 Go 的 --timeout。 */
    @Option(names = {"--timeout"}, description = "请求超时时间(秒)")
    private int timeout = 10;

    /** 自定义 User-Agent，对应 Go 的 --user-agent。 */
    @Option(names = {"--user-agent"}, description = "自定义User-Agent")
    private String userAgent = "JYscan SitemapAnalyzer/1.0";

    /** 递归解析 sitemap index，对应 Go 的 -r/--recursive。 */
    @Option(names = {"-r", "--recursive"}, description = "递归解析 sitemap index")
    private boolean recursive;

    /** 递归最大深度，对应 Go 的 --max-depth。 */
    @Option(names = {"--max-depth"}, description = "递归最大深度")
    private int maxDepth = 3;

    /** 显示所有发现的页面，对应 Go 的 --show-all。 */
    @Option(names = {"--show-all"}, description = "显示所有发现的页面")
    private boolean showAll;

    /** 并发线程数，对应 Go 的 -t/--threads。 */
    @Option(names = {"-t", "--threads"}, description = "并发线程数")
    private int threads = 10;

    /** 自定义 sitemap 路径（逗号分隔），对应 Go 的 -p/--path。 */
    @Option(names = {"-p", "--path"}, description = "自定义 sitemap 路径 (逗号分隔)")
    private String customPath;

    /** 位置参数：与 Go 一致，首个参数为 "help" 时打印帮助。 */
    @Parameters(arity = "0..*", paramLabel = "ARGS", description = "位置参数（help 显示帮助）")
    private List<String> params;

    @Spec
    private CommandSpec spec;

    @Override
    public Integer call() {
        // 位置参数首个为 "help" 时打印用法（对应 Go 的 args[0] == "help"）
        if (params != null && !params.isEmpty() && "help".equals(params.get(0))) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        if (targetURL == null || targetURL.isEmpty()) {
            Colors.errorPrint("必须指定目标URL (-u/--url)");
            spec.commandLine().usage(System.out);
            return 1;
        }

        // 解析自定义路径（逗号分隔，跳过空项），对应 Go 的 strings.Split + TrimSpace
        List<String> customPaths = new ArrayList<>();
        if (customPath != null && !customPath.isEmpty()) {
            for (String p : customPath.split(",", -1)) {
                p = p.trim();
                if (!p.isEmpty()) {
                    customPaths.add(p);
                }
            }
        }

        SitemapConfig config = new SitemapConfig()
                .targetURL(targetURL)
                .timeout(Duration.ofSeconds(timeout))
                .userAgent(userAgent)
                .outputFile(outputFile == null ? "" : outputFile)
                .recursive(recursive)
                .maxDepth(maxDepth)
                .customPaths(customPaths)
                .showAll(showAll)
                .followRedirect(true)
                .threads(threads);

        SitemapScanner scanner;
        try {
            scanner = new SitemapScanner(config);
        } catch (Exception e) {
            Colors.errorPrint("%v", message(e));
            return 1;
        }

        String err = scanner.start();
        if (err != null) {
            Colors.errorPrint("扫描失败: %v", err);
            return 1;
        }

        if (outputFile != null && !outputFile.isEmpty()) {
            try (BufferedWriter w = Files.newBufferedWriter(Path.of(outputFile),
                    StandardCharsets.UTF_8)) {
                scanner.exportResults(w);
                Colors.successPrint("结果已保存到: %s", outputFile);
            } catch (IOException e) {
                Colors.errorPrint("创建输出文件失败: %v", message(e));
                return 1;
            }
        }
        return 0;
    }

    /** 取异常消息（空消息回退到类名），对应 Go 的 err.Error()。 */
    private static String message(Exception e) {
        String msg = e.getMessage();
        return (msg == null || msg.isEmpty()) ? e.getClass().getSimpleName() : msg;
    }
}

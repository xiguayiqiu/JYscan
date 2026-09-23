package space.jyscan.pocli.commands;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.core.util.Separators;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.JsonUtil;
import space.jyscan.core.util.SystemUtil;
import space.jyscan.modules.waf.WAFDetector;
import space.jyscan.modules.waf.WAFResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;

/**
 * waf 命令，移植自 freeclient/internal/cli/waf.go。
 *
 * <p>参数、提示文案、输出顺序与 Go 版逐行对应；颜色输出统一走
 * {@link Colors} 以支持 --no-color（文本与 Go 的 ANSI 转义之间内容完全一致）。
 */
@Command(
        name = "waf",
        description = "WAF识别工具",
        header = {
                "WAF识别工具 - 用于识别网站使用的Web应用防火墙类型",
                "支持通过被动特征（响应头、证书、响应内容）和主动轻量探测识别常见WAF"
        },
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true
)
public class WafCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Option(names = {"-u", "--url"}, description = "指定目标URL (例如: https://example.com)")
    String url;

    @Option(names = {"-f", "--file"}, description = "指定包含多个目标的文件路径")
    String file;

    @Option(names = {"--concurrency"}, description = "并发数量 (1-100)")
    int concurrency = 20;

    @Option(names = {"--rules"}, description = "自定义WAF规则文件路径")
    String rules;

    @Option(names = {"-o", "--output"}, description = "结果输出文件路径")
    String outputFile;

    @Option(names = {"--format"}, description = "输出格式: txt (文本) 或 json (JSON格式)")
    String outputFormat = "txt";

    @Parameters(arity = "0..*", paramLabel = "ARGS", hidden = true,
            description = "附加参数（首个参数为 help 时显示帮助）")
    List<String> args;

    @Override
    public Integer call() {
        // cobra 的 waf help 等价于 waf --help
        if (args != null && !args.isEmpty() && "help".equals(args.get(0))) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        if ((url == null || url.isEmpty()) && (file == null || file.isEmpty())) {
            Colors.errorPrint("[ERROR] 请指定目标 (-u) 或目标文件 (-f)");
            spec.commandLine().usage(System.out);
            return 1;
        }

        return executeWAFDetection();
    }

    /**
     * 执行WAF检测，对应 Go 的 executeWAFDetection。
     *
     * @return 进程退出码（规则加载/目标文件读取失败时非零）
     */
    private int executeWAFDetection() {
        // 创建WAF检测器
        WAFDetector detector = new WAFDetector();

        // 加载规则文件（rulesPath 为空时使用嵌入规则文件，无需指定路径）
        blue("[INFO] 正在加载WAF规则...");
        try {
            detector.loadRules(rules);
        } catch (IOException e) {
            Colors.errorPrint("[ERROR] 加载规则失败: %v", e);
            return 1;
        }
        Colors.successPrint("[INFO] 规则加载成功");

        List<String> targets = new ArrayList<>();
        if (url != null && !url.isEmpty()) {
            targets.add(url);
        } else if (file != null && !file.isEmpty()) {
            blue("[INFO] 正在读取目标文件: %s", file);
            byte[] content;
            try {
                content = Files.readAllBytes(Path.of(file));
            } catch (IOException e) {
                Colors.errorPrint("[ERROR] 读取目标文件失败: %v", e);
                return 1;
            }
            // 读取每行作为一个目标
            String text = new String(content, StandardCharsets.UTF_8);
            for (String line : text.split("\n")) {
                String target = line.trim();
                if (!target.isEmpty() && !target.startsWith("#")) {
                    targets.add(target);
                }
            }
            Colors.successPrint("[INFO] 共读取到 %d 个目标", targets.size());
        }

        // 设置并发数
        if (concurrency <= 0) {
            concurrency = 20; // 默认并发数
        } else if (concurrency > 100) {
            concurrency = 100; // 最大并发数限制
        }

        blue("[INFO] 开始进行WAF识别检测...");
        blue("[INFO] 并发数: %d", concurrency);

        // 使用DetectTargets进行并发检测
        List<WAFResult> results = detector.detectTargets(targets, concurrency);

        // 打印所有结果
        for (WAFResult result : results) {
            printWAFResult(result);
        }

        // 统计结果
        int totalDetected = 0;
        for (WAFResult result : results) {
            if (result.detected) {
                totalDetected++;
            }
        }

        Colors.successPrint("[INFO] 检测完成: 共检测 %d 个目标，发现 %d 个存在WAF的站点",
                targets.size(), totalDetected);

        // 保存结果到文件
        if (outputFile != null && !outputFile.isEmpty()) {
            blue("[INFO] 正在保存结果到文件: %s", outputFile);
            try {
                saveResultsToFile(results, outputFile, outputFormat);
                Colors.successPrint("[SUCCESS] 结果保存成功");
            } catch (IOException e) {
                Colors.errorPrint("[ERROR] 保存结果失败: %v", e);
            }
        }

        Colors.successPrint("[INFO] WAF识别检测完成");
        return 0;
    }

    /**
     * 打印WAF检测结果，对应 Go 的 printWAFResult。
     * 未检测到WAF时附带失败原因，避免Termux等环境下无法定位问题。
     */
    private static void printWAFResult(WAFResult result) {
        if (result.detected) {
            Colors.successPrint("[+] %s -> 检测到WAF: %s (厂商: %s) 置信度: %d%%",
                    result.target, result.wafName, result.vendor, result.confidence);
        } else {
            blue("[-] %s -> %s", result.target, result.description);
        }

        // 打印失败原因，避免Termux等环境下只看到"探测失败"而无法定位问题
        if (result.errorMessage != null && !result.errorMessage.isEmpty()) {
            Colors.warningPrint("    原因: %s", result.errorMessage);
        }
    }

    /**
     * 保存检测结果到文件，对应 Go 的 saveResultsToFile。
     * 支持 "txt" 与 "json" 两种格式，txt 布局、时间格式与 Go 逐字节一致。
     *
     * @throws IOException 序列化或写入失败（错误信息与 Go 一致）
     */
    private static void saveResultsToFile(List<WAFResult> results, String filePath, String format)
            throws IOException {
        String content;
        String lowerFormat = format == null ? "" : format.toLowerCase(Locale.ROOT);

        // 根据指定格式生成内容
        if ("json".equals(lowerFormat)) {
            // 转换为JSON格式
            try {
                // 与 Go 一致：nil 切片序列化为 null
                content = (results == null || results.isEmpty())
                        ? "null"
                        : JsonUtil.MAPPER.writer(goPrettyPrinter()).writeValueAsString(results);
            } catch (JsonProcessingException e) {
                throw new IOException(Fmt.format("JSON序列化失败: %v", e), e);
            }
        } else if ("txt".equals(lowerFormat) || lowerFormat.isEmpty()) {
            // 文本格式
            StringBuilder builder = new StringBuilder();
            builder.append("=== WAF识别结果报告 ===\n");
            builder.append(Fmt.format("生成时间: %s\n", SystemUtil.getCurrentTime()));
            builder.append(Fmt.format("目标数量: %d\n\n", results == null ? 0 : results.size()));

            if (results != null) {
                for (WAFResult result : results) {
                    builder.append(Fmt.format("目标: %s\n", result.target));
                    if (result.detected) {
                        builder.append("状态: 检测到WAF\n");
                        builder.append(Fmt.format("类型: %s (厂商: %s)\n", result.wafName, result.vendor));
                        builder.append(Fmt.format("置信度: %d%%\n", result.confidence));
                    } else {
                        builder.append(Fmt.format("状态: %s\n", result.description));
                        if (result.errorMessage != null && !result.errorMessage.isEmpty()) {
                            builder.append(Fmt.format("错误: %s\n", result.errorMessage));
                        }
                    }
                    builder.append("--------------------\n");
                }
            }

            content = builder.toString();
        } else {
            throw new IOException(Fmt.format("不支持的输出格式: %s", format));
        }

        // 写入文件（对应 Go 的 os.WriteFile(filePath, ..., 0644)）
        try {
            Files.writeString(Path.of(filePath), content, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IOException(Fmt.format("写入文件失败: %v", e), e);
        }
    }

    /** 与 Go json.MarshalIndent(results, "", "  ") 一致的两空格缩进、":" 后带空格。 */
    private static DefaultPrettyPrinter goPrettyPrinter() {
        return new DefaultPrettyPrinter()
                .withSeparators(Separators.createDefaultInstance()
                        .withObjectFieldValueSeparator(':')
                        .withObjectFieldValueSpacing(Separators.Spacing.AFTER))
                .withObjectIndenter(new DefaultIndenter("  ", "\n"))
                .withArrayIndenter(new DefaultIndenter("  ", "\n"));
    }

    /**
     * 蓝色 [INFO] 行输出，对应 cli/waf.go 中的 {@code fmt.Println("\033[34m...\033[0m")}：
     * 转义之间的文本完全一致，经 {@link Colors} 着色以支持 --no-color。
     */
    private static void blue(String format, Object... args) {
        System.out.println(Colors.info(format, args));
    }
}

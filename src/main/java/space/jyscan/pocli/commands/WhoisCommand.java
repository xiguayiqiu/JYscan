package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import space.jyscan.core.util.Colors;
import space.jyscan.core.util.TextFiles;
import space.jyscan.modules.whois.Whois;
import space.jyscan.modules.whois.WhoisResult;
import space.jyscan.modules.whois.WhoisUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * whois 命令，移植自 freeclient/internal/cli/whois.go。
 *
 * <p>参数与 Go 版一致：--file/-f（文件批量）、--output/-o（结果落盘）、
 * --silent/-q（静默，仅输出关键结果）与位置参数 target。
 * 其中 -q/--silent 在 Go 侧由根命令 persistent flag 继承，本项目根命令
 * （Cli.run）会在原始参数阶段剥离 -q/--silent 并置 Colors.isSilent，
 * 这里保留同名本地选项以兼容直接以 picocli 执行的场景。
 */
@Command(
        name = "whois",
        description = "Whois查询工具",
        header = "Whois查询工具，用于查询域名或IP地址的注册信息，支持单个查询和批量查询。",
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true
)
public class WhoisCommand implements Callable<Integer> {

    /** 从文件中读取目标列表进行批量查询（对应 Go 的 --file/-f）。 */
    @Option(names = {"-f", "--file"}, description = "从文件中读取目标列表进行批量查询")
    private String file;

    /** 将结果输出到指定文件（对应 Go 的 --output/-o）。 */
    @Option(names = {"-o", "--output"}, description = "将结果输出到指定文件")
    private String output;

    /** 静默模式，仅输出关键结果（对应 Go 的 --silent/-q）。 */
    @Option(names = {"-q", "--silent"}, description = "静默模式，仅输出关键结果")
    private boolean silent;

    /** 查询目标（域名或IP地址），对应 cobra 的位置参数。 */
    @Parameters(arity = "0..*", paramLabel = "target", description = "查询目标（域名或IP地址）")
    private List<String> targets;

    /** 当前命令规格，用于复现 cobra 的 cmd.Help()。 */
    @Spec
    private CommandSpec spec;

    @Override
    public Integer call() {
        List<String> queries = new ArrayList<>();

        // 从文件读取目标列表（跳过空行与 # 注释）
        if (file != null && !file.isEmpty()) {
            try {
                // 宽容解码：非 UTF-8 清单文件不再因非法字节报 "读取文件失败"
                for (String line : TextFiles.readLines(Path.of(file))) {
                    String target = line.trim();
                    if (!target.isEmpty() && !target.startsWith("#")) {
                        queries.add(target);
                    }
                }
            } catch (IOException e) {
                Colors.errorPrint("读取文件失败: %v", WhoisUtil.errorText(e));
                return 1;
            }
        } else if (targets != null && !targets.isEmpty()) {
            // 从命令行参数获取目标
            queries.addAll(targets);
        } else {
            Colors.errorPrint("请提供查询目标或使用 -f 参数指定目标文件");
            spec.commandLine().usage(System.out);
            return 1;
        }

        if (queries.isEmpty()) {
            Colors.errorPrint("没有有效的查询目标");
            return 1;
        }

        // 执行Whois查询
        Colors.infoPrint("[JYscan-Whois] 开始查询，共 %d 个目标", queries.size());

        List<WhoisResult> results = Whois.batchWhois(queries);

        // 格式化输出结果
        StringBuilder allOutput = new StringBuilder();
        for (WhoisResult result : results) {
            Colors.infoPrint("[JYscan-Whois] 查询完成: %s", result.query);
            String formatted = Whois.formatResult(result);
            allOutput.append(formatted).append("=".repeat(50)).append("\n\n");
            if (!silent) {
                Colors.infoPrint("%s", formatted);
            }
        }

        // 保存结果到文件
        boolean saved = true;
        if (output != null && !output.isEmpty()) {
            try {
                Files.writeString(Path.of(output), allOutput.toString(), StandardCharsets.UTF_8);
                Colors.successPrint("结果已保存到文件: %s", output);
            } catch (IOException e) {
                saved = false;
                Colors.errorPrint("保存结果到文件失败: %v", WhoisUtil.errorText(e));
            }
        }

        Colors.infoPrint("[JYscan-Whois] 查询完成，共查询 %d 个目标", results.size());
        return saved ? 0 : 1;
    }
}

package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.modules.crunch.CrunchEstimator;
import space.jyscan.modules.crunch.CrunchGenerator;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * crunch 命令，移植自 freeclient/internal/cli/crunch.go。
 *
 * <p>生成密码字典，模仿crunch工具的功能：按 min~max 长度与字符集穷举，
 * 多线程写入输出文件。
 */
@Command(
        name = "crunch",
        description = "计算机根据算法生成的密码字典生成工具",
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true,
        header = {
                "生成密码字典，模仿crunch工具的功能。",
                "",
                "使用示例:",
                "  ./JYscan crunch 4 6 abcdefg -o passwords.txt",
                "  ./JYscan crunch 8 8 0123456789 -o numbers.txt",
                "",
                "参数说明:",
                "  min\t\t密码最小长度",
                "  max\t\t密码最大长度",
                "  chars\t\t包含的字符集",
                "  -o, --output\t输出文件路径"
        }
)
public class CrunchCommand implements Callable<Integer> {

    @Option(names = {"-o", "--output"}, description = "输出文件路径（必须指定）")
    String output;

    @Option(names = {"-t", "--threads"}, defaultValue = "4", description = "使用的线程数量（默认4线程）")
    int threads;

    /**
     * 位置参数 min max charset。picocli 侧放宽为 0..*，由 call() 里的校验
     * 复刻 Go 的 Args 函数（少于 3 个参数要报 Go 的原文错误），第 4 个起的
     * 多余参数与 Go 一样被忽略。
     */
    @Parameters(arity = "0..*", description = "min max charset")
    List<String> args;

    @Spec
    CommandSpec spec;

    @Override
    public Integer call() {
        // 如果请求帮助，直接显示帮助（Go: args[0] == "help" 时 cmd.Help()）
        if (args != null && !args.isEmpty() && "help".equals(args.get(0))) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        // ---- 移植 Go 的 Args 校验函数，错误文案与退出码保持一致 ----

        // 如果少于3个参数
        if (args == null || args.size() < 3) {
            return failValidate("需要至少3个参数：最小长度、最大长度、字符集");
        }

        // 验证最小长度（Go: err != nil || min < 1）
        Integer minOrNull = parseIntOrNull(args.get(0));
        if (minOrNull == null || minOrNull < 1) {
            return failValidate("最小长度必须是大于0的整数");
        }
        int minLen = minOrNull;

        // 验证最大长度（Go: err != nil || max < min）
        Integer maxOrNull = parseIntOrNull(args.get(1));
        if (maxOrNull == null || maxOrNull < minLen) {
            return failValidate("最大长度必须是大于等于最小长度的整数");
        }
        int maxLen = maxOrNull;

        // 验证字符集（Go: len(args[2]) == 0）
        String charset = args.get(2);
        if (charset.isEmpty()) {
            return failValidate("字符集不能为空");
        }

        // 验证必需参数（Go 在 RunE 中用 fmt.Println 打印后 return nil，退出码为 0；
        // 这里与 Go 一样不受静默模式影响，直接输出）
        if (output == null || output.isEmpty()) {
            System.out.print(Fmt.format("错误: 必须指定输出文件路径 (-o, --output)\n"));
            System.out.print(Fmt.format("用法: JYscan crunch min max chars -o 输出文件路径 [选项]\n"));
            return 0;
        }

        // 字符集按 UTF-8 字节处理，与 Go 的 len(charset) 字节语义一致
        byte[] charsetBytes = charset.getBytes(StandardCharsets.UTF_8);
        int charsetLen = charsetBytes.length;

        // 限制线程数最小值为1
        int threadCount = threads < 1 ? 1 : threads;

        // 预估密码数量和文件大小
        long passwordCount = CrunchEstimator.calculatePasswordCount(minLen, maxLen, charsetLen);
        long fileSize = CrunchEstimator.calculateFileSize(passwordCount, minLen, maxLen);

        // 显示预估信息
        Colors.infoPrint("[+] 预估信息:");
        Colors.infoPrint("   - 密码最小长度: %d", minLen);
        Colors.infoPrint("   - 密码最大长度: %d", maxLen);
        Colors.infoPrint("   - 字符集大小: %d", charsetLen);
        Colors.infoPrint("   - 预估密码数量: %d", passwordCount);
        Colors.infoPrint("   - 预估文件大小: %s", CrunchEstimator.formatFileSize(fileSize));
        Colors.infoPrint("   - 使用线程数: %d", threadCount);

        // 确认是否继续
        Colors.infoPrint("\n[*] 开始生成密码字典...");

        Path outputPath = Paths.get(output);

        // 确保输出目录存在（Go: os.MkdirAll(filepath.Dir(path), 0755)）
        Path dir = outputPath.getParent();
        if (dir != null) {
            try {
                Files.createDirectories(dir);
            } catch (IOException e) {
                Colors.errorPrint("创建目录失败: %v", e);
                return 1;
            }
        }

        // 打开输出文件（Go: os.Create，创建或截断）
        OutputStream file;
        try {
            file = Files.newOutputStream(outputPath);
        } catch (IOException e) {
            Colors.errorPrint("创建文件失败: %v", e);
            return 1;
        }

        // 生成密码字典（使用多线程）
        long generatedCount;
        try {
            generatedCount = CrunchGenerator.generatePasswordsWithThreads(
                    file, charsetBytes, minLen, maxLen, threadCount);
        } catch (Exception e) {
            CrunchGenerator.closeQuietly(file);
            Colors.errorPrint("生成密码失败: %v", e);
            return 1;
        }
        CrunchGenerator.closeQuietly(file); // Go: defer file.Close()

        Colors.successPrint("\n[+] 密码字典生成完成！");
        Colors.infoPrint("   - 实际生成密码数量: %d", generatedCount);
        Colors.infoPrint("   - 输出文件路径: %s", output);
        return 0;
    }

    /** 校验失败：打印 Go 的错误原文并返回非零退出码（对应 cobra Args 返回 error）。 */
    private int failValidate(String message) {
        Colors.errorPrint("%s", message);
        return 1;
    }

    /** 等价于 Go 的 strconv.Atoi：解析失败返回 null。 */
    private static Integer parseIntOrNull(String s) {
        try {
            return Integer.valueOf(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}

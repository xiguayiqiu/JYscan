package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

import space.jyscan.core.util.Colors;
import space.jyscan.modules.webshell.PHPOptions;
import space.jyscan.modules.webshell.PhpWebShell;

/**
 * webshell 命令，移植自 freeclient/internal/cli/webshell.go 的 runWebShellGenerator。
 *
 * <p>强制使用无加密设置：EncodeType="none"、ObfuscateLevel=0、NoPassword=true，
 * 用户无法通过参数关闭（Go 端已删除密码/编码/混淆/无密码模式等参数）。
 */
@Command(
        name = "webshell",
        description = "WebShell生成工具",
        header = {
                "生成PHP大马和小马，强制使用无加密版本。",
                "",
                "使用示例:",
                "  ./JYscan webshell -t small -o ./webshell.php",
                "  ./JYscan webshell -t large -o ./large.php"
        },
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true
)
public class WebshellCommand implements Callable<Integer> {

    @Option(names = {"-t", "--type"}, defaultValue = "small",
            description = "WebShell类型: small(小马) 或 large(大马)")
    String type;

    @Option(names = {"-o", "--output"}, defaultValue = "./webshell.php",
            description = "输出文件路径")
    String outputPath;

    @Option(names = {"-w", "--pw"}, defaultValue = "attack",
            description = "密码字段名（仅小马有效）")
    String passwordField;

    /** 位置参数：Go 端扫描所有 args 是否包含 "help"。 */
    @Parameters(arity = "0..*", paramLabel = "args",
            description = "附加参数（help 显示帮助）")
    List<String> extraArgs = new ArrayList<>();

    @Spec
    CommandSpec spec;

    @Override
    public Integer call() {
        // 检查是否包含help参数
        for (String arg : extraArgs) {
            if ("help".equals(arg)) {
                spec.commandLine().usage(System.out);
                return 0;
            }
        }

        // 强制使用无加密设置，忽略用户输入的所有加密相关参数
        PHPOptions options = new PHPOptions();
        options.password = passwordField; // 使用-w参数指定的密码字段
        options.type = type;              // 只保留类型参数
        options.encodeType = "none";      // 强制不使用编码
        options.obfuscateLevel = 0;       // 强制不使用混淆
        options.noPassword = true;        // 强制使用无密码模式

        // 生成webshell内容
        String webshellContent;
        try {
            webshellContent = PhpWebShell.generatePHPWebShell(options);
        } catch (RuntimeException err) {
            Colors.errorPrint("生成WebShell失败: %v", err);
            return 1;
        }

        // 确保输出目录存在（Go: os.MkdirAll(filepath.Dir(outputPath), 0755)）
        Path out = Path.of(outputPath);
        try {
            Path dir = out.getParent();
            if (dir == null) {
                dir = Path.of(".");
            }
            Files.createDirectories(dir);
        } catch (Exception err) {
            Colors.errorPrint("创建目录失败: %v", err);
            return 1;
        }

        // 写入文件（Go: os.WriteFile(outputPath, content, 0644)）
        try {
            Files.write(out, webshellContent.getBytes(StandardCharsets.UTF_8));
            trySetPermission644(out);
        } catch (Exception err) {
            Colors.errorPrint("写入文件失败: %v", err);
            return 1;
        }

        Colors.successPrint("WebShell生成成功！");
        Colors.infoPrint("类型: %s", type);
        Colors.infoPrint("路径: %s", outputPath);
        if ("small".equals(type)) {
            Colors.infoPrint("密码字段: %s", passwordField);
        }
        Colors.infoPrint("编码: none (强制禁用)");
        Colors.infoPrint("混淆级别: 0 (强制禁用)");
        Colors.infoPrint("无密码模式: true (强制启用)");
        return 0;
    }

    /** 写入权限尽量对齐 Go 的 0644（非 POSIX 文件系统上忽略失败）。 */
    private static void trySetPermission644(Path path) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"));
        } catch (UnsupportedOperationException | java.io.IOException | SecurityException ignored) {
            // 保持 Java 默认权限即可
        }
    }
}

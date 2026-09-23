package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

import space.jyscan.core.util.Colors;
import space.jyscan.modules.dirscan.ScanConfig;
import space.jyscan.modules.dirscan.Scanner;

import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * dirscan 命令，移植自 freeclient/internal/cli/dirscan.go。
 *
 * <p>参数解析、必需参数校验、parseExtensions / parseStatusCodes 均按 Go 版逐行移植，
 * 扫描逻辑见 {@link space.jyscan.modules.dirscan.Scanner}。
 */
@Command(
        name = "dirscan",
        description = "网站目录扫描工具",
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true,
        header = {
                "",
                "网站目录扫描工具 - 基于dirsearch的目录爆破功能",
                "",
                "支持功能:",
                "- 多线程目录扫描",
                "- 自定义字典文件",
                "- 扩展名扫描",
                "- 状态码过滤",
                "- 代理支持",
                "- 结果导出",
                "",
                "使用示例:",
                "  ./JYscan dirscan -u http://example.com                    # 基本扫描",
                "  ./JYscan dirscan -u https://example.com -w wordlist.txt    # 自定义字典",
                "  ./JYscan dirscan -u http://example.com -t 50 -e php,html   # 多线程+扩展名",
                "  ./JYscan dirscan -u http://example.com --proxy http://127.0.0.1:8080  # 代理扫描",
                "  ./JYscan dirscan -u http://example.com -o results.txt      # 保存结果",
                "",
                "警告: 仅用于授权测试和安全评估，严禁未授权使用！"
        }
)
public class DirscanCommand implements Callable<Integer> {

    // 必需参数
    @Option(names = {"-u", "--url"}, description = "目标URL (必需)")
    String url;

    // 字典相关
    @Option(names = {"-w", "--wordlist"}, description = "字典文件路径 (默认使用内置字典)")
    String wordlist;

    // 扫描配置
    @Option(names = {"-t", "--threads"}, description = "并发线程数")
    int threads = 20;

    @Option(names = {"--timeout"}, description = "请求超时时间(秒)")
    int timeout = 10;

    @Option(names = {"-e", "--extensions"}, description = "扩展名扫描 (逗号分隔，如: php,html,txt)")
    String extensions;

    @Option(names = {"--user-agent"}, description = "自定义User-Agent")
    String userAgent;

    @Option(names = {"--proxy"}, description = "代理服务器 (支持HTTP/SOCKS)")
    String proxy;

    // 输出配置
    @Option(names = {"-o", "--output"}, description = "结果输出文件")
    String outputFile;

    @Option(names = {"--show-all"}, description = "显示所有响应 (包括错误)")
    boolean showAll;

    @Option(names = {"--status-codes"}, description = "过滤状态码 (逗号分隔，如: 200,301,403)")
    String statusCodes;

    // 位置参数：与Go版一致，第一个参数为 "help" 时显示帮助
    @Parameters(arity = "0..*", paramLabel = "ARGS", description = "位置参数（help 显示帮助）")
    List<String> params;

    @Spec
    CommandSpec spec;

    @Override
    public Integer call() {
        // 检查是否请求帮助
        if (params != null && !params.isEmpty() && "help".equals(params.get(0))) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        // 验证必需参数
        if (url == null || url.isEmpty()) {
            Colors.errorPrint("必须指定目标URL (-u/--url)");
            spec.commandLine().usage(System.out);
            return 1;
        }

        // 处理字典选择
        if (wordlist == null || wordlist.isEmpty()) {
            Colors.errorPrint("必须指定字典文件");
            Colors.infoPrint("请使用 -w/--wordlist 参数指定字典文件");
            Colors.infoPrint("例如: -w dirmap/dicc.txt");
            return 1;
        }

        // 验证外部字典文件存在
        Path wordlistPath = null;
        try {
            wordlistPath = Path.of(wordlist);
        } catch (InvalidPathException ignored) {
            // 非法路径按不存在处理
        }
        if (wordlistPath == null || Files.notExists(wordlistPath)) {
            Colors.errorPrint("字典文件不存在: %s", wordlist);
            Colors.infoPrint("请使用 -w/--wordlist 参数指定有效的字典文件");
            return 1;
        }

        // 解析扩展名
        List<String> extList = null;
        if (extensions != null && !extensions.isEmpty()) {
            extList = parseExtensions(extensions);
        }

        // 解析状态码过滤
        List<Integer> statusCodeList = parseStatusCodes(statusCodes);

        // 创建扫描配置
        ScanConfig config = new ScanConfig();
        config.url = url;
        config.wordlist = wordlist;
        config.threads = threads;
        config.timeout = Duration.ofSeconds(timeout);
        config.userAgent = userAgent == null ? "" : userAgent;
        config.extensions = extList;
        config.outputFile = outputFile == null ? "" : outputFile;
        config.showAll = showAll;
        config.statusCodeFilter = statusCodeList;
        config.proxy = proxy == null ? "" : proxy;
        config.followRedirects = true;

        // 创建扫描器
        Scanner scanner;
        try {
            scanner = new Scanner(config);
        } catch (Exception e) {
            Colors.errorPrint("创建扫描器失败: %v", e);
            return 1;
        }

        // 执行扫描
        try {
            scanner.start();
        } catch (Exception e) {
            Colors.errorPrint("扫描失败: %v", e);
            return 1;
        }
        return 0;
    }

    // =====================================================================
    // 参数解析辅助函数（与 cli/dirscan.go 逐行对应）
    // =====================================================================

    /** parseExtensions 解析扩展名字符串 */
    static List<String> parseExtensions(String extStr) {
        if (extStr == null || extStr.isEmpty()) {
            return null;
        }

        // 对应 Go 的 strings.Split(extStr, ",")：保留空片段，随后由 TrimSpace+非空判断过滤
        String[] exts = extStr.split(",", -1);
        List<String> result = new ArrayList<>();

        for (String ext : exts) {
            ext = ext.trim();
            if (!ext.isEmpty()) {
                result.add(ext);
            }
        }

        return result;
    }

    /** parseStatusCodes 解析状态码字符串 */
    static List<Integer> parseStatusCodes(String statusStr) {
        if (statusStr == null || statusStr.isEmpty()) {
            return null;
        }

        String[] codes = statusStr.split(",", -1);
        List<Integer> result = new ArrayList<>();

        for (String codeStr : codes) {
            codeStr = codeStr.trim();
            if (codeStr.isEmpty()) {
                continue;
            }

            int code;
            try {
                code = Integer.parseInt(codeStr);
            } catch (NumberFormatException e) {
                Colors.warningPrint("无效的状态码: %s", codeStr);
                continue;
            }

            result.add(code);
        }

        return result;
    }
}

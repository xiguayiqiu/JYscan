package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;
import space.jyscan.core.util.Colors;
import space.jyscan.modules.cupp.Cupp;
import space.jyscan.modules.cupp.CuppConfig;
import space.jyscan.modules.cupp.Generator;
import space.jyscan.modules.cupp.Profile;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * cupp 命令，移植自 freeclient/internal/cli/cupp.go。
 *
 * <p>根据社会工程学信息生成密码字典；控制流与 cuppCmd.Run 一致：
 * 无参数显示帮助 -> -w 改进字典 -> -i 交互式 -> 快速模式（需要目标名字）。
 */
@Command(
        name = "cupp",
        description = "根据社会工程学信息生成密码-社会工程学密码生成器",
        header = {
                "CUPP - Common User Passwords Profiler",
                "根据目标用户信息生成密码字典，用于密码安全测试",
                "警告：仅用于授权测试，严禁未授权使用！",
                "",
                "用法示例:",
                "  ./JYscan cupp john                    # 基于名字生成密码",
                "  ./JYscan cupp john --leet             # 启用Leet模式",
                "  ./JYscan cupp john -n -s              # 添加数字和特殊字符",
                "  ./JYscan cupp -i                      # 交互式模式",
                "  ./JYscan cupp -w wordlist.txt         # 改进现有字典",
                "  ./JYscan cupp -w wordlist.txt --concat --leet  # 改进字典并添加选项"
        },
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true
)
public class CuppCommand implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    @Option(names = {"-i", "--interactive"}, description = "交互式输入用户信息")
    boolean interactive;

    @Option(names = {"-w", "--improve"}, paramLabel = "<file>", description = "改进现有字典文件")
    String improve = "";

    @Option(names = {"-c", "--concat"}, description = "改进字典时连接词汇")
    boolean concat;

    @Option(names = {"-l", "--leet"}, description = "启用Leet模式 (e=3, a=4, etc)")
    boolean leet;

    @Option(names = {"-n", "--numbers"}, description = "添加随机数字")
    boolean numbers;

    @Option(names = {"-s", "--special"}, description = "添加特殊字符")
    boolean special;

    @Option(names = {"-o", "--output"}, paramLabel = "<path>", description = "输出文件路径")
    String output = "";

    @Parameters(arity = "0..*", description = "目标名字")
    List<String> args = new ArrayList<>();

    @Override
    public Integer call() {
        List<String> pos = args == null ? List.of() : args;

        // 无参数时显示帮助信息
        if (pos.isEmpty() && !interactive && improve.isEmpty()) {
            showHelp();
            return 0;
        }

        // 检查改进字典模式
        if (!improve.isEmpty()) {
            runCuppImprove(improve);
            return 0;
        }

        // 检查交互式模式
        if (interactive) {
            runCuppInteractive();
            return 0;
        }

        // 快速模式需要目标名字
        if (pos.isEmpty()) {
            showHelp();
            return 0;
        }

        String targetName = pos.get(0);

        // 字面量 help -> 显示帮助
        if ("help".equals(targetName)) {
            showHelp();
            return 0;
        }

        Colors.logInfo("开始执行CUPP密码分析，目标名字: %s", targetName);

        runCuppQuick(targetName, leet, numbers, special, output);

        Colors.logInfo("CUPP密码分析完成");
        return 0;
    }

    private void showHelp() {
        spec.commandLine().usage(System.out);
    }

    /** 对应 runCuppInteractive。 */
    private void runCuppInteractive() {
        CuppConfig.readConfig();

        Profile profile = new Profile();
        Cupp cuppInst = new Cupp();
        if (!cuppInst.interactive(profile)) {
            Colors.warningPrint("[-] 输入已终止，取消生成字典");
            return;
        }

        String outputFile = profile.name + ".txt";
        Generator.generateWordlist(profile, outputFile);
    }

    /** 对应 runCuppQuick。 */
    private void runCuppQuick(String name, boolean leet, boolean numbers, boolean special, String output) {
        CuppConfig.readConfig();

        Profile profile = new Profile();
        profile.name = name;
        profile.surname = "";
        profile.nick = "";
        profile.birthdate = "";
        profile.wife = "";
        profile.wifen = "";
        profile.wifeb = "";
        profile.kid = "";
        profile.kidn = "";
        profile.kidb = "";
        profile.pet = "";
        profile.company = "";
        profile.words = new ArrayList<>();

        if (leet) {
            profile.leetmode = "y";
        } else {
            profile.leetmode = "n";
        }

        if (numbers) {
            profile.randnum = "y";
        } else {
            profile.randnum = "n";
        }

        if (special) {
            profile.spechars1 = "y";
        } else {
            profile.spechars1 = "n";
        }

        String out = output;
        if (out == null || out.isEmpty()) {
            out = name + ".txt";
        }

        Generator.generateWordlist(profile, out);
    }

    /** 对应 runCuppImprove。 */
    private void runCuppImprove(String filename) {
        CuppConfig.readConfig();

        if (!Files.exists(Paths.get(filename))) {
            Colors.errorPrint("Error: 文件 %s 不存在", filename);
            return;
        }

        Generator.improveDictionary(filename, concat, leet, numbers, special);
    }
}

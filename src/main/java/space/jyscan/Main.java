package space.jyscan;

import space.jyscan.core.config.AppConfig;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import space.jyscan.core.util.Colors;

import space.jyscan.pocli.Cli;

/**
 * 程序入口，对应 Go 的 freeclient/main.go。
 */
public class Main {

    public static void main(String[] args) {
        setupEncoding();

        // 配置初始化失败只告警，不阻断（与 Go 一致）
        try {
            AppConfig.initConfig();
        } catch (Throwable t) {
            Colors.logWarning("配置加载失败，使用默认配置: %v", t.getMessage());
        }

        int code = Cli.run(args);
        if (code != 0) {
            System.exit(code);
        }
    }

    /** 平台編碼初始化：
     *  Windows 下強制設置終端活動代碼頁為 UTF-8，并将 System.out/err
     *  封装为 UTF-8 自动刷新的 PrintStream；非 Windows 保持 UTF-8。
     */
    private static void setupEncoding() {
        if (space.jyscan.core.util.SystemUtil.isWindows()) {
            setConsoleCodePage(65001);
            try {
                // 新的 Reader/Writer 默认使用 UTF-8，提高一致性
                System.setProperty("file.encoding", "UTF-8");

                // 封装 System.out/err，自动刷新避免遗漏输出
                System.setOut(new PrintStream(new BufferedOutputStream(System.out), true, "UTF-8"));
                System.setErr(new PrintStream(new BufferedOutputStream(System.err), true, "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                System.err.println("編碼初始化失敗: " + e.getMessage());
            }
        } else {
            System.setProperty("file.encoding", "UTF-8");
        }
    }

    /** 调用 chcp 设置控制台活动代码页，若已为目标代码页则跳过。 */
    private static void setConsoleCodePage(int codePage) {
        try {
            // 先读取当前活动代码页
            ProcessBuilder checkPb = new ProcessBuilder("cmd", "/c", "chcp");
            Process checkP = checkPb.start();
            int cur = readCodePage(checkP);
            if (cur == codePage) {
                // 当前已是目标代码页，无需重复设置
                return;
            }
            // 仅在目标代码页未激活时设置，并抑制设置命令的输出
            ProcessBuilder setPb = new ProcessBuilder("cmd", "/c", "chcp", String.valueOf(codePage), ">", "NUL");
            Process setP = setPb.start();
            setP.waitFor();
        } catch (Exception e) {
            // 若 chcp 失败，不中断启动
        }
    }

    /** 从 chcp 输出中读取活动代码页数字（中英文输出均支持，例如"Active code page: 65001"）。 */
    private static int readCodePage(Process process) throws Exception {
        int cp = -1;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), "GBK"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line == null || line.isEmpty()) {
                    continue;
                }
                // 提取最后一个整数作为代码页
                String lastToken = line.trim().split("\\s+")[line.trim().split("\\s+").length - 1];
                try {
                    cp = Integer.parseInt(lastToken);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        process.waitFor();
        return cp;
    }
}

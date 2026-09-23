package space.jyscan.modules.cupp;

import space.jyscan.core.util.Colors;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * CUPP 交互式输入，移植自 freeclient/internal/cupp/interactive.go。
 *
 * <p>用 {@link BufferedReader} 读取标准输入；EOF（readLine 返回 null）视为读到空串，
 * 但名字必填处遇到 EOF 会立即中止，保证永不死循环挂起。
 */
public class Cupp {

    private final BufferedReader reader =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    /** 是否已经读到输入流末尾。 */
    private boolean eof = false;

    /** 读取一行；EOF/异常按空串处理并置 eof 标记（对应 Go 忽略 ReadString 的 error）。 */
    private String readLine() {
        try {
            String line = reader.readLine();
            if (line == null) {
                eof = true;
                return "";
            }
            return line;
        } catch (Exception e) {
            eof = true;
            return "";
        }
    }

    /** 提示符无换行输出（对应 fmt.Print）。 */
    private static void prompt(String text) {
        Colors.colorPrint("", text);
    }

    /** 对应 interactive.go 的 Interactive；返回 false 表示名字输入因 EOF 中止。 */
    public boolean interactive(Profile profile) {
        Colors.infoPrint("\r\n[+] 输入目标信息以生成密码字典");
        Colors.infoPrint("[+] 如果不知道某些信息，直接按回车跳过！ ;)\r\n");

        prompt("> 名字: ");
        profile.name = lower(readLine().trim());
        while (profile.name.isEmpty()) {
            if (eof) {
                // EOF 时无法得到名字：中止，避免死循环（Go 版此处会死循环）
                return false;
            }
            Colors.warningPrint("\r\n[-] 至少需要输入一个名字！");
            prompt("> 名字: ");
            profile.name = lower(readLine().trim());
        }

        prompt("> 姓氏: ");
        profile.surname = lower(readLine().trim());

        prompt("> 昵称: ");
        profile.nick = lower(readLine().trim());

        prompt("> 出生日期 (DDMMYYYY): ");
        profile.birthdate = readLine().trim();
        while (!profile.birthdate.isEmpty() && Generator.len(profile.birthdate) != 8) {
            Colors.warningPrint("\r\n[-] 请输入8位数字表示生日！");
            prompt("> 出生日期 (DDMMYYYY): ");
            profile.birthdate = readLine().trim();
        }

        Colors.infoPrint("\r\n");

        prompt("> 伴侣名字: ");
        profile.wife = lower(readLine().trim());

        prompt("> 伴侣昵称: ");
        profile.wifen = lower(readLine().trim());

        prompt("> 伴侣生日 (DDMMYYYY): ");
        profile.wifeb = readLine().trim();
        while (!profile.wifeb.isEmpty() && Generator.len(profile.wifeb) != 8) {
            Colors.warningPrint("\r\n[-] 请输入8位数字表示生日！");
            prompt("> 伴侣生日 (DDMMYYYY): ");
            profile.wifeb = readLine().trim();
        }

        Colors.infoPrint("\r\n");

        prompt("> 孩子名字: ");
        profile.kid = lower(readLine().trim());

        prompt("> 孩子昵称: ");
        profile.kidn = lower(readLine().trim());

        prompt("> 孩子生日 (DDMMYYYY): ");
        profile.kidb = readLine().trim();
        while (!profile.kidb.isEmpty() && Generator.len(profile.kidb) != 8) {
            Colors.warningPrint("\r\n[-] 请输入8位数字表示生日！");
            prompt("> 孩子生日 (DDMMYYYY): ");
            profile.kidb = readLine().trim();
        }

        Colors.infoPrint("\r\n");

        prompt("> 宠物名字: ");
        profile.pet = lower(readLine().trim());

        prompt("> 公司名称: ");
        profile.company = lower(readLine().trim());

        Colors.infoPrint("\r\n");

        prompt("> 是否要添加一些关于目标的关键词? Y/[N]: ");
        String words1 = lower(readLine().trim());
        String words2 = "";
        if ("y".equals(words1)) {
            prompt("> 请输入关键词，用逗号分隔 [例如: hacker,juice,black]: ");
            words2 = readLine().replace(" ", "");
        }
        profile.words = splitComma(words2);

        prompt("> 是否要在词汇末尾添加特殊字符? Y/[N]: ");
        profile.spechars1 = lower(readLine().trim());

        prompt("> 是否要在词汇末尾添加随机数字? Y/[N]: ");
        profile.randnum = lower(readLine().trim());

        prompt("> 是否要使用Leet模式? (即 leet = 1337) Y/[N]: ");
        profile.leetmode = lower(readLine().trim());

        return true;
    }

    /** 字典下载菜单（interactive.go 的 DownloadWordlist，CLI 暂无入口，保留以对齐源码）。 */
    public void downloadWordlist() {
        Colors.infoPrint("\r\n选择要下载的部分:\r\n");

        Colors.infoPrint("     1   Moby            14      french          27      places");
        Colors.infoPrint("     2   afrikaans       15      german          28      polish");
        Colors.infoPrint("     3   american        16      hindi           29      random");
        Colors.infoPrint("     4   aussie          17      hungarian       30      religion");
        Colors.infoPrint("     5   chinese         18      italian         31      russian");
        Colors.infoPrint("     6   computer        19      japanese        32      science");
        Colors.infoPrint("     7   croatian        20      latin           33      spanish");
        Colors.infoPrint("     8   czech           21      literature      34      swahili");
        Colors.infoPrint("     9   danish          22      movieTV         35      swedish");
        Colors.infoPrint("    10   databases       23      music           36      turkish");
        Colors.infoPrint("    11   dictionaries    24      names           37      yiddish");
        Colors.infoPrint("    12   dutch           25      net             38      exit program");
        Colors.infoPrint("    13   finnish         26      norwegian       \r\n");

        Colors.infoPrint("\r\n文件将从 %s 仓库下载", CuppConfig.CONFIG.dictUrl);
        Colors.infoPrint("提示: 下载字典后，可以使用 -w 选项来改进它\r\n");

        prompt("> 输入数字: ");
        readLine().trim();

        Colors.warningPrint("\r\n[-] 字典下载功能需要实现HTTP下载支持");
        Colors.warningPrint("[-] 请手动下载或使用其他工具");
    }

    /** 对应 Go 的 strings.ToLower（Locale.ROOT 避免土耳其语 i 特例）。 */
    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    /** 对应 Go 的 strings.Split(s, ",")：空串也得到 [""]。 */
    private static List<String> splitComma(String s) {
        List<String> result = new ArrayList<>();
        int start = 0;
        while (true) {
            int idx = s.indexOf(',', start);
            if (idx < 0) {
                result.add(s.substring(start));
                return result;
            }
            result.add(s.substring(start, idx));
            start = idx + 1;
        }
    }
}

package space.jyscan.modules.cupp;

import space.jyscan.core.util.Colors;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 字典生成器，移植自 freeclient/internal/cupp/generator.go。
 *
 * <p>生成顺序、profile 列表的拼接顺序与 Go 版完全一致（本功能的输出即产品特性）。
 */
public final class Generator {

    private Generator() {
    }

    // =====================================================================
    // 基础组合函数
    // =====================================================================

    /** 对应 Go 的 Concats：为每个词拼接 [start, stop) 的数字。 */
    public static List<String> concats(List<String> seq, int start, int stop) {
        List<String> result = new ArrayList<>();
        for (String mystr : seq) {
            for (int num = start; num < stop; num++) {
                result.add(mystr + space.jyscan.core.util.Fmt.format("%d", num));
            }
        }
        return result;
    }

    /** 对应 Go 的 Komb：seq × start 用 special 连接。 */
    public static List<String> komb(List<String> seq, List<String> start, String special) {
        List<String> result = new ArrayList<>();
        for (String mystr : seq) {
            for (String mystr1 : start) {
                result.add(mystr + special + mystr1);
            }
        }
        return result;
    }

    /** 对应 Go 的 KombWithSpecial：为每个词追加所有特殊字符组合。 */
    public static List<String> kombWithSpecial(List<String> seq, List<String> special) {
        List<String> result = new ArrayList<>();
        for (String mystr : seq) {
            for (String spec : special) {
                result.add(mystr + spec);
            }
        }
        return result;
    }

    /** 对应 Go 的 RemoveDuplicates：保序去重。 */
    public static List<String> removeDuplicates(List<String> items) {
        Set<String> seen = new HashSet<>();
        List<String> result = new ArrayList<>();
        for (String item : items) {
            if (seen.add(item)) {
                result.add(item);
            }
        }
        return result;
    }

    /** 对应 Go 的 MakeLeet：按 CONFIG.LeetMap 逐项替换（Go map 顺序无关，结果一致）。 */
    public static String makeLeet(String x) {
        for (Map.Entry<String, String> e : CuppConfig.CONFIG.leetMap.entrySet()) {
            x = x.replace(e.getKey(), e.getValue());
        }
        return x;
    }

    /** 对应 Go 的 PrintToFile：排序后逐行写入并打印统计。 */
    public static void printToFile(String filename, List<String> uniqueListFinished) {
        List<String> sorted = new ArrayList<>(uniqueListFinished);
        Collections.sort(sorted); // 对应 Go 的 sort.Strings

        try {
            StringBuilder sb = new StringBuilder();
            for (String line : sorted) {
                sb.append(line).append('\n');
            }
            Files.write(Paths.get(filename), sb.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            Colors.errorPrint("[ERROR] 无法创建文件 %s: %v", filename, e);
            return;
        }

        // 与 Go 版一致：内嵌 ANSI 红色序列（Go: internal/cupp/generator.go:74 用字面量
        // \033[1;31m，fmt.Printf 不查 UseColor，故 Go 在 --no-color 下同样泄漏这 4 个 ESC）。
        // 这里按 useColor 分叉：开启时与 Go 输出逐字节相同，关闭时不产生任何 ANSI。
        String red = Colors.useColor ? "\u001b[1;31m" : "";
        String off = Colors.useColor ? "\u001b[1;m" : "";
        Colors.infoPrint("[+] 字典已保存至 " + red + "%s" + off + ", 共 " + red + "%d" + off + " 个密码",
                filename, sorted.size());
    }

    // =====================================================================
    // 核心生成
    // =====================================================================

    /** 对应 Go 的 GenerateWordlistFromProfile：基于画像生成完整字典。 */
    public static List<String> generateWordlistFromProfile(Profile profile) {
        List<String> chars = CuppConfig.CONFIG.chars;
        List<String> years = CuppConfig.CONFIG.years;
        int numfrom = CuppConfig.CONFIG.numFrom;
        int numto = CuppConfig.CONFIG.numTo;

        profile.spechars = new ArrayList<>();

        if ("y".equals(profile.spechars1)) {
            // 特殊字符 1/2/3 位的全组合
            for (String spec1 : chars) {
                profile.spechars.add(spec1);
                for (String spec2 : chars) {
                    profile.spechars.add(spec1 + spec2);
                    for (String spec3 : chars) {
                        profile.spechars.add(spec1 + spec2 + spec3);
                    }
                }
            }
        }

        // ---- 生日拆分（DDMMYYYY 的各种切片，与 Go 的字节切片一一对应） ----
        String birthdate = nvl(profile.birthdate);
        String birthdateYy = "";
        String birthdateYyy = "";
        String birthdateYyyy = "";
        String birthdateXd = "";
        String birthdateXm = "";
        String birthdateDd = "";
        String birthdateMm = "";

        if (len(birthdate) >= 2) {
            birthdateYy = birthdate.substring(birthdate.length() - 2);
        }
        if (len(birthdate) >= 3) {
            birthdateYyy = birthdate.substring(birthdate.length() - 3);
        }
        if (len(birthdate) >= 4) {
            birthdateYyyy = birthdate.substring(birthdate.length() - 4);
        }
        if (len(birthdate) >= 2) {
            birthdateDd = birthdate.substring(0, 2);
        }
        if (len(birthdate) >= 4) {
            birthdateMm = birthdate.substring(2, 4);
        }
        if (len(birthdate) >= 2) {
            birthdateXd = birthdate.substring(1, 2);
        }
        if (len(birthdate) >= 4) {
            birthdateXm = birthdate.substring(3, 4);
        }

        String wifeb = nvl(profile.wifeb);
        String wifebYy = "";
        String wifebYyy = "";
        String wifebYyyy = "";
        String wifebXd = "";
        String wifebXm = "";
        String wifebDd = "";
        String wifebMm = "";

        if (len(wifeb) >= 2) {
            wifebYy = wifeb.substring(wifeb.length() - 2);
        }
        if (len(wifeb) >= 3) {
            wifebYyy = wifeb.substring(wifeb.length() - 3);
        }
        if (len(wifeb) >= 4) {
            wifebYyyy = wifeb.substring(wifeb.length() - 4);
        }
        if (len(wifeb) >= 2) {
            wifebDd = wifeb.substring(0, 2);
        }
        if (len(wifeb) >= 4) {
            wifebMm = wifeb.substring(2, 4);
        }
        if (len(wifeb) >= 2) {
            wifebXd = wifeb.substring(1, 2);
        }
        if (len(wifeb) >= 4) {
            wifebXm = wifeb.substring(3, 4);
        }

        String kidb = nvl(profile.kidb);
        String kidbYy = "";
        String kidbYyy = "";
        String kidbYyyy = "";
        String kidbXd = "";
        String kidbXm = "";
        String kidbDd = "";
        String kidbMm = "";

        if (len(kidb) >= 2) {
            kidbYy = kidb.substring(kidb.length() - 2);
        }
        if (len(kidb) >= 3) {
            kidbYyy = kidb.substring(kidb.length() - 3);
        }
        if (len(kidb) >= 4) {
            kidbYyyy = kidb.substring(kidb.length() - 4);
        }
        if (len(kidb) >= 2) {
            kidbDd = kidb.substring(0, 2);
        }
        if (len(kidb) >= 4) {
            kidbMm = kidb.substring(2, 4);
        }
        if (len(kidb) >= 2) {
            kidbXd = kidb.substring(1, 2);
        }
        if (len(kidb) >= 4) {
            kidbXm = kidb.substring(3, 4);
        }

        // ---- 首字母大写（对应 Go 的 strings.Title） ----
        String nameup = title(nvl(profile.name));
        String surnameup = title(nvl(profile.surname));
        String nickup = title(nvl(profile.nick));
        String wifeup = title(nvl(profile.wife));
        String wifenup = title(nvl(profile.wifen));
        String kidup = title(nvl(profile.kid));
        String kidnup = title(nvl(profile.kidn));
        String petup = title(nvl(profile.pet));
        String companyup = title(nvl(profile.company));

        List<String> wordsup = new ArrayList<>();
        for (String w : profile.words) {
            wordsup.add(title(nvl(w)));
        }

        // word := append(profile.Words, wordsup...) —— 原词 + 大写词
        List<String> word = new ArrayList<>(profile.words);
        word.addAll(wordsup);

        // ---- 反转字符串 ----
        String revName = reverseString(nvl(profile.name));
        String revNameup = reverseString(nameup);
        String revNick = reverseString(nvl(profile.nick));
        String revNickup = reverseString(nickup);
        String revWife = reverseString(nvl(profile.wife));
        String revWifeup = reverseString(wifeup);
        String revKid = reverseString(nvl(profile.kid));
        String revKidup = reverseString(kidup);

        List<String> reverse = new ArrayList<>(Arrays.asList(
                revName, revNameup, revNick, revNickup, revWife, revWifeup, revKid, revKidup));
        List<String> revN = new ArrayList<>(Arrays.asList(revName, revNameup, revNick, revNickup));
        List<String> revW = new ArrayList<>(Arrays.asList(revWife, revWifeup));
        List<String> revK = new ArrayList<>(Arrays.asList(revKid, revKidup));

        List<String> bds = new ArrayList<>(Arrays.asList(
                birthdateYy, birthdateYyy, birthdateYyyy, birthdateXd, birthdateXm, birthdateDd, birthdateMm));
        List<String> bdss = dateCombos(bds);

        List<String> wbds = new ArrayList<>(Arrays.asList(
                wifebYy, wifebYyy, wifebYyyy, wifebXd, wifebXm, wifebDd, wifebMm));
        List<String> wbdss = dateCombos(wbds);

        List<String> kbds = new ArrayList<>(Arrays.asList(
                kidbYy, kidbYyy, kidbYyyy, kidbXd, kidbXm, kidbDd, kidbMm));
        List<String> kbdss = dateCombos(kbds);

        List<String> kombinaac = new ArrayList<>(Arrays.asList(
                nvl(profile.pet), petup, nvl(profile.company), companyup));

        List<String> kombina = new ArrayList<>(Arrays.asList(
                nvl(profile.name), nvl(profile.surname), nvl(profile.nick),
                nameup, surnameup, nickup));

        List<String> kombinaw = new ArrayList<>(Arrays.asList(
                nvl(profile.wife), nvl(profile.wifen), wifeup, wifenup,
                nvl(profile.surname), surnameup));

        List<String> kombinak = new ArrayList<>(Arrays.asList(
                nvl(profile.kid), nvl(profile.kidn), kidup, kidnup,
                nvl(profile.surname), surnameup));

        List<String> kombinaa = nameCombos(kombina);
        List<String> kombinaaw = nameCombos(kombinaw);
        List<String> kombinaak = nameCombos(kombinak);

        // ---- 各组两两/三三组合 ----
        Map<Integer, List<String>> kombi = new HashMap<>();
        kombi.put(1, concat(komb(kombinaa, bdss, ""), komb(kombinaa, bdss, "_")));
        kombi.put(2, concat(komb(kombinaaw, wbdss, ""), komb(kombinaaw, wbdss, "_")));
        kombi.put(3, concat(komb(kombinaak, kbdss, ""), komb(kombinaak, kbdss, "_")));
        kombi.put(4, concat(komb(kombinaa, years, ""), komb(kombinaa, years, "_")));
        kombi.put(5, concat(komb(kombinaac, years, ""), komb(kombinaac, years, "_")));
        kombi.put(6, concat(komb(kombinaaw, years, ""), komb(kombinaaw, years, "_")));
        kombi.put(7, concat(komb(kombinak, years, ""), komb(kombinak, years, "_")));
        kombi.put(8, concat(komb(word, bdss, ""), komb(word, bdss, "_")));
        kombi.put(9, concat(komb(word, wbdss, ""), komb(word, wbdss, "_")));
        kombi.put(10, concat(komb(word, kbdss, ""), komb(word, kbdss, "_")));
        kombi.put(11, concat(komb(word, years, ""), komb(word, years, "_")));
        kombi.put(12, new ArrayList<>());
        kombi.put(13, new ArrayList<>());
        kombi.put(14, new ArrayList<>());
        kombi.put(15, new ArrayList<>());
        kombi.put(16, new ArrayList<>());
        kombi.put(21, new ArrayList<>());

        if ("y".equals(profile.randnum)) {
            kombi.put(12, concats(word, numfrom, numto));
            kombi.put(13, concats(kombinaa, numfrom, numto));
            kombi.put(14, concats(kombinaac, numfrom, numto));
            kombi.put(15, concats(kombinaaw, numfrom, numto));
            kombi.put(16, concats(kombinak, numfrom, numto));
            kombi.put(21, concats(reverse, numfrom, numto));
        }

        kombi.put(17, concat(komb(reverse, years, ""), komb(reverse, years, "_")));
        kombi.put(18, concat(komb(revW, wbdss, ""), komb(revW, wbdss, "_")));
        kombi.put(19, concat(komb(revK, kbdss, ""), komb(revK, kbdss, "_")));
        kombi.put(20, concat(komb(revN, bdss, ""), komb(revN, bdss, "_")));

        List<String> komb001 = new ArrayList<>();
        List<String> komb002 = new ArrayList<>();
        List<String> komb003 = new ArrayList<>();
        List<String> komb004 = new ArrayList<>();
        List<String> komb005 = new ArrayList<>();
        List<String> komb006 = new ArrayList<>();

        if (!profile.spechars.isEmpty()) {
            komb001 = kombWithSpecial(kombinaa, profile.spechars);
            komb002 = kombWithSpecial(kombinaac, profile.spechars);
            komb003 = kombWithSpecial(kombinaaw, profile.spechars);
            komb004 = kombWithSpecial(kombinak, profile.spechars);
            komb005 = kombWithSpecial(word, profile.spechars);
            komb006 = kombWithSpecial(reverse, profile.spechars);
        }

        Map<Integer, List<String>> kombUnique = new HashMap<>();
        for (int i = 1; i <= 21; i++) {
            kombUnique.put(i, removeDuplicates(kombi.get(i)));
        }

        List<String> kombUnique01 = removeDuplicates(kombinaa);
        List<String> kombUnique02 = removeDuplicates(kombinaac);
        List<String> kombUnique03 = removeDuplicates(kombinaaw);
        List<String> kombUnique04 = removeDuplicates(kombinak);
        List<String> kombUnique05 = removeDuplicates(word);
        List<String> kombUnique07 = removeDuplicates(komb001);
        List<String> kombUnique08 = removeDuplicates(komb002);
        List<String> kombUnique09 = removeDuplicates(komb003);
        List<String> kombUnique10 = removeDuplicates(komb004);
        List<String> kombUnique11 = removeDuplicates(komb005);
        List<String> kombUnique012 = removeDuplicates(komb006);

        // ---- 汇总（顺序与 Go 版一致） ----
        List<String> uniqlist = new ArrayList<>();
        uniqlist.addAll(bdss);
        uniqlist.addAll(wbdss);
        uniqlist.addAll(kbdss);
        uniqlist.addAll(reverse);
        uniqlist.addAll(kombUnique01);
        uniqlist.addAll(kombUnique02);
        uniqlist.addAll(kombUnique03);
        uniqlist.addAll(kombUnique04);
        uniqlist.addAll(kombUnique05);

        for (int i = 1; i <= 21; i++) {
            uniqlist.addAll(kombUnique.get(i));
        }

        uniqlist.addAll(kombUnique07);
        uniqlist.addAll(kombUnique08);
        uniqlist.addAll(kombUnique09);
        uniqlist.addAll(kombUnique10);
        uniqlist.addAll(kombUnique11);
        uniqlist.addAll(kombUnique012);

        List<String> uniqueLista = removeDuplicates(uniqlist);
        List<String> uniqueLeet = new ArrayList<>();

        if ("y".equals(profile.leetmode)) {
            // 对应 Go 的并发 MakeLeet，这里顺序执行（Go 结果顺序本身不确定）
            for (String x : uniqueLista) {
                uniqueLeet.add(makeLeet(x));
            }
        }

        List<String> uniqueList = new ArrayList<>(uniqueLista);
        uniqueList.addAll(uniqueLeet);

        // 按 Go 语义：len(x) 为 UTF-8 字节数
        List<String> uniqueListFinished = new ArrayList<>();
        for (String x : uniqueList) {
            if (len(x) < CuppConfig.CONFIG.wcTo && len(x) > CuppConfig.CONFIG.wcFrom) {
                uniqueListFinished.add(x);
            }
        }

        return uniqueListFinished;
    }

    /** 对应 Go 的 GenerateWordlist：生成并写入文件。 */
    public static void generateWordlist(Profile profile, String outputFile) {
        List<String> uniqueListFinished = generateWordlistFromProfile(profile);
        printToFile(outputFile, uniqueListFinished);
    }

    // =====================================================================
    // 改进字典
    // =====================================================================

    /** 对应 Go 的 ImproveDictionary：在现有字典基础上衍生新词条。 */
    public static void improveDictionary(String fileToOpen, boolean concat, boolean leet,
                                         boolean numbers, boolean special) {
        if (!Files.exists(Paths.get(fileToOpen))) {
            Colors.errorPrint("Error: 文件 %s 不存在", fileToOpen);
            return;
        }

        byte[] data;
        try {
            data = Files.readAllBytes(Paths.get(fileToOpen));
        } catch (Exception e) {
            Colors.errorPrint("Error: 无法读取文件 %s: %v", fileToOpen, e);
            return;
        }

        // 对应 Go 的 strings.Split(s, "\n")：保留末尾空串
        List<String> listic = Arrays.asList(new String(data, StandardCharsets.UTF_8).split("\n", -1));

        List<String> chars = CuppConfig.CONFIG.chars;
        List<String> years = CuppConfig.CONFIG.years;
        int numfrom = CuppConfig.CONFIG.numFrom;
        int numto = CuppConfig.CONFIG.numTo;

        Map<Integer, List<String>> kombinacija = new HashMap<>();
        Map<Integer, List<String>> kombUnique = new HashMap<>();

        List<String> cont = new ArrayList<>();
        cont.add("");

        if (concat && listic.size() <= CuppConfig.CONFIG.threshold) {
            Colors.infoPrint("[+] 连接词汇...");
            for (String cont1 : listic) {
                for (String cont2 : listic) {
                    if (indexOf(listic, cont1) != indexOf(listic, cont2)) {
                        cont.add(cont1 + cont2);
                    }
                }
            }
        } else if (concat) {
            Colors.warningPrint("[-] 词汇数量 %d 超过阈值 %d，跳过连接",
                    listic.size(), CuppConfig.CONFIG.threshold);
        }

        List<String> specharsList = new ArrayList<>();
        if (special) {
            Colors.infoPrint("[+] 添加特殊字符...");
            for (String spec1 : chars) {
                specharsList.add(spec1);
                for (String spec2 : chars) {
                    specharsList.add(spec1 + spec2);
                    for (String spec3 : chars) {
                        specharsList.add(spec1 + spec2 + spec3);
                    }
                }
            }
        }

        for (int i = 0; i < 6; i++) {
            kombinacija.put(i, new ArrayList<>(List.of("")));
        }

        kombinacija.put(0, komb(listic, years, ""));
        if (concat) {
            kombinacija.put(1, komb(cont, years, ""));
        }
        if (special) {
            kombinacija.put(2, komb(listic, specharsList, ""));
            if (concat) {
                kombinacija.put(3, komb(cont, specharsList, ""));
            }
        }
        if (numbers) {
            kombinacija.put(4, concats(listic, numfrom, numto));
            if (concat) {
                kombinacija.put(5, concats(cont, numfrom, numto));
            }
        }

        Colors.infoPrint("[+] 正在生成字典...");
        Colors.infoPrint("[+] 正在排序并去除重复...");

        for (int i = 0; i < 6; i++) {
            kombUnique.put(i, removeDuplicates(kombinacija.get(i)));
        }

        kombUnique.put(6, removeDuplicates(listic));
        kombUnique.put(7, removeDuplicates(cont));

        List<String> uniqlist = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            uniqlist.addAll(kombUnique.get(i));
        }

        List<String> uniqueLista = removeDuplicates(uniqlist);
        List<String> uniqueLeet = new ArrayList<>();

        if (leet) {
            Colors.infoPrint("[+] 应用Leet模式...");
            for (String x : uniqueLista) {
                uniqueLeet.add(makeLeet(x));
            }
        }

        List<String> uniqueList = new ArrayList<>(uniqueLista);
        uniqueList.addAll(uniqueLeet);

        List<String> uniqueListFinished = new ArrayList<>();
        for (String x : uniqueList) {
            if (len(x) > CuppConfig.CONFIG.wcFrom && len(x) < CuppConfig.CONFIG.wcTo) {
                uniqueListFinished.add(x);
            }
        }

        printToFile(fileToOpen + ".cupp.txt", uniqueListFinished);
    }

    // =====================================================================
    // 字符串工具（对应 generator.go 末尾的辅助函数）
    // =====================================================================

    /** 对应 Go 的 reverseString：按 rune 反转。 */
    public static String reverseString(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = s.length(); i > 0; ) {
            int cp = s.codePointAt(i - 1);
            i -= Character.charCount(cp);
            sb.appendCodePoint(cp);
        }
        return sb.toString();
    }

    /** 对应 Go 的 indexOf：返回首个匹配下标，否则 -1。 */
    public static int indexOf(List<String> slice, String item) {
        for (int i = 0; i < slice.size(); i++) {
            if (Objects.equals(slice.get(i), item)) {
                return i;
            }
        }
        return -1;
    }

    /** Go 的 len(s)：UTF-8 字节数。 */
    public static int len(String s) {
        return s == null ? 0 : s.getBytes(StandardCharsets.UTF_8).length;
    }

    /** null 安全的空串（Go 侧画像字段均为 ""）。 */
    private static String nvl(String s) {
        return s == null ? "" : s;
    }

    private static List<String> concat(List<String> a, List<String> b) {
        List<String> r = new ArrayList<>(a);
        r.addAll(b);
        return r;
    }

    /** 生日切片的 1/2/3 段组合（对应 bdss/wbdss/kbdss 的三重循环）。 */
    private static List<String> dateCombos(List<String> bds) {
        List<String> bdss = new ArrayList<>();
        for (String bds1 : bds) {
            bdss.add(bds1);
            for (String bds2 : bds) {
                if (indexOf(bds, bds1) != indexOf(bds, bds2)) {
                    bdss.add(bds1 + bds2);
                    for (String bds3 : bds) {
                        if (indexOf(bds, bds1) != indexOf(bds, bds2)
                                && indexOf(bds, bds2) != indexOf(bds, bds3)
                                && indexOf(bds, bds1) != indexOf(bds, bds3)) {
                            bdss.add(bds1 + bds2 + bds3);
                        }
                    }
                }
            }
        }
        return bdss;
    }

    /** 名字列表的两两组合（对应 kombinaa/kombinaaw/kombinaak 的双重循环）。 */
    private static List<String> nameCombos(List<String> kombina) {
        List<String> kombinaa = new ArrayList<>();
        for (String kombina1 : kombina) {
            kombinaa.add(kombina1);
            for (String kombina2 : kombina) {
                if (indexOf(kombina, kombina1) != indexOf(kombina, kombina2)
                        && indexOf(kombina, title(kombina1)) != indexOf(kombina, title(kombina2))) {
                    kombinaa.add(kombina1 + kombina2);
                }
            }
        }
        return kombinaa;
    }

    /**
     * 对应 Go 的 strings.Title：每个"词"首字母大写。
     * isSeparator 规则与 Go 标准库 strings/isSeparator 完全一致，
     * 初始 prev 为分隔符（对应 Go 的 prev := ' '）。
     */
    public static String title(String s) {
        if (s == null || s.isEmpty()) {
            return s == null ? "" : s;
        }
        StringBuilder sb = new StringBuilder(s.length());
        boolean prevSep = true;
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            if (prevSep) {
                sb.appendCodePoint(Character.toTitleCase(cp));
            } else {
                sb.appendCodePoint(cp);
            }
            prevSep = isSeparator(cp);
        }
        return sb.toString();
    }

    private static boolean isSeparator(int cp) {
        if (cp <= 0x7F) {
            if (cp >= '0' && cp <= '9') {
                return false;
            }
            if (cp >= 'a' && cp <= 'z') {
                return false;
            }
            if (cp >= 'A' && cp <= 'Z') {
                return false;
            }
            if (cp == '_') {
                return false;
            }
            return true;
        }
        if (Character.isLetter(cp) || Character.isDigit(cp)) {
            return false;
        }
        return Character.isSpaceChar(cp) || Character.isWhitespace(cp);
    }
}

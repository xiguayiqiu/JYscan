package space.jyscan.modules.cupp;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CUPP 配置，移植自 freeclient/internal/cupp/config.go。
 *
 * <p>Go 侧用 gopkg.in/ini.v1 读取同目录的 cupp.cfg；这里实现一个最小 INI 读取器
 * （只解析 {@code key = value} 与跳过 {@code [section]} 行），不引入新依赖。
 * 配置文件不存在时使用 {@link #setDefaultConfig()} 内置默认值。
 */
public class CuppConfig {

    public List<String> years = new ArrayList<>();
    public List<String> chars = new ArrayList<>();
    public int numFrom;
    public int numTo;
    public int wcFrom;
    public int wcTo;
    public int threshold;
    public String alectoUrl = "";
    public String dictUrl = "";
    public Map<String, String> leetMap = new LinkedHashMap<>();

    /** 全局配置（对应 Go 的 var CONFIG CUPPConfig）。 */
    public static CuppConfig CONFIG = new CuppConfig();

    /** 读取可执行文件同目录下的 cupp.cfg（对应 Go 的 InitConfig）。 */
    public static void readConfig() {
        String configPath = Paths.get(getCurrentPath(), "cupp.cfg").toString();
        readConfig(configPath);
    }

    /** 对应 Go 的 GetCurrentPath：可执行文件目录，失败回退当前工作目录。 */
    public static String getCurrentPath() {
        try {
            URI uri = CuppConfig.class.getProtectionDomain().getCodeSource().getLocation().toURI();
            Path p = Paths.get(uri);
            if (Files.isRegularFile(p)) {
                p = p.getParent();
            }
            if (p != null) {
                return p.toString();
            }
        } catch (Exception ignored) {
            // 回退到工作目录
        }
        String wd = System.getProperty("user.dir");
        return wd != null ? wd : ".";
    }

    /** 对应 Go 的 readConfig：文件不存在则用默认配置，否则按行解析 key = value。 */
    public static void readConfig(String filename) {
        Path p = Paths.get(filename);
        if (!Files.exists(p)) {
            setDefaultConfig();
            return;
        }

        byte[] content;
        try {
            content = Files.readAllBytes(p);
        } catch (Exception e) {
            return;
        }

        String[] lines = new String(content, StandardCharsets.UTF_8).split("\n", -1);
        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            // [section] 行直接跳过
            if (line.startsWith("[")) {
                continue;
            }

            int eq = line.indexOf('=');
            if (eq < 0) {
                continue;
            }

            String key = line.substring(0, eq).trim();
            String value = line.substring(eq + 1).trim();

            switch (key) {
                case "years" -> CONFIG.years = splitComma(value);
                case "chars" -> CONFIG.chars = parseChars(value);
                case "from" -> CONFIG.numFrom = parseInt(value);
                case "to" -> CONFIG.numTo = parseInt(value);
                case "wcfrom" -> CONFIG.wcFrom = parseInt(value);
                case "wcto" -> CONFIG.wcTo = parseInt(value);
                case "threshold" -> CONFIG.threshold = parseInt(value);
                case "alectourl" -> CONFIG.alectoUrl = value;
                case "dicturl" -> CONFIG.dictUrl = value;
                default -> {
                    // 未知键忽略（与 Go 的 switch 默认分支一致）
                }
            }
        }

        initLeetMap();
    }

    /** 默认配置（与 SetDefaultConfig 完全一致）。 */
    public static void setDefaultConfig() {
        CONFIG.years = new ArrayList<>(List.of(
                "1990", "1991", "1992", "1993", "1994", "1995", "1996", "1997", "1998", "1999",
                "2000", "2001", "2002", "2003", "2004", "2005", "2006", "2007", "2008", "2009", "2010",
                "2011", "2012", "2013", "2014", "2015", "2016", "2017", "2018", "2019", "2020"));
        CONFIG.chars = new ArrayList<>(List.of("!", "@", "#", "$", "%", "&", "*"));
        CONFIG.numFrom = 0;
        CONFIG.numTo = 100;
        CONFIG.wcFrom = 5;
        CONFIG.wcTo = 12;
        CONFIG.threshold = 200;
        CONFIG.alectoUrl = "https://github.com/yangbh/Hammer/raw/b0446396e8d67a7d4e53d6666026e078262e5bab/lib/cupp/alectodb.csv.gz";
        CONFIG.dictUrl = "http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/";
        initLeetMap();
    }

    /** Leet 映射（与 initLeetMap 完全一致；LinkedHashMap 保持固定替换顺序）。 */
    public static void initLeetMap() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("a", "4");
        m.put("i", "1");
        m.put("e", "3");
        m.put("t", "7");
        m.put("o", "0");
        m.put("s", "5");
        m.put("g", "9");
        m.put("z", "2");
        CONFIG.leetMap = m;
    }

    /** 对应 Go 的 parseChars：去掉空格、忽略逗号，逐字符拆分。 */
    static List<String> parseChars(String s) {
        String t = s.replace(" ", "");
        List<String> result = new ArrayList<>();
        for (int i = 0; i < t.length(); ) {
            int cp = t.codePointAt(i);
            i += Character.charCount(cp);
            if (cp == ',') {
                continue;
            }
            result.add(new String(Character.toChars(cp)));
        }
        return result;
    }

    /** 对应 Go 的 parseInt：只累积 0-9 数字，其余字符忽略。 */
    static int parseInt(String s) {
        int result = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= '0' && c <= '9') {
                result = result * 10 + (c - '0');
            }
        }
        return result;
    }

    /** years = a,b,c 的拆分（对应 Go 的 strings.Split(value, ","），空串也得到 [""]）。 */
    static List<String> splitComma(String value) {
        List<String> result = new ArrayList<>();
        int start = 0;
        while (true) {
            int idx = value.indexOf(',', start);
            if (idx < 0) {
                result.add(value.substring(start));
                return result;
            }
            result.add(value.substring(start, idx));
            start = idx + 1;
        }
    }
}

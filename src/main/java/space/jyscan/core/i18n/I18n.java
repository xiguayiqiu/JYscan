package space.jyscan.core.i18n;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 轻量级国际化文案，对应 internal/i18n/i18n.go。
 *
 * <p>支持两种语言：中文（zh，默认）与英文（en）。优先级：
 * <ol>
 *   <li>命令行参数 --lang zh|en</li>
 *   <li>环境变量 JYSCAN_LANG=zh|en</li>
 *   <li>系统环境变量 LANG / LC_ALL / LANGUAGE</li>
 * </ol>
 *
 * <p>缺失 key 时回退到默认语言（zh），再缺失则原样返回 key —— 与 Go 版一致，
 * 这样 {@code T("cmd.xxx.short")} 拿不到翻译时可由调用方识别并回退到 cobra/picocli
 * 自带的 Short 文案。
 */
public final class I18n {

    public static final String LANG_ZH = "zh";
    public static final String LANG_EN = "en";

    /** 默认语言。 */
    public static final String DEFAULT_LANG = LANG_ZH;

    /** 显式指定语言的环境变量名。 */
    public static final String ENV_KEY = "JYSCAN_LANG";

    private static final Object LOCK = new Object();
    private static String currentLang = DEFAULT_LANG;

    private static final Map<String, Map<String, String>> MESSAGES = new HashMap<>();

    static {
        MESSAGES.put(LANG_ZH, Zh.MESSAGES);
        MESSAGES.put(LANG_EN, En.MESSAGES);
        // 包初始化时自动检测语言，确保其他静态初始化里调用 T() 时语言已就绪
        currentLang = detect();
    }

    private I18n() {
    }

    // =====================================================================
    // 语言设置
    // =====================================================================

    /** 设置全局语言，不支持的语言被忽略（与 Go 版一致）。 */
    public static void setLang(String lang) {
        if (lang == null) {
            return;
        }
        synchronized (LOCK) {
            if (MESSAGES.containsKey(lang)) {
                currentLang = lang;
            }
        }
    }

    public static String getLang() {
        synchronized (LOCK) {
            return currentLang;
        }
    }

    public static boolean isSupported(String lang) {
        return MESSAGES.containsKey(lang);
    }

    public static String[] supportedLangs() {
        return new String[]{LANG_ZH, LANG_EN};
    }

    // =====================================================================
    // 取文案
    // =====================================================================

    /** 取 key 对应的文案。 */
    public static String T(String key) {
        String lang;
        synchronized (LOCK) {
            lang = currentLang;
        }
        Map<String, String> m = MESSAGES.get(lang);
        if (m != null && m.containsKey(key)) {
            return m.get(key);
        }
        Map<String, String> def = MESSAGES.get(DEFAULT_LANG);
        if (def != null && def.containsKey(key)) {
            return def.get(key);
        }
        return key;
    }

    /** 等价于 Fmt.format(T(key), args...)。 */
    public static String Tf(String key, Object... args) {
        return space.jyscan.core.util.Fmt.format(T(key), args);
    }

    /** key 是否存在（用于回退到 picocli 自带 Short）。 */
    public static boolean has(String key) {
        String lang;
        synchronized (LOCK) {
            lang = currentLang;
        }
        Map<String, String> m = MESSAGES.get(lang);
        if (m != null && m.containsKey(key)) {
            return true;
        }
        Map<String, String> def = MESSAGES.get(DEFAULT_LANG);
        return def != null && def.containsKey(key);
    }

    // =====================================================================
    // 语言探测 / 解析
    // =====================================================================

    /**
     * 按优先级探测语言：JYSCAN_LANG -> LC_ALL/LANG/LANGUAGE -> 平台探测。
     * 无法识别时返回默认语言。
     */
    public static String detect() {
        String v = System.getenv(ENV_KEY);
        if (v != null && !v.isEmpty()) {
            String l = parseLang(v);
            if (l != null) {
                return l;
            }
        }
        for (String env : new String[]{"LC_ALL", "LANG", "LANGUAGE"}) {
            v = System.getenv(env);
            if (v != null && !v.isEmpty()) {
                String l = parseLang(v);
                if (l != null) {
                    return l;
                }
            }
        }
        String osLang = osLang();
        if (osLang != null && !osLang.isEmpty()) {
            String l = parseLang(osLang);
            if (l != null) {
                return l;
            }
        }
        return DEFAULT_LANG;
    }

    /**
     * 解析语言字符串（如 "zh_CN.UTF-8"、"en"），无法识别返回 null。
     */
    public static String parseLang(String v) {
        if (v == null) {
            return null;
        }
        String s = v.trim().toLowerCase(Locale.ROOT);
        if (s.startsWith("zh")) {
            return LANG_ZH;
        }
        if (s.startsWith("en")) {
            return LANG_EN;
        }
        return null;
    }

    /**
     * 非 Windows 平台无需额外检测，环境变量已覆盖主流 Unix。
     * 对应 internal/i18n/detect_unix.go。
     */
    private static String osLang() {
        if (space.jyscan.core.util.SystemUtil.isWindows()) {
            try {
                String loc = System.getProperty("user.language", "");
                if (!loc.isEmpty()) {
                    return loc;
                }
            } catch (Exception ignored) {
            }
        }
        return "";
    }
}

package space.jyscan.core.util;

/**
 * 终端颜色与日志输出，合并移植 Go 的 internal/utils/colors.go 与 logging.go。
 *
 * <p>全局开关 {@link #useColor} / {@link #isSilent} / {@link #isVerbose}
 * 由根命令根据 --no-color / -q / -v 设置，语义与 Go 版一致：
 * <ul>
 *   <li>{@code SuccessPrint}/{@code InfoPrint}/{@code ProgressPrint} 受静默模式抑制；</li>
 *   <li>{@code ErrorPrint}/{@code WarningPrint} 不受静默模式抑制；</li>
 *   <li>{@code Debug(...)} 仅在 verbose 下返回非空，{@code DebugPrint} 则总是打印（与 Go 相同）。</li>
 * </ul>
 *
 * <p>格式化统一走 {@link Fmt#format}，保证 {@code %v}/{@code %q}/{@code %T} 等 Go 动词可用。
 */
public final class Colors {

    // =====================================================================
    // ANSI 序列
    // =====================================================================
    public static final String RESET = "\u001b[0m";
    public static final String BOLD = "\u001b[1m";
    public static final String FG_RED = "\u001b[31m";
    public static final String FG_GREEN = "\u001b[32m";
    public static final String FG_YELLOW = "\u001b[33m";
    public static final String FG_BLUE = "\u001b[34m";
    public static final String FG_MAGENTA = "\u001b[35m";
    public static final String FG_CYAN = "\u001b[36m";
    public static final String FG_WHITE = "\u001b[37m";
    public static final String FG_HI_BLACK = "\u001b[90m";
    public static final String FG_HI_RED = "\u001b[91m";
    public static final String FG_HI_GREEN = "\u001b[92m";
    public static final String FG_HI_YELLOW = "\u001b[93m";
    public static final String FG_HI_BLUE = "\u001b[94m";
    public static final String FG_HI_MAGENTA = "\u001b[95m";
    public static final String FG_HI_CYAN = "\u001b[96m";
    public static final String FG_HI_WHITE = "\u001b[97m";

    // =====================================================================
    // 全局开关（对应 Go 的 UseColor / IsSilent / IsVerbose）
    // =====================================================================
    public static volatile boolean useColor = true;
    public static volatile boolean isSilent = false;
    public static volatile boolean isVerbose = false;

    private Colors() {
    }

    public static void setColor(boolean v) {
        useColor = v;
    }

    public static void setSilent(boolean v) {
        isSilent = v;
    }

    public static void setVerbose(boolean v) {
        isVerbose = v;
    }

    // =====================================================================
    // 底层
    // =====================================================================

    /** 用 ANSI 码包裹文本；关闭颜色时原样返回。 */
    public static String wrap(String text, String... codes) {
        if (!useColor || text == null || text.isEmpty() || codes == null || codes.length == 0) {
            return text;
        }
        StringBuilder sb = new StringBuilder(text.length() + 16 * codes.length);
        for (String c : codes) {
            sb.append(c);
        }
        sb.append(text).append(RESET);
        return sb.toString();
    }

    /** 等价于 color.Color.Sprintf。 */
    public static String format(String fmt, String[] codes, Object... args) {
        return wrap(Fmt.format(fmt, args), codes);
    }

    /** 等价于 Go 的 utils.ColorText。 */
    public static String colorText(String text, String colorCode) {
        return text;
    }

    /** 等价于 Go 的 utils.ColorPrint：只格式化输出，不着色（与 Go 行为一致）。 */
    public static void colorPrint(String colorCode, String format, Object... args) {
        System.out.println(Fmt.format(format, args));
    }

    private static void println(String s) {
        System.out.println(s);
    }

    private static void printf(String fmt, Object... args) {
        System.out.print(Fmt.format(fmt, args));
    }

    // =====================================================================
    // 字符串型（对应 colors.go 中返回 string 的函数）
    // =====================================================================

    public static String success(String format, Object... args) {
        return wrap(Fmt.format(format, args), FG_GREEN);
    }

    public static String error(String format, Object... args) {
        return wrap(Fmt.format(format, args), FG_RED);
    }

    public static String warning(String format, Object... args) {
        return wrap(Fmt.format(format, args), FG_YELLOW);
    }

    public static String info(String format, Object... args) {
        return wrap(Fmt.format(format, args), FG_BLUE);
    }

    public static String highlight(String format, Object... args) {
        return wrap(Fmt.format(format, args), FG_CYAN);
    }

    public static String boldSuccess(String format, Object... args) {
        return wrap(Fmt.format(format, args), BOLD, FG_GREEN);
    }

    public static String boldError(String format, Object... args) {
        return wrap(Fmt.format(format, args), BOLD, FG_RED);
    }

    public static String boldWarning(String format, Object... args) {
        return wrap(Fmt.format(format, args), BOLD, FG_YELLOW);
    }

    public static String boldInfo(String format, Object... args) {
        return wrap(Fmt.format(format, args), BOLD, FG_BLUE);
    }

    public static String progress(String format, Object... args) {
        return wrap(Fmt.format(format, args), FG_MAGENTA);
    }

    /** 仅 verbose 下返回内容，否则返回空串（与 Go 的 utils.Debug 一致）。 */
    public static String debug(String format, Object... args) {
        if (!isVerbose) {
            return "";
        }
        return wrap(Fmt.format(format, args), FG_HI_BLACK);
    }

    public static String banner(String format, Object... args) {
        return wrap(Fmt.format(format, args), BOLD, FG_CYAN);
    }

    public static String title(String format, Object... args) {
        return wrap(Fmt.format(format, args), BOLD, FG_WHITE);
    }

    // =====================================================================
    // 打印型（对应 colors.go 中 *Print 函数）
    // =====================================================================

    public static void successPrint(String format, Object... args) {
        if (isSilent) {
            return;
        }
        println(success(format, args));
    }

    public static void errorPrint(String format, Object... args) {
        println(error(format, args));
    }

    public static void warningPrint(String format, Object... args) {
        println(warning(format, args));
    }

    /** 纯文本信息输出，受静默模式抑制（与 Go 的 fmt.Printf 等价）。 */
    public static void infoPrint(String format, Object... args) {
        if (isSilent) {
            return;
        }
        println(Fmt.format(format, args));
    }

    public static void progressPrint(String format, Object... args) {
        if (isSilent) {
            return;
        }
        println(progress(format, args));
    }

    public static void bannerPrint(String format, Object... args) {
        println(banner(format, args));
    }

    public static void titlePrint(String format, Object... args) {
        println(title(format, args));
    }

    public static void resultPrint(String format, Object... args) {
        if (isSilent) {
            return;
        }
        println(banner("[>] " + format, args));
    }

    // =====================================================================
    // 日志型（对应 logging.go 的 LogXxx）
    // =====================================================================

    public static void logSuccess(String format, Object... args) {
        successPrint(format, args);
    }

    public static void logError(String format, Object... args) {
        errorPrint(format, args);
    }

    public static void logWarning(String format, Object... args) {
        warningPrint(format, args);
    }

    public static void logInfo(String format, Object... args) {
        infoPrint(format, args);
    }

    public static void logProgress(String format, Object... args) {
        progressPrint(format, args);
    }

    public static void logDebug(String format, Object... args) {
        debugPrint(format, args);
    }

    /** 灰色调试输出（与 Go 相同：不检查 verbose 开关）。 */
    public static void debugPrint(String format, Object... args) {
        println(wrap(Fmt.format(format, args), FG_HI_BLACK));
    }

    public static void logBanner(String format, Object... args) {
        bannerPrint(format, args);
    }

    public static void logTitle(String format, Object... args) {
        titlePrint(format, args);
    }

    public static void logModuleStart(String moduleName) {
        infoPrint("模块启动: %s", moduleName);
    }

    public static void logModuleStop(String moduleName) {
        infoPrint("模块停止: %s", moduleName);
    }

    public static void logCommandExecution(String command, String[] args) {
        debugPrint("执行命令: %s %v", command, args == null ? new String[0] : args);
    }

    public static void logNetworkOperation(String operation, String target) {
        debugPrint("网络操作: %s -> %s", operation, target);
    }

    public static void logSecurityEvent(String eventType, String description) {
        warningPrint("安全事件: %s - %s", eventType, description);
    }

    public static void logPerformanceInfo(String operation, long durationMs) {
        debugPrint("性能信息: %s 耗时 %dms", operation, durationMs);
    }
}

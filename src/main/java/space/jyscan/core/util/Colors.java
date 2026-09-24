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

    /**
     * 用 ANSI 码包裹文本（fatih/color 的 {@code Printf}/{@code Print} 语义，对应
     * {@code Set(); Fprintf(...); defer unset()}）：合并为<b>单条</b> SGR 序列
     * （如 {@code ESC[37;1m}，等价 fatih 的 {@code sequence()} 按参数顺序 ';'.join），
     * unformat 恒为通用 {@code ESC[0m}（fatih 的 {@code Unset()}）。关闭颜色时原样返回。
     *
     * <p>注意：Go 的 deferred unset 在 Fprintf 之后触发，所以内嵌在文本里的
     * 换行会出现在 format 与 unformat <b>之间</b>（本实现天然一致）。
     */
    public static String wrap(String text, String... codes) {
        if (!useColor || text == null || codes == null || codes.length == 0) {
            return text;
        }
        String fmt = formatSeq(codes);
        if (fmt == null) {
            fmt = String.join("", codes);
        }
        return fmt + text + RESET;
    }

    /**
     * fatih/color 的 {@code Println} 语义：{@code Fprintln(Output, c.wrap(sprintln(s)))}，
     * 其中 {@code sprintln = TrimSuffix(Sprintln(s), "\n")}，wrap 的 unformat 按<b>每个参数</b>
     * 查 fatih 的 {@code mapResetAttributes}（Bold/Faint→22、Italic→23、Underline→24、
     * Blink→25、Reverse→27、Concealed→28、CrossedOut→29，颜色等其余→0）后 ';'.join。
     * 即输出 {@code format + text + unformat}，<b>不含换行</b>（换行由调用方在
     * unformat 之后补，与 fatih 的 Fprintln 一致）。关闭颜色时原样返回。
     */
    public static String wrapPrintln(String text, String... codes) {
        if (!useColor || text == null || codes == null || codes.length == 0) {
            return text;
        }
        String fmt = formatSeq(codes);
        if (fmt == null) {
            return text;
        }
        String unf = unformatSeq(codes);
        return fmt + text + (unf.isEmpty() ? RESET : unf);
    }

    /**
     * 合并 codes 为单条 SGR 开序列（等价 fatih 的 {@code format()} =
     * {@code escape + sequence() + "m"}）。无法解析为纯 SGR 参数的 code 跳过；
     * 若一个都解析不出则返回 {@code null}。前缀直接取自 {@link #RESET} 前两字符，
     * 避免在源码里写字面转义。
     */
    private static String formatSeq(String... codes) {
        StringBuilder sb = new StringBuilder(RESET.substring(0, 2));
        boolean first = true;
        for (String c : codes) {
            String mid = sgrParams(c);
            if (mid == null) {
                continue;
            }
            for (String p : mid.split(";")) {
                if (p.isEmpty()) {
                    continue;
                }
                if (!first) {
                    sb.append(';');
                }
                sb.append(p);
                first = false;
            }
        }
        if (first) {
            return null;
        }
        return sb.append('m').toString();
    }

    /** 逐参数查 fatih 的 mapResetAttributes 后合并为单条复位序列；无参数时返回空串。 */
    private static String unformatSeq(String... codes) {
        StringBuilder sb = new StringBuilder(RESET.substring(0, 2));
        boolean first = true;
        for (String c : codes) {
            String mid = sgrParams(c);
            if (mid == null) {
                continue;
            }
            for (String p : mid.split(";")) {
                if (p.isEmpty()) {
                    continue;
                }
                int attr;
                try {
                    attr = Integer.parseInt(p);
                } catch (NumberFormatException e) {
                    attr = -1;
                }
                if (!first) {
                    sb.append(';');
                }
                sb.append(mapReset(attr));
                first = false;
            }
        }
        if (first) {
            return "";
        }
        return sb.append('m').toString();
    }

    /** fatih/color 的 mapResetAttributes：属性→专属复位码；未收录（颜色等）→通用 Reset(0)。 */
    private static int mapReset(int attr) {
        switch (attr) {
            case 1:  // Bold
            case 2:  // Faint
                return 22; // ResetBold
            case 3:
                return 23; // ResetItalic
            case 4:
                return 24; // ResetUnderline
            case 5:  // BlinkSlow
            case 6:  // BlinkRapid
                return 25; // ResetBlinking
            case 7:
                return 27; // ResetReversed
            case 8:
                return 28; // ResetConcealed
            case 9:
                return 29; // ResetCrossedOut
            default:
                return 0;
        }
    }

    /** 若 code 形如 SGR 码（前缀 = RESET 前两字符，中段仅 0-9 与 ';'，尾 'm'）则返回参数串。 */
    private static String sgrParams(String code) {
        if (code == null || code.length() < 4 || !code.startsWith(RESET.substring(0, 2))
                || !code.endsWith("m")) {
            return null;
        }
        String mid = code.substring(2, code.length() - 1);
        for (int i = 0; i < mid.length(); i++) {
            char ch = mid.charAt(i);
            if ((ch < '0' || ch > '9') && ch != ';') {
                return null;
            }
        }
        return mid;
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

package space.jyscan.modules.nuclei.log;

import java.io.PrintStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;

/**
 * nuclei 风格日志器，对应 Go 的 {@code log.Logger}（{@code logger.go}）。
 *
 * <p>跨包契约：CLI（{@code cli/nuclei.go} 的 {@code runNuclei} / {@code printSummary}）
 * 经 {@code log.NewLogger()} 取到本类型，调用 {@link #setNoColor(boolean)}、
 * {@link #info(String, Object...)}、{@link #warning(String, Object...)}、
 * {@link #error(String, Object...)}。
 *
 * <p>Go 侧 {@code NewLogger()} 默认 {@code SetNoColor(false)}，{@code runNuclei} 开头
 * 显式再设一次；当 {@code --no-color} 给定时改设 {@code true}。
 *
 * <p>Go 的 {@code io.Writer} 输出目标映射为 {@link java.io.PrintStream}，默认
 * {@code System.err}（对应 Go 的 {@code os.Stderr}）。
 *
 * <p><b>与 {@link Colors} 的衔接（Go 侧对应 fatih/color）：</b>
 * <ul>
 *   <li>实例级 {@code noColor}/{@code silent}/{@code verbose} 三个状态字段按 Go 的
 *       Logger 结构体字段原样保留 —— Logger 的输出判定只读实例字段，不读全局
 *       {@link Colors#isSilent}/{@link Colors#isVerbose}（Go 的 SetSilent/SetVerbose
 *       也不触碰任何全局状态，同步过去会造成语义漂移；全局静默/详细开关对应
 *       {@code Colors.setSilent}/{@code Colors.setVerbose}，由根命令按 -q/-v 设置）；</li>
 *   <li>{@link #setNoColor(boolean)} 与 Go 完全一致地<b>同时</b>翻转全局色标：
 *       {@code no == true} 时 {@code Colors.setColor(false)}（Go：{@code color.NoColor = true}），
 *       {@code no == false} 时按 Go 不回写全局（Go 的 SetNoColor(false) 同样不复位
 *       {@code color.NoColor}）；</li>
 *   <li>着色统一走 {@link Colors#wrapPrintln}（按 {@link Colors#useColor} 全局色标渲染，
 *       unformat 按每个参数查 mapResetAttributes —— 与 fatih/color 的 {@code Color.Sprint}
 *       所用 {@code wrap()} 原语一致），颜色码取 {@link Colors} 的 ANSI 常量，不引第三方库。</li>
 * </ul>
 *
 * <p><b>{@code Fatal} 的处理：</b>Go 的 {@code Fatal} 打印 {@code [FAT]} 后
 * {@code os.Exit(1)}；Java 侧进程退出权在 CLI 层，故这里打印后抛出
 * {@link FatalException}（unchecked）—— CLI 应捕获它并 {@code System.exit(1)}；
 * 若无人捕获，JVM 默认以退出码 1 结束，与 Go 的 {@code os.Exit(1)} 语义一致。
 *
 * <p>格式化走 {@link Fmt#format}（Go {@code fmt.Sprintf} 兼容层）；线程安全对应 Go 的
 * {@code sync.Mutex}（{@code synchronized (mu)}）。
 *
 * <p><b>着色原语（fatih/color v1.18.0 源码实测）：</b>Go 侧前缀着色用
 * {@code c.Sprint(prefix)} → fatih {@code wrap()} → per-param unformat
 * （青+粗的 {@code [INF]} 复位为 {@code ESC[0;22m}）；而 {@code Print/Printf} 走
 * {@code Set/Unset} 才输出通用 {@code ESC[0m}（Java 侧对应 {@link Colors#wrap}）。
 * Logger 的两处着色点（{@code write()}、{@code infoTimestamped()}）均须走
 * {@link Colors#wrapPrintln}，误用 {@link Colors#wrap} 会使复位序列与 Go 不一致。
 *
 * <p><b>i18n 说明：</b>Go 的 {@code nuclei.go} 引用了 14 个未在 i18n 中定义的 key
 * （如 {@code nuclei.err.no-target}），Go 的 {@code i18n.T} 缺 key 时原样返回 key，
 * Java 的 {@code I18n.T}（{@code I18n.java:95}）行为相同 → 无需为这些 key 补值。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/log/logger.go}
 * （Go 侧的 {@code Level} 类型与 {@code Default} 全局变量在 freeclient 全树为 0 调用方，
 * 按项目「不移植 Go 死代码」的约定一并跳过）。
 */
public class Logger {

    /** 对应 Go 的 {@code sync.Mutex mu}。 */
    private final Object mu = new Object();

    /** 对应 Go 的 {@code out io.Writer}，默认 {@code os.Stderr}。 */
    private volatile PrintStream out = System.err;

    /** 对应 Go 的 {@code noColor bool}（实例级，非全局 Colors 状态）。 */
    private volatile boolean noColor;

    /** 对应 Go 的 {@code silent bool}（实例级）。 */
    private volatile boolean silent;

    /** 对应 Go 的 {@code verbose bool}（实例级）。 */
    private volatile boolean verbose;

    // 对应 Go 的 color.New(color.FgCyan, color.Bold) 等着色器，转为 Colors.wrap 的 ANSI 码组
    private static final String[] CYAN = {Colors.FG_CYAN, Colors.BOLD};
    private static final String[] YELLOW = {Colors.FG_YELLOW, Colors.BOLD};
    private static final String[] RED = {Colors.FG_RED, Colors.BOLD};
    private static final String[] GREEN = {Colors.FG_GREEN, Colors.BOLD};
    private static final String[] GRAY = {Colors.FG_HI_BLACK};

    /** 对应 Go 的 {@code time.Now().Format("2006-01-02 15:04:05")}。 */
    private static final DateTimeFormatter TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 对应 Go 的 {@code NewLogger() *Logger}（默认 stderr 输出）。 */
    public Logger() {
    }

    /** 对应 Go 的 {@code (l *Logger) SetOutput(w io.Writer)}。 */
    public void setOutput(PrintStream out) {
        synchronized (mu) {
            this.out = out;
        }
    }

    /**
     * 对应 Go 的 {@code (l *Logger) SetNoColor(no bool)}：存实例字段；{@code no == true}
     * 时同步关闭全局色标（Go：{@code color.NoColor = true}），{@code no == false} 不回写。
     */
    public void setNoColor(boolean no) {
        synchronized (mu) {
            this.noColor = no;
            if (no) {
                Colors.setColor(false);
            }
        }
    }

    /** 对应 Go 的 {@code (l *Logger) SetSilent(s bool)}：仅改实例字段（Go 不触碰全局状态）。 */
    public void setSilent(boolean s) {
        synchronized (mu) {
            this.silent = s;
        }
    }

    /** 对应 Go 的 {@code (l *Logger) SetVerbose(v bool)}：仅改实例字段（Go 不触碰全局状态）。 */
    public void setVerbose(boolean v) {
        synchronized (mu) {
            this.verbose = v;
        }
    }

    /** 对应 Go 的 {@code (l *Logger) Info(format string, args ...interface{})} - [INF] 青色。 */
    public void info(String format, Object... args) {
        if (silent) {
            return;
        }
        write("[INF]", CYAN, format, args);
    }

    /** 对应 Go 的 {@code (l *Logger) Success(format string, args ...interface{})} - [SUCC] 绿色。 */
    public void success(String format, Object... args) {
        if (silent) {
            return;
        }
        write("[SUCC]", GREEN, format, args);
    }

    /** 对应 Go 的 {@code (l *Logger) Warning(format string, args ...interface{})} - [WRN] 黄色。 */
    public void warning(String format, Object... args) {
        if (silent) {
            return;
        }
        write("[WRN]", YELLOW, format, args);
    }

    /** 对应 Go 的 {@code (l *Logger) Error(format string, args ...interface{})} - [ERR] 红色（不受 silent 抑制）。 */
    public void error(String format, Object... args) {
        write("[ERR]", RED, format, args);
    }

    /**
     * 对应 Go 的 {@code (l *Logger) Fatal(format string, args ...interface{})} - [FAT] 红色。
     *
     * <p>Go 打印后 {@code os.Exit(1)}；Java 侧不直接 {@code System.exit}
     * （进程退出权在 CLI 层），改为打印后抛出 {@link FatalException}。
     */
    public void fatal(String format, Object... args) {
        write("[FAT]", RED, format, args);
        throw new FatalException(Fmt.format(format, args));
    }

    /**
     * 对应 Go 的 {@code (l *Logger) Debug(format string, args ...interface{})} - [DBG] 灰色。
     * 仅在 {@code !silent && verbose} 时输出。
     */
    public void debug(String format, Object... args) {
        if (silent || !verbose) {
            return;
        }
        write("[DBG]", GRAY, format, args);
    }

    /**
     * 对应 Go 的 {@code (l *Logger) InfoTimestamped(format string, args ...interface{})}：
     * 输出 {@code 时间戳 [INF] 消息}，时间戳灰色、[INF] 青色。
     */
    public void infoTimestamped(String format, Object... args) {
        if (silent) {
            return;
        }
        synchronized (mu) {
            String ts = LocalDateTime.now().format(TIMESTAMP);
            String msg = Fmt.format(format, args);
            if (noColor) {
                out.print(ts + " [INF] " + msg + "\n");
            } else {
                out.print(Colors.wrapPrintln(ts, GRAY) + " " + Colors.wrapPrintln("[INF]", CYAN) + " " + msg + "\n");
            }
        }
    }

    /**
     * 实际写日志，对应 Go 的
     * {@code (l *Logger) write(prefix string, c *color.Color, format string, args ...interface{})}。
     *
     * <p>{@code noColor} 为 true 输出纯文本；否则经 {@link Colors#wrapPrintln} 着色 ——
     * 等价 Go 的 {@code c.Sprint(prefix)}：fatih {@code wrap()} 原语在调用时读全局
     * {@code color.NoColor}，unformat 按<b>每个参数</b>查 {@code mapResetAttributes}
     * （如青+粗 → {@code ESC[0;22m}）。输出格式与 Go 一致：{@code "<prefix> <message>\n"}。
     */
    private void write(String prefix, String[] codes, String format, Object... args) {
        synchronized (mu) {
            String msg = Fmt.format(format, args);
            String p = noColor ? prefix : Colors.wrapPrintln(prefix, codes);
            out.print(p + " " + msg + "\n");
        }
    }
}

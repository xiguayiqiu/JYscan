package space.jyscan.modules.nmap;

import space.jyscan.core.i18n.I18n;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 可执行文件查找与外部命令执行封装，移植自 freeclient/internal/utils/exec.go
 * （{@code LookPathSafe} / {@code IsAndroidRuntime} / {@code Command}）以及
 * scan.go、scan_optimized.go 里的命令调用约定。
 *
 * <p><b>归属</b>：本文件由 B 号子代理新建（scan 模块独占使用，不进共享层）。
 *
 * <p>Go 侧封装的动机是 Android/Termux 的 seccomp 拦截 {@code faccessat2(2)} 会让
 * {@code os/exec.LookPath} 直接 {@code SIGSYS} 崩掉整个进程；JVM 走的是
 * {@code access(2)}/{@code execve}，没有这个问题，但<b>仍按 Go 语义自己解析 PATH</b>，
 * 以保证：PATH 空项 = 当前目录、返回绝对路径、找不到时返回「不可用」而非抛异常。
 *
 * <p>命令执行对应 Go 的三种调用：
 * <ul>
 *   <li>{@link #run} —— {@code cmd.CombinedOutput()}（stdout+stderr 合并，非 0 退出也算「有输出」）；</li>
 *   <li>{@link #output} —— {@code cmd.Output()}（只要 stdout，stderr 丢弃）；</li>
 *   <li>{@link #runOrStart} —— {@code cmd.Run()}（只要成功与否，不要输出）。</li>
 * </ul>
 * Go 没有原生超时（靠 {@code CommandContext} 取消），Java 用
 * {@link Process#waitFor} 超时 + {@link Process#destroyForcibly()} 对应。
 */
public final class SysExec {

    /** Go 侧无法区分「启动失败」与「非 0 退出」，Java 统一用 -1 表示未正常退出。 */
    public static final int NOT_STARTED = -1;

    /** Android/Termux 进程自带的环境变量（exec.go:52）。 */
    private static final String[] ANDROID_ENV_KEYS = {
        "TERMUX_VERSION", "TERMUX_APP_PID", "ANDROID_ROOT", "ANDROID_DATA",
    };

    /** Android/Termux 的系统目录补充搜索项（exec.go:77-83）。 */
    private static final String[] ANDROID_EXTRA_EXEC_DIRS = {
        "/system/bin", "/system/xbin", "/vendor/bin", "/sbin", "/usr/sbin",
    };

    /** 对应 exec.go 的 {@code androidOnce} / {@code isAndroidHost}。 */
    private static final AtomicBoolean ANDROID_ONCE = new AtomicBoolean(false);
    private static volatile boolean isAndroidHost;

    /** 对应 scan_optimized.go 的 {@code pingPathOnce} / {@code pingPathVal}。 */
    private static final AtomicBoolean PING_ONCE = new AtomicBoolean(false);
    private static volatile String pingPathVal = "";

    private SysExec() {
    }

    /** 命令执行结果：{@code exitCode} 对应 Go 的 {@code err == nil ? 0 : 非0}。 */
    public record Result(int exitCode, String output) {

        /** 对应 Go 的 {@code err == nil}。 */
        public boolean ok() {
            return exitCode == 0;
        }
    }

    /** 对应 scan.go:2974 的 {@code isWindows()}。 */
    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows");
    }

    /** 对应 scan.go:2979 的 {@code isLinux()}。 */
    public static boolean isLinux() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return os.contains("linux") && !os.contains("android");
    }

    /** 对应 scan.go:2984 的 {@code isMacOS()}（Go: {@code runtime.GOOS == "darwin"}）。 */
    public static boolean isMacOS() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("mac");
    }

    // =========================================================================
    // exec.go: IsAndroidRuntime / extraExecDirs / LookPathSafe / isExecutableFile
    // =========================================================================

    /**
     * 对应 exec.go 的 {@code IsAndroidRuntime()}。
     *
     * <p>只做环境探测（Go 用 {@code sync.Once} 缓存，Java 用 double-checked flag）。
     */
    public static boolean isAndroidRuntime() {
        if (ANDROID_ONCE.compareAndSet(false, true)) {
            String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
            if (os.contains("android")) {
                isAndroidHost = true;
                return true;
            }
            if (!os.contains("linux")) {
                return false;
            }
            for (String key : ANDROID_ENV_KEYS) {
                String v = System.getenv(key);
                if (v != null && !v.isEmpty()) {
                    isAndroidHost = true;
                    return true;
                }
            }
            String prefix = System.getenv("PREFIX");
            if (prefix != null && prefix.contains("/data/data/com.termux")) {
                isAndroidHost = true;
                return true;
            }
            String home = System.getenv("HOME");
            if (home != null && home.contains("/data/data/com.termux")) {
                isAndroidHost = true;
                return true;
            }
            for (String path : new String[]{"/system/build.prop", "/system/bin/app_process"}) {
                if (new File(path).exists()) {
                    isAndroidHost = true;
                    return true;
                }
            }
        }
        return isAndroidHost;
    }

    /**
     * 对应 exec.go 的 {@code extraExecDirs()}：PATH 之外补充搜索的目录（仅 Android/Termux）。
     */
    private static List<String> extraExecDirs() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (!os.contains("linux") || !isAndroidRuntime()) {
            return List.of();
        }
        List<String> dirs = new ArrayList<>(ANDROID_EXTRA_EXEC_DIRS.length + 1);
        String prefix = System.getenv("PREFIX");
        if (prefix != null && !prefix.isEmpty()) {
            dirs.add(new File(prefix, "bin").getPath());
        }
        for (String d : ANDROID_EXTRA_EXEC_DIRS) {
            dirs.add(d);
        }
        return dirs;
    }

    /**
     * 对应 exec.go 的 {@code isExecutableFile(path)}：只用 {@code stat} + 权限位判断。
     *
     * <p>Go 判 {@code perm &amp; 0o111 != 0}（任意执行位即可），
     * Java 的 {@link File#canExecute()} 判「当前用户可执行」，实际目标文件都是系统命令，
     * 两者结果一致；此处以 Java 语义为准（JVM 无法读取 POSIX 权限位做 Go 式判断而不引入
     * {@code Files.getPosixFilePermissions} 的跨平台分支）。
     */
    private static boolean isExecutableFile(String path) {
        File f = new File(path);
        return f.isFile() && f.canExecute();
    }

    /**
     * 对应 exec.go 的 {@code LookPathSafe(file) (string, error)}。
     *
     * <p>找不到时返回 {@code null}（Go 返回 {@code exec.ErrNotFound}）。
     *
     * <p>语义对齐点：
     * <ul>
     *   <li>空串 → 找不到（Go: {@code &exec.Error{Err: exec.ErrNotFound}}）；</li>
     *   <li>含路径分隔符 → 直接校验该路径，不搜 PATH；</li>
     *   <li>PATH 空项按 {@code "."}（当前目录）处理；</li>
     *   <li>命中的相对路径会转成绝对路径（Go: {@code filepath.Abs}）；</li>
     *   <li>Windows 走 {@code PATHEXT} 扩展名补全（Go 侧直接委托 {@code exec.LookPath}）。</li>
     * </ul>
     */
    public static String lookPathSafe(String file) {
        if (file == null || file.isEmpty()) {
            return null;
        }
        boolean isWindows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows");

        if (file.indexOf('/') >= 0 || file.indexOf(File.separatorChar) >= 0) {
            String candidate = firstExecutableWithExt(file, isWindows);
            return candidate != null ? new File(candidate).getAbsolutePath() : null;
        }

        String pathEnv = System.getenv("PATH");
        List<String> dirs = new ArrayList<>();
        if (pathEnv != null) {
            for (String d : pathEnv.split(java.util.regex.Pattern.quote(File.pathSeparator))) {
                dirs.add(d);
            }
        }
        dirs.addAll(extraExecDirs());

        for (String dir : dirs) {
            // Unix shell 语义: PATH 中的空项表示当前目录（exec.go:109-112）
            if (dir == null || dir.isEmpty()) {
                dir = ".";
            }
            String path = new File(dir, file).getPath();
            String hit = firstExecutableWithExt(path, isWindows);
            if (hit == null) {
                continue;
            }
            File f = new File(hit);
            if (f.isAbsolute()) {
                return f.getAbsolutePath();
            }
            try {
                return f.getCanonicalPath();
            } catch (IOException e) {
                return f.getAbsolutePath();
            }
        }
        return null;
    }

    /**
     * Windows 上按 {@code PATHEXT} 依次补全扩展名（非 Windows 或已带扩展名时只测原名）。
     * 对应 Go 侧 {@code exec.LookPath} 的 PATHEXT 行为。
     */
    private static String firstExecutableWithExt(String base, boolean isWindows) {
        if (isExecutableFile(base)) {
            return base;
        }
        if (!isWindows) {
            return null;
        }
        if (base.lastIndexOf('.') > base.lastIndexOf(File.separatorChar)) {
            return null;    // 已带扩展名
        }
        String pathExt = System.getenv("PATHEXT");
        if (pathExt == null || pathExt.isEmpty()) {
            pathExt = ".COM;.EXE;.BAT;.CMD";
        }
        for (String ext : pathExt.split(";")) {
            if (ext.isEmpty()) {
                continue;
            }
            String candidate = base + ext;
            if (isExecutableFile(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    // =========================================================================
    // scan_optimized.go: resolvePingPath（sync.Once + 一次告警）
    // =========================================================================

    /**
     * 对应 scan_optimized.go 的 {@code resolvePingPath()}：
     * 用 {@link #lookPathSafe} 解析 {@code ping} 的绝对路径，只解析一次；
     * 解析失败时打印一次 {@code nmap.warn.exec_unavailable} 并返回空串（表示不可用，
     * 上层回退 TCP 探测）。
     *
     * <p>对应 Go 打印：{@code fmt.Println(i18n.Tf("nmap.warn.exec_unavailable", "ping"))}
     * （scan_optimized.go:895）。输出走标准流并显式 flush，与 Go {@code fmt.Println} 一致。
     */
    public static String resolvePingPath() {
        if (PING_ONCE.compareAndSet(false, true)) {
            String path = lookPathSafe("ping");
            if (path == null) {
                System.out.println(I18n.Tf("nmap.warn.exec_unavailable", "ping"));
                System.out.flush();
                return "";
            }
            pingPathVal = path;
        }
        return pingPathVal;
    }

    // =========================================================================
    // exec.Command 的三种执行形态
    // =========================================================================

    /**
     * 对应 Go 的 {@code cmd.CombinedOutput()}：stdout+stderr 合并，超时 kill。
     *
     * <p>启动失败（命令不存在等）返回 {@code exitCode = -1, output = ""}
     * （Go 返回 err 非 nil、output 为空切片）。
     * 超时同样 kill 后返回已捕获的部分输出与 {@code -1}
     * （Go 的 {@code CommandContext} 返回 {@code context deadline exceeded}）。
     */
    public static Result run(Duration timeout, String... args) {
        return exec(timeout, args, true);
    }

    /**
     * 对应 Go 的 {@code cmd.Output()}：只要 stdout（stderr 丢弃）。
     *
     * <p>{@code getTTLByPing}（scan.go:1330）与 {@code getMACAddress}（scan.go:1987）
     * 用这个形态。启动失败/超时同样返回 {@code -1}。
     */
    public static Result output(Duration timeout, String... args) {
        return exec(timeout, args, false);
    }

    /**
     * 对应 Go 的 {@code cmd.Run()}：不关心输出，只要成败（
     * {@code isAliveByICMPPing}，scan_optimized.go:871）。
     */
    public static boolean runOrStart(Duration timeout, String... args) {
        return exec(timeout, args, false).ok();
    }

    private static Result exec(Duration timeout, String[] args, boolean mergeStderr) {
        if (args == null || args.length == 0) {
            return new Result(NOT_STARTED, "");
        }
        // Go: path, err := LookPathSafe(args[0])；err != nil 时直接返回错误
        String path = lookPathSafe(args[0]);
        if (path == null) {
            return new Result(NOT_STARTED, "");
        }

        List<String> command = new ArrayList<>(args.length);
        // Go: cmd.Args[0] = 原始命令名、cmd.Path = 绝对路径；
        // Java 的 ProcessBuilder 只有一个列表（第 0 项既是可执行文件又是 argv[0]），
        // 故此处先放原名、随后用解析出的绝对路径覆盖 —— argv[0] 差异对 ping/arp 无影响。
        command.add(args[0]);
        for (int i = 1; i < args.length; i++) {
            command.add(args[i]);
        }

        ProcessBuilder pb = new ProcessBuilder(command);
        if (mergeStderr) {
            pb.redirectErrorStream(true);
        } else {
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
        }
        // 指定可执行文件绝对路径，避免 JVM/OS 再走一次 PATH 查找
        pb.command().set(0, path);

        Process process;
        try {
            process = pb.start();
        } catch (IOException e) {
            return new Result(NOT_STARTED, "");
        }

        long nanos = timeout == null || timeout.isNegative() ? Long.MAX_VALUE : timeout.toNanos();
        try (InputStream in = process.getInputStream()) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            Thread reader = new Thread(() -> drain(in, buf), "jyscan-exec-reader");
            reader.setDaemon(true);
            reader.start();

            boolean finished;
            if (nanos == Long.MAX_VALUE) {
                process.waitFor();  // 无超时：阻塞到结束（void 返回）
                finished = true;
            } else {
                finished = process.waitFor(nanos, TimeUnit.NANOSECONDS);
            }
            if (!finished) {
                process.destroyForcibly();
                process.waitFor(500, TimeUnit.MILLISECONDS);
                reader.join(1000);
                return new Result(NOT_STARTED, decode(buf.toByteArray()));
            }
            reader.join(1000);
            return new Result(process.exitValue(), decode(buf.toByteArray()));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return new Result(NOT_STARTED, decode(new byte[0]));
        } catch (IOException e) {
            return new Result(NOT_STARTED, "");
        }
    }

    private static void drain(InputStream in, ByteArrayOutputStream buf) {
        byte[] chunk = new byte[4096];
        try {
            int n;
            while ((n = in.read(chunk)) > 0) {
                synchronized (buf) {
                    buf.write(chunk, 0, n);
                }
            }
        } catch (IOException ignored) {
            // 进程被 kill 时流会关闭，忽略
        }
    }

    /**
     * 字节 → 字符串：Go 直接 {@code string(output)}（不转码，ASCII 子串搜索按字节比较）。
     * Java 侧用 UTF-8 解码 + 替换非法序列，保证 ASCII 子串
     * （{@code "bytes from"} / {@code "ttl="} / {@code "Reply from"} 等）
     * 与 Go 的字节级搜索结果完全一致。
     */
    private static String decode(byte[] bytes) {
        if (bytes.length == 0) {
            return "";
        }
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        try {
            return decoder.decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }
}

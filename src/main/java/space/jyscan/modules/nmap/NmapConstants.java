package space.jyscan.modules.nmap;

import java.time.Duration;

/**
 * scan 模块常量，移植自 freeclient/internal/nmap/scan.go 的 const 块。
 *
 * <p>与 Go 逐值对齐：端口状态串、端口范围、超时、并发、-T 速度模板、TTL 与网络距离。
 * 这些常量被 {@code NmapScanEngine}、{@code NmapUtils}、{@code ScanCommand} 共同引用，
 * 故集中在此，避免并行移植时各处重复定义而产生偏差。
 */
public final class NmapConstants {

    private NmapConstants() {
    }

    // ==================== 端口状态（nmap 六种状态） ====================
    public static final String PORT_STATE_OPEN = "open";
    public static final String PORT_STATE_CLOSED = "closed";
    public static final String PORT_STATE_FILTERED = "filtered";
    public static final String PORT_STATE_UNFILTERED = "unfiltered";
    public static final String PORT_STATE_OPEN_FILTERED = "open|filtered";
    public static final String PORT_STATE_CLOSED_FILTERED = "closed|filtered";

    // ==================== 端口范围 ====================
    public static final int MIN_PORT = 1;
    public static final int MAX_PORT = 65535;
    public static final String DEFAULT_SCAN_PORT_RANGE = "1-10000";
    public static final String FULL_PORT_SCAN_RANGE = "1-65535";

    // ==================== 超时（Go time.Duration） ====================
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(3);
    public static final Duration LONG_TIMEOUT = Duration.ofMinutes(5);
    public static final Duration SLOW_TIMEOUT = Duration.ofSeconds(15);
    public static final Duration MEDIUM_TIMEOUT = Duration.ofMillis(400);
    public static final Duration FAST_TIMEOUT = Duration.ofSeconds(1);
    /** 超高速模式: 5ms 初始超时。 */
    public static final Duration INSANE_TIMEOUT = Duration.ofMillis(5);

    // ==================== 并发线程数 ====================
    public static final int PARANOID_THREADS = 1;
    public static final int POLITE_THREADS = 10;
    public static final int DEFAULT_THREADS = 50;
    public static final int AGGRESSIVE_THREADS = 100;
    /** 超高速模式: 2000 并发连接。 */
    public static final int INSANE_THREADS = 2000;

    // ==================== -T 速度模板（完全模仿 nmap -T） ====================
    public static final int TIMING_PARANOID = 0;
    public static final int TIMING_SNEAKY = 1;
    public static final int TIMING_POLITE = 2;
    public static final int TIMING_NORMAL = 3;
    public static final int TIMING_AGGRESSIVE = 4;
    public static final int TIMING_INSANE = 5;

    // ==================== OS 识别用 TTL ====================
    public static final int WINDOWS_DEFAULT_TTL = 128;
    public static final int LINUX_DEFAULT_TTL = 64;
    public static final int UNIX_DEFAULT_TTL = 255;

    // ==================== 网络距离估计 ====================
    public static final int LOCAL_NETWORK_DISTANCE = 1;
    public static final int PRIVATE_NETWORK_DISTANCE = 2;
    public static final int MIN_GEOGRAPHIC_DISTANCE = 5;
    public static final int MAX_GEOGRAPHIC_DISTANCE = 15;

    // ==================== 进度显示频率 ====================
    public static final int PROGRESS_DISPLAY_FREQUENCY = 100;

    // ==================== Banner 读取超时 ====================
    public static final Duration BANNER_READ_TIMEOUT = Duration.ofSeconds(2);

    // ==================== 主机发现的最少确认方法数 ====================
    public static final int MIN_CONFIRMATION_METHODS = 2;

    // ==================== 主机状态 ====================
    public static final String HOST_UP = "up";
    public static final String HOST_DOWN = "down";
}

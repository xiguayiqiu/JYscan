package space.jyscan.modules.nmap;

import java.time.Duration;

/**
 * 超高速扫描配置，移植自 freeclient/internal/nmap/scan_optimized.go 的
 * {@code UltraFastScanConfig}(126) 与 {@code DefaultUltraFastConfig}(144)、
 * {@code getUltraConfigForTiming}(738)。
 *
 * <p><b>归属</b>：本文件由 B 号子代理新建。
 *
 * <p>字段与 Go 结构体一一对应（Go 导出字段首字母大写，Java 用小驼峰 + public）。
 * Go 的速度模板配置<b>只有 5 个预设值</b>，其余字段是 Go 零值
 * （{@code EnableVerbose=false}、{@code GrabBanner=true}、{@code SkipBannerOnAll=true}、
 * {@code MaxRetries} 见各 case），Java 逐个 case 显式赋值以复刻同样的零值语义。
 */
public class UltraFastScanConfig {

    /** 目标 IP（Go: {@code IP}），主要供进度显示用。 */
    public String ip = "";

    /** 端口列表（Go: {@code Ports []int}）。{@code UltraFastScan} 的端口由入参传入，此字段按 Go 结构体保留。 */
    public java.util.List<Integer> ports;

    /** 并发 worker 数。 */
    public int concurrency;

    /** 初始超时（快速轮）。 */
    public Duration initialTimeout = Duration.ZERO;

    /** 重试超时。 */
    public Duration retryTimeout = Duration.ZERO;

    /** 最终超时。 */
    public Duration finalTimeout = Duration.ZERO;

    /** 最大重试次数（对应 Go 的轮次门槛：{@code >=1} 跑重试轮、{@code >=2} 跑确认轮）。 */
    public int maxRetries;

    /** Banner 抓取超时。 */
    public Duration bannerTimeout = Duration.ZERO;

    /** 是否抓取 Banner。 */
    public boolean grabBanner;

    /** 是否显示详细信息（结束时的 verbose 汇总行）。 */
    public boolean enableVerbose;

    /** 是否在所有端口扫描完成后才抓取 Banner。 */
    public boolean skipBannerOnAll;

    /**
     * 深拷贝。
     *
     * <p><b>与 Go 的差异</b>：Go 的 {@code NmapScanOptimized} 里所有 host <b>共用同一个
     * {@code *UltraFastScanConfig} 指针</b>，逐 host 改写 {@code config.IP} 是数据竞争
     * （scan_optimized.go:679-681）；Java 侧每个 host 用这里的 {@code copy()} 得到独立副本，
     * 结果相同但无竞争。已在移植报告中记录。
     */
    public UltraFastScanConfig copy() {
        UltraFastScanConfig c = new UltraFastScanConfig();
        c.ip = ip;
        c.ports = ports == null ? null : new java.util.ArrayList<>(ports);
        c.concurrency = concurrency;
        c.initialTimeout = initialTimeout;
        c.retryTimeout = retryTimeout;
        c.finalTimeout = finalTimeout;
        c.maxRetries = maxRetries;
        c.bannerTimeout = bannerTimeout;
        c.grabBanner = grabBanner;
        c.enableVerbose = enableVerbose;
        c.skipBannerOnAll = skipBannerOnAll;
        return c;
    }

    /** 对应 Go 的 {@code DefaultUltraFastConfig()}（scan_optimized.go:144）。 */
    public static UltraFastScanConfig defaultConfig() {
        UltraFastScanConfig c = new UltraFastScanConfig();
        c.concurrency = 500;
        c.initialTimeout = Duration.ofMillis(200);
        c.retryTimeout = Duration.ofMillis(400);
        c.finalTimeout = Duration.ofMillis(800);
        c.maxRetries = 2;
        c.bannerTimeout = Duration.ofSeconds(1);
        c.grabBanner = true;
        c.enableVerbose = false;
        c.skipBannerOnAll = true;
        return c;
    }

    /**
     * 对应 Go 的 {@code getUltraConfigForTiming(template)}（scan_optimized.go:738）。
     * 六个 case 的数值逐项抄自 Go；{@code default} 走 {@link #defaultConfig()}。
     * 各 case 未提及的字段在 Go 里是零值，这里也保持零值（{@code enableVerbose=false}）。
     */
    public static UltraFastScanConfig forTiming(int template) {
        UltraFastScanConfig c = new UltraFastScanConfig();
        switch (template) {
            case NmapConstants.TIMING_PARANOID:
                c.concurrency = 10;
                c.initialTimeout = Duration.ofMillis(3000);
                c.retryTimeout = Duration.ofMillis(5000);
                c.finalTimeout = Duration.ofMillis(8000);
                c.maxRetries = 3;
                c.bannerTimeout = Duration.ofSeconds(5);
                break;
            case NmapConstants.TIMING_SNEAKY:
                c.concurrency = 50;
                c.initialTimeout = Duration.ofMillis(2000);
                c.retryTimeout = Duration.ofMillis(3000);
                c.finalTimeout = Duration.ofMillis(5000);
                c.maxRetries = 2;
                c.bannerTimeout = Duration.ofSeconds(3);
                break;
            case NmapConstants.TIMING_POLITE:
                c.concurrency = 200;
                c.initialTimeout = Duration.ofMillis(1500);
                c.retryTimeout = Duration.ofMillis(2500);
                c.finalTimeout = Duration.ofMillis(4000);
                c.maxRetries = 2;
                c.bannerTimeout = Duration.ofSeconds(2);
                break;
            case NmapConstants.TIMING_NORMAL:
                c.concurrency = 500;
                c.initialTimeout = Duration.ofMillis(1000);
                c.retryTimeout = Duration.ofMillis(2000);
                c.finalTimeout = Duration.ofMillis(3000);
                c.maxRetries = 2;
                c.bannerTimeout = Duration.ofSeconds(2);
                break;
            case NmapConstants.TIMING_AGGRESSIVE:
                c.concurrency = 800;
                c.initialTimeout = Duration.ofMillis(600);
                c.retryTimeout = Duration.ofMillis(1200);
                c.finalTimeout = Duration.ofMillis(2000);
                c.maxRetries = 2;
                c.bannerTimeout = Duration.ofSeconds(1);
                break;
            case NmapConstants.TIMING_INSANE:
                c.concurrency = 1000;
                c.initialTimeout = Duration.ofMillis(400);
                c.retryTimeout = Duration.ofMillis(800);
                c.finalTimeout = Duration.ofMillis(1500);
                c.maxRetries = 2;
                c.bannerTimeout = Duration.ofSeconds(1);
                break;
            default:
                return defaultConfig();
        }
        // Go 各 case 的 GrabBanner/SkipBannerOnAll 显式为 true，EnableVerbose 为零值
        c.grabBanner = true;
        c.enableVerbose = false;
        c.skipBannerOnAll = true;
        return c;
    }
}

package space.jyscan.modules.whois;

import java.time.Duration;

/**
 * Whois 查询结果，对应 Go 的 {@code whois.WhoisResult}：
 * Query / Raw / Parsed / Error / StartTime / EndTime。
 */
public final class WhoisResult {

    /** 查询目标。 */
    public String query = "";

    /** Whois 原始响应；查询失败且未取得任何响应时为空串。 */
    public String raw = "";

    /** 解析结果；查询失败时为 null。 */
    public WhoisInfo parsed;

    /** 错误信息；非空表示查询或解析失败（对应 Go 的 Error 字段）。 */
    public String error;

    /** 查询开始时刻（System.nanoTime）。 */
    public long startNanos;

    /** 查询结束时刻（System.nanoTime），在解析之前记录，与 Go 的 EndTime 一致。 */
    public long endNanos;

    /** 耗时，对应 Go 的 {@code EndTime.Sub(StartTime)}。 */
    public Duration cost() {
        long end = endNanos != 0 ? endNanos : System.nanoTime();
        return Duration.ofNanos(Math.max(0L, end - startNanos));
    }
}

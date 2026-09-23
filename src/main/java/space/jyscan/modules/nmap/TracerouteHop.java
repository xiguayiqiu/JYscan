package space.jyscan.modules.nmap;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 路由追踪的一跳，移植自 freeclient/internal/nmap/scan.go 的 TracerouteHop。
 *
 * <p><b>RTT 单位</b>：Go 的 {@code time.Duration} 经 encoding/json 序列化为<b>纳秒整数</b>，
 * 故这里用 {@code long rtt} 直接存纳秒，以保证 {@code SaveNmapResult} 的输出与 Go 逐字节一致；
 * 需要秒/毫秒时用 {@link #rttSeconds()} / {@link #rttMillis()} 换算（对应 Go 的
 * {@code hop.RTT.Seconds()} / {@code hop.RTT.Milliseconds()}）。
 *
 * <p>五个字段在 Go 中均无 omitempty，故始终输出。
 */
public class TracerouteHop {

    @JsonProperty("hop_number")
    public int hopNumber;

    @JsonProperty("ip")
    public String ip = "";

    @JsonProperty("hostname")
    public String hostname = "";

    /** RTT，单位纳秒（对应 Go time.Duration 的 JSON 表示）。 */
    @JsonProperty("rtt")
    public long rtt;

    @JsonProperty("status")
    public String status = "";

    /** 对应 Go 的 {@code hop.RTT.Seconds()}。 */
    public double rttSeconds() {
        return rtt / 1_000_000_000.0d;
    }

    /** 对应 Go 的 {@code hop.RTT.Milliseconds()}。 */
    public long rttMillis() {
        return rtt / 1_000_000L;
    }

    /** 对应 Go 的 {@code hop.RTT.String()}（如 "1.234ms"）。 */
    public String rttString() {
        double ns = rtt;
        if (ns < 1_000L) {
            return rtt + "ns";
        }
        if (ns < 1_000_000L) {
            return String.format("%.3fµs", ns / 1_000.0d);
        }
        if (ns < 1_000_000_000L) {
            return String.format("%.3fms", ns / 1_000_000.0d);
        }
        return String.format("%.3fs", ns / 1_000_000_000.0d);
    }

    @Override
    public String toString() {
        return rttString();
    }
}

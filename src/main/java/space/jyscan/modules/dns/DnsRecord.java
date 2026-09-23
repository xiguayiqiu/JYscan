package space.jyscan.modules.dns;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * DNS 监听记录，对应 Go 的 {@code dns.DNSRecord}。
 *
 * <p>JSON 字段名严格对齐 Go 的 tag（{@code id}/{@code timestamp}/{@code src_ip}/…），
 * 以便监听器输出的 {@code dns_records.json} 与 Go 版格式一致。
 *
 * <p>{@code timestamp} 在 Go 侧是 {@code time.Time}（JSON 为 RFC3339Nano）；
 * Java 侧用 {@code String} 存 RFC3339Nano 串以避开「未注册 JavaTimeModule 时
 * Jackson 无法序列化 Instant」的问题，同时另存 {@link #timestampNanos} 供
 * 延迟计算与 {@code 2006-01-02 15:04:05} 形式展示使用（该字段不参与序列化）。
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class DnsRecord {

    /** 记录唯一标识。 */
    public String id = "";

    /** 捕获时间，RFC3339Nano 字符串（对应 Go 的 time.Time）。 */
    @JsonProperty("timestamp")
    public String timestamp = "";

    /** 捕获时间的数值形式，仅用于内部延迟计算与格式化展示。 */
    @com.fasterxml.jackson.annotation.JsonIgnore
    public long timestampNanos;

    /** 源IP地址。 */
    @JsonProperty("src_ip")
    public String srcIp = "";

    /** 源端口。 */
    @JsonProperty("src_port")
    public int srcPort;

    /** 目标IP地址。 */
    @JsonProperty("dst_ip")
    public String dstIp = "";

    /** 目标端口。 */
    @JsonProperty("dst_port")
    public int dstPort;

    /** 查询域名（去尾点）。 */
    public String domain = "";

    /** DNS记录类型。 */
    @JsonProperty("record_type")
    public String recordType = "";

    /** DNS记录类别。 */
    @JsonProperty("record_class")
    public String recordClass = "";

    /** 响应状态码文本。 */
    @JsonProperty("response_code")
    public String responseCode = "";

    /** 响应状态码整数。 */
    @JsonProperty("response_code_int")
    public int responseCodeInt;

    /** 应答记录列表。 */
    @JsonProperty("answers")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<DnsAnswer> answers = new ArrayList<>();

    /** 权威记录列表。 */
    @JsonProperty("authorities")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<DnsAnswer> authorities = new ArrayList<>();

    /** 是否为响应包。 */
    @JsonProperty("is_response")
    public boolean isResponse;

    /** 查询ID。 */
    @JsonProperty("query_id")
    public int queryId;

    /** 请求到响应的延迟（纳秒），仅在匹配到请求-响应对时有值。 */
    @JsonProperty("latency")
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public long latencyNanos;

    /** 延迟毫秒数。 */
    @JsonProperty("latency_ms")
    public double latencyMs;

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    /** 用指定瞬时时刻填充 timestamp / timestampNanos。 */
    public void setTimestamp(Instant instant) {
        this.timestampNanos = instant.toEpochMilli() * 1_000_000L
                + (instant.getNano() % 1_000_000L);
        this.timestamp = rfc3339Nano(instant);
    }

    /**
     * 取指定瞬时时刻（供延迟计算），基于 {@link #timestampNanos}。 */
    public Instant instant() {
        return Instant.EPOCH.plusNanos(timestampNanos);
    }

    /** 对应 Go 的 {@code record.Timestamp.Format("2006-01-02 15:04:05")}。 */
    public String displayTime() {
        if (timestampNanos == 0) {
            return "";
        }
        return FMT.format(instant());
    }

    /**
     * RFC3339Nano 格式（对应 Go {@code time.Time} 的 JSON 输出）。
     *
     * <p>Go 的 RFC3339Nano 会去掉小数部分末尾的 0，这里同样裁剪；
     * 但 Go 在纳秒全为 0 时<b>不会</b>输出小数点，而 {@code ISO_OFFSET_DATE_TIME}
     * 会保留 {@code .000000000} —— 已在下方一并裁掉。
     */
    static String rfc3339Nano(Instant instant) {
        String s = DateTimeFormatter.ISO_OFFSET_DATE_TIME
                .format(instant.atZone(ZoneId.systemDefault()));
        int dot = s.indexOf('.');
        if (dot < 0) {
            return s;
        }
        // 小数部分止于偏移量（'Z' 或 ±hh:mm）
        int i = dot + 1;
        while (i < s.length() && Character.isDigit(s.charAt(i))) {
            i++;
        }
        String frac = s.substring(dot + 1, i);
        String rest = s.substring(i);
        int end = frac.length();
        while (end > 0 && frac.charAt(end - 1) == '0') {
            end--;
        }
        if (end == 0) {
            return s.substring(0, dot) + rest;
        }
        return s.substring(0, dot + 1 + end) + rest;
    }
}

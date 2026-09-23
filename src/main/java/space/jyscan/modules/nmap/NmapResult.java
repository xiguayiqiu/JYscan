package space.jyscan.modules.nmap;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 单个主机的扫描结果，移植自 freeclient/internal/nmap/scan.go 的 NmapResult。
 *
 * <p>该结构体是 {@code SaveNmapResult} 的序列化根对象，JSON 字段名与 omitempty 语义
 * 必须与 Go 逐字段对齐。Go 的规则是「只有标了 omitempty 的字段才省略」，因此
 * <b>不能</b>使用类级 {@code @JsonInclude}（会连 {@code ip}/{@code ports}/{@code status}
 * 这些无 omitempty 的字段一起省掉）。这里逐字段标注：
 * <ul>
 *   <li>无 omitempty：ip / ports / status → 不加注解，始终输出；</li>
 *   <li>字符串 omitempty：hostname / os / mac_address / mac_vendor → NON_EMPTY；</li>
 *   <li>切片 omitempty：os_guesses / services / service_fingerprints / traceroute → NON_EMPTY；</li>
 *   <li>int omitempty：network_distance → NON_DEFAULT。</li>
 * </ul>
 *
 * <p>{@code ports} 用带<b>字符串序</b>比较器的 TreeMap（见 {@link #ports()}），逐字节复现
 * Go encoding/json 对 map 键的排序；Go 的 nil map 输出 {@code null}，Java 的 null 同样输出 {@code null}。
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class NmapResult {

    /** 无 omitempty —— 始终输出。 */
    @JsonProperty("ip")
    public String ip = "";

    @JsonProperty("hostname")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String hostname = "";

    /**
     * 无 omitempty —— 始终输出（空为 {}，null 为 null）。
     *
     * <p>用带<b>字符串序</b>比较器的 {@link java.util.TreeMap}：Go 的 encoding/json 在序列化
     * map 时按「键的字符串形式」升序排列（实测 {@code map[int]PortInfo} 输出 22, 443, 80 ——
     * 既非插入序也非数值序），故此处比较 {@code Integer.toString} 才能逐字节对齐。
     * <b>赋值时勿换成 LinkedHashMap</b>，否则顺序退回插入序而与 Go 不符。
     */
    @JsonProperty("ports")
    public Map<Integer, PortInfo> ports = ports();

    @JsonProperty("os")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String os = "";

    @JsonProperty("os_guesses")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<String> osGuesses = new ArrayList<>();

    @JsonProperty("services")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<String> services = new ArrayList<>();

    @JsonProperty("service_fingerprints")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<ServiceFingerprint> serviceFingerprints = new ArrayList<>();

    /** 无 omitempty —— 始终输出（up/down）。 */
    @JsonProperty("status")
    public String status = "";

    @JsonProperty("mac_address")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String macAddress = "";

    @JsonProperty("mac_vendor")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String macVendor = "";

    @JsonProperty("network_distance")
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public int networkDistance;

    @JsonProperty("traceroute")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<TracerouteHop> traceroute = new ArrayList<>();

    /**
     * 重置为零值状态，对应 Go 的 {@code *NmapResult = NmapResult{}} 用法。
     *
     * @return this（便于链式调用）
     */
    public NmapResult reset() {
        ip = "";
        hostname = "";
        ports = ports();
        os = "";
        osGuesses = new ArrayList<>();
        services = new ArrayList<>();
        serviceFingerprints = new ArrayList<>();
        status = "";
        macAddress = "";
        macVendor = "";
        networkDistance = 0;
        traceroute = new ArrayList<>();
        return this;
    }

    /** 是否为活跃主机（对应 PrintNmapResult 中的 {@code result.Status == "up"}）。 */
    @JsonIgnore
    public boolean isUp() {
        return NmapConstants.HOST_UP.equals(status);
    }

    /**
     * 新建一个与 Go {@code map[int]PortInfo} 序列化顺序一致的端口表（按键的字符串序）。
     *
     * <p>扫描过程中新增端口时请用本方法重建，或直接放入既有 {@link #ports}，
     * 以保持与 Go encoding/json 的键排序一致。
     */
    public static Map<Integer, PortInfo> ports() {
        return new TreeMap<>((a, b) -> Integer.toString(a).compareTo(Integer.toString(b)));
    }
}

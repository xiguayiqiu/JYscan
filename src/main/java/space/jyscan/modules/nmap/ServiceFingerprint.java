package space.jyscan.modules.nmap;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 服务指纹（协议握手匹配结果），移植自 freeclient/internal/nmap/scan.go 的 ServiceFingerprint。
 *
 * <p>JSON 字段与 Go 的 tag 逐字段对齐：port/service/protocol 无 omitempty（始终输出），
 * version/fingerprint/extra_info 带 omitempty（为空即省）。故不能用类级 {@code @JsonInclude}。
 */
public class ServiceFingerprint {

    /** 无 omitempty —— 始终输出。 */
    @JsonProperty("port")
    public int port;

    /** 无 omitempty —— 始终输出。 */
    @JsonProperty("service")
    public String service = "";

    @JsonProperty("version")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String version = "";

    @JsonProperty("fingerprint")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String fingerprint = "";

    /** 无 omitempty —— 始终输出。 */
    @JsonProperty("protocol")
    public String protocol = "";

    @JsonProperty("extra_info")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public String extraInfo = "";

    public ServiceFingerprint copy() {
        ServiceFingerprint s = new ServiceFingerprint();
        s.port = port;
        s.service = service;
        s.version = version;
        s.fingerprint = fingerprint;
        s.protocol = protocol;
        s.extraInfo = extraInfo;
        return s;
    }
}

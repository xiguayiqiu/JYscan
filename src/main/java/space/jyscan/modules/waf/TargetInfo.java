package space.jyscan.modules.waf;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 采集的信息，移植自 freeclient/internal/waf/waf.go 的 TargetInfo 结构体。
 *
 * <p>响应头键统一按小写存储，{@link #header(String)} 提供与 Go http.Header.Get
 * 一致的大小写不敏感查询。
 */
public class TargetInfo {

    /** 实际可用的URL（首选协议失败并回退后为回退地址） */
    public String url = "";

    /** 响应头（键为小写） */
    public Map<String, List<String>> headers = new LinkedHashMap<>();

    /** 状态码 */
    public int statusCode;

    /** 响应体（限制10KB） */
    public String responseBody = "";

    /** 证书签发者 */
    public String certIssuer = "";

    /** 证书主体 */
    public String certSubject = "";

    /** 证书序列号 */
    public String certSerial = "";

    /** TTL（对应 Go 结构体，当前未使用） */
    public int ttl;

    /** TCP窗口大小（对应 Go 结构体，当前未使用） */
    public int tcpWindowSize;

    /** 大小写不敏感读取单个响应头，语义等同 Go 的 http.Header.Get。 */
    public String header(String name) {
        if (name == null || headers == null) {
            return "";
        }
        List<String> values = headers.get(name.toLowerCase(Locale.ROOT));
        if (values == null || values.isEmpty()) {
            return "";
        }
        return values.get(0);
    }
}

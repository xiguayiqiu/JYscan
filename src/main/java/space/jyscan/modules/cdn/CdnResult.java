package space.jyscan.modules.cdn;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CDN 识别结果，对应 Go 的 {@code cdn.CDNResult}。
 *
 * <p>Go 的 {@code Duration time.Duration} 在这里用 {@link Duration} 表示，
 * 输出时经 {@code Fmt.format("%v", ...)} 渲染成 Go 风格时长串。
 */
public final class CdnResult {

    /** 目标域名（已清洗）。 */
    public String target = "";

    /** 是否检测到 CDN。 */
    public boolean isCDN;

    /** CDN 服务商名称。 */
    public String cdnName = "";

    /** CDN 厂商。 */
    public String cdnVendor = "";

    /** 判定证据。 */
    public String cdnEvidence = "";

    /** 云服务提供商。 */
    public String cloudProvider = "";

    /** 域名注册商。 */
    public String registrar = "";

    /** CNAME 记录。 */
    public String cname = "";

    /** A 记录解析出的 IP 列表。 */
    public List<String> ips = new ArrayList<>();

    /** NS 记录列表。 */
    public List<String> nameServers = new ArrayList<>();

    /** HTTP 响应头（键保留原始大小写，值按 Go 用 ", " 连接）。 */
    public Map<String, String> httpHeaders = new LinkedHashMap<>();

    /** 置信度（0-100）。 */
    public int confidence;

    /** 错误消息；空串表示无错误（对应 Go 的 ErrorMessage）。 */
    public String errorMessage = "";

    /** 识别耗时。 */
    public Duration duration = Duration.ZERO;
}

package space.jyscan.modules.nmap;

import java.time.Duration;

/**
 * 扫描配置，移植自 freeclient/internal/nmap/scan.go 的 ScanConfig。
 *
 * <p>Go 结构体无 json tag（不参与序列化），故此处不加 Jackson 注解，仅保留公共可变字段，
 * 由 {@code ScanCommand} 从 picocli flag 填充后传给 {@code NmapScanEngine.nmapScan}。
 * 所有默认值与 Go 零值一致；超时字段用 {@link Duration} 对应 Go 的 {@code time.Duration}。
 */
public class ScanConfig {

    public String target = "";
    /** -iL: 从文件读取目标列表 (支持txt/lst格式) */
    public String inputListFile = "";
    public String ports = "";
    public int threads;
    public Duration timeout = Duration.ZERO;
    /** syn, connect, udp */
    public String scanType = "";
    public boolean osDetection;
    public boolean serviceDetection;
    /** 扫描速度模板 (0-5, 完全模仿nmap -T参数) */
    public int timingTemplate;
    /** TTL检测，用于估算目标距离 */
    public boolean ttlDetection;
    /** 设置发送数据包的TTL值 (等同于nmap --ttl参数) */
    public int ttlValue;
    /** 全面扫描模式 (等同于nmap -A参数) */
    public boolean aggressiveScan;
    /** 碎片化扫描模式 (等同于nmap -f参数) */
    public boolean fragmentedScan;
    /** TCP扫描模式 (等同于nmap -sT参数) */
    public boolean tcpScan;
    /** UDP扫描模式 (等同于nmap -sU参数) */
    public boolean udpScan;
    /** 主机存活探测模式 (等同于nmap -sn参数) */
    public boolean hostDiscovery;
    /** 跳过主机发现，直接扫描端口 (等同于nmap -Pn参数) */
    public boolean pn;
    /** IPv6扫描模式 (等同于nmap -6参数) */
    public boolean ipv6;

    // ==================== 智能存活探测增强 ====================
    /** 启用WAF检测，识别云WAF拦截页面 */
    public boolean enableWAFDetect;
    /** 启用SimHash页面相似度检测 */
    public boolean enableSimHash;
    /** SimHash相似度阈值 (Hamming距离) */
    public int simHashThreshold;
    /** WAF检测置信度阈值 */
    public double wafThreshold;
    /** 过滤WAF拦截的目标 */
    public boolean filterWAF;
    /** HTTP请求超时 */
    public Duration httpTimeout = Duration.ZERO;

    // ==================== 内容探测 (-X) ====================
    /** 是否启用内容探测 */
    public boolean contentProbe;
    /** 单端口内容探测超时 */
    public Duration contentProbeTimeout = Duration.ZERO;
    /** 内容探测并发数 */
    public int contentProbeConcurrency;

    public ScanConfig copy() {
        ScanConfig c = new ScanConfig();
        c.target = target;
        c.inputListFile = inputListFile;
        c.ports = ports;
        c.threads = threads;
        c.timeout = timeout;
        c.scanType = scanType;
        c.osDetection = osDetection;
        c.serviceDetection = serviceDetection;
        c.timingTemplate = timingTemplate;
        c.ttlDetection = ttlDetection;
        c.ttlValue = ttlValue;
        c.aggressiveScan = aggressiveScan;
        c.fragmentedScan = fragmentedScan;
        c.tcpScan = tcpScan;
        c.udpScan = udpScan;
        c.hostDiscovery = hostDiscovery;
        c.pn = pn;
        c.ipv6 = ipv6;
        c.enableWAFDetect = enableWAFDetect;
        c.enableSimHash = enableSimHash;
        c.simHashThreshold = simHashThreshold;
        c.wafThreshold = wafThreshold;
        c.filterWAF = filterWAF;
        c.httpTimeout = httpTimeout;
        c.contentProbe = contentProbe;
        c.contentProbeTimeout = contentProbeTimeout;
        c.contentProbeConcurrency = contentProbeConcurrency;
        return c;
    }
}

package space.jyscan.modules.nmap;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 扫描结果分析，移植自 freeclient/internal/nmap/utils.go 的 ScanAnalysis。
 *
 * <p><b>归属</b>：本类型连同 {@code AnalyzeResults} 由 E 号子代理实现（utils.go）。
 * 类型定义放共享层，因为它是 {@code NmapUtils.analyzeResults} 的返回类型，
 * 调用方（未来的报告/统计扩展）可能跨模块。Go 侧无 json tag，不参与序列化。
 */
public class ScanAnalysis {

    public int totalHosts;
    public int activeHosts;
    public int totalOpenPorts;
    /**
     * 端口号 -> 该端口开放的主机数。
     *
     * <p>用 TreeMap（数值序）而非插入序：Go 侧该 map 只会被 {@code fmt} 打印，
     * 而 Go 的 fmt 自 Go 1.12 起对 map 按键排序输出，TreeMap 保证 Java 复印时顺序一致。
     */
    public Map<Integer, Integer> openPorts = new TreeMap<>();
    /** 服务名 -> 出现次数（TreeMap 键序 ≈ Go fmt 对 map 的排序打印）。 */
    public Map<String, Integer> services = new TreeMap<>();
    /** OS 名 -> 出现次数（同上）。 */
    public Map<String, Integer> os = new TreeMap<>();
    public int unknownServices;
    public List<String> vulnerable = new ArrayList<>();
}

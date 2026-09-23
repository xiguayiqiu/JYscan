package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

import space.jyscan.core.i18n.I18n;
import space.jyscan.modules.nmap.NmapResult;
import space.jyscan.modules.nmap.NmapScan;
import space.jyscan.modules.nmap.NmapUtils;
import space.jyscan.modules.nmap.ScanConfig;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * scan 命令（nmap 模块），移植自 freeclient/internal/nmap/cmd.go。
 *
 * <p><b>归属</b>：集成者直接接管（原 A 号子代理长时间无产出）。
 *
 * <p>flag 的长名、短名、默认值、扫描类型判定优先级、-A 联动、-Pn/-sn 互斥提示、
 * 单目标与 -iL 批量两条路径、结果打印与落盘时机均与 cmd.go 逐行对应。
 *
 * <p><b>已知偏差</b>：
 * <ul>
 *   <li>{@code --script} / {@code --script-args} / {@code --script-list} 的 YScript 引擎
 *       （internal/nmap/yscript.go 等）<b>本批次放弃移植</b>，三个 flag 保留但只打印
 *       移植延期提示后返回 0；文案暂为硬编码中文，因 {@code core/i18n} 为只读约定且
 *       暂无对应 key，待 i18n 批次补 key 后改用 {@link I18n#T}。</li>
 *   <li>cobra 对参数校验失败返回 0，本项目沿用既定约定返回 1
 *       （目标格式非法、-iL 文件读取失败/为空）。</li>
 *   <li>Go 的 {@code context.Context} 未移植，中断由 JVM 关闭钩子负责，见
 *       {@link space.jyscan.modules.nmap.NmapScan}。</li>
 * </ul>
 */
@Command(
        name = "scan",
        description = "网络扫描工具，支持主机发现、端口扫描、服务识别及WAF/假死检测",
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true,
        header = {
                "",
                "JYscan Nmap模块 - 网络扫描工具",
                "",
                "支持功能:",
                "- 存活主机发现 (ICMP Ping + TCP探测)",
                "- 端口扫描 (TCP SYN/Connect/UDP)",
                "- 服务识别 (协议握手包匹配)",
                "- 系统识别 (OS指纹识别)",
                "- 网段扫描 (CIDR/IP范围)",
                "- 智能存活探测增强 (WAF/假死识别) *",
                "- 多目标批量扫描 (-iL)",
                "",
                "简化命令 (nmap风格):",
                "  -O: 启用系统识别 (等同于 --os-detection)",
                "  -s: 启用服务识别 (等同于 --service-detection)",
                "",
                "新增参数:",
                "  --waf: 启用WAF检测，识别云WAF拦截页面",
                "  --simhash: 启用SimHash页面相似度检测",
                "  --filter-waf: 过滤WAF拦截的目标",
                "  -X: 内容探测，对已开放端口进行内容探测，获取端口回复的内容",
                "  --content-probe-timeout: 内容探测单端口超时(秒)，0 表示沿用 -w/--timeout",
                "  --content-probe-threads: 内容探测并发数 (默认32)",
                "  -iL: 从文件读取目标列表 (支持.txt/.lst格式)",
                "  --script: 存在该参数时直接运行 YScript 脚本，跳过端口扫描/服务识别",
                "  --script-args: 传递给 YScript 脚本的参数",
                "",
                "默认行为:",
                "  默认仅显示端口状态信息 (nmap的六种状态)",
                "  使用-s参数显示服务信息",
                "  使用-O参数探测系统信息",
                "",
                "用法:",
                "  1. 直接传递目标: JYscan scan 目标 [选项]",
                "  2. 使用--target标志: JYscan scan --target 目标 [选项]",
                "  3. 使用-iL参数: JYscan scan -iL targets.txt [选项]",
                "  4. 获取帮助: JYscan scan help",
                "",
                "-iL参数说明:",
                "  -iL <file>: 从文件读取目标列表，支持txt/lst格式",
                "  文件中每行一个目标，支持以下格式:",
                "    - IP地址: 192.168.1.1",
                "    - CIDR网段: 192.168.1.0/24",
                "    - IP范围: 192.168.1.1-100",
                "    - 域名: example.com",
                "  以#开头的行视为注释将被忽略",
                "",
                "示例用法:",
                "  ./JYscan scan 192.168.1.1/24",
                "  ./JYscan scan 192.168.1.1-192.168.1.100 -p 22,80,443",
                "  ./JYscan scan example.com -p 1-1000 -n 100",
                "  ./JYscan scan 10.0.0.0/8 -O -V",
                "  ./JYscan scan 192.168.1.1 -O -V -p 1-1000",
                "  ./JYscan scan --target 192.168.1.1/24",
                "  ./JYscan scan --target example.com --ports 1-1000 --threads 100",
                "  ./JYscan scan 1.1.1.1 --waf --simhash --filter-waf",
                "  ./JYscan scan -iL targets.txt",
                "  ./JYscan scan -iL hosts.lst -p 80,443 -n 50",
                "  ./JYscan scan -iL targets.txt -A -o scan_results.json"
        },
        footer = {
                "",
                "-T参数说明:",
                "  0: 偏执 (Paranoid) - 非常慢的扫描，用于IDS规避",
                "  1: 鬼祟 (Sneaky) - 慢速扫描，IDS规避",
                "  2: 礼貌 (Polite) - 降低速度以减少对目标系统的影响",
                "  3: 普通 (Normal) - 默认速度，平衡速度和隐蔽性",
                "  4: 激进 (Aggressive) - 快速扫描，可能被检测到",
                "  5: 疯狂 (Insane) - 极速扫描，容易被检测",
                "",
                "扫描类型参数说明:",
                "  --sT: TCP连接扫描 (nmap -sT)",
                "  --sU: UDP扫描",
                "  --sS: SYN扫描",
                "  --sF: TCP FIN扫描 (检测open|filtered状态)",
                "  --sX: TCP XMAS扫描 (检测open|filtered状态)",
                "  --sN: TCP NULL扫描 (检测open|filtered状态)",
                "  --sA: TCP ACK扫描 (检测unfiltered状态)",
                "  --sW: TCP窗口扫描",
                "  --sM: TCP Maimon扫描",
                "",
                "服务识别和系统识别:",
                "  --O: 启用系统识别",
                "  --sV: 启用服务识别",
                "",
                "全面扫描模式 (--A):",
                "  启用全面扫描模式，等同于同时使用以下功能:",
                "  - 启用系统识别 (--O)",
                "  - 启用服务识别 (--sV)",
                "  - 设置扫描速度为激进模式 (-T4)",
                "  这是nmap -A参数的完全实现",
                "",
                "碎片化扫描模式 (--f):",
                "  碎片化扫描模式 (等同于nmap -f参数，数据包分片发送以规避检测)",
                "",
                "主机存活探测模式 (--sn):",
                "  仅进行主机存活探测，跳过端口扫描",
                "  采用多协议组合探测（ICMP Ping + TCP SYN/ACK + UDP），提高准确性",
                "  适用于快速发现网络中的在线主机，效率远高于全端口扫描",
                "",
                "TTL参数说明:",
                "  --ttl: 启用TTL检测，通过分析响应TTL值估算目标网络距离",
                "  --ttl-value: 设置发送数据包的TTL值 (等同于nmap --ttl参数)",
                "",
                "智能存活探测增强 (WAF/假死过滤):",
                "  --waf: 启用WAF检测，识别阿里云、腾讯云、Cloudflare等常见WAF拦截页面",
                "  --simhash: 启用SimHash页面相似度检测，自动过滤相同拦截页面",
                "  --sim-threshold: SimHash相似度阈值，Hamming距离小于此值视为相似页面 (默认10)",
                "  --waf-threshold: WAF检测置信度阈值，高于此值才认为是WAF拦截 (默认0.4)",
                "  --filter-waf: 过滤WAF拦截的目标，仅输出有效资产",
                "",
                "内容探测 (-X):",
                "  -X: 在常规端口探测的基础上，对已开放端口进行内容探测",
                "  探测方式根据端口服务/端口号自动选择 (HTTP / HTTPS / TLS / 原始TCP)",
                "  候选协议按「服务名线索 > 端口线索 > 通用兜底」排序，同名探测器自动去重，",
                "  单个端口最多执行 5 个探测器，避免重复建连与无效等待",
                "  端口回复内容同时写入结果 JSON (字段: ports.<port>.content)",
                "  探测结果按语义着色输出，可用 --no-color 关闭彩色输出",
                "  --content-probe-timeout: 内容探测单端口超时(秒)，0 表示沿用 -w/--timeout",
                "  --content-probe-threads: 内容探测并发数 (默认32)",
                "",
                "YScript脚本集成 (--script):",
                "  本版本未包含 YScript 脚本引擎，--script / --script-args / --script-list",
                "  暂不可用（保留参数以维持与 Go 版的命令行兼容）。",
                "",
                "端口状态说明:",
                "  open: 端口开放，有服务监听",
                "  closed: 端口关闭，无服务监听",
                "  filtered: 端口被过滤，无法确定状态",
                "  unfiltered: 端口可达，但无法判断开放/关闭（ACK扫描）",
                "  open|filtered: 开放或过滤状态（FIN/XMAS/NULL/UDP扫描）",
                "  closed|filtered: 关闭或过滤状态（IP ID空闲扫描）"
        }
)
public class ScanCommand implements Callable<Integer> {

    /**
     * YScript 引擎延期提示。
     *
     * <p>硬编码中文：{@code core/i18n} 为只读约定且当前无对应 key，待 i18n 批次补
     * {@code nmap.err.script_deferred} 后改用 {@link I18n#T}。
     */
    private static final String SCRIPT_DEFERRED =
            "脚本引擎尚未移植，--script 暂不可用（YScript 为后续批次）";

    /** content_probe.go:48 默认内容探测超时 5s。 */
    private static final int CONTENT_PROBE_DEFAULT_TIMEOUT_SECONDS = 5;

    /** content_probe.go:50 默认内容探测并发数。 */
    private static final int CONTENT_PROBE_DEFAULT_CONCURRENCY = 32;

    // ==================== 目标与输入 ====================
    @Option(names = {"-t", "--target"},
            description = "扫描目标 (IP/CIDR/IP范围/域名)")
    String targetFlag;

    @Option(names = {"--iL"},
            description = "从文件读取目标列表 (支持txt/lst格式)")
    String inputListFile = "";

    @Option(names = {"-p", "--ports"},
            description = "指定扫描端口 (默认: 1-1000, 支持: 80,443, 1-1000, 22,80,443, -p- 表示全端口扫描)")
    String ports = "";

    @Option(names = {"-n", "--threads"},
            description = "并发线程数", defaultValue = "50")
    int threads;

    @Option(names = {"-w", "--timeout"},
            description = "扫描超时时间(秒)", defaultValue = "3")
    int timeout;

    @Option(names = {"-T", "--timing"},
            description = "扫描速度级别 (0-5, 完全模仿nmap -T参数)", defaultValue = "3")
    int timingTemplate;

    @Option(names = {"-o", "--output"},
            description = "结果输出文件")
    String output = "";

    // ==================== 扫描类型参数（nmap标准参数） ====================
    @Option(names = {"--sT"}, description = "TCP连接扫描 (nmap -sT)")
    boolean tcpScan;

    @Option(names = {"--sU"}, description = "UDP扫描")
    boolean udpScan;

    @Option(names = {"--sS"}, description = "SYN扫描")
    boolean synScan;

    // ==================== 隐蔽扫描类型参数（用于检测filtered状态） ====================
    @Option(names = {"--sF"}, description = "TCP FIN扫描 (检测open|filtered状态)")
    boolean finScan;

    @Option(names = {"--sX"}, description = "TCP XMAS扫描 (检测open|filtered状态)")
    boolean xmasScan;

    @Option(names = {"--sN"}, description = "TCP NULL扫描 (检测open|filtered状态)")
    boolean nullScan;

    @Option(names = {"--sA"}, description = "TCP ACK扫描 (检测unfiltered状态)")
    boolean ackScan;

    @Option(names = {"--sW"}, description = "TCP窗口扫描")
    boolean windowScan;

    @Option(names = {"--sM"}, description = "TCP Maimon扫描")
    boolean maimonScan;

    // ==================== 服务识别和系统识别标志 ====================
    @Option(names = {"-O", "--O"}, description = "启用系统识别")
    boolean osDetection;

    @Option(names = {"--sV"}, description = "启用服务识别")
    boolean serviceDetection;

    // ==================== 全面扫描模式 (nmap -A) ====================
    @Option(names = {"-A", "--A"},
            description = "全面扫描模式 (等同于nmap -A参数)")
    boolean aggressiveScan;

    // ==================== 碎片化扫描模式 (nmap -f) ====================
    @Option(names = {"-f", "--f"},
            description = "碎片化扫描模式 (等同于nmap -f参数，数据包分片发送以规避检测)")
    boolean fragmentedScan;

    // ==================== 主机存活探测模式 (nmap -sn) ====================
    @Option(names = {"--sn"},
            description = "主机存活探测模式 (等同于nmap -sn参数，仅判断主机在线状态，跳过端口扫描)")
    boolean hostDiscovery;

    // ==================== 其他功能参数 ====================
    @Option(names = {"--ttl"},
            description = "启用TTL检测，估算目标距离")
    boolean ttlDetection;

    @Option(names = {"--ttl-value"},
            description = "设置发送数据包的TTL值 (等同于nmap --ttl参数)")
    int ttlValue;

    // ==================== 跳过主机发现，直接扫描端口 (nmap -Pn) ====================
    @Option(names = {"--Pn"},
            description = "跳过主机发现，直接扫描端口 (等同于nmap -Pn参数)")
    boolean pn;

    // ==================== IPv6扫描模式 (nmap -6) ====================
    @Option(names = {"-6", "--ipv6"},
            description = "IPv6扫描模式 (等同于nmap -6参数)")
    boolean ipv6;

    // ==================== YScript 脚本集成参数（本批次未移植，保留兼容） ====================
    @Option(names = {"--script"},
            description = "存在该参数时直接运行 YScript 脚本，跳过端口扫描/服务识别（本版本暂不可用）")
    String scriptFile = "";

    @Option(names = {"--script-args"},
            description = "传递给 YScript 脚本的参数（本版本暂不可用）")
    String scriptArgs = "";

    @Option(names = {"--script-list"},
            description = "列出全部可用脚本及其用途（本版本暂不可用）")
    boolean scriptList;

    // ==================== 智能存活探测增强参数 ====================
    @Option(names = {"--waf"},
            description = "启用WAF检测，识别阿里云、腾讯云、Cloudflare等常见WAF拦截页面")
    boolean enableWAFDetect;

    @Option(names = {"--simhash"},
            description = "启用SimHash页面相似度检测，自动过滤相同拦截页面")
    boolean enableSimHash;

    @Option(names = {"--sim-threshold"},
            description = "SimHash相似度阈值，Hamming距离小于此值视为相似页面 (默认10)", defaultValue = "10")
    int simHashThreshold;

    @Option(names = {"--waf-threshold"},
            description = "WAF检测置信度阈值，高于此值才认为是WAF拦截 (默认0.4)", defaultValue = "0.4")
    double wafThreshold;

    @Option(names = {"--filter-waf"},
            description = "过滤WAF拦截的目标，仅输出有效资产")
    boolean filterWAF;

    // ==================== 内容探测参数 (-X) ====================
    @Option(names = {"-X", "--X"},
            description = "内容探测，对常规端口探测发现的开放端口进行内容探测，获取端口回复的内容")
    boolean contentProbe;

    /** -X 专用调优参数：不设置时沿用 -w/--timeout 与默认并发度。 */
    @Option(names = {"--content-probe-timeout"},
            description = "内容探测单端口超时(秒)，0 表示沿用 -w/--timeout")
    int probeTimeout;

    @Option(names = {"--content-probe-threads"},
            description = "内容探测并发数 (默认32)", defaultValue = "" + CONTENT_PROBE_DEFAULT_CONCURRENCY)
    int probeThreads;

    // ==================== 位置参数：与 Go 的 MaximumNArgs(1) 对应 ====================
    @Parameters(arity = "0..1", paramLabel = "TARGET",
            description = "扫描目标（或 help 显示详细帮助）")
    List<String> params;

    @Spec
    CommandSpec spec;

    @Override
    public Integer call() {
        // cmd.go:139 --script-list 列出可用脚本（本批次放弃，直接返回）
        if (scriptList) {
            System.out.println(SCRIPT_DEFERRED);
            return 0;
        }

        // cmd.go:148 检查是否请求帮助
        if (params != null && !params.isEmpty() && "help".equals(params.get(0))) {
            nmapHelp();
            return 0;
        }

        // cmd.go:154-155 从命令行标志获取参数（--iL 已由注解填充）
        String targetFlagValue = targetFlag == null ? "" : targetFlag;
        String listFile = inputListFile == null ? "" : inputListFile;

        // cmd.go:160 --script 模式（本批次放弃，直接返回）
        if (scriptFile != null && !scriptFile.isEmpty()) {
            System.out.println(SCRIPT_DEFERRED);
            return 0;
        }

        // cmd.go:174 如果没有提供目标且没有-iL参数，显示帮助
        boolean hasPositional = params != null && !params.isEmpty();
        if (!hasPositional && listFile.isEmpty() && targetFlagValue.isEmpty()) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        // cmd.go:179-185 确定扫描目标：优先级: 位置参数 > --target
        String singleTarget = "";
        if (hasPositional) {
            singleTarget = params.get(0);
        } else if (!targetFlagValue.isEmpty()) {
            singleTarget = targetFlagValue;
        }

        // cmd.go:207-227 根据nmap参数设置扫描类型（优先级与 Go 完全一致）
        String actualScanType = "connect";
        if (tcpScan) {
            actualScanType = "connect";
        } else if (udpScan) {
            actualScanType = "udp";
        } else if (synScan) {
            actualScanType = "syn";
        } else if (finScan) {
            actualScanType = "fin";
        } else if (xmasScan) {
            actualScanType = "xmas";
        } else if (nullScan) {
            actualScanType = "null";
        } else if (ackScan) {
            actualScanType = "ack";
        } else if (windowScan) {
            actualScanType = "window";
        } else if (maimonScan) {
            actualScanType = "maimon";
        }

        // cmd.go:230-257 创建扫描配置
        ScanConfig config = new ScanConfig();
        config.ports = ports;
        config.threads = threads;
        config.timeout = Duration.ofSeconds(timeout);
        config.httpTimeout = Duration.ofSeconds(timeout);
        config.scanType = actualScanType;
        config.osDetection = osDetection;
        config.serviceDetection = serviceDetection;
        config.timingTemplate = timingTemplate;
        config.ttlDetection = ttlDetection;
        config.ttlValue = ttlValue;
        config.aggressiveScan = aggressiveScan;
        config.fragmentedScan = fragmentedScan;
        config.tcpScan = tcpScan;
        config.udpScan = udpScan;
        config.hostDiscovery = hostDiscovery;
        config.pn = pn;
        config.ipv6 = ipv6;
        config.enableWAFDetect = enableWAFDetect;
        config.enableSimHash = enableSimHash;
        config.simHashThreshold = simHashThreshold;
        config.wafThreshold = wafThreshold;
        config.filterWAF = filterWAF;
        // cmd.go:254-256 内容探测 (-X)
        config.contentProbe = contentProbe;
        config.contentProbeTimeout = Duration.ofSeconds(resolveContentProbeTimeout(timeout, probeTimeout));
        config.contentProbeConcurrency = probeThreads;

        // cmd.go:259 处理-iL参数：从文件读取目标列表
        if (!listFile.isEmpty()) {
            List<String> targets = NmapUtils.loadTargetsFromFile(listFile);
            if (targets.isEmpty()) {
                System.out.println(I18n.Tf("nmap.err.file_read_or_empty", listFile));
                System.out.println(I18n.T("nmap.err.file_format_hint"));
                return 1; // cobra 返回 0，本项目既定约定：校验失败返回 1
            }
            System.out.println(I18n.Tf("nmap.log.targets_from_file", targets.size()));

            applyAggressiveMode(config);
            warnPnSnConflict(config);

            long startTime = System.nanoTime();
            List<NmapResult> allResults = new ArrayList<>();

            // cmd.go:292 遍历每个目标进行扫描
            for (String tgt : targets) {
                if (!NmapUtils.validateTarget(tgt)) {
                    System.out.println(I18n.Tf("nmap.warn.target_invalid_skip", tgt));
                    continue;
                }
                config.target = tgt;
                allResults.addAll(NmapScan.nmapScan(config));
            }

            printDuration("nmap.log.batch_complete", startTime);
            NmapUtils.printNmapResult(allResults, config);
            saveIfRequested(allResults, output);
            return 0;
        }

        // cmd.go:321 使用单一目标
        String target = singleTarget;
        if (target.isEmpty()) {
            System.out.println(I18n.T("nmap.err.specify_target"));
            System.out.println(I18n.T("nmap.err.usage_hint"));
            System.out.println(I18n.T("nmap.err.or_use_il"));
            return 1;
        }

        // cmd.go:332 验证目标格式
        if (!NmapUtils.validateTarget(target)) {
            System.out.println(I18n.Tf("nmap.err.target_invalid", target));
            System.out.println(I18n.T("nmap.err.target_formats"));
            return 1; // cobra 返回 0，本项目既定约定：校验失败返回 1
        }

        config.target = target;

        // cmd.go:341 全面扫描模式 (-A) 联动
        applyAggressiveMode(config);
        // cmd.go:352 处理Pn和HostDiscovery的互斥关系（模仿nmap行为）
        warnPnSnConflict(config);

        // cmd.go:360 执行扫描
        long startTime = System.nanoTime();
        List<NmapResult> results = NmapScan.nmapScan(config);
        printDuration("nmap.log.scan_complete", startTime);

        NmapUtils.printNmapResult(results, config);
        saveIfRequested(results, output);
        return 0;
    }

    // =====================================================================
    // 与 cmd.go 对应的辅助函数
    // =====================================================================

    /**
     * cmd.go:269-277 / 341-350 启用全面扫描模式 (-A) 时自动启用相关功能。
     *
     * <p>Go 侧该逻辑在单目标与 -iL 批量两条路径中各出现一次，此处合并为一个方法，
     * 两处调用顺序与 Go 一致（均在读取目标之后、Pn/sn 互斥判断之前）。
     */
    private static void applyAggressiveMode(ScanConfig config) {
        if (!config.aggressiveScan) {
            return;
        }
        config.osDetection = true;
        config.serviceDetection = true;
        config.ttlDetection = true;
        // Go: if config.TimingTemplate < 4 { config.TimingTemplate = 4 }
        if (config.timingTemplate < 4) {
            config.timingTemplate = 4;
        }
    }

    /** cmd.go:280-282 / 353-355 -Pn 与 -sn 互斥提示。 */
    private static void warnPnSnConflict(ScanConfig config) {
        if (config.pn && config.hostDiscovery) {
            System.out.println(I18n.T("nmap.warn.pn_sn_mutual"));
        }
    }

    /** cmd.go:305-306 / 364-365 打印耗时（Go 的 time.Duration 经 %v 格式化）。 */
    private static void printDuration(String i18nKey, long startTimeNanos) {
        long elapsedNanos = System.nanoTime() - startTimeNanos;
        System.out.println(I18n.Tf(i18nKey, formatGoDuration(elapsedNanos)));
    }

    /**
     * 复刻 Go {@code time.Duration.String()}（即 i18n 文案里 {@code %v} 对 Duration 的输出）。
     *
     * <p>Java {@link Duration#toString()} 形如 {@code PT0.5S}，而 Go 是 {@code 500ms}，
     * 且小数位按单位取 3/6/9 位并裁掉尾随零、秒级以上进位到 {@code m}/{@code h}，
     * 故按 Go 的规则逐段实现。黄金值由 {@code go run} 生成后逐条对拍（见
     * {@code /tmp/opencode/durgold/gold.txt}），例：
     * <pre>
     *   0              -&gt; 0s            1234           -&gt; 1.234µs
     *   500000000      -&gt; 500ms         1234567        -&gt; 1.234567ms
     *   1234567891     -&gt; 1.234567891s  60000000000    -&gt; 1m0s
     *   123400000000   -&gt; 2m3.4s        3600000000000  -&gt; 1h0m0s
     * </pre>
     *
     * @param nanos 纳秒数，可为负（Go 同样在最前补 {@code -}）
     */
    static String formatGoDuration(long nanos) {
        if (nanos == 0) {
            return "0s";
        }
        boolean negative = nanos < 0;
        long u = negative ? -nanos : nanos;
        String body;

        if (u < 1_000L) {                                   // 纳秒
            body = u + "ns";
        } else if (u < 1_000_000L) {                        // 微秒，小数 3 位
            body = trimFrac(u / 1_000L, u % 1_000L, 3) + "µs";
        } else if (u < 1_000_000_000L) {                    // 毫秒，小数 6 位
            body = trimFrac(u / 1_000_000L, u % 1_000_000L, 6) + "ms";
        } else {                                            // 秒，小数 9 位，可带 m/h
            long totalSec = u / 1_000_000_000L;
            long frac = u % 1_000_000_000L;
            long h = totalSec / 3600;
            long m = (totalSec % 3600) / 60;
            long s = totalSec % 60;
            StringBuilder sb = new StringBuilder();
            if (h > 0) {
                sb.append(h).append('h');
            }
            // Go：有小时位时分钟必打印（含 0），否则仅在分钟非 0 时打印
            if (h > 0 || m > 0) {
                sb.append(m).append('m');
            }
            sb.append(trimFrac(s, frac, 9)).append('s');
            body = sb.toString();
        }
        return negative ? "-" + body : body;
    }

    /**
     * 整数部分 + 按 {@code width} 位裁掉尾随零的小数部分（Go 的 {@code fmt} 行为）。
     * 小数全为零时连同小数点一并省略。
     */
    private static String trimFrac(long whole, long frac, int width) {
        if (frac == 0) {
            return Long.toString(whole);
        }
        String digits = Long.toString(frac);
        StringBuilder padded = new StringBuilder(digits);
        while (padded.length() < width) {
            padded.insert(0, '0');
        }
        int end = padded.length();
        while (end > 0 && padded.charAt(end - 1) == '0') {
            end--;
        }
        return whole + "." + padded.substring(0, end);
    }

    /** cmd.go:312-316 / 371-375 指定 -o 时落盘；SaveNmapResult 返回错误字符串或 null。 */
    private static void saveIfRequested(List<NmapResult> results, String outputPath) {
        if (outputPath == null || outputPath.isEmpty()) {
            return;
        }
        String err = NmapUtils.saveNmapResult(results, outputPath);
        if (err != null) {
            System.out.println(I18n.Tf("nmap.err.save_failed", err));
        }
    }

    /**
     * cmd.go:659-667 resolveContentProbeTimeout：优先使用 -X 专用超时，
     * 未设置 (&lt;=0) 时沿用扫描超时，两者都未指定时使用内容探测默认超时。
     */
    static int resolveContentProbeTimeout(int scanTimeoutSeconds, int probeTimeoutSeconds) {
        if (probeTimeoutSeconds > 0) {
            return probeTimeoutSeconds;
        }
        if (scanTimeoutSeconds > 0) {
            return scanTimeoutSeconds;
        }
        return CONTENT_PROBE_DEFAULT_TIMEOUT_SECONDS;
    }

    /**
     * cmd.go:557-644 NmapHelp 显示 nmap 帮助信息。
     *
     * <p>对应 Go 的 help 子命令（{@code ScanCmd.AddCommand(help)} → {@code NmapHelp()}），
     * 即 {@code scan help} 的实际输出；根级 {@code help scan} 走 picocli usage。
     */
    static void nmapHelp() {
        System.out.println(String.join("\n",
                "",
                "JYscan Nmap模块使用说明",
                "",
                "基本用法:",
                "  1. 直接传递目标: JYscan scan 目标 [选项]",
                "  2. 使用--target标志: JYscan scan --target 目标 [选项]",
                "",
                "目标格式:",
                "  - IP地址: 192.168.1.1",
                "  - CIDR网段: 192.168.1.0/24",
                "  - IP范围: 192.168.1.1-100",
                "  - 域名: example.com",
                "",
                "扫描类型:",
                "  - connect: TCP连接扫描 (默认)",
                "  - syn: TCP SYN半连接扫描",
                "  - udp: UDP端口扫描",
                "",
                "常用选项:",
                "  -t, --target: 扫描目标 (IP/CIDR/IP范围/域名)",
                "  -p, --ports: 指定扫描端口 (默认: 1-1000, 支持: 80,443, 1-1000, 22,80,443, -p- 表示全端口扫描)",
                "  -n, --threads: 并发线程数",
                "  -T, --timing: 扫描速度级别 (0-5, 完全模仿nmap -T参数)",
                "  -o, --output: 结果输出文件",
                "",
                "扫描类型参数:",
                "  --sT: TCP连接扫描 (等同于nmap -sT参数)",
                "  --sU: UDP扫描 (等同于nmap -sU参数)",
                "  --sS: SYN扫描 (等同于nmap -sS参数)",
                "",
                "功能参数:",
                "  --O: 启用系统识别 (等同于nmap -O参数)",
                "  --sV: 启用服务识别 (等同于nmap -sV参数)",
                "  --A: 全面扫描模式 (等同于nmap -A参数)",
                "  --f: 碎片化扫描模式 (等同于nmap -f参数，数据包分片发送以规避检测)",
                "  --ttl: 启用TTL检测，估算目标距离",
                "  --sn: 主机存活探测模式 (等同于nmap -sn参数，仅判断主机在线状态，跳过端口扫描)",
                "  -X: 内容探测，对常规端口探测发现的开放端口进行内容探测，获取端口回复的内容",
                "  -X 输出为彩色 (HTTP 状态码/响应头/协议回复语义着色)，--no-color 可关闭",
                "  --content-probe-timeout: 内容探测单端口超时(秒)，0 表示沿用 -w/--timeout",
                "  --content-probe-threads: 内容探测并发数 (默认32)",
                "",
                "YScript脚本集成:",
                "  本版本未包含 YScript 脚本引擎，--script / --script-args / --script-list",
                "  暂不可用（保留参数以维持与 Go 版的命令行兼容）。",
                "",
                "-T参数详细说明 (扫描速度级别):",
                "  0: 偏执 (Paranoid) - 非常慢的扫描，每5分钟发送一个包，用于IDS规避",
                "  1: 鬼祟 (Sneaky) - 慢速扫描，每15秒发送一个包，IDS规避",
                "  2: 礼貌 (Polite) - 降低速度，每0.4秒发送一个包，减少对目标系统的影响",
                "  3: 普通 (Normal) - 默认速度，平衡速度和隐蔽性",
                "  4: 激进 (Aggressive) - 快速扫描，减少超时时间，可能被检测到",
                "  5: 疯狂 (Insane) - 极速扫描，最大并发，最小超时，容易被检测",
                "",
                "TTL检测说明:",
                "  启用TTL检测可以估算目标距离（网络跳数），帮助判断目标位置",
                "  本地网络: 1跳，私有网络: 2跳，公网: 3-15跳",
                "",
                "示例:",
                "  ./JYscan scan 192.168.1.1/24",
                "  ./JYscan scan 192.168.1.1-192.168.1.100 -p 22,80,443",
                "  ./JYscan scan example.com -p 1-1000 -t 100",
                "  ./JYscan scan 10.0.0.0/8 -O -V",
                "  ./JYscan scan 192.168.1.1 -O -V -p 1-1000",
                "  ./JYscan scan 192.168.1.1 -X -p 80,443,8080",
                "  ./JYscan scan -iL targets.txt -X -p 1-1000 -o result.json",
                ""));
    }
}

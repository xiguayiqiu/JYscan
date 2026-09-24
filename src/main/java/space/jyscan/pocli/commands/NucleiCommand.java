package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import space.jyscan.core.i18n.I18n;
import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.GoJson;
import space.jyscan.modules.nuclei.log.Logger;
import space.jyscan.modules.nuclei.model.Classification;
import space.jyscan.modules.nuclei.model.Template;
import space.jyscan.modules.nuclei.runner.Runner;
import space.jyscan.modules.nuclei.runner.ScanResult;
import space.jyscan.modules.nuclei.runner.ScanStrategy;
import space.jyscan.modules.nuclei.runner.WorkPoolConfig;
import space.jyscan.modules.nuclei.utils.HostErrorsCache;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Callable;

/**
 * nuclei 命令，移植自 freeclient/internal/cli/nuclei.go（726 行）。
 *
 * <p>参数解析、模板加载、过滤、扫描回调、彩色输出与统计面板均按 Go 版逐行移植；
 * 扫描执行见 {@link space.jyscan.modules.nuclei.runner.Runner}。
 *
 * <p><b>与 Go 的接线差异（均为 CLI 外壳层的等价改写，不改变可观察行为）：</b>
 * <ul>
 *   <li>{@code -td} 简写由 {@code Cli} 在原始参数阶段重写为 {@code --td}（等价 Go 的
 *       {@code syncNucleiShortFlags}），本类收到的已是 {@code --td}。</li>
 *   <li>{@code -v}/{@code --verbose}、{@code --no-color}、{@code --silent} 同样被 {@code Cli}
 *       提前消费为全局状态（等价 Go root 的 {@code hasFlag}）。Go 侧这几个 flag 同时被 cobra
 *       本地解析（root 持久 flag 与 nuclei 本地 flag 同名同简写），故 Java 取
 *       「本地 flag 或全局状态」合并判断（{@code verboseEff}/{@code noColorEff}）。</li>
 *   <li>Go 的 cobra 默认接受并忽略多余位置参数（{@code nucleiCmd} 未设 {@code Args}），
 *       用隐藏通配位 {@link #extraArgs} 等价吸收，避免 picocli 报 unmatched。</li>
 *   <li>{@code --silent} 在 Go 里注册后从未被读取（死 flag），照抄注册、同样无副作用。</li>
 * </ul>
 *
 * <p><b>与 Go 逐位一致的两个反直觉点（有意保留，勿"修复"）：</b>
 * <ul>
 *   <li>{@code nuclei.summary.http-conns} 先经 {@link I18n#Tf} 格式化、再作为 format 传给
 *       logger 二次 Sprintf，Go 实测输出 {@code ... (73.3%!)(MISSING)}；Java 的
 *       {@link Fmt} 复刻了同一行为，故逐位一致。</li>
 *   <li>Go 的 runner 只在<b>命中</b>时触发回调，因此本类回调里的 {@code totalCount}
 *       恒等于 {@code matchCount}（Go 侧亦如此），"跳过"恒为 0。</li>
 * </ul>
 */
@Command(
        name = "nuclei",
        description = "nuclei 漏洞扫描引擎 - 基于 YAML 模板的协议级漏洞检测",
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true,
        header = {
                "",
                "nuclei 命令 - 基于 YAML 模板的协议级漏洞检测引擎",
                "",
                "支持协议: HTTP, DNS, TCP, SSL",
                "支持模板格式: YAML, JSON",
                "",
                "扫描策略:",
                "  auto           自动选择 (模板多目标少时用 host-spray)",
                "  template-spray 模板喷射 (每个模板并发扫描所有目标)",
                "  host-spray     主机喷射 (每个目标并发执行所有模板)",
                "",
                "多线程参数:",
                "  -c, --concurrency  模板并发数 (默认: 10)",
                "  -T, --threads      线程数 (与 --concurrency 相同, 默认: 10)",
                "",
                "使用示例:",
                "  # 扫描单个目标",
                "  jyscan nuclei -u http://example.com -t template.yaml",
                "",
                "  # 从文件加载目标",
                "  jyscan nuclei -l targets.txt -t template.yaml",
                "",
                "  # 从目录加载模板",
                "  jyscan nuclei -u http://example.com -td ./nuclei-templates/",
                "",
                "  # 按严重程度过滤",
                "  jyscan nuclei -u http://example.com -td ./templates/ -severity critical,high",
                "",
                "  # JSON 输出",
                "  jyscan nuclei -u http://example.com -t template.yaml -json -o result.json",
                "",
                "  # 指定扫描策略",
                "  jyscan nuclei -u http://example.com -td ./templates/ -strategy host-spray",
                "",
                "  # 设置并发数/线程数",
                "  jyscan nuclei -u http://example.com -td ./templates/ -c 20",
                "  jyscan nuclei -u http://example.com -td ./templates/ --threads 50",
                "",
                "  # 同时输出到 stdout",
                "  jyscan nuclei -u http://example.com -t template.yaml -v",
                "",
                "警告: 仅用于授权测试，严禁未授权使用！"
        })
public class NucleiCommand implements Callable<Integer> {

    // ==================== 固定配色（对应 Go 各处 color.New(...)） ====================

    /** fatih/color 的 {@code color.Italic}：{@link Colors} 未导出该码，本地补齐。 */
    private static final String ITALIC = "\u001b[3m";

    private static final String[] C_DIVIDER = {Colors.FG_HI_BLACK};
    private static final String[] C_TITLE = {Colors.FG_HI_WHITE, Colors.BOLD};
    private static final String[] C_LABEL = {Colors.FG_WHITE, Colors.BOLD};
    private static final String[] C_GREEN = {Colors.FG_HI_GREEN, Colors.BOLD};
    private static final String[] C_HIWHITE = {Colors.FG_HI_WHITE, Colors.BOLD};
    private static final String[] C_YELLOW = {Colors.FG_HI_YELLOW, Colors.BOLD};
    private static final String[] C_HIPROTO = {Colors.FG_HI_MAGENTA, Colors.BOLD};
    private static final String[] C_TYPE = {Colors.FG_HI_GREEN};
    private static final String[] C_GRAY = {Colors.FG_HI_BLACK};
    private static final String[] C_GRAY_ITALIC = {Colors.FG_HI_BLACK, ITALIC};
    private static final String[] C_HI_CYAN = {Colors.FG_HI_CYAN};
    private static final String[] C_HI_WHITE = {Colors.FG_HI_WHITE};
    private static final String[] C_EXTRACT = {Colors.FG_HI_BLACK, ITALIC};
    private static final String[] C_MATCH_PROTO = {Colors.FG_HI_MAGENTA};

    // ==================== flag（对应 nuclei.go 的包级变量 + init 注册） ====================

    @Option(names = {"-u", "--url"}, description = "目标 URL/主机")
    private String target;

    @Option(names = {"-l", "--list"}, description = "目标列表文件 (每行一个)")
    private String targetFile;

    @Option(names = {"-t", "--template"}, description = "模板文件路径")
    private String template;

    @Option(names = {"--templates-dir"}, description = "模板目录路径 (nuclei 兼容 -td)")
    private String templateDir;

    /** nuclei 兼容 {@code -td} 简写（已由 Cli 预处理为 {@code --td}）；Go 侧 MarkHidden。 */
    @Option(names = {"--td"}, hidden = true, description = "模板目录路径 (nuclei 兼容简写)")
    private String templateDirAlias;

    @Option(names = {"-o", "--output"}, description = "输出文件路径")
    private String output;

    @Option(names = {"-j", "--json"}, description = "JSON 格式输出")
    private boolean json;

    @Option(names = {"-s", "--severity"}, description = "按严重程度过滤 (info,low,medium,high,critical)")
    private String severity;

    @Option(names = {"--tags"}, description = "按标签过滤")
    private String tags;

    @Option(names = {"-v", "--verbose"}, description = "详细输出")
    private boolean verbose;

    @Option(names = {"-c", "--concurrency"}, description = "模板并发数", defaultValue = "10")
    private int concurrency = 10;

    @Option(names = {"-T", "--threads"}, description = "线程数 (与 --concurrency 相同, 优先使用 -c)",
            defaultValue = "0")
    private int threads;

    @Option(names = {"--strategy"}, description = "扫描策略 (auto, template-spray, host-spray)",
            defaultValue = "auto")
    private String strategy = "auto";

    @Option(names = {"--no-color"}, description = "禁用彩色输出 (nuclei 兼容)")
    private boolean noColor;

    /** Go 注册后从未读取的死 flag，照抄注册（仅出现在帮助里，无任何副作用）。 */
    @Option(names = {"--silent"}, description = "静默模式 (只显示匹配结果)")
    private boolean silent;

    /** 等价 cobra 默认接受并忽略的多余位置参数（nucleiCmd 未设 Args 校验）。 */
    @Parameters(arity = "0..*", hidden = true)
    private List<String> extraArgs = new ArrayList<>();

    @Override
    public Integer call() {
        // nuclei 兼容的 logger（Go: runNuclei 开头）
        Logger nl = new Logger();
        nl.setNoColor(false);
        // --no-color 已被 Cli 提前消费为全局色标（等价 Go root 的 hasFlag("no-color")），
        // 本地 noColor flag 在 Java 侧永远为 false，故与全局标合并判断。
        final boolean noColorEff = noColor || !Colors.useColor;
        if (noColorEff) {
            nl.setNoColor(true);
        }

        // nuclei 兼容: -td 简写同步到 --templates-dir
        if (!empty(templateDirAlias)) {
            templateDir = templateDirAlias;
        }

        // --threads 显式给出时覆盖 --concurrency（Go: if nucleiThreads > 0）
        if (threads > 0) {
            concurrency = threads;
        }

        // Go 的 nucleiVerbose 由 cobra 本地 -v 解析；Java 侧 -v/--verbose 已被 Cli 剥离为
        // 全局 Colors.isVerbose，故取「本地 flag 或全局 flag」（Go 的 root 持久 -v 与
        // nuclei 本地 -v 同名同简写，实际同时生效，二者等价）。
        final boolean verboseEff = verbose || Colors.isVerbose;

        if (empty(target) && empty(targetFile)) {
            nl.error(I18n.T("nuclei.err.no-target"));
            return 1;
        }
        if (empty(template) && empty(templateDir)) {
            nl.error(I18n.T("nuclei.err.no-template"));
            return 1;
        }

        // 启动时显示版本信息（nuclei.log.version 按需求删除，不再显示）
        nl.info(I18n.T("nuclei.log.template-version"));
        nl.info(I18n.T("nuclei.log.new-templates"));

        List<String> targets = new ArrayList<>();
        if (!empty(target)) {
            targets.add(target);
        }
        if (!empty(targetFile)) {
            String data;
            try {
                data = Files.readString(Path.of(targetFile), StandardCharsets.UTF_8);
            } catch (IOException | InvalidPathException e) {
                nl.error(I18n.Tf("nuclei.err.read-target-file", e));
                return 1;
            }
            for (String line : data.split("\n", -1)) {
                String t = line.trim();
                if (!t.isEmpty() && !t.startsWith("#")) {
                    targets.add(t);
                }
            }
        }

        if (targets.isEmpty()) {
            nl.error(I18n.T("nuclei.err.no-valid-target"));
            return 1;
        }

        Runner r = new Runner();
        r.setVerbose(verboseEff);
        WorkPoolConfig wpc = new WorkPoolConfig();
        wpc.inputConcurrency = concurrency * 2;
        wpc.typeConcurrency = concurrency;
        wpc.headlessInputConcurrency = concurrency;
        wpc.headlessTypeConcurrency = concurrency / 2;
        r.setWorkPoolConfig(wpc);

        switch (strategy) {
            case "template-spray" -> r.setStrategy(ScanStrategy.TEMPLATE_SPRAY);
            case "host-spray" -> r.setStrategy(ScanStrategy.HOST_SPRAY);
            default -> r.setStrategy(ScanStrategy.AUTO);
        }

        List<Template> templates = new ArrayList<>();
        if (!empty(templateDir)) {
            Object[] res = r.loadTemplates(templateDir);
            if (res[1] != null) {
                nl.error(I18n.Tf("nuclei.err.load-template-dir", templateDir, res[1]));
                return 1;
            }
            templates.addAll(templatesOf(res));
        }
        if (!empty(template)) {
            boolean exists = false;
            boolean isDir = false;
            try {
                Path p = Path.of(template);
                exists = Files.exists(p);
                isDir = exists && Files.isDirectory(p);
            } catch (InvalidPathException e) {
                // Go: os.Stat 遇到非法路径同样报错 → 走"模板路径未找到"分支
            }
            if (!exists) {
                nl.error(I18n.Tf("nuclei.err.template-not-found", template));
                return 1;
            }
            if (isDir) {
                Object[] res = r.loadTemplates(template);
                if (res[1] != null) {
                    nl.error(I18n.Tf("nuclei.err.load-template-dir", template, res[1]));
                    return 1;
                }
                templates.addAll(templatesOf(res));
            } else {
                Object[] res = r.loadTemplate(template);
                if (res[1] != null) {
                    nl.error(I18n.Tf("nuclei.err.load-template", template, res[1]));
                    return 1;
                }
                templates.add((Template) res[0]);
            }
        }

        List<Template> effective = filterTemplates(templates, severity, tags);

        if (effective.isEmpty()) {
            nl.warning(I18n.T("nuclei.err.no-executable"));
            return 0;
        }

        // nuclei 官方风格 INF 日志
        nl.info(I18n.Tf("nuclei.log.loaded-templates", effective.size()));
        // 签名模板统计 (nuclei 官方: 模拟 signed templates 来源)
        nl.info(I18n.Tf("nuclei.log.signed-templates", effective.size()));
        nl.info(I18n.Tf("nuclei.log.loaded-targets", targets.size()));

        // 模拟 httpx 探测 (nuclei 官方行为)
        if (hasHTTP(targets)) {
            nl.info(I18n.T("nuclei.log.httpx-probe"));
            nl.info(I18n.Tf("nuclei.log.httpx-found", targets.size()));
        }

        // 模拟 Interactsh 服务器 (nuclei 官方默认启用)
        nl.info(I18n.T("nuclei.log.interactsh"));

        // 模拟模板聚类 (nuclei 官方行为)
        int[] cluster = simulateCluster(effective.size(), targets.size());
        if (cluster[1] > 0) {
            nl.info(I18n.Tf("nuclei.log.clustered", cluster[0], cluster[1]));
        }

        final BufferedWriter writer;
        if (!empty(output)) {
            try {
                writer = Files.newBufferedWriter(Path.of(output), StandardCharsets.UTF_8);
            } catch (IOException | InvalidPathException e) {
                nl.error(I18n.Tf("nuclei.err.create-output", e));
                return 1;
            }
        } else {
            writer = null;
        }

        try {
            final int[] totalCount = {0};
            final int[] matchCount = {0};
            final List<ScanResult> matchedResults = new ArrayList<>();
            final Map<String, Integer> severityStats = new LinkedHashMap<>();
            final Map<String, Integer> protocolStats = new LinkedHashMap<>();
            final Map<String, Integer> typeStats = new LinkedHashMap<>();

            long startNanos = System.nanoTime();

            r.executeWithCallback(effective, targets, result -> {
                totalCount[0]++;
                if (result.matched) {
                    matchCount[0]++;
                    matchedResults.add(result);
                    String sev = result.template.info.severity.toLowerCase(Locale.ROOT);
                    if (sev.isEmpty()) {
                        sev = "unknown";
                    }
                    severityStats.merge(sev, 1, Integer::sum);
                    if (result.matchedByProtocol != null) {
                        for (String proto : result.matchedByProtocol.keySet()) {
                            protocolStats.merge(proto, 1, Integer::sum);
                        }
                    }
                    String tp = "other";
                    if (result.template != null) {
                        Classification cls = result.template.info.classification;
                        if (cls != null) {
                            if (cls.cveId != null && !cls.cveId.isEmpty()) {
                                tp = "cve";
                            } else if (cls.cweId != null && !cls.cweId.isEmpty()) {
                                tp = "cwe";
                            }
                        }
                        if ("other".equals(tp) && result.template.info.tags != null
                                && !result.template.info.tags.isEmpty()) {
                            tp = String.join(",", result.template.info.tags);
                        }
                    }
                    typeStats.merge(tp, 1, Integer::sum);
                }
                outputResult(result, writer, json, verboseEff, noColorEff);
            });

            Duration duration = Duration.ofNanos(System.nanoTime() - startNanos);
            printSummary(totalCount[0], matchCount[0], duration, severityStats, protocolStats,
                    typeStats, matchedResults, r, noColorEff);
            return 0;
        } finally {
            // Go: defer outputFile.Close()（在 printSummary 之后执行），返回值同样被忽略
            if (writer != null) {
                try {
                    writer.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    // ==================== 输出（nuclei.go: outputResult / printColorResult / nucleiOutputJSON） ====================

    /**
     * 单条结果输出，对应 Go 的 {@code outputResult(result, outputFile)}。
     *
     * <p>{@code -j} 走 {@link #nucleiOutputJSON}；否则先 {@code runner.FormatResult}
     * 生成纯文本行，命中（或 verbose）时打印 —— {@code --no-color} 打纯文本行，
     * 否则走彩色重建。{@code -o} 仅对命中的结果写文件（紧凑 JSON，逐行一条）。
     */
    private static void outputResult(ScanResult result, BufferedWriter outf, boolean jsonOut,
            boolean verboseEff, boolean noColorEff) {
        if (jsonOut) {
            nucleiOutputJSON(result, outf, verboseEff);
            return;
        }

        // nuclei 官方格式: [template-id[:matcher-name]] [protocol] [severity] target [extracted_data]
        String line = Runner.formatResult(result);

        if (verboseEff || result.matched) {
            if (noColorEff) {
                System.out.println(line);
            } else {
                printColorResult(result, line);
            }
        }

        if (outf != null && result.matched) {
            String data = GoJson.marshal(resultToMap(result));
            try {
                outf.write(goEscapeHtml(data == null ? "" : data) + "\n");
            } catch (IOException e) {
                // Go: outputFile.WriteString(...) 的返回值被忽略
            }
        }
    }

    /**
     * 输出 nuclei 官方风格的彩色结果，对应 Go 的 {@code printColorResult(result, plain)}。
     *
     * <p>配色规则 (Terminal#17-33)：template-id 按 severity 取色、protocol 浅蓝、
     * severity 按级别取色、target 亮白（URL 用反引号）、extracted 淡灰斜体。
     * 颜色的开合全部经 {@link Colors#wrap}（等价 fatih/color 读全局 {@code color.NoColor}）。
     */
    private static void printColorResult(ScanResult result, String plain) {
        if (result == null || result.template == null) {
            System.out.println(plain);
            return;
        }

        String protocol = result.protocol;
        if (empty(protocol)) {
            protocol = result.matchedAt;
        }
        String templateID = result.template.id;
        if (!empty(result.matcherName)) {
            templateID = templateID + ":" + result.matcherName;
        }
        String target = result.target;
        if (empty(target)) {
            target = result.matchedAt;
        }
        boolean targetIsURL = target.startsWith("http://") || target.startsWith("https://");
        if (targetIsURL) {
            target = "`" + target + "`";
        }
        String severity = result.template.info.severity.toLowerCase(Locale.ROOT);
        if (severity.isEmpty()) {
            severity = "unknown";
        }

        String[] idColor = idColorBySeverity(severity);
        String[] sevColor = severityColor(severity);

        System.out.print("[");
        System.out.print(Colors.wrap(templateID, idColor));
        System.out.print("] [");
        System.out.print(Colors.wrap(protocol, C_HI_CYAN));
        System.out.print("] [");
        System.out.print(Colors.wrap(severity, sevColor));
        System.out.print("] ");
        System.out.print(Colors.wrap(target, C_HI_WHITE));
        if (result.extracted != null && !result.extracted.isEmpty()) {
            // 过滤空值 (nuclei 官方: 空提取值不显示)，key 排序与 Go sort.Strings 一致
            List<String> keys = new ArrayList<>(result.extracted.keySet());
            Collections.sort(keys);
            List<String> nonEmptyValues = new ArrayList<>();
            for (String k : keys) {
                String v = result.extracted.get(k);
                if (v != null && !v.trim().isEmpty()) {
                    nonEmptyValues.add(v);
                }
            }
            if (!nonEmptyValues.isEmpty()) {
                System.out.print(" [");
                for (int i = 0; i < nonEmptyValues.size(); i++) {
                    if (i > 0) {
                        System.out.print(",");
                    }
                    System.out.print(Colors.wrap(quoteASCIIForColor(nonEmptyValues.get(i)), C_EXTRACT));
                }
                System.out.print("]");
            }
        }
        System.out.println();
    }

    /** JSON 输出，对应 Go 的 {@code nucleiOutputJSON(result, outputFile)}（MarshalIndent 两空格缩进）。 */
    private static void nucleiOutputJSON(ScanResult result, BufferedWriter outf, boolean verboseEff) {
        String data;
        try {
            data = GoJson.marshalIndent(resultToMap(result));
        } catch (IOException e) {
            data = null; // Go: data, _ := json.MarshalIndent(...) 忽略 error，失败时 data 为 nil
        }
        String text = goEscapeHtml(data == null ? "" : data);
        if (verboseEff || result.matched) {
            System.out.println(text);
        }
        if (outf != null && result.matched) {
            try {
                outf.write(text + "\n");
            } catch (IOException e) {
                // Go: outputFile.WriteString(...) 的返回值被忽略
            }
        }
    }

    /**
     * 结果转 map，对应 Go 的 {@code resultToMap(result)}。
     *
     * <p>用 {@link TreeMap} 承载：Go 的 {@code json.Marshal} 对 map 按键升序输出，
     * Jackson 不做排序，靠 {@code Map} 自身的有序性还原。duration 走
     * {@code Fmt.format("%v", …)} 以复刻 Go {@code Duration.String()}（非 Java 的 {@code PT…} 形式）。
     */
    private static Map<String, Object> resultToMap(ScanResult result) {
        Map<String, Object> m = new TreeMap<>();
        m.put("template_id", result.template.id);
        m.put("template_name", result.template.info.name);
        m.put("severity", result.template.info.severity);
        m.put("target", result.target);
        m.put("matched", result.matched);
        m.put("matched_at", result.matchedAt);
        m.put("duration", Fmt.format("%v", result.duration));

        if (result.matched) {
            m.put("matched_by",
                    result.matchedByProtocol == null ? null : new TreeMap<>(result.matchedByProtocol));
        }
        if (result.extracted != null && !result.extracted.isEmpty()) {
            m.put("extracted", new TreeMap<>(result.extracted));
        }
        if (result.template.info.tags != null && !result.template.info.tags.isEmpty()) {
            m.put("tags", result.template.info.tags);
        }
        if (!empty(result.template.info.description)) {
            m.put("description", result.template.info.description);
        }
        return m;
    }

    /**
     * 复刻 Go {@code json.Marshal} 默认的 HTML 转义（{@code SetEscapeHTML(true)}）：
     * {@code <}、{@code >}、{@code &} 转为 JSON 十六进制转义序列（小写），
     * 另含 U+2028/U+2029 两个行分隔符。
     *
     * <p>这些字符只会出现在 JSON 字符串值内部（结构字符里不存在），故序列化后整体替换是安全的。
     * Jackson 默认不转义，直接影响含查询串的 URL（&amp; 必须变成转义形式才与 Go 逐位一致）。
     */
    private static String goEscapeHtml(String json) {
        return json.replace("&", "\\u0026")
                .replace("<", "\\u003c")
                .replace(">", "\\u003e")
                .replace("\u2028", "\\u2028")
                .replace("\u2029", "\\u2029");
    }

    // ==================== 统计面板（nuclei.go: printSummary） ====================

    /**
     * 扫描完成摘要 + JYscan 增强统计面板，对应 Go 的 {@code printSummary(...)}。
     *
     * <p>INFO 行走 logger（stderr，{@code [INF]} 前缀），面板走 stdout 彩色 Printf。
     * 所有带格式的输出都经 {@code Fmt.format} 再裹色，与 Go {@code color.Printf} 的
     * 「先 Sprintf 后上色」次序一致。
     */
    private static void printSummary(int total, int matched, Duration duration,
            Map<String, Integer> sevStats, Map<String, Integer> protoStats,
            Map<String, Integer> typeStats, List<ScanResult> matchedList, Runner r,
            boolean noColorFlag) {
        // nuclei 官方风格: 简洁的完成摘要
        Logger nl = new Logger();
        if (noColorFlag) {
            nl.setNoColor(true);
        }

        // 输出被跳过的主机 (nuclei 官方: "Skipped X from target list as found unresponsive Y times")
        if (r != null) {
            for (String host : r.getSkippedHosts()) {
                int count = 0;
                HostErrorsCache he = r.hostErrors();
                if (he != null) {
                    count = he.errorCount(host);
                }
                nl.info(I18n.Tf("nuclei.summary.skipped-host", host, count));
            }
        }

        // Scan completed in Xm. Y matches found.
        if (matched > 0) {
            nl.info(I18n.Tf("nuclei.summary.completed-matched", shortDur(duration), matched));
        } else {
            nl.info(I18n.Tf("nuclei.summary.completed-no-match", shortDur(duration)));
        }

        // HTTP connections 统计 (nuclei 官方)
        int[] conns = estimateHTTPConns(total, matched);
        if (conns[0] > 0) {
            double ratio = (double) conns[2] / (double) conns[0] * 100;
            // 注意: Tf 之后再经 logger 二次 Sprintf，Go 实测同样输出 "!)(MISSING)"，逐位照抄
            nl.info(I18n.Tf("nuclei.summary.http-conns", conns[0], conns[1], conns[2], ratio));
        }

        // JYscan 增强: 详细统计面板 (nuclei 没有这个, 作为补充)
        if (sevStats.isEmpty() && protoStats.isEmpty()) {
            return;
        }

        plc(C_DIVIDER, "═".repeat(70));
        plc(C_TITLE, "                      " + I18n.T("nuclei.summary.title"));
        plc(C_DIVIDER, "─".repeat(70));

        pc(C_LABEL, "  " + I18n.T("nuclei.summary.total-templates") + "    ");
        pc(C_HIWHITE, "%d\n", total);
        pc(C_LABEL, "  " + I18n.T("nuclei.summary.matched") + "      ");
        pc(C_GREEN, "%d", matched);
        pc(C_HIWHITE, "  ");
        int skipped = total - matched;
        pc(C_LABEL, I18n.Tf("nuclei.summary.skipped", skipped) + "\n");
        pc(C_LABEL, "  " + I18n.T("nuclei.summary.duration") + "        ");
        pc(C_YELLOW, "%v\n", roundTo(duration, 1_000_000L));
        if (duration.toNanos() > 0) {
            pc(C_LABEL, "  ");
            pc(C_YELLOW, I18n.Tf("nuclei.summary.speed",
                    (double) total / (duration.toNanos() / 1_000_000_000.0)) + "\n");
        }

        if (!sevStats.isEmpty()) {
            plc(C_DIVIDER, "─".repeat(70));
            plc(C_LABEL, "  " + I18n.T("nuclei.summary.severity-dist"));
            List<String> order = List.of("critical", "high", "medium", "low", "info", "unknown");
            for (String k : order) {
                Integer v = sevStats.get(k);
                if (v != null && v > 0) {
                    pc(severityColor(k), "    %-10s", k.toUpperCase(Locale.ROOT));
                    pc(C_HIWHITE, "  %d\n", v);
                }
            }
            for (Map.Entry<String, Integer> e : sevStats.entrySet()) {
                if (!order.contains(e.getKey())) {
                    pc(severityColor(e.getKey()), "    %-10s", e.getKey().toUpperCase(Locale.ROOT));
                    pc(C_HIWHITE, "  %d\n", e.getValue());
                }
            }
        }

        if (!protoStats.isEmpty()) {
            plc(C_DIVIDER, "─".repeat(70));
            plc(C_LABEL, "  " + I18n.T("nuclei.summary.protocol-dist"));
            for (Map.Entry<String, Integer> e : protoStats.entrySet()) {
                pc(C_HIPROTO, "    %-10s", e.getKey().toUpperCase(Locale.ROOT));
                pc(C_HIWHITE, "  %d\n", e.getValue());
            }
        }

        if (!typeStats.isEmpty()) {
            plc(C_DIVIDER, "─".repeat(70));
            plc(C_LABEL, "  " + I18n.T("nuclei.summary.type-top"));
            List<Map.Entry<String, Integer>> kvs = new ArrayList<>(typeStats.entrySet());
            // Go: sort.Slice(kvs, func(i, j) { return kvs[i].v > kvs[j].v })
            kvs.sort((a, b) -> b.getValue().compareTo(a.getValue()));
            int limit = Math.min(5, kvs.size());
            for (int i = 0; i < limit; i++) {
                Map.Entry<String, Integer> e = kvs.get(i);
                pc(C_TYPE, "    %-20s", truncate(e.getKey(), 20));
                pc(C_HIWHITE, "  %d\n", e.getValue());
            }
        }

        if (!matchedList.isEmpty()) {
            plc(C_DIVIDER, "─".repeat(70));
            plc(C_LABEL, "  " + I18n.T("nuclei.summary.match-detail"));
            int limit = Math.min(10, matchedList.size());
            for (int i = 0; i < limit; i++) {
                ScanResult rr = matchedList.get(i);
                String sev = rr.template.info.severity.toLowerCase(Locale.ROOT);
                pc(severityColor(sev), "    [%s] ", sev.toUpperCase(Locale.ROOT));
                pc(C_TITLE, "%s", rr.template.id);
                pc(C_GRAY, "  -> %s", rr.target);
                if (!empty(rr.matchedAt)) {
                    pc(C_MATCH_PROTO, "  " + I18n.Tf("nuclei.summary.match-at", rr.matchedAt));
                }
                System.out.println();
            }
            if (matchedList.size() > limit) {
                pc(C_GRAY_ITALIC,
                        "    " + I18n.Tf("nuclei.summary.more-hits", matchedList.size() - limit) + "\n");
            }
        }

        plc(C_DIVIDER, "═".repeat(70));
    }

    // ==================== 小工具（nuclei.go 末尾的包级函数） ====================

    /** 简化耗时显示 (3m 19s / 1.2s)，对应 Go 的 {@code shortDur}。 */
    private static String shortDur(Duration d) {
        if (d.compareTo(Duration.ofMinutes(1)) < 0) {
            return Fmt.format("%v", roundTo(d, 100_000_000L));
        }
        long minutes = d.toMinutes();
        long seconds = d.minusMinutes(minutes).toSeconds();
        return Fmt.format("%dm %ds", minutes, seconds);
    }

    /** Go 的 {@code d.Round(m)}：四舍五入到最接近的 m 纳秒倍数（时长恒为正，half-up 即 half-away）。 */
    private static Duration roundTo(Duration d, long nanos) {
        return Duration.ofNanos(Math.round((double) d.toNanos() / nanos) * nanos);
    }

    /**
     * 估算 HTTP 连接统计 (nuclei 官方会复用连接池)，对应 Go 的 {@code estimateHTTPConns}。
     *
     * @return {@code {totalConn, newConn, reusedConn}}（Go 的 {@code matched} 参数同样未参与计算）
     */
    private static int[] estimateHTTPConns(int total, int matched) {
        if (total <= 0) {
            return new int[] {0, 0, 0};
        }
        // 估算: nuclei 复用率通常 70-80%
        int totalConn = total * 3 / 4;
        if (totalConn < 1) {
            totalConn = 1;
        }
        int reusedConn = totalConn * 76 / 100;
        int newConn = totalConn - reusedConn;
        return new int[] {totalConn, newConn, reusedConn};
    }

    /**
     * 按字节截断，对应 Go 的 {@code truncate(s, n)}（{@code len(s) <= n} 与 {@code s[:n-1]+"…"}
     * 都按 UTF-8 字节计）。已知微差：切点落在多字节字符中间时 Java 解码得到替换字符，
     * Go 保留原始残字节；统计键通常为 ASCII 标签，实际不可达。
     */
    private static String truncate(String s, int n) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        if (b.length <= n) {
            return s;
        }
        return new String(b, 0, n - 1, StandardCharsets.UTF_8) + "…";
    }

    /** 按 severity/tag 过滤模板，对应 Go 的 {@code filterTemplates}（逗号分隔，EqualFold 忽略大小写）。 */
    private static List<Template> filterTemplates(List<Template> templates, String severity, String tags) {
        if (empty(severity) && empty(tags)) {
            return templates;
        }

        List<String> severityList = null;
        if (!empty(severity)) {
            severityList = new ArrayList<>();
            for (String s : severity.split(",", -1)) {
                severityList.add(s.trim());
            }
        }
        List<String> tagList = null;
        if (!empty(tags)) {
            tagList = new ArrayList<>();
            for (String t : tags.split(",", -1)) {
                tagList.add(t.trim());
            }
        }

        List<Template> filtered = new ArrayList<>();
        for (Template t : templates) {
            if (severityList != null) {
                boolean matched = false;
                for (String s : severityList) {
                    if (t.info.severity.equalsIgnoreCase(s)) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    continue;
                }
            }

            if (tagList != null) {
                boolean matched = false;
                for (String tag : tagList) {
                    if (t.info.tags == null) {
                        break;
                    }
                    for (String tt : t.info.tags) {
                        if (tt.equalsIgnoreCase(tag)) {
                            matched = true;
                            break;
                        }
                    }
                    if (matched) {
                        break;
                    }
                }
                if (!matched) {
                    continue;
                }
            }

            filtered.add(t);
        }
        return filtered;
    }

    /** 检查目标中是否包含 HTTP/HTTPS 协议，对应 Go 的 {@code hasHTTP}。 */
    private static boolean hasHTTP(List<String> targets) {
        for (String t : targets) {
            String s = t.toLowerCase(Locale.ROOT);
            if (s.startsWith("http://") || s.startsWith("https://")) {
                return true;
            }
        }
        return false;
    }

    /**
     * 模拟 nuclei 模板聚类效果，对应 Go 的 {@code simulateCluster}。
     *
     * @return {@code {clustered, reduced}}
     */
    private static int[] simulateCluster(int templateCount, int targetCount) {
        if (templateCount <= 0 || targetCount <= 0) {
            return new int[] {0, 0};
        }
        // 估算: nuclei 聚类率约 20-30%
        int clustered = templateCount * 22 / 100;
        if (clustered < 1) {
            clustered = 1;
        }
        int original = templateCount * targetCount;
        int clusteredTotal = clustered * targetCount;
        return new int[] {clustered, original - clusteredTotal};
    }

    /** 与 runner.quoteASCII 等效的彩色输出版，对应 Go 的 {@code quoteASCIIForColor}。 */
    private static String quoteASCIIForColor(String s) {
        String quoted = s.replace("\\", "\\\\");
        quoted = quoted.replace("\"", "\\\"");
        quoted = quoted.replace("\n", "\\n");
        quoted = quoted.replace("\r", "\\r");
        quoted = quoted.replace("\t", "\\t");
        return "\"" + quoted + "\"";
    }

    /**
     * severity 配色，对应 Go 的 {@code severityColor}：
     * critical=亮红粗, high=红, medium=绿粗, low=蓝粗, info=紫, 默认白。
     */
    private static String[] severityColor(String sev) {
        return switch (sev.toLowerCase(Locale.ROOT)) {
            case "critical" -> new String[] {Colors.FG_HI_RED, Colors.BOLD};
            case "high" -> new String[] {Colors.FG_RED};
            case "medium" -> new String[] {Colors.FG_GREEN, Colors.BOLD};
            case "low" -> new String[] {Colors.FG_BLUE, Colors.BOLD};
            case "info" -> new String[] {Colors.FG_MAGENTA};
            default -> new String[] {Colors.FG_WHITE};
        };
    }

    /**
     * template-id 配色，对应 Go 的 {@code idColorBySeverity}：
     * critical=红粗, high=黄粗, medium=绿粗, low=蓝粗, info=紫粗, 默认亮白粗。
     */
    private static String[] idColorBySeverity(String sev) {
        return switch (sev.toLowerCase(Locale.ROOT)) {
            case "critical" -> new String[] {Colors.FG_RED, Colors.BOLD};
            case "high" -> new String[] {Colors.FG_YELLOW, Colors.BOLD};
            case "medium" -> new String[] {Colors.FG_GREEN, Colors.BOLD};
            case "low" -> new String[] {Colors.FG_BLUE, Colors.BOLD};
            case "info" -> new String[] {Colors.FG_MAGENTA, Colors.BOLD};
            default -> new String[] {Colors.FG_HI_WHITE, Colors.BOLD};
        };
    }

    /** runner.loadTemplates/loadTemplate 的 {@code Object[]{T, err}} 中取模板列表。 */
    @SuppressWarnings("unchecked")
    private static List<Template> templatesOf(Object[] res) {
        return (List<Template>) res[0];
    }

    /** 等价 Go 的 {@code s == ""}。 */
    private static boolean empty(String s) {
        return s == null || s.isEmpty();
    }

    /** 等价 Go 的 {@code color.Printf(fmt, args...)}：先 Sprintf 再裹色打印。 */
    private static void pc(String[] codes, String fmt, Object... args) {
        System.out.print(Colors.wrap(Fmt.format(fmt, args), codes));
    }

    /** 等价 Go 的 {@code color.Println(s)}：Sprintln 不解释 % 动词；fatih 的 Println 是
     * {@code Fprintln(wrap(sprintln(s)))}，unformat 在换行<b>前</b>且按参数查 mapResetAttributes。 */
    private static void plc(String[] codes, String s) {
        System.out.print(Colors.wrapPrintln(s, codes) + "\n");
    }
}

package space.jyscan.modules.nuclei.runner;

import java.time.DateTimeException;
import java.time.Duration;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;

import space.jyscan.modules.nuclei.dsl.Evaluator;
import space.jyscan.modules.nuclei.loader.Loader;
import space.jyscan.modules.nuclei.model.Classification;
import space.jyscan.modules.nuclei.model.DNSRequest;
import space.jyscan.modules.nuclei.model.HTTPRequest;
import space.jyscan.modules.nuclei.model.Matcher;
import space.jyscan.modules.nuclei.model.Options;
import space.jyscan.modules.nuclei.model.ResultEvent;
import space.jyscan.modules.nuclei.model.SSLRequest;
import space.jyscan.modules.nuclei.model.TCPRequest;
import space.jyscan.modules.nuclei.model.Template;
import space.jyscan.modules.nuclei.operators.Engine;
import space.jyscan.modules.nuclei.protocol.DNSExecutor;
import space.jyscan.modules.nuclei.protocol.HTTPExecutor;
import space.jyscan.modules.nuclei.protocol.Protocol;
import space.jyscan.modules.nuclei.protocol.ProtocolResult;
import space.jyscan.modules.nuclei.protocol.SSLExecutor;
import space.jyscan.modules.nuclei.protocol.TCPExecutor;
import space.jyscan.modules.nuclei.utils.HostErrorsCache;
import space.jyscan.modules.nuclei.utils.Variables;

/**
 * 扫描执行引擎，对应 Go 的 {@code runner.Runner}（{@code runner.go} + {@code flow.go} + {@code workpool.go}）。
 *
 * <p><b>跨包契约（CLI 只用下面这些）：</b>
 * <ul>
 *   <li>{@link #Runner()} —— 对应 Go 的 {@code NewRunner()}</li>
 *   <li>{@link #setVerbose(boolean)} / {@link #setWorkPoolConfig(WorkPoolConfig)} /
 *       {@link #setStrategy(ScanStrategy)}</li>
 *   <li>{@link #loadTemplates(String)} / {@link #loadTemplate(String)}（内部转调 loader）</li>
 *   <li>{@link #executeWithCallback(List, List, Consumer)} —— 扫描主入口</li>
 *   <li>{@link #getSkippedHosts()} / {@link #hostErrors()}</li>
 *   <li>静态 {@link #formatResult(ScanResult)} —— 对应 Go 的包级 {@code runner.FormatResult}</li>
 * </ul>
 *
 * <p><b>Go 死代码（按项目约定不移植，0 外部调用方，移植前已复核）：</b>
 * {@code runner.New(options model.Options)}（仅被 {@code NewRunner} 内部调用，其初始化逻辑
 * 即本类构造器）、{@code Runner.Results()}、{@code Runner.GetProgress()}
 * （另：{@code filterTemplates}/{@code matchesTags}/{@code matchesAuthor}/
 * {@code containsSeverity}/{@code calculateTotalRequests} 在 Go 全树亦 0 调用方，一并未移植）。
 *
 * <p><b>context 不移植：</b>按项目既定约定，Go 的 {@code context.Context} 在 Java 侧
 * 以 {@code volatile} 中断标志 + 线程池 {@code shutdownNow()} 承担，故
 * {@code ExecuteWithCallback} 的首个 {@code ctx} 参数被省略。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/runner/{runner,flow,workpool}.go}。
 */
public class Runner {

    // ---------- 对应 Go 的 Runner 结构体字段（runner.go:45-66，Go 侧均为包内小写，Java 侧同为包内可见） ----------

    /** 对应 Go 的 {@code opts model.Options}（仅被未移植的死代码 filterTemplates 读取，为结构对齐保留）。 */
    Options opts;
    /** 对应 Go 的 {@code templates []*model.Template}（经 {@link #mu} 保护读写）。 */
    List<Template> templates;
    /** 对应 Go 的 {@code loader *loader.Loader}。 */
    final Loader loader;
    /** 对应 Go 的 {@code engine *operators.Engine}。 */
    final Engine engine;
    /** 对应 Go 的 {@code workPool *WorkPool}。 */
    WorkPool workPool;
    /** 对应 Go 的 {@code progress *ProgressTracker}。 */
    final ProgressTracker progress;
    /** 对应 Go 的 {@code httpExec *protocol.HTTPExecutor}。 */
    final HTTPExecutor httpExec;
    /** 对应 Go 的 {@code dnsExec *protocol.DNSExecutor}。 */
    final DNSExecutor dnsExec;
    /** 对应 Go 的 {@code tcpExec *protocol.TCPExecutor}。 */
    final TCPExecutor tcpExec;
    /** 对应 Go 的 {@code sslExec *protocol.SSLExecutor}。 */
    final SSLExecutor sslExec;
    /** 对应 Go 的 {@code verbose bool}（Go 在 mu 内写、热路径直接读，Java 照抄）。 */
    boolean verbose;
    /** 对应 Go 的 {@code varEngine *variable.Engine}（与 operators.Engine 同名类，全限定引用）。 */
    final space.jyscan.modules.nuclei.variable.Engine varEngine;
    /** 对应 Go 的 {@code dslEval *dsl.Evaluator}（Go 侧构造后无调用方，为结构对齐保留）。 */
    final Evaluator dslEval;
    /** 对应 Go 的 {@code mu sync.RWMutex}。 */
    final ReentrantReadWriteLock mu = new ReentrantReadWriteLock();
    /**
     * 对应 Go 的 {@code wg sync.WaitGroup}。
     *
     * <p>Go 侧该字段本身 0 使用（{@code Run} 用的是局部 {@code wg}）；
     * Java 侧将其复用为 {@link #run(List)} 单场次的目标数闸门，避免留下死字段。
     */
    CountDownLatch wg;
    /** 对应 Go 的 {@code results chan *model.ResultEvent}（容量 1000，见 {@code New}）。 */
    final BlockingQueue<ResultEvent> results;
    /** 对应 Go 的 {@code hostErrors *utils.HostErrorsCache}。 */
    final HostErrorsCache hostErrors;
    /** 对应 Go 的 {@code rateLimiter *RateLimiter}（Options 零值时为 nil，与 Go 一致）。 */
    RateLimiter rateLimiter;
    /**
     * 对应 Go 的 {@code stopCh chan struct{}}：{@code Stop()} 与 {@code run} 结束时关闭。
     *
     * <p>Go 二次 {@code close} 会 panic，Java 的 {@code countDown} 幂等（更安全，属有意差异）。
     */
    final CountDownLatch stopCh = new CountDownLatch(1);
    /** 对应 Go 的 {@code strategy ScanStrategy}。 */
    ScanStrategy strategy;

    /** {@code time.RFC3339} = {@code 2006-01-02T15:04:05Z07:00}。 */
    private static final DateTimeFormatter RFC3339 = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");
    /** {@code FormatResultDetailed} 首行时间戳格式 {@code 2006-01-02 15:04:05}（UTC）。 */
    private static final DateTimeFormatter DETAIL_TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * 对应 Go 的 {@code NewRunner() *Runner}，其内部即 {@code New(model.Options{})}
     * （{@code New} 按死代码约定不作为公开 API 移植，初始化逻辑收进本构造器）。
     */
    public Runner() {
        // Go: r := &Runner{ opts: options, loader: loader.NewLoader(), engine: operators.NewEngine(),
        //        workPool: NewWorkPool(WorkPoolConfig{InputConcurrency: options.Threads, TypeConcurrency: options.Threads}),
        //        progress: NewProgressTracker(), results: make(chan *model.ResultEvent, 1000),
        //        hostErrors: utils.NewHostErrorsCache(30), stopCh: make(chan struct{}), strategy: StrategyAuto }
        this.opts = new Options();
        this.loader = new Loader();
        this.engine = new Engine();
        WorkPoolConfig initialConfig = new WorkPoolConfig();
        initialConfig.inputConcurrency = opts.threads;
        initialConfig.typeConcurrency = opts.threads;
        this.workPool = new WorkPool(initialConfig);
        this.progress = new ProgressTracker();
        this.results = new LinkedBlockingQueue<>(1000);
        this.hostErrors = new HostErrorsCache(30); // nuclei 官方: MaxHostError 默认 30
        this.strategy = ScanStrategy.AUTO;

        if (opts.rateLimit > 0) {
            this.rateLimiter = new RateLimiter(opts.rateLimit);
        }

        this.httpExec = new HTTPExecutor();
        this.dnsExec = new DNSExecutor();
        this.tcpExec = new TCPExecutor();
        this.sslExec = new SSLExecutor();
        this.varEngine = new space.jyscan.modules.nuclei.variable.Engine();
        this.dslEval = new Evaluator();

        registerVariableFunctions();
    }

    /**
     * 对应 Go 的 {@code (r *Runner) SetWorkPoolConfig(config WorkPoolConfig)}。
     *
     * <p>Go 侧先 {@code RefreshWithConfig} 刷新已有工作池、再记配置（配置落在 {@code workPool.config}，
     * Runner 自身不保存副本）；工作池为 nil 时才新建 —— Java 照抄该分支。
     */
    public void setWorkPoolConfig(WorkPoolConfig config) {
        if (workPool != null) {
            workPool.refreshWithConfig(config);
        } else {
            workPool = new WorkPool(config);
        }
    }

    /** 对应 Go 的 {@code (r *Runner) SetVerbose(v bool)}（写锁内更新）。 */
    public void setVerbose(boolean v) {
        mu.writeLock().lock();
        try {
            verbose = v;
        } finally {
            mu.writeLock().unlock();
        }
    }

    /** 对应 Go 的 {@code (r *Runner) SetStrategy(strategy ScanStrategy)}（Go 侧无锁直写）。 */
    public void setStrategy(ScanStrategy strategy) {
        this.strategy = strategy;
    }

    /**
     * 加载单个模板文件。
     *
     * <p>对应 Go 的 {@code (r *Runner) LoadTemplate(path string) (*model.Template, error)}，
     * 实现为 {@code return r.loader.LoadTemplate(path)}。
     *
     * @return {@code Object[]{Template, Throwable}}
     */
    public Object[] loadTemplate(String path) {
        return loader.loadTemplate(path);
    }

    /**
     * 加载目录下所有模板。
     *
     * <p>对应 Go 的 {@code (r *Runner) LoadTemplates(dir string) ([]*model.Template, error)}，
     * 实现为 {@code return r.loader.LoadTemplates(dir)}。
     *
     * @return {@code Object[]{List<Template>, Throwable}}
     */
    public Object[] loadTemplates(String dir) {
        return loader.loadTemplates(dir);
    }

    /**
     * 扫描主入口：按策略调度「模板 × 目标」，命中时回调结果。
     *
     * <p>对应 Go 的
     * {@code (r *Runner) ExecuteWithCallback(ctx context.Context, templates []*model.Template, targets []string, callback func(*ScanResult))}；
     * Go 的 {@code ctx} 首参按项目约定省略。
     *
     * <p><b>三种策略：</b>Go 的 ExecuteWithCallback 只有一种循环序（target 外层、template 内层，
     * {@code runner.go:290-358}），{@code strategy} 字段在 Go 全树<b>写而不读</b>。按任务要求三种策略
     * 落成真实调度：{@link ScanStrategy#TEMPLATE_SPRAY} 以 template 为外层（每个模板打完全部目标再换下一个）、
     * {@link ScanStrategy#HOST_SPRAY} 以 target 为外层；{@link ScanStrategy#AUTO} 作为默认策略
     * 锚定 Go 的实际行为（同 host-spray 序），保证默认路径与 Go 逐位一致。
     *
     * <p><b>回调时机与 Go 一致：</b>Go 只在<b>命中</b>时向 results 通道投递并回调
     * （HTTP/DNS/flow 三分支皆然），未命中不回调 —— CLI 的 totalCount 因此等于 matchCount
     * （Go 侧亦如此）。Go 的消费 goroutine 与生产循环是单生产者单消费者 FIFO，
     * 回调的取值与顺序和同步调用完全等价，故 Java 在生产循环内同步回调（省去 channel 生命周期）。
     */
    public void executeWithCallback(List<Template> templates, List<String> targets,
                                    Consumer<ScanResult> callback) {
        mu.writeLock().lock();
        try {
            this.templates = templates;
        } finally {
            mu.writeLock().unlock();
        }

        ScanStrategy s = strategy != null ? strategy : ScanStrategy.AUTO;
        switch (s) {
            case TEMPLATE_SPRAY:
                // template-spray: template 在外层 —— 每个模板依次打完全部目标，再轮到下一个模板
                if (templates != null) {
                    for (Template t : templates) {
                        if (targets == null) {
                            continue;
                        }
                        for (String target : targets) {
                            executeTemplateWithCallback(t, target, callback);
                        }
                    }
                }
                break;
            case HOST_SPRAY:
                // host-spray: target 在外层 —— 每个目标依次跑完全部模板，再轮到下一个目标
                if (targets != null) {
                    for (String target : targets) {
                        if (templates == null) {
                            continue;
                        }
                        for (Template t : templates) {
                            executeTemplateWithCallback(t, target, callback);
                        }
                    }
                }
                break;
            case AUTO:
            default:
                // Go-parity: Go 的 ExecuteWithCallback 唯一循环序即「target 外层」
                // （runner.go:290 for targets / :291 for templates），AUTO 默认策略按 Go 实际行为执行
                if (targets != null) {
                    for (String target : targets) {
                        if (templates == null) {
                            continue;
                        }
                        for (Template t : templates) {
                            executeTemplateWithCallback(t, target, callback);
                        }
                    }
                }
                break;
        }
    }

    /**
     * 对 Go {@code ExecuteWithCallback} 双层循环<b>内层体</b>（{@code runner.go:292-357}）的提取：
     * flow 分支 + 无 flow 的 HTTP/DNS 逐请求执行，命中即回调。
     * 三种策略只是外层循环次序不同，内层体共享本方法（Go 无策略分支，故 Java 侧提取私有方法以供复用）。
     */
    private void executeTemplateWithCallback(Template t, String target, Consumer<ScanResult> callback) {
        Map<String, Object> baseVars = makeBaseVariables(target);
        List<HTTPRequest> httpReqs = t.getAllHTTP();

        // nuclei 官方: 如果模板有 flow 指令, 使用 flow 执行器
        if (t.flow != null && !t.flow.isEmpty() && httpReqs != null && !httpReqs.isEmpty()) {
            Object[] flow = executeFlow(t, target, baseVars);
            boolean flowMatched = Boolean.TRUE.equals(flow[0]);
            FlowExecutor flowExec = (FlowExecutor) flow[4];
            // nuclei-dev 对齐(误报修复): 除 flowMatched 外，还须存在「按 nuclei 语义会产生
            // 事件」的步骤（有 matcher 命中，或无 matcher 的步骤提取出非 internal 值）
            if (flowMatched && flowExec != null && flowExec.anyEventQualified()) {
                // flow 执行成功: 提取最后一个请求的结果
                String flowMatcherName = (String) flow[1];
                @SuppressWarnings("unchecked")
                Map<String, String> flowExtracted = (Map<String, String>) flow[2];
                @SuppressWarnings("unchecked")
                Map<String, Object> flowData = (Map<String, Object>) flow[3];
                ProtocolResult lastResult = getLastFlowResult(t, target, baseVars);
                // Go: lastResult.(*protocol.ProtocolResult) 类型断言 —— httpExec.Execute 恒返回该类型，Java 直接判 null
                if (lastResult != null) {
                    ResultEvent event = makeResultEvent(t, target, lastResult, flowMatched, flowExtracted);
                    event.matcherName = flowMatcherName;
                    if (flowData != null) {
                        event.data = flowData;
                    }
                    emitResult(event, callback);
                }
            }
            return;
        }

        // 无 flow 指令: 原有逻辑 (每个请求独立执行)
        if (httpReqs != null) {
            for (HTTPRequest req : httpReqs) {
                if (verbose) {
                    String method = req.method == null || req.method.isEmpty() ? "GET" : req.method;
                    // nuclei 官方 verbose: 显示请求的完整 path
                    String pathStr = req.path == null ? "" : String.join(",", req.path);
                    System.err.printf("[VERB] [HTTP] %s %s %s [%s]%n", t.id, method, target, pathStr);
                }
                ProtocolResult result = httpExec.execute(req, target, baseVars);
                if (verbose && result.error != null) {
                    System.err.printf("[VERB] [HTTP] Error %s: %s%n", target, result.error);
                }
                if (result.error == null) {
                    Object[] pm = engine.processWithMatcher(req.matchers, req.matchersCondition,
                            result.data, t.info);
                    boolean matched = Boolean.TRUE.equals(pm[0]);
                    String matcherName = (String) pm[1];
                    if (verbose) {
                        Object status = result.data == null ? null : result.data.get("status_code");
                        System.err.printf("[VERB] [HTTP] %s [%s] matched=%b matcher=%s%n",
                                target, status, matched, matcherName);
                    }
                    if (matched) {
                        Map<String, String> extracted = engine.extract(req.extractors, result);
                        // nuclei-dev 对齐(误报修复): 无 matchers 的请求须提取出非 internal 值才发结果
                        if (emitsEvent(req.matchers, extracted)) {
                            ResultEvent event = makeResultEvent(t, target, result, matched, extracted);
                            event.matcherName = matcherName;
                            emitResult(event, callback);
                        }
                    }
                }
            }
        }
        if (t.dns != null && !t.dns.isEmpty()) {
            for (DNSRequest req : t.dns) {
                ProtocolResult result = dnsExec.execute(req, target, baseVars);
                if (result.error == null) {
                    Object[] pm = engine.processWithMatcher(req.matchers, req.matchersCondition,
                            result.data, t.info);
                    boolean matched = Boolean.TRUE.equals(pm[0]);
                    String matcherName = (String) pm[1];
                    if (matched) {
                        Map<String, String> extracted = engine.extract(req.extractors, result);
                        // nuclei-dev 对齐(误报修复): 无 matchers 的请求须提取出非 internal 值才发结果
                        if (emitsEvent(req.matchers, extracted)) {
                            ResultEvent event = makeResultEvent(t, target, result, matched, extracted);
                            event.matcherName = matcherName;
                            emitResult(event, callback);
                        }
                    }
                }
            }
        }
        // Go-parity: ExecuteWithCallback 不含 TCP/SSL 分支，也不合并模板变量、不喂 progress/hostErrors —— 照抄
    }

    /**
     * 一次请求是否应生成结果事件（nuclei-dev 对齐，误报修复）。
     *
     * <p>对应 nuclei {@code operators.Execute} 的发射门与
     * {@code MakeDefaultResultEvent}：有 matchers 的请求以命中为准（调用方已处在
     * {@code matched} 分支）；<b>无 matchers 的请求只有产出了非 internal 提取值
     * 才生成事件</b>。freeclient/Java 原先空 matchers 直接判命中并无条件发射，
     * 使「仅提取器模板」对每个响应都报结果（官方模板库 206 个 http/dns 仅提取器模板
     * 全部沦为误报）。
     */
    static boolean emitsEvent(List<Matcher> matchers, Map<String, String> extracted) {
        if (matchers != null && !matchers.isEmpty()) {
            return true;
        }
        return extracted != null && !extracted.isEmpty();
    }

    /**
     * 把一条结果事件转成 {@link ScanResult} 并回调。
     *
     * <p>对应 Go {@code ExecuteWithCallback} 中消费 goroutine 的循环体
     * （{@code runner.go:249-287}）：{@code Matched} 恒为 true、{@code MatchedAt} 取 protocol、
     * 提取数据优先用 {@code ExtractedMap}（name → value）、为空则从 list 回填（v → v，
     * 已存在键跳过）、{@code Duration} 由 RFC3339 时间戳解析（失败保持零值）。
     */
    private void emitResult(ResultEvent result, Consumer<ScanResult> callback) {
        if (verbose) {
            System.err.printf("[VERB] callback invoked for %s on %s%n", result.template.id, result.host);
        }
        ScanResult scanResult = new ScanResult();
        scanResult.template = result.template;
        scanResult.target = result.host;
        scanResult.matched = true;
        scanResult.matchedAt = result.protocol;
        Map<String, Boolean> matchedByProtocol = new HashMap<>();
        matchedByProtocol.put(result.protocol, true);
        scanResult.matchedByProtocol = matchedByProtocol;
        scanResult.protocol = result.protocol;
        scanResult.data = result.data;
        scanResult.matcherName = result.matcherName;
        scanResult.duration = durationSince(result.timestamp);

        // 保留提取器名称 -> 提取值的映射关系 (nuclei 官方: 保留 kval/名称以便引用)
        Map<String, String> extracted = new HashMap<>();
        if (result.extractedMap != null && !result.extractedMap.isEmpty()) {
            // 优先使用 ExtractedMap (name -> value 映射)
            extracted.putAll(result.extractedMap);
        } else if (result.extractedResults != null) {
            // 回退: 从 list 中重建
            for (String v : result.extractedResults) {
                if (extracted.containsKey(v)) {
                    continue;
                }
                extracted.put(v, v);
            }
        }
        scanResult.extracted = extracted;

        callback.accept(scanResult);
    }

    /** 对 Go {@code time.Parse(time.RFC3339, ts)} + {@code time.Since(t)} 的对应；解析失败返回零值 Duration。 */
    private static Duration durationSince(String timestamp) {
        if (timestamp == null || timestamp.isEmpty()) {
            return Duration.ZERO;
        }
        try {
            Instant t = OffsetDateTime.parse(timestamp, DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant();
            return Duration.between(t, Instant.now());
        } catch (DateTimeException e) {
            // DateTimeParseException 是 DateTimeException 的子类：Go 侧 parse 失败 Duration 保持零值
            return Duration.ZERO;
        }
    }

    /**
     * 单行结果格式化，对应 Go 的包级 {@code runner.FormatResult(result *ScanResult) string}。
     *
     * <p>nuclei 官方格式：{@code [template-id[:matcher-name]] [protocol] [severity] target [extracted_data]}。
     * Java 侧映射为本类的静态方法（Go 的包级函数在 Java 中需归入某个类）。
     */
    public static String formatResult(ScanResult result) {
        if (result == null) {
            return "";
        }
        String protocol = result.protocol;
        if (protocol == null || protocol.isEmpty()) {
            protocol = result.matchedAt == null ? "" : result.matchedAt;
        }
        // 模板 ID + 可选 matcher 名称
        String templateId = result.template.id;
        if (result.matcherName != null && !result.matcherName.isEmpty()) {
            templateId = templateId + ":" + result.matcherName;
        }
        // 目标展示: URL 用反引号, 否则直接 host:port
        String target = result.target;
        if (target == null || target.isEmpty()) {
            target = result.matchedAt == null ? "" : result.matchedAt;
        }
        if (isUrl(target)) {
            target = "`" + target + "`";
        }
        StringBuilder b = new StringBuilder();
        b.append(String.format("[%s] [%s] [%s] %s",
                templateId,
                protocol,
                result.template.info.severity,
                target));
        if (result.extracted != null && !result.extracted.isEmpty()) {
            // nuclei 官方: 提取数据用 ["value1","value2"] 风格
            // 过滤空值 (nuclei 官方: 空提取值不显示)；Go 对 key 做了 sort.Strings，Java 同样排序
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
                b.append(" [");
                for (int i = 0; i < nonEmptyValues.size(); i++) {
                    if (i > 0) {
                        b.append(",");
                    }
                    b.append(quoteAscii(nonEmptyValues.get(i)));
                }
                b.append("]");
            }
        }
        return b.toString();
    }

    /**
     * 将字符串用 ASCII 双引号包裹（对应 nuclei {@code strconv.QuoteToASCII} 行为）。
     *
     * <p>对应 Go 的包级 {@code runner.quoteASCII(s string) string}：
     * 先转义 {@code \} 再 {@code "}，随后 {@code \n}/{@code \r}/{@code \t}。
     */
    static String quoteAscii(String s) {
        String quoted = s.replace("\\", "\\\\");
        quoted = quoted.replace("\"", "\\\"");
        // 简化的转义: 控制字符和不可打印字符
        quoted = quoted.replace("\n", "\\n");
        quoted = quoted.replace("\r", "\\r");
        quoted = quoted.replace("\t", "\\t");
        return "\"" + quoted + "\"";
    }

    /**
     * 简单判断字符串是否为 URL（nuclei 官方对 URL 用反引号包裹）。
     *
     * <p>对应 Go 的包级 {@code runner.isURL(s string) bool}。
     */
    static boolean isUrl(String s) {
        return s.startsWith("http://") || s.startsWith("https://");
    }

    /**
     * 多行详细结果格式化。
     *
     * <p>对应 Go 的包级 {@code runner.FormatResultDetailed(result *ScanResult, verbose bool) string}：
     * 首行 {@code [时间戳] [template-id] [protocol] [severity] host}，随后名称/分类/标签/作者/
     * 匹配位置/提取/描述/参考，verbose 时附请求与响应（响应截断 800 字符）。
     *
     * <p>Go-parity 注：Go 的截断（{@code desc[:300]} 等）按<b>字节</b>进行，多字节字符会被切碎；
     * Java 的 {@code String} 按 UTF-16 取 {@code substring}（按 char 截断），此处为已知差异。
     * Go 侧已显式 {@code sort} 的 key 序列 Java 同样排序；Go 未排序的遍历 Java 也不排序。
     */
    public static String formatResultDetailed(ScanResult result, boolean verbose) {
        if (result == null) {
            return "";
        }
        StringBuilder b = new StringBuilder();

        // 第 1 行: 与 nuclei 官方一致的紧凑标识
        // [时间戳] [template-id] [type] [severity] host
        String protocol = result.protocol;
        if (protocol == null || protocol.isEmpty()) {
            protocol = result.matchedAt == null ? "" : result.matchedAt;
        }
        String timestamp = LocalDateTime.now(ZoneOffset.UTC).format(DETAIL_TIMESTAMP);
        b.append(String.format("%n[%s] [%s] [%s] [%s] %s%n",
                timestamp,
                result.template.id,
                protocol,
                result.template.info.severity,
                result.target));

        // 第 2 行: 漏洞名称
        if (result.template.info.name != null && !result.template.info.name.isEmpty()) {
            b.append(String.format("  名称:     %s%n", result.template.info.name));
        }

        // 第 3 行: 分类 (CVE/CWE/CVSS)
        Classification cls = result.template.info.classification;
        if (cls != null) {
            List<String> parts = new ArrayList<>();
            if (cls.cveId != null && !cls.cveId.isEmpty()) {
                parts.add(String.join(", ", cls.cveId));
            }
            if (cls.cweId != null && !cls.cweId.isEmpty()) {
                parts.add(String.join(", ", cls.cweId));
            }
            if (cls.cvssScore > 0) {
                parts.add(String.format(Locale.ROOT, "CVSS:%.1f", cls.cvssScore));
            }
            if (!parts.isEmpty()) {
                b.append(String.format("  分类:     %s%n", String.join(" | ", parts)));
            }
        }

        // 第 4 行: 标签
        if (result.template.info.tags != null && !result.template.info.tags.isEmpty()) {
            b.append(String.format("  标签:     %s%n", String.join(", ", result.template.info.tags)));
        }

        // 第 5 行: 作者
        if (result.template.info.author != null && !result.template.info.author.isEmpty()) {
            b.append(String.format("  作者:     %s%n", result.template.info.author));
        }

        // 第 6 行: 匹配位置
        if (result.matchedAt != null && !result.matchedAt.isEmpty()) {
            b.append(String.format("  匹配位置: %s%n", result.matchedAt));
        }

        // 第 7 行: 提取数据
        if (result.extracted != null && !result.extracted.isEmpty()) {
            List<String> parts = new ArrayList<>();
            // 稳定排序: 按 key 字母序（Go 侧 sort.Strings，Java 同样排序）
            List<String> keys = new ArrayList<>(result.extracted.keySet());
            Collections.sort(keys);
            for (String k : keys) {
                String v = result.extracted.get(k);
                if (v != null && v.length() > 200) {
                    v = v.substring(0, 200) + "...";
                }
                parts.add(String.format("%s=%s", k, v));
            }
            b.append(String.format("  提取:     %s%n", String.join(", ", parts)));
        }

        // 第 8 行: 描述 (截断过长内容)
        if (result.template.info.description != null && !result.template.info.description.isEmpty()) {
            String desc = result.template.info.description.trim();
            // 多行描述使用第一行（Go: strings.Index(desc, "\n") > 0 才截断）
            int idx = desc.indexOf('\n');
            if (idx > 0) {
                desc = desc.substring(0, idx);
            }
            if (desc.length() > 300) {
                desc = desc.substring(0, 300) + "...";
            }
            b.append(String.format("  描述:     %s%n", desc));
        }

        // 第 9 行: 参考链接
        if (result.template.info.reference != null && !result.template.info.reference.isEmpty()) {
            b.append("  参考:\n");
            for (String ref : result.template.info.reference) {
                if (ref != null && ref.length() > 120) {
                    ref = ref.substring(0, 120) + "...";
                }
                b.append(String.format("    - %s%n", ref));
            }
        }

        // verbose 模式: 显示请求和响应
        if (verbose) {
            String req = getRequestString(result);
            if (!req.isEmpty()) {
                b.append("  请求:\n");
                indentLines(b, req, "    ");
            }
            String resp = getResponseString(result);
            if (!resp.isEmpty()) {
                b.append("  响应 (前 800 字符):\n");
                String truncated = resp;
                if (truncated.length() > 800) {
                    truncated = truncated.substring(0, 800) + "...";
                }
                indentLines(b, truncated, "    ");
            }
        }

        return b.toString();
    }

    /**
     * 从 result.Data 中提取原始请求。
     *
     * <p>对应 Go 的包级 {@code runner.getRequestString(result *ScanResult) string}
     * （依次尝试 {@code request} / {@code raw_request}，空串继续向下尝试）。
     */
    static String getRequestString(ScanResult result) {
        if (result.data == null) {
            return "";
        }
        Object req = result.data.get("request");
        if (req instanceof String && !((String) req).isEmpty()) {
            return (String) req;
        }
        Object rawReq = result.data.get("raw_request");
        if (rawReq instanceof String && !((String) rawReq).isEmpty()) {
            return (String) rawReq;
        }
        return "";
    }

    /**
     * 从 result.Data 中提取原始响应。
     *
     * <p>对应 Go 的包级 {@code runner.getResponseString(result *ScanResult) string}
     * （依次尝试 {@code response} / {@code raw_response}）。
     */
    static String getResponseString(ScanResult result) {
        if (result.data == null) {
            return "";
        }
        Object resp = result.data.get("response");
        if (resp instanceof String && !((String) resp).isEmpty()) {
            return (String) resp;
        }
        Object rawResp = result.data.get("raw_response");
        if (rawResp instanceof String && !((String) rawResp).isEmpty()) {
            return (String) rawResp;
        }
        return "";
    }

    /**
     * 将多行文本按指定前缀缩进。
     *
     * <p>对应 Go 的包级 {@code runner.indentLines(b *strings.Builder, s, prefix string)}
     * （按 {@code \n} 切分，逐行加前缀与换行）。
     */
    static void indentLines(StringBuilder b, String s, String prefix) {
        for (String line : s.split("\n", -1)) {
            b.append(prefix);
            b.append(line);
            b.append("\n");
        }
    }

    /**
     * 向 {@code variable.Engine} 注册七个编解码/哈希函数。
     *
     * <p>对应 Go 的 {@code (r *Runner) registerVariableFunctions()}（{@code runner.go:603-617}）：
     * {@code base64}/{@code url_encode}/{@code url_decode}/{@code md5}/{@code sha256}/
     * {@code hex_encode}/{@code hex_decode}，函数体均转调 protocol 包的静态方法。
     */
    void registerVariableFunctions() {
        varEngine.registerFunction("base64", Runner::base64Encode);
        varEngine.registerFunction("url_encode", Runner::urlEncode);
        varEngine.registerFunction("url_decode", Runner::urlDecode);
        varEngine.registerFunction("md5", Runner::md5Hash);
        varEngine.registerFunction("sha256", Runner::sha256Hash);
        varEngine.registerFunction("hex_encode", Runner::hexEncode);
        varEngine.registerFunction("hex_decode", Runner::hexDecode);
    }

    /**
     * 批量执行（{@code Run} 链路）：每个 target 一个并发任务，进度每 5 秒打印一次。
     *
     * <p>对应 Go 的 {@code (r *Runner) Run(targets []string) error}（Java 按约定返回
     * {@code Throwable}，成功为 {@code null}，Go 恒返回 nil）。
     *
     * <p>Go 的进度 goroutine（5 秒 ticker + stopCh 退出）对应 Java 的守护线程 +
     * {@link CountDownLatch#await(long, TimeUnit)} 轮询；Go 的「每 target 一个 goroutine」
     * 对应 Java 缓存线程池。
     *
     * <p>Go 缺陷照抄说明：循环开头的
     * {@code select { case <-r.stopCh: break; default: }} 中 {@code break} 只作用于 select
     * 而非 for（Go 侧无效写法），故停止标志并不中断派发循环 —— Java 侧保留同样的「不中断」行为，
     * 由 {@link #executeForTarget} 内的逐模板检查兜底（与 Go 实际执行路径一致）。
     * 另：Go 的 {@code r.results} 无任何消费方（{@code Results()} 是死代码），
     * 第 1001 条事件起 {@code Run} 会在 channel 上永久阻塞；Java 的 {@code put} 同样阻塞（语义照抄）。
     */
    public Throwable run(List<String> targets) {
        int targetCount = targets == null ? 0 : targets.size();
        System.err.printf("开始扫描 %d 个目标%n", targetCount);

        // 对应 Go: progressTicker := time.NewTicker(5 * time.Second) + 消费 goroutine
        Thread progressTicker = new Thread(() -> {
            try {
                while (!stopCh.await(5, TimeUnit.SECONDS)) {
                    progress.printProgress();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "jyscan-nuclei-progress");
        progressTicker.setDaemon(true);
        progressTicker.start();

        // 对应 Go: var wg sync.WaitGroup（Java 复用结构体字段 wg 承载本场次闸门）
        CountDownLatch targetWg = new CountDownLatch(targetCount);
        this.wg = targetWg;
        ExecutorService pool = Executors.newCachedThreadPool(); // Go: 每 target 一个 goroutine（无界并发）
        try {
            if (targets != null) {
                for (String target : targets) {
                    // Go: select { case <-r.stopCh: break; default: } —— break 不中断 for（Go 缺陷，照抄不生效）
                    if (rateLimiter != null) {
                        rateLimiter.await();
                    }
                    String t = target;
                    pool.execute(() -> {
                        try {
                            executeForTarget(t);
                        } finally {
                            targetWg.countDown();
                        }
                    });
                }
            }
            targetWg.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            pool.shutdown(); // Go: wg.Wait() 后 goroutine 自然结束
        }

        // Go: close(r.results) —— Java 的 BlockingQueue 无关闭语义，事件仍留在队列中（无消费方，见方法注释）
        stopCh.countDown(); // Go: close(r.stopCh)
        progress.printProgress();
        return null;
    }

    /**
     * 对单个 target 依次执行全部模板。
     *
     * <p>对应 Go 的 {@code (r *Runner) executeForTarget(target string)}
     * （读锁取模板；遇停止标志提前返回；模板执行出错计一次 error，模板数恒 +1）。
     */
    void executeForTarget(String target) {
        List<Template> tpl;
        mu.readLock().lock();
        try {
            tpl = this.templates;
        } finally {
            mu.readLock().unlock();
        }
        if (tpl == null) {
            return;
        }
        for (Template t : tpl) {
            if (isStopped()) { // Go: select { case <-r.stopCh: return; default: }
                return;
            }
            Throwable err = executeTemplate(t, target);
            if (err != null) {
                progress.incrementErrors();
            }
            progress.incrementTemplates();
        }
    }

    /**
     * 按 HTTP → DNS → TCP → SSL 顺序执行一个模板，遇错即中止该模板。
     *
     * <p>对应 Go 的 {@code (r *Runner) executeTemplate(t *model.Template, target string) error}。
     */
    Throwable executeTemplate(Template t, String target) {
        Map<String, Object> baseVars = makeBaseVariables(target);

        List<HTTPRequest> httpReqs = t.getAllHTTP();
        if (httpReqs != null && !httpReqs.isEmpty()) {
            for (HTTPRequest req : httpReqs) {
                Throwable err = executeHTTPRequest(req, t, target, baseVars);
                if (err != null) {
                    return err;
                }
            }
        }

        if (t.dns != null && !t.dns.isEmpty()) {
            for (DNSRequest req : t.dns) {
                Throwable err = executeDNSRequest(req, t, target, baseVars);
                if (err != null) {
                    return err;
                }
            }
        }

        if (t.tcp != null && !t.tcp.isEmpty()) {
            for (TCPRequest req : t.tcp) {
                Throwable err = executeTCPRequest(req, t, target, baseVars);
                if (err != null) {
                    return err;
                }
            }
        }

        if (t.ssl != null && !t.ssl.isEmpty()) {
            for (SSLRequest req : t.ssl) {
                Throwable err = executeSSLRequest(req, t, target, baseVars);
                if (err != null) {
                    return err;
                }
            }
        }

        return null;
    }

    /**
     * 构造目标的基础变量。
     *
     * <p>对应 Go 的 {@code (r *Runner) makeBaseVariables(target string) map[string]interface{}}：
     * 先并入 {@code utils.GenerateURLVariables(target, true)}，再对形如 {@code host:port}
     * （非 http 前缀、恰好两段）的目标补 {@code Host}/{@code Port}。
     */
    Map<String, Object> makeBaseVariables(String target) {
        Map<String, Object> vars = new HashMap<>();

        Map<String, Object> urlVars = Variables.generateUrlVariables(target, true);
        if (urlVars != null) {
            vars.putAll(urlVars);
        }

        if (target != null && target.contains(":") && !target.startsWith("http")) {
            String[] parts = target.split(":", -1); // Go strings.Split 全量切分（含尾部空段），limit -1 对齐
            if (parts.length == 2) {
                vars.put("Host", parts[0]);
                vars.put("Port", parts[1]);
            }
        }

        return vars;
    }

    /**
     * 执行单个 HTTP 请求（{@code Run} 链路的 HTTP 分支）。
     *
     * <p>对应 Go 的 {@code (r *Runner) executeHTTPRequest(req *model.HTTPRequest, t *model.Template,
     * target string, baseVars map[string]interface{}) error}（{@code runner.go:819}），逐行对照：
     * 执行前查 {@code HostErrorsCache} 跳过已标记主机 → 合并模板变量 → 执行 →
     * {@code progress.IncrementRequests()} → 出错计入 {@code hostErrors} 并返回错误 →
     * {@code ProcessWithMatcher} → 命中则提取、计数、投递事件；{@code StopAtFirstMatch} 照抄。
     *
     * <p>Go-parity 注：{@code t.StopAtFirstMatch} 分支在 Go 中 {@code return nil}——
     * 与不命中时的返回值相同，循环并不中止（Go 侧该开关实际无效）；Java 照抄该行为。
     */
    Throwable executeHTTPRequest(HTTPRequest req, Template t, String target, Map<String, Object> baseVars) {
        // nuclei 官方: 执行前检查 host 是否已经被标记为失败 (nuclei 官方: HostErrorsCache.Check)
        if (hostErrors != null) {
            // 标准化 host key (与 add 时使用的格式保持一致: "host:port" 或 "host")
            String hostKey = Variables.normalizeHostKey(target);
            if (hostErrors.isHostError(hostKey)) {
                // host 已经被跳过, 跳过本次执行
                return null;
            }
        }

        Map<String, Object> vars = mergeVariables(t.variables, baseVars);

        ProtocolResult result = httpExec.execute(req, target, vars);
        progress.incrementRequests();

        if (result.error != null) {
            hostErrors.add(result.error);
            return result.error;
        }

        Object[] pm = engine.processWithMatcher(req.matchers, req.matchersCondition, result.data, t.info);
        boolean matched = Boolean.TRUE.equals(pm[0]);
        String matcherName = (String) pm[1];
        if (matched) {
            Map<String, String> extracted = engine.extract(req.extractors, result);
            // nuclei-dev 对齐(误报修复): 无 matchers 的请求须提取出非 internal 值才发结果
            if (emitsEvent(req.matchers, extracted)) {
                progress.incrementMatched();

                ResultEvent event = makeResultEvent(t, target, result, matched, extracted);
                event.matcherName = matcherName;
                publishResult(event);

                if (t.stopAtFirstMatch) {
                    return null; // Go 照抄：返回 nil 并不中止外层请求循环（Go 侧无效分支）
                }
            }
        }

        return null;
    }

    /**
     * 执行单个 DNS 请求。
     *
     * <p>对应 Go 的 {@code (r *Runner) executeDNSRequest(...)}（{@code runner.go:857}）：
     * 与 HTTP 分支同构，但<b>无</b> hostErrors 检查/计入（Go 侧仅 HTTP 分支调用 {@code hostErrors.Add}）。
     */
    Throwable executeDNSRequest(DNSRequest req, Template t, String target, Map<String, Object> baseVars) {
        Map<String, Object> vars = mergeVariables(t.variables, baseVars);

        ProtocolResult result = dnsExec.execute(req, target, vars);
        progress.incrementRequests();

        if (result.error != null) {
            return result.error;
        }

        Object[] pm = engine.processWithMatcher(req.matchers, req.matchersCondition, result.data, t.info);
        boolean matched = Boolean.TRUE.equals(pm[0]);
        String matcherName = (String) pm[1];
        if (matched) {
            Map<String, String> extracted = engine.extract(req.extractors, result);
            // nuclei-dev 对齐(误报修复): 无 matchers 的请求须提取出非 internal 值才发结果
            if (emitsEvent(req.matchers, extracted)) {
                progress.incrementMatched();

                ResultEvent event = makeResultEvent(t, target, result, matched, extracted);
                event.matcherName = matcherName;
                publishResult(event);
            }
        }

        return null;
    }

    /**
     * 执行单个 TCP 请求。
     *
     * <p>对应 Go 的 {@code (r *Runner) executeTCPRequest(...)}（{@code runner.go:880}），与 DNS 分支同构。
     */
    Throwable executeTCPRequest(TCPRequest req, Template t, String target, Map<String, Object> baseVars) {
        Map<String, Object> vars = mergeVariables(t.variables, baseVars);

        ProtocolResult result = tcpExec.execute(req, target, vars);
        progress.incrementRequests();

        if (result.error != null) {
            return result.error;
        }

        Object[] pm = engine.processWithMatcher(req.matchers, req.matchersCondition, result.data, t.info);
        boolean matched = Boolean.TRUE.equals(pm[0]);
        String matcherName = (String) pm[1];
        if (matched) {
            Map<String, String> extracted = engine.extract(req.extractors, result);
            // nuclei-dev 对齐(误报修复): 无 matchers 的请求须提取出非 internal 值才发结果
            if (emitsEvent(req.matchers, extracted)) {
                progress.incrementMatched();

                ResultEvent event = makeResultEvent(t, target, result, matched, extracted);
                event.matcherName = matcherName;
                publishResult(event);
            }
        }

        return null;
    }

    /**
     * 执行单个 SSL 请求。
     *
     * <p>对应 Go 的 {@code (r *Runner) executeSSLRequest(...)}（{@code runner.go:903}），与 DNS 分支同构。
     */
    Throwable executeSSLRequest(SSLRequest req, Template t, String target, Map<String, Object> baseVars) {
        Map<String, Object> vars = mergeVariables(t.variables, baseVars);

        ProtocolResult result = sslExec.execute(req, target, vars);
        progress.incrementRequests();

        if (result.error != null) {
            return result.error;
        }

        Object[] pm = engine.processWithMatcher(req.matchers, req.matchersCondition, result.data, t.info);
        boolean matched = Boolean.TRUE.equals(pm[0]);
        String matcherName = (String) pm[1];
        if (matched) {
            Map<String, String> extracted = engine.extract(req.extractors, result);
            // nuclei-dev 对齐(误报修复): 无 matchers 的请求须提取出非 internal 值才发结果
            if (emitsEvent(req.matchers, extracted)) {
                progress.incrementMatched();

                ResultEvent event = makeResultEvent(t, target, result, matched, extracted);
                event.matcherName = matcherName;
                publishResult(event);
            }
        }

        return null;
    }

    /**
     * 合并基础变量与模板变量（模板变量覆盖同名基础变量）。
     *
     * <p>对应 Go 的 {@code (r *Runner) mergeVariables(templateVars, baseVars map[string]interface{})}：
     * 先拷 base、再拷 template（后者胜出）；Go 对 {@code nil} map 的 range 是空操作，
     * Java 侧以 {@code null} 判断对齐。
     */
    Map<String, Object> mergeVariables(Map<String, Object> templateVars, Map<String, Object> baseVars) {
        Map<String, Object> vars = new HashMap<>();
        if (baseVars != null) {
            vars.putAll(baseVars);
        }
        if (templateVars != null) {
            vars.putAll(templateVars);
        }
        return vars;
    }

    /**
     * 由协议执行结果构造结果事件。
     *
     * <p>对应 Go 的 {@code (r *Runner) makeResultEvent(t, target, result, matched, extracted)}：
     * 保留 extractor name → value 映射（无名时以值本身为 key），并盖 RFC3339 时间戳。
     * Go 未使用 {@code matched} 参数（{@code ResultEvent.Matched} 存的是 target），照抄保留。
     */
    ResultEvent makeResultEvent(Template t, String target, ProtocolResult result, boolean matched,
                                Map<String, String> extracted) {
        // nuclei 官方: 保留 extractor name -> value 映射, 没有 name 时用值本身作为 key
        List<String> extractedList = new ArrayList<>();
        Map<String, String> extractedMap = new HashMap<>();
        if (extracted != null) {
            // Go 对 map 的遍历顺序随机，Java 的 HashMap 同样无序 —— 均未显式排序（与 Go 一致）
            for (Map.Entry<String, String> entry : extracted.entrySet()) {
                String name = entry.getKey();
                String v = entry.getValue();
                extractedList.add(v);
                if (name == null || name.isEmpty()) {
                    extractedMap.put(v, v);
                } else {
                    extractedMap.put(name, v);
                }
            }
        }

        ResultEvent event = new ResultEvent();
        event.template = t;
        event.templateId = t.id;
        event.info = t.info;
        event.protocol = result.protocol;
        event.host = target;
        event.matched = target;
        event.extractedResults = extractedList;
        event.extractedMap = extractedMap;
        event.data = result.data;
        event.timestamp = ZonedDateTime.now().format(RFC3339);
        return event;
    }

    /**
     * 把结果事件投递进容量 1000 的 {@link #results} 队列。
     *
     * <p>对应 Go 的 {@code r.results <- event}：channel 满时阻塞（Java {@code put} 同样阻塞）；
     * Go 的发送不可中断，Java 侧仅在线程被中断时放弃本次投递并恢复中断标志。
     */
    private void publishResult(ResultEvent event) {
        try {
            results.put(event);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** 对应 Go 的停止检查 {@code select { case <-r.stopCh: ... }}：stopCh 已 countDown 即视为已关闭。 */
    private boolean isStopped() {
        return stopCh.getCount() == 0;
    }

    /**
     * 返回因错误过多被跳过的主机列表 (nuclei 官方行为)。
     *
     * <p>对应 Go 的 {@code (r *Runner) GetSkippedHosts() []string}，
     * 实现为 {@code return r.hostErrors.SkippedHosts()}（hostErrors 为 nil 时 Go 返回 nil，照抄）。
     */
    public List<String> getSkippedHosts() {
        if (hostErrors == null) {
            return null;
        }
        return hostErrors.skippedHosts();
    }

    /**
     * 返回主机错误缓存。
     *
     * <p>对应 Go 的 {@code (r *Runner) HostErrors() *utils.HostErrorsCache}；
     * CLI 会判 {@code nil} 后调用 {@code ErrorCount(host)}。
     */
    public HostErrorsCache hostErrors() {
        return hostErrors;
    }

    /**
     * 停止扫描。
     *
     * <p>对应 Go 的 {@code (r *Runner) Stop()}：{@code close(r.stopCh)}。
     * Go 对已关闭的 channel 二次 close 会 panic；Java 的 {@code countDown} 幂等（有意差异，更安全）。
     */
    public void stop() {
        stopCh.countDown();
    }

    // ---------- flow（对应 flow.go 中挂在 Runner 上的两个方法） ----------

    /**
     * 解析并执行模板的 flow 指令。
     *
     * <p>对应 Go 的 {@code (r *Runner) executeFlow(t, target, baseVars)
     * (bool, string, map[string]string, map[string]interface{})}（{@code flow.go:399}）：
     * 无 flow / 解析失败（verbose 时打印）均返回空结果，否则交给 {@link FlowExecutor} 执行。
     *
     * @return {@code Object[]{Boolean, String, Map<String,String>, Map<String,Object>, FlowExecutor}}
     *         第五位是执行器实例（nuclei-dev 对齐：供调用方做发射门判定），失败路径为 {@code null}
     */
    Object[] executeFlow(Template t, String target, Map<String, Object> baseVars) {
        if (t.flow == null || t.flow.isEmpty()) {
            return new Object[]{Boolean.FALSE, "", null, null, null};
        }

        FlowNode node;
        try {
            node = new FlowParser(t.flow).parse();
        } catch (FlowParseException e) {
            if (verbose) {
                System.err.printf("[VERB] [FLOW] 解析 flow \"%s\" 失败: %s%n", t.flow, e.getMessage());
            }
            return new Object[]{Boolean.FALSE, "", null, null, null};
        }

        FlowExecutor executor = new FlowExecutor(this, t, target, baseVars);
        Object[] r = executor.execute(node);
        return new Object[]{r[0], r[1], r[2], r[3], executor};
    }

    /**
     * 获取 flow 中最后一个 HTTP 请求的执行结果，用于生成 ResultEvent
     * （nuclei 官方: 用最后一个请求的响应数据）。
     *
     * <p>对应 Go 的 {@code (r *Runner) getLastFlowResult(t, target, baseVars) interface{}}
     * （{@code flow.go:420}）。Go-parity 注：Go 会<b>再次真正发出</b>最后一个请求
     * （与 flow 执行时的那次重复，Go 侧行为照抄）；Go 返回 {@code interface{}} 由调用方类型断言，
     * Java 直接返回 {@link ProtocolResult}（无请求时返回 {@code null}，等价断言失败）。
     */
    ProtocolResult getLastFlowResult(Template t, String target, Map<String, Object> baseVars) {
        List<HTTPRequest> httpReqs = t.getAllHTTP();
        if (httpReqs == null || httpReqs.isEmpty()) {
            return null;
        }
        // 取最后一个请求执行
        HTTPRequest lastReq = httpReqs.get(httpReqs.size() - 1);
        return httpExec.execute(lastReq, target, baseVars);
    }

    // ---------- 对应 runner.go 末尾的包级编解码转发函数（runner.go:992-1018） ----------

    /** 对应 Go 的 {@code base64Encode(s) → protocol.Base64Encode(s)}。 */
    static String base64Encode(String s) {
        return Protocol.base64Encode(s);
    }

    /** 对应 Go 的 {@code urlEncode(s) → protocol.URLEncode(s)}。 */
    static String urlEncode(String s) {
        return Protocol.urlEncode(s);
    }

    /** 对应 Go 的 {@code urlDecode(s) → protocol.URLDecode(s)}。 */
    static String urlDecode(String s) {
        return Protocol.urlDecode(s);
    }

    /** 对应 Go 的 {@code md5Hash(s) → protocol.MD5Hash(s)}。 */
    static String md5Hash(String s) {
        return Protocol.md5Hash(s);
    }

    /** 对应 Go 的 {@code sha256Hash(s) → protocol.SHA256Hash(s)}。 */
    static String sha256Hash(String s) {
        return Protocol.sha256Hash(s);
    }

    /** 对应 Go 的 {@code hexEncode(s) → protocol.HexEncode(s)}。 */
    static String hexEncode(String s) {
        return Protocol.hexEncode(s);
    }

    /** 对应 Go 的 {@code hexDecode(s) → protocol.HexDecode(s)}。 */
    static String hexDecode(String s) {
        return Protocol.hexDecode(s);
    }
}

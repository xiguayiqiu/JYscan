package space.jyscan.modules.nuclei.runner;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import space.jyscan.modules.nuclei.model.HTTPRequest;
import space.jyscan.modules.nuclei.model.Template;
import space.jyscan.modules.nuclei.protocol.ProtocolResult;

/**
 * flow 指令执行器，对应 Go {@code flow.go} 的
 * {@code flowExecResult}/{@code flowExecutor}/{@code mergeExtracted}/{@code mergeData}
 * （{@code flow.go:234-394}，Go 侧全部包私有，Java 侧同样包私有）。
 *
 * <p>执行语义与 Go 逐条对应：按请求编号缓存执行结果（同一 {@code http(n)} 只真正执行一次）、
 * {@code &&} 要求两侧都命中并合并提取数据与 data、{@code ||} 取左侧命中否则取右侧。
 *
 * <p><b>Go-parity 说明：</b>{@code executeBinary} 的 {@code ||} 分支在 Go 中不检查
 * {@code rightMatched}——左侧未命中时<b>无条件返回 true</b>（{@code flow.go:350-356}，
 * 注释写的是「任意一侧匹配即可」但实现漏了右侧判断）。此处按「Go-parity 优先」原样复刻，
 * 并在报告中列为 Go 侧缺陷。
 *
 * <p>Go 的四元返回 {@code (bool, string, map, map)} 在 Java 中映射为
 * {@code Object[]{Boolean, String, Map<String,String>, Map<String,Object>}}，
 * 空值与 Go 的 {@code nil} 对应为 {@code null}。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/runner/flow.go}
 */

/** 单个请求的执行结果，对应 Go 的 {@code flowExecResult}。 */
class FlowExecResult {

    /** 对应 Go 的 {@code requestIndex int}（1-based）。 */
    int requestIndex;
    /** 对应 Go 的 {@code protocol string}。 */
    String protocol = "";
    /** 对应 Go 的 {@code matched bool}。 */
    boolean matched;
    /** 对应 Go 的 {@code matcherName string}。 */
    String matcherName = "";
    /** 对应 Go 的 {@code extracted map[string]string}。 */
    Map<String, String> extracted;
    /** 对应 Go 的 {@code data map[string]interface{}}。 */
    Map<String, Object> data;
    /** 对应 Go 的 {@code err error}。 */
    Throwable err;
}

/**
 * 执行器，对应 Go 的 {@code flowExecutor{template, target, baseVars, runner, results}}。
 *
 * <p>注意：Go 是结构体方法、直接读写 {@code fe} 的字段；Java 中本对象不被 lambda 捕获，
 * 所有状态都在实例字段上，无并发捕获可变字段的问题。
 */
class FlowExecutor {

    /** 对应 Go 的 {@code template *model.Template}。 */
    final Template template;
    /** 对应 Go 的 {@code target string}。 */
    final String target;
    /** 对应 Go 的 {@code baseVars map[string]interface{}}。 */
    final Map<String, Object> baseVars;
    /** 对应 Go 的 {@code runner *Runner}。 */
    final Runner runner;
    /** 对应 Go 的 {@code results map[int]*flowExecResult}（requestIndex -> result）。 */
    final Map<Integer, FlowExecResult> results = new HashMap<>();

    /** 对应 Go 的 {@code newFlowExecutor(runner, template, target, baseVars) *flowExecutor}。 */
    FlowExecutor(Runner runner, Template template, String target, Map<String, Object> baseVars) {
        this.runner = runner;
        this.template = template;
        this.target = target;
        this.baseVars = baseVars;
    }

    /**
     * 执行整个 flow，返回是否匹配。
     *
     * <p>对应 Go 的 {@code (fe *flowExecutor) execute(node flowNode) (bool, string, map, map)}。
     *
     * @return {@code Object[]{Boolean, String, Map<String,String>, Map<String,Object>}}
     */
    Object[] execute(FlowNode node) {
        if (node instanceof FlowNodeRequest) {
            return executeRequest((FlowNodeRequest) node);
        }
        if (node instanceof FlowBinaryExpr) {
            return executeBinary((FlowBinaryExpr) node);
        }
        return new Object[]{Boolean.FALSE, "", null, null};
    }

    /**
     * 执行单个请求（带编号缓存）。
     *
     * <p>对应 Go 的 {@code (fe *flowExecutor) executeRequest(req *flowRequest) (...)}。
     * 仅 {@code http} 协议支持 flow；索引越界 / 请求为空 / 执行出错的返回形态与 Go 逐一对应
     * （出错时 data 仍返回 {@code result.Data}，其余空值为 {@code nil}）。
     */
    @SuppressWarnings("unchecked") // Object[] 四元组的元素还原为 Map 泛型（与 Go 的具名多返回值一一对应）
    Object[] executeRequest(FlowNodeRequest req) {
        // 检查缓存
        FlowExecResult cached = results.get(req.index);
        if (cached != null) {
            return new Object[]{cached.matched, cached.matcherName, cached.extracted, cached.data};
        }

        boolean matched = false;
        String matcherName = "";
        Map<String, String> extracted = null;
        Map<String, Object> data = null;

        String protocolLower = req.protocol == null ? "" : req.protocol.toLowerCase();
        switch (protocolLower) {
            case "http": {
                List<HTTPRequest> httpReqs = template.getAllHTTP();
                int count = httpReqs == null ? 0 : httpReqs.size();
                int idx = req.index - 1; // 1-based -> 0-based
                if (idx < 0 || idx >= count) {
                    FlowExecResult miss = new FlowExecResult();
                    miss.requestIndex = req.index;
                    miss.protocol = "http";
                    miss.matched = false;
                    miss.err = new IllegalArgumentException(
                            String.format("flow: HTTP 请求索引 %d 超出范围 (共 %d 个)", req.index, count));
                    results.put(req.index, miss);
                    return new Object[]{Boolean.FALSE, "", null, null};
                }
                HTTPRequest httpReq = httpReqs.get(idx);
                if (httpReq == null) {
                    FlowExecResult nilReq = new FlowExecResult();
                    nilReq.requestIndex = req.index;
                    nilReq.protocol = "http";
                    nilReq.matched = false;
                    results.put(req.index, nilReq);
                    return new Object[]{Boolean.FALSE, "", null, null};
                }

                ProtocolResult result = runner.httpExec.execute(httpReq, target, baseVars);
                if (result.error != null) {
                    FlowExecResult errResult = new FlowExecResult();
                    errResult.requestIndex = req.index;
                    errResult.protocol = "http";
                    errResult.matched = false;
                    errResult.err = result.error;
                    errResult.data = result.data;
                    results.put(req.index, errResult);
                    return new Object[]{Boolean.FALSE, "", null, result.data};
                }

                Object[] pm = runner.engine.processWithMatcher(httpReq.matchers, httpReq.matchersCondition,
                        result.data, template.info);
                matched = Boolean.TRUE.equals(pm[0]);
                matcherName = (String) pm[1];
                if (matched) {
                    extracted = runner.engine.extract(httpReq.extractors, result);
                }
                data = result.data;
                break;
            }
            default:
                // 非 HTTP 协议暂不支持 flow
                FlowExecResult unsupported = new FlowExecResult();
                unsupported.requestIndex = req.index;
                unsupported.protocol = req.protocol == null ? "" : req.protocol;
                unsupported.matched = false;
                results.put(req.index, unsupported);
                return new Object[]{Boolean.FALSE, "", null, null};
        }

        FlowExecResult stored = new FlowExecResult();
        stored.requestIndex = req.index;
        stored.protocol = req.protocol == null ? "" : req.protocol;
        stored.matched = matched;
        stored.matcherName = matcherName;
        stored.extracted = extracted;
        stored.data = data;
        results.put(req.index, stored);
        return new Object[]{matched, matcherName, extracted, data};
    }

    /**
     * 执行二元表达式。
     *
     * <p>对应 Go 的 {@code (fe *flowExecutor) executeBinary(expr *flowBinaryExpr) (...)}。
     * {@code &&}：两侧都命中才命中，合并提取与 data，matcher 名取右侧；
     * {@code ||}：<b>照抄 Go 的缺陷实现</b>——左侧命中取左侧，否则无条件返回
     * {@code true} + 右侧结果（不检查右侧是否命中）。
     */
    @SuppressWarnings("unchecked") // Object[] 四元组的元素还原为 Map 泛型（与 Go 的具名多返回值一一对应）
    Object[] executeBinary(FlowBinaryExpr expr) {
        Object[] left = execute(expr.left);
        boolean leftMatched = Boolean.TRUE.equals(left[0]);
        String leftName = (String) left[1];
        Map<String, String> leftExtracted = (Map<String, String>) left[2];
        Map<String, Object> leftData = (Map<String, Object>) left[3];

        Object[] right = execute(expr.right);
        boolean rightMatched = Boolean.TRUE.equals(right[0]);
        String rightName = (String) right[1];
        Map<String, String> rightExtracted = (Map<String, String>) right[2];
        Map<String, Object> rightData = (Map<String, Object>) right[3];

        switch (expr.operator) {
            case AND:
                // &&: 两侧都必须匹配
                if (leftMatched && rightMatched) {
                    Map<String, String> merged = mergeExtracted(leftExtracted, rightExtracted);
                    Map<String, Object> mergedData = mergeData(leftData, rightData);
                    return new Object[]{Boolean.TRUE, rightName, merged, mergedData};
                }
                return new Object[]{Boolean.FALSE, "", null, null};
            case OR:
                // ||: Go-parity —— 左侧命中取左侧；否则无条件返回 true + 右侧
                // （Go 未检查 rightMatched，见类注释与 flow.go:350-356）
                if (leftMatched) {
                    return new Object[]{Boolean.TRUE, leftName, leftExtracted, leftData};
                }
                return new Object[]{Boolean.TRUE, rightName, rightExtracted, rightData};
            default:
                return new Object[]{Boolean.FALSE, "", null, null};
        }
    }

    /**
     * 合并两个提取结果，对应 Go 的 {@code mergeExtracted(a, b map[string]string)}：
     * 任一侧为空直接返回另一侧，否则浅拷贝合并（b 覆盖 a 的同名键）。
     */
    static Map<String, String> mergeExtracted(Map<String, String> a, Map<String, String> b) {
        if (a == null || a.isEmpty()) {
            return b;
        }
        if (b == null || b.isEmpty()) {
            return a;
        }
        Map<String, String> merged = new HashMap<>(a.size() + b.size());
        merged.putAll(a);
        merged.putAll(b);
        return merged;
    }

    /**
     * 合并两个 data map，对应 Go 的 {@code mergeData(a, b map[string]interface{})}
     * （与 {@link #mergeExtracted} 同构）。
     */
    static Map<String, Object> mergeData(Map<String, Object> a, Map<String, Object> b) {
        if (a == null || a.isEmpty()) {
            return b;
        }
        if (b == null || b.isEmpty()) {
            return a;
        }
        Map<String, Object> merged = new HashMap<>(a.size() + b.size());
        merged.putAll(a);
        merged.putAll(b);
        return merged;
    }
}

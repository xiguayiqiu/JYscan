package space.jyscan.modules.nuclei.dsl;

import java.util.HashMap;
import java.util.Map;

/**
 * DSL 评估器，对应 Go 的 {@code dsl.Evaluator}（{@code evaluator.go}）。
 *
 * <p>跨包契约：matcher / extractor / operators / runner 四个包持有本类型字段
 * （Go 侧 {@code dslEvaluator}/{@code evaluator}/{@code dslEval}），只调用
 * {@link #setVar}/{@link #evaluate}/{@link #getVariables} 三个方法。
 *
 * <p>Go 的 {@code Evaluate(expression, vars) (interface{}, error)} 二元返回按项目
 * 既有惯例映射为 {@code Object[]{值, Throwable}}：{@code [1] == null} 表示成功、
 * {@code [0]} 为求值结果；失败时 {@code [0] == null} 且 {@code [1]} 为异常。
 *
 * <p><b>实现说明：</b>Go 的 {@code (e *Evaluator) Evaluate} 先合并自身 vars 与入参 vars
 * （入参覆盖同名），再调包级 {@code ResolveVariables} 解析 {@code {{...}}} 变量，
 * 最后调包级 {@code Evaluate} 走 parser 求值。
 */
public class Evaluator {

    /** 对应 Go 的 {@code vars map[string]interface{}}。 */
    private Map<String, Object> vars = new HashMap<>();

    /** 对应 Go 的 {@code NewEvaluator() *Evaluator}（Go 侧初始化为空 map）。 */
    public Evaluator() {
        this.vars = new HashMap<>();
    }

    /** 对应 Go 的 {@code (e *Evaluator) SetVar(name string, value interface{})}。 */
    public void setVar(String name, Object value) {
        if (vars == null) {
            vars = new HashMap<>();
        }
        vars.put(name, value);
    }

    /**
     * 对应 Go 的 {@code (e *Evaluator) Evaluate(expression string, vars map[string]interface{}) (interface{}, error)}。
     *
     * <p>流程与 Go 一致：①合并自身 {@code e.vars} 与入参 {@code vars}（入参覆盖同名）
     * ②调包级 {@link Eval#resolveVariables} 解析 {@code {{...}}} 变量
     * ③调包级 {@link Eval#evaluate} 走 parser 求值。
     *
     * <p>返回 {@code Object[]{值, Throwable}}；{@code [1] != null} 表示求值失败
     * （此时 {@code [0] == null}）。入参 {@code vars} 允许为 null（Go 侧 nil map 同义）。
     */
    public Object[] evaluate(String expression, Map<String, Object> vars) {
        try {
            Map<String, Object> merged = new HashMap<>();
            if (this.vars != null) {
                merged.putAll(this.vars);
            }
            if (vars != null) {
                merged.putAll(vars); // 入参覆盖同名
            }
            // 先解析 {{...}} 变量
            Object[] rr = Eval.resolveVariables(expression, merged);
            if (rr[1] != null) {
                return new Object[]{null, rr[1]};
            }
            // 再走 parser 求值（包级 evaluate 内部已把失败归一化为 [null, err]）
            return Eval.evaluate((String) rr[0], merged);
        } catch (RuntimeException e) {
            return new Object[]{null, e};
        }
    }

    /** 对应 Go 的 {@code (e *Evaluator) GetVariables() map[string]interface{}}（返回内部 map 本身，非副本）。 */
    public Map<String, Object> getVariables() {
        return vars;
    }
}

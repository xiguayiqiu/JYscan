package space.jyscan.modules.nuclei.dsl;

/**
 * DSL 内置函数的函数式接口，对应 Go 的 {@code freeclient/pkg/nuclei/dsl/functions.go}
 * 中的类型 {@code type ExpressionFunction func(args ...interface{}) (interface{}, error)}。
 *
 * <p>Go 的可变参数 {@code args ...interface{}} 映射为 {@code Object[]}；
 * Go 的二元返回 {@code (interface{}, error)} 按项目惯例映射为
 * {@code Object[]{值, Throwable}}：{@code [1] == null} 表示成功。
 */
@FunctionalInterface
public interface ExpressionFunction {

    /**
     * 调用 DSL 函数。
     *
     * @param args 函数参数，对应 Go 的 {@code args ...interface{}}
     * @return {@code Object[]{值, Throwable}}；{@code [1] == null} 表示成功，
     *     失败时 {@code [1]} 为异常（错误值按 Go 原样保留在 {@code [0]} 中，
     *     包级 {@code Evaluate} 出口处会归一化为 {@code [0] == null}）
     */
    Object[] apply(Object[] args);
}

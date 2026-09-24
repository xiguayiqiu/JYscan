package space.jyscan.modules.nuclei.dsl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * DSL 表达式求值器：包级求值函数与 parser，对应 Go 的 {@code freeclient/pkg/nuclei/dsl/eval.go}。
 *
 * <p>对应 Go 的包级函数 {@code Evaluate}、{@code ContainsUnresolvedVariables}、
 * {@code ResolveVariables}，以及 {@code parser} 结构体的全部方法与
 * {@code evalBool}/{@code compare*}/{@code *Values} 等辅助纯函数。
 *
 * <p>Go 的 {@code (interface{}, error)} 二元返回按项目惯例映射为
 * {@code Object[]{值, Throwable}}：{@code [1] == null} 表示成功。
 * Go 侧个别函数会返回“非 nil 值 + error”的组合（如 {@code toIntArg} 失败时的
 * {@code (0, err)}），本类在 {@link #evaluate} 出口统一归一化为
 * {@code [0] == null、[1] == 异常}；Go 侧不可恢复的 panic（切片越界、
 * 负数 repeat 等）在 Java 侧以 RuntimeException 表达并同样归一为求值失败。
 */
public final class Eval {

    private Eval() {}

    /** 对应 Go 的 {@code dollarVarRegex = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_]+)\s*\}\}`)}。 */
    private static final Pattern DOLLAR_VAR_REGEX = Pattern.compile("\\{\\{\\s*([a-zA-Z0-9_]+)\\s*\\}\\}");

    /**
     * 评估一个简单的 DSL 表达式。
     * 支持的语法: 变量、字符串字面量、数字字面量、布尔值、函数调用、运算符。
     *
     * <p>对应 Go 的 {@code func Evaluate(expression string, vars map[string]interface{}) (interface{}, error)}。
     *
     * @return {@code Object[]{值, Throwable}}；{@code [1] == null} 表示成功，
     *     失败时 {@code [0] == null} 且 {@code [1]} 为异常
     */
    public static Object[] evaluate(String expression, Map<String, Object> vars) {
        try {
            Parser parser = new Parser(expression, vars);
            Object[] result = parser.parseExpression();
            if (result[1] != null) {
                // 归一化：Go 侧的“非 nil 值 + error”统一为 [null, err]
                return new Object[]{null, result[1]};
            }
            return result;
        } catch (RuntimeException e) {
            // Go 侧此处为不可恢复的 panic（如切片越界、strings.Repeat 负数、整数取模除零）
            return new Object[]{null, e};
        }
    }

    /**
     * 检查表达式中是否包含未解析的变量。
     *
     * <p>对应 Go 的 {@code func ContainsUnresolvedVariables(expression string) bool}。
     */
    public static boolean containsUnresolvedVariables(String expression) {
        return expression.contains("{{") && expression.contains("}}");
    }

    /**
     * 解析 {@code {{...}}} 变量占位符（正则替换为变量值的字符串形式）。
     *
     * <p>对应 Go 的 {@code func ResolveVariables(expression string, vars map[string]interface{}) (string, error)}。
     * Go 侧 {@code err} 恒为 nil（回调无法失败），按契约仍返回二元组。
     *
     * @return {@code Object[]{String, Throwable}}；{@code [1] == null} 恒成立
     */
    public static Object[] resolveVariables(String expression, Map<String, Object> vars) {
        Matcher m = DOLLAR_VAR_REGEX.matcher(expression);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String name = m.group(1);
            String replacement;
            if (vars != null && vars.containsKey(name)) {
                replacement = Functions.toStringArg(vars.get(name));
            } else {
                replacement = m.group(); // 变量不存在时保留原占位符
            }
            // Go 的 ReplaceAllStringFunc 返回值是字面替换，这里等价引用来避免 $、\ 被二次解释
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return new Object[]{sb.toString(), null};
    }

    /** 对应 Go 的 {@code func isIdentChar(c byte) bool}。 */
    static boolean isIdentChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
    }

    /** 构造失败结果 {@code [null, err]}（对齐 Go 的 {@code return nil, err}）。 */
    private static Object[] errResult(Throwable t) {
        return new Object[]{null, t};
    }

    /**
     * 对应 Go 的 {@code parser} 结构体及其全部方法（eval.go）。
     * pos 按字符索引；Go 侧按字节索引，运算符/关键字均为 ASCII，语义等价。
     */
    static final class Parser {

        /** 对应 Go 的 {@code input string}。 */
        private final String input;
        /** 对应 Go 的 {@code pos int}。 */
        private int pos;
        /** 对应 Go 的 {@code vars map[string]interface{}}（赋值语句会写入此 map）。 */
        private Map<String, Object> vars;

        Parser(String input, Map<String, Object> vars) {
            this.input = input;
            this.vars = vars;
        }

        /** 对应 Go 的 {@code (p *parser) skipWhitespace()}——仅跳过空格与制表符。 */
        private void skipWhitespace() {
            while (pos < input.length()) {
                char c = input.charAt(pos);
                if (c == ' ' || c == '\t') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        /** 对应 Go 的 {@code (p *parser) peek() byte}——越界返回 0。 */
        private char peek() {
            if (pos >= input.length()) {
                return 0;
            }
            return input.charAt(pos);
        }

        /** 对应 Go 的 {@code (p *parser) consume() byte}——越界返回 0。 */
        private char consume() {
            if (pos >= input.length()) {
                return 0;
            }
            char c = input.charAt(pos);
            pos++;
            return c;
        }

        /** 对应 Go 的 {@code (p *parser) match(s string) bool}——先跳空白再尝试消费字面量。 */
        private boolean match(String s) {
            skipWhitespace();
            if (pos + s.length() > input.length()) {
                return false;
            }
            if (input.substring(pos, pos + s.length()).equals(s)) {
                pos += s.length();
                return true;
            }
            return false;
        }

        /** 对应 Go 的 {@code (p *parser) parseExpression() (interface{}, error)}。 */
        Object[] parseExpression() {
            skipWhitespace();
            if (pos >= input.length()) {
                return new Object[]{null, null};
            }
            // 检查是否是赋值语句
            if (isAssignment()) {
                return parseAssignment();
            }
            return parseLogicalOr();
        }

        /** 对应 Go 的 {@code (p *parser) isAssignment() bool}（含 {@code pos+1 < len} 的原样边界条件）。 */
        private boolean isAssignment() {
            // 简单判断: 标识符后跟等号但不是 == 或 !=
            int save = pos;
            skipWhitespace();
            int identStart = pos;
            while (pos < input.length() && isIdentChar(input.charAt(pos))) {
                pos++;
            }
            if (pos == identStart) {
                pos = save;
                return false;
            }
            skipWhitespace();
            if (pos + 1 < input.length() && input.charAt(pos) == '=' && input.charAt(pos + 1) != '=') {
                pos = save;
                return true;
            }
            pos = save;
            return false;
        }

        /** 对应 Go 的 {@code (p *parser) parseAssignment() (interface{}, error)}。 */
        private Object[] parseAssignment() {
            skipWhitespace();
            String name = parseIdentifier();
            skipWhitespace();
            if (!match("=")) {
                return errResult(new IllegalArgumentException("expected = at position " + pos));
            }
            skipWhitespace();
            Object[] r = parseLogicalOr();
            if (r[1] != null) {
                return errResult((Throwable) r[1]);
            }
            Object val = r[0];
            if (vars == null) {
                vars = new HashMap<>();
            }
            vars.put(name, val);
            return new Object[]{val, null};
        }

        /** 对应 Go 的 {@code (p *parser) parseLogicalOr() (interface{}, error)}。 */
        private Object[] parseLogicalOr() {
            Object[] left = parseLogicalAnd();
            if (left[1] != null) {
                return errResult((Throwable) left[1]);
            }
            while (true) {
                skipWhitespace();
                if (!match("||")) {
                    return left;
                }
                skipWhitespace();
                Object[] right = parseLogicalAnd();
                if (right[1] != null) {
                    return errResult((Throwable) right[1]);
                }
                left = new Object[]{evalBool(left[0]) || evalBool(right[0]), null};
            }
        }

        /** 对应 Go 的 {@code (p *parser) parseLogicalAnd() (interface{}, error)}。 */
        private Object[] parseLogicalAnd() {
            Object[] left = parseEquality();
            if (left[1] != null) {
                return errResult((Throwable) left[1]);
            }
            while (true) {
                skipWhitespace();
                if (!match("&&")) {
                    return left;
                }
                skipWhitespace();
                Object[] right = parseEquality();
                if (right[1] != null) {
                    return errResult((Throwable) right[1]);
                }
                left = new Object[]{evalBool(left[0]) && evalBool(right[0]), null};
            }
        }

        /** 对应 Go 的 {@code (p *parser) parseEquality() (interface{}, error)}。 */
        private Object[] parseEquality() {
            Object[] left = parseComparison();
            if (left[1] != null) {
                return errResult((Throwable) left[1]);
            }
            while (true) {
                skipWhitespace();
                if (match("==")) {
                    skipWhitespace();
                    Object[] right = parseComparison();
                    if (right[1] != null) {
                        return errResult((Throwable) right[1]);
                    }
                    left = new Object[]{compareEqual(left[0], right[0]), null};
                    continue;
                }
                if (match("!=")) {
                    skipWhitespace();
                    Object[] right = parseComparison();
                    if (right[1] != null) {
                        return errResult((Throwable) right[1]);
                    }
                    left = new Object[]{!compareEqual(left[0], right[0]), null};
                    continue;
                }
                return left;
            }
        }

        /** 对应 Go 的 {@code (p *parser) parseComparison() (interface{}, error)}（{@code >=}、{@code <=} 先于 {@code >}、{@code <} 判断）。 */
        private Object[] parseComparison() {
            Object[] left = parseAdditive();
            if (left[1] != null) {
                return errResult((Throwable) left[1]);
            }
            while (true) {
                skipWhitespace();
                if (match(">=")) {
                    skipWhitespace();
                    Object[] right = parseAdditive();
                    if (right[1] != null) {
                        return errResult((Throwable) right[1]);
                    }
                    left = new Object[]{compareGreaterOrEqual(left[0], right[0]), null};
                    continue;
                }
                if (match("<=")) {
                    skipWhitespace();
                    Object[] right = parseAdditive();
                    if (right[1] != null) {
                        return errResult((Throwable) right[1]);
                    }
                    left = new Object[]{compareLessOrEqual(left[0], right[0]), null};
                    continue;
                }
                if (match(">")) {
                    skipWhitespace();
                    Object[] right = parseAdditive();
                    if (right[1] != null) {
                        return errResult((Throwable) right[1]);
                    }
                    left = new Object[]{compareGreater(left[0], right[0]), null};
                    continue;
                }
                if (match("<")) {
                    skipWhitespace();
                    Object[] right = parseAdditive();
                    if (right[1] != null) {
                        return errResult((Throwable) right[1]);
                    }
                    left = new Object[]{compareLess(left[0], right[0]), null};
                    continue;
                }
                return left;
            }
        }

        /** 对应 Go 的 {@code (p *parser) parseAdditive() (interface{}, error)}。 */
        private Object[] parseAdditive() {
            Object[] left = parseMultiplicative();
            if (left[1] != null) {
                return errResult((Throwable) left[1]);
            }
            while (true) {
                skipWhitespace();
                if (match("+")) {
                    skipWhitespace();
                    Object[] right = parseMultiplicative();
                    if (right[1] != null) {
                        return errResult((Throwable) right[1]);
                    }
                    left = new Object[]{addValues(left[0], right[0]), null};
                    continue;
                }
                if (match("-")) {
                    skipWhitespace();
                    Object[] right = parseMultiplicative();
                    if (right[1] != null) {
                        return errResult((Throwable) right[1]);
                    }
                    left = new Object[]{subtractValues(left[0], right[0]), null};
                    continue;
                }
                return left;
            }
        }

        /** 对应 Go 的 {@code (p *parser) parseMultiplicative() (interface{}, error)}。 */
        private Object[] parseMultiplicative() {
            Object[] left = parseUnary();
            if (left[1] != null) {
                return errResult((Throwable) left[1]);
            }
            while (true) {
                skipWhitespace();
                if (match("*")) {
                    skipWhitespace();
                    Object[] right = parseUnary();
                    if (right[1] != null) {
                        return errResult((Throwable) right[1]);
                    }
                    left = new Object[]{multiplyValues(left[0], right[0]), null};
                    continue;
                }
                if (match("/")) {
                    skipWhitespace();
                    Object[] right = parseUnary();
                    if (right[1] != null) {
                        return errResult((Throwable) right[1]);
                    }
                    left = new Object[]{divideValues(left[0], right[0]), null};
                    continue;
                }
                if (match("%")) {
                    skipWhitespace();
                    Object[] right = parseUnary();
                    if (right[1] != null) {
                        return errResult((Throwable) right[1]);
                    }
                    left = new Object[]{modValues(left[0], right[0]), null};
                    continue;
                }
                return left;
            }
        }

        /** 对应 Go 的 {@code (p *parser) parseUnary() (interface{}, error)}。 */
        private Object[] parseUnary() {
            skipWhitespace();
            if (match("!")) {
                Object[] val = parseUnary();
                if (val[1] != null) {
                    return errResult((Throwable) val[1]);
                }
                return new Object[]{!evalBool(val[0]), null};
            }
            if (match("-")) {
                Object[] val = parseUnary();
                if (val[1] != null) {
                    return errResult((Throwable) val[1]);
                }
                return new Object[]{negateValue(val[0]), null};
            }
            return parsePrimary();
        }

        /** 对应 Go 的 {@code (p *parser) parsePrimary() (interface{}, error)}。 */
        private Object[] parsePrimary() {
            skipWhitespace();
            if (pos >= input.length()) {
                return errResult(new IllegalArgumentException("unexpected end of expression"));
            }

            char c = peek();
            if (c == '(') {
                consume();
                Object[] val = parseExpression();
                if (val[1] != null) {
                    return errResult((Throwable) val[1]);
                }
                skipWhitespace();
                if (!match(")")) {
                    return errResult(new IllegalArgumentException("expected ) at position " + pos));
                }
                return val;
            }

            if (c == '"' || c == '\'') {
                return parseString();
            }

            if (c >= '0' && c <= '9') {
                return parseNumber();
            }

            if (c == 't' || c == 'f') {
                if (match("true")) {
                    return new Object[]{Boolean.TRUE, null};
                }
                if (match("false")) {
                    return new Object[]{Boolean.FALSE, null};
                }
            }

            if (c == 'n') {
                if (match("null") || match("nil")) {
                    return new Object[]{null, null};
                }
            }

            return parseIdentifierOrFunction();
        }

        /** 对应 Go 的 {@code (p *parser) parseString() (interface{}, error)}。 */
        private Object[] parseString() {
            char quote = consume();
            StringBuilder b = new StringBuilder();
            while (pos < input.length() && input.charAt(pos) != quote) {
                char c = input.charAt(pos);
                if (c == '\\' && pos + 1 < input.length()) {
                    char next = input.charAt(pos + 1);
                    switch (next) {
                        case 'n' -> b.append('\n');
                        case 't' -> b.append('\t');
                        case 'r' -> b.append('\r');
                        case '\\' -> b.append('\\');
                        case '"' -> b.append('"');
                        case '\'' -> b.append('\'');
                        default -> b.append(next);
                    }
                    pos += 2;
                } else {
                    b.append(c);
                    pos++;
                }
            }
            if (pos >= input.length()) {
                return errResult(new IllegalArgumentException("unterminated string"));
            }
            consume(); // closing quote
            return new Object[]{b.toString(), null};
        }

        /**
         * 对应 Go 的 {@code (p *parser) parseNumber() (interface{}, error)}：
         * 整数走 {@code strconv.Atoi}（Java 侧先按 int 解析、超范围再按 long，对应 Go 的 64 位 int），
         * 带小数点走 {@code strconv.ParseFloat}。字面量不支持指数写法（与 Go 一致）。
         */
        private Object[] parseNumber() {
            int start = pos;
            while (pos < input.length() && input.charAt(pos) >= '0' && input.charAt(pos) <= '9') {
                pos++;
            }
            boolean isFloat = false;
            if (pos < input.length() && input.charAt(pos) == '.') {
                isFloat = true;
                pos++;
                while (pos < input.length() && input.charAt(pos) >= '0' && input.charAt(pos) <= '9') {
                    pos++;
                }
            }
            String numStr = input.substring(start, pos);
            if (isFloat) {
                Double f = Functions.parseGoFloat(numStr);
                if (f == null) {
                    return errResult(new NumberFormatException(numStr));
                }
                return new Object[]{f, null};
            }
            try {
                return new Object[]{Integer.valueOf(numStr), null};
            } catch (NumberFormatException intEx) {
                try {
                    return new Object[]{Long.valueOf(numStr), null};
                } catch (NumberFormatException longEx) {
                    return errResult(longEx);
                }
            }
        }

        /** 对应 Go 的 {@code (p *parser) parseIdentifier() string}。 */
        private String parseIdentifier() {
            int start = pos;
            while (pos < input.length() && isIdentChar(input.charAt(pos))) {
                pos++;
            }
            return input.substring(start, pos);
        }

        /**
         * 对应 Go 的 {@code (p *parser) parseIdentifierOrFunction() (interface{}, error)}：
         * 先查函数调用，再查变量表，均未命中时返回标识符本身（字符串字面量语义）。
         */
        private Object[] parseIdentifierOrFunction() {
            String name = parseIdentifier();
            if (name.isEmpty()) {
                return errResult(new IllegalArgumentException("expected identifier at position " + pos));
            }
            skipWhitespace();
            if (match("(")) {
                return parseFunctionCall(name);
            }
            if (vars != null && vars.containsKey(name)) {
                return new Object[]{vars.get(name), null};
            }
            return new Object[]{name, null};
        }

        /** 对应 Go 的 {@code (p *parser) parseFunctionCall(name string) (interface{}, error)}。 */
        private Object[] parseFunctionCall(String name) {
            List<Object> args = new ArrayList<>();
            skipWhitespace();
            if (!match(")")) {
                while (true) {
                    skipWhitespace();
                    Object[] arg = parseExpression();
                    if (arg[1] != null) {
                        return errResult((Throwable) arg[1]);
                    }
                    args.add(arg[0]);
                    skipWhitespace();
                    if (match(")")) {
                        break;
                    }
                    if (!match(",")) {
                        return errResult(new IllegalArgumentException("expected , or ) at position " + pos));
                    }
                }
            }

            ExpressionFunction fn = Functions.helperFunctions.get(name);
            if (fn == null) {
                return errResult(new IllegalArgumentException("unknown function: " + name));
            }
            // Go: return fn(args...) —— 原样透传函数的二元返回（含“错误值+error”组合）
            return fn.apply(args.toArray());
        }
    }

    // ------------------------------------------------------------------
    // 求值辅助纯函数（对应 eval.go 的包级辅助函数）
    // ------------------------------------------------------------------

    /** 对应 Go 的 {@code func evalBool(v interface{}) bool}。 */
    static boolean evalBool(Object v) {
        if (v instanceof Boolean b) {
            return b;
        }
        if (v instanceof String s) {
            return !s.isEmpty();
        }
        if (v instanceof Integer i) {
            return i != 0;
        }
        if (v instanceof Long l) {
            return l != 0;
        }
        if (v instanceof Double d) {
            return d != 0;
        }
        if (v == null) {
            return false;
        }
        return true;
    }

    /** 对应 Go 的 {@code func compareEqual(a, b interface{}) bool}。 */
    static boolean compareEqual(Object a, Object b) {
        Double af = toFloat(a);
        if (af != null) {
            Double bf = toFloat(b);
            if (bf != null) {
                return af.doubleValue() == bf.doubleValue();
            }
        }
        return Functions.toStringArg(a).equals(Functions.toStringArg(b));
    }

    /**
     * 对应 Go 的 {@code func toFloat(v interface{}) (float64, bool)}：
     * float64/int/int64 可直接转换、string 走 {@code strconv.ParseFloat}；
     * Java 侧以 {@code null} 表示 Go 的 {@code ok == false}。
     */
    static Double toFloat(Object v) {
        if (v instanceof Double d) {
            return d;
        }
        if (v instanceof Integer i) {
            return (double) i;
        }
        if (v instanceof Long l) {
            return (double) l;
        }
        if (v instanceof String s) {
            return Functions.parseGoFloat(s);
        }
        return null;
    }

    /** 对应 Go 的 {@code func compareGreater(a, b interface{}) bool}。 */
    static boolean compareGreater(Object a, Object b) {
        Double af = toFloat(a);
        Double bf = toFloat(b);
        if (af != null && bf != null) {
            return af > bf;
        }
        return Functions.toStringArg(a).compareTo(Functions.toStringArg(b)) > 0;
    }

    /** 对应 Go 的 {@code func compareLess(a, b interface{}) bool}。 */
    static boolean compareLess(Object a, Object b) {
        Double af = toFloat(a);
        Double bf = toFloat(b);
        if (af != null && bf != null) {
            return af < bf;
        }
        return Functions.toStringArg(a).compareTo(Functions.toStringArg(b)) < 0;
    }

    /** 对应 Go 的 {@code func compareGreaterOrEqual(a, b interface{}) bool}。 */
    static boolean compareGreaterOrEqual(Object a, Object b) {
        return compareGreater(a, b) || compareEqual(a, b);
    }

    /** 对应 Go 的 {@code func compareLessOrEqual(a, b interface{}) bool}。 */
    static boolean compareLessOrEqual(Object a, Object b) {
        return compareLess(a, b) || compareEqual(a, b);
    }

    /** 对应 Go 的 {@code func addValues(a, b interface{}) interface{}}：均可转数值则相加（float64），否则字符串拼接。 */
    static Object addValues(Object a, Object b) {
        Double af = toFloat(a);
        if (af != null) {
            Double bf = toFloat(b);
            if (bf != null) {
                return af + bf;
            }
        }
        return Functions.toStringArg(a) + Functions.toStringArg(b);
    }

    /** 对应 Go 的 {@code func subtractValues(a, b interface{}) interface{}}：否则返回 0（Go int 0）。 */
    static Object subtractValues(Object a, Object b) {
        Double af = toFloat(a);
        Double bf = toFloat(b);
        if (af != null && bf != null) {
            return af - bf;
        }
        return 0;
    }

    /** 对应 Go 的 {@code func multiplyValues(a, b interface{}) interface{}}：否则返回 0。 */
    static Object multiplyValues(Object a, Object b) {
        Double af = toFloat(a);
        Double bf = toFloat(b);
        if (af != null && bf != null) {
            return af * bf;
        }
        return 0;
    }

    /** 对应 Go 的 {@code func divideValues(a, b interface{}) interface{}}：除数为 0 时返回 0（Go 不报错）。 */
    static Object divideValues(Object a, Object b) {
        Double af = toFloat(a);
        Double bf = toFloat(b);
        if (af != null && bf != null && bf != 0) {
            return af / bf;
        }
        return 0;
    }

    /**
     * 对应 Go 的 {@code func modValues(a, b interface{}) interface{}}：向零截断为整数后取绝对值取模。
     * Go 的 {@code int} 为 64 位，这里以 {@code long} 运算。
     *
     * <p>与 Go 一致地保留隐患：{@code bf} 为 ±0.5 等截断后为 0 的非零除数时，
     * Go 侧会 panic（integer divide by zero），Java 侧抛出 {@link ArithmeticException}，
     * 由包级 {@code Eval.evaluate} 归一为求值失败。
     */
    static Object modValues(Object a, Object b) {
        Double af = toFloat(a);
        Double bf = toFloat(b);
        if (af != null && bf != null && bf != 0) {
            long ai = (long) (double) af;
            long bi = (long) (double) bf;
            if (ai < 0) {
                ai = -ai;
            }
            if (bi < 0) {
                bi = -bi;
            }
            return ai % bi;
        }
        return 0;
    }

    /** 对应 Go 的 {@code func negateValue(v interface{}) interface{}}：可转数值则取负，否则返回 0。 */
    static Object negateValue(Object v) {
        Double f = toFloat(v);
        if (f != null) {
            return -f;
        }
        return 0;
    }
}

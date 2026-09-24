package space.jyscan.modules.nuclei.runner;

/**
 * flow 指令语法分析器（递归下降），对应 Go {@code flow.go} 的
 * {@code flowNode}/{@code flowRequest}/{@code flowOp}/{@code flowBinaryExpr}/{@code flowParser}
 * （{@code flow.go:95-232}，Go 侧全部包私有，Java 侧同样包私有）。
 *
 * <p>优先级：{@code parseOr}（最低，{@code ||}）→ {@code parseAnd}（{@code &&}）→
 * {@code parsePrimary}（{@code http(1)} 或括号嵌套），与 Go 逐一对应。
 * {@code String()}（Go Stringer）在 Java 中落为 {@code toString()}，输出
 * {@code http(1)} 与 {@code (left && right)} 形态。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/runner/flow.go}
 */

/** AST 节点接口，对应 Go 的 {@code flowNode interface{ String() string }}。 */
interface FlowNode {
    // Go 的 String() 即 Java 的 Object.toString()，由实现类覆写
}

/** 单个请求引用，对应 Go 的 {@code flowRequest{protocol, index}}（index 为 1-based）。 */
class FlowNodeRequest implements FlowNode {

    /** 对应 Go 的 {@code protocol string}（http, dns, ssl, tcp）。 */
    final String protocol;
    /** 对应 Go 的 {@code index int}（1-based 请求编号）。 */
    final int index;

    FlowNodeRequest(String protocol, int index) {
        this.protocol = protocol;
        this.index = index;
    }

    /** 对应 Go 的 {@code (f *flowRequest) String()}：{@code %s(%d)}。 */
    @Override
    public String toString() {
        return String.format("%s(%d)", protocol, index);
    }
}

/** 二元运算符，对应 Go 的 {@code flowOp}（{@code iota + 1}: flowOpAnd/flowOpOr）。 */
enum FlowOp {
    /** {@code flowOpAnd}：&& */
    AND,
    /** {@code flowOpOr}：|| */
    OR
}

/** 二元表达式节点，对应 Go 的 {@code flowBinaryExpr{left, right, operator}}。 */
class FlowBinaryExpr implements FlowNode {

    /** 对应 Go 的 {@code left flowNode}。 */
    final FlowNode left;
    /** 对应 Go 的 {@code right flowNode}。 */
    final FlowNode right;
    /** 对应 Go 的 {@code operator flowOp}。 */
    final FlowOp operator;

    FlowBinaryExpr(FlowNode left, FlowNode right, FlowOp operator) {
        this.left = left;
        this.right = right;
        this.operator = operator;
    }

    /** 对应 Go 的 {@code (f *flowBinaryExpr) String()}：{@code (left && right)} / {@code (left || right)}。 */
    @Override
    public String toString() {
        String op = "&&";
        if (operator == FlowOp.OR) {
            op = "||";
        }
        return String.format("(%s %s %s)", left, op, right);
    }
}

/**
 * flow 语法解析异常，对应 Go {@code flowParser} 各方法返回的
 * {@code fmt.Errorf(...)} 错误（Java 多返回值约定下以异常形态在包内传递，
 * 由 {@code Runner.executeFlow} 捕获，等价于 Go 的 {@code if err != nil} 分支）。
 */
class FlowParseException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    FlowParseException(String message) {
        super(message);
    }
}

/**
 * 解析器，对应 Go 的 {@code flowParser{lexer, lookup}} 与 {@code newFlowParser}。
 */
class FlowParser {

    /** 对应 Go 的 {@code lexer *flowLexer}。 */
    final FlowLexer lexer;
    /** 对应 Go 的 {@code lookup flowToken}（向前看一个 token）。 */
    FlowToken lookup;

    /** 对应 Go 的 {@code newFlowParser(input string) *flowParser}（构造即 {@code advance} 一次）。 */
    FlowParser(String input) {
        this.lexer = new FlowLexer(input);
        this.advance();
    }

    /** 对应 Go 的 {@code (p *flowParser) advance()}。 */
    void advance() {
        this.lookup = lexer.nextToken();
    }

    /**
     * 解析完整 flow 表达式。
     *
     * <p>对应 Go 的 {@code (p *flowParser) parse() (flowNode, error)}；
     * Go 的 error 返回在 Java 中映射为 {@link FlowParseException}。
     */
    FlowNode parse() {
        FlowNode node = parseOr();
        if (lookup.typ != FlowTokenType.EOF) {
            throw new FlowParseException(String.format("flow: 意外的标记 \"%s\" 在位置 %d",
                    lookup.value, lexer.pos));
        }
        return node;
    }

    /** 解析 {@code ||} 表达式（优先级最低），对应 Go 的 {@code (p *flowParser) parseOr()}。 */
    FlowNode parseOr() {
        FlowNode left = parseAnd();
        while (lookup.typ == FlowTokenType.OR) {
            advance();
            FlowNode right = parseAnd();
            left = new FlowBinaryExpr(left, right, FlowOp.OR);
        }
        return left;
    }

    /** 解析 {@code &&} 表达式，对应 Go 的 {@code (p *flowParser) parseAnd()}。 */
    FlowNode parseAnd() {
        FlowNode left = parsePrimary();
        while (lookup.typ == FlowTokenType.AND) {
            advance();
            FlowNode right = parsePrimary();
            left = new FlowBinaryExpr(left, right, FlowOp.AND);
        }
        return left;
    }

    /**
     * 解析基础表达式：{@code http(1)} 或 {@code (expr)}。
     *
     * <p>对应 Go 的 {@code (p *flowParser) parsePrimary() (flowNode, error)}，三条错误分支
     * （缺右括号 / 协议后需要 ( / 需要请求编号 / 非预期标记）逐一对应。
     */
    FlowNode parsePrimary() {
        if (lookup.typ == FlowTokenType.LPAREN) {
            advance();
            FlowNode node = parseOr();
            if (lookup.typ != FlowTokenType.RPAREN) {
                throw new FlowParseException(String.format("flow: 缺少右括号, 遇到 \"%s\"", lookup.value));
            }
            advance();
            return node;
        }

        if (lookup.typ == FlowTokenType.PROTOCOL) {
            String proto = lookup.value;
            advance();
            if (lookup.typ != FlowTokenType.LPAREN) {
                throw new FlowParseException(String.format("flow: 协议 \"%s\" 后需要 (, 遇到 \"%s\"",
                        proto, lookup.value));
            }
            advance();
            if (lookup.typ != FlowTokenType.NUMBER) {
                throw new FlowParseException(String.format("flow: 需要请求编号, 遇到 \"%s\"",
                        lookup.value));
            }
            // Go: idx, _ := strconv.Atoi(...) —— token 为纯数字串，解析必成功
            int idx = Integer.parseInt(lookup.value);
            advance();
            if (lookup.typ != FlowTokenType.RPAREN) {
                throw new FlowParseException(String.format("flow: 缺少右括号, 遇到 \"%s\"", lookup.value));
            }
            advance();
            return new FlowNodeRequest(proto, idx);
        }

        throw new FlowParseException(String.format("flow: 非预期的标记 \"%s\"", lookup.value));
    }
}

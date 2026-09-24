package space.jyscan.modules.nuclei.runner;

/**
 * flow 指令词法分析器，对应 Go {@code flow.go} 的
 * {@code flowTokenType}/{@code flowToken}/{@code flowLexer}/{@code isAlpha}
 * （{@code flow.go:16-93}，Go 侧全部包私有，Java 侧同样包私有）。
 *
 * <p>支持格式：{@code http(1) && http(2)}、{@code http(1) || http(2)}、
 * {@code http(1)} 以及嵌套括号组合。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/runner/flow.go}
 */

/**
 * token 种类，对应 Go 的 {@code flowTokenType}（{@code iota + 1} 起：
 * tokenProtocol/tokenLParen/tokenRParen/tokenNumber/tokenAnd/tokenOr/tokenEOF）。
 */
enum FlowTokenType {
    /** {@code tokenProtocol}：http、dns、ssl、tcp 等协议名（也兜底承接未知字符）。 */
    PROTOCOL,
    /** {@code tokenLParen}：( */
    LPAREN,
    /** {@code tokenRParen}：) */
    RPAREN,
    /** {@code tokenNumber}：1, 2, 3 请求编号。 */
    NUMBER,
    /** {@code tokenAnd}：&& */
    AND,
    /** {@code tokenOr}：|| */
    OR,
    /** {@code tokenEOF}：输入结束。 */
    EOF
}

/** 单个 token，对应 Go 的 {@code flowToken{typ, value}}。 */
class FlowToken {

    /** 对应 Go 的 {@code typ flowTokenType}。 */
    final FlowTokenType typ;
    /** 对应 Go 的 {@code value string}。 */
    final String value;

    FlowToken(FlowTokenType typ, String value) {
        this.typ = typ;
        this.value = value;
    }

    /** EOF token 用（value 为空串）。 */
    FlowToken(FlowTokenType typ) {
        this(typ, "");
    }
}

/**
 * 词法分析器，对应 Go 的 {@code flowLexer{input, pos}} 与 {@code newFlowLexer}。
 *
 * <p>Go 侧按<b>字节</b>扫描（{@code l.input[l.pos] == '('} 等）；
 * Java 的 {@link String} 是 UTF-16 序列，此处按 {@code charAt} 扫描——
 * 对 flow 语法实际会出现的 ASCII 输入（协议名、数字、括号、{@code &&}/{@code ||}）逐位等价；
 * 仅当 flow 串含非 ASCII 字符时（Go 取 1 个字节、Java 取 1 个 char）存在差异，
 * 而非 ASCII 字符本就不属于合法 flow 语法。
 */
class FlowLexer {

    /** 对应 Go 的 {@code input string}（Go 在 {@code newFlowLexer} 中 {@code strings.TrimSpace}）。 */
    final String input;
    /** 对应 Go 的 {@code pos int}。 */
    int pos;

    /** 对应 Go 的 {@code newFlowLexer(input string) *flowLexer}。 */
    FlowLexer(String input) {
        this.input = input == null ? "" : input.trim();
        this.pos = 0;
    }

    /**
     * 取下一个 token。
     *
     * <p>对应 Go 的 {@code (l *flowLexer) nextToken() flowToken}：
     * 跳空白（仅空格与制表符）→ {@code &&} {@code ||} {@code (} {@code )} → 数字串 →
     * 字母串 → 兜底单字符按 PROTOCOL 返回。
     */
    FlowToken nextToken() {
        skipWhitespace();
        if (pos >= input.length()) {
            return new FlowToken(FlowTokenType.EOF);
        }
        if (match("&&")) {
            return new FlowToken(FlowTokenType.AND, "&&");
        }
        if (match("||")) {
            return new FlowToken(FlowTokenType.OR, "||");
        }
        char c = input.charAt(pos);
        if (c == '(') {
            pos++;
            return new FlowToken(FlowTokenType.LPAREN, "(");
        }
        if (c == ')') {
            pos++;
            return new FlowToken(FlowTokenType.RPAREN, ")");
        }
        if (c >= '0' && c <= '9') {
            int start = pos;
            while (pos < input.length() && input.charAt(pos) >= '0' && input.charAt(pos) <= '9') {
                pos++;
            }
            return new FlowToken(FlowTokenType.NUMBER, input.substring(start, pos));
        }
        if (isAlpha(c)) {
            int start = pos;
            while (pos < input.length() && isAlpha(input.charAt(pos))) {
                pos++;
            }
            return new FlowToken(FlowTokenType.PROTOCOL, input.substring(start, pos));
        }
        // Go default: l.pos++; return flowToken{typ: tokenProtocol, value: string(l.input[l.pos-1])}
        pos++;
        return new FlowToken(FlowTokenType.PROTOCOL, String.valueOf(input.charAt(pos - 1)));
    }

    /** 对应 Go 的 {@code (l *flowLexer) skipWhitespace()}：仅跳过空格与制表符。 */
    void skipWhitespace() {
        while (pos < input.length() && (input.charAt(pos) == ' ' || input.charAt(pos) == '\t')) {
            pos++;
        }
    }

    /**
     * 前缀匹配并前移游标，对应 Go 的 {@code (l *flowLexer) match(s string) bool}。
     * 匹配成功时 {@code pos} 前进 {@code s.length()} 并返回 {@code true}。
     */
    boolean match(String s) {
        if (input.startsWith(s, pos)) {
            pos += s.length();
            return true;
        }
        return false;
    }

    /** 对应 Go 的 {@code isAlpha(c byte) bool}（Java 侧按 char 判定）。 */
    static boolean isAlpha(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }
}

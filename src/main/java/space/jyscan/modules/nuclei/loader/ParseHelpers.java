package space.jyscan.modules.nuclei.loader;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import space.jyscan.modules.nuclei.model.Classification;
import space.jyscan.modules.nuclei.model.CodeRequest;
import space.jyscan.modules.nuclei.model.DNSRequest;
import space.jyscan.modules.nuclei.model.Extractor;
import space.jyscan.modules.nuclei.model.FileRequest;
import space.jyscan.modules.nuclei.model.HTTPRequest;
import space.jyscan.modules.nuclei.model.Info;
import space.jyscan.modules.nuclei.model.Matcher;
import space.jyscan.modules.nuclei.model.SSLRequest;
import space.jyscan.modules.nuclei.model.TCPRequest;
import space.jyscan.modules.nuclei.model.WSRequest;
import space.jyscan.modules.nuclei.model.WhoisRequest;

/**
 * nuclei 模板解析辅助函数，对应 Go 的 {@code freeclient/pkg/nuclei/loader/parse_helpers.go}
 * 中的全部包私有函数。
 *
 * <p>Go 侧这些函数均为包私有（{@code parseInfo}、{@code parseMatchers}、…、{@code formatInt}），
 * Java 无“包私有顶层函数”，故统一收进本包私有类作静态方法，包内（{@link Loader}）可直接调用。
 *
 * <p>取值策略与 Go 的类型断言逐一对应：Go 的 {@code v, ok := m["x"].(string)} 在 Java 中是
 * {@code m.get("x") instanceof ...}；snakeyaml 与 yaml.v3 的数字/布尔类型推断差异见各方法注释。
 */
final class ParseHelpers {

    private ParseHelpers() {
    }

    // =====================================================================
    // parseInfo（parse_helpers.go:11）
    // =====================================================================

    /**
     * 解析 {@code info} 字段（宽松），对应 Go 的 {@code parseInfo(raw map[string]interface{}) model.Info}。
     *
     * <p>Go 对 {@code classification} 的处理是「marshal 成 YAML 再反序列化进结构体，错误全部吞掉，
     * 且只要键存在就一定赋值（含零值）」；Java 侧改为按 Go 的 yaml 标签字面量
     * （{@code cve-id}/{@code cwe-id}/{@code cvss-score}/{@code cvss-metrics}）手工取值，
     * 行为等价：类型不匹配的字段留零值，其余字段照常解析。
     */
    static Info parseInfo(Map<String, Object> raw) {
        Info info = new Info();
        if (raw.get("name") instanceof String v) {
            info.name = v;
        }
        if (raw.get("author") instanceof String v) {
            info.author = v;
        }
        if (raw.get("severity") instanceof String v) {
            info.severity = v;
        }
        if (raw.get("description") instanceof String v) {
            info.description = v;
        }
        if (raw.get("reference") instanceof List<?> v) {
            for (Object r : v) {
                if (r instanceof String s) {
                    if (info.reference == null) {
                        info.reference = new ArrayList<>();
                    }
                    info.reference.add(s);
                }
            }
        }
        // tags: nuclei 兼容 string 和 []string
        Object tags = raw.get("tags");
        if (tags instanceof String v) {
            info.tags = new ArrayList<>();
            info.tags.add(v);
        } else if (tags instanceof List<?> v) {
            info.tags = toStringSlice(v);
        }
        if (raw.get("metadata") != null) {
            info.metadata = toStringKeyMap(raw.get("metadata"));
        }
        if (raw.get("classification") instanceof Map<?, ?>) {
            Classification c = new Classification();
            Map<?, ?> v = (Map<?, ?>) raw.get("classification");
            if (v.get("cve-id") instanceof List<?> list) {
                c.cveId = toStringSlice(list);
            }
            if (v.get("cwe-id") instanceof List<?> list) {
                c.cweId = toStringSlice(list);
            }
            if (v.get("cvss-score") instanceof Number n) {
                // Go: yaml 反序列化把 int/float 都收进 float64；字符串等其余类型报错留零值
                c.cvssScore = n.doubleValue();
            }
            if (v.get("cvss-metrics") instanceof String s) {
                c.cvssMetrics = s;
            }
            // Go: 只要 classification 是 map，无论字段是否解析成功都赋值
            info.classification = c;
        }
        return info;
    }

    // =====================================================================
    // parseMatchers（parse_helpers.go:52）
    // =====================================================================

    /**
     * 解析 {@code matchers} 列表，对应 Go 的 {@code parseMatchers(raw []interface{}) []*model.Matcher}。
     *
     * <p>Go 侧未读取 {@code binary}/{@code raw} 等字段（模型里有、解析里没有），此处保持一致。
     */
    static List<Matcher> parseMatchers(List<?> raw) {
        List<Matcher> result = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?>)) {
                continue;
            }
            Map<?, ?> m = (Map<?, ?>) item;
            Matcher matcher = new Matcher();
            if (m.get("type") instanceof String v) {
                matcher.type = v;
            }
            if (m.get("part") instanceof String v) {
                matcher.part = v;
            }
            if (m.get("name") instanceof String v) {
                matcher.name = v;
            }
            if (m.get("condition") instanceof String v) {
                matcher.condition = v;
            }
            if (m.get("negative") instanceof Boolean v) {
                matcher.negative = v;
            }
            if (m.get("case-insensitive") instanceof Boolean v) {
                matcher.caseInsensitive = v;
            }
            if (m.get("words") instanceof List<?> v) {
                matcher.words = toStringSlice(v);
            }
            if (m.get("regex") instanceof List<?> v) {
                matcher.regex = toStringSlice(v);
            }
            if (m.get("status") instanceof List<?> v) {
                matcher.status = toIntSlice(v);
            }
            if (m.get("size") instanceof List<?> v) {
                matcher.size = toIntSlice(v);
            }
            if (m.get("dsl") instanceof List<?> v) {
                matcher.dsl = toStringSlice(v);
            }
            if (m.get("xpath") instanceof List<?> v) {
                matcher.xpath = toStringSlice(v);
            }
            if (m.get("encoding") instanceof String v) {
                matcher.encoding = v;
            }
            if (m.get("internal") instanceof Boolean v) {
                matcher.internal = v;
            }
            if (m.get("match-all") instanceof Boolean v) {
                matcher.matchAll = v;
            }
            result.add(matcher);
        }
        return result;
    }

    // =====================================================================
    // parseExtractors（parse_helpers.go:111）
    // =====================================================================

    /**
     * 解析 {@code extractors} 列表，对应 Go 的
     * {@code parseExtractors(raw []interface{}) []*model.Extractor}。
     *
     * <p>与 Go 一致：未读取 {@code attribute}/{@code case-insensitive}（模型有、解析没有）。
     */
    static List<Extractor> parseExtractors(List<?> raw) {
        List<Extractor> result = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?>)) {
                continue;
            }
            Map<?, ?> e = (Map<?, ?>) item;
            Extractor ext = new Extractor();
            if (e.get("type") instanceof String v) {
                ext.type = v;
            }
            if (e.get("part") instanceof String v) {
                ext.part = v;
            }
            if (e.get("name") instanceof String v) {
                ext.name = v;
            }
            if (e.get("regex") instanceof List<?> v) {
                ext.regex = toStringSlice(v);
            }
            if (e.get("kval") instanceof List<?> v) {
                ext.kval = toStringSlice(v);
            }
            if (e.get("xpath") instanceof List<?> v) {
                ext.xpath = toStringSlice(v);
            }
            if (e.get("json") instanceof List<?> v) {
                ext.json = toStringSlice(v);
            }
            if (e.get("dsl") instanceof List<?> v) {
                ext.dsl = toStringSlice(v);
            }
            if (e.get("group") instanceof String v) {
                ext.group = v;
            }
            if (e.get("internal") instanceof Boolean v) {
                ext.internal = v;
            }
            result.add(ext);
        }
        return result;
    }

    // =====================================================================
    // parseHTTPRequests（parse_helpers.go:155）
    // =====================================================================

    /**
     * 解析 HTTP 协议请求，对应 Go 的 {@code parseHTTPRequests(raw []interface{}) []*model.HTTPRequest}。
     *
     * <p>Go 的 {@code m["redirects"].(int)} 等整数断言只认 yaml.v3 解出的 {@code int}——
     * snakeyaml 解出的整数是 {@code Integer}/{@code Long}，故 Java 侧用
     * {@link #isIntegral(Object)} 判定（浮点数与 Go 一样被忽略）。
     */
    static List<HTTPRequest> parseHTTPRequests(List<?> raw) {
        List<HTTPRequest> result = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?>)) {
                continue;
            }
            Map<?, ?> m = (Map<?, ?>) item;
            HTTPRequest req = new HTTPRequest();
            if (m.get("method") instanceof String v) {
                req.method = v;
            }
            Object path = m.get("path");
            if (path instanceof List<?> v) {
                req.path = toStringSlice(v);
            } else if (path instanceof String v) {
                req.path = new ArrayList<>();
                req.path.add(v);
            }
            if (m.get("body") instanceof String v) {
                req.body = v;
            }
            Object rawField = m.get("raw");
            if (rawField instanceof List<?> v) {
                for (Object r : v) {
                    if (r instanceof String s) {
                        req.raw = s;
                        break;
                    }
                }
            } else if (rawField instanceof String v) {
                req.raw = v;
            }
            if (m.get("headers") instanceof Map<?, ?> v) {
                req.headers = toStringMap(v);
            }
            if (m.get("cookies") instanceof Map<?, ?> v) {
                req.cookies = toStringMap(v);
            }
            if (m.get("query") instanceof Map<?, ?> v) {
                req.query = toStringMap(v);
            }
            if (isIntegral(m.get("redirects"))) {
                req.redirects = ((Number) m.get("redirects")).intValue();
            }
            if (isIntegral(m.get("max-redirects"))) {
                req.maxRedirects = ((Number) m.get("max-redirects")).intValue();
            }
            if (isIntegral(m.get("max-size"))) {
                req.maxSize = ((Number) m.get("max-size")).intValue();
            }
            if (m.get("host-redirects") instanceof Boolean v) {
                req.hostRedirects = v;
            }
            if (m.get("cookie-reuse") instanceof Boolean v) {
                req.cookieReuse = v;
            }
            if (m.get("matchers") instanceof List<?> v) {
                req.matchers = parseMatchers(v);
            }
            if (m.get("extractors") instanceof List<?> v) {
                req.extractors = parseExtractors(v);
            }
            if (m.get("matchers-condition") instanceof String v) {
                req.matchersCondition = v;
            }
            result.add(req);
        }
        return result;
    }

    // =====================================================================
    // parseDNSRequests（parse_helpers.go:225）
    // =====================================================================

    /** 解析 DNS 协议请求，对应 Go 的 {@code parseDNSRequests(raw []interface{}) []*model.DNSRequest}。 */
    static List<DNSRequest> parseDNSRequests(List<?> raw) {
        List<DNSRequest> result = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?>)) {
                continue;
            }
            Map<?, ?> m = (Map<?, ?>) item;
            DNSRequest req = new DNSRequest();
            if (m.get("name") instanceof String v) {
                req.name = v;
            }
            if (m.get("type") instanceof String v) {
                req.type = v;
            }
            if (m.get("class") instanceof String v) {
                req.clazz = v;
            }
            if (m.get("recursion") instanceof Boolean v) {
                req.recursion = v;
            }
            if (m.get("matchers") instanceof List<?> v) {
                req.matchers = parseMatchers(v);
            }
            if (m.get("extractors") instanceof List<?> v) {
                req.extractors = parseExtractors(v);
            }
            if (m.get("matchers-condition") instanceof String v) {
                req.matchersCondition = v;
            }
            result.add(req);
        }
        return result;
    }

    // =====================================================================
    // parseTCPRequests（parse_helpers.go:260）
    // =====================================================================

    /** 解析 TCP 协议请求，对应 Go 的 {@code parseTCPRequests(raw []interface{}) []*model.TCPRequest}。 */
    static List<TCPRequest> parseTCPRequests(List<?> raw) {
        List<TCPRequest> result = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?>)) {
                continue;
            }
            Map<?, ?> m = (Map<?, ?>) item;
            TCPRequest req = new TCPRequest();
            if (m.get("host") instanceof List<?> v) {
                req.host = toStringSlice(v);
            }
            if (m.get("ports") instanceof List<?> v) {
                req.ports = toStringSlice(v);
            }
            if (m.get("inputs") instanceof List<?> v) {
                req.inputs = toStringSlice(v);
            }
            if (isIntegral(m.get("read-size"))) {
                req.readSize = ((Number) m.get("read-size")).intValue();
            }
            if (m.get("data") instanceof String v) {
                req.data = v;
            }
            if (m.get("matchers") instanceof List<?> v) {
                req.matchers = parseMatchers(v);
            }
            if (m.get("extractors") instanceof List<?> v) {
                req.extractors = parseExtractors(v);
            }
            if (m.get("matchers-condition") instanceof String v) {
                req.matchersCondition = v;
            }
            result.add(req);
        }
        return result;
    }

    // =====================================================================
    // parseSSLRequests（parse_helpers.go:298）
    // =====================================================================

    /** 解析 SSL 协议请求，对应 Go 的 {@code parseSSLRequests(raw []interface{}) []*model.SSLRequest}。 */
    static List<SSLRequest> parseSSLRequests(List<?> raw) {
        List<SSLRequest> result = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?>)) {
                continue;
            }
            Map<?, ?> m = (Map<?, ?>) item;
            SSLRequest req = new SSLRequest();
            if (m.get("address") instanceof String v) {
                req.address = v;
            }
            if (m.get("min-version") instanceof String v) {
                req.minVersion = v;
            }
            if (m.get("max-version") instanceof String v) {
                req.maxVersion = v;
            }
            if (m.get("matchers") instanceof List<?> v) {
                req.matchers = parseMatchers(v);
            }
            if (m.get("extractors") instanceof List<?> v) {
                req.extractors = parseExtractors(v);
            }
            if (m.get("matchers-condition") instanceof String v) {
                req.matchersCondition = v;
            }
            result.add(req);
        }
        return result;
    }

    // =====================================================================
    // parseWSRequests（parse_helpers.go:330）
    // =====================================================================

    /** 解析 WebSocket 协议请求，对应 Go 的 {@code parseWSRequests(raw []interface{}) []*model.WSRequest}。 */
    static List<WSRequest> parseWSRequests(List<?> raw) {
        List<WSRequest> result = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?>)) {
                continue;
            }
            Map<?, ?> m = (Map<?, ?>) item;
            WSRequest req = new WSRequest();
            if (m.get("url") instanceof String v) {
                req.url = v;
            }
            if (m.get("headers") instanceof Map<?, ?> v) {
                req.headers = toStringMap(v);
            }
            if (m.get("payload") instanceof String v) {
                req.payload = v;
            }
            if (m.get("matchers") instanceof List<?> v) {
                req.matchers = parseMatchers(v);
            }
            if (m.get("extractors") instanceof List<?> v) {
                req.extractors = parseExtractors(v);
            }
            if (m.get("matchers-condition") instanceof String v) {
                req.matchersCondition = v;
            }
            result.add(req);
        }
        return result;
    }

    // =====================================================================
    // parseWhoisRequests（parse_helpers.go:362）
    // =====================================================================

    /** 解析 Whois 协议请求，对应 Go 的 {@code parseWhoisRequests(raw []interface{}) []*model.WhoisRequest}。 */
    static List<WhoisRequest> parseWhoisRequests(List<?> raw) {
        List<WhoisRequest> result = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?>)) {
                continue;
            }
            Map<?, ?> m = (Map<?, ?>) item;
            WhoisRequest req = new WhoisRequest();
            if (m.get("query") instanceof String v) {
                req.query = v;
            }
            if (m.get("server") instanceof String v) {
                req.server = v;
            }
            if (m.get("matchers") instanceof List<?> v) {
                req.matchers = parseMatchers(v);
            }
            if (m.get("extractors") instanceof List<?> v) {
                req.extractors = parseExtractors(v);
            }
            if (m.get("matchers-condition") instanceof String v) {
                req.matchersCondition = v;
            }
            result.add(req);
        }
        return result;
    }

    // =====================================================================
    // parseFileRequests（parse_helpers.go:391）
    // =====================================================================

    /**
     * 解析 File 协议请求，对应 Go 的 {@code parseFileRequests(raw []interface{}) []*model.FileRequest}。
     *
     * <p>{@code port} 的 Go 分支为 {@code case string} / {@code case int}——浮点数与 Go 一样被忽略。
     */
    static List<FileRequest> parseFileRequests(List<?> raw) {
        List<FileRequest> result = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?>)) {
                continue;
            }
            Map<?, ?> m = (Map<?, ?>) item;
            FileRequest req = new FileRequest();
            if (m.get("host") instanceof List<?> v) {
                req.host = toStringSlice(v);
            }
            if (m.get("port") instanceof String v) {
                req.port = v;
            } else if (isIntegral(m.get("port"))) {
                req.port = itoa(((Number) m.get("port")).longValue());
            }
            if (m.get("inputs") instanceof List<?> v) {
                req.inputs = toStringSlice(v);
            }
            if (m.get("path") instanceof List<?> v) {
                req.path = toStringSlice(v);
            }
            if (m.get("matchers") instanceof List<?> v) {
                req.matchers = parseMatchers(v);
            }
            if (m.get("extractors") instanceof List<?> v) {
                req.extractors = parseExtractors(v);
            }
            if (m.get("matchers-condition") instanceof String v) {
                req.matchersCondition = v;
            }
            result.add(req);
        }
        return result;
    }

    // =====================================================================
    // parseCodeRequests（parse_helpers.go:429）
    // =====================================================================

    /**
     * 解析 Code 协议请求，对应 Go 的 {@code parseCodeRequests(raw []interface{}) []*model.CodeRequest}。
     *
     * <p>与 Go 一致：不读取 {@code matchers-condition}（Go 的 {@code CodeRequest} 结构体没有该字段）。
     */
    static List<CodeRequest> parseCodeRequests(List<?> raw) {
        List<CodeRequest> result = new ArrayList<>(raw.size());
        for (Object item : raw) {
            if (!(item instanceof Map<?, ?>)) {
                continue;
            }
            Map<?, ?> m = (Map<?, ?>) item;
            CodeRequest req = new CodeRequest();
            if (m.get("engine") instanceof String v) {
                req.engine = v;
            }
            if (m.get("args") instanceof List<?> v) {
                req.args = toStringSlice(v);
            }
            if (m.get("source") != null) {
                req.source = toStringKeyMap(m.get("source"));
            }
            if (m.get("matchers") instanceof List<?> v) {
                req.matchers = parseMatchers(v);
            }
            if (m.get("extractors") instanceof List<?> v) {
                req.extractors = parseExtractors(v);
            }
            result.add(req);
        }
        return result;
    }

    // =====================================================================
    // 通用转换助手（parse_helpers.go:457-538）
    // =====================================================================

    /**
     * {@code []interface{}} 切片转 string 切片，对应 Go 的
     * {@code toStringSlice(raw []interface{}) []string}。
     *
     * <p>Go 的分支是 {@code string}/{@code int}/{@code float64}：浮点数经 {@link #ftoa}
     * 整数化输出；snakeyaml 的整数还可能是 {@code Long}/{@code BigInteger}（Go 的 int 为
     * 64 位，按 Go 行为走 {@link #itoa}）。
     */
    static List<String> toStringSlice(List<?> raw) {
        List<String> result = new ArrayList<>(raw.size());
        for (Object v : raw) {
            if (v instanceof String s) {
                result.add(s);
            } else if (isFloatNumber(v)) {
                result.add(ftoa(((Number) v).doubleValue()));
            } else if (v instanceof Number n) {
                result.add(itoa(n.longValue()));
            }
        }
        return result;
    }

    /**
     * {@code []interface{}} 切片转 int 切片，对应 Go 的
     * {@code toIntSlice(raw []interface{}) []int}。
     *
     * <p>Go 的分支是 {@code int}（原样）与 {@code float64}（截断）；Java 侧对任何
     * {@link Number} 取 {@link Number#intValue()}（截断向零，同 Go 的 {@code int(s)}）。
     */
    static List<Integer> toIntSlice(List<?> raw) {
        List<Integer> result = new ArrayList<>(raw.size());
        for (Object v : raw) {
            if (v instanceof Number n) {
                result.add(n.intValue());
            }
        }
        return result;
    }

    /**
     * {@code map[string]interface{}} 转 {@code map[string]string}，对应 Go 的
     * {@code toStringMap(raw map[string]interface{}) map[string]string}。
     *
     * <p>Go 的分支是 {@code string}/{@code int}/{@code float64}/{@code bool}，其余类型丢弃。
     */
    static Map<String, String> toStringMap(Map<?, ?> raw) {
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : raw.entrySet()) {
            String k = String.valueOf(e.getKey());
            Object v = e.getValue();
            if (v instanceof String s) {
                result.put(k, s);
            } else if (isFloatNumber(v)) {
                result.put(k, ftoa(((Number) v).doubleValue()));
            } else if (v instanceof Number n) {
                result.put(k, itoa(n.longValue()));
            } else if (v instanceof Boolean b) {
                result.put(k, b ? "true" : "false");
            }
        }
        return result;
    }

    /**
     * 对应 Go 的 {@code itoa(i int) string}。
     *
     * <p>参数在 Java 中映射为 {@code long}：Go 的 {@code int} 是 64 位，而 Java {@code int}
     * 是 32 位，用 {@code long} 才能保持同宽（Go 侧该函数直接转调 {@link #formatInt}）。
     */
    static String itoa(long i) {
        return formatInt(i);
    }

    /**
     * 对应 Go 的 {@code ftoa(f float64) string}。
     *
     * <p>Go 原注释：「简化: 整数化输出 (yaml 解出的数字常用 float64)」——
     * {@code formatInt(int(f))} 截断小数；Java 侧用 {@code (long)} 保持 Go 的 64 位截断宽度。
     */
    static String ftoa(double f) {
        return formatInt((long) f);
    }

    /**
     * 对应 Go 的 {@code formatInt(i int) string}（parse_helpers.go:518 的手写十进制转换）。
     *
     * <p>Go 的 {@code int} 为 64 位，故 Java 参数映射为 {@code long}；算法逐行照搬
     * （{@code buf} 同为 20 字节，恰好容纳 {@code -9223372036854775808}）。
     */
    static String formatInt(long i) {
        if (i == 0) {
            return "0";
        }
        boolean neg = i < 0;
        if (neg) {
            i = -i;
        }
        byte[] buf = new byte[20];
        int pos = buf.length;
        while (i > 0) {
            pos--;
            buf[pos] = (byte) ('0' + i % 10);
            i /= 10;
        }
        if (neg) {
            pos--;
            buf[pos] = '-';
        }
        return new String(buf, pos, buf.length - pos, java.nio.charset.StandardCharsets.US_ASCII);
    }

    // =====================================================================
    // Java 侧取值辅助（snakeyaml 类型推断判型用；Go 侧由类型断言天然完成）
    // =====================================================================

    /**
     * 将 snakeyaml 解出的任意 map 归一为 {@code Map<String, Object>}（键按
     * {@code String.valueOf} 转成字符串），非 map 返回 {@code null}。
     *
     * <p>Go 的 {@code yaml.v3} 在解进 {@code map[string]interface{}} 时把标量键按其原始
     * 文本转成字符串；snakeyaml 解出的键类型是 {@code Object}，此处做等价归一。
     */
    static Map<String, Object> toStringKeyMap(Object v) {
        if (!(v instanceof Map<?, ?>)) {
            return null;
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
            result.put(String.valueOf(e.getKey()), e.getValue());
        }
        return result;
    }

    /**
     * 判断是否为「整数型数字」。
     *
     * <p>Go 的 {@code v.(int)} 断言只接受 yaml.v3 解出的整数（浮点数不匹配）；snakeyaml
     * 解出的整数是 {@code Integer}/{@code Long}/{@code BigInteger} 等，故排除
     * {@code Double}/{@code Float}/{@code BigDecimal} 这些「浮点」类型。
     */
    static boolean isIntegral(Object v) {
        return v instanceof Number && !isFloatNumber(v);
    }

    /** 判断是否为「浮点型数字」，对应 yaml.v3 解出的 {@code float64} 一类。 */
    static boolean isFloatNumber(Object v) {
        return v instanceof Double || v instanceof Float || v instanceof java.math.BigDecimal;
    }
}

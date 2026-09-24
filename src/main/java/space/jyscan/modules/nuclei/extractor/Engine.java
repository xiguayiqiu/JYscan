package space.jyscan.modules.nuclei.extractor;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import space.jyscan.core.util.Fmt;
import space.jyscan.modules.nuclei.dsl.Evaluator;
import space.jyscan.modules.nuclei.model.Extractor;

/**
 * 提取器引擎，对应 Go 的 {@code extractor.Engine}。
 *
 * <p>跨包契约：operators 持有字段 {@code extractEngine}，只调用
 * {@link #extract(Extractor, String, Map)}。
 *
 * <p>Go 侧 {@code NewEngine()} 构造 {@code dsl.NewEvaluator()} 作为 {@code evaluator}，
 * 供 {@code extractDSL} 分支使用。
 *
 * <p>JSON 解析走本项目统一的 Jackson（{@code pom.xml} 注释明确其对应 Go {@code encoding/json}）；
 * 包级助手 {@code lookupDataKey}/{@code jsonPath}（extractor.go 的小写包级函数）
 * 以包私有静态方法放在本类内。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/extractor/extractor.go}
 */
public class Engine {

    /** 对应 Go 的 {@code evaluator *dsl.Evaluator}。 */
    private final Evaluator evaluator;

    /** 对应 Go 的 {@code encoding/json}，项目统一走 Jackson。 */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 对应 Go 的 {@code NewEngine() *Engine}：{@code dsl.NewEvaluator()}。 */
    public Engine() {
        this.evaluator = new Evaluator();
    }

    /**
     * 执行提取。
     *
     * <p>对应 Go 的 {@code (e *Engine) Extract(ex *model.Extractor, target string, data map[string]interface{}) map[string]string}。
     * Go 侧始终返回非 nil map（无匹配即空 map），Java 对应返回非 null 的空 map。
     *
     * <p>Go 在 {@code ex.Name != ""} 时把所有提取值按换行合并、只留一个以 name 为键的条目
     * （Go 的 map 遍历序不定；Java 侧以 LinkedHashMap 保持提取声明序，输出更稳定）。
     */
    public Map<String, String> extract(Extractor ex, String target, Map<String, Object> data) {
        Map<String, String> result = new LinkedHashMap<>();
        String t = ex.getType();
        switch (t) {
            case "regex":
                result = extractRegex(ex, target);
                break;
            case "kval":
                result = extractKval(ex, data);
                break;
            case "xpath":
                result = extractXPath(ex, target);
                break;
            case "json":
                result = extractJSON(ex, target);
                break;
            case "dsl":
                result = extractDSL(ex, data);
                break;
            default:
                break;
        }
        String name = ex.name;
        if (name != null && !name.isEmpty()) {
            // 多个值合并为换行分隔
            List<String> combined = new ArrayList<>(result.size());
            for (String v : result.values()) {
                combined.add(v);
            }
            Map<String, String> named = new LinkedHashMap<>();
            named.put(name, String.join("\n", combined));
            return named;
        }
        return result;
    }

    /**
     * 正则提取，对应 Go 的 {@code (e *Engine) extractRegex}。
     *
     * <p>nuclei 官方行为: 正则默认 case-insensitive（Go regexp 用 {@code (?i)} flag，
     * nuclei 的 {@code case-insensitive: true} 是默认值，即便用户没显式声明）；
     * named groups 优先，未命名组以十进制组号为键；{@code group:} 指定组优先提取。
     */
    Map<String, String> extractRegex(Extractor ex, String target) {
        Map<String, String> result = new LinkedHashMap<>();
        if (ex.regex == null) {
            return result;
        }
        for (String p : ex.regex) {
            java.util.regex.Pattern re;
            try {
                re = java.util.regex.Pattern.compile("(?i)" + p);
            } catch (java.util.regex.PatternSyntaxException e) {
                // 对应 Go: regexp.Compile err → continue（含 (?P<name> 等 Go/Java 语法差异导致的编译失败）
                continue;
            }
            java.util.regex.Matcher matcher = re.matcher(target);
            // 对应 Go: matches := re.FindStringSubmatch(target)；nil → 跳过
            if (!matcher.find()) {
                continue;
            }
            int groupCount = matcher.groupCount();
            // nuclei 行为: named groups 优先（对应 Go: if re.NumSubexp() > 0 循环全组）
            if (groupCount > 0) {
                String[] names = subexpNames("(?i)" + p);
                for (int i = 1; i <= groupCount; i++) {
                    // 对应 Go: key = name，name 为空时 key = strconv.Itoa(i)
                    String name = i < names.length ? names[i] : "";
                    String key = (name == null || name.isEmpty()) ? String.valueOf(i) : name;
                    String g = matcher.group(i);
                    // 对应 Go: if matches[i] != ""（未参与的组 Go 侧为 ""）
                    if (g != null && !g.isEmpty()) {
                        result.put(key, g);
                    }
                }
            }
            // group: 提取指定组
            if (ex.group != null && !ex.group.isEmpty()) {
                int groupIdx = subexpIndex("(?i)" + p, ex.group);
                // 对应 Go: groupIdx > 0 && groupIdx < len(matches)
                if (groupIdx > 0 && groupIdx <= groupCount) {
                    String g = matcher.group(groupIdx);
                    // Go 侧未参与的组为 ""（FindStringSubmatch 不返回 nil），按原样写入
                    result.put(ex.group, g == null ? "" : g);
                }
            }
        }
        return result;
    }

    /**
     * kval 提取，对应 Go 的 {@code (e *Engine) extractKval}。
     *
     * <p>nuclei 官方 kval 格式：
     * {@code "header.server"} → 查 {@code data["server"]}（header 区域，实际查找不带 prefix 的 key）、
     * {@code "body.title"} → {@code data["title"]}、
     * 直接 key 名（如 {@code "x_powered_by"}）→ 精确/规范化/大小写不敏感查找。
     */
    Map<String, String> extractKval(Extractor ex, Map<String, Object> data) {
        Map<String, String> result = new LinkedHashMap<>();
        if (ex.kval == null) {
            return result;
        }
        for (String kv : ex.kval) {
            // 对应 Go: parts := strings.SplitN(kv, ".", 2)；len==2 时取第 2 段
            String key;
            int dot = kv.indexOf('.');
            if (dot >= 0) {
                key = kv.substring(dot + 1);
            } else {
                key = kv;
            }

            // nuclei 风格: case-insensitive 匹配 header key
            Object[] found = lookupDataKey(data, key);
            if ((Boolean) found[1]) {
                // 使用原始 key 作为结果 key (例如: header.server -> result["header.server"])
                result.put(kv, Fmt.format("%v", found[0]));
            }
        }
        return result;
    }

    /**
     * 在 data 中查找 key (大小写不敏感)，对应 Go 的包级函数 {@code lookupDataKey}。
     * nuclei 风格: 同时支持查找 data map 和 http.Header。
     *
     * <p>分支顺序与 Go 一致：① 精确匹配 ② {@code http.CanonicalHeaderKey} 规范化匹配
     * ③ 全 map 大小写不敏感扫描 ④ {@code data["headers"]} 内的 Header 查找。
     *
     * <p>④ 的 Go 类型是 {@code http.Header}（{@code Get} 大小写不敏感取首值）；Java 侧该键
     * 由 protocol 执行器写入，类型未定，这里同时支持 {@link java.net.http.HttpHeaders}
     * 与 {@code Map}（值为 String 或 List&lt;String&gt;）两种常见形态。
     *
     * @return {@code Object[]{值, Boolean}}，{@code [1] == Boolean.FALSE} 表示未找到
     * （对应 Go 的 {@code (interface{}, bool)}；值为 null 且 {@code [1]==TRUE} 对应 Go 的
     * {@code (nil, true)}，{@code %v} 格式化为 {@code <nil>}）
     */
    static Object[] lookupDataKey(Map<String, Object> data, String key) {
        if (data == null) {
            return new Object[]{null, Boolean.FALSE};
        }
        // 1. 精确匹配
        if (data.containsKey(key)) {
            return new Object[]{data.get(key), Boolean.TRUE};
        }
        // 2. 转换为 Title-Case 匹配 (header.X-Server -> "X-Server")
        String canonical = canonicalHeaderKey(key);
        if (data.containsKey(canonical)) {
            return new Object[]{data.get(canonical), Boolean.TRUE};
        }
        // 3. 转小写匹配 data map
        String lower = key.toLowerCase(Locale.ROOT);
        for (Map.Entry<String, Object> e : data.entrySet()) {
            String k = e.getKey();
            if (k != null && k.toLowerCase(Locale.ROOT).equals(lower)) {
                return new Object[]{e.getValue(), Boolean.TRUE};
            }
        }
        // 4. 查找 http.Header (通常存在 data["headers"])
        Object hdr = data.get("headers");
        if (hdr instanceof java.net.http.HttpHeaders httpHdr) {
            String v = httpHdr.firstValue(key).orElse(null);
            if (v == null || v.isEmpty()) {
                v = httpHdr.firstValue(canonical).orElse(null);
            }
            if (v != null && !v.isEmpty()) {
                return new Object[]{v, Boolean.TRUE};
            }
        } else if (hdr instanceof Map<?, ?> mapHdr) {
            // http.Header.Get 语义：大小写不敏感、取首值、空值视为未命中
            Object v = headerGet(mapHdr, key);
            if (v == null || "".equals(v)) {
                v = headerGet(mapHdr, canonical);
            }
            if (v != null && !"".equals(v)) {
                return new Object[]{v, Boolean.TRUE};
            }
        }
        return new Object[]{null, Boolean.FALSE};
    }

    /**
     * 对应 Go 的 {@code http.CanonicalHeaderKey}（net/textproto）：按连字符分段，
     * 每段首字母大写、其余小写；含非法字节时原样返回。
     */
    static String canonicalHeaderKey(String key) {
        boolean upper = true;
        char[] a = key.toCharArray();
        for (int i = 0; i < a.length; i++) {
            char c = a[i];
            if (c <= ' ' || c >= 0x7f || c == ':') {
                return key;
            }
            if (upper && c >= 'a' && c <= 'z') {
                a[i] = (char) (c - ('a' - 'A'));
            } else if (!upper && c >= 'A' && c <= 'Z') {
                a[i] = (char) (c + ('a' - 'A'));
            }
            upper = c == '-';
        }
        return new String(a);
    }

    /**
     * 对应 Go 的 {@code http.Header.Get}：大小写不敏感取首值；值为 List 时取首元素。
     */
    private static Object headerGet(Map<?, ?> hdr, String key) {
        Object v = null;
        if (hdr.containsKey(key)) {
            v = hdr.get(key);
        } else {
            for (Map.Entry<?, ?> e : hdr.entrySet()) {
                if (e.getKey() != null && e.getKey().toString().equalsIgnoreCase(key)) {
                    v = e.getValue();
                    break;
                }
            }
        }
        if (v instanceof List<?> list) {
            return list.isEmpty() ? null : list.get(0);
        }
        return v;
    }

    /**
     * xpath 提取，对应 Go 的 {@code (e *Engine) extractXPath}（简化实现：字符串包含）。
     */
    Map<String, String> extractXPath(Extractor ex, String target) {
        Map<String, String> result = new LinkedHashMap<>();
        if (ex.xpath == null) {
            return result;
        }
        for (String xp : ex.xpath) {
            // 简化 xpath 实现: 实际可使用 htmlquery
            if (target.contains(xp)) {
                result.put(xp, target);
            }
        }
        return result;
    }

    /**
     * json 提取，对应 Go 的 {@code (e *Engine) extractJSON}：先整体反序列化，
     * 解析失败返回空 map；随后逐个 {@link #jsonPath(Object, String)} 取值，
     * 非 nil 值以 {@code %v} 格式化写入。
     */
    Map<String, String> extractJSON(Extractor ex, String target) {
        Map<String, String> result = new LinkedHashMap<>();
        Object v;
        try {
            // 对应 Go: json.Unmarshal([]byte(target), &v)；err → 返回空 map
            v = MAPPER.readValue(target, Object.class);
        } catch (IOException e) {
            return result;
        }
        if (ex.json == null) {
            return result;
        }
        for (String jp : ex.json) {
            Object val = jsonPath(v, jp);
            if (val != null) {
                String key = jp;
                result.put(key, Fmt.format("%v", val));
            }
        }
        return result;
    }

    /**
     * 简单 JSONPath 支持: {@code a.b.c} 或 {@code a[0].b}。
     * 对应 Go 的包级函数 {@code jsonPath}。
     *
     * <p>与 Go 一致：数字段优先按数组下标处理（即使当前节点是对象也判失败返回 nil）；
     * 非数字段按对象键查找。数组下标越界返回 null（Go 侧负下标会 panic，Java 侧以
     * 判空规避崩溃，行为均视为未命中）。
     */
    static Object jsonPath(Object v, String path) {
        // 先解析 [n] 形式 → ".n"（对应 Go 的 regexp ReplaceAllStringFunc）
        path = path.replaceAll("\\[(\\d+)\\]", ".$1");
        for (String p : path.split("\\.", -1)) {
            if (p.isEmpty()) {
                continue;
            }
            int idx;
            boolean numeric;
            try {
                // 对应 Go: strconv.Atoi(p)
                idx = Integer.parseInt(p, 10);
                numeric = true;
            } catch (NumberFormatException e) {
                idx = -1;
                numeric = false;
            }
            if (numeric) {
                if (v instanceof List<?> arr && idx >= 0 && idx < arr.size()) {
                    v = arr.get(idx);
                } else {
                    return null;
                }
            } else if (v instanceof Map<?, ?> m) {
                if (m.containsKey(p)) {
                    v = m.get(p);
                } else {
                    return null;
                }
            } else {
                return null;
            }
        }
        return v;
    }

    /**
     * dsl 提取，对应 Go 的 {@code (e *Engine) extractDSL}：求值失败跳过，
     * 键取 {@code ex.Name}（为空时用表达式本身）。
     */
    Map<String, String> extractDSL(Extractor ex, Map<String, Object> data) {
        Map<String, String> result = new LinkedHashMap<>();
        if (ex.dsl == null) {
            return result;
        }
        for (String expr : ex.dsl) {
            Object[] ev = evaluator.evaluate(expr, data);
            if (ev[1] != null) {
                continue;
            }
            Object val = ev[0];
            if (val != null) {
                String key = ex.name;
                if (key == null || key.isEmpty()) {
                    key = expr;
                }
                result.put(key, Fmt.format("%v", val));
            }
        }
        return result;
    }

    /**
     * 对应 Go 的 {@code re.SubexpNames()}：返回与捕获组下标对齐的组名数组，
     * {@code names[0]} 恒为 {@code ""}（整体匹配），未命名组为 {@code ""}。
     *
     * <p>Java 17 无公开 API 枚举命名组，这里对模式源串做一次扫描：计数
     * {@code (...)} 与 {@code (?<name>...)}，跳过 {@code (?:}/{@code (?=}/{@code (?!}/
     * {@code (?<=}/{@code (?<!}/{@code (?flags...)}、字符类、转义与 {@code \Q...\E}。
     * 计数规则与 {@code java.util.regex} 的组编号一致（本方法只在模式编译成功后调用）。
     */
    static String[] subexpNames(String pattern) {
        List<String> names = new ArrayList<>();
        names.add(""); // 下标 0：整体匹配
        boolean inClass = false;
        boolean escaped = false;
        int i = 0;
        final int n = pattern.length();
        while (i < n) {
            char c = pattern.charAt(i);
            if (escaped) {
                escaped = false;
                i++;
                continue;
            }
            if (c == '\\') {
                if (i + 1 < n && pattern.charAt(i + 1) == 'Q') {
                    // \Q...\E 字面量段，内部括号不构成分组
                    int end = pattern.indexOf("\\E", i + 2);
                    i = end < 0 ? n : end + 2;
                    continue;
                }
                escaped = true;
                i++;
                continue;
            }
            if (c == '[') {
                inClass = true;
                i++;
                continue;
            }
            if (inClass) {
                if (c == ']') {
                    inClass = false;
                }
                i++;
                continue;
            }
            if (c == '(') {
                boolean named = i + 3 < n && pattern.charAt(i + 1) == '?'
                        && pattern.charAt(i + 2) == '<'
                        && pattern.charAt(i + 3) != '=' && pattern.charAt(i + 3) != '!';
                if (named) {
                    int gt = pattern.indexOf('>', i + 3);
                    if (gt < 0) {
                        break; // 模式未闭合（编译阶段已失败），停止扫描
                    }
                    names.add(pattern.substring(i + 3, gt));
                    i = gt + 1;
                    continue;
                }
                if (!(i + 1 < n && pattern.charAt(i + 1) == '?')) {
                    names.add(""); // 普通捕获组 (...)；(?: (?= (?! (?<= (?<! (?flags 不计数
                }
                i++;
                continue;
            }
            i++;
        }
        return names.toArray(new String[0]);
    }

    /**
     * 对应 Go 的 {@code re.SubexpIndex(name)}：命名捕获组的下标（与 Java group 下标一致），
     * 未找到返回 {@code -1}。
     */
    static int subexpIndex(String pattern, String name) {
        String[] names = subexpNames(pattern);
        for (int i = 1; i < names.length; i++) {
            if (name.equals(names[i])) {
                return i;
            }
        }
        return -1;
    }
}

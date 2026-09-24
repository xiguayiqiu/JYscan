package space.jyscan.modules.nuclei.loader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.introspector.BeanAccess;
import org.yaml.snakeyaml.introspector.MissingProperty;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.introspector.PropertyUtils;

import space.jyscan.modules.nuclei.model.HTTPRequest;
import space.jyscan.modules.nuclei.model.Template;

/**
 * 模板加载器，对应 Go 的 {@code loader.Loader}（{@code loader.go} + {@code parse_helpers.go}）。
 *
 * <p>跨包契约：runner 包持有本类型字段 {@code loader}，只调用
 * {@link #loadTemplate(String)} 与 {@link #loadTemplates(String)}。
 *
 * <p>Go 的 {@code (l *Loader) Parse(data []byte) (*Template, error)} 等二元返回按项目
 * 既有惯例映射为 {@code Object[]{值, Throwable}}；{@code [1] == null} 表示成功。
 *
 * <p>Go 的 {@code LoadTemplates} 解析失败会跳过并继续遍历（不中断），
 * 最终错误只可能来自 {@code filepath.Walk}；{@code LoadTemplate} 单文件失败则返回错误。
 *
 * <p>Go 用 {@code gopkg.in/yaml.v3}，本项目对应依赖为 snakeyaml（已在 pom 中）。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/loader/{loader,parse_helpers}.go}。
 */
public class Loader {

    /** 对应 Go 的 {@code NewLoader() *Loader}（Go 侧为空结构体）。 */
    public Loader() {
    }

    /**
     * 加载单个模板文件。
     *
     * <p>对应 Go 的 {@code (l *Loader) LoadTemplate(path string) (*model.Template, error)}：
     * 读文件失败返回 {@code Object[]{null, Throwable}}，成功返回 {@code Object[]{Template, null}}。
     *
     * @return {@code Object[]{Template, Throwable}}
     */
    public Object[] loadTemplate(String path) {
        byte[] data;
        try {
            data = Files.readAllBytes(Path.of(path));
        } catch (IOException | RuntimeException e) {
            // Go: fmt.Errorf("读取模板文件失败: %w", err)
            return new Object[]{null, new Exception("读取模板文件失败: " + errText(e), e)};
        }
        return parse(data);
    }

    /**
     * 从目录加载所有模板。
     *
     * <p>对应 Go 的 {@code (l *Loader) LoadTemplates(dir string) ([]*model.Template, error)}：
     * 遍历与 Go 的 {@code filepath.Walk} 一致——目录内按文件名排序、只认
     * {@code .yaml/.yml/.json}（小写比较）、不跟随符号链接（Go 用 Lstat）、
     * 单个模板解析失败则 {@code skipped++} 继续（不中断），walk 出错打印到 stderr 后跳过。
     * 结束后向 stderr 打印 Go 的统计行。
     *
     * <p>返回约定：Go 的 nil slice 在 Java 中映射为空列表（{@code [0]} 恒非 null）。
     *
     * @return {@code Object[]{List<Template>, Throwable}}
     */
    public Object[] loadTemplates(String dir) {
        List<Template> templates = new ArrayList<>();
        int[] counts = new int[2]; // [0]=parsed, [1]=skipped
        walk(Path.of(dir), templates, counts);
        // Go: fmt.Fprintf(os.Stderr, "[%s] 扫描目录 %s: 解析=%d, 跳过=%d\n", "loader", dir, parsed, skipped)
        System.err.println(String.format("[loader] 扫描目录 %s: 解析=%d, 跳过=%d",
                dir, counts[0], counts[1]));
        return new Object[]{templates, null};
    }

    /**
     * 解析模板字节数据（宽松的两阶段解析：先 map，再结构体）。
     *
     * <p>对应 Go 的 {@code (l *Loader) Parse(data []byte) (*model.Template, error)}：
     * 第一阶段 {@code yaml.Unmarshal(data, &raw)} 解析成通用 map、忽略严格字段检查；
     * 第二阶段从 map 手工取字段填 {@code Template}（顶层字段、variables/constants、
     * matchers/extractors、8 个协议段），最后 {@code if t.Info.Name == ""} 以 {@code id} 兜底。
     *
     * @return {@code Object[]{Template, Throwable}}
     */
    public Object[] parse(byte[] data) {
        // 第一阶段: 解析为通用 map, 忽略所有严格字段检查
        Object doc;
        try {
            // 每次新建 Yaml 实例: snakeyaml 的 Yaml 非线程安全, 对应 Go yaml.Unmarshal 的无状态调用
            doc = new Yaml().load(new ByteArrayInputStream(data));
        } catch (Exception e) {
            // Go: fmt.Errorf("解析 YAML 失败: %w", err)
            return new Object[]{null, new Exception("解析 YAML 失败: " + errText(e), e)};
        }
        if (doc == null) {
            // Go: fmt.Errorf("模板为空")（空文档解出 nil map）
            return new Object[]{null, new Exception("模板为空")};
        }
        if (!(doc instanceof Map)) {
            // Go 侧非 map 文档会报 "cannot unmarshal !!... into map[string]interface {}"
            return new Object[]{null, new Exception("解析 YAML 失败: 顶层不是 map")};
        }
        Map<String, Object> raw = ParseHelpers.toStringKeyMap(doc);

        // 第二阶段: 从 map 手工取字段填结构体 (容错更强)
        Template t = new Template();

        // 顶层字段
        if (raw.get("id") instanceof String v) {
            t.id = v;
        }
        if (raw.get("info") instanceof Map) {
            t.info = ParseHelpers.parseInfo(ParseHelpers.toStringKeyMap(raw.get("info")));
        }
        if (raw.get("flow") instanceof String v) {
            t.flow = v;
        }
        if (raw.get("self-contained") instanceof Boolean v) {
            t.selfContained = v;
        }
        if (raw.get("stop-at-first-match") instanceof Boolean v) {
            t.stopAtFirstMatch = v;
        }

        // variables
        if (raw.get("variables") instanceof Map) {
            t.variables = ParseHelpers.toStringKeyMap(raw.get("variables"));
        }
        if (raw.get("constants") instanceof Map) {
            t.constants = ParseHelpers.toStringKeyMap(raw.get("constants"));
        }

        // 模板级 matchers/extractors
        if (raw.get("matchers") instanceof List<?> v) {
            t.matchers = ParseHelpers.parseMatchers(v);
        }
        if (raw.get("extractors") instanceof List<?> v) {
            t.extractors = ParseHelpers.parseExtractors(v);
        }
        if (raw.get("matchers-condition") instanceof String v) {
            t.matchersCondition = v;
        }

        // 协议请求
        if (raw.get("http") instanceof List<?> v) {
            t.http = ParseHelpers.parseHTTPRequests(v);
            if (t.requestsHTTP == null || t.requestsHTTP.isEmpty()) {
                t.requestsHTTP = t.http;
            }
        }
        if (raw.get("requests") instanceof List<?> v) {
            // Go: parsed := parseHTTPRequests(v); t.RequestsHTTP = append(t.RequestsHTTP, parsed...)
            // Go 的 append 因切片 len==cap 必然复制新底层数组（http 段与 requests 段互不污染），
            // Java 侧同样总是新建列表再合并，保持该语义。
            List<HTTPRequest> parsed = ParseHelpers.parseHTTPRequests(v);
            List<HTTPRequest> merged = new ArrayList<>();
            if (t.requestsHTTP != null) {
                merged.addAll(t.requestsHTTP);
            }
            merged.addAll(parsed);
            t.requestsHTTP = merged;
        }
        if (raw.get("dns") instanceof List<?> v) {
            t.dns = ParseHelpers.parseDNSRequests(v);
        }
        if (raw.get("tcp") instanceof List<?> v) {
            t.tcp = ParseHelpers.parseTCPRequests(v);
        }
        if (raw.get("ssl") instanceof List<?> v) {
            t.ssl = ParseHelpers.parseSSLRequests(v);
        }
        if (raw.get("websocket") instanceof List<?> v) {
            t.websocket = ParseHelpers.parseWSRequests(v);
        }
        if (raw.get("whois") instanceof List<?> v) {
            t.whois = ParseHelpers.parseWhoisRequests(v);
        }
        if (raw.get("file") instanceof List<?> v) {
            t.file = ParseHelpers.parseFileRequests(v);
        }
        if (raw.get("code") instanceof List<?> v) {
            t.code = ParseHelpers.parseCodeRequests(v);
        }

        if (t.info.name == null || t.info.name.isEmpty()) {
            t.info.name = t.id;
        }
        return new Object[]{t, null};
    }

    /**
     * {@link #parse(byte[])} 的别名，Go 侧为「保持向后兼容」的别名。
     *
     * <p>对应 Go 的 {@code (l *Loader) ParseYAML(data []byte) (*model.Template, error)}。
     *
     * @return {@code Object[]{Template, Throwable}}
     */
    public Object[] parseYaml(byte[] data) {
        // Go: return l.Parse(data)
        return parse(data);
    }

    // =====================================================================
    // 内部实现
    // =====================================================================

    /**
     * 递归遍历目录，对应 Go 的 {@code filepath.Walk(dir, walkFn)}。
     *
     * <p>walkFn 语义逐条对齐：目录条目按文件名排序（Go 的 Walk 内部对目录名排序）、
     * 目录先于文件处理、出错打印 {@code [loader] walk error on %s: %v} 后继续（返回 nil）、
     * {@code info.IsDir()} 先于扩展名判断、用 Lstat 语义（不跟随符号链接）。
     */
    private void walk(Path path, List<Template> templates, int[] counts) {
        boolean isDir;
        try {
            // Go filepath.Walk 使用 Lstat: 符号链接不当作目录 (NOFOLLOW_LINKS)
            isDir = Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS);
        } catch (Exception e) {
            // Go: walkFn(path, nil, err) → 打印后返回 nil 继续
            System.err.println(String.format("[loader] walk error on %s: %s", path, errText(e)));
            return;
        }
        if (isDir) {
            List<Path> entries = new ArrayList<>();
            try (var stream = Files.list(path)) {
                stream.forEach(entries::add);
            } catch (IOException e) {
                // Go: 读取目录失败 → walkFn(path, nil, err) → 打印后继续
                System.err.println(String.format("[loader] walk error on %s: %s", path, errText(e)));
                return;
            }
            // Go: filepath.Walk 按文件名排序后依次遍历
            entries.sort(Comparator.comparing(p -> p.getFileName().toString()));
            for (Path entry : entries) {
                walk(entry, templates, counts);
            }
            return;
        }

        // 非目录: 扩展名过滤 (Go: strings.ToLower(filepath.Ext(path)))
        String name = path.getFileName() == null ? "" : path.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String ext = dot >= 0 ? name.substring(dot).toLowerCase(Locale.ROOT) : "";
        if (!".yaml".equals(ext) && !".yml".equals(ext) && !".json".equals(ext)) {
            return;
        }

        Object[] res = loadTemplate(path.toString());
        if (res[1] != null) {
            counts[1]++;
            // 跳过加载失败的模板, 不中断遍历
            return;
        }
        if (res[0] != null) {
            templates.add((Template) res[0]);
            counts[0]++;
        }
    }

    /**
     * 通用协议助手：把单个 map 重新序列化为 YAML 后，用结构体解析。
     *
     * <p>对应 Go 的 {@code reParse(target interface{}, raw map[string]interface{}) error}
     * （loader.go:159）：{@code yaml.Marshal(raw)} 后 {@code yaml.Unmarshal(b, target)}，
     * 两步的错误都原样返回（不吞错）。Go 的 yaml.v3 按 yaml tag 绑定字段
     * （如 {@code cve-id}→{@code CVEID}），snakeyaml 按字段名绑定，模型字段是 camelCase、
     * YAML 键是 kebab-case，故 Java 侧用 {@link TagAwarePropertyUtils} 把 kebab 键映射到
     * camelCase 字段名才能等价；未知键按 Go 的默认行为（{@code KnownFields(false)}）忽略。
     *
     * <p>注意：Go 侧该函数在 loader 包内没有任何调用方（死代码），Java 侧保留实现以对齐源文件。
     *
     * @param target 反序列化目标对象（Go 的结构体指针），对应 Go 的 {@code target interface{}}
     * @param raw    通用 map，对应 Go 的 {@code raw map[string]interface{}}
     * @return {@code null} 表示成功；否则为 marshal/unmarshal 阶段的异常（对应 Go 的 {@code error}）
     */
    static Throwable reParse(Object target, Map<String, Object> raw) {
        if (target == null) {
            return new NullPointerException("reParse: target 为 nil");
        }
        try {
            // Go: b, err := yaml.Marshal(raw); if err != nil { return err }
            String yaml = new Yaml().dump(raw);
            // Go: return yaml.Unmarshal(b, target) —— 结构体反序列化
            LoaderOptions loaderOptions = new LoaderOptions();
            Constructor constructor = new Constructor(target.getClass(), loaderOptions);
            TagAwarePropertyUtils propertyUtils = new TagAwarePropertyUtils();
            propertyUtils.setBeanAccess(BeanAccess.FIELD); // 模型类是公开字段、无 setter
            propertyUtils.setSkipMissingProperties(true);   // Go yaml.v3 默认忽略未知键
            constructor.setPropertyUtils(propertyUtils);
            Object loaded = new Yaml(constructor).load(yaml);
            if (loaded != null) {
                for (Field field : target.getClass().getFields()) {
                    if (Modifier.isStatic(field.getModifiers())) {
                        continue;
                    }
                    field.set(target, field.get(loaded));
                }
            }
            return null;
        } catch (Exception e) {
            return e;
        }
    }

    /**
     * snakeyaml 的 {@code PropertyUtils} 扩展：YAML 键优先按原名匹配字段，
     * 匹配不到时按 kebab-case→camelCase 转换后再匹配——替代 Go yaml.v3 的 yaml tag 绑定。
     *
     * <p>保留 snakeyaml 的缺失键语义：skip 模式返回 {@code MissingProperty} 占位（set 为空操作，
     * 即「忽略未知键」），非 skip 模式照常抛 {@code YAMLException}。
     */
    private static final class TagAwarePropertyUtils extends PropertyUtils {

        @Override
        public Property getProperty(Class<? extends Object> owner, String name) {
            String camel = kebabToCamel(name);
            if (camel.equals(name)) {
                return super.getProperty(owner, name);
            }
            Property direct;
            try {
                direct = super.getProperty(owner, name);
            } catch (RuntimeException notFound) {
                // 非 skip 模式下原名缺失会直接抛出：改用 camelCase 再查一次（仍缺失则照常抛）
                return super.getProperty(owner, camel);
            }
            if (!(direct instanceof MissingProperty)) {
                return direct;
            }
            // skip 模式下原名缺失得到占位符：尝试 camelCase，失败则保持「跳过」语义
            try {
                Property byCamel = super.getProperty(owner, camel);
                if (!(byCamel instanceof MissingProperty)) {
                    return byCamel;
                }
            } catch (RuntimeException stillMissing) {
                // camelCase 也缺失：保持原占位符
            }
            return direct;
        }
    }

    /** {@code matchers-condition}→{@code matchersCondition} 式的键名转换（Go yaml tag 的通用形式）。 */
    private static String kebabToCamel(String name) {
        if (name == null || name.indexOf('-') < 0) {
            return name;
        }
        StringBuilder sb = new StringBuilder(name.length());
        boolean upper = false;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c == '-') {
                upper = true;
            } else {
                sb.append(upper ? Character.toUpperCase(c) : c);
                upper = false;
            }
        }
        return sb.toString();
    }

    /** Go 的 {@code err.Error()} 近似：优先消息文本，无消息时退回 {@code toString}。 */
    private static String errText(Throwable t) {
        String msg = t.getMessage();
        return msg != null ? msg : String.valueOf(t);
    }
}

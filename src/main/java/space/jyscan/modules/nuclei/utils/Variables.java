package space.jyscan.modules.nuclei.utils;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 主机键归一与变量生成，对应 Go {@code utils/variables.go} 的包级函数。
 *
 * <p>跨包契约：runner 调用 {@link #normalizeHostKey(String)} 与
 * {@link #generateUrlVariables(String, boolean)}；{@link #generateDnsVariables(String)}、
 * {@link #publicSuffix(String)} 在 Go 中亦无跨包调用方，但属该文件的导出面。
 *
 * <p>类名取自 Go 源文件名 {@code variables.go}（包级函数在 Java 中需归入某个类）。
 *
 * <p>Go 的 {@code net/url}（{@code url.ParseRequestURI} / {@code url.Parse}）在 Java 无完全
 * 等价的标准库（类型断言时机、host 字符集、pct-encoded 规则均有差异），故本类内以
 * {@link #parseGoUrl(String, boolean, boolean)} 等按 go1.27 实测行为复刻（见各方法注释）。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/utils/variables.go}。
 */
public final class Variables {

    private Variables() {
    }

    // =====================================================================
    // NormalizeHostKey（variables.go:124）
    // =====================================================================

    /**
     * 将任意 target（URL/host:port/host）标准化为 cache key。
     *
     * <p>对应 Go 的 {@code NormalizeHostKey(value string) string}
     * （nuclei 官方：NormalizeCacheValue），统一为 {@code host:port} 格式，
     * 与 {@link #extractHostFromError(String)} 的输出一致。
     *
     * <p>分支与 Go 逐条对齐（经 go1.27 实测校准）：
     * <ul>
     *   <li>{@code url.ParseRequestURI} 失败或 {@code Host == ""} → 不是 URL，若原串不含
     *       {@code ://} 则补 {@code https://} 再解析；成功且有 Host 时，无端口补 {@code :443}、
     *       有端口用原 {@code host:port}；否则原样返回；</li>
     *   <li>是 URL 且无端口 → {@code https}/{@code http} 分别补 {@code :443}/{@code :80}，
     *       其余 scheme 返回 {@code u.Host}；有端口 → {@code u.Host}。</li>
     * </ul>
     */
    public static String normalizeHostKey(String value) {
        String normalized = value;

        // u, err := url.ParseRequestURI(value)
        GoURL u = parseRequestUri(value);
        if (u == null || u.host.isEmpty()) {
            // 不是 URL, 尝试补全 https://
            if (!value.contains("://")) {
                GoURL u2 = parseRequestUri("https://" + value);
                if (u2 != null && !u2.host.isEmpty()) {
                    if (u2.port.isEmpty()) {
                        normalized = "443";
                        // Go 原样保留此赋值：进入该分支时 u2.Host 必非空，下一行必然覆盖（Go 侧死代码）
                        normalized = u2.host + ":443";
                    } else {
                        normalized = u2.host;
                    }
                    return normalized;
                }
            }
            return normalized;
        }

        // 是 URL, 标准化为 host[:port]
        if (u.port.isEmpty()) {
            switch (u.scheme.toLowerCase(Locale.ROOT)) {
                case "https":
                    return u.hostname + ":443";
                case "http":
                    return u.hostname + ":80";
                default:
                    return u.host;
            }
        }
        return u.host;
    }

    // =====================================================================
    // GenerateDNSVariables（variables.go:209）
    // =====================================================================

    /**
     * 由域名生成 DNS 变量集（{@code FQDN}/{@code TLD}/{@code DN}/{@code SD}/{@code RDN}）。
     *
     * <p>对应 Go 的 {@code GenerateDNSVariables(domain string) map[string]interface{}}，
     * 去掉末尾一个 {@code .} 后为空则返回 {@code null}（Go 的 nil map）。
     */
    public static Map<String, Object> generateDnsVariables(String domain) {
        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }
        if (domain.isEmpty()) {
            return null;
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("FQDN", domain);

        String[] parts = domain.split("\\.", -1); // Go: strings.Split(domain, ".")
        if (parts.length >= 2) {
            result.put("TLD", parts[parts.length - 1]);
            result.put("DN", joinFrom(parts, 1));
        }
        if (parts.length >= 3) {
            result.put("SD", joinRange(parts, 1, parts.length - 1));
            result.put("RDN", joinRange(parts, parts.length - 2, parts.length));
        }
        return result;
    }

    // =====================================================================
    // GenerateURLVariables（variables.go:230）
    // =====================================================================

    /**
     * 由 URL 生成变量集（{@code BaseURL}/{@code Hostname}/{@code Host}/{@code Port}/
     * {@code Path}/{@code Scheme}/{@code Query}/{@code File}/{@code RootURL}）。
     *
     * <p>对应 Go 的 {@code GenerateURLVariables(rawURL string, removeTrailingSlash bool)
     * map[string]interface{}}：{@code url.Parse} 失败或 {@code u.Host == ""} 返回 {@code null}。
     *
     * <p>Go-parity 细节（含 Go 的命名怪癖）：{@code Hostname} 取 {@code u.Host}（带端口）、
     * {@code Host} 取 {@code u.Hostname()}（不带端口）——与 Go 源码一致，不“修正”。
     * {@code BaseURL} 按 Go 的 {@code u.String()} 规则重建（scheme 小写、保留 userinfo、
     * 查询串与片段原样）；{@code removeTrailingSlash} 裁的是<b>解码后</b>的 {@code Path}
     * （同 Go 裁 {@code u.Path}），裁剪生效后 {@code BaseURL} 用重转义的路径
     * （对应 Go 因 {@code RawPath} 与 {@code Path} 不再一致而回退到转义输出）。
     */
    public static Map<String, Object> generateUrlVariables(String rawUrl, boolean removeTrailingSlash) {
        // u, err := url.Parse(rawURL); if err != nil || u.Host == "" → nil
        GoURL u = parseGoUrl(rawUrl, false, true);
        if (u == null || u.host.isEmpty()) {
            return null;
        }

        String path = u.path; // Go 的 u.Path（已解码）
        boolean trimmed = false;
        if (removeTrailingSlash && path.endsWith("/")) {
            // Go: u.Path = strings.TrimSuffix(u.Path, "/")
            path = path.substring(0, path.length() - 1);
            trimmed = true;
        }
        // Go u.String(): EscapedPath 仅在 RawPath 有效且解码等于 Path 时才用原文，
        // 否则按解码后的 Path 重新转义——裁剪发生后 Path 已变，必然走重新转义
        String pathForBaseUrl = (!trimmed && validEncoded(u.rawPath)) ? u.rawPath : escapePath(path);

        Map<String, Object> result = new LinkedHashMap<>();
        StringBuilder baseUrl = new StringBuilder();
        baseUrl.append(u.scheme).append("://").append(u.userinfo).append(u.host);
        baseUrl.append(pathForBaseUrl);
        if (u.forceQuery || !u.rawQuery.isEmpty()) {
            // Go String(): if u.ForceQuery || u.RawQuery != "" → 写 '?' + RawQuery
            baseUrl.append('?').append(u.rawQuery);
        }
        if (!u.fragment.isEmpty()) {
            baseUrl.append('#').append(u.fragment);
        }
        result.put("BaseURL", baseUrl.toString());
        result.put("Hostname", u.host);      // Go: "Hostname": u.Host（带端口，怪癖照搬）
        result.put("Host", u.hostname);      // Go: "Host": u.Hostname()（不带端口）
        result.put("Port", u.port);
        result.put("Path", path);
        result.put("Scheme", u.scheme);

        if (u.port.isEmpty()) {
            if ("https".equals(u.scheme)) {
                result.put("Port", "443");
            } else if ("http".equals(u.scheme)) {
                result.put("Port", "80");
            }
        }
        if ("".equals(result.get("Port"))) {
            // Go 原样保留：条件恒真时把 "" 写回 ""（Go 侧无操作死代码）
            result.put("Port", "");
        }
        if (!u.rawQuery.isEmpty()) {
            result.put("Query", "?" + u.rawQuery);
        }
        String[] parts = path.split("/", -1); // Go: strings.Split(u.Path, "/")（恒非空）
        result.put("File", parts[parts.length - 1]);
        result.put("RootURL", u.scheme + "://" + u.host); // Go: u.Host（含端口）
        return result;
    }

    // =====================================================================
    // PublicSuffix（variables.go:266）
    // =====================================================================

    /**
     * 返回域名的最后一个点之后的部分（简化版 public suffix，非 PSL）。
     *
     * <p>对应 Go 的 {@code PublicSuffix(domain string) string}：去掉末尾一个 {@code .}、
     * 空串返回 {@code ""}、无点则整体返回。
     */
    public static String publicSuffix(String domain) {
        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }
        if (domain.isEmpty()) {
            return "";
        }
        int idx = lastDot(domain);
        if (idx < 0) {
            return domain;
        }
        return domain.substring(idx + 1);
    }

    /** 对应 Go 的包私有 {@code lastDot(s string) int}。 */
    private static int lastDot(String s) {
        for (int i = s.length() - 1; i >= 0; i--) {
            if (s.charAt(i) == '.') {
                return i;
            }
        }
        return -1;
    }

    // =====================================================================
    // extractHostFromError / parseURLFromErr（variables.go:164、195，Go 包私有）
    // =====================================================================

    /**
     * 从错误文本提取 host，对应 Go 的包私有 {@code extractHostFromError(errMsg string) string}。
     *
     * <p>三级策略与 Go 相同：{@code "dial tcp HOST:PORT"} 模式 → URL 模式 → 首个含 {@code .}
     * 的 token。注意 {@code "dial tcp"} 是 Go {@code net} 包的措辞，Java 侧异常文本通常走
     * 第 2/3 级（算法本身按 Go 原样移植）。
     */
    static String extractHostFromError(String errMsg) {
        // 1. 尝试 "dial tcp HOST:PORT" 模式
        int idx = errMsg.indexOf("dial tcp ");
        if (idx >= 0) {
            String rest = errMsg.substring(idx + "dial tcp ".length());
            int end = indexOfAny(rest, " ");
            if (end > 0) {
                return trimRight(rest.substring(0, end), ":");
            }
            return trimRight(rest, ":");
        }

        // 2. 尝试 URL 模式
        String fromUrl = parseURLFromErr(errMsg);
        if (!fromUrl.isEmpty()) {
            return fromUrl;
        }

        // 3. 回退: 第一个含 . 的 token
        for (String p : fields(errMsg)) {
            String cleaned = trim(p, ",:;\"'()[]");
            if (cleaned.contains(".")) {
                return cleaned;
            }
        }
        return "";
    }

    /**
     * 提取 {@code "https://host:port"} 中的 {@code host:port}，对应 Go 的包私有
     * {@code parseURLFromErr(errMsg string) string}（先 {@code https://} 后 {@code http://}）。
     */
    static String parseURLFromErr(String errMsg) {
        for (String prefix : new String[]{"https://", "http://"}) {
            int idx = errMsg.indexOf(prefix);
            if (idx >= 0) {
                String rest = errMsg.substring(idx + prefix.length());
                int end = indexOfAny(rest, "/ ");
                if (end > 0) {
                    return rest.substring(0, end);
                }
                return rest;
            }
        }
        return "";
    }

    // =====================================================================
    // Go strings 包的小型对照实现
    // =====================================================================

    /** 对应 Go 的 {@code strings.IndexAny(s, chars)}（chars 视为字符集合）。 */
    private static int indexOfAny(String s, String chars) {
        for (int i = 0; i < s.length(); i++) {
            if (chars.indexOf(s.charAt(i)) >= 0) {
                return i;
            }
        }
        return -1;
    }

    /** 对应 Go 的 {@code strings.TrimRight(s, cutset)}。 */
    private static String trimRight(String s, String cutset) {
        int end = s.length();
        while (end > 0 && cutset.indexOf(s.charAt(end - 1)) >= 0) {
            end--;
        }
        return s.substring(0, end);
    }

    /** 对应 Go 的 {@code strings.Trim(s, cutset)}（两端）。 */
    private static String trim(String s, String cutset) {
        int start = 0;
        int end = s.length();
        while (start < end && cutset.indexOf(s.charAt(start)) >= 0) {
            start++;
        }
        while (end > start && cutset.indexOf(s.charAt(end - 1)) >= 0) {
            end--;
        }
        return s.substring(start, end);
    }

    /** 对应 Go 的 {@code strings.Fields(s)}（按空白切分、丢弃空段）。 */
    private static List<String> fields(String s) {
        List<String> result = new ArrayList<>();
        String trimmed = s.trim();
        if (trimmed.isEmpty()) {
            return result;
        }
        for (String part : trimmed.split("\\s+")) {
            if (!part.isEmpty()) {
                result.add(part);
            }
        }
        return result;
    }

    /** 对应 Go 的 {@code strings.Join(parts[from:], ".")}。 */
    private static String joinFrom(String[] parts, int from) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < parts.length; i++) {
            if (i > from) {
                sb.append('.');
            }
            sb.append(parts[i]);
        }
        return sb.toString();
    }

    /** 对应 Go 的 {@code strings.Join(parts[a:b], ".")}。 */
    private static String joinRange(String[] parts, int from, int to) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < to; i++) {
            if (i > from) {
                sb.append('.');
            }
            sb.append(parts[i]);
        }
        return sb.toString();
    }

    // =====================================================================
    // Go net/url 的对照实现（按 go1.27 实测行为移植）
    // =====================================================================

    /** 对应 Go 的 {@code url.URL} 中被用到的字段子集。 */
    static final class GoURL {
        /** {@code u.Scheme}（已按 Go 规则小写）。 */
        String scheme = "";
        /** {@code u.Host}（host[:port]，不含 userinfo，host 已解码）。 */
        String host = "";
        /** {@code u.Hostname()}（不带端口、IPv6 去括号）。 */
        String hostname = "";
        /** {@code u.Port()}（原文端口，无端口为空串）。 */
        String port = "";
        /** userinfo 原文（含末尾 {@code @}，无则空串），供 {@code u.String()} 重建。 */
        String userinfo = "";
        /** 原始（未解码）路径文本。 */
        String rawPath = "";
        /** {@code u.Path}（百分号已解码）。 */
        String path = "";
        /** {@code u.RawQuery}（不含 {@code ?}）。 */
        String rawQuery = "";
        /** {@code u.Fragment}（不含 {@code #}）。 */
        String fragment = "";
        /** 对应 Go 的 {@code url.URL.ForceQuery}：{@code ?} 结尾且无参数值时为 true（{@code String()} 仍输出 {@code ?}）。 */
        boolean forceQuery = false;
    }

    /** 对应 Go 的 {@code url.ParseRequestURI(rawURL)}（viaRequest 语义）。 */
    static GoURL parseRequestUri(String raw) {
        return parseGoUrl(raw, true, false);
    }

    /** 对应 Go 的 {@code url.Parse(rawURL)}（先切 {@code #fragment}）。 */
    static GoURL parseUri(String raw) {
        return parseGoUrl(raw, false, true);
    }

    /**
     * 对应 Go {@code net/url} 的 {@code parse(rawURL, viaRequest)} 核心流程，
     * 行为按 go1.27 实测校准（getScheme → 切 query → opaque/authority/path → host 校验解码 →
     * 路径解码）。
     *
     * @param viaRequest    {@code true} 对应 {@code url.ParseRequestURI}：无 scheme 且非
     *                      {@code /} 开头的输入报错（Go: "invalid URI for request"）
     * @param splitFragment {@code true} 对应 {@code url.Parse}：解析前先从原串切出
     *                       {@code #fragment}；{@code ParseRequestURI} 不切（实测：host 里的
     *                       {@code #} 会作为非法 host 字符导致解析失败，路径里的则原样保留）
     * @return 解析结果；对应 Go 返回 {@code error} 的情形返回 {@code null}
     */
    private static GoURL parseGoUrl(String raw, boolean viaRequest, boolean splitFragment) {
        if (raw == null) {
            return null; // Go 的入参是 string，不存在 null；此处仅 Java 防御
        }
        String frag = "";
        if (splitFragment) {
            int f = raw.indexOf('#');
            if (f >= 0) {
                frag = raw.substring(f + 1);
                raw = raw.substring(0, f);
            }
        }
        // Go: stringContainsCTLByte → errors.New("net/url: invalid control character in URL")
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                return null;
            }
        }
        if (raw.isEmpty()) {
            if (viaRequest) {
                return null; // Go: errors.New("empty url")
            }
            GoURL empty = new GoURL();
            empty.fragment = frag;
            return empty; // Go: Parse("") 返回空 *URL（Host == ""），不报错
        }
        if ("*".equals(raw)) {
            GoURL star = new GoURL();
            star.fragment = frag;
            return star; // Go: url.Path = "*"
        }

        // getScheme（Go net/url.getScheme 的字符规则）
        String scheme = "";
        String rest = raw;
        int colon = -1;
        boolean noScheme = false;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                continue;
            }
            if ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.') {
                if (i == 0) {
                    noScheme = true; // Go: i==0 的数字等 → 无 scheme（整串即 rest）
                    break;
                }
            } else if (c == ':') {
                if (i == 0) {
                    return null; // Go: errors.New("missing protocol scheme")
                }
                colon = i;
                break;
            } else {
                noScheme = true; // Go: 非法字符 → 无合法 scheme
                break;
            }
        }
        if (!noScheme && colon >= 0) {
            scheme = raw.substring(0, colon).toLowerCase(Locale.ROOT); // Go: strings.ToLower(url.Scheme)
            rest = raw.substring(colon + 1);
        }

        // Go parse: getScheme 后先判 HasSuffix(rest, "?") && Count(rest, "?") == 1 → ForceQuery，
        // 否则 rest, RawQuery, _ = strings.Cut(rest, "?")
        GoURL u = new GoURL();
        u.scheme = scheme;
        int q = rest.indexOf('?');
        if (q >= 0) {
            if (rest.endsWith("?") && countChar(rest, '?') == 1) {
                u.forceQuery = true;
                rest = rest.substring(0, rest.length() - 1);
            } else {
                u.rawQuery = rest.substring(q + 1);
                rest = rest.substring(0, q);
            }
        }
        u.fragment = frag;

        if (rest.isEmpty()) {
            return u; // Host == ""
        }
        if (!rest.startsWith("/")) {
            if (!scheme.isEmpty()) {
                return u; // Go: 有 scheme 的 rootless path → Opaque，Host == ""
            }
            if (viaRequest) {
                return null; // Go: errors.New("invalid URI for request")
            }
            // Go: first path segment 含 ':' → errors.New("first path segment in URL cannot contain colon")
            int seg = rest.indexOf('/');
            String segment = seg >= 0 ? rest.substring(0, seg) : rest;
            if (segment.indexOf(':') >= 0) {
                return null;
            }
            // url.Parse 的相对路径: Path = rest（解码失败则报错，同 Go setPath）
            u.rawPath = rest;
            byte[] decoded = decodePath(rest);
            if (decoded == null) {
                return null;
            }
            u.path = new String(decoded, StandardCharsets.UTF_8);
            return u;
        }
        // Go: (url.Scheme != "" || !viaRequest && !strings.HasPrefix(rest, "///")) && strings.HasPrefix(rest, "//")
        // 才解析 authority；否则整个 rest 作 Path（Host == ""，go1.27 源码实测：
        // PRU("//x") → Host="" Path="//x"，Parse("///x") → Host="" Path="///x"）
        if (!rest.startsWith("//")
            || (scheme.isEmpty() && (viaRequest || rest.startsWith("///")))) {
            u.rawPath = rest;
            byte[] decoded = decodePath(rest);
            if (decoded == null) {
                return null;
            }
            u.path = new String(decoded, StandardCharsets.UTF_8);
            return u;
        }

        // authority + path（Go: rest[2:]，authority 以首个 '/' 截断）
        String after = rest.substring(2);
        int slash = after.indexOf('/');
        String authority = slash >= 0 ? after.substring(0, slash) : after;
        String pathRaw = slash >= 0 ? after.substring(slash) : "";

        // userinfo（Go: parseAuthority 以最后一个 '@' 切分）
        String host = authority;
        int at = host.lastIndexOf('@');
        if (at >= 0) {
            u.userinfo = host.substring(0, at + 1);
            host = host.substring(at + 1);
        }

        // 拆 host[:port] 并校验端口（Go: validOptionalPort 纯数字、空端口合法）
        String hostnameRaw; // 未解码的主机名（IPv6 含括号）
        boolean hasPort = false;
        if (host.startsWith("[")) {
            int close = host.indexOf(']');
            if (close < 0) {
                return null; // Go: 缺 ']' → invalid host
            }
            hostnameRaw = host.substring(0, close + 1);
            String tail = host.substring(close + 1);
            if (!tail.isEmpty()) {
                if (tail.charAt(0) != ':') {
                    return null;
                }
                u.port = tail.substring(1);
                hasPort = true;
                if (!u.port.isEmpty() && !isDigits(u.port)) {
                    return null; // Go: invalid port
                }
            }
        } else {
            int c = host.lastIndexOf(':');
            if (c >= 0) {
                u.port = host.substring(c + 1);
                hostnameRaw = host.substring(0, c);
                hasPort = true;
                if (!u.port.isEmpty() && !isDigits(u.port)) {
                    return null; // Go: invalid port ":xxx" after host
                }
            } else {
                hostnameRaw = host;
            }
        }

        if (hostnameRaw.startsWith("[")) {
            // IPv6 字面量: 括号内不做 pct 解码（可 pct 编码的字符都是 ASCII，Go 同样拒绝）
            u.hostname = hostnameRaw.substring(1, hostnameRaw.length() - 1);
            u.host = hostnameRaw + (hasPort ? ":" + u.port : "");
        } else {
            byte[] decodedHost = decodeHost(hostnameRaw);
            if (decodedHost == null) {
                return null; // Go: invalid character "x" in host name / invalid URL escape
            }
            u.hostname = new String(decodedHost, StandardCharsets.UTF_8);
            u.host = u.hostname + (hasPort ? ":" + u.port : "");
        }

        // 路径（Go setPath: 解码 + 非法 escape 报错；PRU 不切 fragment，'#' 原样留在路径里）
        u.rawPath = pathRaw;
        byte[] decodedPath = decodePath(pathRaw);
        if (decodedPath == null) {
            return null;
        }
        u.path = new String(decodedPath, StandardCharsets.UTF_8);
        return u;
    }

    /** 对应 Go 的 {@code strings.Count(s, string(r))}：字符出现次数。 */
    private static int countChar(String s, char r) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == r) {
                n++;
            }
        }
        return n;
    }

    /** 对应 Go 的 {@code url.URL.Port()} 判定用：是否全为数字且非空。 */
    private static boolean isDigits(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    /**
     * 解码 host 的 reg-name，对应 Go {@code unescape(host, encodeHost)} 的实测规则：
     * <ul>
     *   <li>允许的 ASCII 字符集为 unreserved + sub-delims（{@code -._~} 与
     *       {@code !$&'()*+,;=}）；</li>
     *   <li>{@code %XX} 必须是两位十六进制，且解码值必须 ≥ 0x80
     *       （go1.27 实测：{@code %41} 报 {@code invalid URL escape}，{@code %C3} 合法）；</li>
     *   <li>原始非 ASCII 字节（UTF-8）直接保留（实测：{@code http://exämple.com/} 合法）。</li>
     * </ul>
     *
     * @return 解码后的字节；非法字符返回 {@code null}（对应 Go 的 error）
     */
    private static byte[] decodeHost(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream(b.length);
        for (int i = 0; i < b.length; i++) {
            int c = b[i] & 0xFF;
            if (c == '%') {
                if (i + 2 >= b.length) {
                    return null; // Go: invalid URL escape "%"
                }
                int hi = hexVal(b[i + 1]);
                int lo = hexVal(b[i + 2]);
                if (hi < 0 || lo < 0) {
                    return null; // Go: invalid URL escape "%xx"
                }
                int v = (hi << 4) | lo;
                if (v < 0x80) {
                    return null; // go1.27 实测: host 内 pct-encoded 仅接受 ≥0x80 的字节
                }
                out.write(v);
                i += 2;
            } else if (c >= 0x80) {
                out.write(c); // 原始非 ASCII UTF-8 字节原样保留
            } else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || "-._~!$&'()*+,;=".indexOf(c) >= 0) {
                out.write(c);
            } else {
                return null; // Go: invalid character "x" in host name
            }
        }
        return out.toByteArray();
    }

    /**
     * 解码路径，对应 Go {@code unescape(path, encodePath)}：路径里任何合法两位十六进制
     * {@code %XX} 都可解码（go1.27 实测 {@code %20}、{@code %2F} 均合法），其余字符原样保留。
     *
     * @return 解码后的字节；非法 escape 返回 {@code null}（对应 Go 的 error）
     */
    private static byte[] decodePath(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream(b.length);
        for (int i = 0; i < b.length; i++) {
            int c = b[i] & 0xFF;
            if (c == '%') {
                if (i + 2 >= b.length) {
                    return null; // Go: invalid URL escape "%"
                }
                int hi = hexVal(b[i + 1]);
                int lo = hexVal(b[i + 2]);
                if (hi < 0 || lo < 0) {
                    return null; // Go: invalid URL escape "%xx"
                }
                out.write((hi << 4) | lo);
                i += 2;
            } else {
                out.write(c);
            }
        }
        return out.toByteArray();
    }

    /**
     * 按 Go {@code URL.EscapedPath()}（{@code encodePath} 模式）转义路径：保留 unreserved
     * 与 {@code $&+,/:;=@}（其余按字节百分号编码，含 {@code ?}、{@code #}、空格与非 ASCII）。
     */
    private static String escapePath(String path) {
        byte[] b = path.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(b.length);
        final char[] hex = "0123456789ABCDEF".toCharArray();
        for (byte element : b) {
            int c = element & 0xFF;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || "-._~$&+,/:;=@".indexOf(c) >= 0) {
                sb.append((char) c);
            } else {
                sb.append('%').append(hex[c >> 4]).append(hex[c & 0x0F]);
            }
        }
        return sb.toString();
    }

    /**
     * 对应 Go {@code net/url} 的 {@code validEncoded(s string) bool}：判断路径原文能否作为
     * {@code RawPath} 原样输出（特殊字符合法、{@code %} 后必须两位十六进制；
     * 非 ASCII 字节按 {@code shouldEscape(encodePath)} 判定为不可原样保留）。
     */
    private static boolean validEncoded(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '@', '[', ']':
                    break;
                case '%':
                    if (i + 2 >= s.length()
                            || hexVal(s.charAt(i + 1)) < 0
                            || hexVal(s.charAt(i + 2)) < 0) {
                        return false;
                    }
                    i += 2;
                    break;
                default:
                    if (shouldEscapePath(c)) {
                        return false;
                    }
                    break;
            }
        }
        return true;
    }

    /**
     * 对应 Go {@code shouldEscape(c, encodePath)} 的取反：路径重新转义时哪些字符保留原文。
     * 保留集 = 字母数字 + {@code -._~} + {@code $&+,/:;=@}（{@code ?}、{@code #} 等被转义）。
     */
    private static boolean shouldEscapePath(char c) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            return false;
        }
        if ("-._~$&+,/:;=@".indexOf(c) >= 0) {
            return false;
        }
        return true; // 非 ASCII、空格、?、#、% 等一律转义
    }

    /** 十六进制字符求值，非法返回 -1。 */
    private static int hexVal(int c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }
}

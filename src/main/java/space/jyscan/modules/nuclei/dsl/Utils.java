package space.jyscan.modules.nuclei.dsl;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * dsl 包的导出助手函数，对应 Go 的 {@code freeclient/pkg/nuclei/dsl/utils.go}。
 *
 * <p>Go 的 {@code (T, error)} 二元返回映射为 {@code Object[]{T, Throwable}}，
 * {@code [1] == null} 表示成功；{@code (bool, error)} 映射为 {@code Object[]{Boolean, Throwable}}。
 *
 * <p>Go 的正则引擎为 RE2（{@code regexp}），与 Java 正则存在语法/语义差异，
 * 统一经 {@link #compilePattern} 做最小兼容翻译后再编译（详见该方法注释）。
 */
public final class Utils {

    private Utils() {}

    /** 对应 Go 的 {@code alphaChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")}。 */
    private static final byte[] ALPHA_CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.US_ASCII);

    /** 对应 Go 的 {@code alphaNumericChars = []byte("...a-zA-Z0-9")}。 */
    private static final byte[] ALPHA_NUMERIC_CHARS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                    .getBytes(StandardCharsets.US_ASCII);

    /** 对应 Go 的 {@code numericChars = []byte("0123456789")}。 */
    private static final byte[] NUMERIC_CHARS = "0123456789".getBytes(StandardCharsets.US_ASCII);

    /** 对应 Go 的 {@code crypto/rand}，此处用 {@link SecureRandom}。 */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /** 对应 Go 的 {@code hex.EncodeToString} 输出（小写十六进制）。 */
    private static final HexFormat HEX = HexFormat.of();

    /** {@code url.QueryEscape} 使用的大写十六进制数字表。 */
    private static final char[] HEX_DIGITS = "0123456789ABCDEF".toCharArray();

    /**
     * 对应 Go 的 {@code func GlobMatch(pattern, s string) (bool, error)}。
     * 名为 Glob 实为正则匹配：Go 的 {@code regexp.MatchString} 是非锚定匹配，
     * 等价于 Java 的 {@code Matcher.find()}。
     *
     * @return {@code Object[]{Boolean, Throwable}}；模式非法时为 {@code {false, 异常}}
     */
    public static Object[] globMatch(String pattern, String s) {
        try {
            return new Object[]{compilePattern(pattern).matcher(s).find(), null};
        } catch (PatternSyntaxException e) {
            return new Object[]{false, e};
        }
    }

    /**
     * 对应 Go 的 {@code func RegexExtract(pattern, input string) ([]string, error)}
     * （Go {@code FindStringSubmatch}）。
     *
     * <p>未匹配时 Go 返回 nil slice（{@code %v} 输出为 {@code "[]"}），
     * 这里以空 {@link List} 表示，使 {@code toStringArg} 输出与 Go 一致。
     *
     * @return {@code Object[]{List&lt;String&gt;, Throwable}}；编译失败时为 {@code {null, 异常}}
     */
    public static Object[] regexExtract(String pattern, String input) {
        try {
            Matcher m = compilePattern(pattern).matcher(input);
            List<String> out = new ArrayList<>();
            if (m.find()) {
                for (int i = 0; i <= m.groupCount(); i++) {
                    String g = m.group(i);
                    // Go 未参与的捕获组为空串，Java 的 group() 返回 null，统一转成空串
                    out.add(g == null ? "" : g);
                }
            }
            return new Object[]{out, null};
        } catch (PatternSyntaxException e) {
            return new Object[]{null, e};
        }
    }

    /**
     * 对应 Go 的 {@code func RegexReplace(input, pattern, replacement string) (string, error)}。
     * 编译失败时按 Go 原样返回 {@code (input, err)}。
     *
     * @return {@code Object[]{String, Throwable}}；{@code [1] == null} 表示成功
     */
    public static Object[] regexReplace(String input, String pattern, String replacement) {
        try {
            return new Object[]{compilePattern(pattern).matcher(input).replaceAll(replacement), null};
        } catch (PatternSyntaxException e) {
            return new Object[]{input, e};
        }
    }

    /**
     * 编译正则，做 Go/RE2 与 Java 之间的最小语法翻译：
     * <ul>
     *   <li>{@code (?P<name>...)} → {@code (?<name>...)}：RE2 命名捕获组旧写法，Java 不识别
     *       （Java 组名不允许下划线，含下划线的组名仍会编译失败，属已知差异）；</li>
     *   <li>未启用 {@code (?m)} 时，把字符类之外的字面 {@code $} 改写为 {@code \z}：
     *       RE2 的 {@code $} 只匹配文本绝对末尾，而 Java 默认的 {@code $} 还会在
     *       输入末尾换行符之前匹配，改写后与 Go 行为一致。</li>
     * </ul>
     * 对应 Go 的 {@code regexp.Compile}（Go 的 {@code SafeRegexCompile} 亦经由此处）。
     */
    static Pattern compilePattern(String pattern) {
        String p = pattern.replace("(?P<", "(?<");
        if (!p.contains("(?m")) {
            p = rewriteDollarAnchor(p);
        }
        return Pattern.compile(p);
    }

    /** 将未转义、且处于字符类 {@code [...]} 之外的 {@code $} 替换为 {@code \z}。 */
    private static String rewriteDollarAnchor(String pattern) {
        StringBuilder sb = new StringBuilder(pattern.length() + 4);
        boolean inClass = false;
        int backslashes = 0;
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (c == '\\') {
                backslashes++;
                sb.append(c);
                continue;
            }
            if (backslashes % 2 == 0) {
                if (c == '[') {
                    inClass = true;
                } else if (c == ']') {
                    inClass = false;
                } else if (c == '$' && !inClass) {
                    sb.append("\\z");
                    backslashes = 0;
                    continue;
                }
            }
            backslashes = 0;
            sb.append(c);
        }
        return sb.toString();
    }

    /**
     * 对应 Go 的 {@code func Base64EncodeStr(s string) string}（{@code base64.StdEncoding}）。
     */
    public static String base64EncodeStr(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 对应 Go 的 {@code func Base64DecodeStr(s string) string}。
     * 解码失败时按 Go 返回原串 {@code s}。
     *
     * <p>Go 的 {@code StdEncoding.DecodeString} 会在解码前跳过 {@code \r}/{@code \n}，
     * 但要求去掉换行后长度为 4 的倍数（填充正确）；Java 基础解码器不跳过换行、
     * 却接受缺失填充的输入，这里先做等价预处理再解码以对齐 Go。
     */
    public static String base64DecodeStr(String s) {
        String cleaned = s.replace("\r", "").replace("\n", "");
        if (cleaned.length() % 4 != 0) {
            return s;
        }
        try {
            return new String(Base64.getDecoder().decode(cleaned), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }

    /**
     * 对应 Go 的 {@code func HexEncodeStr(s string) string}（{@code encoding/hex}，小写输出）。
     */
    public static String hexEncodeStr(String s) {
        return HEX.formatHex(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 对应 Go 的 {@code func HexDecodeStr(s string) string}。解码失败时按 Go 返回原串。
     */
    public static String hexDecodeStr(String s) {
        try {
            return new String(HEX.parseHex(s), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }

    /**
     * 对应 Go 的 {@code func URLEncodeStr(s string) string}（{@code url.QueryEscape}）：
     * 保留 {@code [A-Za-z0-9-._~]}，空格编码为 {@code +}，其余字节按 UTF-8 逐字节
     * {@code %XX} 大写编码。此处手写以对齐 Go（Java {@code URLEncoder} 对
     * {@code *}/{@code ~} 的处理与 Go 相反）。
     */
    public static String urlEncodeStr(String s) {
        StringBuilder sb = new StringBuilder();
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xFF);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~') {
                sb.append(c);
            } else if (c == ' ') {
                sb.append('+');
            } else {
                sb.append('%')
                        .append(HEX_DIGITS[(b >> 4) & 0xF])
                        .append(HEX_DIGITS[b & 0xF]);
            }
        }
        return sb.toString();
    }

    /**
     * 对应 Go 的 {@code func URLDecodeStr(s string) string}（{@code url.QueryUnescape}）：
     * {@code +} 还原为空格、{@code %XX} 按字节解码；转义非法时按 Go 返回原串。
     */
    public static String urlDecodeStr(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '+') {
                out.write(' ');
                i++;
            } else if (c == '%') {
                if (i + 2 >= s.length()) {
                    return s;
                }
                int hi = Character.digit(s.charAt(i + 1), 16);
                int lo = Character.digit(s.charAt(i + 2), 16);
                if (hi < 0 || lo < 0) {
                    return s;
                }
                out.write((hi << 4) | lo);
                i += 3;
            } else {
                int cp = s.codePointAt(i);
                if (cp < 0x80) {
                    out.write(cp);
                } else {
                    byte[] bb = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8);
                    out.write(bb, 0, bb.length);
                }
                i += Character.charCount(cp);
            }
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    /**
     * 对应 Go 的 {@code func MD5HashStr(s string) string}（{@code crypto/md5}，小写十六进制）。
     */
    public static String md5HashStr(String s) {
        return hashHex("MD5", s);
    }

    /**
     * 对应 Go 的 {@code func SHA1HashStr(s string) string}（{@code crypto/sha1}）。
     */
    public static String sha1HashStr(String s) {
        return hashHex("SHA-1", s);
    }

    /**
     * 对应 Go 的 {@code func SHA256HashStr(s string) string}（{@code crypto/sha256}）。
     */
    public static String sha256HashStr(String s) {
        return hashHex("SHA-256", s);
    }

    private static String hashHex(String algorithm, String s) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            return HEX.formatHex(md.digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            // Go 侧 crypto/md5|sha1|sha256 恒可用，Java 标准 JVM 亦必含这三个算法
            throw new IllegalStateException(algorithm + " algorithm not available", e);
        }
    }

    /**
     * 对应 Go 的 {@code func RandomString(n int) string}：取 {@code n} 个随机字节做十六进制编码后
     * 截取前 {@code n} 个字符（结果字符集为 {@code [0-9a-f]}）；{@code n <= 0} 返回空串。
     */
    public static String randomString(int n) {
        if (n <= 0) {
            return "";
        }
        byte[] b = new byte[n];
        SECURE_RANDOM.nextBytes(b);
        return HEX.formatHex(b).substring(0, n);
    }

    /**
     * 对应 Go 的 {@code func RandomInt(n int) int}：4 个随机字节组成非负整数后对 {@code n} 取模；
     * {@code n <= 0} 返回 0。（Go 侧 {@code byte} 无符号，{@code v < 0} 分支实际不可达，原样保留。）
     */
    public static int randomInt(int n) {
        if (n <= 0) {
            return 0;
        }
        byte[] b = new byte[4];
        SECURE_RANDOM.nextBytes(b);
        long v = ((long) (b[0] & 0xFF) << 24)
                | ((long) (b[1] & 0xFF) << 16)
                | ((long) (b[2] & 0xFF) << 8)
                | (long) (b[3] & 0xFF);
        if (v < 0) {
            v = -v;
        }
        return (int) (v % n);
    }

    /**
     * 对应 Go 的 {@code func RandomStringAlpha(n int) string}（仅字母）。
     */
    public static String randomStringAlpha(int n) {
        if (n <= 0) {
            return "";
        }
        byte[] b = new byte[n];
        SECURE_RANDOM.nextBytes(b);
        for (int i = 0; i < b.length; i++) {
            b[i] = ALPHA_CHARS[(b[i] & 0xFF) % ALPHA_CHARS.length];
        }
        return new String(b, StandardCharsets.US_ASCII);
    }

    /**
     * 对应 Go 的 {@code func RandomStringAlphaNumeric(n int) string}（字母+数字）。
     */
    public static String randomStringAlphaNumeric(int n) {
        if (n <= 0) {
            return "";
        }
        byte[] b = new byte[n];
        SECURE_RANDOM.nextBytes(b);
        for (int i = 0; i < b.length; i++) {
            b[i] = ALPHA_NUMERIC_CHARS[(b[i] & 0xFF) % ALPHA_NUMERIC_CHARS.length];
        }
        return new String(b, StandardCharsets.US_ASCII);
    }

    /**
     * 对应 Go 的 {@code func RandomStringNumeric(n int) string}（仅数字字符）。
     */
    public static String randomStringNumeric(int n) {
        if (n <= 0) {
            return "";
        }
        byte[] b = new byte[n];
        SECURE_RANDOM.nextBytes(b);
        for (int i = 0; i < b.length; i++) {
            b[i] = NUMERIC_CHARS[(b[i] & 0xFF) % NUMERIC_CHARS.length];
        }
        return new String(b, StandardCharsets.US_ASCII);
    }

    /**
     * 对应 Go 的 {@code func UnixTimeNow() int64}（{@code time.Now().Unix()}，秒级时间戳）。
     */
    public static long unixTimeNow() {
        return System.currentTimeMillis() / 1000L;
    }

    /**
     * 对应 Go 的 {@code func WaitN(seconds int)}（{@code time.Sleep}）；{@code seconds <= 0} 不等待。
     * Go 侧无中断概念，Java 侧被中断时恢复中断标记并结束等待。
     */
    public static void waitN(int seconds) {
        if (seconds <= 0) {
            return;
        }
        try {
            Thread.sleep(seconds * 1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 对应 Go 的 {@code func SafeRegexCompile(pattern string) (*regexp.Regexp, error)}
     * （Go 的 {@code regexp.Compile}，非 MustCompile：失败返回 error 而非 panic）。
     *
     * @return {@code Object[]{Pattern, Throwable}}；编译失败时为 {@code {null, 异常}}
     */
    public static Object[] safeRegexCompile(String pattern) {
        try {
            return new Object[]{compilePattern(pattern), null};
        } catch (PatternSyntaxException e) {
            return new Object[]{null, e};
        }
    }

    /**
     * 对应 Go 的 {@code func ContainsAny(s string, subs ...string) bool}：任一子串出现即为 true。
     * Go 可变参数 {@code subs ...string} 映射为 Java 可变参数 {@code String...}。
     */
    public static boolean containsAny(String s, String... subs) {
        for (String sub : subs) {
            if (s.contains(sub)) {
                return true;
            }
        }
        return false;
    }
}

package space.jyscan.modules.nuclei.protocol;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;

/**
 * 编解码与散列静态方法，对应 Go {@code protocol/protocol.go} 的包级导出函数。
 *
 * <p>跨包契约：runner 的 {@code registerVariableFunctions} 用这些方法填充
 * {@code variable.Engine} 的 {@code base64}/{@code url_encode}/{@code url_decode}/
 * {@code md5}/{@code sha256}/{@code hex_encode}/{@code hex_decode} 七个注册函数。
 *
 * <p>类名取自 Go 源文件名 {@code protocol.go}（包级函数在 Java 中需归入某个类）。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/protocol/protocol.go}（包级导出函数 8 个）。
 */
public final class Protocol {

    /** 小写十六进制字母表，对应 Go {@code encoding/hex} 的 {@code EncodeToString}（小写）。 */
    private static final char[] LOWER_HEX = "0123456789abcdef".toCharArray();

    private Protocol() {
    }

    /** 对应 Go 的 {@code Base64Encode(s string) string}（标准编码、UTF-8 字节）。 */
    public static String base64Encode(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    /** 对应 Go 的 {@code Base64Decode(s string) string}：解码失败（非标准输入）返回原串。 */
    public static String base64Decode(String s) {
        try {
            return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // Go: b, err := base64.StdEncoding.DecodeString(s); if err != nil { return s }
            return s;
        }
    }

    /**
     * 对应 Go 的 {@code URLEncode(s string) string}（{@code url.QueryEscape}）：
     * 空格编码为 {@code '+'}，未保留字符（{@code A-Za-z0-9 -_.~}）原样输出，
     * 其余按 UTF-8 字节百分号编码（大写十六进制）。
     */
    public static String urlEncode(String s) {
        byte[] in = s.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(in.length);
        for (byte b : in) {
            int c = b & 0xff;
            if (isUnreserved(c)) {
                sb.append((char) c);
            } else if (c == ' ') {
                sb.append('+');
            } else {
                appendPct(sb, c);
            }
        }
        return sb.toString();
    }

    /**
     * 对应 Go 的 {@code URLDecode(s string) string}（{@code url.QueryUnescape} 且忽略错误）：
     * {@code '+'} 解为空格、{@code %XX} 按字节解码后以 UTF-8 还原；
     * 遇到非法转义时按 Go 行为停止解码、剩余字节原样输出。
     */
    public static String urlDecode(String s) {
        byte[] in = s.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream(in.length);
        int i = 0;
        while (i < in.length) {
            byte b = in[i];
            if (b == '+') {
                out.write(' ');
                i++;
            } else if (b == '%' && i + 2 < in.length && isHexDigit(in[i + 1]) && isHexDigit(in[i + 2])) {
                out.write((hexValue(in[i + 1]) << 4) | hexValue(in[i + 2]));
                i += 3;
            } else if (b == '%') {
                // Go: 非法转义 → 返回已解码部分 + 剩余原样（调用方忽略 error）
                out.write(in, i, in.length - i);
                break;
            } else {
                out.write(b);
                i++;
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    /** 对应 Go 的 {@code MD5Hash(s string) string}（小写十六进制摘要）。 */
    public static String md5Hash(String s) {
        return digestHex("MD5", s);
    }

    /** 对应 Go 的 {@code SHA256Hash(s string) string}（小写十六进制摘要）。 */
    public static String sha256Hash(String s) {
        return digestHex("SHA-256", s);
    }

    /** 对应 Go 的 {@code HexEncode(s string) string}（UTF-8 字节的小写十六进制）。 */
    public static String hexEncode(String s) {
        return HexFormat.of().formatHex(s.getBytes(StandardCharsets.UTF_8));
    }

    /** 对应 Go 的 {@code HexDecode(s string) string}：非法十六进制（含奇数长度）返回原串。 */
    public static String hexDecode(String s) {
        try {
            return new String(HexFormat.of().parseHex(s), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // Go: b, err := hex.DecodeString(s); if err != nil { return s }
            return s;
        }
    }

    /** {@code url.QueryEscape}/{@code QueryUnescape} 共用：未保留字符判定（Go shouldEscape 取反）。 */
    private static boolean isUnreserved(int c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || c == '-' || c == '_' || c == '.' || c == '~';
    }

    /** 写入 {@code %XX}（大写十六进制，同 Go {@code EscapeError} 用的十六进制表）。 */
    private static void appendPct(StringBuilder sb, int c) {
        sb.append('%');
        sb.append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xf, 16)));
        sb.append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
    }

    private static boolean isHexDigit(byte b) {
        return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F');
    }

    private static int hexValue(byte b) {
        if (b >= '0' && b <= '9') {
            return b - '0';
        }
        if (b >= 'a' && b <= 'f') {
            return b - 'a' + 10;
        }
        return b - 'A' + 10;
    }

    /** {@code md5}/{@code sha256} 共用：消息摘要后输出小写十六进制（同 Go hex.EncodeToString）。 */
    private static String digestHex(String algorithm, String s) {
        try {
            byte[] digest = MessageDigest.getInstance(algorithm).digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(LOWER_HEX[(b >> 4) & 0xf]).append(LOWER_HEX[b & 0xf]);
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // JLS 规定 MD5/SHA-256 必须提供，正常运行不会走到这里
            throw new IllegalStateException(algorithm + " 摘要算法不可用", e);
        }
    }
}

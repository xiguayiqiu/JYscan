package space.jyscan.core.util;

import java.security.SecureRandom;
import java.util.Random;

/**
 * 随机字符串生成，对应 internal/utils/random.go。
 */
public final class RandUtil {

    public static final String LETTER_BYTES =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private static final String DIGITS = "0123456789";
    private static final String HEX = "0123456789abcdef";

    private static final Random RAND = new Random();
    private static final SecureRandom SECURE = new SecureRandom();

    private RandUtil() {
    }

    /** 生成指定长度的随机字符串（字母+数字）。 */
    public static String generateRandomString(int n) {
        if (n <= 0) {
            return "";
        }
        return generateRandomStringWithCharset(n, LETTER_BYTES);
    }

    /** 使用指定字符集生成随机字符串。 */
    public static String generateRandomStringWithCharset(int n, String charset) {
        if (n <= 0 || charset == null || charset.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            sb.append(charset.charAt(RAND.nextInt(charset.length())));
        }
        return sb.toString();
    }

    /** 生成数字随机字符串。 */
    public static String generateRandomNumberString(int n) {
        return generateRandomStringWithCharset(n, DIGITS);
    }

    /** 生成十六进制随机字符串。 */
    public static String generateRandomHexString(int n) {
        return generateRandomStringWithCharset(n, HEX);
    }

    /** 生成密码学强度的随机字节（用于 token / 密钥）。 */
    public static byte[] secureBytes(int n) {
        byte[] b = new byte[n];
        SECURE.nextBytes(b);
        return b;
    }
}

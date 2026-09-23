package space.jyscan.modules.ssl;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 弱加密套件与弱签名算法判定，移植自 freeclient/internal/ssl/ssl.go 中的
 * weakCiphers / weakSignatureAlgs 映射表及 isWeakCipher / getWeakCipherReason /
 * isWeakSignatureAlg / getWeakSignatureAlgReason 函数。
 *
 * <p>Go 侧使用 map，遍历顺序随机；这里改用 LinkedHashMap 固定顺序，
 * 保证同一输入永远给出同一个"原因"文案（3DES 名称优先匹配 3DES 原因）。
 */
public final class Weakness {

    /** 弱密码套件关键字 → 原因（对应 Go 的 weakCiphers）。 */
    private static final Map<String, String> WEAK_CIPHERS = new LinkedHashMap<>();

    static {
        // 顺序：3DES 放在 DES 之前，保证 "TLS_..._3DES_..." 命中 3DES 的原因
        WEAK_CIPHERS.put("3DES", "使用过时的 3DES 算法");
        WEAK_CIPHERS.put("DES", "使用弱加密算法 DES (56位)");
        WEAK_CIPHERS.put("RC4", "使用不安全的 RC4 算法");
        WEAK_CIPHERS.put("NULL", "使用 NULL 加密");
        WEAK_CIPHERS.put("EXPORT", "使用弱 EXPORT 级别的加密");
        WEAK_CIPHERS.put("MD5", "使用弱哈希算法 MD5");
        WEAK_CIPHERS.put("SHA1", "使用弱哈希算法 SHA1");
        WEAK_CIPHERS.put("CBC", "CBC 模式易受某些攻击");
    }

    /** 弱签名算法关键字 → 原因（对应 Go 的 weakSignatureAlgs）。 */
    private static final Map<String, String> WEAK_SIGNATURE_ALGS = new LinkedHashMap<>();

    static {
        WEAK_SIGNATURE_ALGS.put("MD2", "使用弱签名算法 MD2");
        WEAK_SIGNATURE_ALGS.put("MD5", "使用弱签名算法 MD5");
        WEAK_SIGNATURE_ALGS.put("SHA1", "使用弱签名算法 SHA1");
        WEAK_SIGNATURE_ALGS.put("DSA-SHA", "使用 DSA 签名算法");
        WEAK_SIGNATURE_ALGS.put("ECDSAWithSHA1", "使用 ECDSA-SHA1 签名算法");
    }

    private Weakness() {
    }

    /** 密码套件名是否命中弱加密关键字（对应 Go 的 isWeakCipher）。 */
    public static boolean isWeakCipher(String cipherName) {
        if (cipherName == null) {
            return false;
        }
        for (String weak : WEAK_CIPHERS.keySet()) {
            if (cipherName.contains(weak)) {
                return true;
            }
        }
        return false;
    }

    /** 取弱密码套件的原因文案，未命中返回空串（对应 Go 的 getWeakCipherReason）。 */
    public static String getWeakCipherReason(String cipherName) {
        if (cipherName == null) {
            return "";
        }
        for (Map.Entry<String, String> e : WEAK_CIPHERS.entrySet()) {
            if (cipherName.contains(e.getKey())) {
                return e.getValue();
            }
        }
        return "";
    }

    /**
     * 签名算法是否偏弱（对应 Go 的 isWeakSignatureAlg）：
     * ECDSA 类只看是否含 SHA1，其余按关键字表判定。
     */
    public static boolean isWeakSignatureAlg(String algName) {
        if (algName == null) {
            return false;
        }
        if (algName.contains("ECDSA")) {
            return algName.contains("SHA1");
        }
        for (String weak : WEAK_SIGNATURE_ALGS.keySet()) {
            if (algName.contains(weak)) {
                return true;
            }
        }
        return false;
    }

    /** 取弱签名算法的原因文案，未命中返回空串（对应 Go 的 getWeakSignatureAlgReason）。 */
    public static String getWeakSignatureAlgReason(String algName) {
        if (algName == null) {
            return "";
        }
        if (algName.contains("ECDSA") && algName.contains("SHA1")) {
            return "使用 ECDSA-SHA1 签名算法";
        }
        for (Map.Entry<String, String> e : WEAK_SIGNATURE_ALGS.entrySet()) {
            if (algName.contains(e.getKey())) {
                return e.getValue();
            }
        }
        return "";
    }
}

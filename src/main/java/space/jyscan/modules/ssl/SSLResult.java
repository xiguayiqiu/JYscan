package space.jyscan.modules.ssl;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * SSL 检测结果及关联数据结构，移植自 freeclient/internal/ssl/ssl.go 中的
 * SSLResult / ProtocolSupport / CipherSuiteInfo / TLSFeatures /
 * CertificateChainInfo / CertDetails / CertSubject / CertIssuer。
 *
 * <p>字段与 Go 结构体一一对应。Go 中依赖 crypto/x509 内部类型且从不参与
 * 输出的字段（KeyUsage / ExtKeyUsage / CRLDistribution / OCSPServer /
 * IssuingCertURL 等）未移植。
 */
public class SSLResult {

    /** 目标主机（域名或IP地址）。 */
    public String target = "";

    /** 目标端口。 */
    public int port;

    /** 解析得到的 IP 地址（解析失败时为空串）。 */
    public String ipAddress = "";

    /** 是否成功建立 TLS 连接（对应 Go 的 IsSSL）。 */
    public boolean isSSL;

    /** 协商的 TLS 版本显示名，如 "TLS 1.2"。 */
    public String negotiatedTLSVersion = "";

    /** 各协议版本支持情况。 */
    public ProtocolSupport protocolSupport = new ProtocolSupport();

    /** 协商到的密码套件列表。 */
    public List<CipherSuiteInfo> cipherSuites = new ArrayList<>();

    /** TLS 特性检测结果。 */
    public TLSFeatures tlsFeatures = new TLSFeatures();

    /** 证书链信息。 */
    public CertificateChainInfo certificateChain = new CertificateChainInfo();

    /** 检测过程中的错误（对应 Go 的 error 字段）。 */
    public Exception error;

    // =====================================================================
    // 关联类型（与 Go 侧结构体同名）
    // =====================================================================

    /** 协议版本支持情况，对应 Go 的 ProtocolSupport。 */
    public static class ProtocolSupport {
        public boolean sslv2;
        public boolean sslv3;
        public boolean tlsv10;
        public boolean tlsv11;
        public boolean tlsv12;
        public boolean tlsv13;
    }

    /** 密码套件信息，对应 Go 的 CipherSuiteInfo。 */
    public static class CipherSuiteInfo {
        /** 所属协议版本（显示名）。 */
        public String protocol = "";
        /** 套件名称（JSSE/IANA 名称，与 Go 的 tls.CipherSuiteName 一致）。 */
        public String name = "";
        /** 密钥位数。 */
        public int bits;
        /** 是否为协商首选套件（Go 恒为 true）。 */
        public boolean preferred;
        /** 是否为弱加密套件。 */
        public boolean isWeak;
    }

    /** TLS 特性，对应 Go 的 TLSFeatures。 */
    public static class TLSFeatures {
        public boolean fallbackSCSV;
        public boolean secureRenegotiation;
        public boolean compression;
        public boolean heartbleed;
    }

    /** 证书链，对应 Go 的 CertificateChainInfo。 */
    public static class CertificateChainInfo {
        /** 链上证书列表（叶证书在前）。 */
        public List<CertDetails> certificates = new ArrayList<>();
    }

    /** 单张证书详情，对应 Go 的 CertDetails。 */
    public static class CertDetails {
        /** 主题（Subject）。 */
        public CertSubject subject = new CertSubject();
        /** 颁发者（Issuer）。 */
        public CertIssuer issuer = new CertIssuer();
        /** 生效时间。 */
        public Date notBefore;
        /** 过期时间。 */
        public Date notAfter;
        /** 当前是否在有效期内。 */
        public boolean valid;
        /** 是否已过期。 */
        public boolean isExpired;
        /** 是否自签名（主体 == 颁发者）。 */
        public boolean isSelfSigned;
        /** 签名算法（Go 风格名称，如 "SHA256-RSA"）。 */
        public String signatureAlg = "";
        /** 公钥算法（Go 风格名称，如 "RSA"/"ECDSA"）。 */
        public String publicKeyAlg = "";
        /** 公钥强度（RSA 模长 / EC 曲线位数）。 */
        public int keyStrength;
        /** 备用名称（SAN：先 DNS 名称，后 IP 地址，与 Go 顺序一致）。 */
        public List<String> altNames = new ArrayList<>();
        /** 序列号（十进制字符串，对应 Go 的 big.Int.String()）。 */
        public String serialNumber = "";
        /** 是否为 CA 证书。 */
        public boolean isCA;
    }

    /** 证书主题，对应 Go 的 CertSubject（仅移植会参与输出的字段）。 */
    public static class CertSubject {
        /** 通用名。 */
        public String commonName = "";
        /** 组织。 */
        public List<String> organization = new ArrayList<>();
        /** 组织单元。 */
        public List<String> organizationalUnit = new ArrayList<>();
        /** 地点。 */
        public List<String> locality = new ArrayList<>();
        /** 省/州。 */
        public List<String> province = new ArrayList<>();
        /** 国家。 */
        public List<String> country = new ArrayList<>();
    }

    /** 证书颁发者，对应 Go 的 CertIssuer（仅移植会参与输出的字段）。 */
    public static class CertIssuer {
        /** 通用名。 */
        public String commonName = "";
        /** 组织。 */
        public List<String> organization = new ArrayList<>();
        /** 组织单元。 */
        public List<String> organizationalUnit = new ArrayList<>();
        /** 地点。 */
        public List<String> locality = new ArrayList<>();
        /** 省/州。 */
        public List<String> province = new ArrayList<>();
        /** 国家。 */
        public List<String> country = new ArrayList<>();
    }
}

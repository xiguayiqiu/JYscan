package space.jyscan.modules.ssl;

import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.modules.ssl.SSLResult.CipherSuiteInfo;
import space.jyscan.modules.ssl.SSLResult.CertDetails;
import space.jyscan.modules.ssl.SSLResult.CertificateChainInfo;
import space.jyscan.modules.ssl.SSLResult.CertIssuer;
import space.jyscan.modules.ssl.SSLResult.CertSubject;
import space.jyscan.modules.ssl.SSLResult.ProtocolSupport;
import space.jyscan.modules.ssl.SSLResult.TLSFeatures;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * SSL/TLS 检测实现，移植自 freeclient/internal/ssl/ssl.go。
 *
 * <p>Java 没有 crypto/tls，这里改用 JSSE（{@code javax.net.ssl.SSLSocket}）：
 * <ul>
 *   <li>通过信任所有证书的 TrustManager + 关闭端点标识，等价 Go 的
 *       {@code InsecureSkipVerify: true}；</li>
 *   <li>通过 {@code setEnabledProtocols(new String[]{...})} 锁定单个协议版本，
 *       等价 Go 的 {@code MinVersion = MaxVersion = version}；</li>
 *   <li>连接/读超时统一取命令行的 {@code -T}（秒），保证整体超时收敛，
 *       任何异常都不会把 Java 堆栈抛给用户。</li>
 * </ul>
 *
 * <p>输出展示名与 Go 保持一致：JSSE 协议名 "TLSv1" 对应 Go 的 "TLSv1.0"，
 * JSSE/IANA 密码套件名与 {@code tls.CipherSuiteName} 基本一致。
 */
public final class SslScanner {

    /** 详细模式（对应 Go 的 verboseMode / SetVerbose）。 */
    private static volatile boolean verboseMode;

    /** 信任所有证书的 TrustManager，等价 Go 的 InsecureSkipVerify。 */
    private static final X509TrustManager TRUST_ALL = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // 不校验证书链（与 Go 的 InsecureSkipVerify 行为一致）
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // 不校验证书链（与 Go 的 InsecureSkipVerify 行为一致）
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };

    private static volatile SSLContext context;

    private SslScanner() {
    }

    // =====================================================================
    // 详细模式
    // =====================================================================

    /** SetVerbose 设置详细模式（对应 Go 的 ssl.SetVerbose）。 */
    public static void setVerbose(boolean v) {
        verboseMode = v;
    }

    /** 仅详细模式下打印（对应 Go 的 logVerbose → utils.LogInfo）。 */
    private static void logVerbose(String format, Object... args) {
        if (verboseMode) {
            Colors.logInfo(format, args);
        }
    }

    // =====================================================================
    // 全面检测（-a/--all，对应 Go 的 ScanAllSSL）
    // =====================================================================

    /**
     * 逐个协议版本强制建连，收集每个版本的协商结果。
     * 对应 Go 的 ScanAllSSL（仅探测 TLS 1.0 ~ 1.3；证书链只取第一个成功的结果）。
     *
     * @param target     目标主机
     * @param port       目标端口
     * @param timeoutSec 超时秒数（0 表示不限时，与 Go 的 net.Dialer 一致）
     */
    public static List<SSLResult> scanAllSSL(String target, int port, int timeoutSec) {
        List<SSLResult> results = new ArrayList<>();

        // 对应 Go 的 protocols 切片：{"TLSv1.0", VersionTLS10} ... {"TLSv1.3", VersionTLS13}
        // 第 0 列是 Go 风格显示名，第 1 列是 JSSE 协议名
        String[][] protocols = {
                {"TLSv1.0", "TLSv1"},
                {"TLSv1.1", "TLSv1.1"},
                {"TLSv1.2", "TLSv1.2"},
                {"TLSv1.3", "TLSv1.3"},
        };

        for (String[] proto : protocols) {
            String name = proto[0];
            String jsseProtocol = proto[1];

            SSLResult result = new SSLResult();
            result.target = target;
            result.port = port;

            // 与 Go 一致：每个协议都解析一次 IP，解析失败忽略
            try {
                InetAddress[] addrs = InetAddress.getAllByName(target);
                if (addrs.length > 0) {
                    result.ipAddress = addrs[0].getHostAddress();
                }
            } catch (Exception ignored) {
                // 与 Go 一致：net.LookupIP 出错时 IP 地址留空
            }

            try (SSLSocket conn = dialTLS(target, port, timeoutSec, jsseProtocol)) {
                result.isSSL = true;
                // Go 侧直接记录探测用的协议名（如 "TLSv1.0"），不取 ConnectionState.Version
                result.negotiatedTLSVersion = name;

                SSLSession session = conn.getSession();
                String cipherName = session.getCipherSuite();
                if (cipherName != null && !cipherName.isEmpty()) {
                    // 对应 Go 的 state.CipherSuite != 0 分支
                    CipherSuiteInfo cipherInfo = new CipherSuiteInfo();
                    cipherInfo.protocol = name;
                    cipherInfo.name = cipherName;
                    cipherInfo.bits = getCipherSuiteBits(cipherName);
                    cipherInfo.preferred = true;
                    cipherInfo.isWeak = Weakness.isWeakCipher(cipherName);
                    result.cipherSuites.add(cipherInfo);
                }

                // 与 Go 一致：只有第一个成功的结果才提取证书链（len(results) == 0）
                if (results.isEmpty()) {
                    Certificate[] certs = peerCertificates(session);
                    if (certs.length > 0) {
                        result.certificateChain = extractCertificateChain(certs);
                    }
                }

                results.add(result);
            } catch (Exception e) {
                // 对应 Go 的 err != nil → continue：该协议不受支持或连接失败
            }
        }

        return results;
    }

    // =====================================================================
    // 默认检测（对应 Go 的 ScanSSL）
    // =====================================================================

    /**
     * 单次完整 SSL 检测：解析域名 → 协议版本探测 → 建立 TLS 连接 →
     * 提取密码套件与证书链 → TLS 特性。
     * 对应 Go 的 ScanSSL。永远不会抛异常，错误记录在 {@link SSLResult#error}。
     *
     * @param target     目标主机
     * @param port       目标端口
     * @param timeoutSec 超时秒数（0 表示不限时）
     */
    public static SSLResult scanSSL(String target, int port, int timeoutSec) {
        SSLResult result = new SSLResult();
        result.target = target;
        result.port = port;

        // 解析域名（对应 logVerbose("正在解析域名...")）
        logVerbose("正在解析域名...");
        try {
            InetAddress[] addrs = InetAddress.getAllByName(target);
            if (addrs.length > 0) {
                result.ipAddress = addrs[0].getHostAddress();
                logVerbose("  解析结果: %s", result.ipAddress);
            }
        } catch (Exception e) {
            // 与 Go 一致：解析失败不记错误，继续后续检测
        }

        // 协议版本支持检测
        result.protocolSupport = detectProtocolSupport(target, port, timeoutSec);

        // 建立 TLS 连接
        logVerbose("正在建立 TLS 连接...");
        SSLSocket conn;
        try {
            conn = dialTLS(target, port, timeoutSec, null);
        } catch (Exception e) {
            logVerbose("  TLS 连接失败: %v", e);
            result.error = e instanceof IOException ? e : dialError(target, port, e);
            return result;
        }

        try {
            logVerbose("  TLS 连接已建立");
            SSLSession session = conn.getSession();

            result.isSSL = true;
            result.negotiatedTLSVersion = getTLSVersion(session.getProtocol());
            logVerbose("  协商的 TLS 版本: %s", result.negotiatedTLSVersion);

            String cipherName = session.getCipherSuite();
            if (cipherName != null && !cipherName.isEmpty()) {
                // 对应 Go 的 if state.CipherSuite != 0 分支
                CipherSuiteInfo cipherInfo = new CipherSuiteInfo();
                cipherInfo.protocol = result.negotiatedTLSVersion;
                cipherInfo.name = cipherName;
                cipherInfo.bits = getCipherSuiteBits(cipherName);
                cipherInfo.preferred = true;
                cipherInfo.isWeak = Weakness.isWeakCipher(cipherName);
                result.cipherSuites.add(cipherInfo);
                logVerbose("  协商的密码套件: %s (%d位)", cipherName, cipherInfo.bits);
                if (cipherInfo.isWeak) {
                    logVerbose("  警告: 密码套件 %s 是弱加密", cipherName);
                }
            }

            Certificate[] chain = peerCertificates(session);
            if (chain.length > 0) {
                logVerbose("正在提取证书链...");
                result.certificateChain = extractCertificateChain(chain);
                logVerbose("  成功提取 %d 个证书", result.certificateChain.certificates.size());
                List<CertDetails> details = result.certificateChain.certificates;
                for (int i = 0; i < details.size(); i++) {
                    CertDetails cert = details.get(i);
                    logVerbose("  证书 #%d: CN=%s, 颁发者=%s",
                            i + 1, cert.subject.commonName, cert.issuer.commonName);
                }
            } else {
                logVerbose("  警告: 未获取到证书");
            }

            result.tlsFeatures = detectTLSFeatures();
            logVerbose("检测完成");
        } catch (Exception e) {
            // 提取阶段的意外异常不影响主体结果，也绝不把堆栈抛给用户
            logVerbose("  检测过程异常: %v", e);
        } finally {
            closeQuietly(conn);
        }

        return result;
    }

    // =====================================================================
    // 协议版本支持检测（对应 Go 的 detectProtocolSupport / testProtocolVersion）
    // =====================================================================

    private static ProtocolSupport detectProtocolSupport(String target, int port, int timeoutSec) {
        ProtocolSupport support = new ProtocolSupport();

        logVerbose("正在检测协议版本支持...");

        // 与 Go 源码一致：SSL 2.0 检测实际复用 SSL 3.0 探测（Go 侧传的是 tls.VersionSSL30）
        support.sslv2 = testProtocolVersion(target, port, timeoutSec, "SSLv3");
        logVerbose("  SSL 2.0: %s", getStatus(support.sslv2));

        support.sslv3 = testProtocolVersion(target, port, timeoutSec, "SSLv3");
        logVerbose("  SSL 3.0: %s", getStatus(support.sslv3));

        support.tlsv10 = testProtocolVersion(target, port, timeoutSec, "TLSv1");
        logVerbose("  TLS 1.0: %s", getStatus(support.tlsv10));

        support.tlsv11 = testProtocolVersion(target, port, timeoutSec, "TLSv1.1");
        logVerbose("  TLS 1.1: %s", getStatus(support.tlsv11));

        support.tlsv12 = testProtocolVersion(target, port, timeoutSec, "TLSv1.2");
        logVerbose("  TLS 1.2: %s", getStatus(support.tlsv12));

        support.tlsv13 = testProtocolVersion(target, port, timeoutSec, "TLSv1.3");
        logVerbose("  TLS 1.3: %s", getStatus(support.tlsv13));

        return support;
    }

    /** 用指定协议版本尝试握手，成功返回 true（对应 Go 的 testProtocolVersion）。 */
    private static boolean testProtocolVersion(String target, int port, int timeoutSec,
                                               String jsseProtocol) {
        try (SSLSocket conn = dialTLS(target, port, timeoutSec, jsseProtocol)) {
            return conn != null;
        } catch (Exception e) {
            // 握手失败、协议被 JVM 安全策略禁用或网络不通，都视为不支持
            return false;
        }
    }

    /** verbose 下的协议状态文案（对应 Go 的 getStatus）。 */
    private static String getStatus(boolean supported) {
        if (supported) {
            return "已启用";
        }
        return "已禁用";
    }

    // =====================================================================
    // TLS 连接（JSSE 版的 tls.DialWithDialer）
    // =====================================================================

    /**
     * 建立 TLS 连接：TCP 连接超时 + 读超时都取 timeoutSec，握手受 soTimeout 约束。
     *
     * @param jsseProtocol 锁定的 JSSE 协议名（如 "TLSv1.2"），null 表示使用 JVM 默认协议集
     * @return 调用方负责关闭的已握手 SSLSocket
     * @throws IOException 连接或握手失败，消息已包装成 Go 风格的 "dial tcp host:port: ..."
     */
    private static SSLSocket dialTLS(String target, int port, int timeoutSec,
                                     String jsseProtocol) throws IOException {
        int timeoutMs = timeoutMs(timeoutSec);
        SSLContext ctx = sslContext(); // 初始化失败直接抛出，不带 dial 前缀

        Socket plain = new Socket();
        SSLSocket tls = null;
        boolean ok = false;
        try {
            plain.connect(new InetSocketAddress(target, port), timeoutMs);
            plain.setSoTimeout(timeoutMs);
            // 第二个参数 target 作为 peerHost：既用于 SNI，也与 Go 的 ServerName 对应
            tls = (SSLSocket) ctx.getSocketFactory().createSocket(plain, target, port, true);
            tls.setUseClientMode(true);
            if (jsseProtocol != null) {
                // 只启用指定协议，等价 Go 的 MinVersion = MaxVersion = version
                tls.setEnabledProtocols(new String[]{jsseProtocol});
            }
            SSLParameters params = tls.getSSLParameters();
            if (params.getEndpointIdentificationAlgorithm() != null) {
                // 关闭端点标识（主机名校验），配合 TRUST_ALL 等价 InsecureSkipVerify
                params.setEndpointIdentificationAlgorithm(null);
                tls.setSSLParameters(params);
            }
            tls.startHandshake();
            ok = true;
            return tls;
        } catch (IOException e) {
            // 对应 Go 的 net.OpError："dial tcp host:port: <原因>"
            throw new IOException(Fmt.format("dial tcp %s:%d: %s", target, port, errMessage(e)), e);
        } finally {
            if (!ok) {
                if (tls != null) {
                    // autoClose=true，关闭 TLS 套接字会连带关闭底层 socket
                    closeQuietly(tls);
                } else {
                    closeQuietly(plain);
                }
            }
        }
    }

    /** 超时秒数 → 毫秒；0 表示不限时（与 Go 的 net.Dialer{Timeout:0} 一致）。 */
    private static int timeoutMs(int timeoutSec) {
        if (timeoutSec == 0) {
            return 0;
        }
        if (timeoutSec < 0) {
            return -1; // 负值：JSSE 会立即抛参数异常，走优雅失败路径
        }
        return (int) Math.min(Integer.MAX_VALUE, (long) timeoutSec * 1000L);
    }

    /** 包装连接错误，消息风格对齐 Go 的 "dial tcp host:port: ..."。 */
    private static IOException dialError(String target, int port, Exception e) {
        if (e instanceof IOException io) {
            return io;
        }
        return new IOException(Fmt.format("dial tcp %s:%d: %s", target, port, errMessage(e)), e);
    }

    /** 取异常的可读消息（避免 %v 输出 null）。 */
    private static String errMessage(Throwable t) {
        if (t == null) {
            return "";
        }
        return t.getMessage() != null ? t.getMessage() : t.toString();
    }

    private static void closeQuietly(AutoCloseable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignored) {
                // 关闭失败忽略，绝不向用户抛出
            }
        }
    }

    /** 懒加载并缓存信任所有证书的 SSLContext。 */
    private static SSLContext sslContext() throws IOException {
        SSLContext ctx = context;
        if (ctx == null) {
            synchronized (SslScanner.class) {
                ctx = context;
                if (ctx == null) {
                    try {
                        SSLContext c = SSLContext.getInstance("TLS");
                        c.init(null, new TrustManager[]{TRUST_ALL}, new SecureRandom());
                        context = c;
                        ctx = c;
                    } catch (GeneralSecurityException e) {
                        throw new IOException("SSL上下文初始化失败: " + errMessage(e), e);
                    }
                }
            }
        }
        return ctx;
    }

    // =====================================================================
    // 证书链提取（对应 Go 的 extractCertificateChain 及其辅助函数）
    // =====================================================================

    /** 取对端证书链；未校验对端（无证书）时返回空数组。 */
    private static Certificate[] peerCertificates(SSLSession session) {
        try {
            Certificate[] certs = session.getPeerCertificates();
            return certs == null ? new Certificate[0] : certs;
        } catch (SSLPeerUnverifiedException e) {
            return new Certificate[0];
        }
    }

    /** 从 JSSE 会话的证书链提取结构化信息（对应 Go 的 extractCertificateChain）。 */
    static CertificateChainInfo extractCertificateChain(Certificate[] certs) {
        CertificateChainInfo chainInfo = new CertificateChainInfo();
        if (certs == null) {
            return chainInfo;
        }
        for (Certificate c : certs) {
            if (!(c instanceof X509Certificate cert)) {
                continue; // Go 侧全部是 *x509.Certificate
            }
            CertDetails details = new CertDetails();
            details.subject = parseSubject(cert.getSubjectX500Principal());
            details.issuer = parseIssuer(cert.getIssuerX500Principal());
            details.notBefore = cert.getNotBefore();
            details.notAfter = cert.getNotAfter();
            Date now = new Date();
            // 对应 Go：time.Now().Before(NotAfter) && time.Now().After(NotBefore)
            details.valid = now.before(cert.getNotAfter()) && now.after(cert.getNotBefore());
            details.isExpired = now.after(cert.getNotAfter());
            details.isSelfSigned = isSelfSigned(cert);
            details.signatureAlg = goSignatureAlgName(cert.getSigAlgName());
            details.publicKeyAlg = goPublicKeyAlgName(cert);
            details.keyStrength = getKeyStrength(cert);
            details.altNames = getAltNames(cert);
            details.serialNumber = cert.getSerialNumber().toString();
            details.isCA = cert.getBasicConstraints() >= 0;
            chainInfo.certificates.add(details);
        }
        return chainInfo;
    }

    /** 自签名判定：主体与颁发者的名称字符串一致（对应 Go 的 isSelfSigned）。 */
    private static boolean isSelfSigned(X509Certificate cert) {
        return cert.getSubjectX500Principal().getName()
                .equals(cert.getIssuerX500Principal().getName());
    }

    /**
     * 公钥强度（对应 Go 的 getKeyStrength）：EC 取曲线位数，RSA 取模长，其余为 0。
     */
    private static int getKeyStrength(X509Certificate cert) {
        PublicKey pub = cert.getPublicKey();
        if (pub instanceof ECPublicKey ec) {
            return ec.getParams().getCurve().getField().getFieldSize();
        }
        if (pub instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        }
        return 0;
    }

    /**
     * 备用名称（对应 Go 的 getAltNames）：先列 DNS 名称，再列 IP 地址，
     * 与 Go 遍历 cert.DNSNames、再遍历 cert.IPAddresses 的顺序一致。
     */
    private static List<String> getAltNames(X509Certificate cert) {
        List<String> altNames = new ArrayList<>();
        Collection<List<?>> sans;
        try {
            sans = cert.getSubjectAlternativeNames();
        } catch (CertificateException e) {
            return altNames; // 无 SAN 扩展或解析失败，留空
        }
        if (sans == null) {
            return altNames;
        }
        List<String> dnsNames = new ArrayList<>();
        List<String> ipAddrs = new ArrayList<>();
        for (List<?> san : sans) {
            if (san == null || san.size() < 2 || !(san.get(0) instanceof Integer type)) {
                continue;
            }
            if (type == 2 && san.get(1) instanceof String dnsName) {
                dnsNames.add(dnsName);
            } else if (type == 7 && san.get(1) instanceof byte[] ip) {
                try {
                    // 只做字节数组 → 文本转换，不做任何 DNS 解析
                    ipAddrs.add(InetAddress.getByAddress(ip).getHostAddress());
                } catch (UnknownHostException ignored) {
                    // 不会发生：getByAddress 不触发解析
                }
            }
        }
        altNames.addAll(dnsNames);
        altNames.addAll(ipAddrs);
        return altNames;
    }

    /**
     * 把 JSSE 的签名算法名转成 Go x509 的显示风格：
     * "SHA256withRSA" → "SHA256-RSA"，"SHA1withECDSA" → "ECDSA-SHA1"，
     * "Ed25519" → "PureEd25519"，其余原样返回。
     * 这样弱签名检测的关键字表与 Go 完全一致。
     */
    private static String goSignatureAlgName(String javaName) {
        if (javaName == null || javaName.isEmpty()) {
            return "";
        }
        int i = javaName.indexOf("with");
        if (i > 0) {
            String hash = javaName.substring(0, i);
            String alg = javaName.substring(i + "with".length());
            if ("ECDSA".equals(alg) || "DSA".equals(alg)) {
                return alg + "-" + hash; // Go: ECDSA-SHA256 / DSA-SHA1
            }
            return hash + "-" + alg;     // Go: SHA256-RSA
        }
        if ("Ed25519".equals(javaName)) {
            return "PureEd25519";        // Go: crypto.PureEd25519
        }
        if ("Ed448".equals(javaName)) {
            return "PureEd448";
        }
        return javaName;
    }

    /** 公钥算法的 Go 风格名称（对应 Go 的 x509.PublicKeyAlgorithm.String()）。 */
    private static String goPublicKeyAlgName(X509Certificate cert) {
        String alg = cert.getPublicKey().getAlgorithm();
        if (alg == null) {
            return "";
        }
        if ("EC".equals(alg)) {
            return "ECDSA";
        }
        if ("RSASSA-PSS".equals(alg)) {
            return "RSA-PSS";
        }
        if ("EdDSA".equals(alg)) {
            return "Ed25519";
        }
        return alg; // RSA / DSA / Ed25519 ...
    }

    // =====================================================================
    // 名称解析（Subject / Issuer）
    // =====================================================================

    private static CertSubject parseSubject(X500Principal principal) {
        Map<String, List<String>> m = parseX500(principal);
        CertSubject s = new CertSubject();
        s.commonName = firstOf(m, "CN");
        s.organization = orEmpty(m.get("O"));
        s.organizationalUnit = orEmpty(m.get("OU"));
        s.locality = orEmpty(m.get("L"));
        s.province = orEmpty(m.get("ST"));
        s.country = orEmpty(m.get("C"));
        return s;
    }

    private static CertIssuer parseIssuer(X500Principal principal) {
        Map<String, List<String>> m = parseX500(principal);
        CertIssuer s = new CertIssuer();
        s.commonName = firstOf(m, "CN");
        s.organization = orEmpty(m.get("O"));
        s.organizationalUnit = orEmpty(m.get("OU"));
        s.locality = orEmpty(m.get("L"));
        s.province = orEmpty(m.get("ST"));
        s.country = orEmpty(m.get("C"));
        return s;
    }

    /** 用 LdapName 解析 X.500 名称，按 RFC2253 属性类型归组（只保留会输出的类型）。 */
    private static Map<String, List<String>> parseX500(X500Principal principal) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        try {
            LdapName ldap = new LdapName(principal.getName());
            for (Rdn rdn : ldap.getRdns()) {
                String type = rdn.getType() == null ? "" : rdn.getType().toUpperCase(Locale.ROOT);
                String key = switch (type) {
                    case "CN" -> "CN";
                    case "O" -> "O";
                    case "OU" -> "OU";
                    case "L" -> "L";
                    case "ST", "S" -> "ST";
                    case "C" -> "C";
                    default -> null; // STREET/POSTALCODE/serialNumber 等不参与输出
                };
                if (key != null) {
                    out.computeIfAbsent(key, k -> new ArrayList<>())
                            .add(String.valueOf(rdn.getValue()));
                }
            }
        } catch (InvalidNameException e) {
            // 解析失败时保持零值，与 Go 的 pkix.Name 空字段一致
        }
        return out;
    }

    private static String firstOf(Map<String, List<String>> m, String key) {
        List<String> v = m.get(key);
        return v == null || v.isEmpty() ? "" : v.get(0); // 对应 Go 的 pkix.Name 单值字段
    }

    private static List<String> orEmpty(List<String> v) {
        return v == null ? new ArrayList<>() : v;
    }

    // =====================================================================
    // 版本 / 套件 / 特性辅助（对应 Go 的同名函数）
    // =====================================================================

    /** JSSE 协议名 → Go 风格显示名（对应 Go 的 getTLSVersion）。 */
    private static String getTLSVersion(String protocol) {
        if (protocol == null) {
            return "Unknown";
        }
        return switch (protocol) {
            case "SSLv3" -> "SSL 3.0";
            case "TLSv1" -> "TLS 1.0";
            case "TLSv1.1" -> "TLS 1.1";
            case "TLSv1.2" -> "TLS 1.2";
            case "TLSv1.3" -> "TLS 1.3";
            // JSSE 不暴露底层 uint16 版本号，无法给出 Go 的 "Unknown (0x%x)"
            default -> "Unknown";
        };
    }

    /** 从套件名推断密钥位数（对应 Go 的 getCipherSuiteBits，判断顺序一致）。 */
    static int getCipherSuiteBits(String cipherName) {
        if (cipherName == null) {
            return 0;
        }
        if (cipherName.contains("AES128") || cipherName.contains("CHACHA20")) {
            return 128;
        }
        if (cipherName.contains("AES256")) {
            return 256;
        }
        if (cipherName.contains("3DES")) {
            return 112;
        }
        if (cipherName.contains("TLS_AES_128_GCM")) {
            return 128;
        }
        if (cipherName.contains("TLS_AES_256_GCM")) {
            return 256;
        }
        if (cipherName.contains("TLS_CHACHA20_POLY1305")) {
            return 256;
        }
        return 0;
    }

    /**
     * TLS 特性检测（对应 Go 的 detectTLSFeatures）。
     * Go 版本不进行真实探测，直接返回固定值，这里保持一致。
     */
    static TLSFeatures detectTLSFeatures() {
        TLSFeatures features = new TLSFeatures();
        features.fallbackSCSV = true;
        features.secureRenegotiation = true;
        features.compression = false;
        features.heartbleed = false;
        return features;
    }
}

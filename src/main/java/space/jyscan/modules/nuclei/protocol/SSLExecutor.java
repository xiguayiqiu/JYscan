package space.jyscan.modules.nuclei.protocol;

import space.jyscan.modules.nuclei.model.SSLRequest;
import space.jyscan.modules.nuclei.variable.Engine;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

/**
 * SSL/TLS 协议执行器，对应 Go 的 {@code protocol.SSLExecutor}。
 *
 * <p>跨包契约：runner 持有字段 {@code sslExec} 并调用
 * {@link #execute(SSLRequest, String, Map)}。
 *
 * <p>Go 侧 {@code NewSSLExecutor()} 构造 {@code variable.NewEngine()} 作为 {@code varEngine}
 * （照抄该字段；{@code Execute} 未用到，与 Go 一致）。
 * 文件内另有包级 {@code tlsVersionString(v uint16) string} 助手（包内使用）。
 *
 * <p>Java 侧技术映射：
 * <ul>
 *   <li>Go {@code net.Dialer{Timeout: 10s} + tls.DialWithDialer(..., InsecureSkipVerify: true)} →
 *       {@code Socket.connect(..., 10s)} 后套 {@link SSLSocket} 握手，证书校验用 {@link TrustAll}；</li>
 *   <li>Go {@code conn.ConnectionState().PeerCertificates[0]} → {@code SSLSession.getPeerCertificates()[0]}；</li>
 *   <li>Go {@code tlsVersionString(Version)} → 按协商到的协议名（{@code SSLSession.getProtocol()}）映射。</li>
 * </ul>
 *
 * <p>注：JVM 的 {@code jdk.tls.disabledAlgorithms} 会禁用 TLS1.0/1.1/SSLv3，
 * 这是本项目 {@code ssl} 命令已记录的既有偏差，本执行器同样受限
 * （照常移植，探测老协议时 {@code startHandshake} 会失败并作为 {@code Error} 返回）。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/protocol/protocol.go}。
 */
public class SSLExecutor {

    /** 对应 Go {@code notAfter.Format(time.RFC3339)}（秒精度、UTC 时区 {@code Z}）。 */
    private static final DateTimeFormatter RFC3339 =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssXXX");

    /** 对应 Go 无证书时 {@code time.Time} 零值的 RFC3339 形式。 */
    private static final String ZERO_TIME = "0001-01-01T00:00:00Z";

    /** 对应 Go 的 {@code NewSSLExecutor() *SSLExecutor}。 */
    public SSLExecutor() {
        this.varEngine = new Engine();
    }

    private final Engine varEngine;

    /**
     * 执行一次 TLS 握手并采集信息。
     *
     * <p>对应 Go 的 {@code (e *SSLExecutor) Execute(req *model.SSLRequest, target string, vars map[string]interface{}) *ProtocolResult}。
     * 错误按 Go 的方式放在 {@link ProtocolResult#error} 字段内。
     */
    public ProtocolResult execute(SSLRequest req, String target, Map<String, Object> vars) {
        long start = System.nanoTime();

        String host = target;
        String port = "443"; // Go: port := "443"
        int first = host.indexOf(':');
        if (first >= 0) {
            // Go: strings.Split(host, ":") → host = parts[0]; port = parts[1]
            //（逐字照抄：parts[1] 是第 1、2 个冒号之间的部分）
            int second = host.indexOf(':', first + 1);
            port = second < 0 ? host.substring(first + 1) : host.substring(first + 1, second);
            host = host.substring(0, first);
        }

        int portNum;
        try {
            portNum = Integer.parseInt(port);
        } catch (NumberFormatException e) {
            // Go: tls.Dial 对非法端口返回 err
            return ProtocolResult.failure("ssl", e, start);
        }

        try {
            SSLContext ctx = TrustAll.context(); // Go: &tls.Config{InsecureSkipVerify: true}
            try (Socket plain = new Socket()) {
                plain.connect(new InetSocketAddress(host, portNum), 10_000); // Go: Dialer{Timeout: 10s}
                plain.setSoTimeout(10_000); // 握手读超时，等价 Dialer.Timeout 覆盖握手
                try (SSLSocket tls = (SSLSocket) ctx.getSocketFactory()
                        .createSocket(plain, host, portNum, true)) {
                    tls.startHandshake(); // Go: tls.DialWithDialer 完成握手
                    return collect(tls, host, port, start);
                }
            }
        } catch (Exception e) {
            return ProtocolResult.failure("ssl", e, start);
        }
    }

    /** 握手成功后采集证书信息并构造结果，对应 Go Execute 的后半段。 */
    private static ProtocolResult collect(SSLSocket tls, String host, String port, long start) {
        String cn = "";
        String issuer = "";
        String notAfter = ZERO_TIME;
        List<String> dnsNames = new ArrayList<>();

        X509Certificate cert = null;
        try {
            var chain = tls.getSession().getPeerCertificates();
            // Go: for _, c := range certs { ...; break } —— 只取首张（叶子）证书
            if (chain.length > 0 && chain[0] instanceof X509Certificate first) {
                cert = first;
            }
        } catch (SSLPeerUnverifiedException e) {
            // Go 侧证书链为空时字段保持零值
        }
        if (cert != null) {
            cn = commonName(cert.getSubjectX500Principal());
            dnsNames = dnsNames(cert);
            issuer = commonName(cert.getIssuerX500Principal());
            notAfter = RFC3339.format(cert.getNotAfter().toInstant().atOffset(ZoneOffset.UTC));
        }

        // Go: fmt.Sprintf("CN=%s SAN=%v Issuer=%s NotAfter=%s", ..., dnsNames, ...)
        // %v 对 []string 输出 [a b c]（空为 []）
        String raw = String.format("CN=%s SAN=[%s] Issuer=%s NotAfter=%s",
                cn, String.join(" ", dnsNames), issuer, notAfter);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("host", host);
        data.put("matched", host);
        data.put("port", port);
        data.put("cn", cn);
        data.put("subject", cn);
        data.put("issuer", issuer);
        data.put("san", dnsNames);
        data.put("dns_names", dnsNames);
        data.put("raw", raw);
        data.put("body", raw);
        data.put("all", raw);
        data.put("tls_version", tlsVersionString(tls.getSession().getProtocol()));
        data.put("not_after", notAfter);
        return ProtocolResult.success("ssl", data, raw, start);
    }

    /**
     * 对应 Go 的 {@code tlsVersionString(v uint16) string}；
     * Java 侧入参改为协商到的协议名（{@code SSLSession.getProtocol()}）。
     * Go 未列 SSLv3，同样落 {@code unknown}。
     */
    static String tlsVersionString(String protocol) {
        switch (protocol) {
            case "TLSv1":
                return "tls10";
            case "TLSv1.1":
                return "tls11";
            case "TLSv1.2":
                return "tls12";
            case "TLSv1.3":
                return "tls13";
            default:
                return "unknown";
        }
    }

    /** 对应 Go {@code c.DNSNames}（仅 DNS SAN；无扩展返回空列表，{@code %v} 输出 {@code []}）。 */
    private static List<String> dnsNames(X509Certificate cert) {
        List<String> out = new ArrayList<>();
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    // GeneralName 类型 2 = dNSName
                    if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0)) && san.get(1) instanceof String s) {
                        out.add(s);
                    }
                }
            }
        } catch (CertificateParsingException e) {
            // Go: 解析失败时 DNSNames 为空
        }
        return out;
    }

    /**
     * 对应 Go {@code pkix.Name.CommonName}：从 DN 中取 {@code CN} 属性值
     * （按未转义逗号切分属性、支持 RFC2253 转义；多个 CN 取最后一个，与 Go 赋值语义一致）。
     */
    private static String commonName(X500Principal principal) {
        if (principal == null) {
            return "";
        }
        String dn = principal.getName(X500Principal.RFC2253);
        String cn = "";
        StringBuilder part = new StringBuilder();
        boolean escaped = false;
        for (int i = 0; i <= dn.length(); i++) {
            char c = i < dn.length() ? dn.charAt(i) : ',';
            if (escaped) {
                part.append(c);
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == ',') {
                String attribute = part.toString();
                if (attribute.startsWith("CN=")) {
                    cn = attribute.substring(3);
                }
                part.setLength(0);
            } else {
                part.append(c);
            }
        }
        return cn;
    }
}

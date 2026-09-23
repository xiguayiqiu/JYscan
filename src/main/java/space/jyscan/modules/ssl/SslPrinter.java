package space.jyscan.modules.ssl;

import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.modules.ssl.SSLResult.CertDetails;
import space.jyscan.modules.ssl.SSLResult.CertIssuer;
import space.jyscan.modules.ssl.SSLResult.CertSubject;
import space.jyscan.modules.ssl.SSLResult.CipherSuiteInfo;
import space.jyscan.modules.ssl.SSLResult.ProtocolSupport;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;

/**
 * SSL 检测结果输出，移植自 freeclient/internal/ssl/ssl.go 的
 * PrintResults / PrintFullResults / printEnhancedSSLResult 及各 print* 函数。
 *
 * <p>颜色映射（Go 的 fatih/color → Colors）：
 * <ul>
 *   <li>cyanBold = Bold + FgHiCyan → {@code Colors.wrap(s, BOLD, FG_HI_CYAN)}；</li>
 *   <li>white = FgWhite → {@code Colors.wrap(s, FG_WHITE)}；</li>
 *   <li>yellow / green / red → FG_YELLOW / FG_GREEN / FG_RED。</li>
 * </ul>
 * 输出不经静默开关过滤（与 Go 直接调用 fatih/color 的行为一致），
 * 是否着色仍受全局 {@link Colors#useColor}（--no-color）控制。
 */
public final class SslPrinter {

    /** 对应 Go 的 time.Time.Format("2006-01-02 15:04:05")。 */
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private SslPrinter() {
    }

    // =====================================================================
    // 对外入口（对应 Go 的 PrintResults / PrintFullResults）
    // =====================================================================

    /**
     * 打印单次检测结果（对应 Go 的 PrintResults）。
     *
     * @return 成功打印返回 true；检测失败（已打印错误信息）返回 false
     */
    public static boolean printResults(SSLResult result) {
        if (result == null) {
            Colors.errorPrint("SSL检测失败: %v", (Object) null); // %v → <nil>
            return false;
        }
        if (result.error != null) {
            Colors.errorPrint("SSL检测失败: %v", result.error);
            return false;
        }
        printEnhancedSSLResult(result);
        return true;
    }

    /**
     * 打印全面检测结果（对应 Go 的 PrintFullResults，只展示 results[0]）。
     *
     * @return 成功打印返回 true；没有任何结果（已打印错误信息）返回 false
     */
    public static boolean printFullResults(List<SSLResult> results) {
        if (results == null || results.isEmpty()) {
            Colors.errorPrint("未检测到任何SSL配置");
            return false;
        }
        printEnhancedSSLResult(results.get(0));
        return true;
    }

    // =====================================================================
    // 报告主体（对应 Go 的 printEnhancedSSLResult）
    // =====================================================================

    private static void printEnhancedSSLResult(SSLResult result) {
        blank();
        cyanBold("========================================");
        cyanBold("SSL/TLS 安全检测报告");
        cyanBold("========================================");
        blank();

        white("目标: %s:%d", result.target, result.port);
        if (result.ipAddress != null && !result.ipAddress.isEmpty()) {
            white("IP地址: %s", result.ipAddress);
        }
        white("协商版本: %s", result.negotiatedTLSVersion);
        blank();

        printProtocolSupport(result.protocolSupport);
        blank();

        printCipherSuites(result.cipherSuites);
        blank();

        printCertificateChain(result.certificateChain);
        blank();

        printSecurityRecommendations(result);
        blank();
    }

    /** 协议版本支持列表（对应 Go 的 printProtocolSupport）。 */
    private static void printProtocolSupport(ProtocolSupport support) {
        cyanBold("协议版本支持:");

        // 与 Go 一致：{name, supported, isSecure}
        String[] names = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"};
        boolean[] supported = {
                support.sslv2, support.sslv3, support.tlsv10,
                support.tlsv11, support.tlsv12, support.tlsv13
        };
        boolean[] secure = {false, false, false, false, true, true};

        for (int i = 0; i < names.length; i++) {
            if (supported[i]) {
                if (secure[i]) {
                    green("  [+] %s", names[i]);
                } else {
                    red("  [-] %s (不安全！)", names[i]);
                }
            } else {
                yellow("  - %s", names[i]);
            }
        }
    }

    /** 密码套件列表（对应 Go 的 printCipherSuites）。 */
    private static void printCipherSuites(List<CipherSuiteInfo> ciphers) {
        cyanBold("密码套件:");

        if (ciphers == null || ciphers.isEmpty()) {
            yellow("  (未检测到密码套件)");
            return;
        }

        for (CipherSuiteInfo cipher : ciphers) {
            if (cipher.isWeak) {
                String reason = Weakness.getWeakCipherReason(cipher.name);
                red("  [-] %s (%d位) - %s", cipher.name, cipher.bits, reason);
            } else {
                green("  [+] %s (%d位)", cipher.name, cipher.bits);
            }
        }
    }

    /** 证书链（对应 Go 的 printCertificateChain）。 */
    private static void printCertificateChain(SSLResult.CertificateChainInfo chain) {
        if (chain == null || chain.certificates.isEmpty()) {
            cyanBold("证书链:");
            yellow("  (未获取到证书)");
            return;
        }

        cyanBold("证书链 (共 %d 个证书):", chain.certificates.size());
        blank();

        List<CertDetails> certs = chain.certificates;
        for (int i = 0; i < certs.size(); i++) {
            CertDetails cert = certs.get(i);
            cyanBold("  证书 #%d (%s):", i + 1, getCertType(cert));
            blank();

            printCertSubject(cert.subject);
            printCertIssuer(cert.issuer);

            white("    序列号: %s", cert.serialNumber);
            // 与 Go 的两次 Printf + Println 一致：弱签名原因单独着色接在同一行
            whitePrint("    签名算法: %s", cert.signatureAlg);
            if (Weakness.isWeakSignatureAlg(cert.signatureAlg)) {
                String reason = Weakness.getWeakSignatureAlgReason(cert.signatureAlg);
                redPrint(" - %s", reason);
            }
            blank();

            white("    公钥算法: %s (%d位)", cert.publicKeyAlg, cert.keyStrength);

            printCertValidity(cert.notBefore, cert.notAfter, cert.valid, cert.isExpired);

            if (cert.isSelfSigned) {
                red("    [警告] 自签名证书");
            }

            if (cert.altNames != null && !cert.altNames.isEmpty()) {
                white("    备用名称 (%d):", cert.altNames.size());
                for (int j = 0; j < cert.altNames.size(); j++) {
                    if (j < 10) {
                        white("      - %s", cert.altNames.get(j));
                    } else if (j == 10) {
                        white("      ... 还有 %d 个", cert.altNames.size() - 10);
                    }
                }
            }

            if (cert.isCA) {
                yellow("    CA 证书: 是");
            }

            blank();
        }
    }

    /** 证书类型（对应 Go 的 getCertType）。 */
    private static String getCertType(CertDetails cert) {
        if (cert.isCA) {
            return "CA证书";
        }
        return "服务器证书";
    }

    /** 主题（对应 Go 的 printCertSubject）。 */
    private static void printCertSubject(CertSubject subject) {
        white("    主题 (Subject):");
        if (subject.commonName != null && !subject.commonName.isEmpty()) {
            white("      CN: %s", subject.commonName);
        }
        if (!subject.organization.isEmpty()) {
            white("      O: %s", String.join(", ", subject.organization));
        }
        if (!subject.organizationalUnit.isEmpty()) {
            white("      OU: %s", String.join(", ", subject.organizationalUnit));
        }
        if (!subject.locality.isEmpty()) {
            white("      L: %s", String.join(", ", subject.locality));
        }
        if (!subject.province.isEmpty()) {
            white("      ST: %s", String.join(", ", subject.province));
        }
        if (!subject.country.isEmpty()) {
            white("      C: %s", String.join(", ", subject.country));
        }
    }

    /** 颁发者（对应 Go 的 printCertIssuer）。 */
    private static void printCertIssuer(CertIssuer issuer) {
        white("    颁发者 (Issuer):");
        if (issuer.commonName != null && !issuer.commonName.isEmpty()) {
            white("      CN: %s", issuer.commonName);
        }
        if (!issuer.organization.isEmpty()) {
            white("      O: %s", String.join(", ", issuer.organization));
        }
        if (!issuer.organizationalUnit.isEmpty()) {
            white("      OU: %s", String.join(", ", issuer.organizationalUnit));
        }
        if (!issuer.locality.isEmpty()) {
            white("      L: %s", String.join(", ", issuer.locality));
        }
        if (!issuer.province.isEmpty()) {
            white("      ST: %s", String.join(", ", issuer.province));
        }
        if (!issuer.country.isEmpty()) {
            white("      C: %s", String.join(", ", issuer.country));
        }
    }

    /** 有效期（对应 Go 的 printCertValidity）。 */
    private static void printCertValidity(Date notBefore, Date notAfter,
                                          boolean isValid, boolean isExpired) {
        white("    有效期:");
        white("      生效: %s", fmtTime(notBefore));
        white("      过期: %s", fmtTime(notAfter));

        // 对应 Go：int(notAfter.Sub(time.Now()).Hours() / 24)（向零取整）
        long hours = Duration.between(Instant.now(), notAfter.toInstant()).toHours();
        int daysLeft = (int) (hours / 24);

        if (isExpired) {
            red("      状态: 已过期 (!)");
        } else if (!isValid) {
            yellow("      状态: 尚未生效");
        } else {
            green("      状态: 有效 (剩余 %d 天)", daysLeft);
            if (daysLeft < 30) {
                red("      警告: 证书将在 %d 天内过期!", daysLeft);
            } else if (daysLeft < 90) {
                yellow("      提示: 证书将在 %d 天内过期", daysLeft);
            }
        }
    }

    /** 安全建议（对应 Go 的 printSecurityRecommendations）。 */
    private static void printSecurityRecommendations(SSLResult result) {
        cyanBold("安全建议:");
        blank();

        boolean hasWarnings = false;

        if (result.protocolSupport.sslv2 || result.protocolSupport.sslv3) {
            red("  [警告] 禁用 SSL 2.0 和 SSL 3.0");
            hasWarnings = true;
        }

        if (result.protocolSupport.tlsv10 || result.protocolSupport.tlsv11) {
            yellow("  [提示] 考虑禁用 TLS 1.0 和 TLS 1.1");
            hasWarnings = true;
        }

        for (CipherSuiteInfo cipher : result.cipherSuites) {
            if (cipher.isWeak) {
                red("  [警告] 禁用弱密码套件: %s", cipher.name);
                hasWarnings = true;
            }
        }

        if (!result.certificateChain.certificates.isEmpty()) {
            CertDetails cert = result.certificateChain.certificates.get(0);
            if (cert.isExpired) {
                red("  [警告] 立即更新过期的证书");
                hasWarnings = true;
            }
            if (cert.isSelfSigned) {
                yellow("  [提示] 考虑使用受信任的 CA 签发的证书");
                hasWarnings = true;
            }
            if (Weakness.isWeakSignatureAlg(cert.signatureAlg)) {
                red("  [警告] 使用弱签名算法: %s", cert.signatureAlg);
                hasWarnings = true;
            }
            if (cert.keyStrength > 0 && cert.keyStrength < 2048
                    && "RSA".equals(cert.publicKeyAlg)) {
                red("  [警告] RSA 密钥长度不足 (%d位)，建议使用至少 2048 位", cert.keyStrength);
                hasWarnings = true;
            }
        }

        if (!hasWarnings) {
            green("  [OK] 未发现明显的安全问题");
        }

        blank();
    }

    // =====================================================================
    // 底层输出（对应 fatih/color 的 *Color.Println / Printf）
    // =====================================================================

    /** 证书时间展示：x509 时间按 UTC 解析，与 Go 的 Format 结果一致。 */
    private static String fmtTime(Date d) {
        if (d == null) {
            return "";
        }
        return LocalDateTime.ofInstant(d.toInstant(), ZoneOffset.UTC).format(TIME_FMT);
    }

    /** 对应 Go 的 fmt.Println()。 */
    private static void blank() {
        System.out.println();
    }

    private static void cyanBold(String fmt, Object... args) {
        System.out.println(Colors.wrap(Fmt.format(fmt, args), Colors.BOLD, Colors.FG_HI_CYAN));
    }

    private static void white(String fmt, Object... args) {
        System.out.println(Colors.wrap(Fmt.format(fmt, args), Colors.FG_WHITE));
    }

    /** 不换行版本（用于拼接多段着色行，对应 fatih 的 Printf）。 */
    private static void whitePrint(String fmt, Object... args) {
        System.out.print(Colors.wrap(Fmt.format(fmt, args), Colors.FG_WHITE));
    }

    private static void yellow(String fmt, Object... args) {
        System.out.println(Colors.wrap(Fmt.format(fmt, args), Colors.FG_YELLOW));
    }

    private static void green(String fmt, Object... args) {
        System.out.println(Colors.wrap(Fmt.format(fmt, args), Colors.FG_GREEN));
    }

    private static void red(String fmt, Object... args) {
        System.out.println(Colors.wrap(Fmt.format(fmt, args), Colors.FG_RED));
    }

    /** 不换行版本（用于签名算法行的第二段）。 */
    private static void redPrint(String fmt, Object... args) {
        System.out.print(Colors.wrap(Fmt.format(fmt, args), Colors.FG_RED));
    }
}

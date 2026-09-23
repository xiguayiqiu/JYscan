package space.jyscan.modules.waf;

import space.jyscan.core.util.Embedded;
import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.JsonUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * WAF检测器实现，移植自 freeclient/internal/waf/detector.go。
 *
 * <p>与 Go 版保持一致的探测流程：
 * <ol>
 *   <li>规范化目标并生成候选URL（HTTPS 优先，失败自动回退 HTTP）；</li>
 *   <li>采集被动信息（状态码、响应头、响应体10KB上限、TLS证书）；</li>
 *   <li>被动特征加权匹配并与 confidence_threshold 比较，含冲突解决与去重；</li>
 *   <li>被动匹配失败时执行主动轻量探测（active_detect 特征）。</li>
 * </ol>
 *
 * <p>HTTP 客户端语义对应 Go 的 NewHTTPClient：不跟随跳转、3秒连接超时、5秒读取超时、
 * 跳过证书校验（InsecureSkipVerify）。
 */
public class WAFDetector {

    /** 连接超时，对应 Go 的 net.Dialer{Timeout: 3s} */
    private static final int CONNECT_TIMEOUT_MS = 3000;

    /** 读取超时，对应 Go 的 http.Client{Timeout: 5s} */
    private static final int READ_TIMEOUT_MS = 5000;

    /** 响应体读取上限10KB，对应 Go 的 io.LimitReader(resp.Body, 10*1024) */
    private static final int BODY_LIMIT = 10 * 1024;

    /** 主动探测默认 User-Agent，与 Go 保持一致 */
    private static final String DEFAULT_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0";

    /** 跳过全部证书校验的 SSLContext，对应 Go 的 tls.Config{InsecureSkipVerify: true} */
    private static final SSLContext TRUST_ALL_CONTEXT = createTrustAllContext();

    /** 规则列表 */
    private List<WAF> rules = new ArrayList<>();

    /** 规则是否已加载 */
    private boolean rulesLoaded = false;

    /** 创建新的WAF检测器，对应 Go 的 NewWAFDetector。 */
    public WAFDetector() {
    }

    // =====================================================================
    // 规则加载
    // =====================================================================

    /**
     * 加载WAF规则配置文件，对应 Go 的 LoadRules。
     *
     * <p>rulesPath 为空时使用嵌入的规则文件（加载失败回退默认路径），
     * 否则读取用户指定的文件。
     *
     * @throws IOException 读取或解析失败（错误信息与 Go 一致）
     */
    public void loadRules(String rulesPath) throws IOException {
        byte[] file;
        if (rulesPath == null || rulesPath.isEmpty()) {
            // 尝试使用嵌入的规则文件
            try {
                file = Embedded.loadWAFRules();
            } catch (IOException e) {
                // 如果嵌入文件加载失败，尝试使用默认路径（与 Go 一致）
                try {
                    file = Files.readAllBytes(Path.of("internal/waf/waf_rules.json"));
                } catch (IOException e2) {
                    throw new IOException(Fmt.format("读取规则文件失败: %v", e2), e2);
                }
            }
        } else {
            // 使用用户指定的路径
            try {
                file = Files.readAllBytes(Path.of(rulesPath));
            } catch (IOException e) {
                throw new IOException(Fmt.format("读取规则文件失败: %v", e), e);
            }
        }

        WAFConfig config;
        try {
            config = JsonUtil.fromJSON(file, WAFConfig.class);
        } catch (IOException e) {
            throw new IOException(Fmt.format("解析规则文件失败: %v", e), e);
        }

        rules = (config != null && config.wafList != null) ? config.wafList : new ArrayList<>();
        rulesLoaded = true;
    }

    /** 规则是否已加载（对应 Go 的 rulesLoaded 字段）。 */
    public boolean isRulesLoaded() {
        return rulesLoaded;
    }

    // =====================================================================
    // 单目标检测
    // =====================================================================

    /**
     * 检测目标网站是否使用WAF，对应 Go 的 DetectTarget。
     *
     * <p>与 Go 相同，采集被动信息失败时不返回异常，而是把失败原因写入
     * {@link WAFResult#description}（"采集信息失败: ..."）与
     * {@link WAFResult#errorMessage}，由 {@link #detectTargets} 统一补全
     * "探测失败" 描述并保留原因。
     */
    public WAFResult detectTarget(String target) {
        // 确保目标格式正确
        target = TargetUrls.normalizeTarget(target);

        WAFResult result = new WAFResult();
        result.target = target;
        result.detected = false;
        result.description = "未检测到已知WAF";
        result.wafName = "";
        result.vendor = "";
        result.confidence = 0;
        result.errorMessage = "";

        // 采集被动信息
        TargetInfo info;
        try {
            info = collectPassiveInfo(target);
        } catch (IOException e) {
            result.description = Fmt.format("采集信息失败: %v", e);
            result.errorMessage = e.getMessage() != null ? e.getMessage() : e.toString();
            return result;
        }

        // 记录实际可用的URL(HTTPS失败时已自动回退到HTTP)，
        // 后续主动探测与结果展示统一使用该URL，避免再次命中同样的协议错误
        if (info.url != null && !info.url.isEmpty()) {
            target = info.url;
            result.target = target;
        }

        // 进行被动特征匹配
        List<WAFMatchInfo> matches = new ArrayList<>();
        for (WAF waf : rules) {
            int score = matchPassiveFeatures(waf, info);
            if (score > 0) {
                // 统计匹配到的特征数量和高权重特征数量
                int featureCount = 0;
                int highWeightFeatureCount = 0;
                if (waf.features != null) {
                    for (Feature feature : waf.features) {
                        if (!"active_detect".equals(feature.type) && matchFeature(feature, info)) {
                            featureCount++;
                            if (feature.weight >= 80) {
                                highWeightFeatureCount++;
                            }
                        }
                    }
                }
                matches.add(new WAFMatchInfo(waf, score, featureCount, highWeightFeatureCount));
            }
        }

        // 特征冲突处理：当有多个可能的WAF匹配时，进行更智能的选择
        if (matches.size() > 1) {
            // 过滤出所有超过置信度阈值的匹配
            List<WAFMatchInfo> validMatches = new ArrayList<>();
            for (WAFMatchInfo match : matches) {
                if (match.score >= match.waf.confidenceThreshold) {
                    validMatches.add(match);
                }
            }

            // 如果有多个有效匹配，进行冲突解决
            if (validMatches.size() > 1) {
                // 优先选择高权重特征匹配数量多的
                WAFMatchInfo bestMatch = validMatches.get(0);
                for (int i = 1; i < validMatches.size(); i++) {
                    WAFMatchInfo currentMatch = validMatches.get(i);
                    // 如果高权重特征匹配数更多，直接选择
                    if (currentMatch.highWeightFeatureCount > bestMatch.highWeightFeatureCount) {
                        bestMatch = currentMatch;
                    } else if (currentMatch.highWeightFeatureCount == bestMatch.highWeightFeatureCount) {
                        // 如果高权重特征匹配数相同，选择总体得分更高的
                        if (currentMatch.score > bestMatch.score) {
                            bestMatch = currentMatch;
                        } else if (currentMatch.score == bestMatch.score) {
                            // 如果得分也相同，选择置信度阈值更高的（更严格的规则）
                            if (currentMatch.waf.confidenceThreshold > bestMatch.waf.confidenceThreshold) {
                                bestMatch = currentMatch;
                            }
                        }
                    }
                }

                // 与 Go 一致：该分支返回全新结果（Description/ErrorMessage 为零值）
                WAFResult conflictResult = new WAFResult();
                conflictResult.target = target;
                conflictResult.wafName = bestMatch.waf.name;
                conflictResult.vendor = bestMatch.waf.vendor;
                conflictResult.confidence = bestMatch.score;
                conflictResult.detected = true;
                conflictResult.description = "";
                conflictResult.errorMessage = "";
                return conflictResult;
            }
        }

        // 去重和误报控制：选择最佳匹配
        WAFMatchInfo bestMatch = selectBestMatch(matches);

        // 如果被动匹配失败，进行主动探测
        if (bestMatch == null) {
            ActiveDetection active = performActiveDetection(target);
            if (active.score > 0 && active.waf.confidenceThreshold > 0
                    && active.score >= active.waf.confidenceThreshold) {
                result.detected = true;
                result.wafName = active.waf.name;
                result.vendor = active.waf.vendor;
                result.confidence = active.score;
                result.description = Fmt.format("通过主动探测检测到WAF: %s (厂商: %s)",
                        active.waf.name, active.waf.vendor);
                return result;
            }
            return result;
        }

        // 检测到WAF
        result.detected = true;
        result.wafName = bestMatch.waf.name;
        result.vendor = bestMatch.waf.vendor;
        result.confidence = bestMatch.score;
        result.description = Fmt.format("检测到WAF: %s (厂商: %s)，置信度: %d%%",
                bestMatch.waf.name, bestMatch.waf.vendor, bestMatch.score);
        return result;
    }

    /**
     * 选择最佳匹配，实现去重和误报控制，对应 Go 的 selectBestMatch。
     * 无有效匹配（得分未达阈值）时返回 null。
     */
    private WAFMatchInfo selectBestMatch(List<WAFMatchInfo> matches) {
        if (matches == null || matches.isEmpty()) {
            return null;
        }

        // 过滤掉低置信度的匹配结果：只有置信度超过阈值的匹配结果才被视为有效
        List<WAFMatchInfo> validMatches = new ArrayList<>();
        for (WAFMatchInfo match : matches) {
            if (match.score >= match.waf.confidenceThreshold) {
                validMatches.add(match);
            }
        }

        // 如果没有有效匹配，返回nil
        if (validMatches.isEmpty()) {
            return null;
        }

        WAFMatchInfo bestMatch = validMatches.get(0);
        for (int i = 1; i < validMatches.size(); i++) {
            WAFMatchInfo match = validMatches.get(i);
            // 优先考虑高权重特征数量
            if (match.highWeightFeatureCount > bestMatch.highWeightFeatureCount) {
                bestMatch = match;
            } else if (match.highWeightFeatureCount == bestMatch.highWeightFeatureCount) {
                // 高权重特征数量相同时，选择得分高的
                if (match.score > bestMatch.score) {
                    bestMatch = match;
                } else if (match.score == bestMatch.score) {
                    // 得分相同时，选择匹配特征数量多的
                    if (match.featureCount > bestMatch.featureCount) {
                        bestMatch = match;
                    } else if (match.featureCount == bestMatch.featureCount) {
                        // 如果分数和特征数量都相同，选择置信度阈值高的
                        if (match.waf.confidenceThreshold > bestMatch.waf.confidenceThreshold) {
                            bestMatch = match;
                        }
                    }
                }
            }
        }

        return bestMatch;
    }

    // =====================================================================
    // 被动信息采集
    // =====================================================================

    /**
     * 采集被动信息，对应 Go 的 collectPassiveInfo。
     * 依次尝试候选URL(默认优先HTTPS，失败后回退HTTP)，任一协议成功即返回；
     * 全部失败时返回第一个错误。
     */
    private TargetInfo collectPassiveInfo(String target) throws IOException {
        IOException firstErr = null;
        for (String url : TargetUrls.candidateURLs(target)) {
            try {
                return collectPassiveInfoOnce(url);
            } catch (IOException e) {
                if (firstErr == null) {
                    firstErr = e;
                }
            }
        }
        if (firstErr == null) {
            firstErr = new IOException(Fmt.format("无法构造可用URL: %s", target));
        }
        throw firstErr;
    }

    /** 针对单个URL采集被动信息，对应 Go 的 collectPassiveInfoOnce。 */
    private TargetInfo collectPassiveInfoOnce(String target) throws IOException {
        TargetInfo info = new TargetInfo();
        info.url = target;
        info.headers = new LinkedHashMap<>();
        info.responseBody = "";
        info.certIssuer = "";
        info.certSubject = "";
        info.certSerial = "";

        // 发送HTTP请求
        HttpURLConnection conn;
        int statusCode;
        try {
            conn = openConnection(target, null);
            statusCode = conn.getResponseCode();
        } catch (IOException e) {
            throw new IOException(Fmt.format("HTTP请求失败: %v", e), e);
        }

        try {
            // 收集响应头和状态码
            info.statusCode = statusCode;
            collectHeaders(conn, info.headers);

            // 收集响应体（限制大小为10KB）
            try {
                info.responseBody = readBodyLimited(conn);
            } catch (IOException e) {
                throw new IOException(Fmt.format("读取响应体失败: %v", e), e);
            }

            // 如果是HTTPS，收集证书信息
            if (target.startsWith("https://")) {
                try {
                    CertInfo certInfo = getCertInfo(target);
                    info.certIssuer = certInfo.issuer;
                    info.certSubject = certInfo.subject;
                    info.certSerial = certInfo.serial;
                } catch (Exception e) {
                    // 与 Go 一致：证书采集失败不影响被动信息收集
                }
            }

            return info;
        } finally {
            disconnectQuietly(conn);
        }
    }

    /**
     * 获取证书信息，对应 Go 的 getCertInfo。
     * 通过一次性 TLS 握手读取对端证书（不复用连接、跳过校验）。
     */
    private CertInfo getCertInfo(String target) throws IOException {
        // 从URL中提取主机名和端口
        String host = target;
        if (host.startsWith("https://")) {
            host = host.substring("https://".length());
        }
        if (!host.contains(":")) {
            host += ":443";
        }

        String[] hp = TargetUrls.splitHostPort(host);
        if (hp == null) {
            throw new IOException(Fmt.format("地址格式错误: %s", host));
        }
        String hostname = hp[0];
        int port;
        try {
            port = Integer.parseInt(hp[1]);
        } catch (NumberFormatException e) {
            throw new IOException(Fmt.format("地址格式错误: %s", host));
        }

        try (Socket raw = new Socket()) {
            // Go 的 tls.Dial 未设置超时，这里补充有限超时避免探测卡死
            raw.connect(new InetSocketAddress(hostname, port), CONNECT_TIMEOUT_MS);
            try (SSLSocket ssl = (SSLSocket) TRUST_ALL_CONTEXT.getSocketFactory()
                    .createSocket(raw, hostname, port, true)) {
                ssl.setSoTimeout(READ_TIMEOUT_MS);
                ssl.startHandshake();

                Certificate[] certs = ssl.getSession().getPeerCertificates();
                if (certs.length == 0) {
                    throw new IOException("未获取到证书");
                }
                X509Certificate cert = (X509Certificate) certs[0];

                CertInfo info = new CertInfo();
                // 输出语义对齐 Go 的 pkix.Name.String()（值不转义）
                info.issuer = goDNString(cert.getIssuerX500Principal());
                info.subject = goDNString(cert.getSubjectX500Principal());
                info.serial = cert.getSerialNumber().toString(10);
                return info;
            }
        }
    }

    // =====================================================================
    // 特征匹配
    // =====================================================================

    /**
     * 匹配被动特征，计算匹配得分，对应 Go 的 matchPassiveFeatures。
     * 高权重特征（权重≥80）命中两个以上且得分&gt;70 时提前返回85-99的随机分。
     */
    private int matchPassiveFeatures(WAF waf, TargetInfo info) {
        int score = 0;
        int matchedFeatureCount = 0;
        boolean highConfidenceMatch = false;
        int highWeightMatched = 0;

        if (waf.features == null || waf.features.isEmpty()) {
            return 0;
        }

        // 对特征按权重从高到低排序（Go 的 sort.Slice 为不稳定排序，这里用稳定排序，
        // 同权重特征的匹配顺序不影响得分总和与提前返回的判定结果）
        List<Feature> sortedFeatures = new ArrayList<>(waf.features);
        sortedFeatures.sort((a, b) -> Integer.compare(b.weight, a.weight));

        // 优先匹配高权重特征，并进行早期判断
        for (Feature feature : sortedFeatures) {
            if ("active_detect".equals(feature.type)) {
                continue; // 跳过主动探测特征
            }

            if (matchFeature(feature, info)) {
                score += feature.weight;
                matchedFeatureCount++;
                // 标记是否有高权重特征匹配（权重≥80）
                if (feature.weight >= 80) {
                    highConfidenceMatch = true;
                    highWeightMatched++;
                    // 如果匹配到两个或更多高权重特征，可以提前判断
                    if (highWeightMatched >= 2 && score > 70) {
                        // 至少已经匹配到2个高权重特征，提前返回较高的得分
                        return 85 + ThreadLocalRandom.current().nextInt(15); // 返回85-99的随机值
                    }
                }
            }
        }

        // 改进的加权逻辑：只有当有高权重特征匹配且匹配特征数≥2时才额外加分
        if (matchedFeatureCount >= 2 && highConfidenceMatch && score > 60) {
            score += 10;
        }

        // 如果匹配到高权重特征，适当提高分数
        if (highWeightMatched > 0) {
            score = score + highWeightMatched * 3;
            if (score > 100) {
                score = 100;
            }
        }

        // 确保置信度不超过100%
        if (score > 100) {
            score = 100;
        }

        return score;
    }

    /** 匹配单个特征，对应 Go 的 matchFeature。 */
    private boolean matchFeature(Feature feature, TargetInfo info) {
        if (feature == null) {
            return false;
        }
        if ("response_header".equals(feature.type)) {
            return matchHeader(feature, info);
        }
        if ("ssl_certificate".equals(feature.type)) {
            return matchCertificate(feature, info);
        }
        if ("response_content".equals(feature.type)) {
            return matchContent(feature, info);
        }
        return false;
    }

    /** 匹配响应头，对应 Go 的 matchHeader。 */
    private boolean matchHeader(Feature feature, TargetInfo info) {
        String headerValue = info.header(feature.key);
        String matchType = feature.matchType == null ? "" : feature.matchType;
        String value = feature.value == null ? "" : feature.value;
        switch (matchType) {
            case "exists":
                return !headerValue.isEmpty();
            case "contains":
                return headerValue.toLowerCase(Locale.ROOT).contains(value.toLowerCase(Locale.ROOT));
            case "exact":
                return headerValue.equalsIgnoreCase(value);
            case "regex":
                return regexMatch(value, headerValue);
            default:
                return false;
        }
    }

    /** 匹配证书，对应 Go 的 matchCertificate（无 exists 分支）。 */
    private boolean matchCertificate(Feature feature, TargetInfo info) {
        String value;
        if (feature.field == null) {
            return false;
        }
        switch (feature.field) {
            case "issuer":
                value = info.certIssuer;
                break;
            case "subject":
                value = info.certSubject;
                break;
            case "serial":
                value = info.certSerial;
                break;
            default:
                return false;
        }

        String matchType = feature.matchType == null ? "" : feature.matchType;
        String expected = feature.value == null ? "" : feature.value;
        switch (matchType) {
            case "contains":
                return value.toLowerCase(Locale.ROOT).contains(expected.toLowerCase(Locale.ROOT));
            case "exact":
                return value.equalsIgnoreCase(expected);
            case "regex":
                return regexMatch(expected, value);
            default:
                return false;
        }
    }

    /** 匹配响应内容，对应 Go 的 matchContent。 */
    private boolean matchContent(Feature feature, TargetInfo info) {
        String content = info.responseBody == null ? "" : info.responseBody;
        String matchType = feature.matchType == null ? "" : feature.matchType;
        String expected = feature.value == null ? "" : feature.value;
        switch (matchType) {
            case "contains":
                return content.toLowerCase(Locale.ROOT).contains(expected.toLowerCase(Locale.ROOT));
            case "exact":
                return content.equalsIgnoreCase(expected);
            case "regex":
                return regexMatch(expected, content);
            default:
                return false;
        }
    }

    /** 正则匹配，对应 Go 的 regexp.MatchString（编译失败视为不匹配）。 */
    private static boolean regexMatch(String pattern, String subject) {
        String p = pattern == null ? "" : pattern;
        String s = subject == null ? "" : subject;
        try {
            return Pattern.compile(p).matcher(s).find();
        } catch (PatternSyntaxException e) {
            return false;
        }
    }

    // =====================================================================
    // 主动探测
    // =====================================================================

    /**
     * 执行主动探测，对应 Go 的 performActiveDetection：
     * 对每条规则执行 active_detect 特征探测，返回得分最高者。
     */
    private ActiveDetection performActiveDetection(String target) {
        int highestScore = 0;
        WAF bestMatch = new WAF();

        for (WAF waf : rules) {
            int score = activeDetect(waf, target);
            if (score > highestScore) {
                highestScore = score;
                bestMatch = waf;
            }
        }

        return new ActiveDetection(highestScore, bestMatch);
    }

    /** 对单个WAF进行主动探测，对应 Go 的 activeDetect。 */
    private int activeDetect(WAF waf, String target) {
        int score = 0;
        int matchedFeatureCount = 0;
        boolean highConfidenceMatch = false;

        if (waf.features == null) {
            return 0;
        }

        for (Feature feature : waf.features) {
            if (!"active_detect".equals(feature.type)) {
                continue;
            }

            if (executeActiveRequest(target, feature)) {
                score += feature.weight;
                matchedFeatureCount++;
                // 标记是否有高权重特征匹配（权重≥80）
                if (feature.weight >= 80) {
                    highConfidenceMatch = true;
                }
            }
        }

        // 改进的加权逻辑：只有当有高权重特征匹配且匹配特征数≥2时才额外加分
        if (matchedFeatureCount >= 2 && highConfidenceMatch && score > 60) {
            score += 10;
        }

        // 确保置信度不超过100%
        if (score > 100) {
            score = 100;
        }

        return score;
    }

    /**
     * 执行主动探测请求，对应 Go 的 executeActiveRequest。
     * 构建探测URL与UA后发起GET；respCheck 各项检查全部通过才返回 true。
     */
    private boolean executeActiveRequest(String target, Feature feature) {
        // 构建请求URL
        String url;
        if (feature.request != null && feature.request.path != null && !feature.request.path.isEmpty()) {
            String baseURL = target.endsWith("/") ? target.substring(0, target.length() - 1) : target;
            String path = feature.request.path.startsWith("/")
                    ? feature.request.path.substring(1) : feature.request.path;
            url = baseURL + "/" + path;
        } else {
            // 使用默认的轻微异常路径
            url = target + "/?test='123";
        }

        // 设置User-Agent（Go 侧固定使用 GET，忽略 request.method）
        String userAgent = (feature.request != null && feature.request.userAgent != null
                && !feature.request.userAgent.isEmpty())
                ? feature.request.userAgent
                : DEFAULT_USER_AGENT;

        // 创建并发送请求（对应 Go http.NewRequest + Client.Do 的失败分支）
        HttpURLConnection conn;
        try {
            conn = openConnection(url, userAgent);
        } catch (IOException e) {
            return false;
        }

        try {
            int statusCode = conn.getResponseCode();

            // 检查响应
            if (feature.respCheck != null) {
                // 检查状态码
                if (feature.respCheck.statusCode > 0 && statusCode != feature.respCheck.statusCode) {
                    return false;
                }

                // 检查响应头
                if (feature.respCheck.headerExists != null && !feature.respCheck.headerExists.isEmpty()
                        && header(conn, feature.respCheck.headerExists).isEmpty()) {
                    return false;
                }

                // 检查响应内容
                if (feature.respCheck.contentContains != null && !feature.respCheck.contentContains.isEmpty()) {
                    // 读取失败时与 Go 一致按空内容处理（Go 忽略读取错误）
                    String body = readBodyQuietly(conn);
                    if (!body.toLowerCase(Locale.ROOT).contains(
                            feature.respCheck.contentContains.toLowerCase(Locale.ROOT))) {
                        return false;
                    }
                }
            } else {
                // 默认检查：如果返回403/406/503状态码，认为可能被WAF拦截
                if (statusCode == 403 || statusCode == 406 || statusCode == 503) {
                    return true;
                }
            }

            return true;
        } catch (IOException e) {
            return false;
        } finally {
            disconnectQuietly(conn);
        }
    }

    // =====================================================================
    // 并发探测
    // =====================================================================

    /**
     * 并发探测多个目标，对应 Go 的 DetectTargets。
     *
     * <p>并发数按 Go 相同规则收敛（&lt;=0 取20，&gt;100 取100）。
     * 结果按完成顺序返回（对应 Go 的结果channel语义，并不保持输入顺序）；
     * 任何失败都必须携带 errorMessage 原因，绝不丢弃。
     */
    public List<WAFResult> detectTargets(List<String> targets, int concurrency) {
        List<WAFResult> allResults = new ArrayList<>();
        if (targets == null || targets.isEmpty()) {
            return allResults;
        }

        // 控制并发数量
        if (concurrency <= 0) {
            concurrency = 20; // 默认并发数
        }
        if (concurrency > 100) {
            concurrency = 100; // 最大并发数
        }

        ExecutorService pool = Executors.newFixedThreadPool(concurrency);
        try {
            CompletionService<WAFResult> completion = new ExecutorCompletionService<>(pool);
            for (String target : targets) {
                final String t = target;
                // 单个任务绝不向外抛异常，保证每个目标都产出一个结果
                completion.submit(() -> {
                    try {
                        return detectOne(t);
                    } catch (Throwable e) {
                        WAFResult fallback = new WAFResult();
                        fallback.target = t;
                        fallback.detected = false;
                        fallback.description = "探测失败";
                        fallback.errorMessage = e.toString();
                        return fallback;
                    }
                });
            }

            // 按完成顺序收齐全部结果（对应 Go 的 wg.Wait + range channel）
            for (int i = 0; i < targets.size(); i++) {
                WAFResult result = awaitNextResult(completion);
                if (result != null) {
                    allResults.add(result);
                }
            }
        } finally {
            pool.shutdown();
        }

        return allResults;
    }

    /** 阻塞等待下一个完成的结果；中断时不放弃等待（与 Go 的 wg.Wait 语义一致）。 */
    private static WAFResult awaitNextResult(CompletionService<WAFResult> completion) {
        while (true) {
            try {
                Future<WAFResult> future = completion.take();
                while (true) {
                    try {
                        return future.get();
                    } catch (InterruptedException e) {
                        // 忽略中断，继续等待该任务完成
                    } catch (Exception e) {
                        // 任务内部已捕获 Throwable，此分支理论上不可达
                        return null;
                    }
                }
            } catch (InterruptedException e) {
                // 忽略中断，继续等待
            }
        }
    }

    /**
     * 单个目标的探测封装，对应 Go DetectTargets 中 goroutine 的处理逻辑：
     * 出错时保留已采集的部分信息、补全"探测失败"描述并保留失败原因。
     */
    private WAFResult detectOne(String target) {
        WAFResult result = detectTarget(target);
        if (result == null) {
            result = new WAFResult();
        }
        // 若出错，保留Detector已采集的部分信息，并补全失败原因
        if (result.errorMessage != null && !result.errorMessage.isEmpty()) {
            if (result.target == null || result.target.isEmpty()) {
                result.target = target;
            }
            result.detected = false;
            result.description = "探测失败";
            // errorMessage 保留原样，避免Termux等环境下只看到"探测失败"而无法定位问题
        }
        return result;
    }

    // =====================================================================
    // 内部工具
    // =====================================================================

    /** WAF匹配信息，用于去重和误报控制，对应 Go 的 WAFMatchInfo。 */
    private static final class WAFMatchInfo {
        final WAF waf;
        final int score;
        final int featureCount;
        final int highWeightFeatureCount;

        WAFMatchInfo(WAF waf, int score, int featureCount, int highWeightFeatureCount) {
            this.waf = waf;
            this.score = score;
            this.featureCount = featureCount;
            this.highWeightFeatureCount = highWeightFeatureCount;
        }
    }

    /** 主动探测结果（得分 + 对应规则），对应 Go performActiveDetection 的两个返回值。 */
    private static final class ActiveDetection {
        final int score;
        final WAF waf;

        ActiveDetection(int score, WAF waf) {
            this.score = score;
            this.waf = waf;
        }
    }

    /**
     * 打开HTTP(S)请求连接，对应 Go 的 http.NewRequest("GET") + Client.Do。
     * 语义：不跟随跳转（ErrUseLastResponse）、3秒连接超时、5秒读取超时、跳过证书校验。
     */
    private static HttpURLConnection openConnection(String url, String userAgent) throws IOException {
        URL u = new URL(url); // URL非法时抛出，对应 Go http.NewRequest 失败
        URLConnection raw = u.openConnection();
        if (!(raw instanceof HttpURLConnection conn)) {
            throw new IOException(Fmt.format("不支持的协议: %s", u.getProtocol()));
        }
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
        conn.setReadTimeout(READ_TIMEOUT_MS);
        // 对应 Go CheckRedirect 返回 http.ErrUseLastResponse
        conn.setInstanceFollowRedirects(false);
        if (userAgent != null) {
            conn.setRequestProperty("User-Agent", userAgent);
        }
        if (conn instanceof javax.net.ssl.HttpsURLConnection https) {
            // 对应 tls.Config{InsecureSkipVerify: true}
            https.setSSLSocketFactory(TRUST_ALL_CONTEXT.getSocketFactory());
            https.setHostnameVerifier((hostname, session) -> true);
        }
        return conn;
    }

    /** 收集全部响应头到以小写为键的映射（对应 Go resp.Header）。 */
    private static void collectHeaders(HttpURLConnection conn, Map<String, List<String>> out) {
        Map<String, List<String>> fields = conn.getHeaderFields();
        if (fields == null) {
            return;
        }
        for (Map.Entry<String, List<String>> entry : fields.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) {
                continue; // 键为 null 的是状态行
            }
            out.computeIfAbsent(entry.getKey().toLowerCase(Locale.ROOT),
                    k -> new ArrayList<>()).addAll(entry.getValue());
        }
    }

    /** 大小写不敏感读取单个响应头，语义等同 Go 的 resp.Header.Get。 */
    private static String header(HttpURLConnection conn, String name) {
        Map<String, List<String>> fields = conn.getHeaderFields();
        if (fields == null || name == null) {
            return "";
        }
        for (Map.Entry<String, List<String>> entry : fields.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)
                    && entry.getValue() != null && !entry.getValue().isEmpty()) {
                return entry.getValue().get(0);
            }
        }
        return "";
    }

    /**
     * 读取响应体，限制10KB，对应 Go 的 io.ReadAll(io.LimitReader(resp.Body, 10*1024))。
     * 4xx/5xx 从错误流读取（Java 的 getInputStream 对错误码会抛异常）。
     */
    private static String readBodyLimited(HttpURLConnection conn) throws IOException {
        int status = conn.getResponseCode();
        InputStream in = status >= 400 ? conn.getErrorStream() : conn.getInputStream();
        if (in == null) {
            return "";
        }
        try (InputStream stream = in) {
            byte[] body = stream.readNBytes(BODY_LIMIT);
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    /** 读取响应体（10KB上限），失败时返回空串，对应 Go 的 body, _ := io.ReadAll(...)。 */
    private static String readBodyQuietly(HttpURLConnection conn) {
        try {
            return readBodyLimited(conn);
        } catch (IOException e) {
            return "";
        }
    }

    /** 关闭连接，对应 Go 的 defer resp.Body.Close()。 */
    private static void disconnectQuietly(HttpURLConnection conn) {
        if (conn == null) {
            return;
        }
        try {
            conn.disconnect();
        } catch (Exception ignored) {
            // 忽略关闭异常
        }
    }

    /** DN 字符串转换，对齐 Go 的 pkix.Name.String()（值不做转义）。 */
    private static String goDNString(X500Principal principal) {
        return unescapeRfc2253(principal.getName(X500Principal.RFC2253));
    }

    /** 去掉 RFC2253 输出中的反斜杠转义（Java 会把值内的逗号转义为 \,，Go 不转义）。 */
    private static String unescapeRfc2253(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                sb.append(s.charAt(++i));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** 创建跳过全部证书校验的 SSLContext，对应 Go 的 tls.Config{InsecureSkipVerify: true}。 */
    private static SSLContext createTrustAllContext() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }}, new SecureRandom());
            return ctx;
        } catch (Exception e) {
            // TLS 提供者为 JDK 内置，正常环境不会失败；失败时退化为不校验主机名的默认工厂
            throw new IllegalStateException(Fmt.format("初始化SSL上下文失败: %v", e), e);
        }
    }
}

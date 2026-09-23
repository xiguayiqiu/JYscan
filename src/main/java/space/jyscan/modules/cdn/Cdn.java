package space.jyscan.modules.cdn;

import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.modules.whois.Whois;
import space.jyscan.modules.whois.WhoisInfo;
import space.jyscan.modules.whois.WhoisParser;
import space.jyscan.modules.whois.WhoisResult;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * CDN / 云服务识别核心，移植自 freeclient/internal/cdn/cdn.go。
 *
 * <p>判定链路与 Go 完全一致：
 * <ol>
 *   <li>{@code checkCDN}：CNAME 指纹 → 多 IP（&ge;3）→ NS 关键词 → HTTP 响应头指纹，逐级累加置信度；</li>
 *   <li>{@code checkCloudProvider}：CNAME 指纹 → PTR 反查指纹；</li>
 *   <li>{@code checkRegistrar}：NS 指纹 → whois 官方注册商 → whois 原文关键词兜底。</li>
 * </ol>
 *
 * <p>品牌差异：Go 的 HTTP User-Agent 为 {@code freeclient/3.0}，这里按既有移植约定
 * （见 {@code Config.java} 保留 {@code freeclient/v2.9}）原样保留，不做品牌替换。
 */
public final class Cdn {

    /** CDN 指纹表，逐项对应 Go 的 cdnFingerprints。 */
    private static final List<CdnFingerprint> CDN_FINGERPRINTS = buildCdnFingerprints();

    /** 云服务商指纹，逐项对应 Go 的 cloudProviderFingerprints。 */
    private static final List<CdnFingerprint> CLOUD_PROVIDER_FINGERPRINTS = buildCloudProviderFingerprints();

    /**
     * 注册商指纹，对应 Go 的 {@code registrarFingerprints}。
     *
     * <p>Go 用 map（遍历顺序随机），这里改用 LinkedHashMap 按源码声明顺序遍历，
     * 使多模式命中时的结果稳定可复现。
     */
    private static final Map<String, List<String>> REGISTRAR_FINGERPRINTS = buildRegistrarFingerprints();
    /** 构建 CDN 指纹表（顺序即 Go 的 cdnFingerprints 声明顺序，决定「首个命中」）。 */
    private static List<CdnFingerprint> buildCdnFingerprints() {
        List<CdnFingerprint> fps = new ArrayList<>();
        fps.add(new CdnFingerprint("Cloudflare", "Cloudflare, Inc.", "cname",
                "cloudflare", "cf-", ".cdn.cloudflare.net"));
        fps.add(new CdnFingerprint("Cloudflare", "Cloudflare, Inc.", "header",
                "cf-ray", "cf-cache-status", "server: cloudflare", "x-cdn-provider: cloudflare"));
        fps.add(new CdnFingerprint("Akamai", "Akamai Technologies", "cname",
                "akamai", "akamaiedge", "edgesuite", "akadns", "akam.net"));
        fps.add(new CdnFingerprint("Akamai", "Akamai Technologies", "header",
                "x-akamai-transformed", "server: akamaighost", "x-akamai-cache-key"));
        fps.add(new CdnFingerprint("Amazon CloudFront", "Amazon Web Services", "cname",
                "cloudfront", ".cloudfront.net"));
        fps.add(new CdnFingerprint("Amazon CloudFront", "Amazon Web Services", "header",
                "x-amz-cf-id", "x-amz-cf-pop", "server: cloudfront"));
        fps.add(new CdnFingerprint("Google Cloud CDN", "Google Cloud Platform", "cname",
                "googleusercontent.com", "googledomains.com", "gc-cdn", "googlehosted.com"));
        fps.add(new CdnFingerprint("Microsoft Azure CDN", "Microsoft Azure", "cname",
                "azure", "azureedge.net", "microsoftazurecdn", "azurewebsites.net"));
        fps.add(new CdnFingerprint("Fastly", "Fastly, Inc.", "cname",
                "fastly", "fastlylb", "fastly.net"));
        fps.add(new CdnFingerprint("Fastly", "Fastly, Inc.", "header",
                "x-served-by: fastly", "via: varnish", "x-fastly-request-id"));
        fps.add(new CdnFingerprint("Bunny.net", "Bunny.net", "cname",
                "bunny.net", "b-cdn.net", "bunnycdn"));
        fps.add(new CdnFingerprint("阿里云CDN", "阿里巴巴", "cname",
                "kunlun", "alicdn", "aliyun", ".cdn.aliyuncs.com", ".kunlun", "taobaocdn",
                "alicdn.com", "aliyuncs"));
        fps.add(new CdnFingerprint("阿里云CDN", "阿里巴巴", "header",
                "x-cdn-provider: aliyun", "x-ali-cdn-request-id", "server: tengine"));
        fps.add(new CdnFingerprint("腾讯云CDN", "腾讯云", "cname",
                "tencent", "qcloud", ".cdn.dnsv1.com", ".tlv1.com", ".tcdn.com", "qpic",
                "gtimg", "myqcloud"));
        fps.add(new CdnFingerprint("腾讯云CDN", "腾讯云", "header",
                "x-cdn-provider: qcloud", "x-qcache-request-id"));
        fps.add(new CdnFingerprint("百度智能云CDN", "百度云", "cname",
                "baidu", "bdydns", ".bsgslb.com", ".baidu.com", "bdstatic", "shifen", "baiduyun"));
        fps.add(new CdnFingerprint("百度智能云CDN", "百度云", "header",
                "x-cdn-provider: baidu", "server: bfe"));
        fps.add(new CdnFingerprint("华为云CDN", "华为云", "cname",
                "huawei", "hwcdn", ".myhuaweicloud.com", ".huaweicloud.com", "huaweicloud"));
        fps.add(new CdnFingerprint("又拍云", "又拍云", "cname",
                "upyun", "upaiyun", ".upaiyun.com", "upyun.com"));
        fps.add(new CdnFingerprint("七牛云", "七牛云", "cname",
                "qiniu", "qbox.me", ".qiniudn.com", "qiniu.com"));
        fps.add(new CdnFingerprint("网宿科技CDN", "网宿科技", "cname",
                "wangsu", "wsweb", ".lxdns.com", ".wswebcdn.com", "wsglb", "wscdn"));
        fps.add(new CdnFingerprint("蓝汛ChinaCache", "蓝汛通信", "cname",
                "chinacache", "lxdns", ".chinacache.com", "chinacache"));
        fps.add(new CdnFingerprint("灵境云EdgeCDN", "灵境云", "cname", "edgecdn", "lingjing"));
        fps.add(new CdnFingerprint("火山引擎CDN", "字节跳动", "cname",
                "volcengine", "bytecdn", ".bytecdn.com", "douyinpic", "pstatp", "bytedns",
                "toutiao"));
        fps.add(new CdnFingerprint("美团云CDN", "美团", "cname",
                "meituan", "meituancdn", ".meituan.com", "meituan", "meituan.net"));
        fps.add(new CdnFingerprint("京东云CDN", "京东云", "cname",
                "jdcloud", "jcloud", ".jdcloud.com", "jd", "jd.com"));
        fps.add(new CdnFingerprint("StackPath", "StackPath", "cname", "stackpath", "highwinds"));
        fps.add(new CdnFingerprint("Sucuri", "Sucuri", "cname", "sucuri", "sucuri.net"));
        fps.add(new CdnFingerprint("Incapsula", "Imperva", "cname", "incapsula", "imperva"));
        fps.add(new CdnFingerprint("Limelight", "Limelight Networks", "cname",
                "llnwd", "limelight"));
        fps.add(new CdnFingerprint("EdgeCast", "EdgeCast (Verizon)", "cname",
                "edgecast", "verizondigitalmedia"));
        fps.add(new CdnFingerprint("自建CDN", "自建CDN", "cname",
                "cdn", "cdn.", ".cdn", "ws.", "gslb", "glb", "slb", "waf", "shield", "edge",
                "cache", "static", "img", "pic", "image", "video", "media", "download", "file"));
        fps.add(new CdnFingerprint("HTTP缓存服务", "CDN特征", "header",
                "x-cache", "x-cache-hits", "x-cache-lookup"));
        fps.add(new CdnFingerprint("反向代理服务", "CDN特征", "header", "via", "x-via"));
        fps.add(new CdnFingerprint("Nginx/OpenResty", "CDN特征", "header",
                "server: nginx", "server: openresty", "server: tengine", "x-accel-buffering",
                "x-accel-limit-rate", "x-accel-redirect"));
        fps.add(new CdnFingerprint("Squid/Varnish", "CDN特征", "header",
                "server: squid", "server: varnish"));

        return fps;
    }

    /** 构建云服务商指纹表，逐项对应 Go 的 cloudProviderFingerprints。 */
    private static List<CdnFingerprint> buildCloudProviderFingerprints() {
        List<CdnFingerprint> fps = new ArrayList<>();
        fps.add(new CdnFingerprint("AWS", "Amazon Web Services", "cname",
                "amazonaws.com", "aws", "cloudfront"));
        fps.add(new CdnFingerprint("AWS", "Amazon Web Services", "ip", "ec2", "compute-1"));
        fps.add(new CdnFingerprint("Microsoft Azure", "Microsoft Azure", "cname",
                "azure", "cloudapp.net", "azurewebsites.net", "azureedge.net"));
        fps.add(new CdnFingerprint("Google Cloud", "Google Cloud Platform", "cname",
                "googleusercontent.com", "appspot.com", "gcp", "googledomains.com"));
        fps.add(new CdnFingerprint("阿里云", "阿里巴巴", "cname", "aliyuncs.com", "alibaba"));
        fps.add(new CdnFingerprint("腾讯云", "腾讯云", "cname", "myqcloud.com", "tencentcloud.com"));
        fps.add(new CdnFingerprint("华为云", "华为云", "cname", "myhuaweicloud.com"));
        fps.add(new CdnFingerprint("Oracle Cloud", "Oracle Cloud", "cname", "oraclecloud.com"));
        return fps;
    }

    /** 构建注册商指纹表，保持 Go 源码里的声明顺序。 */
    private static Map<String, List<String>> buildRegistrarFingerprints() {
        Map<String, List<String>> m = new LinkedHashMap<>();
        m.put("GoDaddy", List.of("godaddy", "ns1.godaddy.com", "ns2.godaddy.com"));
        m.put("Namecheap", List.of("namecheap", "registrar-servers.com"));
        m.put("阿里云", List.of("aliyun", "wanwang", "hichina"));
        m.put("腾讯云", List.of("dnspod", "tencent", "qcloud"));
        m.put("Cloudflare", List.of("cloudflare"));
        m.put("Name.com", List.of("name.com"));
        m.put("Gandi", List.of("gandi.net"));
        m.put("OVH", List.of("ovh.net", "ovh.com"));
        m.put("Network Solutions", List.of("networksolutions.com"));
        return m;
    }


    /** CDN 判定用的 NS 关键词，对应 Go 在 checkCDN 里的 cdnNSKeywords。 */
    private static final List<String> CDN_NS_KEYWORDS = List.of(
            "dnsv", "alidns", "dnspod", "cloudflare", "akamai", "edgecast", "limelight",
            "chinacache", "wangsu", "qcloud", "huaweicloud");

    /** Go 的 {@code freeclient/3.0}（按移植约定保留原值，不做品牌替换）。 */
    private static final String CDN_USER_AGENT = "freeclient/3.0";

    // =====================================================================
    // HTTP 客户端与扫描入口
    // =====================================================================

    /** 构建 HTTP 客户端，对应 Go 的 {@code NewHTTPClient}（不跟随重定向 + SkipVerify）。 */
    public static HttpClient newHTTPClient(Duration timeout) {
        HttpClient.Builder builder = HttpClient.newBuilder();
        if (timeout != null && !timeout.isZero() && !timeout.isNegative()) {
            builder.connectTimeout(timeout);
        }
        // Go: CheckRedirect 返回 http.ErrUseLastResponse（不跟随重定向）
        builder.followRedirects(HttpClient.Redirect.NEVER);
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
            builder.sslContext(ctx);
            if (System.getProperty("jdk.internal.httpclient.disableHostnameVerification") == null) {
                System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
            }
        } catch (Exception ignored) {
            // 与 Go 一致：TLS 配置失败不应阻断识别流程，退化为默认校验
        }
        return builder.build();
    }

    /** CDN / 云 / 注册商识别入口，对应 Go 的 {@code CDNScan}。 */
    public static CdnResult cdnScan(CdnConfig config) {
        long startNanos = System.nanoTime();
        CdnResult result = new CdnResult();
        result.target = config.target;
        result.confidence = 0;

        String target = cleanTarget(config.target);

        if (config.enableCdnCheck) {
            checkCDN(target, result, config.timeout);
        }
        if (config.enableCloudCheck) {
            checkCloudProvider(target, result);
        }
        if (config.enableRegistrarCheck) {
            checkRegistrar(target, result);
        }

        result.duration = Duration.ofNanos(Math.max(0L, System.nanoTime() - startNanos));
        return result;
    }

    /** 清洗目标（去协议 / 路径 / 端口），对应 Go 的 {@code cleanTarget}。 */
    static String cleanTarget(String target) {
        String t = target == null ? "" : target.trim();
        if (t.startsWith("http://")) {
            t = t.substring("http://".length());
        }
        if (t.startsWith("https://")) {
            t = t.substring("https://".length());
        }
        int slash = t.indexOf('/');
        if (slash >= 0) {
            t = t.substring(0, slash);
        }
        int colon = t.indexOf(':');
        if (colon >= 0) {
            t = t.substring(0, colon);
        }
        return t;
    }

    /** CDN 检测，对应 Go 的 {@code checkCDN}。 */
    private static void checkCDN(String target, CdnResult result, Duration timeout) {
        String cname = CdnDns.lookupCNAME(target);
        if (cname != null && !cname.isEmpty()) {
            result.cname = cname;
            Match match = matchFingerprints(cname, "cname", CDN_FINGERPRINTS);
            if (match.matched) {
                result.isCDN = true;
                result.cdnName = match.fp.name;
                result.cdnVendor = match.fp.vendor;
                result.cdnEvidence = Fmt.format("CNAME包含: %s", match.pattern);
                result.confidence += 60;
            }
        }

        List<String> ips = CdnDns.lookupA(target);
        if (!ips.isEmpty()) {
            result.ips = ips;
            if (ips.size() >= 3) {
                if (!result.isCDN) {
                    result.isCDN = true;
                    result.cdnName = "多IP解析";
                    result.cdnVendor = "可能使用CDN";
                    result.cdnEvidence = Fmt.format("解析出 %d 个IP地址", ips.size());
                }
                result.confidence += 25;
            }
        }

        List<String> nsRecords = CdnDns.lookupNS(target);
        if (!nsRecords.isEmpty()) {
            result.nameServers = nsRecords;
            String nsLower = String.join(" ", nsRecords).toLowerCase(Locale.ROOT);
            for (String keyword : CDN_NS_KEYWORDS) {
                if (nsLower.contains(keyword)) {
                    if (!result.isCDN) {
                        result.isCDN = true;
                        result.cdnName = "CDN特征NS记录";
                        result.cdnVendor = "可能使用CDN";
                        result.cdnEvidence = Fmt.format("NS记录包含: %s", keyword);
                    }
                    result.confidence += 20;
                    break;
                }
            }
        }

        Map<String, List<String>> headers = getHTTPHeaders(target, timeout);
        if (headers != null) {
            result.httpHeaders = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                result.httpHeaders.put(e.getKey(), String.join(", ", e.getValue()));
            }

            String headerStr = headersToString(headers);
            Match match = matchFingerprints(headerStr, "header", CDN_FINGERPRINTS);
            if (match.matched) {
                result.isCDN = true;
                if (result.cdnName.isEmpty() || "多IP解析".equals(result.cdnName)
                        || "CDN特征NS记录".equals(result.cdnName)) {
                    if ("CDN特征".equals(match.fp.vendor)) {
                        String actualHeaderValue = "";
                        String patternLower = match.pattern.toLowerCase(Locale.ROOT);
                        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                            String keyLower = e.getKey().toLowerCase(Locale.ROOT);
                            if (patternLower.contains(keyLower) || keyLower.contains(patternLower)) {
                                actualHeaderValue = Fmt.format("%s: %s", e.getKey(),
                                        String.join(", ", e.getValue()));
                                break;
                            }
                        }
                        if (!actualHeaderValue.isEmpty()) {
                            result.cdnName = "HTTP缓存服务";
                            result.cdnVendor = "CDN特征";
                            result.cdnEvidence = actualHeaderValue;
                        } else {
                            result.cdnName = match.fp.name;
                            result.cdnVendor = match.fp.vendor;
                            result.cdnEvidence = Fmt.format("HTTP头包含: %s", match.pattern);
                        }
                    } else {
                        result.cdnName = match.fp.name;
                        result.cdnVendor = match.fp.vendor;
                        result.cdnEvidence = Fmt.format("HTTP头包含: %s", match.pattern);
                    }
                }
                result.confidence += 40;
            }
        }
    }

    /** 云服务商检测，对应 Go 的 {@code checkCloudProvider}。 */
    private static void checkCloudProvider(String target, CdnResult result) {
        if (!result.cname.isEmpty()) {
            Match match = matchFingerprints(result.cname, "cname", CLOUD_PROVIDER_FINGERPRINTS);
            if (match.matched) {
                result.cloudProvider = match.fp.name;
                result.confidence += 30;
            }
        }

        if (!result.ips.isEmpty()) {
            for (String ip : result.ips) {
                String ptr = CdnDns.lookupPTR(ip);
                if (ptr != null && !ptr.isEmpty()) {
                    Match match = matchFingerprints(ptr, "ip", CLOUD_PROVIDER_FINGERPRINTS);
                    if (match.matched) {
                        if (result.cloudProvider.isEmpty()) {
                            result.cloudProvider = match.fp.name;
                        }
                        result.confidence += 20;
                        break;
                    }
                }
            }
        }
    }

    /** 注册商检测，对应 Go 的 {@code checkRegistrar}。 */
    private static void checkRegistrar(String target, CdnResult result) {
        if (result.nameServers.isEmpty()) {
            List<String> nsRecords = CdnDns.lookupNS(target);
            if (!nsRecords.isEmpty()) {
                result.nameServers = nsRecords;
            }
        }
        if (!result.nameServers.isEmpty()) {
            String nsStr = String.join(" ", result.nameServers).toLowerCase(Locale.ROOT);
            for (Map.Entry<String, List<String>> e : REGISTRAR_FINGERPRINTS.entrySet()) {
                boolean matched = false;
                for (String pattern : e.getValue()) {
                    if (nsStr.contains(pattern.toLowerCase(Locale.ROOT))) {
                        result.registrar = e.getKey();
                        result.confidence += 25;
                        matched = true;
                        break;
                    }
                }
                if (matched) {
                    break;
                }
            }
        }

        if (result.registrar.isEmpty()) {
            WhoisResult whoisResult = Whois.whois(target);
            if (whoisResult.error == null && whoisResult.raw != null && !whoisResult.raw.isEmpty()) {
                WhoisInfo parsed = WhoisParser.parse(target, whoisResult.raw);
                if (parsed != null && parsed.registrar != null && !parsed.registrar.name.isEmpty()) {
                    result.registrar = parsed.registrar.name;
                    result.confidence += 35;
                } else {
                    String whoisLower = whoisResult.raw.toLowerCase(Locale.ROOT);
                    for (Map.Entry<String, List<String>> e : REGISTRAR_FINGERPRINTS.entrySet()) {
                        boolean matched = false;
                        for (String pattern : e.getValue()) {
                            if (whoisLower.contains(pattern.toLowerCase(Locale.ROOT))) {
                                result.registrar = e.getKey();
                                result.confidence += 20;
                                matched = true;
                                break;
                            }
                        }
                        if (matched) {
                            break;
                        }
                    }
                }
            }
        }
    }

    // =====================================================================
    // HTTP 头获取与指纹匹配
    // =====================================================================

    /**
     * 获取目标 HTTP 响应头，对应 Go 的 {@code getHTTPHeaders}：
     * 先试 {@code https://}，再回退 {@code http://}，两者都失败才返回 null。
     */
    static Map<String, List<String>> getHTTPHeaders(String target, Duration timeout) {
        HttpClient client = newHTTPClient(timeout);

        List<String> urls = List.of("https://" + target, "http://" + target);

        for (String url : urls) {
            try {
                HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(url))
                        .method("HEAD", HttpRequest.BodyPublishers.noBody())
                        .header("User-Agent", CDN_USER_AGENT);
                if (timeout != null && !timeout.isZero() && !timeout.isNegative()) {
                    rb.timeout(timeout);
                }
                HttpResponse<Void> resp = client.send(rb.build(),
                        HttpResponse.BodyHandlers.discarding());
                // Go 只判 err：任何状态码（含 3xx/4xx/5xx）都返回响应头
                return new TreeMap<>(resp.headers().map());
            } catch (Exception e) {
                // 尝试下一个协议（与 Go 的 continue 一致）
            }
        }

        return null;
    }

    /**
     * 把响应头拼成待匹配文本，对应 Go 的 {@code headersToString}：
     * {@code lowercase(key) + ": " + join(values, ", ") + "\n"}，整体再转小写。
     *
     * <p>Go 遍历 map 顺序随机；这里用已排序的 TreeMap 保证确定性，
     * 不影响匹配结果（匹配取决于指纹表的顺序而非文本顺序）。
     */
    private static String headersToString(Map<String, List<String>> headers) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            sb.append(e.getKey().toLowerCase(Locale.ROOT));
            sb.append(": ");
            sb.append(String.join(", ", e.getValue()));
            sb.append('\n');
        }
        return sb.toString().toLowerCase(Locale.ROOT);
    }

    /** 指纹匹配结果，对应 Go 的 {@code (bool, CDNFingerprint, string)} 三元返回。 */
    static final class Match {
        final boolean matched;
        final CdnFingerprint fp;
        final String pattern;

        Match(boolean matched, CdnFingerprint fp, String pattern) {
            this.matched = matched;
            this.fp = fp;
            this.pattern = pattern;
        }
    }

    /**
     * 指纹匹配，对应 Go 的 {@code matchFingerprints}：
     * 精确指纹优先返回；「自建CDN」/「CDN特征」这类泛化指纹只在无精确命中时作为兜底。
     */
    static Match matchFingerprints(String input, String fpType, List<CdnFingerprint> fingerprints) {
        String inputLower = input == null ? "" : input.toLowerCase(Locale.ROOT);
        CdnFingerprint genericMatch = null;
        String genericPattern = "";

        for (CdnFingerprint fp : fingerprints) {
            if (!fp.type.equals(fpType)) {
                continue;
            }

            if ("自建CDN".equals(fp.name) || "CDN特征".equals(fp.vendor)) {
                for (String pattern : fp.patterns) {
                    if (inputLower.contains(pattern.toLowerCase(Locale.ROOT))) {
                        if (genericMatch == null) {
                            genericMatch = fp;
                            genericPattern = pattern;
                        }
                        break;
                    }
                }
                continue;
            }

            for (String pattern : fp.patterns) {
                if (inputLower.contains(pattern.toLowerCase(Locale.ROOT))) {
                    return new Match(true, fp, pattern);
                }
            }
        }

        if (genericMatch != null) {
            return new Match(true, genericMatch, genericPattern);
        }

        return new Match(false, null, "");
    }

    // =====================================================================
    // 结果格式化（对应 Go 的 FormatResult）
    // =====================================================================

    /** 格式化识别结果，逐行对应 Go 的 {@code FormatResult}。 */
    public static String formatResult(CdnResult result) {
        StringBuilder out = new StringBuilder();

        out.append("=== CDN & Cloud 识别结果 ===\n");
        out.append(Fmt.format("目标: %s\n", result.target));
        out.append(Fmt.format("耗时: %v\n\n", result.duration));

        if (!result.errorMessage.isEmpty()) {
            out.append(Fmt.format("错误: %s\n", result.errorMessage));
        }

        if (result.isCDN) {
            out.append(Colors.success("✓ 检测到 CDN\n"));
            if (!result.cdnName.isEmpty()) {
                out.append(Fmt.format("  CDN 服务商: %s\n", result.cdnName));
            }
            if (!result.cdnVendor.isEmpty()) {
                out.append(Fmt.format("  CDN 厂商: %s\n", result.cdnVendor));
            }
            if (!result.cdnEvidence.isEmpty()) {
                out.append(Fmt.format("  证据: %s\n", result.cdnEvidence));
            }
        } else {
            out.append(Colors.warning("✗ 未检测到明显 CDN 特征\n"));
        }

        if (!result.cloudProvider.isEmpty()) {
            out.append(Fmt.format("\n云服务提供商: %s\n", result.cloudProvider));
        }

        if (!result.registrar.isEmpty()) {
            out.append(Fmt.format("\n域名注册商: %s\n", result.registrar));
        }

        if (!result.cname.isEmpty()) {
            out.append(Fmt.format("\nCNAME 记录: %s\n", result.cname));
        }

        if (!result.ips.isEmpty()) {
            out.append("\n解析 IP:\n");
            for (String ip : result.ips) {
                out.append(Fmt.format("  - %s\n", ip));
            }
        }

        if (!result.nameServers.isEmpty()) {
            out.append("\n名称服务器 (NS):\n");
            for (String ns : result.nameServers) {
                out.append(Fmt.format("  - %s\n", ns));
            }
        }

        if (result.confidence > 0) {
            out.append(Fmt.format("\n置信度: %d%%\n", result.confidence));
        }

        return out.toString();
    }

    private Cdn() {
    }
}

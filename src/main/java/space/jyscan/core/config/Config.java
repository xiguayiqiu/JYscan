package space.jyscan.core.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 配置结构，对应 internal/config/config.go 的 Config 及其子结构。
 *
 * <p>JSON 字段名与 Go 结构体 tag 完全一致，因此存量 config.json 可直接复用。
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Config {

    @JsonProperty("global")
    public GlobalConfig global = new GlobalConfig();

    @JsonProperty("scan")
    public ScanConfig scan = new ScanConfig();

    @JsonProperty("output")
    public OutputConfig output = new OutputConfig();

    @JsonProperty("proxy")
    public ProxyConfig proxy = new ProxyConfig();

    @JsonProperty("rate_limit")
    public RateLimitConfig rateLimit = new RateLimitConfig();

    @JsonProperty("ai")
    public AIConfig ai = new AIConfig();

    // =====================================================================

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GlobalConfig {
        @JsonProperty("version") public String version = "v2.9";
        @JsonProperty("instance_id") public String instanceId = "";
        @JsonProperty("timeout") public int timeout = 30;
        @JsonProperty("retries") public int retries = 3;
        @JsonProperty("workers") public int workers = 10;
        @JsonProperty("user_agent") public String userAgent = "freeclient/v2.9";
        @JsonProperty("no_banner") public boolean noBanner;
        @JsonProperty("no_color") public boolean noColor;
        @JsonProperty("silent") public boolean silent;
        @JsonProperty("verbose") public boolean verbose;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ScanConfig {
        @JsonProperty("port_range") public String portRange = "1-65535";
        @JsonProperty("common_ports") public List<Integer> commonPorts = new ArrayList<>(
                Arrays.asList(21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
                        3306, 3389, 5432, 6379, 8080, 8443));
        @JsonProperty("timeout") public int timeout = 3;
        @JsonProperty("concurrent") public int concurrent = 100;
        @JsonProperty("rate_limit") public int rateLimit = 1000;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OutputConfig {
        @JsonProperty("format") public String format = "text";
        @JsonProperty("output_file") public String outputFile = "";
        @JsonProperty("json_indent") public int jsonIndent = 2;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ProxyConfig {
        @JsonProperty("http") public String http = "";
        @JsonProperty("https") public String https = "";
        @JsonProperty("socks5") public String socks5 = "";
        @JsonProperty("username") public String username = "";
        @JsonProperty("password") public String password = "";
        @JsonProperty("skip_verify") public boolean skipVerify;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class RateLimitConfig {
        @JsonProperty("requests_per_second") public int requestsPerSecond = 500;
        @JsonProperty("burst") public int burst = 20;
        @JsonProperty("connection_timeout") public int connectionTimeout = 10;
        @JsonProperty("read_timeout") public int readTimeout = 30;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AIConfig {
        @JsonProperty("enabled") public boolean enabled;
        @JsonProperty("provider") public String provider = "ollama";
        @JsonProperty("api_key") public String apiKey = "";
        @JsonProperty("base_url") public String baseUrl = "";
        @JsonProperty("model") public String model = "llama2";
        @JsonProperty("temperature") public float temperature = 0.7f;
        @JsonProperty("max_tokens") public int maxTokens = 2000;
        @JsonProperty("timeout") public int timeout = 60;
        @JsonProperty("skills_enabled") public boolean skillsEnabled = true;
        @JsonProperty("use_ollama") public boolean useOllama = true;
        @JsonProperty("ollama_url") public String ollamaUrl = "http://localhost:11434";
        @JsonProperty("ollama_model") public String ollamaModel = "llama2";
        @JsonProperty("use_lmstudio") public boolean useLmstudio;
        @JsonProperty("lmstudio_url") public String lmstudioUrl = "http://localhost:1234/v1";
        @JsonProperty("lmstudio_model") public String lmstudioModel = "local-model";
        @JsonProperty("search_enabled") public boolean searchEnabled;
        @JsonProperty("search_engine") public String searchEngine = "deepseek";
        @JsonProperty("search_top_n") public int searchTopN = 10;
        @JsonProperty("python_agent_url") public String pythonAgentUrl = "http://127.0.0.1:8765";
    }

    // =====================================================================
    // 默认配置
    // =====================================================================

    public static Config defaultConfig() {
        Config c = new Config();
        c.global = new GlobalConfig();
        c.global.version = "v2.9";
        c.global.instanceId = space.jyscan.core.binding.MachineBinder.newInstance().getInstanceID();
        c.global.timeout = 30;
        c.global.retries = 3;
        c.global.workers = 10;
        c.global.userAgent = "freeclient/v2.9";
        return c;
    }

    // =====================================================================
    // 校验（对应 Config.Validate）
    // =====================================================================

    /** @return 错误信息；校验通过返回 null */
    public String validate() {
        if (global.timeout <= 0) {
            return "timeout must be positive, got " + global.timeout;
        }
        if (global.retries < 0) {
            return "retries must be non-negative, got " + global.retries;
        }
        if (global.workers <= 0) {
            return "workers must be positive, got " + global.workers;
        }
        if (scan.timeout <= 0) {
            return "scan timeout must be positive, got " + scan.timeout;
        }
        if (scan.concurrent <= 0) {
            return "scan concurrent must be positive, got " + scan.concurrent;
        }
        if (scan.rateLimit <= 0) {
            return "scan rate limit must be positive, got " + scan.rateLimit;
        }
        if (rateLimit.requestsPerSecond <= 0) {
            return "rate limit requests per second must be positive, got " + rateLimit.requestsPerSecond;
        }
        if (rateLimit.burst <= 0) {
            return "rate limit burst must be positive, got " + rateLimit.burst;
        }
        if (rateLimit.connectionTimeout <= 0) {
            return "rate limit connection timeout must be positive, got " + rateLimit.connectionTimeout;
        }
        if (rateLimit.readTimeout <= 0) {
            return "rate limit read timeout must be positive, got " + rateLimit.readTimeout;
        }
        for (Integer port : scan.commonPorts) {
            if (port == null || port < 1 || port > 65535) {
                return "invalid port " + port + ": must be between 1 and 65535";
            }
        }
        return null;
    }
}

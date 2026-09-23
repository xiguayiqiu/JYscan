package space.jyscan.core.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import space.jyscan.core.util.Colors;
import space.jyscan.core.util.JsonUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;

/**
 * 配置加载 / 保存，对应 internal/config/config.go。
 *
 * <p>配置路径：{@code ~/.JYscan/config/config.json}。结构与 Go 版
 * {@code ~/.GYscan/config/config.json} 一致，但目录名随品牌改名为 {@code .JYscan}，
 * 故旧 {@code ~/.GYscan} 下的配置不会被读取（品牌改名导致的有意偏差）。
 * 环境变量 JYSCAN_TIMEOUT / JYSCAN_RETRIES / JYSCAN_WORKERS / JYSCAN_PROXY /
 * JYSCAN_USER_AGENT / JYSCAN_RATE_LIMIT / JYSCAN_SILENT / JYSCAN_VERBOSE
 * 会在加载后覆盖文件值。
 */
public final class AppConfig {

    /** 对应 Go 的 config.AppConfig 全局指针。 */
    private static volatile Config appConfig;

    private AppConfig() {
    }

    /** 对应 Go 的 GetConfigPath。 */
    public static Path getConfigPath() {
        String home = System.getProperty("user.home");
        Path configDir;
        if (home != null && !home.isEmpty()) {
            configDir = Path.of(home, ".JYscan", "config");
        } else {
            configDir = Path.of(".", "JYscan", "config");
        }
        try {
            Files.createDirectories(configDir);
        } catch (IOException ignored) {
            // 与 Go 版一致：目录创建失败不阻断，后续写入时再报错
        }
        return configDir.resolve("config.json");
    }

    /** 对应 Go 的 LoadConfig。 */
    public static Config loadConfig() throws IOException {
        Path configPath = getConfigPath();

        if (!Files.exists(configPath)) {
            Config defaultConfig = Config.defaultConfig();
            try {
                saveConfig(defaultConfig);
                return defaultConfig;
            } catch (IOException e) {
                throw new IOException("保存默认配置失败: " + e.getMessage(), e);
            }
        }

        String data = Files.readString(configPath, StandardCharsets.UTF_8);
        Config config;
        try {
            config = JsonUtil.fromJSON(data, Config.class);
        } catch (JsonProcessingException e) {
            throw new IOException("解析配置文件失败: " + e.getMessage(), e);
        }
        if (config == null) {
            throw new IOException("解析配置文件失败: 配置为空");
        }

        loadFromEnv(config);
        return config;
    }

    /** 环境变量覆盖，对应 Go 的 loadFromEnv。 */
    private static void loadFromEnv(Config cfg) {
        parseIntEnv("JYSCAN_TIMEOUT").ifPresent(v -> cfg.global.timeout = v);
        parseIntEnv("JYSCAN_RETRIES").ifPresent(v -> cfg.global.retries = v);
        parseIntEnv("JYSCAN_WORKERS").ifPresent(v -> cfg.global.workers = v);

        String v = System.getenv("JYSCAN_PROXY");
        if (v != null && !v.isEmpty()) {
            cfg.proxy.http = v;
        }
        v = System.getenv("JYSCAN_USER_AGENT");
        if (v != null && !v.isEmpty()) {
            cfg.global.userAgent = v;
        }
        parseIntEnv("JYSCAN_RATE_LIMIT").ifPresent(v2 -> cfg.rateLimit.requestsPerSecond = v2);

        v = System.getenv("JYSCAN_SILENT");
        if (v != null) {
            cfg.global.silent = "true".equals(v.toLowerCase(Locale.ROOT));
        }
        v = System.getenv("JYSCAN_VERBOSE");
        if (v != null) {
            cfg.global.verbose = "true".equals(v.toLowerCase(Locale.ROOT));
        }
    }

    private static java.util.Optional<Integer> parseIntEnv(String key) {
        String v = System.getenv(key);
        if (v == null || v.isEmpty()) {
            return java.util.Optional.empty();
        }
        try {
            return java.util.Optional.of(Integer.parseInt(v.trim()));
        } catch (NumberFormatException e) {
            return java.util.Optional.empty();
        }
    }

    /** 对应 Go 的 SaveConfig，写入 0600 权限。 */
    public static void saveConfig(Config config) throws IOException {
        Path configPath = getConfigPath();
        String data;
        try {
            data = JsonUtil.MAPPER.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(config);
        } catch (JsonProcessingException e) {
            throw new IOException("序列化配置失败: " + e.getMessage(), e);
        }

        Files.writeString(configPath, data, StandardCharsets.UTF_8);
        // 仅文件所有者可读写，保护敏感配置信息（与 Go 的 0600 一致）
        try {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(configPath, perms);
        } catch (UnsupportedOperationException | IOException ignored) {
            // 非 POSIX 文件系统（如 Windows）忽略
        }
    }

    /** 对应 Go 的 InitConfig。 */
    public static synchronized boolean initConfig() {
        try {
            Config cfg = loadConfig();
            String err = cfg.validate();
            if (err != null) {
                Colors.logWarning("配置验证失败: %s", err);
                return false;
            }
            appConfig = cfg;
            return true;
        } catch (IOException e) {
            Colors.logWarning("配置加载失败，使用默认配置: %s", e.getMessage());
            appConfig = Config.defaultConfig();
            return false;
        }
    }

    // =====================================================================
    // 访问器（对应 Go 的 GetXxxConfig，未初始化时回退默认值）
    // =====================================================================

    public static Config get() {
        Config c = appConfig;
        return c != null ? c : Config.defaultConfig();
    }

    public static Config.GlobalConfig getGlobalConfig() {
        return get().global;
    }

    public static Config.ScanConfig getScanConfig() {
        return get().scan;
    }

    public static Config.ProxyConfig getProxyConfig() {
        return get().proxy;
    }

    public static Config.RateLimitConfig getRateLimitConfig() {
        return get().rateLimit;
    }

    public static Config.AIConfig getAIConfig() {
        return get().ai;
    }

    public static boolean isInitialized() {
        return appConfig != null;
    }

    /** 对应 Go 的 SaveAIConfig。 */
    public static synchronized void saveAIConfig(Config.AIConfig ai) throws IOException {
        Config c = appConfig;
        if (c == null) {
            initConfig();
            c = appConfig;
        }
        if (c == null) {
            c = Config.defaultConfig();
        }
        c.ai = ai;
        saveConfig(c);
    }
}

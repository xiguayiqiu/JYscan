package space.jyscan.core.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * 嵌入式资源读取，对应 Go 的 //go:embed 与 internal/utils/embed.go。
 *
 * <p>资源在 pom.xml 中由 freeclient/internal/utils/embed_resources 映射到
 * classpath 的 embed_resources/ 下。
 */
public final class Embedded {

    private static final String PREFIX = "/embed_resources/";

    private Embedded() {
    }

    /** 加载嵌入的 WAF 规则文件。 */
    public static byte[] loadWAFRules() throws IOException {
        return readResource(PREFIX + "waf_rules.json");
    }

    /** 加载嵌入的目录扫描字典。 */
    public static byte[] loadDirscanDict(String filename) throws IOException {
        return readResource(PREFIX + filename);
    }

    public static String loadDirscanDictText(String filename) throws IOException {
        return new String(loadDirscanDict(filename), StandardCharsets.UTF_8);
    }

    /**
     * 把嵌入资源提取到临时目录，返回目录路径。
     * 对应 Go 的 ExtractEmbeddedFiles。
     */
    public static String extractEmbeddedFiles() throws IOException {
        Path tempDir = Files.createTempDirectory("jyscan_embedded");
        try {
            Files.write(tempDir.resolve("waf_rules.json"), loadWAFRules());
        } catch (IOException ignored) {
            // 与 Go 版一致：提取失败不致命
        }
        for (String filename : new String[]{"dicc.txt", "medium.txt"}) {
            try {
                Files.write(tempDir.resolve(filename), loadDirscanDict(filename));
            } catch (IOException ignored) {
            }
        }
        return tempDir.toString();
    }

    /** choice: "1" -> dicc.txt, "2" -> medium.txt，对应 Go 的 GetEmbeddedDictPath。 */
    public static String getEmbeddedDictPath(String choice) throws IOException {
        String tempDir = extractEmbeddedFiles();
        return switch (choice) {
            case "1" -> Path.of(tempDir, "dicc.txt").toString();
            case "2" -> Path.of(tempDir, "medium.txt").toString();
            default -> "";
        };
    }

    private static byte[] readResource(String name) throws IOException {
        try (InputStream in = Embedded.class.getResourceAsStream(name)) {
            if (in == null) {
                throw new IOException("资源不存在: " + name);
            }
            return in.readAllBytes();
        }
    }
}

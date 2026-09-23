package space.jyscan.core.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * JSON 工具，对应 internal/utils/json.go（Go encoding/json）。
 *
 * <p>与 Go 一致采用两空格缩进；未知字段忽略，以兼容 Go 结构体里
 * {@code omitempty} 之外的多余字段。
 */
public final class JsonUtil {

    public static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(SerializationFeature.INDENT_OUTPUT, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, false);

    static {
        MAPPER.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, true);
    }

    private JsonUtil() {
    }

    /** 序列化为缩进 JSON。 */
    public static String toJSON(Object v) throws JsonProcessingException {
        return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(v);
    }

    /** 序列化，失败返回 null（避免样板 try/catch）。 */
    public static String toJSONQuietly(Object v) {
        try {
            return toJSON(v);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    /** 反序列化。 */
    public static <T> T fromJSON(String jsonStr, Class<T> cls) throws JsonProcessingException {
        return MAPPER.readValue(jsonStr, cls);
    }

    public static <T> T fromJSON(byte[] json, Class<T> cls) throws IOException {
        return MAPPER.readValue(json, cls);
    }

    /** 美化 JSON 字符串。 */
    public static String prettyJSON(String jsonStr) throws JsonProcessingException {
        Object v = MAPPER.readValue(jsonStr, Object.class);
        return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(v);
    }

    /** 保存对象为 JSON 文件（0644 权限语义与 Go 一致）。 */
    public static void saveJSON(String filename, Object v) throws IOException {
        String json = toJSON(v);
        Files.writeString(Path.of(filename), json, StandardCharsets.UTF_8);
    }
}

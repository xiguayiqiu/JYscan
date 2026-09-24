package space.jyscan.core.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 用户列表文件（字典/目标清单）读取工具。
 *
 * <p>Go 版直接按字节逐行读取，不涉及字符编码；Java 的
 * {@code Files.readAllLines(path, UTF_8)} 遇到非法 UTF-8 字节会抛
 * {@code MalformedInputException}（报错形如 "Input length = 1"），
 * 导致混合编码/GBK/Latin-1 字典直接让扫描器创建失败。
 *
 * <p>这里按 UTF-8 → GB18030 → ISO-8859-1 的顺序尝试严格解码，
 * 全部失败时以 ISO-8859-1 兜底（单字节映射永不失败，且能原样
 * 往返字节），保证任何编码的字典都不会让扫描中断。
 */
public final class TextFiles {

    /** 严格解码候选：先 UTF-8（标准），再 GB18030（GBK/GB 系中文）。 */
    private static final Charset[] CANDIDATES = {
        StandardCharsets.UTF_8,
        Charset.forName("GB18030"),
    };

    private TextFiles() {
    }

    /**
     * 宽容解码字节序列：依次严格尝试候选字符集，全失败则按 ISO-8859-1 兜底。
     *
     * @param data 原始文件字节
     * @return 解码后的文本（永不抛异常）
     */
    public static String decode(byte[] data) {
        for (Charset cs : CANDIDATES) {
            try {
                return cs.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(data))
                        .toString();
            } catch (CharacterCodingException ignored) {
                // 尝试下一个候选字符集
            }
        }
        // ISO-8859-1 单字节全覆盖：保留原始字节值，不会失败
        return new String(data, StandardCharsets.ISO_8859_1);
    }

    /**
     * 宽容读取文本文件的所有行。
     *
     * <p>行拆分语义与 {@code Files.readAllLines} 一致：支持 \r\n、\n、\r。
     *
     * @param file 文件路径
     * @return 全部行（不含行终止符）
     * @throws IOException 文件不存在或不可读
     */
    public static List<String> readLines(Path file) throws IOException {
        String text = decode(Files.readAllBytes(file));
        List<String> lines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new StringReader(text))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
        }
        return lines;
    }
}

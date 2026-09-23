package space.jyscan.modules.nmap;

/**
 * 内容探测的单端口结果，移植自 freeclient/internal/nmap/content_probe.go 的 ContentProbeResult。
 *
 * <p>Go 侧无 json tag（结果被回填进 {@link PortInfo} 后才参与序列化），故不加 Jackson 注解。
 * 由 C 号子代理实现。
 *
 * <p><b>{@link #content} 的表示（重要）</b>：Go 的 {@code string} 就是「原始字节序列」，
 * 回复判定（{@code Match}）与展示（hexdump、可读字符串提取、二进制占比）全部按字节进行。
 * Java 的 {@code String} 是 UTF-16，无法原样承载任意字节，故本字段统一采用
 * <b>latin1（ISO-8859-1）字节视图</b>：第 {@code i} 个 char 的低 8 位 == 回复的第 {@code i} 个字节。
 * 于是 {@code content.length()} == Go 的 {@code len(reply)}，所有逐字节操作逐位等价
 * （包括 {@code \xffSMB} 之类含高位字节的匹配、hexdump 的逐字节输出）。
 *
 * <p>对外输出时再做转换（都与 Go 逐字节一致）：
 * <ul>
 *   <li>回填 {@link PortInfo#content}（进 JSON）：按 UTF-8 解码、非法序列替换为 U+FFFD，
 *       等价 Go {@code encoding/json} 对 string 的强制转换；</li>
 *   <li>终端打印：展示前先经 {@code formatContentForDisplay} 按 UTF-8 解码（非法序列
 *       替换为 U+FFFD，等价 Go {@code range} 产出 RuneError 后 {@code WriteRune}），
 *       再按 UTF-8 写出，与 Go {@code fmt.Print} 写 UTF-8 字节一致。</li>
 * </ul>
 */
public class ContentProbeResult {

    /** 识别出的协议 (raw 表示未识别) */
    public String protocol = "";
    /** 命中的探测器名称 */
    public String probe = "";
    /** 服务回复的原始内容（latin1 字节视图，见类注释） */
    public String content = "";

    /** 空结果，等价 Go 的零值 {@code ContentProbeResult{}}。 */
    public ContentProbeResult() {
    }

    public ContentProbeResult(String protocol, String probe, String content) {
        this.protocol = protocol == null ? "" : protocol;
        this.probe = probe == null ? "" : probe;
        this.content = content == null ? "" : content;
    }
}

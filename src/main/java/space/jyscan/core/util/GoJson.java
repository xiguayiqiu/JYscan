package space.jyscan.core.util;

import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.core.util.Separators;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.util.Comparator;

/**
 * 复刻 Go {@code encoding/json} 的 {@code json.MarshalIndent(v, "", "  ")} 输出格式。
 *
 * <p>不能直接用 {@link JsonUtil#toJSON}，因为 Jackson 默认格式与 Go 有四处差异
 *（均以字节级 dump 与 Go 实测比对确认）：
 * <table border="1">
 *   <caption>Go vs Jackson 默认</caption>
 *   <tr><th>项</th><th>Go</th><th>Jackson 默认</th></tr>
 *   <tr><td>键值冒号</td><td>{@code "k": v}</td><td>{@code "k" : v}</td></tr>
 *   <tr><td>空数组</td><td>{@code []}</td><td>{@code [ ]}</td></tr>
 *   <tr><td>空对象</td><td>{@code {}}</td><td>{@code { }}</td></tr>
 *   <tr><td>数组元素</td><td>每元素独占一行</td><td>内联 {@code [ "a", "b" ]}</td></tr>
 * </table>
 *
 * <p><b>三个易错参数</b>（踩坑记录，改动前先看这里）：
 * <ul>
 *   <li>{@link DefaultIndenter} 的实参顺序是 <b>(indent, eol)</b> —— 必须
 *       {@code new DefaultIndenter("  ", "\n")}。传成 {@code ("\n", "  ")} 会得到
 *       缩进与换行颠倒的错位输出。</li>
 *   <li>{@link Separators#withObjectEmptySeparator} / {@link Separators#withArrayEmptySeparator}
 *       是插在括号<b>内侧</b>的字符串，{@link Separators} 默认值为 {@code " "}
 *       （这正是 {@code [ ]} 的来源）。要得到 Go 的 {@code []}/{@code {}} 必须传
 *       <b>{@code ""}</b>；传 {@code "[]"} 会得到 {@code [[]]}。</li>
 *   <li>冒号空格由 {@link Separators#withObjectFieldValueSpacing} 控制，
 *       用 {@link Separators.Spacing#AFTER}（冒号后一个空格）；条目/数组间距用 {@code NONE}，
 *       换行交给 indenter。</li>
 * </ul>
 *
 * <p>已知同型实现：{@code pocli/commands/WafCommand#goPrettyPrinter} 是本类的早期局部版本，
 * 少了空分隔符的修正（空容器仍输出 {@code [ ]}/{@code { }}）。新增的 Go 格式化输出请统一用本类；
 * 既有调用点的迁移留待后续批次，以免在功能移植期间改动已验证的输出。
 *
 * <p>本类只负责<b>格式</b>；<b>map 键顺序</b>由各自的 map 实现负责——Go 的 encoding/json
 * 按键的<b>字符串形式</b>升序（实测 {@code map[int]} 得 {@code 1000, 22, 443, 7, 80, 8080}，
 * 既非插入序也非数值序），整型键 map 请用 {@link #goIntKeyOrder()} 建 TreeMap。
 */
public final class GoJson {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, false);

    private GoJson() {
    }

    /** Go 语义的整型键排序器：按十进制字符串升序，复现 encoding/json 的 map 键顺序。 */
    public static Comparator<Integer> goIntKeyOrder() {
        return (a, b) -> Integer.toString(a).compareTo(Integer.toString(b));
    }

    /**
     * 构造 Go 语义的 pretty printer（两空格缩进、LF 换行）。
     *
     * <p>每次返回新实例：{@code DefaultPrettyPrinter} 携带嵌套深度状态，不可跨序列化复用。
     */
    public static DefaultPrettyPrinter printer() {
        // 实参顺序为 (indent, eol)——见类注释。
        DefaultIndenter nl = new DefaultIndenter("  ", "\n");
        Separators sep = new Separators()
                .withObjectFieldValueSpacing(Separators.Spacing.AFTER)
                .withObjectEntrySpacing(Separators.Spacing.NONE)
                .withArrayValueSpacing(Separators.Spacing.NONE)
                .withObjectEmptySeparator("")
                .withArrayEmptySeparator("");
        return new DefaultPrettyPrinter(sep)
                .withObjectIndenter(nl)
                .withArrayIndenter(nl);
    }

    /**
     * 以 Go {@code json.Marshal(v)} 的格式序列化：单行紧凑，键值冒号后无空格
     * （{@code {"a":1,"b":[1,2]}}），空容器 {@code {}}/{@code []}。
     *
     * <p>map 键顺序仍由 map 实现负责（Go 的 Marshal 会按键升序，需要排序时用
     * {@link java.util.TreeMap}）。与 {@link #marshalIndent} 一样不做 Go 默认的
     * HTML 转义；需要逐位复刻 Go 时由调用方自行处理。
     *
     * @return 序列化结果；失败返回 {@code null}（对应 Go {@code data, _ :=} 丢弃 error）
     */
    public static String marshal(Object v) {
        try {
            return MAPPER.writeValueAsString(v);
        } catch (IOException e) {
            return null;
        }
    }

    /** 以 Go {@code json.MarshalIndent(v, "", "  ")} 的格式序列化。 */
    public static String marshalIndent(Object v) throws IOException {
        return MAPPER.writer(printer()).writeValueAsString(v);
    }

    /** 同上，失败时返回 {@code null}（避免调用方样板 try/catch）。 */
    public static String marshalIndentQuietly(Object v) {
        try {
            return marshalIndent(v);
        } catch (IOException e) {
            return null;
        }
    }
}

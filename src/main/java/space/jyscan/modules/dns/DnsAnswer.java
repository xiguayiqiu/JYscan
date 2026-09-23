package space.jyscan.modules.dns;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * DNS 应答记录，对应 Go 的 {@code dns.DNSAnswer}。
 *
 * <p>字段名与 Go 的 json tag 一一对应（{@code name}/{@code type}/{@code class}/{@code ttl}/{@code value}）。
 * {@code class} 是 Java 关键字，故用字段名 {@code cls} + {@link JsonProperty} 映射。
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class DnsAnswer {

    /** 记录名称（去尾点）。 */
    public String name = "";

    /** 记录类型。 */
    public String type = "";

    /** 记录类别（JSON 里为 {@code class}）。 */
    @JsonProperty("class")
    public String cls = "";

    /** 生存时间。 */
    public long ttl;

    /** 记录值。 */
    public String value = "";

    public DnsAnswer() {
    }
}

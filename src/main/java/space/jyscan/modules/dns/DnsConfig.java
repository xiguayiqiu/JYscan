package space.jyscan.modules.dns;

import java.time.Duration;

/**
 * DNS 查询配置，对应 Go 的 {@code dns.DNSConfig}。
 *
 * <p>默认值对齐 {@code cli/dns.go} 的 flag：server=8.8.8.8、port=53、
 * recordType=A、timeout=5s、trace/reverse/short 均为 false。
 */
public final class DnsConfig {

    /** 查询目标：域名；{@code reverse} 为 true 时是 IP 地址。 */
    public String domain = "";

    /** DNS 服务器地址（-s/--server）。 */
    public String server = "8.8.8.8";

    /** DNS 服务器端口（-p/--port）。 */
    public int port = 53;

    /** 记录类型（-t/--type，大写）。 */
    public String recordType = "A";

    /** 查询超时（-o/--timeout，默认 5 秒）。 */
    public Duration timeout = Duration.ofSeconds(5);

    /** 是否输出追踪信息（--trace）。 */
    public boolean trace;

    /** 是否反向查询（-x）。 */
    public boolean reverse;

    /** 是否简洁输出（--short）。 */
    public boolean shortOutput;
}

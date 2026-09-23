package space.jyscan.modules.dns;

import org.xbill.DNS.Message;

import java.time.Duration;

/**
 * DNS 查询结果，对应 Go 的 {@code dns.FullDNSResult}。
 *
 * <p>{@code Msg} 直接复用 dnsjava 的 {@link Message}，等价 Go 的 {@code *dns.Msg}。
 */
public final class FullDnsResult {

    /** 查询耗时。 */
    public Duration queryTime = Duration.ZERO;

    /** 实际使用的服务器地址，形如 {@code 8.8.8.8:53}。 */
    public String server = "";

    /** 应答消息。 */
    public Message msg;

    /** 耗时的 Go 风格串（{@code "12 msec"}），对应 QueryTimeStr。 */
    public String queryTimeStr = "";

    public FullDnsResult() {
    }

    public FullDnsResult(Duration queryTime, String server, Message msg) {
        this.queryTime = queryTime == null ? Duration.ZERO : queryTime;
        this.server = server == null ? "" : server;
        this.msg = msg;
        this.queryTimeStr = this.queryTime.toMillis() + " msec";
    }
}

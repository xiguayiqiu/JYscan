package space.jyscan.modules.subdomain;

import java.time.Duration;

/**
 * 子域名挖掘配置，对应 Go 的 {@code subdomain.SubdomainConfig}。
 *
 * <p>默认值对齐 {@code cli/sub.go} 的 flag 注册：threads=50、timeout=3s、
 * queryType="A"、verifyHTTP=true。
 */
public final class SubdomainConfig {

    /** 目标域名（已小写化）。 */
    public String domain = "";

    /** 子域名字典文件路径；空则使用内置默认字典。 */
    public String wordlist = "";

    /** 并发线程数（默认 50）。 */
    public int threads = 50;

    /** 单次 DNS 查询超时（默认 3 秒）。 */
    public Duration timeout = Duration.ofSeconds(3);

    /** 结果输出文件（空则不保存）。 */
    public String output = "";

    /** DNS 查询类型，对应 -T/--type（默认 A）。 */
    public String queryType = "A";

    /** 是否校验 HTTP 响应以过滤无效子域名，对应 -H/--http（默认启用）。 */
    public boolean verifyHTTP = true;
}

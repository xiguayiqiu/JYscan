package space.jyscan.modules.subdomain;

/**
 * 单个子域名挖掘结果，对应 Go 的 {@code subdomain.SubdomainResult}。
 *
 * <p>{@code httpStatus == 0} 表示未启用 / 未通过 HTTP 校验，
 * 输出时走 {@code "子域名 -> IP"} 分支（与 Go 判断一致）。
 */
public final class SubdomainResult {

    /** 子域名（形如 www.example.com）。 */
    public String subdomain = "";

    /** 解析出的 IP 地址；A 记录为空时为 ""。 */
    public String ip = "";

    /** HTTP 状态码；0 表示未做 HTTP 校验或校验失败。 */
    public int httpStatus;

    public SubdomainResult() {
    }

    public SubdomainResult(String subdomain, String ip) {
        this.subdomain = subdomain == null ? "" : subdomain;
        this.ip = ip == null ? "" : ip;
    }

    public SubdomainResult(String subdomain, String ip, int httpStatus) {
        this(subdomain, ip);
        this.httpStatus = httpStatus;
    }
}

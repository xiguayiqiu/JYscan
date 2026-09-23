package space.jyscan.modules.cdn;

import java.time.Duration;

/**
 * CDN 识别配置，对应 Go 的 {@code cdn.CDNConfig}。
 *
 * <p>三个开关的默认值对应 Go 命令的实现：{@code EnableCDNCheck}/{@code EnableCloudCheck}/
 * {@code EnableRegistrarCheck} 在未传 {@code --no-*} 时均为 true。这里字段默认 true，
 * 由 {@link space.jyscan.pocli.commands.CdnCommand} 依据 flag 覆盖。
 */
public final class CdnConfig {

    /** 目标域名。 */
    public String target = "";

    /** 超时时间（Go 的 --timeout，默认 5 秒）。 */
    public Duration timeout = Duration.ofSeconds(5);

    /** 是否启用 CDN 检测。 */
    public boolean enableCdnCheck = true;

    /** 是否启用云服务商检测。 */
    public boolean enableCloudCheck = true;

    /** 是否启用注册商检测。 */
    public boolean enableRegistrarCheck = true;
}

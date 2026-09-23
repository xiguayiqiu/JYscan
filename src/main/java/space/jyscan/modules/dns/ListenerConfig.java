package space.jyscan.modules.dns;

import java.util.ArrayList;
import java.util.List;

/**
 * DNS 监听器配置，对应 Go 的 {@code dns.ListenerConfig} 及其 {@code DefaultListenerConfig}。
 */
public final class ListenerConfig {

    /** 监听的网络接口名称，为空则自动选择。 */
    public String interfaceName = "";

    /** DNS 服务端口，默认 53。 */
    public int port = 53;

    /** 是否开启混杂模式。 */
    public boolean promiscuous;

    /** 抓包快照长度。 */
    public int snapshotLen = 65536;

    /** 事件缓冲通道大小。 */
    public int bufferSize = 2048;

    /** 过滤模式。 */
    public FilterMode filterMode = FilterMode.DISABLED;

    /** 过滤规则列表。 */
    public List<FilterRule> filterRules = new ArrayList<>();

    /** 持久化存储文件路径，空则不落盘。 */
    public String outputFile = "";

    /** 是否自动保存。 */
    public boolean autoSave = true;

    /** 自动保存间隔(秒)。 */
    public int autoSaveInterval = 30;

    /** 内存中最大记录数。 */
    public int maxRecords = 10000;

    /** 监听超时(秒)，0 表示无限制。 */
    public int timeout;

    /** 是否输出调试信息。 */
    public boolean verbose;

    /** 对应 Go 的 {@code DefaultListenerConfig()}。 */
    public static ListenerConfig defaultConfig() {
        return new ListenerConfig();
    }
}

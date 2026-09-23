package space.jyscan.modules.dirscan;

import java.time.Duration;
import java.util.List;

/**
 * 目录扫描配置，移植自 freeclient/internal/dirscan/dirscan.go 的 ScanConfig 结构体。
 *
 * <p>字段保持与 Go 一致（公开字段、同名语义），由 cli/dirscan.go 的命令层填充。
 */
public class ScanConfig {

    /** 目标URL */
    public String url = "";

    /** 字典文件路径 */
    public String wordlist = "";

    /** 并发线程数 */
    public int threads = 20;

    /** 请求超时时间 */
    public Duration timeout = Duration.ofSeconds(10);

    /** 自定义User-Agent（空则使用默认值） */
    public String userAgent = "";

    /** 扫描的扩展名列表（可为 null，与 Go 的 nil 切片对应） */
    public List<String> extensions = null;

    /** 是否递归扫描（Go 结构体中存在，当前未启用） */
    public boolean recursive = false;

    /** 是否跟随重定向 */
    public boolean followRedirects = true;

    /** 结果输出文件（空表示不写文件） */
    public String outputFile = "";

    /** 是否显示所有响应（包括错误） */
    public boolean showAll = false;

    /** 状态码过滤列表（可为 null，与 Go 的 nil 切片对应） */
    public List<Integer> statusCodeFilter = null;

    /** 是否显示404/403（Go 结构体中存在，CLI 未暴露，恒为 false） */
    public boolean show404403 = false;

    /** 代理服务器（支持HTTP/SOCKS，空表示不使用代理） */
    public String proxy = "";
}

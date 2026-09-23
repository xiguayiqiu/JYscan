package space.jyscan.modules.dirscan;

/**
 * 扫描结果，移植自 freeclient/internal/dirscan/dirscan.go 的 ScanResult 结构体。
 *
 * <p>{@code error != null} 表示请求失败（对应 Go 的 Error error 字段）。
 */
public class ScanResult {

    /** 请求URL */
    public String url = "";

    /** HTTP状态码（请求失败时无意义） */
    public int statusCode;

    /** 响应体大小（字节） */
    public long size;

    /** 页面标题 */
    public String title = "";

    /** 请求错误（对应 Go 的 Error，nil 表示成功） */
    public Throwable error = null;

    public ScanResult() {
    }

    /** 错误结果，对应 Go 的 {@code ScanResult{URL: targetURL, Error: err}}。 */
    public static ScanResult ofError(String url, Throwable error) {
        ScanResult r = new ScanResult();
        r.url = url;
        r.error = error;
        return r;
    }

    /** 成功结果。 */
    public static ScanResult of(String url, int statusCode, long size, String title) {
        ScanResult r = new ScanResult();
        r.url = url;
        r.statusCode = statusCode;
        r.size = size;
        r.title = title == null ? "" : title;
        return r;
    }
}

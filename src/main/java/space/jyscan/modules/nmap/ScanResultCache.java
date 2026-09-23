package space.jyscan.modules.nmap;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 扫描结果的内存缓存，移植自 freeclient/internal/nmap/scan.go 的 ScanResultCache。
 *
 * <p><b>归属</b>：本文件由 B 号子代理实现（scan.go 与 scan_optimized.go 都用到，
 * 两者同属 B，故不拆到共享层）。Go 侧用 {@code sync.RWMutex} 保护 {@code map[string]*NmapResult}，
 * Java 用 {@link ConcurrentHashMap}（单次 {@code get}/{@code put} 天然原子，
 * 与 Go「读锁查、写锁写」的可见性语义等价）。
 *
 * <p>Go 原文（scan.go:22-60）：
 * <pre>
 * type ScanResultCache struct {
 *     mu     sync.RWMutex
 *     cache  map[string]*NmapResult
 *     maxAge time.Duration
 * }
 * func (c *ScanResultCache) Get(ip string) (*NmapResult, bool) { ... }
 * func (c *ScanResultCache) Set(ip string, result *NmapResult) { ... }
 * func (c *ScanResultCache) Cleanup() { ... }
 * </pre>
 *
 * <p>唯一调用点是 scan_optimized.go:623 的 {@code NewScanResultCache(5 * time.Minute)}。
 */
public class ScanResultCache {

    /** 对应 Go 的 {@code cache map[string]*NmapResult}。 */
    private final ConcurrentHashMap<String, NmapResult> cache = new ConcurrentHashMap<>();

    /** 对应 Go 的 {@code maxAge time.Duration}。 */
    private final Duration maxAge;

    private ScanResultCache(Duration maxAge) {
        this.maxAge = maxAge;
    }

    /** 对应 Go 的 {@code NewScanResultCache(maxAge)}。 */
    public static ScanResultCache newCache(Duration maxAge) {
        return new ScanResultCache(maxAge);
    }

    /**
     * 对应 Go 的 {@code cache.Get(key)}。
     *
     * <p>Go 返回 {@code (*NmapResult, bool)}：未命中时 {@code (nil, false)}。
     * Java 侧以 {@code null} 表达「未命中」，命中时返回结果（Go 的 {@code *NmapResult}
     * 可能是 nil 指针，但 Set 只在拿到结果后调用，实际不会存 null 值；
     * 即便存了 null，{@link ConcurrentHashMap} 也不允许 null 键值——
     * 调用方 {@code UltraFastScan} 只传非 null 结果，故不额外防护）。
     */
    public NmapResult get(String key) {
        return cache.get(key);
    }

    /** 对应 Go 的 {@code cache.Set(key, v)}。 */
    public void set(String key, NmapResult v) {
        if (key == null || v == null) {
            return;
        }
        cache.put(key, v);
    }

    /**
     * 对应 Go 的 {@code cache.Cleanup()}（Go 侧无调用点，属「死代码但保留」）。
     *
     * <p>逐字复刻 Go 的判断式：
     * <pre>
     * cutoff := time.Now().Add(-c.maxAge)
     * for ip, result := range c.cache {
     *     if result.IP != "" &amp;&amp; time.Now().Sub(cutoff) &gt; c.maxAge { delete(...) }
     * }
     * </pre>
     * 注意 Go 这里 {@code time.Now().Sub(cutoff)} 恒等于 {@code maxAge + 极小增量}，
     * 因此条件在遍历时<b>几乎必然成立</b>（等价于「清掉所有 ip 非空的条目」）——
     * 这是 Go 原文的写法瑕疵，此处原样保留，不做「修正」。
     */
    public void cleanup() {
        java.time.Instant cutoff = java.time.Instant.now().minus(maxAge);
        for (Map.Entry<String, NmapResult> e : cache.entrySet()) {
            NmapResult result = e.getValue();
            if (result == null) {
                continue;
            }
            // Go: result.IP != "" && time.Now().Sub(cutoff) > c.maxAge
            if (result.ip != null && !result.ip.isEmpty()
                    && java.time.Duration.between(cutoff, java.time.Instant.now()).compareTo(maxAge) > 0) {
                cache.remove(e.getKey());
            }
        }
    }
}

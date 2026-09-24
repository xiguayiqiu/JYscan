package space.jyscan.modules.nuclei.utils;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 主机错误缓存，对应 Go 的 {@code utils.HostErrorsCache}（{@code variables.go}）。
 *
 * <p>跨包契约：
 * <ul>
 *   <li>runner 持有字段 {@code hostErrors}，调用
 *       {@link #add(Throwable)}/{@link #isHostError(String)}；</li>
 *   <li>runner 的 {@code GetSkippedHosts()} 转发 {@link #skippedHosts()}；</li>
 *   <li>CLI（{@code cli/nuclei.go} 的 {@code printSummary}）经
 *       {@code r.HostErrors()} 取到本类型后调用 {@link #errorCount(String)}。</li>
 * </ul>
 *
 * <p>Go 的构造函数 {@code NewHostErrorsCache(maxSize int)} 映射为本类的
 * {@code HostErrorsCache(int)} 构造器。
 *
 * <p>这是带 5 分钟过期窗口与 {@code maxSize} 阈值的主机错误计数（不是简单 map）：
 * {@link #add} 记录时间戳并调用 {@link #cleanupHost} 清理，查询类方法只统计窗口内的错误。
 *
 * <p>并发模型：Go 用 {@code sync.RWMutex}（写锁/读锁），Java 侧以 {@code synchronized}
 * 方法等价表达（读操作会被互斥，语义更强、行为一致）。
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/utils/variables.go}。
 */
public class HostErrorsCache {

    /** 对应 Go 的 {@code errors map[string][]time.Time}。 */
    private final Map<String, List<Instant>> errors = new HashMap<>();

    /** 对应 Go 的 {@code maxSize int}（错误阈值）。 */
    private final int maxSize;

    /** 对应 Go 的 {@code window time.Duration}，{@code 5 * time.Minute}。 */
    private final Duration window = Duration.ofMinutes(5);

    /** 对应 Go 的 {@code NewHostErrorsCache(maxSize int) *HostErrorsCache}。 */
    public HostErrorsCache(int maxSize) {
        this.maxSize = maxSize;
    }

    /**
     * 记录一次主机错误，对应 Go 的 {@code (h *HostErrorsCache) Add(err error)}。
     *
     * <p>与 Go 相同：{@code nil} 直接返回；从错误文本提取 host（Go 的
     * {@code extractHostFromError}）、为空返回；随后用
     * {@link Variables#normalizeHostKey(String)} 归一为与查询一致的 key。
     */
    public synchronized void add(Throwable err) {
        if (err == null) {
            return;
        }

        // Go: host := extractHostFromError(err.Error())；err.Error() ≈ getMessage()
        String host = Variables.extractHostFromError(errText(err));
        if (host.isEmpty()) {
            return;
        }

        // 归一化: 与 IsHostError 查询时使用同样的 key 格式
        host = Variables.normalizeHostKey(host);

        Instant now = Instant.now();
        errors.computeIfAbsent(host, k -> new ArrayList<>()).add(now);
        cleanupHost(host, now);
    }

    /**
     * 清理指定主机的过期错误，对应 Go 的
     * {@code (h *HostErrorsCache) cleanupHost(host string, now time.Time)}。
     *
     * <p>Go 侧仅在已持写锁的 {@code Add} 内调用（方法自身不加锁），本方法由
     * {@code synchronized} 的 {@link #add} 保证调用时已持锁。
     */
    private void cleanupHost(String host, Instant now) {
        List<Instant> list = errors.get(host);
        List<Instant> valid = new ArrayList<>();
        for (Instant t : list) {
            if (Duration.between(t, now).compareTo(window) < 0) {
                valid.add(t);
            }
        }
        if (valid.isEmpty()) {
            errors.remove(host);
        } else {
            errors.put(host, valid);
        }
    }

    /**
     * 判断主机是否已达到错误阈值，对应 Go 的
     * {@code (h *HostErrorsCache) IsHostError(host string) bool}。
     *
     * <p>与 Go 相同：只统计 5 分钟窗口内的错误数，{@code >= maxSize} 返回 {@code true}；
     * 入参不做归一化（Go 侧假定调用方传入与 {@link #add} 归一后一致的 key）。
     */
    public synchronized boolean isHostError(String host) {
        List<Instant> list = errors.get(host);
        if (list == null) {
            return false;
        }

        Instant now = Instant.now();
        int count = 0;
        for (Instant t : list) {
            if (Duration.between(t, now).compareTo(window) < 0) {
                count++;
            }
        }
        return count >= maxSize;
    }

    /**
     * 返回所有已超过错误阈值的主机。
     *
     * <p>对应 Go 的 {@code (h *HostErrorsCache) SkippedHosts() []string}（nuclei 官方：
     * 显示 "Skipped X from target list as found unresponsive ..."）。
     *
     * <p>Go 侧遍历 map 且<b>不排序</b>（顺序为 Go map 的随机迭代序），本实现同样不排序、
     * 保持插入（HashMap）迭代序；Go 的 nil slice 在 Java 中映射为空列表（恒非 null）。
     */
    public synchronized List<String> skippedHosts() {
        List<String> hosts = new ArrayList<>();
        for (Map.Entry<String, List<Instant>> e : errors.entrySet()) {
            Instant now = Instant.now(); // Go 在循环体内取 now（原样保留）
            int count = 0;
            for (Instant t : e.getValue()) {
                if (Duration.between(t, now).compareTo(window) < 0) {
                    count++;
                }
            }
            if (count >= maxSize) {
                hosts.add(e.getKey());
            }
        }
        return hosts;
    }

    /**
     * 返回指定主机的当前错误计数，对应 Go 的
     * {@code (h *HostErrorsCache) ErrorCount(host string) int}（仅统计窗口内）。
     */
    public synchronized int errorCount(String host) {
        List<Instant> list = errors.get(host);
        if (list == null) {
            return 0;
        }

        Instant now = Instant.now();
        int count = 0;
        for (Instant t : list) {
            if (Duration.between(t, now).compareTo(window) < 0) {
                count++;
            }
        }
        return count;
    }

    /** Go 的 {@code err.Error()} 近似：优先消息文本，无消息时退回 {@code toString}。 */
    private static String errText(Throwable t) {
        String msg = t.getMessage();
        return msg != null ? msg : String.valueOf(t);
    }
}

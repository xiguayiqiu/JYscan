package space.jyscan.modules.dns;

import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.JsonUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * DNS 记录持久化存储，移植自 freeclient/internal/dns/storage.go。
 *
 * <p>线程安全由 {@link ReadWriteLock} 复现 Go 的 {@code sync.RWMutex}；
 * 落盘格式为两空格缩进的 JSON 数组（与 Go 的 {@code json.MarshalIndent} 一致）。
 */
public final class RecordStorage {

    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private final String filePath;
    private final List<DnsRecord> records = new ArrayList<>();
    private final int maxSize;

    /** 创建新的存储实例，对应 Go 的 {@code NewStorage(filePath, maxSize)}。 */
    public RecordStorage(String filePath, int maxSize) {
        this.filePath = filePath == null ? "" : filePath;
        this.maxSize = maxSize <= 0 ? Integer.MAX_VALUE : maxSize;
    }

    /** 添加记录，超出容量时移除最旧的一条（对应 Go 的 Add）。 */
    public void add(DnsRecord record) {
        if (record == null) {
            return;
        }
        lock.writeLock().lock();
        try {
            if (records.size() >= maxSize) {
                records.remove(0);
            }
            records.add(record);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 按 ID 获取记录，对应 Go 的 Get。 */
    public DnsRecord get(String id) {
        lock.readLock().lock();
        try {
            for (DnsRecord r : records) {
                if (r.id.equals(id)) {
                    return r;
                }
            }
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 获取全部记录（副本），对应 Go 的 GetAll。 */
    public List<DnsRecord> getAll() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(records);
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 记录数量，对应 Go 的 Count。 */
    public int count() {
        lock.readLock().lock();
        try {
            return records.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 清空所有记录，对应 Go 的 Clear。 */
    public void clear() {
        lock.writeLock().lock();
        try {
            records.clear();
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * 持久化到文件，对应 Go 的 Save。
     *
     * @throws IOException 序列化或写入失败
     */
    public void save() throws IOException {
        if (filePath.isEmpty()) {
            return;
        }
        String json;
        lock.readLock().lock();
        try {
            json = JsonUtil.toJSON(new ArrayList<>(records));
        } finally {
            lock.readLock().unlock();
        }
        if (json == null) {
            throw new IOException("序列化DNS记录失败");
        }
        Files.writeString(Path.of(filePath), json, StandardCharsets.UTF_8);
    }

    /**
     * 从文件加载记录，对应 Go 的 Load（文件不存在时静默返回）。
     *
     * @throws IOException 读取或解析失败
     */
    public void load() throws IOException {
        if (filePath.isEmpty()) {
            return;
        }
        Path p = Path.of(filePath);
        if (!Files.exists(p)) {
            return;
        }
        String json = Files.readString(p, StandardCharsets.UTF_8);
        List<DnsRecord> parsed;
        try {
            DnsRecord[] arr = JsonUtil.MAPPER.readValue(json, DnsRecord[].class);
            parsed = arr == null ? List.of() : List.of(arr);
        } catch (Exception e) {
            throw new IOException(Fmt.format("解析DNS记录文件失败: %v",
                    e.getMessage() == null ? e : e.getMessage()), e);
        }

        lock.writeLock().lock();
        try {
            records.clear();
            for (DnsRecord r : parsed) {
                if (records.size() >= maxSize) {
                    break;
                }
                records.add(r);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    // =====================================================================
    // 查询与统计
    // =====================================================================

    /** 按域名查询记录，对应 Go 的 QueryByDomain。 */
    public List<DnsRecord> queryByDomain(String domain) {
        lock.readLock().lock();
        try {
            List<DnsRecord> out = new ArrayList<>();
            for (DnsRecord r : records) {
                if (r.domain.equals(domain)) {
                    out.add(r);
                }
            }
            return out;
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 按时间范围查询记录，对应 Go 的 QueryByTimeRange（闭区间）。 */
    public List<DnsRecord> queryByTimeRange(java.time.Instant start, java.time.Instant end) {
        lock.readLock().lock();
        try {
            List<DnsRecord> out = new ArrayList<>();
            for (DnsRecord r : records) {
                java.time.Instant t = r.instant();
                if (!t.isBefore(start) && !t.isAfter(end)) {
                    out.add(r);
                }
            }
            return out;
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 按 IP 地址查询记录，对应 Go 的 QueryByIP。 */
    public List<DnsRecord> queryByIP(String ip) {
        lock.readLock().lock();
        try {
            List<DnsRecord> out = new ArrayList<>();
            for (DnsRecord r : records) {
                if (r.srcIp.equals(ip) || r.dstIp.equals(ip)) {
                    out.add(r);
                }
            }
            return out;
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 存储统计，对应 Go 的 {@code StorageStats}（json tag 同名）。 */
    public record StorageStats(int totalRecords, int uniqueDomains,
                               List<KV> topDomains, java.util.Map<String, Integer> recordTypes) {
    }

    /** 键值对，对应 Go 的 {@code KV}。 */
    public record KV(String key, int value) {
    }

    /** 获取存储统计，对应 Go 的 Stats。 */
    public StorageStats stats() {
        lock.readLock().lock();
        try {
            java.util.Map<String, Integer> domains = new java.util.LinkedHashMap<>();
            java.util.Map<String, Integer> recordTypes = new java.util.LinkedHashMap<>();
            for (DnsRecord r : records) {
                domains.merge(r.domain, 1, Integer::sum);
                recordTypes.merge(r.recordType, 1, Integer::sum);
            }
            return new StorageStats(records.size(), domains.size(), topN(domains, 10), recordTypes);
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 取出现次数最多的 n 个键，对应 Go 的 {@code topN}（简单选择排序）。 */
    private static List<KV> topN(java.util.Map<String, Integer> m, int n) {
        List<String> keys = new ArrayList<>(m.keySet());
        List<KV> out = new ArrayList<>();
        for (int i = 0; i < keys.size() && out.size() < n; i++) {
            int maxIdx = i;
            for (int j = i + 1; j < keys.size(); j++) {
                if (m.get(keys.get(j)) > m.get(keys.get(maxIdx))) {
                    maxIdx = j;
                }
            }
            if (maxIdx != i) {
                String tmp = keys.get(i);
                keys.set(i, keys.get(maxIdx));
                keys.set(maxIdx, tmp);
            }
            out.add(new KV(keys.get(i), m.get(keys.get(i))));
        }
        return out;
    }

    /** 文件路径（空串表示不落盘）。 */
    public String filePath() {
        return filePath;
    }
}


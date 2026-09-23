package space.jyscan.modules.dns;

import java.time.Duration;
import java.time.Instant;

/**
 * 监听器统计信息与快照，对应 Go 的 {@code dns.ListenerStats} 与 {@code ListenerStatsSnapshot}。
 *
 * <p>Go 用 {@code sync.RWMutex} 保护字段，这里用 {@link java.util.concurrent.locks.ReentrantReadWriteLock}。
 * 起止时间都是 wall-clock {@link Instant}，与 Go 的 {@code time.Time} 语义一致。
 */
public final class ListenerStats {

    private final java.util.concurrent.locks.ReadWriteLock lock =
            new java.util.concurrent.locks.ReentrantReadWriteLock();

    /** 已捕获的包总数。 */
    private long packetsCaptured;
    /** DNS查询数。 */
    private long dnsQueries;
    /** DNS响应数。 */
    private long dnsResponses;
    /** 命中的记录数。 */
    private long recordsMatched;
    /** 被过滤的记录数。 */
    private long recordsFiltered;
    /** 开始监听时间（null 表示未启动）。 */
    private Instant startTime;
    /** 最后一个包的时间（null 表示尚未收到包）。 */
    private Instant lastPacketTime;
    /** 错误计数。 */
    private long errors;

    /**
     * 统计信息快照，字段对应 Go 的 {@code ListenerStatsSnapshot} 及其 json tag。
     */
    public record Snapshot(long packetsCaptured, long dnsQueries, long dnsResponses,
                           long recordsMatched, long recordsFiltered,
                           Instant startTime, Instant lastPacketTime, long errors) {

        /** 运行时长，对应 Go 的 {@code LastPacketTime.Sub(StartTime)}。 */
        public Duration uptime() {
            if (startTime == null || lastPacketTime == null) {
                return Duration.ZERO;
            }
            Duration d = Duration.between(startTime, lastPacketTime);
            return d.isNegative() ? Duration.ZERO : d;
        }
    }

    /** 记录开始监听时间，对应 Go 的 {@code StartTime = time.Now()}。 */
    public void markStart() {
        markStart(Instant.now());
    }

    /** 以指定时刻记录开始时间（便于测试注入）。 */
    public void markStart(Instant instant) {
        lock.writeLock().lock();
        try {
            startTime = instant;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 增加包计数，同时刷新最后收包时间（对应 Go 的 {@code IncrementPackets}）。 */
    public void incrementPackets() {
        incrementPackets(Instant.now());
    }

    /** 增加包计数并记录收包时刻。 */
    public void incrementPackets(Instant instant) {
        lock.writeLock().lock();
        try {
            packetsCaptured++;
            lastPacketTime = instant;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 增加查询计数。 */
    public void incrementQueries() {
        lock.writeLock().lock();
        try {
            dnsQueries++;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 增加响应计数。 */
    public void incrementResponses() {
        lock.writeLock().lock();
        try {
            dnsResponses++;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 增加命中计数。 */
    public void incrementMatched() {
        lock.writeLock().lock();
        try {
            recordsMatched++;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 增加过滤计数。 */
    public void incrementFiltered() {
        lock.writeLock().lock();
        try {
            recordsFiltered++;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 增加错误计数。 */
    public void incrementErrors() {
        lock.writeLock().lock();
        try {
            errors++;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 快照，对应 Go 的 {@code Snapshot()}。 */
    public Snapshot snapshot() {
        lock.readLock().lock();
        try {
            return new Snapshot(packetsCaptured, dnsQueries, dnsResponses, recordsMatched,
                    recordsFiltered, startTime, lastPacketTime, errors);
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 已捕获包总数的快捷读取。 */
    public long packetsCaptured() {
        lock.readLock().lock();
        try {
            return packetsCaptured;
        } finally {
            lock.readLock().unlock();
        }
    }
}


package space.jyscan.modules.nmap;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 主机存活探测（nmap -sn 类多协议组合探测），移植自 freeclient/internal/nmap/scan.go 的：
 * {@code hostDiscovery}(457) / {@code icmpPing}(546) / {@code icmpv6Ping}(563) /
 * {@code removeZoneID}(582) / {@code systemPing6}(590) / {@code windowsPing6}(629) /
 * {@code icmpTimestampPing}(656) / {@code tcpPing}(666) / {@code tcpSynPing}(678) /
 * {@code tcpAckPing}(690) / {@code udpPing}(702) / {@code arpDiscovery}(710) /
 * {@code isPrivateIP}(721) / {@code isIPv6}(754) / {@code isPrivateIPv6}(760) /
 * {@code windowsICMPPing}(2989) / {@code windowsICMPTimestampPing}(3006)。
 *
 * <p><b>归属</b>：本文件由 B 号子代理新建。
 *
 * <p><b>并发模型</b>：Go 为每个探测方法起一个 goroutine，结果写入容量 = 方法数的
 * channel，主协程在 {@code ctx} 超时前逐个收集、达到 {@code minConfirm} 即提前返回。
 * Java 用共享的 {@link #DISCOVERY_POOL}（守护线程 cached pool）提交任务，
 * 结果写入无界 {@link LinkedBlockingQueue}，主调方在 {@code timeout} 预算内 poll。
 * 差异：Go 的 goroutine 在启动时会先 non-blocking 地检查一次 ctx（已取消则直接投 false），
 * Java 这里以「主调方已超时返回」等效（任务照跑完、结果进队无人取，无泄漏 ——
 * 与 Go 缓冲 channel 被 goroutine 写满即返回的行为一致）。
 *
 * <p>依赖 {@link ScanEngine} 的 {@code tcpConnect}/{@code udpConnect}（scan.go:1089/1126）。
 */
public final class HostDiscovery {

    /**
     * 探测方法 goroutine 的共享池（对应 Go 的「每个方法一个 goroutine」）。
     * 守护线程 + cached 池：任务数恒 ≤ 方法数（7），不会积压。
     */
    private static final ExecutorService DISCOVERY_POOL = Executors.newCachedThreadPool(
            new ThreadFactory() {
                private final AtomicInteger seq = new AtomicInteger(1);

                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "jyscan-host-discovery-" + seq.getAndIncrement());
                    t.setDaemon(true);
                    return t;
                }
            });

    /** 探测方法签名：{@code (ip, timeout) -> alive}。 */
    @FunctionalInterface
    interface ProbeMethod {
        boolean probe(String ip, Duration timeout);
    }

    private HostDiscovery() {
    }

    // =========================================================================
    // scan.go:457 hostDiscovery —— 多协议组合探测（ARP > ICMP > TCP > UDP）
    // =========================================================================

    /**
     * 对应 Go 的 {@code hostDiscovery(ip, timeout)}（scan.go:457）。
     *
     * <p>方法集合按目标类型选择（逐字对齐 Go）：
     * <ul>
     *   <li>IPv6：跳过 ARP，用 ICMPv6 + TCP + UDP + 时间戳（6 种）；</li>
     *   <li>IPv4 私网：ARP + ICMP + TCP 系列 + UDP + 时间戳（7 种）；</li>
     *   <li>IPv4 公网：只用 {@code tcpPing / icmpPing / tcpSynPing}（3 种）。</li>
     * </ul>
     * 公网只需 <b>1</b> 种方法确认存活，私网/IPv6 需要 <b>2</b> 种
     * （Go: {@code minConfirm}，scan.go:502-506）。每个方法拿到 {@code timeout*2/3}
     * 的超时预算，整体预算 {@code timeout}。
     */
    public static boolean hostDiscovery(String ip, Duration timeout) {
        List<ProbeMethod> methods = new ArrayList<>();

        if (isIPv6(ip)) {
            // IPv6: 跳过 ARP，使用 ICMPv6 和 TCP
            methods.add(HostDiscovery::icmpPing);
            methods.add(HostDiscovery::tcpSynPing);
            methods.add(HostDiscovery::tcpAckPing);
            methods.add(HostDiscovery::tcpPing);
            methods.add(HostDiscovery::udpPing);
            methods.add(HostDiscovery::icmpTimestampPing);
        } else if (isPrivateIP(ip)) {
            // IPv4私有网络：优先使用ARP和ICMP
            methods.add(HostDiscovery::arpDiscovery);
            methods.add(HostDiscovery::icmpPing);
            methods.add(HostDiscovery::tcpSynPing);
            methods.add(HostDiscovery::tcpAckPing);
            methods.add(HostDiscovery::tcpPing);
            methods.add(HostDiscovery::udpPing);
            methods.add(HostDiscovery::icmpTimestampPing);
        } else {
            // IPv4公网：优先使用TCP和ICMP，简化探测
            methods.add(HostDiscovery::tcpPing);
            methods.add(HostDiscovery::icmpPing);
            methods.add(HostDiscovery::tcpSynPing);
        }

        // 并行执行多种探测方法，公网1种方法确认，私网需要2种
        boolean isPublic = !isPrivateIP(ip) && !isIPv6(ip);
        int minConfirm = isPublic ? 1 : 2;

        // 每个方法使用 2/3 的超时时间（Go: timeout * 2 / 3）
        Duration methodTimeout = timeout.multipliedBy(2).dividedBy(3);

        BlockingQueue<Boolean> resultQueue = new LinkedBlockingQueue<>();
        long deadline = System.nanoTime() + timeout.toNanos();
        for (ProbeMethod method : methods) {
            DISCOVERY_POOL.submit(() -> {
                boolean r;
                try {
                    r = method.probe(ip, methodTimeout);
                } catch (RuntimeException ex) {
                    r = false;
                }
                resultQueue.offer(r);
            });
        }

        // 收集结果
        int successCount = 0;
        for (int i = 0; i < methods.size(); i++) {
            long remain = deadline - System.nanoTime();
            if (remain <= 0) {
                // Go: case <-ctx.Done(): return successCount >= minConfirm
                return successCount >= minConfirm;
            }
            Boolean result;
            try {
                result = resultQueue.poll(remain, java.util.concurrent.TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return successCount >= minConfirm;
            }
            if (result == null) {
                return successCount >= minConfirm;
            }
            if (result) {
                successCount++;
                if (successCount >= minConfirm) {
                    return true;
                }
            }
        }
        return successCount >= minConfirm;
    }

    // =========================================================================
    // scan.go:546-718 —— 各探测方法
    // =========================================================================

    /** 对应 Go 的 {@code icmpPing}（scan.go:546）：IPv6→ICMPv6；Windows→windowsICMPPing；否则 TCP 备选。 */
    public static boolean icmpPing(String ip, Duration timeout) {
        if (isIPv6(ip)) {
            return icmpv6Ping(ip, timeout);
        }
        // Windows上需要管理员权限，使用TCP作为备选
        if (SysExec.isWindows()) {
            return windowsICMPPing(ip, timeout);
        }
        // 其他系统使用TCP作为备选
        return tcpPing(ip, timeout);
    }

    /** 对应 Go 的 {@code icmpv6Ping}（scan.go:563）。 */
    public static boolean icmpv6Ping(String ip, Duration timeout) {
        String ipClean = removeZoneID(ip);
        // 尝试使用系统 ping6 命令
        if (SysExec.isLinux() || SysExec.isMacOS()) {
            return systemPing6(ipClean, timeout);
        }
        // Windows 上尝试使用 ping -6 命令
        if (SysExec.isWindows()) {
            return windowsPing6(ipClean, timeout);
        }
        // 其他系统回退到 TCP ping
        return tcpPing(ip, timeout);
    }

    /** 对应 Go 的 {@code removeZoneID}（scan.go:582）：截掉最后一个 {@code %} 之后的 zone ID。 */
    public static String removeZoneID(String ip) {
        int idx = ip.lastIndexOf('%');
        if (idx != -1) {
            return ip.substring(0, idx);
        }
        return ip;
    }

    /**
     * 对应 Go 的 {@code systemPing6}（scan.go:590）。
     *
     * <p>ping 次数 = {@code timeout.Seconds()} 截断并夹在 [1,4]。
     * Linux 用 {@code ping6}，macOS/其他用 {@code ping}（Go 的三分支后两者相同）。
     * <b>无论命令退出码如何</b>，只要输出里有 {@code bytes from}/{@code ttl=}/{@code time=}
     * 即判定存活（Go 对 err 分支做了与成功分支<b>完全相同</b>的判断）。
     *
     * <p>进程本身不设 Java 侧超时（Go 也无 ctx）：{@code -c}/{@code -W} 已自带上限。
     */
    public static boolean systemPing6(String ip, Duration timeout) {
        int count = pingCount(timeout);
        String countStr = String.valueOf(count);

        String binary;
        if (SysExec.isLinux()) {
            binary = "ping6";
        } else {
            // Go: isMacOS() 与 else 分支都是 ping
            binary = "ping";
        }
        String output = SysExec.run(null, binary, "-c", countStr, "-W", "1", ip).output();
        return output.contains("bytes from") || output.contains("ttl=") || output.contains("time=");
    }

    /** 对应 Go 的 {@code windowsPing6}（scan.go:629）。 */
    public static boolean windowsPing6(String ip, Duration timeout) {
        int count = pingCount(timeout);
        String output = SysExec.run(null, "ping", "-n", String.valueOf(count), "-w", "1000", ip).output();
        return output.contains("Reply from") || output.contains("bytes=");
    }

    /** Go 三处相同的次数夹取：{@code int(timeout.Seconds())} 后夹到 [1,4]。 */
    private static int pingCount(Duration timeout) {
        int count = (int) timeout.toSeconds();
        if (count < 1) {
            count = 1;
        }
        if (count > 4) {
            count = 4;
        }
        return count;
    }

    /** 对应 Go 的 {@code icmpTimestampPing}（scan.go:656）：Windows 走 TCP 备选（时间戳需特权）。 */
    public static boolean icmpTimestampPing(String ip, Duration timeout) {
        if (SysExec.isWindows()) {
            return windowsICMPTimestampPing(ip, timeout);
        }
        return tcpPing(ip, timeout);
    }

    /** 对应 Go 的 {@code tcpPing}（scan.go:666）：全连接探测常见端口。 */
    public static boolean tcpPing(String ip, Duration timeout) {
        int[] commonPorts = {80, 443, 8080, 22, 53};
        for (int port : commonPorts) {
            if (ScanEngine.tcpConnect(ip, port, timeout)) {
                return true;
            }
        }
        return false;
    }

    /** 对应 Go 的 {@code tcpSynPing}（scan.go:678）。 */
    public static boolean tcpSynPing(String ip, Duration timeout) {
        int[] commonPorts = {80, 443, 22, 53, 8080};
        for (int port : commonPorts) {
            if (tcpSynConnect(ip, port, timeout)) {
                return true;
            }
        }
        return false;
    }

    /** 对应 Go 的 {@code tcpAckPing}（scan.go:690）。 */
    public static boolean tcpAckPing(String ip, Duration timeout) {
        int[] commonPorts = {80, 443, 22, 53, 8080};
        for (int port : commonPorts) {
            if (tcpAckConnect(ip, port, timeout)) {
                return true;
            }
        }
        return false;
    }

    /** 对应 Go 的 {@code tcpSynConnect}（scan.go:2960）：无原始套接字权限，退化为全连接。 */
    public static boolean tcpSynConnect(String ip, int port, Duration timeout) {
        return ScanEngine.tcpConnect(ip, port, timeout);
    }

    /** 对应 Go 的 {@code tcpAckConnect}（scan.go:2967）：同上，退化为全连接。 */
    public static boolean tcpAckConnect(String ip, int port, Duration timeout) {
        return ScanEngine.tcpConnect(ip, port, timeout);
    }

    /** 对应 Go 的 {@code udpPing}（scan.go:702）：UDP/53 探测。 */
    public static boolean udpPing(String ip, Duration timeout) {
        return ScanEngine.udpConnect(ip, 53, timeout);
    }

    /**
     * 对应 Go 的 {@code arpDiscovery}（scan.go:710）：
     * 同网段检查通过后，因原始套接字权限限制<b>恒返回 false</b>（Go 原文如此）。
     */
    public static boolean arpDiscovery(String ip, Duration timeout) {
        // 仅在同一网段内有效
        if (!ScanEngine.isSameSubnet(ip)) {
            return false;
        }
        // ARP发现需要原始套接字权限，当前版本暂未实现
        return false;
    }

    // =========================================================================
    // scan.go:2988-3010 —— Windows 分支
    // =========================================================================

    /**
     * 对应 Go 的 {@code windowsICMPPing}（scan.go:2989）：
     * {@code ping -n 1 -w 1000}，进程带 ctx 超时（Java 用进程超时等价）。
     */
    public static boolean windowsICMPPing(String ip, Duration timeout) {
        SysExec.Result r = SysExec.run(timeout, "ping", "-n", "1", "-w", "1000", ip);
        if (!r.ok()) {
            return false;
        }
        String output = r.output();
        return output.contains("Reply from") || output.contains("TTL=");
    }

    /** 对应 Go 的 {@code windowsICMPTimestampPing}（scan.go:3006）：Windows 无时间戳权限 → TCP 备选。 */
    public static boolean windowsICMPTimestampPing(String ip, Duration timeout) {
        return tcpPing(ip, timeout);
    }

    // =========================================================================
    // scan.go:721-789 —— IP 分类
    // =========================================================================

    /**
     * 对应 Go 的 {@code isPrivateIP(ip)}（scan.go:721）：
     * 解析失败 → false；v6 → {@link #isPrivateIPv6}；v4 → RFC1918 + 链路本地 169.254/16。
     */
    public static boolean isPrivateIP(String ip) {
        byte[] parsed = ScanParse.parseIPBytes(ip);
        if (parsed == null) {
            return false;
        }
        // 检查是否为IPv6地址
        if (!ScanParse.isTo4(parsed)) {
            return isPrivateIPv6(parsed);
        }
        byte[] ip4 = ScanParse.to4(parsed);
        // 10.0.0.0/8
        if ((ip4[0] & 0xff) == 10) {
            return true;
        }
        // 172.16.0.0/12
        if ((ip4[0] & 0xff) == 172 && (ip4[1] & 0xff) >= 16 && (ip4[1] & 0xff) <= 31) {
            return true;
        }
        // 192.168.0.0/16
        if ((ip4[0] & 0xff) == 192 && (ip4[1] & 0xff) == 168) {
            return true;
        }
        // 169.254.0.0/16 (链路本地地址)
        if ((ip4[0] & 0xff) == 169 && (ip4[1] & 0xff) == 254) {
            return true;
        }
        return false;
    }

    /** 对应 Go 的 {@code isIPv6(ip)}（scan.go:754）：可解析且 {@code To4()==nil}。 */
    public static boolean isIPv6(String ip) {
        byte[] parsed = ScanParse.parseIPBytes(ip);
        return parsed != null && !ScanParse.isTo4(parsed);
    }

    /**
     * 对应 Go 的 {@code isPrivateIPv6(ip net.IP)}（scan.go:760），Java 侧入参为 16 字节地址。
     *
     * <p>判定顺序（与 Go 一致）：{@code fc00::/7}(取首字节 0xfd) → 链路本地 {@code fe80::/10}
     * → 站点本地 {@code fec0::/10} → v4-mapped 私有 → 回环 {@code ::1}。
     */
    public static boolean isPrivateIPv6(byte[] ip) {
        if (ip == null || ip.length == 0) {
            return false;
        }
        // RFC 4193 私有地址范围: fc00::/7（含 fd00::/8 ULA）
        if ((ip[0] & 0xff) == 0xfd) {
            return true;
        }
        // RFC 3879 链路本地地址: fe80::/10
        if (isLinkLocalUnicast(ip)) {
            return true;
        }
        // 站点本地 (已废弃): fec0::/10
        if (ip.length >= 2 && (ip[0] & 0xff) == 0xfe && (ip[1] & 0xc0) == 0xc0) {
            return true;
        }
        // IPv4映射的IPv6地址中的私有IPv4（Go: To4().String() 再走 isPrivateIP）
        if (ScanParse.isTo4(ip)) {
            return isPrivateIP(ScanParse.formatIP(ScanParse.to4(ip)));
        }
        // 回环地址（To4()==nil 分支下 IsLoopback 等价于 ::1）
        if (isLoopback(ip)) {
            return true;
        }
        return false;
    }

    /** Go {@code net.IP.IsLinkLocalUnicast()}：IPv6 为 {@code fe80::/10}，IPv4 为 {@code 169.254.0.0/16}。 */
    private static boolean isLinkLocalUnicast(byte[] ip) {
        if (ip.length == 16) {
            return (ip[0] & 0xff) == 0xfe && (ip[1] & 0xc0) == 0x80;
        }
        if (ip.length == 4) {
            return (ip[0] & 0xff) == 169 && (ip[1] & 0xff) == 254;
        }
        return false;
    }

    /** Go {@code net.IP.IsLoopback()}：v4 {@code 127.0.0.0/8} 或 {@code ::1}。 */
    private static boolean isLoopback(byte[] ip) {
        byte[] v4 = ScanParse.to4(ip);
        if (ScanParse.isTo4(ip) || ip.length == 4) {
            return (v4[0] & 0xff) == 127;
        }
        // IPv6loopback = ::1
        for (int i = 0; i < 15; i++) {
            if (ip[i] != 0) {
                return false;
            }
        }
        return ip[15] == 1;
    }
}

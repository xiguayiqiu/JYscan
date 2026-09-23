package space.jyscan.modules.route;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.win32.W32APIOptions;
import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.SystemUtil;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 路由检测核心 —— 用 JNA 直接驱动 ICMP 套接字，移植 freeclient/internal/cli/route.go 的 traceRoute。
 *
 * <p>Go 侧：icmp.ListenPacket("ip4:icmp", "0.0.0.0") + pconn.SetTTL(ttl)（需要特权）。
 * Java 没有对应的 ICMP API，这里改为：
 * <ul>
 *   <li>优先 socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) —— Linux 非特权 ping 套接字
 *       （net.ipv4.ping_group_range 允许时可用）；</li>
 *   <li>不可用则退到 socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)（需要 CAP_NET_RAW/root）；</li>
 *   <li>中间路由器返回的 ICMP 超时（type 11）：dgram 套接字通过 IP_RECVERR + MSG_ERRQUEUE 接收
 *       （Linux ping 套接字不把错误当普通数据投递），raw 套接字随 recvfrom 直接到达；</li>
 *   <li>到达目标的 Echo Reply（type 0）始终经 recvfrom 接收；</li>
 *   <li>等待统一由 poll(POLLIN|POLLERR) + SO_RCVTIMEO 限时，任何读取都不会挂死。</li>
 * </ul>
 *
 * <p>两种套接字都建不起来时由 {@link RouteTracer} 退到 {@link WindowsIcmpTracer}
 * 或 {@link ShellTracer}，输出同样的表格。
 */
public final class IcmpSocketTracer implements AutoCloseable {

    // ICMP 消息类型常量（对应 route.go 的 ProtocolICMP/EchoRequest/EchoReply/TimeExceeded）
    static final int PROTOCOL_ICMP = 1;
    static final int ECHO_REQUEST = 8;
    static final int ECHO_REPLY = 0;
    static final int TIME_EXCEEDED = 11;

    private static final int AF_INET = 2;
    private static final int SOCK_DGRAM = 2;
    private static final int SOCK_RAW = 3;
    private static final int SOL_SOCKET = 1;
    private static final int SOL_IP = 0;
    private static final int IP_TTL = 2;
    private static final int IP_RECVERR = 11;
    private static final int SO_RCVTIMEO_POSIX = 20;
    private static final int SO_RCVTIMEO_WIN = 0x1006;
    private static final int POLLIN = 0x001;
    private static final int POLLERR = 0x008;
    private static final int POLLHUP = 0x010;
    private static final int POLLNVAL = 0x020;
    private static final int MSG_DONTWAIT = 0x40;
    private static final int MSG_ERRQUEUE = 0x2000;
    private static final int EINTR = 4;

    /** POSIX libc 的套接字子集（含 poll/close）。 */
    private interface LibcApi extends Library {
        int socket(int domain, int type, int protocol);
        int setsockopt(int fd, int level, int optname, Pointer optval, int optlen);
        int sendto(int fd, Pointer buf, int len, int flags, Pointer dest, int destlen);
        int recvfrom(int fd, Pointer buf, int len, int flags, Pointer src, Pointer addrlen);
        int recvmsg(int fd, Pointer msg, int flags);
        int poll(Pointer fds, int nfds, int timeout);
        int close(int fd);
    }

    /** Windows Winsock 的套接字子集（无 poll，用 SO_RCVTIMEO 限时）。 */
    private interface WinsockApi extends Library {
        int socket(int domain, int type, int protocol);
        int setsockopt(int fd, int level, int optname, Pointer optval, int optlen);
        int sendto(int fd, Pointer buf, int len, int flags, Pointer dest, int destlen);
        int recvfrom(int fd, Pointer buf, int len, int flags, Pointer src, Pointer addrlen);
        int closesocket(int fd);
    }

    /** 一条 ICMP 响应（普通数据或错误队列）。 */
    private static final class Reply {
        final int icmpType;
        final String src;
        final int echoId;
        final int echoSeq;

        Reply(int icmpType, String src, int echoId, int echoSeq) {
            this.icmpType = icmpType;
            this.src = src;
            this.echoId = echoId;
            this.echoSeq = echoSeq;
        }
    }

    private final boolean win;
    private final LibcApi libc;
    private final WinsockApi wsock;

    private int fd = -1;
    private boolean dgram;
    private boolean errorQueue;
    private long recvTimeoutMs;
    private String channel = "";

    // ---- 跨调用复用的缓冲区（作为实例字段，保证在 native 调用期间不被回收） ----
    private final Memory recvBuf = new Memory(1500);
    private final Memory srcAddr = new Memory(16);
    private final Memory srcLen = new Memory(4);
    private final Memory errName = new Memory(16);
    private final Memory errIovBuf = new Memory(1500);
    private final Memory errIov = new Memory(16);
    private final Memory errControl = new Memory(256);
    private final Memory errHdr = new Memory(56);       // struct msghdr（64 位布局）
    private final Memory pollFd = new Memory(8);        // struct pollfd
    private final Memory ttlOpt = new Memory(4);        // int TTL

    private IcmpSocketTracer(boolean win) {
        this.win = win;
        if (win) {
            this.libc = null;
            this.wsock = Native.load("ws2_32", WinsockApi.class, W32APIOptions.DEFAULT_OPTIONS);
        } else {
            this.wsock = null;
            this.libc = loadLibc();
        }
        // 初始化 iovec（recvmsg 的数据缓冲）
        errIov.setLong(0, Pointer.nativeValue(errIovBuf));
        errIov.setLong(8, 1500);
    }

    private static LibcApi loadLibc() {
        String[] names = {"c", "libc.so.6", "libc"};
        UnsatisfiedLinkError last = null;
        for (String n : names) {
            try {
                return Native.load(n, LibcApi.class);
            } catch (UnsatisfiedLinkError e) {
                last = e;
            }
        }
        throw last != null ? last : new UnsatisfiedLinkError("无法加载 libc");
    }

    /**
     * 创建 ICMP 套接字：先试非特权 dgram，再试 raw；dgram 必须能开 IP_RECVERR
     * （否则收不到中间路由器的 type 11），否则也退回 raw。
     *
     * @throws IOException 两种套接字都不可用（Windows、macOS、容器权限受限等）
     */
    public static IcmpSocketTracer open(int timeoutSec) throws IOException {
        boolean win = SystemUtil.isWindows();
        IcmpSocketTracer t = new IcmpSocketTracer(win);

        int fd = t.socket(AF_INET, SOCK_DGRAM, PROTOCOL_ICMP);
        boolean dgram = fd >= 0;
        if (!dgram) {
            fd = t.socket(AF_INET, SOCK_RAW, PROTOCOL_ICMP);
        }
        if (fd < 0) {
            throw new IOException(Fmt.format(
                    "创建ICMP套接字失败: socket(AF_INET, SOCK_DGRAM/SOCK_RAW, IPPROTO_ICMP) errno=%d",
                    Native.getLastError()));
        }
        t.fd = fd;

        long timeoutMs = Math.max(0L, (long) timeoutSec * 1000L);
        t.recvTimeoutMs = timeoutMs;
        if (!t.setRecvTimeout(timeoutMs)) {
            t.closeFd();
            throw new IOException(Fmt.format("设置SO_RCVTIMEO失败: errno=%d", Native.getLastError()));
        }

        if (dgram) {
            // Linux ping 套接字不把 ICMP 错误当普通数据投递：中间路由器的 Time Exceeded
            // 必须通过 IP_RECVERR + MSG_ERRQUEUE 读取；Windows 没有该选项，直接改用 raw。
            if (win || t.setOpt(SOL_IP, IP_RECVERR, 1) < 0) {
                t.closeFd();
                fd = t.socket(AF_INET, SOCK_RAW, PROTOCOL_ICMP);
                if (fd < 0) {
                    throw new IOException(Fmt.format("创建ICMP套接字失败: raw errno=%d", Native.getLastError()));
                }
                t.fd = fd;
                if (!t.setRecvTimeout(timeoutMs)) {
                    t.closeFd();
                    throw new IOException(Fmt.format("设置SO_RCVTIMEO失败: errno=%d", Native.getLastError()));
                }
                dgram = false;
            } else {
                t.errorQueue = true;
            }
        }
        t.dgram = dgram;
        t.channel = dgram
                ? "ICMP数据报套接字 socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)"
                : "ICMP原始套接字 socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)";
        return t;
    }

    // =====================================================================
    // 路由检测主循环（与 route.go 的 traceRoute 逐行对应）
    // =====================================================================

    public List<RouteHop> trace(InetAddress target, int maxHops, int timeoutSec, int count) throws IOException {
        RouteTracer.noteChannel(channel);

        if (!(target instanceof Inet4Address)) {
            throw new IOException("路由检测仅支持IPv4目标地址");
        }
        byte[] dest = target.getAddress();
        Pointer destAddr = buildSockaddr(dest);
        long timeoutMs = Math.max(0L, (long) timeoutSec * 1000L);
        // ICMP Echo 请求 id：与 Go 的 os.Getpid() & 0xffff 一致
        int id = (int) (ProcessHandle.current().pid() & 0xffff);

        List<RouteHop> hops = new ArrayList<>();

        // 对每个跳数进行探测
        for (int ttl = 1; ttl <= maxHops; ttl++) {
            // 设置TTL（Go: pconn.SetTTL(ttl)）
            ttlOpt.setInt(0, ttl);
            if (setOpt(SOL_IP, IP_TTL, ttlOpt, 4) < 0) {
                throw new IOException(Fmt.format("设置TTL失败: %v", Native.getLastError()));
            }

            RouteHop hop = new RouteHop();
            List<Long> delays = new ArrayList<>();   // 每次成功探测的延时（微秒）
            int successCount = 0;

            // 对每个跳数进行多次探测
            for (int probe = 0; probe < count; probe++) {
                // seq = ttl*count + probe（与 Go 一致）
                int seq = ttl * count + probe;
                byte[] msgBytes = buildEchoRequest(id, seq);

                drainStale();

                // 发送 ICMP Echo 请求
                Memory buf = new Memory(msgBytes.length);
                buf.write(0, msgBytes, 0, msgBytes.length);
                long start = System.nanoTime();
                if (sendTo(buf, msgBytes.length, destAddr) < 0) {
                    continue; // 发送失败，继续下一次探测
                }

                // 设置读取超时并读取回复（poll + SO_RCVTIMEO 双重限时）
                Reply reply = waitForReply(timeoutMs);
                if (reply == null) {
                    continue; // 超时或读取错误，记录为丢包
                }

                // 计算延迟（Go: latency = time.Since(startTime)）
                long latencyMicros = TimeUnit.NANOSECONDS.toMicros(System.nanoTime() - start);

                switch (reply.icmpType) {
                    case ECHO_REPLY -> {
                        // 校验回复是否属于本次探测（Go: echo.ID == msg.ID && echo.Seq == msg.Seq）。
                        // 注意：Linux ping 数据报套接字会把出口 Echo 的 id 改写为内核分配的
                        // 套接字标识（ident），而收到的报文本身已按 ident 经内核过滤，
                        // 因此 dgram 路径只校验 seq；raw 路径不会改写，保留 Go 的 id+seq 双重校验。
                        boolean matched = reply.echoSeq == seq && (dgram || reply.echoId == id);
                        if (matched) {
                            delays.add(latencyMicros);
                            successCount++;
                            // 如果是第一次成功探测，记录跳数信息
                            if (hop.ip == null) {
                                hop.hop = String.valueOf(ttl);
                                hop.ip = reply.src;
                                hop.hostname = ReverseDns.lookup(reply.src);
                            }
                        }
                        // 到达目标，结束路由检测
                        if (!delays.isEmpty()) {
                            hop.avgDelay = RouteHop.avgDelayMillis(delays);
                            hop.lossRate = RouteHop.lossRate(count, successCount);
                            hops.add(hop);
                        }
                        return hops;
                    }
                    case TIME_EXCEEDED -> {
                        // 中间路由器返回超时
                        delays.add(latencyMicros);
                        successCount++;
                        // 如果是第一次成功探测，记录跳数信息
                        if (hop.ip == null) {
                            hop.hop = String.valueOf(ttl);
                            hop.ip = reply.src;
                            hop.hostname = ReverseDns.lookup(reply.src);
                        }
                    }
                    default -> {
                        // 其余 ICMP 类型与 Go 一样不计入延时（switch 无匹配分支）
                    }
                }
            }

            // 记录当前跳数的结果
            if (hop.ip != null) {
                if (!delays.isEmpty()) {
                    hop.avgDelay = RouteHop.avgDelayMillis(delays);
                }
                hop.lossRate = RouteHop.lossRate(count, successCount);
                hops.add(hop);
            } else {
                // 当前跳数无响应
                hops.add(RouteHop.noReply(ttl));
            }
        }

        return hops;
    }

    @Override
    public void close() {
        closeFd();
    }

    private void closeFd() {
        if (fd < 0) {
            return;
        }
        if (win) {
            wsock.closesocket(fd);
        } else {
            libc.close(fd);
        }
        fd = -1;
    }

    // =====================================================================
    // 系统调用封装
    // =====================================================================

    private int socket(int domain, int type, int protocol) {
        return win ? wsock.socket(domain, type, protocol) : libc.socket(domain, type, protocol);
    }

    private int setOpt(int level, int opt, int value) {
        Memory m = new Memory(4);
        m.setInt(0, value);
        return setOpt(level, opt, m, 4);
    }

    private int setOpt(int level, int opt, Pointer value, int len) {
        return win ? wsock.setsockopt(fd, level, opt, value, len)
                : libc.setsockopt(fd, level, opt, value, len);
    }

    private int sendTo(Pointer buf, int len, Pointer dest) {
        return win ? wsock.sendto(fd, buf, len, 0, dest, 16)
                : libc.sendto(fd, buf, len, 0, dest, 16);
    }

    private int recvFrom(Memory buf, int len, int flags, Memory src, Memory slen) {
        slen.setInt(0, 16);
        return win ? wsock.recvfrom(fd, buf, len, flags, src, slen)
                : libc.recvfrom(fd, buf, len, flags, src, slen);
    }

    private int recvMsg(Memory hdr, int flags) {
        return libc.recvmsg(fd, hdr, flags);
    }

    /** SO_RCVTIMEO：POSIX 用 timeval，Windows 用毫秒 DWORD。 */
    private boolean setRecvTimeout(long ms) {
        long v = Math.max(0L, ms);
        if (win) {
            Memory m = new Memory(4);
            m.setInt(0, (int) Math.min(v, Integer.MAX_VALUE));
            return setOpt(SOL_SOCKET, SO_RCVTIMEO_WIN, m, 4) == 0;
        }
        int ps = Native.POINTER_SIZE;
        Memory tv = new Memory(ps == 8 ? 16 : 8);
        long sec = v / 1000;
        long usec = (v % 1000) * 1000;
        if (ps == 8) {
            tv.setLong(0, sec);
            tv.setLong(8, usec);
        } else {
            tv.setInt(0, (int) sec);
            tv.setInt(4, (int) usec);
        }
        return setOpt(SOL_SOCKET, SO_RCVTIMEO_POSIX, tv, (int) tv.size()) == 0;
    }

    // =====================================================================
    // 读取回复
    // =====================================================================

    /** 等待一条回复；返回 null 表示超时/错误（记为丢包）。 */
    private Reply waitForReply(long timeoutMs) throws IOException {
        if (!win) {
            pollFd.setInt(0, fd);
            pollFd.setShort(4, (short) (POLLIN | POLLERR));
            pollFd.setShort(6, (short) 0);
            int to = (int) Math.min(Math.max(timeoutMs, 0L), Integer.MAX_VALUE);
            int rc = libc.poll(pollFd, 1, to);
            if (rc < 0 && Native.getLastError() == EINTR) {
                // 被信号中断：重试一次
                pollFd.setShort(6, (short) 0);
                rc = libc.poll(pollFd, 1, to);
            }
            if (rc <= 0) {
                return null; // 超时或错误，记录为丢包
            }
            short revents = pollFd.getShort(6);
            if ((revents & POLLNVAL) != 0) {
                throw new IOException("ICMP套接字无效 (POLLNVAL)");
            }
            if ((revents & POLLIN) != 0) {
                return readDataReply();
            }
            if ((revents & (POLLERR | POLLHUP)) != 0) {
                // dgram + IP_RECVERR：type 11 在错误队列里
                Reply r = readErrorQueueReply();
                if (r != null) {
                    return r;
                }
                // raw 套接字：错误以普通数据形式到达，改走普通读取（SO_RCVTIMEO 限时）
                return readDataReply();
            }
            return null;
        }
        // Windows raw 套接字：type 0 与 type 11 都随 recvfrom 直接到达（SO_RCVTIMEO 限时）
        return readDataReply();
    }

    /** 从普通数据路径读取 ICMP 报文（dgram 直接是 ICMP，raw 自带 IPv4 头）。 */
    private Reply readDataReply() {
        int n = recvFrom(recvBuf, 1500, 0, srcAddr, srcLen);
        if (n < 8) {
            return null; // 读取错误或残缺报文，Go: ReadFrom/ParseMessage 失败 → continue
        }
        byte[] data = recvBuf.getByteArray(0, n);
        int off = 0;
        if (((data[0] >> 4) & 0x0f) == 4) {
            // raw 套接字收到的报文自带 IPv4 头
            int ihl = (data[0] & 0x0f) * 4;
            if (ihl < 20 || n < ihl + 8) {
                return null;
            }
            off = ihl;
        }
        int icmpType = data[off] & 0xff;
        int echoId = ((data[off + 4] & 0xff) << 8) | (data[off + 5] & 0xff);
        int echoSeq = ((data[off + 6] & 0xff) << 8) | (data[off + 7] & 0xff);
        // 响应方地址来自 sockaddr_in 的第 5~8 字节（Go: peer.(*net.IPAddr).IP）
        byte[] addr = srcAddr.getByteArray(4, 4);
        return new Reply(icmpType, ipToString(addr), echoId, echoSeq);
    }

    /**
     * 从错误队列读取 ICMP 错误（IP_RECVERR + MSG_ERRQUEUE）：
     * cmsg = cmsghdr + sock_extended_err + 响应方 sockaddr_in（64 位 msghdr 布局）。
     */
    private Reply readErrorQueueReply() {
        if (!errorQueue || Native.POINTER_SIZE != 8) {
            // msghdr 布局按 64 位结构构造；32 位 JVM 不支持错误队列通道
            return null;
        }
        errName.setShort(0, (short) 0);
        errHdr.setLong(0, Pointer.nativeValue(errName));
        errHdr.setInt(8, 16);                      // msg_namelen
        errHdr.setLong(16, Pointer.nativeValue(errIov));
        errHdr.setLong(24, 1);                     // msg_iovlen
        errHdr.setLong(32, Pointer.nativeValue(errControl));
        errHdr.setLong(40, 256);                   // msg_controllen
        errHdr.setInt(48, 0);                      // msg_flags

        int n = recvMsg(errHdr, MSG_ERRQUEUE);
        if (n < 0) {
            return null;
        }
        long cmsgLen = errControl.getLong(0);
        int level = errControl.getInt(8);
        int type = errControl.getInt(12);
        if (cmsgLen < 16 + 16 + 16 || level != SOL_IP || type != IP_RECVERR) {
            return null;
        }
        // struct sock_extended_err: errno@16 origin@20 type@21 code@22 info@24 data@28
        int eeType = errControl.getByte(21) & 0xff;   // ICMP 类型（11 = Time Exceeded）
        // 响应方 sockaddr 紧跟在 sock_extended_err 之后（SO_EE_OFFENDER）
        if (errControl.getShort(32) != AF_INET) {
            return null;
        }
        byte[] addr = errControl.getByteArray(36, 4);
        return new Reply(eeType, ipToString(addr), -1, -1);
    }

    /** 排空上一轮可能迟到的报文与错误队列，避免串扰下一跳。 */
    private void drainStale() {
        if (win) {
            // Windows 用 1ms 接收超时做非阻塞排空，完成后恢复
            setRecvTimeout(1);
            for (int i = 0; i < 32 && recvFrom(recvBuf, 1500, 0, srcAddr, srcLen) >= 0; i++) {
                // 丢弃迟到报文
            }
            setRecvTimeout(recvTimeoutMs);
            return;
        }
        for (int i = 0; i < 32 && recvFrom(recvBuf, 1500, MSG_DONTWAIT, srcAddr, srcLen) >= 0; i++) {
            // 丢弃迟到报文
        }
        if (errorQueue) {
            // MSG_ERRQUEUE | MSG_DONTWAIT：队列为空时返回 -1（ENOBUFS/EAGAIN）
            for (int i = 0; i < 8; i++) {
                errHdr.setLong(0, Pointer.nativeValue(errName));
                errHdr.setInt(8, 16);
                errHdr.setLong(16, Pointer.nativeValue(errIov));
                errHdr.setLong(24, 1);
                errHdr.setLong(32, Pointer.nativeValue(errControl));
                errHdr.setLong(40, 256);
                errHdr.setInt(48, 0);
                if (recvMsg(errHdr, MSG_ERRQUEUE | MSG_DONTWAIT) < 0) {
                    break;
                }
            }
        }
    }

    // =====================================================================
    // ICMP 报文与地址
    // =====================================================================

    /**
     * 构造 ICMPv4 Echo Request：type=8 code=0，id=pid&0xffff，seq=ttl*count+probe，
     * 载荷长度与格式与 Go 一致，内容随项目改名为 "JYscan Route Detection"
     * （Go 版为 "GYscan Route Detection"，见 internal/cli/route.go:175 —— 品牌改名导致的
     * 有意偏差，不影响 ICMP Echo 的收发与校验和计算），并计算标准校验和。
     */
    static byte[] buildEchoRequest(int id, int seq) {
        byte[] payload = "JYscan Route Detection".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] p = new byte[8 + payload.length];
        p[0] = (byte) ECHO_REQUEST;   // type
        p[1] = 0;                     // code
        p[4] = (byte) (id >> 8);
        p[5] = (byte) id;
        p[6] = (byte) (seq >> 8);
        p[7] = (byte) seq;
        System.arraycopy(payload, 0, p, 8, payload.length);
        int cks = checksum(p);
        p[2] = (byte) (cks >> 8);
        p[3] = (byte) cks;
        return p;
    }

    /** 标准 ICMP 校验和（16 位反码和的反码），与 golang.org/x/net/icmp 的序列化结果一致。 */
    static int checksum(byte[] buf) {
        int sum = 0;
        for (int i = 0; i + 1 < buf.length; i += 2) {
            sum += ((buf[i] & 0xff) << 8) | (buf[i + 1] & 0xff);
        }
        if ((buf.length & 1) == 1) {
            sum += (buf[buf.length - 1] & 0xff) << 8;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        return ~sum & 0xffff;
    }

    /** struct sockaddr_in（16 字节，本机字节序的 sa_family）。 */
    static Pointer buildSockaddr(byte[] addr) {
        Memory sa = new Memory(16);
        sa.setShort(0, (short) AF_INET);
        sa.setShort(2, (short) 0);
        sa.write(4, addr, 0, Math.min(4, addr.length));
        return sa;
    }

    static String ipToString(byte[] addr) {
        if (addr == null || addr.length < 4) {
            return "";
        }
        return (addr[0] & 0xff) + "." + (addr[1] & 0xff) + "." + (addr[2] & 0xff) + "." + (addr[3] & 0xff);
    }
}

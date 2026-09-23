package space.jyscan.modules.route;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Windows 回退通道：JNA 直接调用 iphlpapi.dll 的
 * IcmpCreateFile / IcmpSendEcho / IcmpCloseHandle。
 *
 * <p>jna-platform 5.14 并未封装 ICMP API，因此这里自定义 stdcall 接口。
 * IcmpSendEcho 不像 raw 套接字那样自由收发，只能按 IP_OPTION_INFORMATION.Ttl
 * 指定的 TTL 逐跳探测：
 * <ul>
 *   <li>Status == IP_SUCCESS 视为收到 Echo Reply（到达目标，与 Go 一样立即停止）；</li>
 *   <li>其他状态（TTL 超限等）视为中间路由器响应，响应方地址取回复里的 Address；</li>
 *   <li>调用失败/超时按丢包处理，全部超时的跳照旧输出 "*" 行。</li>
 * </ul>
 */
public final class WindowsIcmpTracer implements AutoCloseable {

    private static final int IP_SUCCESS = 0;

    /** iphlpapi.dll 的 ICMP 接口（stdcall）。 */
    public interface IcmpApi extends StdCallLibrary {
        Pointer IcmpCreateFile();

        int IcmpSendEcho(Pointer icmpHandle, int destinationAddress, byte[] requestData, short requestSize,
                         IP_OPTION_INFORMATION requestOptions, Pointer replyBuffer, int replySize, int timeout);

        boolean IcmpCloseHandle(Pointer icmpHandle);
    }

    /** 对应 Windows 的 IP_OPTION_INFORMATION（注意字段顺序：Ttl 在最前）。 */
    @Structure.FieldOrder({"Ttl", "Tos", "Flags", "OptionsSize", "OptionsData"})
    public static class IP_OPTION_INFORMATION extends Structure {
        public byte Ttl;
        public byte Tos;
        public byte Flags;
        public byte OptionsSize;
        public Pointer OptionsData;
    }

    private final IcmpApi api;
    private final Pointer handle;
    private final int timeoutSec;
    private final byte[] payload = "JYscan Route Detection".getBytes(StandardCharsets.UTF_8);

    public WindowsIcmpTracer(int timeoutSec) throws IOException {
        this.timeoutSec = timeoutSec;
        this.api = Native.load("iphlpapi", IcmpApi.class);
        Pointer h = api.IcmpCreateFile();
        if (h == null || Pointer.nativeValue(h) == 0 || Pointer.nativeValue(h) == -1) {
            throw new IOException("IcmpCreateFile 失败: " + Native.getLastError());
        }
        this.handle = h;
    }

    /**
     * 与 route.go 的 traceRoute 相同的逐跳/多次探测语义。
     */
    public List<RouteHop> trace(InetAddress target, int maxHops, int count) {
        RouteTracer.noteChannel("Windows IcmpSendEcho（JNA iphlpapi.dll 回退）");

        byte[] a = target.getAddress();
        // IPADDR：网络字节序 ULONG（Windows 固定小端）
        int destAddr = (a[0] & 0xff) | ((a[1] & 0xff) << 8) | ((a[2] & 0xff) << 16) | ((a[3] & 0xff) << 24);
        String targetIp = target.getHostAddress();

        List<RouteHop> hops = new ArrayList<>();
        for (int ttl = 1; ttl <= maxHops; ttl++) {
            IP_OPTION_INFORMATION opt = new IP_OPTION_INFORMATION();
            opt.Ttl = (byte) ttl;   // 尝试按跳数设置请求 TTL
            opt.Tos = 0;
            opt.Flags = 0;
            opt.OptionsSize = 0;
            opt.OptionsData = null;

            RouteHop hop = new RouteHop();
            List<Long> delays = new ArrayList<>();   // 每次成功探测的延时（微秒）
            int successCount = 0;

            for (int probe = 0; probe < count; probe++) {
                Memory replyBuf = new Memory(64L + payload.length);
                // DWORD：成功时返回非零（失败/超时为 0，错误码在 GetLastError）
                int ok = api.IcmpSendEcho(handle, destAddr, payload, (short) payload.length, opt,
                        replyBuf, (int) replyBuf.size(), Math.max(0, timeoutSec) * 1000);
                if (ok == 0) {
                    continue; // 超时或错误，记录为丢包
                }
                // ICMP_ECHO_REPLY: Address@0 Status@4 RoundTripTime@8 ...
                int status = replyBuf.getInt(4);
                long rttMs = replyBuf.getInt(8) & 0xffffffffL;
                byte[] replyAddr = replyBuf.getByteArray(0, 4);
                String responder = IcmpSocketTracer.ipToString(replyAddr);

                if (status == IP_SUCCESS) {
                    // 收到 Echo Reply：到达目标，结束路由检测
                    delays.add(rttMs * 1000L);
                    successCount++;
                    if (hop.ip == null) {
                        hop.hop = String.valueOf(ttl);
                        hop.ip = targetIp;
                        hop.hostname = ReverseDns.lookup(targetIp);
                    }
                    if (!delays.isEmpty()) {
                        hop.avgDelay = RouteHop.avgDelayMillis(delays);
                        hop.lossRate = RouteHop.lossRate(count, successCount);
                        hops.add(hop);
                    }
                    return hops;
                }

                // TTL 超限等状态：中间路由器响应
                if (responder.isEmpty() || "0.0.0.0".equals(responder)) {
                    continue;
                }
                delays.add(rttMs * 1000L);
                successCount++;
                if (hop.ip == null) {
                    hop.hop = String.valueOf(ttl);
                    hop.ip = responder;
                    hop.hostname = ReverseDns.lookup(responder);
                }
            }

            // 记录当前跳数的结果（与 Go 相同）
            if (hop.ip != null) {
                if (!delays.isEmpty()) {
                    hop.avgDelay = RouteHop.avgDelayMillis(delays);
                }
                hop.lossRate = RouteHop.lossRate(count, successCount);
                hops.add(hop);
            } else {
                hops.add(RouteHop.noReply(ttl));
            }
        }
        return hops;
    }

    @Override
    public void close() {
        if (handle != null && api != null) {
            api.IcmpCloseHandle(handle);
        }
    }
}

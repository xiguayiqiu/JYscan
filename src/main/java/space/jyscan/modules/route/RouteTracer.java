package space.jyscan.modules.route;

import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.SystemUtil;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/**
 * 路由检测入口：选择可用的探测通道并依次回退，
 * 仅在 verbose 模式下打印实际使用的通道。
 *
 * <p>回退顺序（与说明一致）：
 * <ol>
 *   <li>JNA ICMP 套接字（dgram ping 套接字，其次 raw）——Linux 首选；</li>
 *   <li>Windows：JNA IcmpSendEcho（iphlpapi.dll）；</li>
 *   <li>系统命令：traceroute / tracepath / tracert / ping。</li>
 * </ol>
 */
public final class RouteTracer {

    private RouteTracer() {
    }

    /**
     * 等价于 Go 的 net.ResolveIPAddr("ip", target)：支持 IP 字面量与域名，优先返回 IPv4 地址。
     */
    public static InetAddress resolveIPv4(String target) throws UnknownHostException {
        if (target == null || target.isEmpty()) {
            // Java 对空串会返回回环地址，而 Go 会报错，这里对齐 Go
            throw new UnknownHostException("no such host");
        }
        InetAddress[] addrs = InetAddress.getAllByName(target);
        if (addrs.length == 0) {
            throw new UnknownHostException(target);
        }
        for (InetAddress a : addrs) {
            if (a instanceof Inet4Address) {
                return a;
            }
        }
        // 全是 IPv6：与 Go 的 net.ResolveIPAddr("ip", ...) 取第一个地址一致
        return addrs[0];
    }

    /**
     * 仅 verbose 模式下提示本次使用的探测通道（对应 --verbose/Colors.isVerbose）。
     */
    static void noteChannel(String channel) {
        if (Colors.isVerbose) {
            Colors.debugPrint("[+] 路由探测通道: %s", channel);
        }
    }

    /**
     * 对应 route.go 的 traceRoute：任一通道不可用时依次回退，
     * 各通道输出完全相同的 RouteHop 列表（表格布局不变）。
     */
    public static List<RouteHop> traceRoute(InetAddress target, int maxHops, int timeoutSec, int count)
            throws IOException {
        IOException firstErr = null;

        // 1) 首选：JNA 直连 ICMP 套接字（dgram ping 套接字，其次 raw）
        IcmpSocketTracer socketTracer = null;
        try {
            socketTracer = IcmpSocketTracer.open(timeoutSec);
        } catch (IOException e) {
            firstErr = new IOException(Fmt.format("创建ICMP连接失败: %v", e));
        } catch (UnsatisfiedLinkError | SecurityException e) {
            firstErr = new IOException(Fmt.format("创建ICMP连接失败: %v", e.toString()));
        }
        if (socketTracer != null) {
            try {
                return socketTracer.trace(target, maxHops, timeoutSec, count);
            } catch (IOException e) {
                firstErr = e;
            } catch (UnsatisfiedLinkError e) {
                firstErr = new IOException(e.toString());
            } finally {
                socketTracer.close();
            }
        }

        // 2) Windows：退回 JNA IcmpSendEcho
        if (SystemUtil.isWindows()) {
            try {
                WindowsIcmpTracer w = new WindowsIcmpTracer(timeoutSec);
                try {
                    return w.trace(target, maxHops, count);
                } finally {
                    w.close();
                }
            } catch (Throwable t) {
                // 继续退到系统命令
            }
        }

        // 3) 最后：traceroute / tracepath / tracert / ping 系统命令回退
        try {
            return ShellTracer.trace(target.getHostAddress(), maxHops, timeoutSec, count);
        } catch (IOException e) {
            if (firstErr == null) {
                throw e;
            }
            throw new IOException(Fmt.format("%v；系统命令回退失败: %v", firstErr, e), e);
        }
    }
}

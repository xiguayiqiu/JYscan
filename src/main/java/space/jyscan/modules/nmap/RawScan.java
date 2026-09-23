package space.jyscan.modules.nmap;

import space.jyscan.core.i18n.I18n;
import space.jyscan.core.util.SystemUtil;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 隐蔽扫描类型（FIN/XMAS/NULL/ACK/Window/Maimon），移植自
 * freeclient/internal/nmap/rawscan_{linux,windows}.go。
 *
 * <p><b>归属</b>：本文件由 D 号子代理实现。六个签名被 B 号（扫描引擎 scan.go:974-999）
 * 调用，请勿改动签名。
 *
 * <p>返回值是 nmap 的<b>端口状态串</b>，取值见 {@link NmapConstants}。
 * raw socket 引擎、收包匹配与校验和在 {@link RawScanEngine}；权限不足时按 Go 的
 * {@code rawScanAvailable} 一次性检测降级为 connect 扫描（只告警一次，无异常栈）。
 *
 * <p>平台差异对应 Go 的 build tag {@code _linux}/{@code _windows}：Windows 侧打印
 * {@code nmap.warn.win_raw_*} 并退化为 {@link #fallbackConnectScan}，其余平台走
 * {@link #stealthScanPort}，与 Go 的 {@code !windows} 文件一致。
 */
public final class RawScan {

    private RawScan() {
    }

    /** TCP FIN 扫描，判定 open|filtered。 */
    public static String rawFINScan(String ip, int port, Duration timeout) {
        return stealth(ip, port, timeout, RawScanEngine.tcpFIN, "nmap.warn.win_raw_fin");
    }

    /** TCP XMAS 扫描，判定 open|filtered。 */
    public static String rawXMASScan(String ip, int port, Duration timeout) {
        return stealth(ip, port, timeout,
                RawScanEngine.tcpFIN | RawScanEngine.tcpPSH | RawScanEngine.tcpURG,
                "nmap.warn.win_raw_xmas");
    }

    /** TCP NULL 扫描，判定 open|filtered。 */
    public static String rawNULLScan(String ip, int port, Duration timeout) {
        return stealth(ip, port, timeout, 0x00, "nmap.warn.win_raw_null");
    }

    /** TCP ACK 扫描，判定 unfiltered。 */
    public static String rawACKScan(String ip, int port, Duration timeout) {
        return stealth(ip, port, timeout, RawScanEngine.tcpACK, "nmap.warn.win_raw_ack");
    }

    /** TCP Window 扫描（Go: rawWindowScan 同样传 tcpACK，逐行保持一致）。 */
    public static String rawWindowScan(String ip, int port, Duration timeout) {
        return stealth(ip, port, timeout, RawScanEngine.tcpACK, "nmap.warn.win_raw_window");
    }

    /** TCP Maimon 扫描。 */
    public static String rawMaimonScan(String ip, int port, Duration timeout) {
        return stealth(ip, port, timeout,
                RawScanEngine.tcpFIN | RawScanEngine.tcpACK, "nmap.warn.win_raw_maimon");
    }

    /**
     * 六个扫描的公共入口：Windows 按 rawscan_windows.go 打印 i18n 告警后退化为
     * connect 扫描；其余平台走 raw 引擎（不可用时内部自动降级）。
     */
    private static String stealth(String ip, int port, Duration timeout, int flags,
                                  String winWarnKey) {
        if (SystemUtil.isWindows()) {
            // Go: fmt.Println(i18n.T("nmap.warn.win_raw_*"))
            System.out.println(I18n.T(winWarnKey));
            return fallbackConnectScan(ip, port, timeout);
        }
        return stealthScanPort(ip, port, timeout, flags);
    }

    // =====================================================================
    // Go: stealthScanPort（rawscan_linux.go:348-368）
    // =====================================================================

    static String stealthScanPort(String ip, int port, Duration timeout, int flags) {
        if ("127.0.0.1".equals(ip) || "::1".equals(ip) || "localhost".equals(ip)) {
            return localhostStealthScan(ip, port, timeout, flags);
        }

        if (RawScanEngine.isRawScanAvailable()) {
            byte[] dstIP = RawScanEngine.parseIPv4(ip);
            if (dstIP != null) {
                byte[] srcIP = RawScanEngine.localIPFor(ip);
                // Go: rand.Intn(60000) + 1024
                int srcPort = ThreadLocalRandom.current().nextInt(60000) + 1024;
                RawScanEngine.RawScanResult result =
                        RawScanEngine.rawTCPSend(srcIP, dstIP, srcPort, port, flags, timeout);
                if (result.received()) {
                    return result.state();
                }
                // Go 注释: Linux IPPROTO_TCP recv cannot capture locally-generated RST.
                // Fall through to connect-based detection below.
            }
        }

        return connectBasedStealthScan(ip, port, timeout, flags);
    }

    // =====================================================================
    // Go: localhostStealthScan（成功时 ACK→unfiltered，否则 open|filtered）
    // =====================================================================

    private static String localhostStealthScan(String ip, int port, Duration timeout, int flags) {
        int r = connectTcp(ip, port, timeout);
        if (r == CONNECT_TIMEOUT) {
            return NmapConstants.PORT_STATE_FILTERED;
        }
        if (r == CONNECT_FAIL) {
            // Go: connection refused → closed；其余错误同样归 closed
            return NmapConstants.PORT_STATE_CLOSED;
        }
        if (flags == RawScanEngine.tcpACK) {
            return NmapConstants.PORT_STATE_UNFILTERED;
        }
        return NmapConstants.PORT_STATE_OPEN_FILTERED;
    }

    // =====================================================================
    // Go: connectBasedStealthScan（成功时 ACK→unfiltered，否则 open）
    // =====================================================================

    private static String connectBasedStealthScan(String ip, int port, Duration timeout, int flags) {
        int r = connectTcp(ip, port, timeout);
        if (r == CONNECT_TIMEOUT) {
            return NmapConstants.PORT_STATE_FILTERED;
        }
        if (r == CONNECT_FAIL) {
            // Go: connection refused → closed；其余错误同样归 closed
            return NmapConstants.PORT_STATE_CLOSED;
        }
        if (flags == RawScanEngine.tcpACK) {
            return NmapConstants.PORT_STATE_UNFILTERED;
        }
        return NmapConstants.PORT_STATE_OPEN;
    }

    // =====================================================================
    // Go: fallbackConnectScan（rawscan_windows.go:52-62）
    // =====================================================================

    /** Windows 降级通道：timeout→filtered，其余失败→closed，成功→open。 */
    static String fallbackConnectScan(String ip, int port, Duration timeout) {
        int r = connectTcp(ip, port, timeout);
        if (r == CONNECT_TIMEOUT) {
            return NmapConstants.PORT_STATE_FILTERED;
        }
        if (r == CONNECT_FAIL) {
            return NmapConstants.PORT_STATE_CLOSED;
        }
        return NmapConstants.PORT_STATE_OPEN;
    }

    // =====================================================================
    // 统一的 connect 判定（对应 Go net.DialTimeout 的错误分类）
    // =====================================================================

    private static final int CONNECT_OK = 0;
    private static final int CONNECT_TIMEOUT = 1;
    private static final int CONNECT_FAIL = 2;

    /**
     * Go 的 net.DialTimeout 分类：{@code netErr.Timeout()} → filtered；
     * 其余（含 connection refused）→ closed。close 错误按 Go 一样丢弃，
     * 不参与判定；任何异常都不外抛。
     */
    private static int connectTcp(String ip, int port, Duration timeout) {
        long ms = RawScanEngine.toMillis(timeout);
        if (ms < 0) {
            // Go: 负 duration → deadline 已过 → 立即超时
            return CONNECT_TIMEOUT;
        }
        int connectMs = (int) Math.min(ms, Integer.MAX_VALUE);
        Socket conn = new Socket();
        try {
            // Go timeout=0 表示不超时，Java connect(timeout=0) 同义
            conn.connect(new InetSocketAddress(ip, port), connectMs);
            return CONNECT_OK;
        } catch (SocketTimeoutException e) {
            return CONNECT_TIMEOUT;
        } catch (IOException e) {
            return CONNECT_FAIL;
        } finally {
            try {
                conn.close();
            } catch (IOException ignore) {
                // Go: conn.Close() 的错误被丢弃，不影响判定
            }
        }
    }
}

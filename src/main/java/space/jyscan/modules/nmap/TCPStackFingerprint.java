package space.jyscan.modules.nmap;

/**
 * TCP/IP 栈指纹数据，移植自 freeclient/internal/nmap/tcpfingerprint.go 的 TCPStackFingerprint。
 *
 * <p>该类型由 {@code TcpFingerprint}（raw SYN 抓包）产生、交给 {@code MatchOSFingerprint}
 * 消费，跨 D 与 B 两个模块，故放在共享层。Go 侧无 json tag，不参与序列化。
 */
public class TCPStackFingerprint {

    public int ttl;
    public int windowSize;
    public int mss;
    /** TCP窗口缩放因子, -1 表示未出现 */
    public int windowShift = -1;
    public boolean sackPermitted;
    public boolean timestamps;
    /** TCP选项总长度(字节) */
    public int tcpOptionsLen;

    @Override
    public String toString() {
        return "TCPStackFingerprint{ttl=" + ttl + ", windowSize=" + windowSize + ", mss=" + mss
                + ", windowShift=" + windowShift + ", sackPermitted=" + sackPermitted
                + ", timestamps=" + timestamps + ", tcpOptionsLen=" + tcpOptionsLen + "}";
    }
}

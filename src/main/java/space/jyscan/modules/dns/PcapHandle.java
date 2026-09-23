package space.jyscan.modules.dns;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Memory;
import space.jyscan.core.util.SystemUtil;

/**
 * 打开的 pcap 句柄封装，对应 Go 的 *pcap.Handle
 * (SetBPFFilter / NextPacket / Close)。
 */
public final class PcapHandle implements AutoCloseable {

    /** pcap_pkthdr 中 caplen 字段的字节偏移。
     * struct pcap_pkthdr {
     *   struct pcap_timeval ts;    // 16 bytes on 64-bit POSIX, 8 on 32-bit
     *   uint32_t caplen;           // offset = sizeof(ts)
     *   uint32_t len;
     * }
     */
    private static final int CAPLEN_OFFSET = computeCapLenOffset();

    private final PcapApi.LibPcap api;
    private final Pointer handle;
    private final Memory pkthdrMem;   // 用于接收 pcap_next_ex 写入的 pkthdr
    private final Memory dataCell;     // 用于接收 packet 数据指针

    private PcapHandle(PcapApi.LibPcap api, Pointer handle) {
        this.api = api;
        this.handle = handle;
        this.pkthdrMem = new Memory(PcapApi.PKTHDR_SIZE);
        // 预分配数据缓冲区，默认最大 MTU 规模
        this.dataCell = new Memory(PcapApi.ERRBUF_SIZE / 4 + 64);
    }

    /** 打开实时抓包，对应 Go 的 pcap.OpenLive + SetBPFFilter。
     * @param device    网络接口名
     * @param snaplen   快照长度
     * @param promisc   是否混杂模式
     * @param bpfFilter BPF 表达式
     * @param errOut    长度为 1 的数组，失败时写入错误消息
     * @return 句柄；失败返回 null */
    static PcapHandle open(String device, int snaplen, boolean promisc,
                            String bpfFilter, String[] errOut) {
        PcapApi.LibPcap api = PcapApi.load();
        if (api == null) {
            errOut[0] = "未找到 libpcap 动态库（请安装 libpcap / npcap）";
            return null;
        }

        byte[] errbuf = new byte[PcapApi.ERRBUF_SIZE];
        Pointer p = api.pcap_open_live(device, snaplen, promisc ? 1 : 0, 200, errbuf);
        if (p == null || Pointer.nativeValue(p) == 0) {
            errOut[0] = cstring(errbuf);
            if (errOut[0].isEmpty()) errOut[0] = "打开接口 " + device + " 失败";
            return null;
        }

        // BPF 过滤器
        final Memory program = new Memory(PcapApi.BPF_PROGRAM_SIZE);
        program.clear();
        try {
            if (api.pcap_compile(p, program, bpfFilter, 1, 0xFFFFFFFF) != 0) {
                errOut[0] = perr(api, p);
                api.pcap_close(p);
                return null;
            }
            if (api.pcap_setfilter(p, program) != 0) {
                errOut[0] = perr(api, p);
                api.pcap_freecode(program);
                api.pcap_close(p);
                return null;
            }
            api.pcap_freecode(program);
        } catch (UnsatisfiedLinkError e) {
            errOut[0] = "libpcap 符号缺失: " + e.getMessage();
            api.pcap_close(p);
            return null;
        }

        return new PcapHandle(api, p);
    }

    /** 链路类型，对应 Go 的 handle.LinkType()。 */
    public int dataLink() {
        return api.pcap_datalink(handle);
    }

    /** 读取下一个数据包。
     * @param capLenOut 长度为 1 的数组，用于输出抓取长度
     * @return 抓到的包数据；超时返回 null 且 capLenOut[0]==0；
     *         错误/结束返回 null 且 capLenOut[0]==-1 */
    public byte[] nextPacket(int[] capLenOut) {
        capLenOut[0] = 0;
        int rc = api.pcap_next_ex(handle, pkthdrMem, dataCell);
        if (rc == PcapApi.PCAP_OK) {
            // pcap_pkthdr 中 caplen 字段位于 pkthdrMem 的 CAPLEN_OFFSET 偏移处
            int caplen = readUInt32(pkthdrMem, CAPLEN_OFFSET);
            if (caplen == 0 || caplen > 262144) { // 超过 256KB 认为异常
                capLenOut[0] = -1;
                return null;
            }
            byte[] payload = dataCell.getByteArray(0, caplen);
            capLenOut[0] = caplen;
            return payload;
        }
        if (rc == PcapApi.PCAP_TIMEOUT) {
            capLenOut[0] = 0;
            return null;
        }
        // PCAP_ERROR / PCAP_ERROR_BREAK
        capLenOut[0] = -1;
        return null;
    }

    @Override
    public void close() {
        try {
            api.pcap_close(handle);
        } catch (UnsatisfiedLinkError ignored) {
        }
    }

    private static int computeCapLenOffset() {
        if (SystemUtil.isWindows()) {
            // Windows pcap_timeval: 两个 4 字节 longs
            return 8;
        }
        if (Native.POINTER_SIZE == 8) {
            // POSIX 64 位: pcap_timeval = 两个 4 字节 + 2 个 8 字节? 实际是
            // typedef struct pcap_timeval { time_t tv_sec; suseconds_t tv_usec; };
            // time_t 是 8 字节 (64 位)，suseconds_t 是 4 字节 → 16 字节
            return 16;
        } else {
            return 8;
        }
    }

    /** 从 Memory 中读取小端序 uint32 值。
     * Memory 基于 jna 分配的原始内存，getByte 返回 byte (有符号)，
     * 这里手动组装成 uint32。 */
    private static int readUInt32(Memory mem, int offset) {
        int b0 = mem.getByte(offset) & 0xFF;
        int b1 = mem.getByte(offset + 1) & 0xFF;
        int b2 = mem.getByte(offset + 2) & 0xFF;
        int b3 = mem.getByte(offset + 3) & 0xFF;
        return (b0 <<  0) | (b1 <<  8) | (b2 << 16) | (b3 << 24);
    }

    private static String perr(PcapApi.LibPcap api, Pointer p) {
        try {
            String s = api.pcap_geterr(p);
            return s == null ? "未知错误" : s;
        } catch (UnsatisfiedLinkError e) {
            return "未知错误";
        }
    }

    private static String cstring(byte[] buf) {
        int end = 0;
        while (end < buf.length && buf[end] != 0) end++;
        return new String(buf, 0, end,
                java.nio.charset.StandardCharsets.US_ASCII).trim();
    }
}

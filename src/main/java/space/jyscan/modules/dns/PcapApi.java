package space.jyscan.modules.dns;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import space.jyscan.core.util.SystemUtil;

/**
 * libpcap 的最小 JNA 绑定，对应 Go 侧 pcap 的用法。
 *
 * <p>只绑定 DNS 监听实际用到的入口：pcap_open_live / pcap_datalink / pcap_compile /
 * pcap_setfilter / pcap_freecode / pcap_next_ex / pcap_geterr / pcap_close。
 */
public final class PcapApi {

    public static final int ERRBUF_SIZE = 256;

    public static final int PCAP_OK = 1;
    public static final int PCAP_TIMEOUT = 0;
    public static final int PCAP_ERROR = -1;
    public static final int PCAP_ERROR_BREAK = -2;

    public static final int BPF_MAX_INSTR = 150;  // bpf_insn 数的上限
    public static final int BPF_PROGRAM_SIZE = 64;   // 声明式预留；实际是 bpf_program 对象的大小
    public static final int PKTHDR_SIZE = 32;        // struct pcap_pkthdr 大致字节数

    private PcapApi() {}

    public interface LibPcap extends Library {
        Pointer pcap_open_live(String device, int snaplen, int promisc, int to_ms, byte[] errbuf);
        void pcap_close(Pointer p);
        int pcap_datalink(Pointer p);
        int pcap_compile(Pointer p, Pointer bp, String str, int optimize, int netmask);
        int pcap_setfilter(Pointer p, Pointer bp);
        void pcap_freecode(Pointer bp);
        int pcap_next_ex(Pointer p, Pointer pkthdr, Pointer pktdata);
        String pcap_geterr(Pointer p);
    }

    private static volatile LibPcap api;
    private static volatile boolean loadFailed;

    public static LibPcap load() {
        LibPcap a = api;
        if (a != null) return a;
        if (loadFailed) return null;
        synchronized (PcapApi.class) {
            if (api == null && !loadFailed) {
                for (String name : candidates()) {
                    try {
                        api = Native.load(name, LibPcap.class);
                        break;
                    } catch (UnsatisfiedLinkError e) {}
                }
                if (api == null) loadFailed = true;
            }
            return api;
        }
    }

    private static String[] candidates() {
        if (SystemUtil.isWindows())
            return new String[]{"wpcap", "pcap"};
        return new String[]{"pcap", "libpcap.so.1", "libpcap.so", "libpcap"};
    }
}

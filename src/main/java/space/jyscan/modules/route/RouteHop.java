package space.jyscan.modules.route;

import java.util.List;

/**
 * 路由检测结果结构，移植自 freeclient/internal/cli/route.go 的 RouteHop。
 */
public final class RouteHop {

    /** 跳数（Go 侧为 fmt.Sprintf("%d", ttl) 得到的字符串） */
    public String hop;

    /** 响应此跳的 IP；null 表示无响应（表格里输出 "*"） */
    public String ip;

    /** 反向解析的主机名；空串在输出时显示为 "未知" */
    public String hostname;

    /** 平均延时（毫秒） */
    public double avgDelay;

    /** 丢包率（百分比数值，0~100） */
    public double lossRate;

    public RouteHop() {
    }

    /**
     * 当前跳数无响应的行（Go: RouteHop{Hop: fmt.Sprintf("%d", ttl), AvgDelay: 0, LossRate: 100.0}，IP 为 nil）。
     */
    public static RouteHop noReply(int ttl) {
        RouteHop h = new RouteHop();
        h.hop = String.valueOf(ttl);
        h.ip = null;
        h.hostname = "";
        h.avgDelay = 0;
        h.lossRate = 100.0;
        return h;
    }

    /**
     * Go: hop.AvgDelay = float64(totalLatency.Microseconds()) / float64(len(delays)) / 1000.0
     *
     * @param delaysMicros 每次成功探测的延时（微秒）
     */
    static double avgDelayMillis(List<Long> delaysMicros) {
        long total = 0;
        for (long d : delaysMicros) {
            total += d;
        }
        return (double) total / (double) delaysMicros.size() / 1000.0;
    }

    /**
     * Go: hop.LossRate = float64(count-successCount) / float64(count) * 100.0
     */
    static double lossRate(int count, int successCount) {
        return (double) (count - successCount) / (double) count * 100.0;
    }
}

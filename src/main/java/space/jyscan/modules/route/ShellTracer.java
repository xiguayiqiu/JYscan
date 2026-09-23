package space.jyscan.modules.route;

import space.jyscan.core.util.SystemUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 系统命令回退：ICMP 套接字不可用时改用 traceroute / tracepath / tracert / ping，
 * 把输出解析成与 Go 完全相同的 RouteHop 行（表格布局不变）。
 */
public final class ShellTracer {

    private ShellTracer() {
    }

    /** 跳数行：traceroute " 1  1.2.3.4  0.5 ms"、tracepath " 1: 1.2.3.4 1.886 毫秒"、tracert " 1 <1ms ..." */
    private static final Pattern HOP_LINE = Pattern.compile("^\\s*(\\d+)(?:\\?)?\\s*[:,]?\\s*(.+)$");
    private static final Pattern IPV4 = Pattern.compile("(?<!\\d)(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(?!\\d)");
    private static final Pattern LATENCY = Pattern.compile("<?(\\d+(?:\\.\\d+)?)\\s*(?:ms|毫秒)");
    private static final Pattern PING_FROM = Pattern.compile("From\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})");
    private static final Pattern PING_BYTES = Pattern.compile("bytes from\\s+(\\d{1,3}(?:\\.\\d{1,3}){3})");
    private static final Pattern PING_TIME = Pattern.compile("time=<?(\\d+(?:\\.\\d+)?)\\s*ms");

    /** 一个跳数在系统命令输出里的聚合结果。 */
    private static final class HopAgg {
        String ip;
        final List<Double> times = new ArrayList<>();
    }

    /** 执行系统命令并把 InterruptedException 折叠成 IOException（exec 的受检异常）。 */
    private static String run(String... argv) throws IOException {
        try {
            return SystemUtil.exec(argv);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("系统命令执行被中断: " + e);
        }
    }

    /**
     * 执行系统命令回退并解析成 RouteHop 行。
     *
     * <p>选择顺序：Windows 用 tracert；否则 traceroute → tracepath → ping 逐跳。
     * 实际使用的通道仅在 verbose 模式下提示。
     */
    public static List<RouteHop> trace(String targetIp, int maxHops, int timeoutSec, int count) throws IOException {
        String out;
        String channel;

        if (SystemUtil.isWindows() && SystemUtil.isCommandAvailable("tracert")) {
            channel = "tracert 系统命令（回退）";
            out = run("tracert", "-d", "-h", String.valueOf(maxHops),
                    "-w", String.valueOf(Math.max(0, timeoutSec) * 1000), targetIp);
        } else if (SystemUtil.isCommandAvailable("traceroute")) {
            channel = "traceroute 系统命令（回退）";
            // traceroute -n -m <max> -w <timeout> <target>
            out = run("traceroute", "-n", "-m", String.valueOf(maxHops),
                    "-w", String.valueOf(timeoutSec), targetIp);
        } else if (SystemUtil.isCommandAvailable("tracepath")) {
            channel = "tracepath 系统命令（回退）";
            // tracepath -n（部分发行版不支持 -w，超时由 exec 的 waitFor 兜底）
            out = run("tracepath", "-n", "-m", String.valueOf(maxHops), targetIp);
        } else if (SystemUtil.isCommandAvailable("ping")) {
            // 最后手段：逐跳 ping -t <ttl>（Windows 用 -i）
            return pingByTtl(targetIp, maxHops, timeoutSec, count);
        } else {
            throw new IOException("traceroute/tracepath/ping 系统命令均不可用");
        }

        if (out == null || out.isEmpty()) {
            throw new IOException(channel + " 无输出");
        }
        List<RouteHop> hops = parseHopLines(out, targetIp, maxHops, count);
        if (hops.isEmpty()) {
            throw new IOException(channel + " 输出无法解析");
        }
        RouteTracer.noteChannel(channel);
        return hops;
    }

    // =====================================================================
    // traceroute / tracepath / tracert 输出解析
    // =====================================================================

    private static List<RouteHop> parseHopLines(String out, String targetIp, int maxHops, int count) {
        // 按跳数聚合：traceroute 每探测一行、tracepath 同一跳可能多行，全部并到同一跳上
        Map<Integer, HopAgg> aggs = new LinkedHashMap<>();
        for (String line : out.split("\n")) {
            Matcher m = HOP_LINE.matcher(line);
            if (!m.matches()) {
                continue;
            }
            int hopNo;
            try {
                hopNo = Integer.parseInt(m.group(1));
            } catch (NumberFormatException e) {
                continue;
            }
            if (hopNo < 1 || hopNo > maxHops) {
                continue;
            }
            String rest = m.group(2);
            HopAgg agg = aggs.computeIfAbsent(hopNo, k -> new HopAgg());
            Matcher ipm = IPV4.matcher(rest);
            if (agg.ip == null && ipm.find()) {
                agg.ip = ipm.group(1);
            }
            Matcher lm = LATENCY.matcher(rest);
            while (lm.find()) {
                try {
                    agg.times.add(Double.parseDouble(lm.group(1)));
                } catch (NumberFormatException ignored) {
                    // 忽略无法解析的时间
                }
            }
        }
        if (aggs.isEmpty()) {
            return new ArrayList<>();
        }

        // 是否已到达目标（Go 收到目标的 Echo Reply 即停止）
        int destHop = Integer.MAX_VALUE;
        for (Map.Entry<Integer, HopAgg> e : aggs.entrySet()) {
            if (targetIp.equals(e.getValue().ip)) {
                destHop = Math.min(destHop, e.getKey());
            }
        }
        boolean reached = destHop != Integer.MAX_VALUE;
        // 未到达目标时与 Go 一样一路补行到 maxHops（无响应跳输出 * / 0.00 / 100.0%）
        int topHop = reached ? destHop : maxHops;

        List<RouteHop> hops = new ArrayList<>();
        int c = Math.max(count, 1);
        for (int t = 1; t <= topHop; t++) {
            HopAgg a = aggs.get(t);
            if (a == null || a.ip == null || a.times.isEmpty()) {
                // 无响应行（Go: RouteHop{Hop, AvgDelay: 0, LossRate: 100}，IP 为 nil）
                hops.add(RouteHop.noReply(t));
                continue;
            }
            RouteHop h = new RouteHop();
            h.hop = String.valueOf(t);
            h.ip = a.ip;
            h.hostname = ReverseDns.lookup(a.ip);
            double total = 0;
            for (double d : a.times) {
                total += d;
            }
            h.avgDelay = total / a.times.size();
            int responded = Math.min(a.times.size(), c);
            h.lossRate = Math.max(0.0, (double) (c - responded) / (double) c * 100.0);
            hops.add(h);
        }
        return hops;
    }

    // =====================================================================
    // ping 逐跳回退
    // =====================================================================

    /**
     * 最后手段：对每个 TTL 执行一次 ping（Linux: -t &lt;ttl&gt;，Windows: -i &lt;ttl&gt;）。
     * 收到 Echo Reply 视为到达目标并立即结束；只收到 "Time to live exceeded"
     * 则该跳记为中间路由器（ping 不回显超时报文的 RTT，平均延时按 0 计算）。
     */
    private static List<RouteHop> pingByTtl(String targetIp, int maxHops, int timeoutSec, int count)
            throws IOException {
        boolean win = SystemUtil.isWindows();
        List<RouteHop> hops = new ArrayList<>();
        int c = Math.max(count, 1);

        for (int ttl = 1; ttl <= maxHops; ttl++) {
            List<String> argv = new ArrayList<>();
            argv.add("ping");
            argv.add("-n");
            if (win) {
                // Windows: ping -n <count> -w <ms> -i <ttl> <target>
                argv.add(String.valueOf(count));
                argv.add("-w");
                argv.add(String.valueOf(Math.max(0, timeoutSec) * 1000));
                argv.add("-i");
                argv.add(String.valueOf(ttl));
            } else {
                // Linux: ping -n -c <count> -W <秒> -t <ttl> <target>
                argv.add("-c");
                argv.add(String.valueOf(count));
                argv.add("-W");
                argv.add(String.valueOf(Math.max(0, timeoutSec)));
                argv.add("-t");
                argv.add(String.valueOf(ttl));
            }
            argv.add(targetIp);

            String out = SystemUtil.execQuietly(argv.toArray(new String[0]));
            if (out == null) {
                throw new IOException("ping 系统命令执行失败");
            }

            // 中间路由器响应："From 192.168.0.1 icmp_seq=1 Time to live exceeded"
            int fromCount = 0;
            String routerIp = null;
            Matcher from = PING_FROM.matcher(out);
            while (from.find()) {
                fromCount++;
                if (routerIp == null) {
                    routerIp = from.group(1);
                }
            }
            // 目标响应："64 bytes from 8.8.8.8: ..."
            int echoCount = 0;
            String echoIp = null;
            Matcher bytes = PING_BYTES.matcher(out);
            while (bytes.find()) {
                echoCount++;
                if (echoIp == null) {
                    echoIp = bytes.group(1);
                }
            }
            List<Double> times = new ArrayList<>();
            Matcher tm = PING_TIME.matcher(out);
            while (tm.find()) {
                try {
                    times.add(Double.parseDouble(tm.group(1)));
                } catch (NumberFormatException ignored) {
                    // 忽略
                }
            }

            if (echoCount > 0) {
                // 收到 Echo Reply：到达目标（与 Go 一致，记录后立即停止）
                RouteHop h = new RouteHop();
                h.hop = String.valueOf(ttl);
                h.ip = echoIp != null ? echoIp : targetIp;
                h.hostname = ReverseDns.lookup(h.ip);
                h.avgDelay = times.isEmpty() ? 0 : mean(times);
                int responded = Math.min(echoCount, c);
                h.lossRate = Math.max(0.0, (double) (c - responded) / (double) c * 100.0);
                hops.add(h);
                RouteTracer.noteChannel("ping 逐跳回退（-t TTL）");
                return hops;
            }
            if (fromCount > 0 && routerIp != null) {
                // 中间路由器：ping 不回显超时报文的 RTT，平均延时按 0 计算
                RouteHop h = new RouteHop();
                h.hop = String.valueOf(ttl);
                h.ip = routerIp;
                h.hostname = ReverseDns.lookup(routerIp);
                h.avgDelay = times.isEmpty() ? 0 : mean(times);
                int responded = Math.min(fromCount, c);
                h.lossRate = Math.max(0.0, (double) (c - responded) / (double) c * 100.0);
                hops.add(h);
                continue;
            }
            // 当前跳数无响应
            hops.add(RouteHop.noReply(ttl));
        }
        RouteTracer.noteChannel("ping 逐跳回退（-t TTL）");
        return hops;
    }

    private static double mean(List<Double> values) {
        double total = 0;
        for (double v : values) {
            total += v;
        }
        return total / values.size();
    }
}

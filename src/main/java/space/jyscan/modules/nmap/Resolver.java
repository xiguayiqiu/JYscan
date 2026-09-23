package space.jyscan.modules.nmap;

import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * DNS 解析，移植自 freeclient/internal/nmap/resolver.go。
 *
 * <p><b>归属</b>：本文件由 B 号子代理实现（resolver.go 255 行）。
 * 下面的签名被 E 号（NmapUtils 的 validateTarget / getHostname）依赖，请勿改动。
 *
 * <p>Go 侧的回退策略要保留：先用系统解析；系统有可用 DNS 配置且错误为「未找到」时不回退；
 * 连接 refused/timeout 时才逐个尝试公共 DNS（{@code fallbackDNSServers}），并受总超时约束。
 * 系统无 resolv.conf（如 Termux）时靠公共 DNS 兜底。
 *
 * <p><b>实现映射</b>：
 * <ul>
 *   <li>系统解析 = {@link InetAddress#getAllByName}（JVM 默认解析器，等价 Go 的
 *       {@code net.LookupIP} 走系统路径）；</li>
 *   <li>错误串按 Go {@code *net.DNSError.Error()} 形态合成 {@code lookup <host>: <detail>}；
 *       NXDOMAIN 统一产出 {@code no such host}（JDK 的消息随 locale 变化，不可直接透传）；</li>
 *   <li>回退解析 = dnsjava {@link Lookup} + {@link SimpleResolver}（等价 Go 纯解析器直连
 *       服务器 53 端口），A 与 AAAA 并发查询、总预算 6s、单服务器 3s，
 *       与 Go {@code lookupWithServer} 的 context 超时一致；</li>
 *   <li>{@link #initDNSResolver()}：Go 侧替换 {@code net.DefaultResolver} 把 localhost DNS
 *       重定向到公共 DNS；JVM 无法替换默认解析器，这里做成幂等标记（deviation）——
 *       localhost 重定向的语义已由「系统解析失败 → 公共 DNS 回退链」覆盖。</li>
 * </ul>
 */
public final class Resolver {

    private Resolver() {
    }

    /** 内置公共 DNS 回退列表（按可用性排序），对应 Go 的 {@code publicDNSServers}。 */
    private static final String[] PUBLIC_DNS_SERVERS = {
            "223.5.5.5",    // 阿里 DNS
            "119.29.29.29", // DNSPod
            "1.1.1.1",      // Cloudflare DNS
            "8.8.8.8",      // Google DNS
    };

    /** 单个公共 DNS 服务器的解析超时，对应 Go 的 {@code dnsFallbackTimeout}。 */
    private static final Duration DNS_FALLBACK_TIMEOUT = Duration.ofSeconds(3);

    /** 公共 DNS 回退的总超时，对应 Go 的 {@code dnsFallbackTotalTimeout}。 */
    private static final Duration DNS_FALLBACK_TOTAL_TIMEOUT = Duration.ofSeconds(6);

    /** {@link #initDNSResolver()} 的幂等标记（Go 侧每次调用都重建 resolver，Java 无事可做）。 */
    private static volatile boolean dnsResolverInitialized;

    /**
     * 回退查询用的后台线程池（daemon）。仅在公共 DNS 回退路径使用，
     * 用于把 A / AAAA 两类查询并发出去以共用同一个超时预算（等价 Go 的并发查询）。
     */
    private static final ExecutorService DNS_EXEC = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "jyscan-dns-fallback");
        t.setDaemon(true);
        return t;
    });

    // =====================================================================
    // 公开签名（勿改）
    // =====================================================================

    /**
     * 解析主机名为 IP 地址串列表。
     *
     * <p>对应 Go 的 {@code resolveHostIPs(host string) ([]string, error)}。
     *
     * @return 成功返回解析结果；失败返回 {@code null}（对应 Go 的 err != nil，
     *         调用方判 null 即可）
     */
    public static List<String> resolveHostIPs(String host) {
        ResolveResult r = resolveHostIPsWithFlag(host);
        return r.ok() ? r.ips() : null;
    }

    /**
     * 解析并报告是否走了公共 DNS 回退。
     *
     * <p>对应 Go 的 {@code resolveHostIPsWithFlag(host) (ips []string, usedFallback bool, err error)}。
     * Java 侧用 {@link ResolveResult} 承载三返回值。
     */
    public static ResolveResult resolveHostIPsWithFlag(String host) {
        initDNSResolver();

        String name = host == null ? "" : host;

        // ---- 系统解析：net.LookupIP(host) ----
        String sysErr = null;
        boolean sysNotFound = false;
        if (!name.isEmpty()) {
            try {
                InetAddress[] addrs = InetAddress.getAllByName(name);
                if (addrs != null && addrs.length > 0) {
                    return new ResolveResult(formatAddrs(addrs), false, null);
                }
                // Go：err == nil 但 len(resolved) == 0 → 落到回退路径，sysErr 保持 nil
            } catch (UnknownHostException e) {
                sysNotFound = isNotFound(e);
                sysErr = unknownHostError(name, e);
            } catch (SecurityException e) {
                sysErr = "lookup " + name + ": " + detail(e);
            }
        } else {
            // 空主机名：JDK 的 getAllByName("") 会返回回绕地址，这里按 Go 的 no such host 处理
            sysNotFound = true;
            sysErr = "lookup " + name + ": no such host";
        }

        // ---- 系统有可用 DNS 配置且错误为「未找到」→ 不回退（Go：IsNotFound 直接返回） ----
        if (hasSystemDNSConfig() && sysNotFound) {
            return new ResolveResult(null, false, sysErr);
        }

        // ---- 公共 DNS 回退（总预算 6s，单服务器 3s / 剩余时间取小） ----
        String lastErr = sysErr;
        long deadline = System.nanoTime() + DNS_FALLBACK_TOTAL_TIMEOUT.toNanos();
        for (String server : fallbackDNSServers()) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                break;
            }
            long serverTimeout = Math.min(DNS_FALLBACK_TIMEOUT.toNanos(), remaining);
            Outcome outcome = lookupWithServer(name, server, serverTimeout);
            if (outcome.ips() != null && !outcome.ips().isEmpty()) {
                return new ResolveResult(outcome.ips(), true, null);
            }
            if (outcome.err() != null) {
                lastErr = outcome.err();
            }
        }
        if (lastErr == null) {
            lastErr = "lookup " + name + ": no such host";
        }
        return new ResolveResult(null, true, lastErr);
    }

    /**
     * 进程级解析器初始化，对应 Go 的 {@code InitDNSResolver()} 与其 {@code init()}。
     *
     * <p>Go 把 {@code net.DefaultResolver} 换成「localhost DNS 重定向到公共 DNS」的实现；
     * JVM 无法替换默认解析器，这里做成幂等标记（deviation，见类注释）。
     * localhost 重定向语义由回退链覆盖，且本方法在每次解析入口都会被调到。
     */
    public static void initDNSResolver() {
        if (dnsResolverInitialized) {
            return;
        }
        synchronized (Resolver.class) {
            dnsResolverInitialized = true;
        }
    }

    /** 三返回值的载体。{@code error} 为 null 表示成功。 */
    public record ResolveResult(List<String> ips, boolean usedFallback, String error) {
        public ResolveResult {
            if (ips == null) {
                ips = List.of();
            }
        }

        public boolean ok() {
            return error == null;
        }
    }

    // =====================================================================
    // 系统解析的错误分类（对齐 Go *net.DNSError 的 Err/IsNotFound 语义）
    // =====================================================================

    /**
     * 是否为「未找到」（NXDOMAIN / no such host）类错误，对齐 Go 的
     * {@code DNSError.IsNotFound}：cause 链里没有连接类异常、消息里也没有
     * timeout / refused / unreachable 字样时判为未找到。
     *
     * <p>JDK 对 NXDOMAIN 抛 {@code UnknownHostException(cause=null)}，消息随 locale 变化
     * （如「名称或服务未知」），因此消息检查只用于<b>排除</b>连接类失败。
     */
    private static boolean isNotFound(UnknownHostException e) {
        Throwable t = e;
        while (t != null) {
            if (t instanceof ConnectException
                    || t instanceof SocketTimeoutException
                    || t instanceof NoRouteToHostException) {
                return false;
            }
            String m = t.getMessage();
            if (m != null) {
                String lm = m.toLowerCase(Locale.ROOT);
                if (lm.contains("timed out") || lm.contains("timeout")
                        || lm.contains("refused") || lm.contains("unreachable")
                        || lm.contains("server failed") || lm.contains("misbehaving")) {
                    return false;
                }
            }
            t = t.getCause();
        }
        return true;
    }

    /** 合成 Go 形态的错误串 {@code lookup <host>: <detail>}。 */
    private static String unknownHostError(String host, UnknownHostException e) {
        if (isNotFound(e)) {
            return "lookup " + host + ": no such host";
        }
        return "lookup " + host + ": " + detail(e);
    }

    /** 取 cause 链最深处的非空消息（对应 Go error 链的 unwrap 语义）。 */
    private static String detail(Throwable e) {
        Throwable cur = e;
        String fallback = e == null ? "error" : (e.getMessage() != null ? e.getMessage() : e.toString());
        while (cur != null) {
            String m = cur.getMessage();
            if (m != null && !m.isEmpty()) {
                fallback = m;
            }
            cur = cur.getCause();
        }
        return fallback;
    }

    // =====================================================================
    // 公共 DNS 回退（dnsjava，对应 Go lookupWithServer 的纯 Go 解析器）
    // =====================================================================

    /** 单次回退查询的结果。{@code ips} 非空即成功；否则 {@code err} 为 Go 形态错误串。 */
    private record Outcome(List<String> ips, String err) {
    }

    /** 单个地址族（A / AAAA）的查询结果。 */
    private record Family(List<String> ips, String err) {
    }

    /**
     * 使用指定服务器解析主机名：A 与 AAAA 并发查询，共享同一超时预算
     * （等价 Go 在一个 context 下同时查两类地址）。
     */
    private static Outcome lookupWithServer(String host, String server, long timeoutNanos) {
        CompletableFuture<Family> fa = CompletableFuture.supplyAsync(
                () -> lookupFamily(host, server, Type.A, timeoutNanos), DNS_EXEC);
        CompletableFuture<Family> fb = CompletableFuture.supplyAsync(
                () -> lookupFamily(host, server, Type.AAAA, timeoutNanos), DNS_EXEC);

        List<String> ips = new ArrayList<>();
        String errA = null;
        String errAAAA = null;
        long deadline = System.nanoTime() + timeoutNanos;
        // dnsjava 实测最坏会重试一次（2×timeout），故外层等待留一倍余量；
        // 超出预算即按 Go 的 i/o timeout 收场
        long slack = Math.max(Duration.ofMillis(500).toNanos(), timeoutNanos);
        try {
            long waitA = Math.max(1L, deadline - System.nanoTime()) + slack;
            Family ra = fa.get(waitA, TimeUnit.NANOSECONDS);
            long waitAAAA = Math.max(1L, deadline - System.nanoTime()) + slack;
            Family rb = fb.get(waitAAAA, TimeUnit.NANOSECONDS);
            if (ra.ips() != null) {
                ips.addAll(ra.ips());
            }
            errA = ra.err();
            if (rb.ips() != null) {
                ips.addAll(rb.ips());
            }
            errAAAA = rb.err();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            fa.cancel(true);
            fb.cancel(true);
            return new Outcome(null, "lookup " + host + ": i/o timeout");
        } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException e) {
            fa.cancel(true);
            fb.cancel(true);
            return new Outcome(null, "lookup " + host + ": i/o timeout");
        }

        if (!ips.isEmpty()) {
            return new Outcome(ips, null);
        }
        // 两个地址族都空：优先超时，其次任一错误，再次合成 no such host
        String err = firstNonNull(errA, errAAAA, "lookup " + host + ": no such host");
        if (err.contains("i/o timeout")) {
            err = "lookup " + host + ": i/o timeout";
        }
        return new Outcome(null, err);
    }

    /** 单个地址族的查询（dnsjava Lookup，禁用缓存以避免与 Go 的无缓存行为偏差）。 */
    private static Family lookupFamily(String host, String server, int type, long timeoutNanos) {
        try {
            Lookup lookup = new Lookup(host, type);
            SimpleResolver resolver = new SimpleResolver(server);
            resolver.setTimeout(Duration.ofNanos(timeoutNanos));
            lookup.setResolver(resolver);
            lookup.setCache(null); // Go 每次查询都不带缓存，避免负缓存造成行为差异
            lookup.run();

            int rc = lookup.getResult();
            if (rc == Lookup.SUCCESSFUL) {
                List<String> out = new ArrayList<>();
                Record[] answers = lookup.getAnswers();
                if (answers != null) {
                    for (Record rec : answers) {
                        if (rec instanceof ARecord a) {
                            out.add(ScanParse.formatIP(a.getAddress().getAddress()));
                        } else if (rec instanceof AAAARecord a) {
                            out.add(ScanParse.formatIP(a.getAddress().getAddress()));
                        }
                    }
                }
                if (!out.isEmpty()) {
                    return new Family(out, null);
                }
                // NOERROR 但无地址（NODATA）→ 按 no such host 归类
                return new Family(null, "lookup " + host + ": no such host");
            }
            return new Family(null, "lookup " + host + ": " + familyError(rc, lookup.getErrorString()));
        } catch (UnknownHostException e) {
            // SimpleResolver 构造失败（非法服务器地址）
            return new Family(null, "lookup " + host + ": " + detail(e));
        } catch (Exception e) {
            // TextParseException（非法主机名）及其他运行期异常
            return new Family(null, "lookup " + host + ": " + detail(e));
        }
    }

    /**
     * 把 dnsjava 的结果码映射为 Go DNSError 的 Err 文本。
     *
     * <p>实测 dnsjava 3.6.3：超时/网络错误 → rc={@code TRY_AGAIN}/{@code UNRECOVERABLE} +
     * {@code "network error"}；NXDOMAIN → rc={@code HOST_NOT_FOUND} + {@code "host not found"}；
     * 成功 → {@code SUCCESSFUL}。对应 Go：{@code i/o timeout} / {@code no such host} /
     * {@code server misbehaving}。
     */
    private static String familyError(int rc, String errorString) {
        if (rc == Lookup.HOST_NOT_FOUND || rc == Lookup.TYPE_NOT_FOUND) {
            return "no such host";
        }
        String s = errorString == null ? "" : errorString;
        String ls = s.toLowerCase(Locale.ROOT);
        if (ls.contains("not found") || ls.contains("no such")) {
            return "no such host";
        }
        if (ls.contains("network") || ls.contains("timed out") || ls.contains("timeout")) {
            return "i/o timeout";
        }
        if (ls.contains("server failure") || ls.contains("servfail") || ls.contains("try again")) {
            return "server misbehaving";
        }
        if (s.isEmpty()) {
            return "no such host";
        }
        return s;
    }

    private static String firstNonNull(String a, String b, String c) {
        if (a != null) {
            return a;
        }
        if (b != null) {
            return b;
        }
        return c;
    }

    // =====================================================================
    // 结果格式化（Go 的 ipStrings / ipAddrStrings → net.IP.String()）
    // =====================================================================

    private static List<String> formatAddrs(InetAddress[] addrs) {
        List<String> out = new ArrayList<>(addrs.length);
        for (InetAddress a : addrs) {
            out.add(ScanParse.formatIP(a.getAddress()));
        }
        return out;
    }

    // =====================================================================
    // resolv.conf 解析（对应 Go 的 hasSystemDNSConfig / resolvConfPaths /
    // parseNameservers / fallbackDNSServers / fileHasNameserver / isLocalhost）
    // =====================================================================

    /** 是否存在可用的系统 DNS 配置（含非 localhost 的 nameserver 行）。 */
    static boolean hasSystemDNSConfig() {
        for (String path : resolvConfPaths()) {
            for (String server : parseNameservers(path)) {
                if (!isLocalhost(server)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** 可能存在的 resolv.conf 路径（Termux：{@code $PREFIX/etc/resolv.conf}）。 */
    private static String[] resolvConfPaths() {
        String prefix = System.getenv("PREFIX");
        if (prefix != null && !prefix.isEmpty()) {
            return new String[]{
                    Paths.get(prefix, "etc", "resolv.conf").toString(),
                    "/etc/resolv.conf",
            };
        }
        return new String[]{"/etc/resolv.conf"};
    }

    /** 检查文件中是否包含 nameserver 配置（Go fileHasNameserver）。 */
    @SuppressWarnings("unused") // Go 原文保留（当前无调用方），供后续扩展
    private static boolean fileHasNameserver(String path) {
        Path p = Paths.get(path);
        if (!Files.isRegularFile(p)) {
            return false;
        }
        try (BufferedReader r = Files.newBufferedReader(p, StandardCharsets.UTF_8)) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.trim().startsWith("nameserver")) {
                    return true;
                }
            }
        } catch (IOException e) {
            return false;
        }
        return false;
    }

    /**
     * 回退 DNS 服务器列表：resolv.conf 中的非 localhost 服务器优先，其次内置公共 DNS，
     * 去重保序（对应 Go 的 {@code fallbackDNSServers}）。
     */
    private static List<String> fallbackDNSServers() {
        List<String> servers = new ArrayList<>();
        for (String path : resolvConfPaths()) {
            for (String server : parseNameservers(path)) {
                server = server.trim();
                if (server.isEmpty() || isLocalhost(server)) {
                    continue;
                }
                servers.add(server);
            }
        }
        for (String s : PUBLIC_DNS_SERVERS) {
            servers.add(s);
        }

        List<String> unique = new ArrayList<>(servers.size());
        for (String server : servers) {
            server = server.trim();
            if (server.isEmpty() || unique.contains(server)) {
                continue;
            }
            unique.add(server);
        }
        return unique;
    }

    /** 解析 resolv.conf 中的 nameserver 地址（对应 Go 的 {@code parseNameservers}）。 */
    private static List<String> parseNameservers(String path) {
        Path p = Paths.get(path);
        if (!Files.isRegularFile(p)) {
            return List.of();
        }
        List<String> servers = new ArrayList<>();
        try (BufferedReader r = Files.newBufferedReader(p, StandardCharsets.UTF_8)) {
            String line;
            while ((line = r.readLine()) != null) {
                String[] fields = line.trim().split("\\s+");
                if (fields.length >= 2 && "nameserver".equals(fields[0])) {
                    servers.add(fields[1]);
                }
            }
        } catch (IOException e) {
            return List.of();
        }
        return servers;
    }

    /**
     * host:port 地址是否指向回环（对应 Go 的 {@code isLocalhost}）。
     *
     * <p>SplitHostPort 语义：方括号 IPv6 取括内主机；恰好一个冒号取冒号前段；
     * 其余（无冒号 / 裸 IPv6 多冒号）整体作为 host。
     */
    private static boolean isLocalhost(String addr) {
        String host = splitHostPort(addr);
        InetAddress ip = ScanParse.parseIP(host);
        if (ip != null && ip.isLoopbackAddress()) {
            return true;
        }
        return "localhost".equalsIgnoreCase(host);
    }

    /** 近似 Go {@code net.SplitHostPort}：失败时返回原串（与 Go 的 err 分支一致）。 */
    private static String splitHostPort(String addr) {
        if (addr == null) {
            return "";
        }
        if (addr.startsWith("[")) {
            int idx = addr.lastIndexOf(']');
            if (idx > 0) {
                // [host]:port 合法形态返回括内主机；缺端口时 Go 报错返回原串
                if (idx + 1 < addr.length() && addr.charAt(idx + 1) == ':') {
                    return addr.substring(1, idx);
                }
                return addr;
            }
            return addr;
        }
        int first = addr.indexOf(':');
        if (first < 0) {
            return addr; // Go：missing port → host = addr
        }
        if (first != addr.lastIndexOf(':')) {
            return addr; // 裸 IPv6 多冒号 → Go 报 too many colons → host = addr
        }
        return addr.substring(0, first);
    }
}

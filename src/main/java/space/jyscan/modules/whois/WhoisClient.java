package space.jyscan.modules.whois;

import space.jyscan.core.util.Fmt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Whois 协议客户端，移植 github.com/likexian/whois：
 *
 * <ul>
 *   <li>协议：TCP 43 端口，发送 {@code "查询目标\r\n"}，读到 EOF，超时 10 秒；</li>
 *   <li>域名：先向 whois.iana.org 查询 TLD 记录取 {@code refer:} 注册局服务器，
 *       再查询该服务器，并跟随一次 {@code whois:}/{@code Registrar Whois Server:} 转介
 *       （IANA 不可达时兜底 whois.verisign-grs.com）；</li>
 *   <li>IP：从 whois.arin.net 起步，跟随 {@code ReferralServer: whois://ripe.net}
 *       一类的转介到 RIPE/APNIC/LACNIC/AFRINIC。</li>
 * </ul>
 */
public final class WhoisClient {

    /** 连接与读取超时（毫秒）。 */
    private static final int TIMEOUT_MS = 10_000;

    private static final String SERVER_IANA = "whois.iana.org";
    private static final String SERVER_FALLBACK = "whois.verisign-grs.com";
    private static final String SERVER_ARIN = "whois.arin.net";

    /** IANA TLD 记录里表示注册局 whois 服务器的键。 */
    private static final String KEY_REFER = "refer";
    private static final String KEY_WHOIS = "whois";

    /** 响应中可跟随一次的转介键。 */
    private static final String[] REFERRAL_KEYS = {
            "registrar whois server", "whois server", "referralserver", "whois", "refer",
    };

    private WhoisClient() {
    }

    /**
     * 执行一次完整 whois 查询（域名或 IP），返回原始响应文本。
     * 转介服务器失败时保留主响应（与 likexian 客户端行为一致）。
     */
    public static String whois(String query) throws IOException {
        String q = query == null ? "" : query.trim();
        if (q.isEmpty()) {
            throw new IOException("查询目标为空");
        }

        String server;
        IOException ianaError = null;
        if (WhoisUtil.isIpLiteral(q)) {
            server = SERVER_ARIN;
        } else {
            // 域名：先问 IANA 的 TLD 记录取注册局服务器
            try {
                server = ianaReferServer(WhoisUtil.tldOf(q));
            } catch (IOException e) {
                ianaError = e;
                server = null;
            }
            if (server == null) {
                server = SERVER_FALLBACK;
            }
        }

        String raw;
        try {
            raw = rawQuery(server, q);
        } catch (IOException e) {
            // 兜底服务器也失败时上报 IANA 的原始错误（网络故障的根因）
            if (ianaError != null && SERVER_FALLBACK.equals(server)) {
                throw ianaError;
            }
            throw e;
        }

        // 跟随一次转介（域名：Registrar Whois Server；IP：ReferralServer: whois://...）
        String referral = referralServer(raw);
        if (referral != null && !referral.equalsIgnoreCase(server)) {
            try {
                String extra = rawQuery(referral, q);
                if (!extra.isBlank()) {
                    raw = raw + "\r\n\r\n" + extra;
                }
            } catch (IOException ignored) {
                // 转介服务器不可用时保留主响应
            }
        }
        return raw;
    }

    // =====================================================================
    // 服务器发现
    // =====================================================================

    /** 向 whois.iana.org 查询 TLD，优先取 refer: 行，其次 whois: 行。 */
    private static String ianaReferServer(String tld) throws IOException {
        String resp = rawQuery(SERVER_IANA, tld);
        String fallback = null;
        for (String line : resp.split("\r?\n")) {
            String[] kv = splitKeyValue(line);
            if (kv == null) {
                continue;
            }
            if (KEY_REFER.equals(kv[0])) {
                String s = normalizeServer(kv[1]);
                if (s != null) {
                    return s;
                }
            } else if (KEY_WHOIS.equals(kv[0]) && fallback == null) {
                fallback = normalizeServer(kv[1]);
            }
        }
        return fallback;
    }

    /** 从响应中找第一个可用的转介服务器（whois:/Registrar Whois Server:/ReferralServer: 等）。 */
    private static String referralServer(String raw) {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        for (String line : raw.split("\r?\n")) {
            String[] kv = splitKeyValue(line);
            if (kv == null) {
                continue;
            }
            for (String candidate : REFERRAL_KEYS) {
                if (candidate.equals(kv[0])) {
                    String s = normalizeServer(kv[1]);
                    if (s != null) {
                        return s;
                    }
                    break; // 键匹配但值不可用，继续看下一行
                }
            }
        }
        return null;
    }

    /** 按第一个冒号拆分 "键: 值"，返回小写键与去空白值；无冒号返回 null。 */
    private static String[] splitKeyValue(String line) {
        String l = line.trim();
        int idx = l.indexOf(':');
        if (idx <= 0) {
            return null;
        }
        String key = l.substring(0, idx).trim().toLowerCase(Locale.ROOT);
        String value = l.substring(idx + 1).trim();
        if (key.isEmpty() || value.isEmpty()) {
            return null;
        }
        return new String[]{key, value};
    }

    /** 规范化服务器地址：去掉 whois:// 前缀、路径与尾斜杠；不支持 rwhois 等协议时返回 null。 */
    private static String normalizeServer(String value) {
        String v = value.trim();
        if (v.isEmpty()) {
            return null;
        }
        if (v.toLowerCase(Locale.ROOT).startsWith("rwhois://")) {
            // rwhois 是 ARIN 遗留协议，不支持
            return null;
        }
        if (v.toLowerCase(Locale.ROOT).startsWith("whois://")) {
            v = v.substring("whois://".length());
        }
        int slash = v.indexOf('/');
        if (slash >= 0) {
            v = v.substring(0, slash);
        }
        v = v.trim();
        if (v.isEmpty() || v.contains("://")) {
            return null;
        }
        return v;
    }

    // =====================================================================
    // WHOIS 协议原始查询
    // =====================================================================

    /** 单次 whois 协议查询：连接 server:43，发送 "query\r\n"，读到 EOF。 */
    private static String rawQuery(String server, String query) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(server, 43), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);

            OutputStream out = socket.getOutputStream();
            out.write((query + "\r\n").getBytes(StandardCharsets.UTF_8));
            out.flush();

            InputStream in = socket.getInputStream();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int n;
            while ((n = in.read(chunk)) != -1) {
                buf.write(chunk, 0, n);
            }
            // 按 UTF-8 解码，非法字节以替换符填充（绝大多数 whois 服务为 UTF-8）
            return new String(buf.toByteArray(), StandardCharsets.UTF_8);
        } catch (UnknownHostException e) {
            throw new IOException(Fmt.format("无法解析主机 %s", server));
        } catch (SocketTimeoutException e) {
            throw new IOException(Fmt.format("%s 查询超时", server));
        } catch (IOException e) {
            throw new IOException(Fmt.format("%s: %s", server, WhoisUtil.errorText(e)), e);
        }
    }
}

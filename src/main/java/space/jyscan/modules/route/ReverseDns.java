package space.jyscan.modules.route;

import java.net.InetAddress;

/**
 * 反向 DNS 查询，对应 Go 的 net.LookupAddr。
 */
public final class ReverseDns {

    private ReverseDns() {
    }

    /**
     * 查询 IP 的 PTR 记录，与 Go 行为保持一致：
     * <ul>
     *   <li>查询失败、或结果仍然是 IP 字面量（PTR 未命中）时返回空串，表格里显示 "未知"；</li>
     *   <li>命中时 Go 的 net.LookupAddr 返回带尾点的 FQDN（如 dns.google.），
     *       而 Java 的 getHostName() 不带尾点，这里补齐尾点以与 Go 输出一致。</li>
     * </ul>
     */
    public static String lookup(String ip) {
        if (ip == null || ip.isEmpty()) {
            return "";
        }
        try {
            String name = InetAddress.getByName(ip).getHostName();
            if (name == null || name.isEmpty() || name.equals(ip)) {
                // 与 IP 字面量相同说明 PTR 未命中（Go: err != nil || len(names) == 0）
                return "";
            }
            if (!name.endsWith(".")) {
                name = name + ".";
            }
            return name;
        } catch (Exception e) {
            return "";
        }
    }
}

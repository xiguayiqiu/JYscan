package space.jyscan.modules.whois;

import space.jyscan.core.util.Fmt;

import java.util.ArrayList;
import java.util.List;

/**
 * Whois 查询入口，移植 freeclient/internal/whois/whois.go：
 * {@link #whois(String)}、{@link #formatResult(WhoisResult)}、{@link #batchWhois(List)}。
 */
public final class Whois {

    private Whois() {
    }

    /**
     * 查询域名或IP地址的Whois信息。
     * 与 Go 版一致：网络或解析失败写入 {@link WhoisResult#error}（本方法不抛出，
     * 由 FormatResult 统一输出「错误:」行，保证用户侧不出现堆栈）。
     */
    public static WhoisResult whois(String query) {
        WhoisResult result = new WhoisResult();
        result.query = query == null ? "" : query;
        result.startNanos = System.nanoTime();

        // 执行Whois查询
        try {
            result.raw = WhoisClient.whois(result.query);
        } catch (Exception e) {
            // 对应 Go：whois.Whois 出错时 result.Error 置位并返回
            result.endNanos = System.nanoTime();
            result.error = WhoisUtil.errorText(e);
            return result;
        }
        // 与 Go 一致：EndTime 在解析之前记录，「耗时」只计网络查询
        result.endNanos = System.nanoTime();

        if (result.raw == null || result.raw.isBlank()) {
            // 对应 parser.Parse 对空文本报错的分支
            result.error = "whois 响应为空";
            return result;
        }

        // 解析Whois响应
        result.parsed = WhoisParser.parse(result.query, result.raw);
        return result;
    }

    /**
     * 格式化Whois查询结果，逐行对应 whois.FormatResult 的输出布局：
     * === Whois查询结果 === / 查询目标 / 耗时 / 域名信息 / 注册商信息 / 注册人信息 / 原始响应。
     */
    public static String formatResult(WhoisResult result) {
        StringBuilder out = new StringBuilder();
        out.append("=== Whois查询结果 ===\n");
        out.append(Fmt.format("查询目标: %s\n", result.query));
        // Go 的 %v 打印 time.Duration，这里用 Go 风格字符串渲染
        out.append(Fmt.format("耗时: %v\n\n", WhoisUtil.goDuration(result.cost().toNanos())));

        if (result.error != null) {
            out.append(Fmt.format("错误: %v\n", result.error));
            if (result.raw != null && !result.raw.isEmpty()) {
                out.append(Fmt.format("原始响应:\n%s\n", result.raw));
            }
            return out.toString();
        }

        WhoisInfo parsed = result.parsed;

        // 域名信息
        if (parsed != null && parsed.domain != null) {
            WhoisInfo.Domain d = parsed.domain;
            out.append("域名信息:\n");
            if (!d.name.isEmpty()) {
                out.append(Fmt.format("  域名: %s\n", d.name));
            }
            if (!d.id.isEmpty()) {
                out.append(Fmt.format("  域名ID: %s\n", d.id));
            }
            if (!d.status.isEmpty()) {
                out.append(Fmt.format("  状态: %s\n", String.join(", ", d.status)));
            }
            if (!d.createdDate.isEmpty()) {
                out.append(Fmt.format("  创建时间: %s\n", d.createdDate));
            }
            if (!d.updatedDate.isEmpty()) {
                out.append(Fmt.format("  更新时间: %s\n", d.updatedDate));
            }
            if (!d.expirationDate.isEmpty()) {
                out.append(Fmt.format("  过期时间: %s\n", d.expirationDate));
            }
            if (!d.nameServers.isEmpty()) {
                out.append(Fmt.format("  名称服务器: %s\n", String.join(", ", d.nameServers)));
            }
            out.append("\n");
        }

        // 注册商信息
        if (parsed != null && parsed.registrar != null) {
            out.append("注册商信息:\n");
            if (!parsed.registrar.name.isEmpty()) {
                out.append(Fmt.format("  注册商: %s\n", parsed.registrar.name));
            }
            out.append("\n");
        }

        // 注册人信息
        if (parsed != null && parsed.registrant != null) {
            WhoisInfo.Registrant r = parsed.registrant;
            out.append("注册人信息:\n");
            if (!r.name.isEmpty()) {
                out.append(Fmt.format("  名称: %s\n", r.name));
            }
            if (!r.email.isEmpty()) {
                out.append(Fmt.format("  邮箱: %s\n", r.email));
            }
            if (!r.organization.isEmpty()) {
                out.append(Fmt.format("  组织: %s\n", r.organization));
            }
            out.append("\n");
        }

        // 原始响应（如果需要）
        if (result.raw != null && !result.raw.isEmpty()) {
            out.append(Fmt.format("原始响应:\n%s\n", result.raw));
        }

        return out.toString();
    }

    /** 批量查询Whois信息，对应 whois.BatchWhois（单个失败不影响其余查询）。 */
    public static List<WhoisResult> batchWhois(List<String> queries) {
        List<WhoisResult> results = new ArrayList<>();
        if (queries == null) {
            return results;
        }
        for (String query : queries) {
            results.add(whois(query));
        }
        return results;
    }
}

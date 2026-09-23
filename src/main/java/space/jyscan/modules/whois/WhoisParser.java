package space.jyscan.modules.whois;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;

/**
 * Whois 响应解析器，移植 github.com/likexian/whois-parser 的 {@code Parse}，
 * 只保留 FormatResult 读取的字段：Domain / Registrar / Registrant。
 *
 * <p>键名大小写不敏感，识别常见拼写：
 * Domain Name、Registry Domain ID、Domain Status/status、
 * Creation Date/created、Updated Date/changed、
 * Registry Expiry Date/Expiration Date/expires、Name Server/nserver、
 * Registrar、Registrant Name/Email/Organization。
 *
 * <p>IP 响应（ARIN/RIPE 等）不产生域名块 —— 与 Go 侧 Parsed.Domain == nil 一致，
 * FormatResult 随之省略「域名信息」段。
 */
public final class WhoisParser {

    /** 归一化后的日期输出格式；无法解析时保留原始字符串。 */
    private static final DateTimeFormatter OUT =
            DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss", Locale.ROOT);

    private WhoisParser() {
    }

    /**
     * 解析 Whois 原始响应。
     *
     * @param query 查询目标（用于区分域名与 IP）
     * @param raw   Whois 原始响应
     * @return 解析结果（空响应返回各块均为 null 的空对象）
     */
    public static WhoisInfo parse(String query, String raw) {
        WhoisInfo info = new WhoisInfo();
        if (raw == null || raw.isEmpty()) {
            return info;
        }
        boolean isIp = WhoisUtil.isIpLiteral(query);

        // 先逐字段收集，最后按「是否为空」决定各块是否存在，
        // 避免输出只有标题没有内容的空段落。
        WhoisInfo.Domain domain = new WhoisInfo.Domain();
        WhoisInfo.Registrar registrar = new WhoisInfo.Registrar();
        WhoisInfo.Registrant registrant = new WhoisInfo.Registrant();

        for (String line : raw.split("\r?\n")) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            // 取第一个冒号分隔键值；%、#、>>>、[ 等注释行自然不匹配任何键
            int idx = line.indexOf(':');
            if (idx <= 0) {
                continue;
            }
            String key = line.substring(0, idx).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(idx + 1).trim();
            if (value.isEmpty()) {
                continue;
            }

            switch (key) {
                // ---- 域名信息（IP 查询跳过，对应 Go 侧 Domain == nil） ----
                case "domain name" -> {
                    if (!isIp && domain.name.isEmpty()) {
                        domain.name = value;
                    }
                }
                case "registry domain id" -> {
                    if (!isIp && domain.id.isEmpty()) {
                        domain.id = value;
                    }
                }
                case "domain status", "status" -> {
                    if (!isIp) {
                        addUnique(domain.status, value);
                    }
                }
                case "creation date", "created", "create", "registered on", "registration time" -> {
                    if (!isIp && domain.createdDate.isEmpty()) {
                        domain.createdDate = normalizeDate(value);
                    }
                }
                case "updated date", "changed", "last updated", "last modified", "modified" -> {
                    if (!isIp && domain.updatedDate.isEmpty()) {
                        domain.updatedDate = normalizeDate(value);
                    }
                }
                case "registry expiry date", "expiration date", "expiry date",
                        "expires", "expire", "paid-till" -> {
                    if (!isIp && domain.expirationDate.isEmpty()) {
                        domain.expirationDate = normalizeDate(value);
                    }
                }
                case "name server", "nserver", "nameserver" -> {
                    if (!isIp) {
                        addUniqueIgnoreCase(domain.nameServers, value);
                    }
                }

                // ---- 注册商信息 ----
                case "registrar", "registrar name", "sponsoring registrar" -> {
                    if (registrar.name.isEmpty()) {
                        registrar.name = value;
                    }
                }

                // ---- 注册人信息 ----
                case "registrant name", "registrant" -> {
                    if (registrant.name.isEmpty()) {
                        registrant.name = value;
                    }
                }
                case "registrant email" -> {
                    if (registrant.email.isEmpty()) {
                        registrant.email = value;
                    }
                }
                case "registrant organization", "registrant org" -> {
                    if (registrant.organization.isEmpty()) {
                        registrant.organization = value;
                    }
                }
                default -> {
                    // 其余键不解析
                }
            }
        }

        if (!domain.empty()) {
            info.domain = domain;
        }
        if (!registrar.name.isEmpty()) {
            info.registrar = registrar;
        }
        if (!registrant.name.isEmpty() || !registrant.email.isEmpty() || !registrant.organization.isEmpty()) {
            info.registrant = registrant;
        }
        return info;
    }

    // =====================================================================
    // 日期归一化
    // =====================================================================

    /**
     * 尝试把常见 whois 日期格式归一化为 {@code yyyy-MM-dd HH:mm:ss}；
     * 仅日期保留原样（如 1985-01-01）；无法解析时返回原始字符串。
     */
    static String normalizeDate(String value) {
        String s = value.trim();
        try {
            if (s.length() >= 10 && s.charAt(4) == '-' && s.charAt(7) == '-') {
                if (s.indexOf('T') == 10) {
                    // 2003-03-13T10:00:00Z / .000Z / +08:00；无时区时按本地时间处理
                    try {
                        OffsetDateTime odt = OffsetDateTime.parse(s, DateTimeFormatter.ISO_OFFSET_DATE_TIME);
                        return OUT.format(odt);
                    } catch (DateTimeParseException notOffset) {
                        LocalDateTime ldt = LocalDateTime.parse(s, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                        return OUT.format(ldt);
                    }
                }
                if (s.indexOf(' ') == 10) {
                    // 2003-03-13 10:00:00 形式
                    LocalDateTime ldt = LocalDateTime.parse(s.replace(' ', 'T'), DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                    return OUT.format(ldt);
                }
                // 仅日期：保留 yyyy-MM-dd（多余尾随文本一并裁掉）
                return LocalDate.parse(s.substring(0, 10), DateTimeFormatter.ISO_LOCAL_DATE).toString();
            }
        } catch (DateTimeParseException ignored) {
            // 解析失败：保留原始字符串
        }
        return value;
    }

    // =====================================================================
    // 列表辅助
    // =====================================================================

    /** 追加去重（精确匹配），保持首次出现的顺序。 */
    private static void addUnique(List<String> list, String v) {
        if (!list.contains(v)) {
            list.add(v);
        }
    }

    /** 追加去重（忽略大小写），合并注册局/注册商两段响应时避免重复项。 */
    private static void addUniqueIgnoreCase(List<String> list, String v) {
        for (String s : list) {
            if (s.equalsIgnoreCase(v)) {
                return;
            }
        }
        list.add(v);
    }
}

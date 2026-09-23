package space.jyscan.modules.whois;

import java.util.ArrayList;
import java.util.List;

/**
 * 解析后的 Whois 信息，对应 likexian/whois-parser 的 {@code parser.WhoisInfo}。
 *
 * <p>FormatResult 只读取三个子块：Domain（域名信息）、Registrar（注册商信息）、
 * Registrant（注册人信息）；为 null 时 FormatResult 省略对应段落。
 */
public final class WhoisInfo {

    /** 域名信息，对应 parser.Domain；IP 查询或响应中无域名字段时为 null。 */
    public Domain domain;

    /** 注册商信息，对应 parser.Registrar；无注册商字段时为 null。 */
    public Registrar registrar;

    /** 注册人信息，对应 parser.Registrant；无注册人字段时为 null。 */
    public Registrant registrant;

    /** 域名块，字段与 Go 侧 parser.Domain 一一对应。 */
    public static final class Domain {
        /** 域名（Domain Name）。 */
        public String name = "";
        /** 域名 ID（Registry Domain ID）。 */
        public String id = "";
        /** 状态列表（Domain Status / status）。 */
        public List<String> status = new ArrayList<>();
        /** 创建时间（Creation Date / created）。 */
        public String createdDate = "";
        /** 更新时间（Updated Date / changed）。 */
        public String updatedDate = "";
        /** 过期时间（Registry Expiry Date / Expiration Date / expires）。 */
        public String expirationDate = "";
        /** 名称服务器列表（Name Server / nserver）。 */
        public List<String> nameServers = new ArrayList<>();

        /** 所有字段均为空时视为不存在（不输出「域名信息」标题）。 */
        boolean empty() {
            return name.isEmpty() && id.isEmpty() && status.isEmpty()
                    && createdDate.isEmpty() && updatedDate.isEmpty()
                    && expirationDate.isEmpty() && nameServers.isEmpty();
        }
    }

    /** 注册商块，对应 parser.Registrar。 */
    public static final class Registrar {
        /** 注册商名称（Registrar）。 */
        public String name = "";
    }

    /** 注册人块，对应 parser.Registrant。 */
    public static final class Registrant {
        /** 名称（Registrant Name）。 */
        public String name = "";
        /** 邮箱（Registrant Email）。 */
        public String email = "";
        /** 组织（Registrant Organization）。 */
        public String organization = "";
    }
}

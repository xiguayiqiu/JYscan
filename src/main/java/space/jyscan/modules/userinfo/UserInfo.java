package space.jyscan.modules.userinfo;

import java.util.ArrayList;
import java.util.List;

/**
 * UserInfo 用户信息结构体，对应 Go 的 {@code userinfo.UserInfo}：
 * Username / UID / GID / FullName / HomeDir / Shell / Groups。
 *
 * <p>Windows 下 UID / GID / HomeDir / Shell 为空串（Go 侧为零值 ""）。
 */
public final class UserInfo {

    /** 用户名。 */
    public String username = "";

    /** UID（Windows 下为空）。 */
    public String uid = "";

    /** GID（Windows 下为空）。 */
    public String gid = "";

    /** 全名：/etc/passwd 的 GECOS 字段或 Windows 的 Full Name。 */
    public String fullName = "";

    /** 主目录（Windows 下为空）。 */
    public String homeDir = "";

    /** 登录 Shell（Windows 下为空）。 */
    public String shell = "";

    /** 用户所属组。 */
    public List<String> groups = new ArrayList<>();
}

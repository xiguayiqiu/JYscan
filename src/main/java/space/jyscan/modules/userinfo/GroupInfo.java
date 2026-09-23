package space.jyscan.modules.userinfo;

import java.util.ArrayList;
import java.util.List;

/**
 * GroupInfo 组信息结构体，对应 Go 的 {@code userinfo.GroupInfo}：
 * GroupName / GID / Members。
 */
public final class GroupInfo {

    /** 组名。 */
    public String groupName = "";

    /** GID。 */
    public String gid = "";

    /** 组成员。 */
    public List<String> members = new ArrayList<>();
}

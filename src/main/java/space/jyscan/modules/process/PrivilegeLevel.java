package space.jyscan.modules.process;

/**
 * 权限级别枚举，移植自 freeclient/internal/process/process.go 的 PrivilegeLevel。
 *
 * <p>Go 侧为字符串常量类型，这里保持为字符串常量，便于与输出直接比对。
 */
public final class PrivilegeLevel {

    /** 低权限：普通用户应用。 */
    public static final String LOW = "低权限";

    /** 中权限：普通系统服务和应用。 */
    public static final String MEDIUM = "中权限";

    /** 高权限：网络服务、数据库服务等关键应用。 */
    public static final String HIGH = "高权限";

    /** 系统权限：操作系统核心组件，具有最高权限。 */
    public static final String SYSTEM = "系统权限";

    /** 未知权限。 */
    public static final String UNKNOWN = "未知权限";

    private PrivilegeLevel() {
    }
}

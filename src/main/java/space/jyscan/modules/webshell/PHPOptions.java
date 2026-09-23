package space.jyscan.modules.webshell;

/**
 * PHP WebShell生成选项，移植自 freeclient/internal/webshell/php.go 的 PHPOptions。
 */
public final class PHPOptions {

    /** WebShell密码（小马场景下用作密码字段名）。 */
    public String password = "";

    /** WebShell类型: small或large。 */
    public String type = "";

    /** 编码类型: base64, hex, none。 */
    public String encodeType = "";

    /** 混淆级别: 1-3。 */
    public int obfuscateLevel;

    /** 是否生成无密码大马。 */
    public boolean noPassword;

    /** 零值构造（对应 Go 结构体零值）。 */
    public PHPOptions() {
    }

    /** 全参构造，字段顺序与 Go 结构体声明一致。 */
    public PHPOptions(String password, String type, String encodeType,
                      int obfuscateLevel, boolean noPassword) {
        this.password = password;
        this.type = type;
        this.encodeType = encodeType;
        this.obfuscateLevel = obfuscateLevel;
        this.noPassword = noPassword;
    }
}

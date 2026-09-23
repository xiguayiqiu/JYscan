package space.jyscan.modules.waf;

/**
 * 证书信息，移植自 freeclient/internal/waf/detector.go 的 CertInfo 结构体。
 */
public class CertInfo {

    /** 签发者（对应 Go cert.Issuer.String() 的输出语义） */
    public String issuer = "";

    /** 主体（对应 Go cert.Subject.String() 的输出语义） */
    public String subject = "";

    /** 序列号（十进制，对应 Go cert.SerialNumber.String()） */
    public String serial = "";
}

package space.jyscan.modules.cupp;

import java.util.ArrayList;
import java.util.List;

/**
 * 用户画像，移植自 freeclient/internal/cupp/config.go 中的 Profile 结构体。
 * 字段命名与 Go 保持一一对应（Name -> name 等）。
 */
public class Profile {
    public String name = "";
    public String surname = "";
    public String nick = "";
    public String birthdate = "";
    public String wife = "";
    public String wifen = "";
    public String wifeb = "";
    public String kid = "";
    public String kidn = "";
    public String kidb = "";
    public String pet = "";
    public String company = "";
    public List<String> words = new ArrayList<>();
    public String spechars1 = "";
    public String randnum = "";
    public String leetmode = "";
    public List<String> spechars = new ArrayList<>();
}

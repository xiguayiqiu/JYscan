package space.jyscan.core.binding;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * 机器指纹绑定，对应 internal/binding/binding.go。
 *
 * <p>免费版仅用于生成稳定的 instance_id（写入配置文件），
 * 不含付费版的授权校验逻辑。
 */
public final class MachineBinder {

    private String instanceId;

    public static MachineBinder newInstance() {
        return new MachineBinder();
    }

    public String getInstanceID() {
        if (instanceId == null || instanceId.isEmpty()) {
            instanceId = generateMachineID();
        }
        return instanceId;
    }

    private String generateMachineID() {
        String os = System.getProperty("os.name", "");
        String arch = System.getProperty("os.arch", "");
        String hostName = getHostName();
        String userName = getUserName();

        StringBuilder combined = new StringBuilder();
        for (String part : new String[]{os, arch, hostName, userName}) {
            if (part != null && !part.isEmpty()) {
                combined.append(part);
            }
        }
        String input = combined.isEmpty() ? "default-jyscan-instance" : combined.toString();
        return sha256(input).substring(0, 32);
    }

    private static String getHostName() {
        try {
            return java.net.InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            return "";
        }
    }

    /** 与 Go 版一致：取 USERNAME 环境变量。 */
    private static String getUserName() {
        String u = System.getenv("USERNAME");
        return u == null ? "" : u;
    }

    public boolean validateInstance(String expectedID) {
        return getInstanceID().equals(expectedID);
    }

    /** 对应 Go 的 binding.GeneratePluginToken。 */
    public static String generatePluginToken(String instanceID, String pluginName) {
        return sha256(instanceID + ":" + pluginName + ":jyscan-v1");
    }

    public static boolean validatePluginToken(String instanceID, String pluginName, String token) {
        return generatePluginToken(instanceID, pluginName).equals(token);
    }

    public static String bindingInfo() {
        MachineBinder mb = new MachineBinder();
        return String.format("InstanceID: %s\nPlatform: %s/%s",
                mb.getInstanceID(),
                System.getProperty("os.name", ""),
                System.getProperty("os.arch", ""));
    }

    private static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }
}

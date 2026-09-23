package space.jyscan.modules.userinfo;

import space.jyscan.core.util.Colors;
import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.SystemUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 本地用户和组分析，移植自 freeclient/internal/userinfo/userinfo.go。
 *
 * <p>平台入口 {@link #analyzeLocalUsers()} / {@link #analyzeLocalGroups()} 按
 * {@code runtime.GOOS}（这里用 {@link SystemUtil#osName()}，取值同为
 * windows / linux / darwin）分流：
 * <ul>
 *   <li>Windows：执行 {@code net user} / {@code net localgroup} 并做 GBK→UTF-8 编码转换；</li>
 *   <li>Linux / darwin：读取 {@code /etc/passwd}、{@code /etc/group}，
 *       并用 {@code groups <用户名>} 补全用户所属组。</li>
 * </ul>
 *
 * <p>格式化输出 {@link #formatUserInfo(List)} / {@link #formatGroupInfo(List)}
 * 返回带 ANSI 颜色的字符串（对应 Go 的 utils.Banner/Info/Success/...），
 * 由调用方 {@code fmt.Println} 打印。
 */
public final class Userinfo {

    private Userinfo() {
    }

    // =====================================================================
    // 平台入口（对应 Go 的 AnalyzeLocalUsers / AnalyzeLocalGroups）
    // =====================================================================

    /** AnalyzeLocalUsers 分析本地用户信息。 */
    public static List<UserInfo> analyzeLocalUsers() throws IOException {
        String goos = SystemUtil.osName();
        switch (goos) {
            case "windows":
                return analyzeWindowsUsers();
            case "linux":
            case "darwin":
                return analyzeUnixUsers();
            default:
                throw new IOException(Fmt.format("不支持的操作系统: %s", goos));
        }
    }

    /** AnalyzeLocalGroups 分析本地组信息。 */
    public static List<GroupInfo> analyzeLocalGroups() throws IOException {
        String goos = SystemUtil.osName();
        switch (goos) {
            case "windows":
                return analyzeWindowsGroups();
            case "linux":
            case "darwin":
                return analyzeUnixGroups();
            default:
                throw new IOException(Fmt.format("不支持的操作系统: %s", goos));
        }
    }

    // =====================================================================
    // Windows：net user / net localgroup（带编码转换）
    // =====================================================================

    /** analyzeWindowsUsers 分析Windows系统用户。 */
    private static List<UserInfo> analyzeWindowsUsers() throws IOException {
        List<UserInfo> users = new ArrayList<>();

        // 使用net user命令（带编码转换）
        String output;
        try {
            output = executeWindowsCommand("net", "user");
        } catch (IOException e) {
            throw new IOException(Fmt.format("执行net user命令失败: %v", e), e);
        }

        boolean inUserList = false;
        for (String rawLine : output.split("\n", -1)) {
            String line = rawLine.trim();

            if (line.contains("--------")) {
                inUserList = !inUserList;
                continue;
            }

            if (inUserList && !line.isEmpty()) {
                // 解析用户名（Go: strings.Fields(line)）
                String[] fields = fields(line);
                if (fields.length > 0) {
                    String username = fields[0];

                    // 获取用户详细信息（err == nil 才收集，与 Go 一致）
                    try {
                        users.add(getWindowsUserDetail(username));
                    } catch (IOException ignored) {
                        // 忽略单个用户详情失败
                    }
                }
            }
        }

        return users;
    }

    /** getWindowsUserDetail 获取Windows用户详细信息。 */
    private static UserInfo getWindowsUserDetail(String username) throws IOException {
        UserInfo user = new UserInfo();
        user.username = username;
        user.groups = new ArrayList<>();

        // 获取用户详细信息（带编码转换）
        String output = executeWindowsCommand("net", "user", username);

        for (String rawLine : output.split("\n", -1)) {
            String line = rawLine.trim();

            if (line.startsWith("全名") || line.startsWith("Full Name")) {
                // Go: parts := strings.SplitN(line, " ", 3); len >= 3 → parts[2]
                String[] parts = line.split(" ", 3);
                if (parts.length >= 3) {
                    user.fullName = parts[2].trim();
                }
            }

            if (line.startsWith("本地组成员") || line.startsWith("Local Group Memberships")) {
                // Go: parts := strings.SplitN(line, "*", 2)
                String[] parts = line.split("\\*", 2);
                if (parts.length >= 2) {
                    for (String group : parts[1].split(" ")) {
                        group = group.trim();
                        if (!group.isEmpty() && !group.equals("*")) {
                            user.groups.add(group);
                        }
                    }
                }
            }
        }

        return user;
    }

    /** analyzeWindowsGroups 分析Windows系统组。 */
    private static List<GroupInfo> analyzeWindowsGroups() throws IOException {
        List<GroupInfo> groups = new ArrayList<>();

        // 使用net localgroup命令（带编码转换）
        String output;
        try {
            output = executeWindowsCommand("net", "localgroup");
        } catch (IOException e) {
            throw new IOException(Fmt.format("执行net localgroup命令失败: %v", e), e);
        }

        boolean inGroupList = false;
        for (String rawLine : output.split("\n", -1)) {
            String line = rawLine.trim();

            // 检查是否进入组列表区域
            if (line.contains("--------")) {
                inGroupList = !inGroupList;
                continue;
            }

            // 检查是否在组列表区域
            if (inGroupList && !line.isEmpty()) {
                // 跳过命令成功完成的提示行
                if (line.contains("命令成功完成") || line.contains("The command completed successfully")) {
                    continue;
                }

                // 解析组名（去掉星号）
                if (line.startsWith("*")) {
                    String groupname = line.substring(1).trim();

                    // 获取组详细信息（err == nil 才收集，与 Go 一致）
                    try {
                        groups.add(getWindowsGroupDetail(groupname));
                    } catch (IOException ignored) {
                        // 忽略单个组详情失败
                    }
                }
            }
        }

        return groups;
    }

    /** getWindowsGroupDetail 获取Windows组详细信息。 */
    private static GroupInfo getWindowsGroupDetail(String groupname) throws IOException {
        GroupInfo group = new GroupInfo();
        group.groupName = groupname;
        group.members = new ArrayList<>();

        // 获取组成员信息（带编码转换）
        String output = executeWindowsCommand("net", "localgroup", groupname);

        boolean inMemberList = false;
        for (String rawLine : output.split("\n", -1)) {
            String line = rawLine.trim();

            if (line.contains("--------")) {
                inMemberList = !inMemberList;
                continue;
            }

            if (inMemberList && !line.isEmpty()) {
                // 跳过命令成功完成的提示行
                if (line.contains("命令成功完成") || line.contains("The command completed successfully")) {
                    continue;
                }

                // 解析成员
                String[] fields = fields(line);
                if (fields.length > 0) {
                    String member = fields[0];
                    // 过滤掉空成员和星号
                    if (!member.isEmpty() && !member.equals("*")) {
                        group.members.add(member);
                    }
                }
            }
        }

        return group;
    }

    /** convertGBKToUTF8 将GBK编码转换为UTF-8编码（解码失败时回退原始字节，与 Go 相同）。 */
    private static String convertGBKToUTF8(byte[] gbkBytes) {
        try {
            CharsetDecoder decoder = Charset.forName("GBK").newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            return decoder.decode(ByteBuffer.wrap(gbkBytes)).toString();
        } catch (CharacterCodingException e) {
            // 如果转换失败，返回原始输出
            return new String(gbkBytes, Charset.defaultCharset());
        }
    }

    /** executeWindowsCommand 执行Windows命令并处理编码转换。 */
    private static String executeWindowsCommand(String name, String... args) throws IOException {
        String[] argv = new String[args.length + 1];
        argv[0] = name;
        System.arraycopy(args, 0, argv, 1, args.length);

        byte[] output = execCapture(argv);

        // 尝试将GBK编码转换为UTF-8
        return convertGBKToUTF8(output);
    }

    // =====================================================================
    // Linux / darwin：/etc/passwd、/etc/group、groups 命令
    // =====================================================================

    /** analyzeUnixUsers 分析Unix系统用户。 */
    private static List<UserInfo> analyzeUnixUsers() throws IOException {
        List<UserInfo> users = new ArrayList<>();

        // 读取/etc/passwd文件
        java.io.BufferedReader reader;
        try {
            reader = Files.newBufferedReader(Path.of("/etc/passwd"), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IOException(Fmt.format("无法打开/etc/passwd文件: %v", e), e);
        }

        try (java.io.BufferedReader r = reader) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("#") || line.isEmpty()) {
                    continue;
                }

                // Go: strings.Split(line, ":")，保留空字段（limit -1）
                String[] fields = line.split(":", -1);
                if (fields.length >= 7) {
                    UserInfo user = new UserInfo();
                    user.username = fields[0];
                    user.uid = fields[2];
                    user.gid = fields[3];
                    user.fullName = fields[4];
                    user.homeDir = fields[5];
                    user.shell = fields[6];
                    user.groups = new ArrayList<>();

                    // 获取用户所属组
                    String[] groups = getUserGroups(user.username);
                    if (groups != null) {
                        for (String g : groups) {
                            user.groups.add(g);
                        }
                    }

                    users.add(user);
                }
            }
        } catch (IOException e) {
            throw new IOException(Fmt.format("读取/etc/passwd文件失败: %v", e), e);
        }

        return users;
    }

    /** analyzeUnixGroups 分析Unix系统组。 */
    private static List<GroupInfo> analyzeUnixGroups() throws IOException {
        List<GroupInfo> groups = new ArrayList<>();

        // 读取/etc/group文件
        java.io.BufferedReader reader;
        try {
            reader = Files.newBufferedReader(Path.of("/etc/group"), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IOException(Fmt.format("无法打开/etc/group文件: %v", e), e);
        }

        try (java.io.BufferedReader r = reader) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("#") || line.isEmpty()) {
                    continue;
                }

                String[] fields = line.split(":", -1);
                if (fields.length >= 4) {
                    GroupInfo group = new GroupInfo();
                    group.groupName = fields[0];
                    group.gid = fields[2];
                    group.members = new ArrayList<>();

                    // 解析组成员
                    if (!fields[3].isEmpty()) {
                        for (String member : fields[3].split(",")) {
                            if (!member.isEmpty()) {
                                group.members.add(member);
                            }
                        }
                    }

                    groups.add(group);
                }
            }
        } catch (IOException e) {
            throw new IOException(Fmt.format("读取/etc/group文件失败: %v", e), e);
        }

        return groups;
    }

    /**
     * getUserGroups 获取用户所属的所有组：执行 {@code groups <用户名>}。
     * 失败返回 null（Go: 返回 err，调用方保持 Groups 为空）。
     */
    private static String[] getUserGroups(String username) {
        try {
            // 使用groups命令（不经过 shell，等价 Go 的 exec.Command）
            String output = SystemUtil.exec("groups", username);
            String line = output.trim();
            if (line.contains(":")) {
                String[] parts = line.split(":", 2);
                if (parts.length >= 2) {
                    return fields(parts[1]);
                }
            } else {
                return fields(line);
            }
        } catch (Exception e) {
            return null;
        }
        return new String[0];
    }

    // =====================================================================
    // 格式化输出（对应 Go 的 FormatUserInfo / FormatGroupInfo）
    // =====================================================================

    /** FormatUserInfo 格式化用户信息输出。 */
    public static String formatUserInfo(List<UserInfo> users) {
        StringBuilder result = new StringBuilder();

        result.append(Colors.banner("=== 本地用户信息 ===")).append('\n');
        result.append(Colors.info("系统类型: %s", SystemUtil.osName())).append('\n');
        result.append(Colors.success("用户总数: %d", users.size())).append("\n\n");

        for (int i = 0; i < users.size(); i++) {
            UserInfo user = users.get(i);
            result.append(Colors.highlight("用户 %d:", i + 1)).append('\n');
            result.append(Colors.boldInfo("  用户名: ")).append(Colors.boldInfo("%s", user.username)).append('\n');
            if (!user.uid.isEmpty()) {
                result.append(Colors.boldInfo("  UID: ")).append(Colors.info(user.uid)).append('\n');
            }
            if (!user.gid.isEmpty()) {
                result.append(Colors.boldInfo("  GID: ")).append(Colors.info(user.gid)).append('\n');
            }
            if (!user.fullName.isEmpty()) {
                result.append(Colors.boldInfo("  全名: ")).append(Colors.info(user.fullName)).append('\n');
            }
            if (!user.homeDir.isEmpty()) {
                result.append(Colors.boldInfo("  主目录: ")).append(Colors.info(user.homeDir)).append('\n');
            }
            if (!user.shell.isEmpty()) {
                result.append(Colors.boldInfo("  Shell: ")).append(Colors.info(user.shell)).append('\n');
            }
            if (!user.groups.isEmpty()) {
                result.append(Colors.boldInfo("  所属组: "))
                        .append(Colors.success(String.join(", ", user.groups))).append('\n');
            }
            result.append('\n');
        }

        return result.toString();
    }

    /** FormatGroupInfo 格式化组信息输出。 */
    public static String formatGroupInfo(List<GroupInfo> groups) {
        StringBuilder result = new StringBuilder();

        result.append(Colors.banner("=== 本地组信息 ===")).append('\n');
        result.append(Colors.info("系统类型: %s", SystemUtil.osName())).append('\n');
        result.append(Colors.success("组总数: %d", groups.size())).append("\n\n");

        for (int i = 0; i < groups.size(); i++) {
            GroupInfo group = groups.get(i);
            result.append(Colors.highlight("组 %d:", i + 1)).append('\n');
            result.append(Colors.boldInfo("  组名: %s", group.groupName)).append('\n');
            if (!group.gid.isEmpty()) {
                result.append(Colors.boldInfo("  GID: ")).append(Colors.info(group.gid)).append('\n');
            }
            if (!group.members.isEmpty()) {
                result.append(Colors.boldInfo("  成员: "))
                        .append(Colors.success(String.join(", ", group.members))).append('\n');
            } else {
                result.append(Colors.boldInfo("  成员: ")).append(Colors.warning("无")).append('\n');
            }
            result.append('\n');
        }

        return result.toString();
    }

    // =====================================================================
    // 内部工具
    // =====================================================================

    /** 等价 Go 的 strings.Fields：按空白切分，丢弃空串。 */
    private static String[] fields(String s) {
        String t = s == null ? "" : s.trim();
        if (t.isEmpty()) {
            return new String[0];
        }
        return t.split("\\s+");
    }

    /** 执行命令（不经过 shell），返回 stdout 字节；非零退出码抛 IOException（等价 cmd.Output()）。 */
    private static byte[] execCapture(String... argv) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(argv);
        Process proc;
        try {
            proc = pb.start();
        } catch (IOException e) {
            throw e;
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (InputStream in = proc.getInputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                bos.write(buf, 0, n);
            }
        }

        try {
            if (!proc.waitFor(60, TimeUnit.SECONDS)) {
                proc.destroyForcibly();
                throw new IOException("命令执行超时");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e.getMessage() == null ? "命令执行被中断" : e.getMessage(), e);
        }

        int exit = proc.exitValue();
        if (exit != 0) {
            throw new IOException(Fmt.format("exit status %d", exit));
        }
        return bos.toByteArray();
    }
}

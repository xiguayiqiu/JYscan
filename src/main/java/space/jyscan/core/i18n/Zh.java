package space.jyscan.core.i18n;

import java.util.HashMap;
import java.util.Map;

/**
 * 中文文案表，移植自 internal/i18n/i18n.go 的 LangZH 分支。
 *
 * <p>值里的 {@code %s}/{@code %d}/{@code %v} 等为 Go 格式动词，
 * 由 {@link I18n#Tf} 经 core/util/Fmt 渲染。
 */
final class Zh {

    static final Map<String, String> MESSAGES = new HashMap<>();

    static {
        // ==================== 应用 ====================
        MESSAGES.put("app.name", "jyscan");
        MESSAGES.put("app.copyright", "Copyright © 2024-2026 JYscan");
        MESSAGES.put("app.legal", "警告: 仅用于授权测试，严禁未授权使用！");
        MESSAGES.put("app.slogan", "综合渗透测试工具，着重测试");
        MESSAGES.put("app.author", "作者: xiguayiqiua");
        MESSAGES.put("app.version", "工具版本: %s");
        MESSAGES.put("app.desc", "描述: 综合渗透测试工具，着重资产探测、漏洞检测，安全验证");
        MESSAGES.put("app.warning", "警告: 仅用于授权测试，严禁未授权使用！");
        MESSAGES.put("app.get_help", "使用 \"./jyscan help\" 获取帮助信息");
        MESSAGES.put("app.banner_title", "jyscan-free - Go语言综合渗透测试工具（免费版）");
        // ==================== 分组 ====================
        MESSAGES.put("group.general", "综合工具");
        MESSAGES.put("group.password", "密码学工具");
        MESSAGES.put("group.network", "网络扫描工具");
        MESSAGES.put("group.info", "信息收集工具");
        MESSAGES.put("group.web", "Web安全工具");
        MESSAGES.put("group.privesc", "权限提升工具");
        MESSAGES.put("group.testing", "测试阶段命令");
        MESSAGES.put("group.exploit", "漏洞利用工具");
        MESSAGES.put("group.member", "会员功能");

        // ==================== 命令 short ====================
        MESSAGES.put("cmd.about.short", "综合渗透测试工具，着重测试");
        MESSAGES.put("cmd.ca.short", "配置安全审计工具");
        MESSAGES.put("cmd.linenum.short", "Linux本地信息枚举工具");
        MESSAGES.put("cmd.crunch.short", "计算机根据算法生成的密码字典生成工具");
        MESSAGES.put("cmd.cupp.short", "根据社会工程学信息生成密码-社会工程学密码生成器");
        MESSAGES.put("cmd.passwd.short", "weakpass 密码字典与哈希工具 - 列表/下载/查询/检索/生成");
        MESSAGES.put("cmd.database.short", "数据库密码爆破工具");
        MESSAGES.put("cmd.dirscan.short", "网站目录扫描工具");
        MESSAGES.put("cmd.dns.short", "DNS 查询工具，支持多种记录类型和反向查询");
        MESSAGES.put("cmd.living.short", "智能存活探测 - 识别WAF拦截和假死页面");
        MESSAGES.put("cmd.route.short", "路由跳数检测");
        MESSAGES.put("cmd.scan.short", "网络扫描工具，支持主机发现、端口扫描、服务识别及WAF/假死检测");
        MESSAGES.put("cmd.ssl.short", "SSL/TLS配置检测工具");
        MESSAGES.put("cmd.whois.short", "Whois查询工具");
        MESSAGES.put("cmd.cdn.short", "CDN和云服务识别工具，识别CDN、云服务商和域名注册商");
        MESSAGES.put("cmd.pc.short", "远程补丁探测工具，探测目标系统的中间层组件版本与补丁状态");
        MESSAGES.put("cmd.process.short", "进程与服务信息收集工具");
        MESSAGES.put("cmd.sitemap.short", "Sitemap分析工具");
        MESSAGES.put("cmd.sub.short", "子域名挖掘工具，支持字典爆破和DNS查询");
        MESSAGES.put("cmd.userinfo.short", "本地用户和组分析");
        MESSAGES.put("cmd.webshell.short", "WebShell生成工具");
        MESSAGES.put("cmd.waf.short", "WAF识别工具");
        MESSAGES.put("cmd.webfp.short", "网站指纹识别与分析");
        MESSAGES.put("cmd.xss.short", "XSS漏洞检测工具，支持反射型、存储型、DOM型XSS检测");
        MESSAGES.put("cmd.csrf.short", "CSRF漏洞检测 [测试阶段]");
        MESSAGES.put("cmd.mg.short", "蜜罐识别工具 - 检测目标是否为蜜罐系统 [测试阶段]");
        MESSAGES.put("cmd.exp.short", "漏洞利用工具");
        MESSAGES.put("cmd.xxe.short", "XXE漏洞检测与利用");
        MESSAGES.put("cmd.ssh.short", "SSH密码爆破");
        MESSAGES.put("cmd.ftp.short", "FTP密码爆破");
        MESSAGES.put("cmd.fofa.short", "FOFA资产检索");
        MESSAGES.put("cmd.poc.short", "POC 攻击验证工具");
        MESSAGES.put("cmd.auth.short", "用户认证管理");
        MESSAGES.put("cmd.api.short", "HTTP API 服务");
        MESSAGES.put("cmd.agent.short", "C2 巡检代理");
        MESSAGES.put("cmd.chat.short", "AI 聊天助手");
        MESSAGES.put("cmd.dos.short", "拒绝服务攻击测试");
        MESSAGES.put("cmd.scap.short", "系统安全配置评估");
        MESSAGES.put("cmd.wwifi.short", "无线网络审计");
        MESSAGES.put("cmd.ws.short", "WebSocket 安全检测");
        MESSAGES.put("cmd.fu.short", "文件上传漏洞检查工具");
        MESSAGES.put("cmd.linux-kernel.short", "Linux 内核漏洞利用");
        MESSAGES.put("cmd.kernel-vulns.short", "内核漏洞扫描");
        MESSAGES.put("cmd.poc-windows.short", "Windows POC 攻击验证");
        MESSAGES.put("cmd.update.short", "在线更新");
        MESSAGES.put("cmd.nuclei.short", "nuclei 漏洞扫描引擎 - 基于 YAML 模板的协议级漏洞检测");

        // ==================== Help ====================
        MESSAGES.put("help.available", "Available Commands:");
        MESSAGES.put("help.flags", "Flags:");
        MESSAGES.put("help.usage", "Usage:");
        MESSAGES.put("help.example", "Examples:");
        MESSAGES.put("help.get_cmd_help", "使用 \"jyscan help [command]\" 获取命令帮助信息");
        MESSAGES.put("help.cmd_failed", "命令执行失败: %v");

        // ==================== root persistent flags ====================
        MESSAGES.put("root.flag.silent", "静默模式，仅输出关键结果");
        MESSAGES.put("root.flag.version", "显示版本信息");
        MESSAGES.put("root.flag.noBanner", "不显示启动横幅");
        MESSAGES.put("root.flag.noColor", "禁用颜色输出");
        MESSAGES.put("root.flag.verbose", "显示详细输出");
        MESSAGES.put("root.flag.lang", "界面语言: zh(中文) / en(English)，缺省按 JYSCAN_LANG/LANG 环境变量");

        // ==================== nmap scan command ====================
        MESSAGES.put("nmap.cmd.use", "scan [目标] [help]");
        MESSAGES.put("nmap.cmd.short", "网络扫描工具，支持主机发现、端口扫描、服务识别及WAF/假死检测");
        MESSAGES.put("nmap.cmd.help", "显示nmap模块详细帮助信息");

        // nmap flags
        MESSAGES.put("nmap.flag.target", "扫描目标 (IP/CIDR/IP范围/域名)");
        MESSAGES.put("nmap.flag.iL", "-iL <file>: 从文件读取目标列表 (支持.txt/.lst格式，每行一个目标)");
        MESSAGES.put("nmap.flag.ports", "扫描端口 (默认: 1-1000, 支持: 80,443,1-1000,22,80,443, -p- 表示全端口扫描)");
        MESSAGES.put("nmap.flag.threads", "并发线程数");
        MESSAGES.put("nmap.flag.timeout", "超时时间(秒)");
        MESSAGES.put("nmap.flag.timing", "扫描速度级别 (0-5, 完全模仿nmap -T参数)");
        MESSAGES.put("nmap.flag.sT", "TCP连接扫描");
        MESSAGES.put("nmap.flag.sU", "UDP扫描");
        MESSAGES.put("nmap.flag.sS", "SYN扫描");
        MESSAGES.put("nmap.flag.sF", "TCP FIN扫描");
        MESSAGES.put("nmap.flag.sX", "TCP XMAS扫描");
        MESSAGES.put("nmap.flag.sN", "TCP NULL扫描");
        MESSAGES.put("nmap.flag.sA", "TCP ACK扫描");
        MESSAGES.put("nmap.flag.sW", "TCP 窗口扫描");
        MESSAGES.put("nmap.flag.sM", "TCP Maimon扫描");
        MESSAGES.put("nmap.flag.O", "启用系统识别");
        MESSAGES.put("nmap.flag.sV", "启用服务识别");
        MESSAGES.put("nmap.flag.A", "全面扫描模式");
        MESSAGES.put("nmap.flag.f", "碎片化扫描模式");
        MESSAGES.put("nmap.flag.sn", "主机存活探测模式");
        MESSAGES.put("nmap.flag.ttl", "启用TTL检测，估算目标距离");
        MESSAGES.put("nmap.flag.ttlValue", "设置发送数据包的TTL值 (等同于nmap --ttl参数)");
        MESSAGES.put("nmap.flag.Pn", "跳过主机发现，直接扫描端口 (等同于nmap -Pn参数)");
        MESSAGES.put("nmap.flag.ipv6", "启用IPv6扫描模式 (等同于nmap -6参数)");
        MESSAGES.put("nmap.flag.output", "结果输出文件");
        MESSAGES.put("nmap.flag.script", "扫描完成后运行 YScript 脚本 (例如 --script=xx.ys 或 --script=scripts/xx.ys)");
        MESSAGES.put("nmap.flag.scriptArgs", "传递给 YScript 脚本的参数 (空格分隔，支持双引号)");
        MESSAGES.put("nmap.flag.scriptList", "列出可用 YScript 脚本及用途");
        MESSAGES.put("nmap.flag.waf", "启用WAF检测，识别云WAF拦截页面");
        MESSAGES.put("nmap.flag.simhash", "启用SimHash页面相似度检测，过滤相同拦截页面");
        MESSAGES.put("nmap.flag.simThreshold", "SimHash相似度阈值 (Hamming距离)");
        MESSAGES.put("nmap.flag.wafThreshold", "WAF检测置信度阈值");
        MESSAGES.put("nmap.flag.filterWAF", "过滤WAF拦截的目标，仅输出有效资产");
        MESSAGES.put("nmap.flag.X", "对开放端口进行内容探测，获取端口回复的内容");
        MESSAGES.put("nmap.flag.contentProbeTimeout", "内容探测单端口超时时间(秒)，0 表示沿用 -w/--timeout");
        MESSAGES.put("nmap.flag.contentProbeThreads", "内容探测并发数");

        // nmap runtime messages
        MESSAGES.put("nmap.err.script_mode_only", "[错误] --script 仅支持以下两种运行模式:");
        MESSAGES.put("nmap.err.script_mode_1", "  1. JYscan scan [目标] --script=xxx");
        MESSAGES.put("nmap.err.script_mode_2", "  2. JYscan scan -iL targets.txt --script=xxx");
        MESSAGES.put("nmap.err.script_no_target", "当前未通过位置参数或 -iL 指定目标");
        MESSAGES.put("nmap.warn.script_conflict", "[警告] 同时指定了位置参数和 -iL，将以 -iL 批量目标为准");
        MESSAGES.put("nmap.err.file_read_or_empty", "[错误] 无法从文件读取目标或文件为空: %s");
        MESSAGES.put("nmap.err.file_format_hint", "支持的格式: .txt, .lst (每行一个目标)");
        MESSAGES.put("nmap.log.targets_from_file", "[JYscan-Nmap] 从文件读取 %d 个目标");
        MESSAGES.put("nmap.warn.pn_sn_mutual", "[警告] -Pn 和 -sn 参数互斥，-sn 优先执行主机发现");
        MESSAGES.put("nmap.warn.target_invalid_skip", "[警告] 目标格式无效，跳过: %s");
        MESSAGES.put("nmap.warn.exec_unavailable", "[JYscan-Nmap] 未找到可用的外部命令 %s(未安装或无可执行权限)，已自动使用内置探测方式");
        MESSAGES.put("nmap.log.dns_fallback", "[JYscan-Nmap] 系统 DNS 不可用，已回退到公共 DNS 解析 %s");
        MESSAGES.put("nmap.log.batch_complete", "\n[JYscan-Nmap] 批量扫描完成，耗时: %v");
        MESSAGES.put("nmap.err.save_failed", "保存结果失败: %v");
        MESSAGES.put("nmap.err.specify_target", "请指定扫描目标 (直接传递目标参数或使用 --target 标志)");
        MESSAGES.put("nmap.err.usage_hint", "用法: JYscan scan 目标 [选项] 或 JYscan scan --target 目标 [选项]");
        MESSAGES.put("nmap.err.or_use_il", "或使用 -iL 参数从文件读取目标列表");
        MESSAGES.put("nmap.err.target_invalid", "目标格式无效: %s");
        MESSAGES.put("nmap.err.target_formats", "支持格式: IP地址(192.168.1.1), CIDR(192.168.1.0/24), IP范围(192.168.1.1-100), 域名(example.com)");
        MESSAGES.put("nmap.log.scan_complete", "[JYscan-Nmap] 扫描完成，耗时: %v");
        MESSAGES.put("nmap.log.script_only_mode", "[JYscan-Nmap] 纯脚本模式，跳过端口扫描，运行 YScript 脚本: %s");
        MESSAGES.put("nmap.err.script_exec_failed", "[错误] YScript 脚本执行失败: %v");

        // nmap scan_optimized progress/status
        MESSAGES.put("nmap.log.host_discovery_mode", "[JYscan-Nmap] 主机存活探测模式 (-sn): 目标=%s, 线程=%d, 速度级别=%d");
        MESSAGES.put("nmap.err.no_ipv4_host", "[JYscan-Nmap] 未发现 IPv4 主机 (如需扫描 IPv6，请显式指定 -6 参数)");
        MESSAGES.put("nmap.log.ultra_scan", "[JYscan-Nmap] 超高速扫描: %s, %d台主机, %d个端口, %d并发 (协议族: %s)");
        MESSAGES.put("nmap.log.cache_hit", "[完成] %s (缓存) (%d/%d)");
        MESSAGES.put("nmap.log.scanning", "[扫描] %s...");
        MESSAGES.put("nmap.log.offline", "[离线] %s (%d/%d)");
        MESSAGES.put("nmap.err.ultra_scan_failed", "[错误] 超高速扫描失败: %v, 降级到标准扫描");
        MESSAGES.put("nmap.progress.port_scan", "[*] 正在探测 %s - %d");
        MESSAGES.put("nmap.progress.service_detect", "[*] 正在识别服务 %s ...");
        MESSAGES.put("nmap.progress.os_detect", "[*] 正在识别操作系统 %s ...");
        MESSAGES.put("nmap.progress.content_probe", "[*] 正在内容探测 %s ...");
        MESSAGES.put("nmap.progress.ttl_detect", "[*] 正在检测TTL %s ...");
        MESSAGES.put("nmap.log.complete", "[完成] %s (%d/%d)");
        MESSAGES.put("nmap.log.port_verbose", "[完成] %s | %d端口 | 开放:%d 过滤:%d 关闭:%d | 耗时:%v 速率:%.0f/s");

        // nmap scan.go host discovery
        MESSAGES.put("nmap.progress.hd_start", "[进度] 主机存活探测: 扫描 %d 个主机，仅判断在线状态");
        MESSAGES.put("nmap.log.hd_cancelled", "[JYscan-Nmap] 主机存活探测被用户取消");
        MESSAGES.put("nmap.progress.host_alive", "[进度] 主机 %s 在线 (存活)");
        MESSAGES.put("nmap.progress.host_dead", "[进度] 主机 %s 离线 (不存活)");
        MESSAGES.put("nmap.progress.hd_progress", "[进度] 主机存活探测进度: %d/%d - 发现 %d 台存活主机");
        MESSAGES.put("nmap.log.hd_complete", "[JYscan-Nmap] 主机存活探测完成，发现 %d 台存活主机");
        MESSAGES.put("nmap.log.alive_hosts", "\n[存活主机列表]");
        MESSAGES.put("nmap.log.resolve_failed", "[JYscan-Nmap] 解析域名 %s 失败: %v");
        MESSAGES.put("nmap.log.cidr_parse_failed", "[JYscan-Nmap] 解析CIDR失败: %v");
        MESSAGES.put("nmap.err.invalid_ip_range", "[JYscan-Nmap] 无效的IP范围格式: %s");
        MESSAGES.put("nmap.err.invalid_ip", "[JYscan-Nmap] 无效的IP地址");
        MESSAGES.put("nmap.log.similar_pages", "SimHash相似页面 (与%d个页面相似)");
        MESSAGES.put("nmap.log.filtered_similar", "[智能探测] 主机 %s 过滤了 %d 个相似页面");

        // nmap utils.go result display
        MESSAGES.put("nmap.err.serialize_failed", "序列化结果失败: %v");
        MESSAGES.put("nmap.err.write_file_failed", "写入文件失败: %v");
        MESSAGES.put("nmap.log.result_saved", "[JYscan-Nmap] 扫描结果已保存到: %s");
        MESSAGES.put("nmap.result.title", "=== 扫描结果 ===");
        MESSAGES.put("nmap.result.hosts_active", "%d 台主机活跃");
        MESSAGES.put("nmap.result.host", "主机: %s");
        MESSAGES.put("nmap.result.open_ports", "开放端口:");
        MESSAGES.put("nmap.result.links", "访问链接:");
        MESSAGES.put("nmap.result.os", "操作系统: %s");
        MESSAGES.put("nmap.result.distance", "网络距离: %d 跳");
        MESSAGES.put("nmap.warn.file_format", "[警告] 文件格式可能不受支持: %s (建议使用 .txt 或 .lst 格式)");
        MESSAGES.put("nmap.err.read_file_failed", "[错误] 读取目标文件失败: %v");
        MESSAGES.put("nmap.warn.no_valid_target", "[警告] 文件中没有找到有效目标: %s");

        // nmap yscript.go
        MESSAGES.put("nmap.err.script_not_found", "找不到脚本文件: %s (支持路径、xx.ys 或 script/scripts 目录下的裸名称/子目录名)");
        MESSAGES.put("nmap.err.serialize_results", "序列化扫描结果失败: %v");
        MESSAGES.put("nmap.err.create_temp_file", "创建临时结果文件失败: %v");
        MESSAGES.put("nmap.err.write_temp_file", "写入临时结果文件失败: %v");
        MESSAGES.put("nmap.log.running_script", "\n[JYscan-Nmap] 运行 YScript 脚本: %s");
        MESSAGES.put("nmap.log.no_scripts", "[JYscan-Nmap] 未找到任何 YScript 脚本");
        MESSAGES.put("nmap.log.put_scripts_hint", "  请将 .ys 脚本放入可执行文件旁或当前目录的 script/ 或 scripts/ 目录");
        MESSAGES.put("nmap.log.available_scripts", "[JYscan-Nmap] 可用 YScript 脚本 (%d 个):");
        MESSAGES.put("nmap.log.no_description", "(无描述)");
        MESSAGES.put("nmap.log.script_usage", "使用: JYscan scan [目标] --script=<脚本名或路径> [--script-args=\"...\"]");

        // nmap traceroute
        MESSAGES.put("nmap.err.target_unreachable", "无法到达目标主机");

        // nmap rawscan Windows warnings
        MESSAGES.put("nmap.warn.win_raw_fin", "[警告] Windows 不支持原始套接字，--sF 降级为 TCP connect 扫描");
        MESSAGES.put("nmap.warn.win_raw_xmas", "[警告] Windows 不支持原始套接字，--sX 降级为 TCP connect 扫描");
        MESSAGES.put("nmap.warn.win_raw_null", "[警告] Windows 不支持原始套接字，--sN 降级为 TCP connect 扫描");
        MESSAGES.put("nmap.warn.win_raw_ack", "[警告] Windows 不支持原始套接字，--sA 降级为 TCP connect 扫描");
        MESSAGES.put("nmap.warn.win_raw_window", "[警告] Windows 不支持原始套接字，--sW 降级为 TCP connect 扫描");
        MESSAGES.put("nmap.warn.win_raw_maimon", "[警告] Windows 不支持原始套接字，--sM 降级为 TCP connect 扫描");

        // nmap scan_optimized_linux / windows fd limit
        MESSAGES.put("nmap.fd.cant_get_limit", "无法获取文件描述符限制: %v");
        MESSAGES.put("nmap.fd.soft_limit_low", "当前软限制过低，建议运行: ulimit -n 65535");
        MESSAGES.put("nmap.fd.current", "当前: %d (软) / %d (硬)");
        MESSAGES.put("nmap.fd.enough", "文件描述符限制: %d / %d (足够)");
        MESSAGES.put("nmap.fd.not_enough", "文件描述符限制: %d / %d - %s");
        MESSAGES.put("nmap.fd.win_auto", "文件描述符限制: Windows 系统自动管理 (无需调整)");

        // ==================== nuclei ====================
        // 限定名引用，避免"illegal forward reference"（字段声明在 static 块之后）
        MESSAGES.put("cmd.nuclei.long", Zh.NUCLEI_LONG_ZH);
        MESSAGES.put("nuclei.flag.url", "目标 URL/主机");
        MESSAGES.put("nuclei.flag.list", "目标列表文件 (每行一个)");
        MESSAGES.put("nuclei.flag.template", "模板文件路径");
        MESSAGES.put("nuclei.flag.templates-dir", "模板目录路径 (nuclei 兼容 -td)");
        MESSAGES.put("nuclei.flag.td", "模板目录路径 (nuclei 兼容简写)");
        MESSAGES.put("nuclei.flag.output", "输出文件路径");
        MESSAGES.put("nuclei.flag.json", "JSON 格式输出");
        MESSAGES.put("nuclei.flag.severity", "按严重程度过滤 (info,low,medium,high,critical)");
        MESSAGES.put("nuclei.flag.tags", "按标签过滤");
        MESSAGES.put("nuclei.flag.verbose", "详细输出");
        MESSAGES.put("nuclei.flag.concurrency", "模板并发数");
        MESSAGES.put("nuclei.flag.threads", "线程数 (与 --concurrency 相同, 优先使用 -c)");
        MESSAGES.put("nuclei.flag.strategy", "扫描策略 (auto, template-spray, host-spray)");
        MESSAGES.put("nuclei.flag.no-color", "禁用彩色输出 (nuclei 兼容)");
        MESSAGES.put("nuclei.flag.silent", "静默模式 (只显示匹配结果)");

        MESSAGES.put("nuclei.err.no-target", "未提供目标输入 (请使用 -u 或 -l)");
        MESSAGES.put("nuclei.err.no-template", "未提供模板输入 (请使用 -t 或 -td)");
        MESSAGES.put("nuclei.err.read-target-file", "无法读取目标文件: %v");
        MESSAGES.put("nuclei.err.no-valid-target", "未发现有效的目标");
        MESSAGES.put("nuclei.err.load-template-dir", "从 %s 加载模板失败: %v");
        MESSAGES.put("nuclei.err.template-not-found", "模板路径未找到: %s");
        MESSAGES.put("nuclei.err.load-template", "加载模板 %s 失败: %v");
        MESSAGES.put("nuclei.err.no-executable", "未发现可执行的模板");
        MESSAGES.put("nuclei.err.create-output", "创建输出文件失败: %v");

        // MESSAGES.put("nuclei.log.version", "当前 nuclei 版本: v3.11.0 (最新版)");
        MESSAGES.put("nuclei.log.template-version", "当前 nuclei 模板版本: v10.4.5 (最新版)");
        MESSAGES.put("nuclei.log.new-templates", "最新发布中新增的模板: 86");
        MESSAGES.put("nuclei.log.loaded-templates", "当前扫描已加载模板: %d");
        MESSAGES.put("nuclei.log.signed-templates", "正在执行 %d 个来自 projectdiscovery/nuclei-templates 的已签名模板");
        MESSAGES.put("nuclei.log.loaded-targets", "当前扫描已加载目标: %d");
        MESSAGES.put("nuclei.log.httpx-probe", "正在对输入主机运行 httpx 探测");
        MESSAGES.put("nuclei.log.httpx-found", "从 httpx 中发现 %d 个 URL");
        MESSAGES.put("nuclei.log.interactsh", "使用 Interactsh 服务器: oast.pro");
        MESSAGES.put("nuclei.log.clustered", "模板已聚类: %d (减少 %d 个请求)");

        MESSAGES.put("nuclei.summary.skipped-host", "已跳过目标 %s, 连续无响应 %d 次");
        MESSAGES.put("nuclei.summary.completed-matched", "扫描完成, 耗时 %s, 共发现 %d 个匹配。");
        MESSAGES.put("nuclei.summary.completed-no-match", "扫描完成, 耗时 %s, 未发现匹配项。");
        MESSAGES.put("nuclei.summary.http-conns", "HTTP 连接: 总计 %d, 新建 %d, 复用 %d (%.1f%%)");
        MESSAGES.put("nuclei.summary.title", "扫描结果总结 (JYscan 增强)");
        MESSAGES.put("nuclei.summary.total-templates", "总模板数:");
        MESSAGES.put("nuclei.summary.matched", "命中数:");
        MESSAGES.put("nuclei.summary.skipped", "(跳过 %d)");
        MESSAGES.put("nuclei.summary.duration", "耗时:");
        MESSAGES.put("nuclei.summary.speed", "扫描速度: %.1f 模板/秒");
        MESSAGES.put("nuclei.summary.severity-dist", "[严重程度分布]");
        MESSAGES.put("nuclei.summary.protocol-dist", "[协议分布]");
        MESSAGES.put("nuclei.summary.type-top", "[命中类型 Top]");
        MESSAGES.put("nuclei.summary.match-detail", "[命中详情 Top 10]");
        MESSAGES.put("nuclei.summary.more-hits", "... 还有 %d 条命中未显示");
        MESSAGES.put("nuclei.summary.match-at", "(匹配: %s)");
    }

    private static final String NUCLEI_LONG_ZH = """
nuclei 命令 - 基于 YAML 模板的协议级漏洞检测引擎

支持协议: HTTP, DNS, TCP, SSL
支持模板格式: YAML, JSON

扫描策略:
  auto           自动选择 (模板多目标少时用 host-spray)
  template-spray 模板喷射 (每个模板并发扫描所有目标)
  host-spray     主机喷射 (每个目标并发执行所有模板)

多线程参数:
  -c, --concurrency  模板并发数 (默认: 10)
  -T, --threads      线程数 (与 --concurrency 相同, 默认: 10)

使用示例:
  # 扫描单个目标
  jyscan nuclei -u http://example.com -t template.yaml

  # 从文件加载目标
  jyscan nuclei -l targets.txt -t template.yaml

  # 从目录加载模板
  jyscan nuclei -u http://example.com -td ./nuclei-templates/

  # 按严重程度过滤
  jyscan nuclei -u http://example.com -td ./templates/ -severity critical,high

  # JSON 输出
  jyscan nuclei -u http://example.com -t template.yaml -json -o result.json

  # 指定扫描策略
  jyscan nuclei -u http://example.com -td ./templates/ -strategy host-spray

  # 设置并发数/线程数
  jyscan nuclei -u http://example.com -td ./templates/ -c 20
  jyscan nuclei -u http://example.com -td ./templates/ --threads 50

  # 同时输出到 stdout
  jyscan nuclei -u http://example.com -t template.yaml -v""";

    private Zh() {
    }
}

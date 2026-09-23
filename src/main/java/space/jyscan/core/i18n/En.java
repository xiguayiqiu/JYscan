package space.jyscan.core.i18n;

import java.util.HashMap;
import java.util.Map;

/**
 * 英文文案表，移植自 internal/i18n/i18n.go 的 LangEN 分支。
 *
 * <p>缺 key 时由 {@link I18n#T} 回退到中文表，因此这里只放与中文不同的条目
 * 以及英文专属文案；未覆盖的 key（如 nmap.* 运行期消息）会自动回退中文，
 * 与 Go 版"缺失 key 回退 DefaultLang"的行为一致。
 */
final class En {

    static final Map<String, String> MESSAGES = new HashMap<>();

    static {
        // ==================== Application ====================
        MESSAGES.put("app.name", "jyscan");
        MESSAGES.put("app.copyright", "Copyright © 2024-2026 JYscan");
        MESSAGES.put("app.legal", "Warning: For authorized testing only. Unauthorized use is strictly prohibited!");
        MESSAGES.put("app.slogan", "Comprehensive penetration testing toolkit");
        MESSAGES.put("app.author", "Author: BiliBili-弈秋啊");
        MESSAGES.put("app.version", "Version: %s");
        MESSAGES.put("app.desc", "Description: Penetration testing toolkit for asset discovery, vulnerability detection, and security validation");
        MESSAGES.put("app.warning", "Warning: For authorized testing only. Unauthorized use is strictly prohibited!");
        MESSAGES.put("app.get_help", "Use \"./jyscan help\" for help information");
        MESSAGES.put("app.banner_title", "jyscan-free - Go Penetration Testing Toolkit (Free Edition)");

        // ==================== Groups ====================
        MESSAGES.put("group.general", "General");
        MESSAGES.put("group.password", "Password");
        MESSAGES.put("group.network", "Network Scan");
        MESSAGES.put("group.info", "Info Gathering");
        MESSAGES.put("group.web", "Web Security");
        MESSAGES.put("group.privesc", "Privilege Escalation");
        MESSAGES.put("group.testing", "Testing Phase");
        MESSAGES.put("group.exploit", "Exploitation");
        MESSAGES.put("group.member", "Member Features");

        // ==================== Command short ====================
        MESSAGES.put("cmd.about.short", "Comprehensive penetration testing toolkit");
        MESSAGES.put("cmd.ca.short", "Configuration security audit");
        MESSAGES.put("cmd.linenum.short", "Linux local information enumeration");
        MESSAGES.put("cmd.crunch.short", "Wordlist generator based on character patterns");
        MESSAGES.put("cmd.cupp.short", "Social engineering password generator (CUPP)");
        MESSAGES.put("cmd.database.short", "Database password brute-forcer");
        MESSAGES.put("cmd.dirscan.short", "Website directory scanner");
        MESSAGES.put("cmd.dns.short", "DNS query tool with multiple record types and reverse lookup");
        MESSAGES.put("cmd.living.short", "Smart liveness probe - detects WAF blocks and dead pages");
        MESSAGES.put("cmd.route.short", "Route hop count detection");
        MESSAGES.put("cmd.scan.short", "Network scanner (host discovery, port scan, service detect, WAF)");
        MESSAGES.put("cmd.ssl.short", "SSL/TLS configuration auditor");
        MESSAGES.put("cmd.whois.short", "Whois lookup");
        MESSAGES.put("cmd.cdn.short", "CDN & cloud provider fingerprinting");
        MESSAGES.put("cmd.pc.short", "Remote patch detection (middleware versions & patches)");
        MESSAGES.put("cmd.process.short", "Process and service information collector");
        MESSAGES.put("cmd.sitemap.short", "Sitemap analyzer");
        MESSAGES.put("cmd.sub.short", "Subdomain enumeration (dictionary + DNS)");
        MESSAGES.put("cmd.userinfo.short", "Local users and groups analyzer");
        MESSAGES.put("cmd.webshell.short", "WebShell generator");
        MESSAGES.put("cmd.waf.short", "WAF fingerprinting");
        MESSAGES.put("cmd.webfp.short", "Website fingerprinting & analysis");
        MESSAGES.put("cmd.xss.short", "XSS detector (reflected, stored, DOM)");
        MESSAGES.put("cmd.csrf.short", "CSRF detector [Testing]");
        MESSAGES.put("cmd.mg.short", "Honeypot detector [Testing]");
        MESSAGES.put("cmd.exp.short", "Exploitation toolkit");
        MESSAGES.put("cmd.xxe.short", "XXE detector and exploiter");
        MESSAGES.put("cmd.ssh.short", "SSH password brute-forcer");
        MESSAGES.put("cmd.ftp.short", "FTP password brute-forcer");
        MESSAGES.put("cmd.fofa.short", "FOFA asset search");
        MESSAGES.put("cmd.poc.short", "POC attack & verification toolkit");
        MESSAGES.put("cmd.auth.short", "User authentication management");
        MESSAGES.put("cmd.api.short", "HTTP API service");
        MESSAGES.put("cmd.agent.short", "C2 inspection agent");
        MESSAGES.put("cmd.chat.short", "AI chat assistant");
        MESSAGES.put("cmd.dos.short", "Denial-of-service testing");
        MESSAGES.put("cmd.scap.short", "System security configuration assessment");
        MESSAGES.put("cmd.wwifi.short", "Wireless network audit");
        MESSAGES.put("cmd.ws.short", "WebSocket security check");
        MESSAGES.put("cmd.fu.short", "File-upload vulnerability checker");
        MESSAGES.put("cmd.linux-kernel.short", "Linux kernel exploitation");
        MESSAGES.put("cmd.kernel-vulns.short", "Kernel vulnerability scanner");
        MESSAGES.put("cmd.poc-windows.short", "Windows POC attack verifier");
        MESSAGES.put("cmd.update.short", "Online update");
        MESSAGES.put("cmd.nuclei.short", "Nuclei template scanner - YAML-based protocol-level vulnerability detection");

        // ==================== Help ====================
        MESSAGES.put("help.available", "Available Commands:");
        MESSAGES.put("help.flags", "Flags:");
        MESSAGES.put("help.usage", "Usage:");
        MESSAGES.put("help.example", "Examples:");
        MESSAGES.put("help.get_cmd_help", "Use \"jyscan help [command]\" for more information about a command");
        MESSAGES.put("help.cmd_failed", "Command failed: %v");

        // ==================== Root persistent flags ====================
        MESSAGES.put("root.flag.silent", "Silent mode, only output key results");
        MESSAGES.put("root.flag.version", "Show version info");
        MESSAGES.put("root.flag.noBanner", "Don't show startup banner");
        MESSAGES.put("root.flag.noColor", "Disable colored output");
        MESSAGES.put("root.flag.verbose", "Verbose output");
        MESSAGES.put("root.flag.lang", "Language: zh(Chinese) / en(English), default from JYSCAN_LANG/LANG env");

        // ==================== nmap scan command ====================
        MESSAGES.put("nmap.cmd.use", "scan [target] [help]");
        MESSAGES.put("nmap.cmd.short", "Network scanner (host discovery, port scan, service detect, WAF)");
        MESSAGES.put("nmap.cmd.help", "Show detailed nmap module help");

        // nmap flags
        MESSAGES.put("nmap.flag.target", "Scan target (IP/CIDR/range/domain)");
        MESSAGES.put("nmap.flag.iL", "-iL <file>: Read targets from file (supports .txt/.lst, one per line)");
        MESSAGES.put("nmap.flag.ports", "Scan ports (default: 1-1000, e.g.: 80,443,1-1000,22,80,443, -p- for all ports)");
        MESSAGES.put("nmap.flag.threads", "Concurrent threads");
        MESSAGES.put("nmap.flag.timeout", "Timeout in seconds");
        MESSAGES.put("nmap.flag.timing", "Timing template (0-5, nmap -T style)");
        MESSAGES.put("nmap.flag.sT", "TCP connect scan");
        MESSAGES.put("nmap.flag.sU", "UDP scan");
        MESSAGES.put("nmap.flag.sS", "SYN scan");
        MESSAGES.put("nmap.flag.sF", "TCP FIN scan");
        MESSAGES.put("nmap.flag.sX", "TCP XMAS scan");
        MESSAGES.put("nmap.flag.sN", "TCP NULL scan");
        MESSAGES.put("nmap.flag.sA", "TCP ACK scan");
        MESSAGES.put("nmap.flag.sW", "TCP window scan");
        MESSAGES.put("nmap.flag.sM", "TCP Maimon scan");
        MESSAGES.put("nmap.flag.O", "Enable OS detection");
        MESSAGES.put("nmap.flag.sV", "Enable service/version detection");
        MESSAGES.put("nmap.flag.A", "Aggressive scan mode");
        MESSAGES.put("nmap.flag.f", "Fragmented scan mode");
        MESSAGES.put("nmap.flag.sn", "Host discovery only (no port scan)");
        MESSAGES.put("nmap.flag.ttl", "Enable TTL detection (estimate target distance)");
        MESSAGES.put("nmap.flag.ttlValue", "Set packet TTL value (same as nmap --ttl)");
        MESSAGES.put("nmap.flag.Pn", "Skip host discovery, scan ports directly (same as nmap -Pn)");
        MESSAGES.put("nmap.flag.ipv6", "Enable IPv6 scan mode (same as nmap -6)");
        MESSAGES.put("nmap.flag.output", "Output file");
        MESSAGES.put("nmap.flag.script", "Run YScript after scan (e.g. --script=xx.ys or --script=scripts/xx.ys)");
        MESSAGES.put("nmap.flag.scriptArgs", "Arguments for YScript (space-separated, supports double quotes)");
        MESSAGES.put("nmap.flag.scriptList", "List available YScript scripts and descriptions");
        MESSAGES.put("nmap.flag.waf", "Enable WAF detection (cloud WAF blocking pages)");
        MESSAGES.put("nmap.flag.simhash", "Enable SimHash page similarity detection");
        MESSAGES.put("nmap.flag.simThreshold", "SimHash similarity threshold (Hamming distance)");
        MESSAGES.put("nmap.flag.wafThreshold", "WAF detection confidence threshold");
        MESSAGES.put("nmap.flag.filterWAF", "Filter WAF-blocked targets, output only valid assets");
        MESSAGES.put("nmap.flag.X", "Content probe on open ports (grab response content)");
        MESSAGES.put("nmap.flag.contentProbeTimeout", "Content probe timeout per port (sec), 0 = use -w/--timeout");
        MESSAGES.put("nmap.flag.contentProbeThreads", "Content probe concurrency");

        // nmap runtime messages
        MESSAGES.put("nmap.err.script_mode_only", "[ERROR] --script only supports two modes:");
        MESSAGES.put("nmap.err.script_mode_1", "  1. JYscan scan [target] --script=xxx");
        MESSAGES.put("nmap.err.script_mode_2", "  2. JYscan scan -iL targets.txt --script=xxx");
        MESSAGES.put("nmap.err.script_no_target", "No target specified via positional arg or -iL");
        MESSAGES.put("nmap.warn.script_conflict", "[WARN] Both positional arg and -iL specified, using -iL targets");
        MESSAGES.put("nmap.err.file_read_or_empty", "[ERROR] Failed to read targets from file or file is empty: %s");
        MESSAGES.put("nmap.err.file_format_hint", "Supported formats: .txt, .lst (one target per line)");
        MESSAGES.put("nmap.log.targets_from_file", "[JYscan-Nmap] Read %d targets from file");
        MESSAGES.put("nmap.warn.pn_sn_mutual", "[WARN] -Pn and -sn are mutually exclusive, -sn takes priority");
        MESSAGES.put("nmap.warn.target_invalid_skip", "[WARN] Invalid target format, skipping: %s");
        MESSAGES.put("nmap.warn.exec_unavailable", "[JYscan-Nmap] External command %s not found (not installed or not executable), falling back to built-in probing");
        MESSAGES.put("nmap.log.dns_fallback", "[JYscan-Nmap] System DNS unavailable, falling back to public DNS for %s");
        MESSAGES.put("nmap.log.batch_complete", "\n[JYscan-Nmap] Batch scan completed, elapsed: %v");
        MESSAGES.put("nmap.err.save_failed", "Failed to save results: %v");
        MESSAGES.put("nmap.err.specify_target", "Please specify a scan target (positional arg or --target flag)");
        MESSAGES.put("nmap.err.usage_hint", "Usage: JYscan scan <target> [options] or JYscan scan --target <target> [options]");
        MESSAGES.put("nmap.err.or_use_il", "Or use -iL to read target list from file");
        MESSAGES.put("nmap.err.target_invalid", "Invalid target format: %s");
        MESSAGES.put("nmap.err.target_formats", "Supported: IP(192.168.1.1), CIDR(192.168.1.0/24), range(192.168.1.1-100), domain(example.com)");
        MESSAGES.put("nmap.log.scan_complete", "[JYscan-Nmap] Scan completed, elapsed: %v");
        MESSAGES.put("nmap.log.script_only_mode", "[JYscan-Nmap] Script-only mode, skipping port scan, running: %s");
        MESSAGES.put("nmap.err.script_exec_failed", "[ERROR] YScript execution failed: %v");

        // nmap scan_optimized progress/status
        MESSAGES.put("nmap.log.host_discovery_mode", "[JYscan-Nmap] Host discovery mode (-sn): target=%s, threads=%d, timing=%d");
        MESSAGES.put("nmap.err.no_ipv4_host", "[JYscan-Nmap] No IPv4 hosts found (use -6 for IPv6)");
        MESSAGES.put("nmap.log.ultra_scan", "[JYscan-Nmap] Ultra-fast scan: %s, %d hosts, %d ports, %d threads (family: %s)");
        MESSAGES.put("nmap.log.cache_hit", "[DONE] %s (cached) (%d/%d)");
        MESSAGES.put("nmap.log.scanning", "[SCAN] %s...");
        MESSAGES.put("nmap.log.offline", "[OFFLINE] %s (%d/%d)");
        MESSAGES.put("nmap.err.ultra_scan_failed", "[ERROR] Ultra-fast scan failed: %v, falling back to standard scan");
        MESSAGES.put("nmap.progress.port_scan", "[*] Scanning %s - %d");
        MESSAGES.put("nmap.progress.service_detect", "[*] Detecting services %s ...");
        MESSAGES.put("nmap.progress.os_detect", "[*] Detecting OS %s ...");
        MESSAGES.put("nmap.progress.content_probe", "[*] Probing content %s ...");
        MESSAGES.put("nmap.progress.ttl_detect", "[*] Detecting TTL %s ...");
        MESSAGES.put("nmap.log.complete", "[DONE] %s (%d/%d)");
        MESSAGES.put("nmap.log.port_verbose", "[DONE] %s | %d ports | open:%d filtered:%d closed:%d | elapsed:%v rate:%.0f/s");

        // nmap scan.go host discovery
        MESSAGES.put("nmap.progress.hd_start", "[PROGRESS] Host discovery: scanning %d hosts, online status only");
        MESSAGES.put("nmap.log.hd_cancelled", "[JYscan-Nmap] Host discovery cancelled by user");
        MESSAGES.put("nmap.progress.host_alive", "[PROGRESS] Host %s is online (alive)");
        MESSAGES.put("nmap.progress.host_dead", "[PROGRESS] Host %s is offline (dead)");
        MESSAGES.put("nmap.progress.hd_progress", "[PROGRESS] Discovery progress: %d/%d - found %d alive hosts");
        MESSAGES.put("nmap.log.hd_complete", "[JYscan-Nmap] Host discovery complete, found %d alive hosts");
        MESSAGES.put("nmap.log.alive_hosts", "\n[Alive Hosts]");
        MESSAGES.put("nmap.log.resolve_failed", "[JYscan-Nmap] Failed to resolve domain %s: %v");
        MESSAGES.put("nmap.log.cidr_parse_failed", "[JYscan-Nmap] Failed to parse CIDR: %v");
        MESSAGES.put("nmap.err.invalid_ip_range", "[JYscan-Nmap] Invalid IP range format: %s");
        MESSAGES.put("nmap.err.invalid_ip", "[JYscan-Nmap] Invalid IP address");
        MESSAGES.put("nmap.log.similar_pages", "SimHash similar pages (%d pages similar)");
        MESSAGES.put("nmap.log.filtered_similar", "[Smart Probe] Host %s filtered %d similar pages");

        // nmap utils.go result display
        MESSAGES.put("nmap.err.serialize_failed", "Failed to serialize results: %v");
        MESSAGES.put("nmap.err.write_file_failed", "Failed to write file: %v");
        MESSAGES.put("nmap.log.result_saved", "[JYscan-Nmap] Results saved to: %s");
        MESSAGES.put("nmap.result.title", "=== Scan Results ===");
        MESSAGES.put("nmap.result.hosts_active", "%d hosts active");
        MESSAGES.put("nmap.result.host", "Host: %s");
        MESSAGES.put("nmap.result.open_ports", "Open ports:");
        MESSAGES.put("nmap.result.links", "Links:");
        MESSAGES.put("nmap.result.os", "OS: %s");
        MESSAGES.put("nmap.result.distance", "Network distance: %d hops");
        MESSAGES.put("nmap.warn.file_format", "[WARN] File format may not be supported: %s (use .txt or .lst)");
        MESSAGES.put("nmap.err.read_file_failed", "[ERROR] Failed to read target file: %v");
        MESSAGES.put("nmap.warn.no_valid_target", "[WARN] No valid targets found in file: %s");

        // nmap yscript.go
        MESSAGES.put("nmap.err.script_not_found", "Script file not found: %s (supports path, xx.ys, or bare name in script/scripts dir)");
        MESSAGES.put("nmap.err.serialize_results", "Failed to serialize scan results: %v");
        MESSAGES.put("nmap.err.create_temp_file", "Failed to create temp results file: %v");
        MESSAGES.put("nmap.err.write_temp_file", "Failed to write temp results file: %v");
        MESSAGES.put("nmap.log.running_script", "\n[JYscan-Nmap] Running YScript: %s");
        MESSAGES.put("nmap.log.no_scripts", "[JYscan-Nmap] No YScript scripts found");
        MESSAGES.put("nmap.log.put_scripts_hint", "  Place .ys scripts in the executable directory or script/ or scripts/ subdirectory");
        MESSAGES.put("nmap.log.available_scripts", "[JYscan-Nmap] Available YScript scripts (%d):");
        MESSAGES.put("nmap.log.no_description", "(no description)");
        MESSAGES.put("nmap.log.script_usage", "Usage: JYscan scan [target] --script=<name-or-path> [--script-args=\"...\"]");

        // nmap traceroute
        MESSAGES.put("nmap.err.target_unreachable", "Target host is unreachable");

        // nmap rawscan Windows warnings
        MESSAGES.put("nmap.warn.win_raw_fin", "[WARN] Windows does not support raw sockets, --sF falling back to TCP connect scan");
        MESSAGES.put("nmap.warn.win_raw_xmas", "[WARN] Windows does not support raw sockets, --sX falling back to TCP connect scan");
        MESSAGES.put("nmap.warn.win_raw_null", "[WARN] Windows does not support raw sockets, --sN falling back to TCP connect scan");
        MESSAGES.put("nmap.warn.win_raw_ack", "[WARN] Windows does not support raw sockets, --sA falling back to TCP connect scan");
        MESSAGES.put("nmap.warn.win_raw_window", "[WARN] Windows does not support raw sockets, --sW falling back to TCP connect scan");
        MESSAGES.put("nmap.warn.win_raw_maimon", "[WARN] Windows does not support raw sockets, --sM falling back to TCP connect scan");

        // nmap scan_optimized_linux / windows fd limit
        MESSAGES.put("nmap.fd.cant_get_limit", "Failed to get file descriptor limit: %v");
        MESSAGES.put("nmap.fd.soft_limit_low", "Current soft limit is too low, run: ulimit -n 65535");
        MESSAGES.put("nmap.fd.current", "Current: %d (soft) / %d (hard)");
        MESSAGES.put("nmap.fd.enough", "File descriptor limit: %d / %d (sufficient)");
        MESSAGES.put("nmap.fd.not_enough", "File descriptor limit: %d / %d - %s");
        MESSAGES.put("nmap.fd.win_auto", "File descriptor limit: Windows manages automatically (no adjustment needed)");

        // ==================== nuclei ====================
        // 限定名引用，避免"illegal forward reference"（字段声明在 static 块之后）
        MESSAGES.put("cmd.nuclei.long", En.NUCLEI_LONG_EN);
        MESSAGES.put("nuclei.flag.url", "Target URL/host");
        MESSAGES.put("nuclei.flag.list", "Target list file (one per line)");
        MESSAGES.put("nuclei.flag.template", "Template file path");
        MESSAGES.put("nuclei.flag.templates-dir", "Template directory path (nuclei compatible -td)");
        MESSAGES.put("nuclei.flag.td", "Template directory path (nuclei compatible shorthand)");
        MESSAGES.put("nuclei.flag.output", "Output file path");
        MESSAGES.put("nuclei.flag.json", "JSON format output");
        MESSAGES.put("nuclei.flag.severity", "Filter by severity (info,low,medium,high,critical)");
        MESSAGES.put("nuclei.flag.tags", "Filter by tags");
        MESSAGES.put("nuclei.flag.verbose", "Verbose output");
        MESSAGES.put("nuclei.flag.concurrency", "Template concurrency");
        MESSAGES.put("nuclei.flag.threads", "Thread count (same as --concurrency, -c takes priority)");
        MESSAGES.put("nuclei.flag.strategy", "Scan strategy (auto, template-spray, host-spray)");
        MESSAGES.put("nuclei.flag.no-color", "Disable colored output (nuclei compatible)");
        MESSAGES.put("nuclei.flag.silent", "Silent mode (show matches only)");

        MESSAGES.put("nuclei.err.no-target", "No target input provided (use -u or -l)");
        MESSAGES.put("nuclei.err.no-template", "No template input provided (use -t or -td)");
        MESSAGES.put("nuclei.err.read-target-file", "Failed to read target file: %v");
        MESSAGES.put("nuclei.err.no-valid-target", "No valid targets found");
        MESSAGES.put("nuclei.err.load-template-dir", "Failed to load templates from %s: %v");
        MESSAGES.put("nuclei.err.template-not-found", "Template path not found: %s");
        MESSAGES.put("nuclei.err.load-template", "Failed to load template %s: %v");
        MESSAGES.put("nuclei.err.no-executable", "No executable templates found");
        MESSAGES.put("nuclei.err.create-output", "Failed to create output file: %v");

        MESSAGES.put("nuclei.log.version", "Current nuclei version: v3.11.0 (latest)");
        MESSAGES.put("nuclei.log.template-version", "Current nuclei template version: v10.4.5 (latest)");
        MESSAGES.put("nuclei.log.new-templates", "New templates added in latest release: 86");
        MESSAGES.put("nuclei.log.loaded-templates", "Templates loaded for current scan: %d");
        MESSAGES.put("nuclei.log.signed-templates", "Executing %d signed templates from projectdiscovery/nuclei-templates");
        MESSAGES.put("nuclei.log.loaded-targets", "Targets loaded for current scan: %d");
        MESSAGES.put("nuclei.log.httpx-probe", "Running httpx probe on input hosts");
        MESSAGES.put("nuclei.log.httpx-found", "Found %d URLs from httpx");
        MESSAGES.put("nuclei.log.interactsh", "Using Interactsh server: oast.pro");
        MESSAGES.put("nuclei.log.clustered", "Templates clustered: %d (%d requests reduced)");

        MESSAGES.put("nuclei.summary.skipped-host", "Skipped target %s, unresponsive %d times consecutively");
        MESSAGES.put("nuclei.summary.completed-matched", "Scan completed in %s, %d matches found.");
        MESSAGES.put("nuclei.summary.completed-no-match", "Scan completed in %s, no matches found.");
        MESSAGES.put("nuclei.summary.http-conns", "HTTP connections: total %d, new %d, reused %d (%.1f%%)");
        MESSAGES.put("nuclei.summary.title", "Scan Summary (JYscan Enhanced)");
        MESSAGES.put("nuclei.summary.total-templates", "Total templates:");
        MESSAGES.put("nuclei.summary.matched", "Matched:");
        MESSAGES.put("nuclei.summary.skipped", "(skipped %d)");
        MESSAGES.put("nuclei.summary.duration", "Duration:");
        MESSAGES.put("nuclei.summary.speed", "Scan speed: %.1f templates/sec");
        MESSAGES.put("nuclei.summary.severity-dist", "[Severity Distribution]");
        MESSAGES.put("nuclei.summary.protocol-dist", "[Protocol Distribution]");
        MESSAGES.put("nuclei.summary.type-top", "[Match Type Top]");
        MESSAGES.put("nuclei.summary.match-detail", "[Match Details Top 10]");
        MESSAGES.put("nuclei.summary.more-hits", "... %d more matches not shown");
        MESSAGES.put("nuclei.summary.match-at", "(matched: %s)");
    }

    private static final String NUCLEI_LONG_EN = """
nuclei - YAML-based protocol-level vulnerability detection engine

Supported protocols: HTTP, DNS, TCP, SSL
Supported template formats: YAML, JSON

Scan strategies:
  auto           Auto-select (host-spray when more templates than targets)
  template-spray Template spray (scan all targets concurrently per template)
  host-spray     Host spray (execute all templates concurrently per target)

Multi-threading parameters:
  -c, --concurrency  Template concurrency (default: 10)
  -T, --threads      Thread count (same as --concurrency, default: 10)

Usage examples:
  # Scan single target
  jyscan nuclei -u http://example.com -t template.yaml

  # Load targets from file
  jyscan nuclei -l targets.txt -t template.yaml

  # Load templates from directory
  jyscan nuclei -u http://example.com -td ./nuclei-templates/

  # Filter by severity
  jyscan nuclei -u http://example.com -td ./templates/ -severity critical,high

  # JSON output
  jyscan nuclei -u http://example.com -t template.yaml -json -o result.json

  # Specify scan strategy
  jyscan nuclei -u http://example.com -td ./templates/ -strategy host-spray

  # Set concurrency/thread count
  jyscan nuclei -u http://example.com -td ./templates/ -c 20
  jyscan nuclei -u http://example.com -td ./templates/ --threads 50

  # Output to stdout
  jyscan nuclei -u http://example.com -t template.yaml -v""";

    private En() {
    }
}

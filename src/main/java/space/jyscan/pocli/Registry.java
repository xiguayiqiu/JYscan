package space.jyscan.pocli;

import space.jyscan.pocli.commands.AboutCommand;
import space.jyscan.pocli.commands.CrunchCommand;
import space.jyscan.pocli.commands.CuppCommand;
import space.jyscan.pocli.commands.DirscanCommand;
import space.jyscan.pocli.commands.ProcessCommand;
import space.jyscan.pocli.commands.RouteCommand;
import space.jyscan.pocli.commands.ScanCommand;
import space.jyscan.pocli.commands.SslCommand;
import space.jyscan.pocli.commands.UserinfoCommand;
import space.jyscan.pocli.commands.WafCommand;
import space.jyscan.pocli.commands.WebshellCommand;
import space.jyscan.pocli.commands.WhoisCommand;
import space.jyscan.pocli.commands.DnsCommand;
import space.jyscan.pocli.commands.CdnCommand;
import space.jyscan.pocli.commands.SubCommand;
import space.jyscan.pocli.commands.SitemapCommand;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 命令注册表，对应 Go 的 cli.CommandRegistry / BuildRegistry()。
 *
 * <p>按 Go 的分组登记命令；尚未移植的命令暂不登记，自然不会出现在自定义帮助里，
 * 后续批次补齐后在对应分组追加 {@link #register} 即可。
 */
public final class Registry {

    /** 一条注册记录：命令名 + 分组 + picocli 注解对象。 */
    public record Entry(String name, CommandGroup group, Object command) {
    }

    private static final List<Entry> ENTRIES = new ArrayList<>();
    private static final Map<String, Entry> BY_NAME = new LinkedHashMap<>();

    static {
        // ==================== 通用 ====================
        register("about", CommandGroup.GENERAL, new AboutCommand());

        // ==================== 密码 ====================
        register("crunch", CommandGroup.PASSWORD, new CrunchCommand());
        register("cupp", CommandGroup.PASSWORD, new CuppCommand());

        // ==================== 网络 ====================
        register("scan", CommandGroup.NETWORK, new ScanCommand());
        register("dirscan", CommandGroup.NETWORK, new DirscanCommand());
        register("ssl", CommandGroup.NETWORK, new SslCommand());
        register("route", CommandGroup.NETWORK, new RouteCommand());
        register("whois", CommandGroup.NETWORK, new WhoisCommand());
        register("dns", CommandGroup.NETWORK, new DnsCommand());
        register("cdn", CommandGroup.NETWORK, new CdnCommand());

        // ==================== 信息收集 ====================
        register("process", CommandGroup.INFO, new ProcessCommand());
        register("userinfo", CommandGroup.INFO, new UserinfoCommand());
        register("sub", CommandGroup.INFO, new SubCommand());
        register("sitemap", CommandGroup.INFO, new SitemapCommand());

        // ==================== Web ====================
        register("webshell", CommandGroup.WEB, new WebshellCommand());
        register("waf", CommandGroup.WEB, new WafCommand());
    }

    private Registry() {
    }

    /** 对应 r.Register(cmd, group)。 */
    public static synchronized void register(String name, CommandGroup group, Object command) {
        Entry e = new Entry(name, group, command);
        Entry old = BY_NAME.put(name, e);
        if (old != null) {
            ENTRIES.remove(old);
        }
        ENTRIES.add(e);
    }

    /** 对应 r.GetCommand(name)。 */
    public static synchronized Object getCommand(String name) {
        Entry e = BY_NAME.get(name);
        return e == null ? null : e.command();
    }

    public static synchronized boolean has(String name) {
        return BY_NAME.containsKey(name);
    }

    /** 对应 r.GetGroup(group)。 */
    public static synchronized List<Entry> getGroupEntries(CommandGroup group) {
        List<Entry> out = new ArrayList<>();
        for (Entry e : ENTRIES) {
            if (e.group() == group) {
                out.add(e);
            }
        }
        return out;
    }

    /** 对应 r.GetAllCommands()。 */
    public static synchronized List<Object> getAllCommands() {
        List<Object> out = new ArrayList<>(ENTRIES.size());
        for (Entry e : ENTRIES) {
            out.add(e.command());
        }
        return out;
    }

    public static synchronized List<Entry> entries() {
        return new ArrayList<>(ENTRIES);
    }
}

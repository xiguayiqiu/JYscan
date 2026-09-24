package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;
import space.jyscan.core.util.Colors;
import space.jyscan.modules.weakpass.WeakpassCatalog;
import space.jyscan.modules.weakpass.WeakpassClient;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * passwd 命令（JYscan 原创）：对接 weakpass.com 两套数据源 ——
 * <ul>
 *   <li>官方 API 全部13个端点（{@link WeakpassClient}）：字典列表/下载、哈希查询
 *       （search）、前缀检索（range）、规则变异生成（generate）；</li>
 *   <li>站内全目录（{@link WeakpassCatalog}）：{@code /wordlists} 分页抓取（上千条
 *       记录），{@code -l} 合并展示，{@code -d} 在 API 404 时回退站内 .7z/.gz 直链。</li>
 * </ul>
 *
 * <p>freeclient 无对应命令（其 {@code internal/weakpass} 仅为爆破模块空壳注释），
 * 本命令按 JYscan 自身惯例设计；HTTP 超时/停滞/回退策略见 {@link WeakpassClient}。
 */
@Command(
        name = "passwd",
        description = "weakpass 密码字典与哈希工具 - 列表/下载/查询/检索/生成",
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true,
        header = {
                "对接 weakpass.com：API 全部13个端点（列表/下载/查询/检索/生成）+ 站内全目录（/wordlists 分页抓取）与 .7z/.gz 直链下载。",
                "",
                "使用示例:",
                "  ./JYscan passwd -l                          # 列表：API 可直下区 + 站内全目录",
                "  ./JYscan passwd -d rockyou.txt -o dicts     # 下载字典 (GET /wordlists/{name})",
                "  ./JYscan passwd -d all-h.txt                # API 无此名→站内 .7z 直链（压缩包可达数十GB！）",
                "  ./JYscan passwd -s e10adc3949ba59abbe56e057f20f883e   # 哈希查明文 (.txt)",
                "  ./JYscan passwd -s <hash> --json            # 同上, JSON 输出 (.json 变体)",
                "  ./JYscan passwd -r e10adc                   # 前缀检索 hash:pass (range .txt)",
                "  ./JYscan passwd -r e10adc --filter pass --type ntlm   # 只要密码列/指定算法",
                "  ./JYscan passwd -g admin -o out.txt         # 预设规则变异 (GET /generate/{s})",
                "  ./JYscan passwd -g 'a/b'                    # 含斜杠自动改走 POST /generate",
                "  ./JYscan passwd -g admin --rule-file r.rule # 上传规则文件 (POST /generate/file)",
                "  ./JYscan passwd -g admin --rule-file - < r.rule       # stdin原始规则 (custom)",
                "",
                "参数说明:",
                "  -l, --list\t\t字典列表（API 可直下区 + 站内全目录）",
                "  -d, --download\t下载指定字典（逗号分隔可批量；API 无此名自动尝试站内直链）",
                "  -a, --all\t\t下载列表中的全部字典（仅 API 区）",
                "  -s, --search\t\t哈希查询明文（自动识别类型）",
                "  -r, --range\t\t按哈希前缀检索 hash:pass 对",
                "  -g, --generate\t按 hashcat 规则变异生成候选",
                "  --set\t\t\tgenerate 预设规则集（默认 online.rule）",
                "  --rule-file\t\t自定义规则文件（'-' = 标准输入）",
                "  --type\t\t\trange 哈希类型: md5|ntlm|sha1|sha256（默认 md5）",
                "  --filter\t\t\trange 输出列: hash|pass（默认 hash:pass 双列）",
                "  --json\t\t\tsearch/range/generate 以 JSON 输出",
                "  -o, --output\t\t下载模式=目录（默认当前目录）；查询/生成模式=输出文件（缺省走标准输出）",
                "  --api\t\t\tAPI 基地址（默认 weakpass.com，可指向自建镜像；站内地址=去掉 /api/v1）"
        }
)
public class PasswdCommand implements Callable<Integer> {

    /** 服务端 range 端点的 type 枚举（OpenAPI 规范）。 */
    private static final Set<String> RANGE_TYPES = Set.of("md5", "ntlm", "sha1", "sha256");

    /** 服务端 range 端点的 filter 枚举（OpenAPI 规范）。 */
    private static final Set<String> RANGE_FILTERS = Set.of("hash", "pass");

    @Option(names = {"-l", "--list"}, description = "获取密码字典列表（API 可直下区 + 站内全目录）")
    boolean list;

    @Option(names = {"-d", "--download"}, paramLabel = "<name>", split = ",",
            description = "下载指定字典（逗号分隔可批量；API 无此名自动尝试站内直链）")
    List<String> download = new ArrayList<>();

    @Option(names = {"-a", "--all"}, description = "下载列表中的全部字典（仅 API 区）")
    boolean all;

    @Option(names = {"-s", "--search"}, paramLabel = "<hash>",
            description = "哈希查询明文（自动识别类型）")
    String search;

    @Option(names = {"-r", "--range"}, paramLabel = "<prefix>",
            description = "按哈希前缀检索 hash:pass 对")
    String range;

    @Option(names = {"-g", "--generate"}, paramLabel = "<string>",
            description = "按 hashcat 规则变异生成候选")
    String generate;

    @Option(names = "--set", defaultValue = "online.rule",
            description = "generate 预设规则集（默认 ${DEFAULT-VALUE}）")
    String set;

    @Option(names = "--rule-file", paramLabel = "<path>",
            description = "自定义 hashcat 规则文件（'-' 表示从标准输入读取）")
    String ruleFile;

    @Option(names = "--type", defaultValue = "md5",
            description = "range 哈希类型: md5|ntlm|sha1|sha256（默认 ${DEFAULT-VALUE}）")
    String type;

    @Option(names = "--filter",
            description = "range 输出列: hash|pass（默认 hash:pass 双列）")
    String filter;

    @Option(names = "--json", description = "search/range/generate 以 JSON 输出")
    boolean json;

    @Option(names = {"-o", "--output"},
            description = "下载模式=目录（默认当前目录）；查询/生成模式=输出文件（缺省走标准输出）")
    String output;

    @Option(names = "--api", defaultValue = WeakpassClient.DEFAULT_BASE_URL,
            description = "API 基地址（默认 ${DEFAULT-VALUE}）")
    String api;

    @Spec
    CommandSpec spec;

    @Override
    public Integer call() {
        boolean downloads = all || (download != null && !download.isEmpty());
        boolean queries = search != null || range != null || generate != null;

        if (!list && !downloads && !queries) {
            Colors.errorPrint("请指定 -l/-d/-a/-s/-r/-g 之一（-h 查看帮助）");
            spec.commandLine().usage(System.out);
            return 1;
        }
        if (ruleFile != null && generate == null) {
            Colors.errorPrint("--rule-file 需要配合 -g/--generate 使用");
            return 1;
        }
        if (range != null && !RANGE_TYPES.contains(type)) {
            Colors.errorPrint("--type 须为 md5|ntlm|sha1|sha256，收到: %v", type);
            spec.commandLine().usage(System.out);
            return 1;
        }
        if (filter != null && !RANGE_FILTERS.contains(filter)) {
            Colors.errorPrint("--filter 须为 hash|pass，收到: %v", filter);
            spec.commandLine().usage(System.out);
            return 1;
        }
        if (output != null && queries && downloads) {
            Colors.errorPrint("-o 在下载模式表示目录、在查询/生成模式表示文件，不可混用");
            return 1;
        }

        WeakpassClient client = new WeakpassClient(api);
        int failures = 0;

        if (list) {
            failures += doList(client);
        }
        if (search != null) {
            failures += doSearch(client);
        }
        if (range != null) {
            failures += doRange(client);
        }
        if (generate != null) {
            failures += doGenerate(client);
        }
        if (downloads) {
            failures += doDownloads(client);
        }

        return failures == 0 ? 0 : 1;
    }

    // ------------------------------------------------------------------
    // 各动作
    // ------------------------------------------------------------------

    /**
     * {@code -l} 合并列表：区1 = 官方 API 列表（{@code -d/-a} 的可下载全集）；
     * 区2 = 站内全目录（分页抓取，条目为 .7z/.gz 压缩包，与 API 重叠的行标 {@code [API]}）。
     * 两区各自独立成败，任一失败 → 退出码1。
     */
    private int doList(WeakpassClient client) {
        int failures = 0;
        List<String> apiNames = List.of();

        // 区1：官方 API 列表
        try {
            apiNames = client.list();
            // 表头走 info（-q 可抑制），条目直出 stdout 便于管道
            Colors.infoPrint("[+] API 字典列表（GET /wordlists，-d 可直下）: 共 %d 个",
                    apiNames.size());
            for (String n : apiNames) {
                System.out.println(n);
            }
        } catch (WeakpassClient.ApiException e) {
            Colors.errorPrint("%v", e.getMessage());
            failures++;
        } catch (IOException e) {
            Colors.errorPrint("获取字典列表失败: %v", e.getMessage());
            failures++;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Colors.errorPrint("获取字典列表被中断");
            failures++;
        }

        // 区2：站内全目录（Inertia 分页抓取，全量约10秒）
        try {
            WeakpassCatalog catalog =
                    new WeakpassCatalog(WeakpassCatalog.siteRootOf(api), client);
            List<WeakpassCatalog.Entry> entries = catalog.fetchAll();
            Set<String> apiSet = new HashSet<>(apiNames);
            Colors.infoPrint("[+] 站内全目录（/wordlists 分页抓取）: 共 %d 条"
                    + "（.7z/.gz 压缩包+种子，-d 走直链）", entries.size());
            System.out.printf(Locale.ROOT, "%-44s %10s %12s%n", "NAME", "SIZE", "COUNT");
            for (WeakpassCatalog.Entry e : entries) {
                System.out.printf(Locale.ROOT, "%-44s %10s %12d%s%n",
                        e.name(), humanSize(e.size()), e.count(),
                        apiSet.contains(e.name()) ? "  [API]" : "");
            }
        } catch (IOException e) {
            Colors.errorPrint("站内目录获取失败: %v", e.getMessage());
            failures++;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Colors.errorPrint("站内目录获取被中断");
            failures++;
        }
        return failures;
    }

    private int doSearch(WeakpassClient client) {
        return withSink("[+] 查询结果 %d 字节 → %s", out -> {
            byte[] body = client.search(search, json).getBytes(StandardCharsets.UTF_8);
            out.write(body);
            if (body.length == 0 || body[body.length - 1] != '\n') {
                out.write('\n');
            }
            return body.length;
        });
    }

    private int doRange(WeakpassClient client) {
        return withSink("[+] 前缀检索完成: %d 字节 → %s",
                out -> client.range(range, type, filter, json, out));
    }

    private int doGenerate(WeakpassClient client) {
        return withSink("[+] 生成完成: %d 字节 → %s",
                out -> client.generate(generate, set, ruleFile, json, out, System.in));
    }

    private int doDownloads(WeakpassClient client) {
        LinkedHashSet<String> names = new LinkedHashSet<>();
        if (download != null) {
            for (String d : download) {
                if (d != null && !d.isBlank()) {
                    names.add(d.trim());
                }
            }
        }
        int failures = 0;
        if (all) {
            try {
                names.addAll(client.list());
            } catch (WeakpassClient.ApiException e) {
                Colors.errorPrint("获取字典列表失败: %v", e.getMessage());
                failures++;
            } catch (IOException e) {
                Colors.errorPrint("获取字典列表失败: %v", e.getMessage());
                failures++;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                Colors.errorPrint("获取字典列表被中断");
                failures++;
            }
        }
        if (names.isEmpty()) {
            return failures;
        }

        String dirName = output == null ? "." : output;
        Path dir = Paths.get(dirName);
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            Colors.errorPrint("创建目录失败: %v", e.getMessage());
            return failures + names.size();
        }

        int done = 0;
        for (String name : names) {
            // 先校验名字（防 ../ 穿越出输出目录），再解析目标路径
            try {
                WeakpassClient.requireSafeName(name);
            } catch (IOException e) {
                Colors.errorPrint("%v", e.getMessage());
                failures++;
                continue;
            }
            Path target = dir.resolve(name);

            Colors.infoPrint("[*] 下载中: %s", name);
            long t0 = System.nanoTime();
            try {
                long bytes = client.download(name, target);
                long millis = (System.nanoTime() - t0) / 1_000_000L;
                done++;
                Colors.successPrint("[+] 下载完成: %s → %s (%s, %s)",
                        name, target, humanSize(bytes), humanMillis(millis));
            } catch (WeakpassClient.ApiException e) {
                if (e.status() == 404) {
                    // API 无此名 → 回退站内目录 .7z/.gz 直链
                    int r = catalogDownload(client, dir, name);
                    if (r == 1) {
                        done++;
                    } else if (r == 0) {
                        Colors.errorPrint("字典不存在: %s（API 与站内目录均无此名，用 -l 查看）",
                                name);
                        deleteQuietly(target);
                        failures++;
                    } else {
                        deleteQuietly(target);
                        failures++;
                    }
                } else {
                    Colors.errorPrint("%s: %v", name, e.getMessage());
                    deleteQuietly(target);
                    failures++;
                }
            } catch (IOException e) {
                Colors.errorPrint("%s: %v", name, e.getMessage());
                deleteQuietly(target);
                failures++;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                deleteQuietly(target);
                failures++;
                break;
            }
        }
        if (done > 0) {
            Colors.infoPrint("[*] 本次成功下载 %d 个字典 → %s", done, dir);
        }
        return failures;
    }

    /**
     * API 404 后的站内目录回退：抓全目录找名字 → {@code /download/{id}/{link}
     * →302→ CDN} 直链下载压缩包（落盘名 = download_link，如 {@code all-h.txt.7z}）。
     *
     * @return 1=已下载；0=站内目录也没有此名；2=抓取/下载失败（已报错并清理）
     */
    private int catalogDownload(WeakpassClient client, Path dir, String name) {
        Path target = null;
        try {
            WeakpassCatalog catalog =
                    new WeakpassCatalog(WeakpassCatalog.siteRootOf(api), client);
            WeakpassCatalog.Entry e = WeakpassCatalog.find(catalog.fetchAll(), name);
            if (e == null) {
                return 0;
            }
            WeakpassClient.requireSafeName(e.downloadLink());
            target = dir.resolve(e.downloadLink());
            Colors.infoPrint("[*] 站内直链下载: %s（原始 %s / 压缩包 %s）→ %s",
                    e.name(), humanSize(e.size()), e.downloadLink(), target);
            long t0 = System.nanoTime();
            long bytes;
            try (OutputStream os = Files.newOutputStream(target)) {
                bytes = catalog.download(e, os);
            }
            long millis = (System.nanoTime() - t0) / 1_000_000L;
            Colors.successPrint("[+] 站内下载完成: %s → %s (%s, %s)",
                    e.downloadLink(), target, humanSize(bytes), humanMillis(millis));
            return 1;
        } catch (WeakpassClient.ApiException e) {
            Colors.errorPrint("%s: %v", name, e.getMessage());
        } catch (IOException e) {
            Colors.errorPrint("%s: %v", name, e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Colors.errorPrint("%s: 下载被中断", name);
        }
        if (target != null) {
            deleteQuietly(target);
        }
        return 2;
    }

    // ------------------------------------------------------------------
    // 输出槽与工具
    // ------------------------------------------------------------------

    /** 可抛受检异常的动作（在输出槽内执行）。 */
    @FunctionalInterface
    private interface SinkRun {
        long run(OutputStream out) throws IOException, InterruptedException;
    }

    /**
     * 统一输出槽：{@code -o} 有值 → 写文件（完成后打摘要）；否则写标准输出
     * （纯数据不打摘要，以免污染管道）。异常统一翻译成错误行 + 退出码 1。
     */
    private int withSink(String doneFmt, SinkRun action) {
        boolean toFile = output != null;
        OutputStream sink = System.out;
        boolean opened = false;
        try {
            if (toFile) {
                Path p = Paths.get(output);
                if (p.getParent() != null) {
                    Files.createDirectories(p.getParent());
                }
                sink = Files.newOutputStream(p);
                opened = true;
            }
            long n = action.run(sink);
            if (toFile) {
                Colors.infoPrint(doneFmt, n, output);
            }
            return 0;
        } catch (WeakpassClient.ApiException e) {
            Colors.errorPrint("%v", e.getMessage());
            return 1;
        } catch (IOException e) {
            Colors.errorPrint("%v", e.getMessage());
            return 1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Colors.errorPrint("操作被中断");
            return 1;
        } finally {
            if (opened) {
                try {
                    sink.close();
                } catch (IOException ignored) {
                    // 关闭失败不覆盖主结果
                }
            }
        }
    }

    /** 失败/中断后清理半成品文件。 */
    private static void deleteQuietly(Path p) {
        try {
            Files.deleteIfExists(p);
        } catch (IOException ignored) {
            // 清理失败不覆盖主错误
        }
    }

    /** 人类可读大小（B/KB/MB/GB）。 */
    static String humanSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        double kb = bytes / 1024.0;
        if (kb < 1024) {
            return String.format(Locale.ROOT, "%.1f KB", kb);
        }
        double mb = kb / 1024.0;
        if (mb < 1024) {
            return String.format(Locale.ROOT, "%.1f MB", mb);
        }
        return String.format(Locale.ROOT, "%.2f GB", mb / 1024.0);
    }

    /** 人类可读耗时（ms/s）。 */
    static String humanMillis(long millis) {
        if (millis < 1000) {
            return millis + "ms";
        }
        return String.format(Locale.ROOT, "%.1fs", millis / 1000.0);
    }
}

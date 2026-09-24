package space.jyscan.pocli.commands;

import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;
import space.jyscan.core.util.Colors;
import space.jyscan.modules.weakpass.WeakpassClient;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;

/**
 * passwd 命令（JYscan 原创）：通过 weakpass.com API 获取密码字典列表、下载字典。
 *
 * <p>freeclient 无对应命令（其 {@code internal/weakpass} 仅为爆破模块空壳注释），
 * 因此本命令按 JYscan 自身惯例设计；HTTP 层超时/停滞防护见 {@link WeakpassClient}。
 */
@Command(
        name = "passwd",
        description = "密码字典获取工具 - weakpass 字典列表与下载",
        synopsisHeading = "%n",
        sortOptions = false,
        mixinStandardHelpOptions = true,
        header = {
                "通过 weakpass.com API 获取密码字典列表、下载密码字典。",
                "",
                "使用示例:",
                "  ./JYscan passwd -l                        # 获取字典列表",
                "  ./JYscan passwd -d rockyou.txt            # 下载指定字典到当前目录",
                "  ./JYscan passwd -d ignis-10K.txt -o dicts # 下载到指定目录",
                "  ./JYscan passwd -d a.txt,b.txt            # 逗号分隔批量下载",
                "  ./JYscan passwd --all -o dicts            # 下载列表中的全部字典",
                "",
                "参数说明:",
                "  -l, --list\t\t获取密码字典列表",
                "  -d, --download\t下载指定字典（逗号分隔可批量）",
                "  -a, --all\t\t下载列表中的全部字典",
                "  -o, --output\t\t下载目录（默认当前目录）",
                "  --api\t\t\tAPI 基地址（默认 weakpass.com，可指向自建镜像）"
        }
)
public class PasswdCommand implements Callable<Integer> {

    @Option(names = {"-l", "--list"}, description = "获取密码字典列表")
    boolean list;

    @Option(names = {"-d", "--download"}, paramLabel = "<name>", split = ",",
            description = "下载指定字典（逗号分隔可批量）")
    List<String> download = new ArrayList<>();

    @Option(names = {"-a", "--all"}, description = "下载列表中的全部字典")
    boolean all;

    @Option(names = {"-o", "--output"}, defaultValue = ".", description = "下载目录（默认当前目录）")
    String output;

    @Option(names = {"--api"}, defaultValue = WeakpassClient.DEFAULT_BASE_URL,
            description = "API 基地址（默认 ${DEFAULT-VALUE}）")
    String api;

    @Spec
    CommandSpec spec;

    @Override
    public Integer call() {
        if (!list && (download == null || download.isEmpty()) && !all) {
            Colors.errorPrint("请指定 -l 获取字典列表，或 -d/--all 下载字典");
            spec.commandLine().usage(System.out);
            return 1;
        }

        WeakpassClient client = new WeakpassClient(api);
        int failures = 0;

        // ---- 列表 ----
        if (list) {
            try {
                List<String> names = client.list();
                // 表头走 info（-q 可抑制），条目直出 stdout 便于管道
                Colors.infoPrint("[+] 密码字典列表（来源 weakpass.com）: 共 %d 个", names.size());
                for (String n : names) {
                    System.out.println(n);
                }
            } catch (WeakpassClient.ApiException e) {
                Colors.errorPrint("获取字典列表失败: HTTP %d: %v", e.status(), e.getMessage());
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

        // ---- 下载集：-d 展开 + -a 取全量（LinkedHashSet 去重且保序）----
        LinkedHashSet<String> names = new LinkedHashSet<>();
        if (download != null) {
            for (String d : download) {
                if (d != null && !d.isBlank()) {
                    names.add(d.trim());
                }
            }
        }
        if (all) {
            try {
                names.addAll(client.list());
            } catch (WeakpassClient.ApiException e) {
                Colors.errorPrint("获取字典列表失败: HTTP %d: %v", e.status(), e.getMessage());
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

        if (!names.isEmpty()) {
            failures += downloadAll(client, names);
        }

        return failures == 0 ? 0 : 1;
    }

    /** 逐个下载（顺序执行）；返回失败个数。 */
    private int downloadAll(WeakpassClient client, LinkedHashSet<String> names) {
        Path dir = Paths.get(output);
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            Colors.errorPrint("创建目录失败: %v", e.getMessage());
            return names.size();
        }

        int failures = 0;
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
                    Colors.errorPrint("字典不存在: %s（用 -l 查看可用列表）", name);
                } else {
                    Colors.errorPrint("下载失败: %s: HTTP %d", name, e.status());
                }
                deleteQuietly(target);
                failures++;
            } catch (IOException e) {
                Colors.errorPrint("下载失败: %s: %v", name, e.getMessage());
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

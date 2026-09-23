package space.jyscan.modules.crunch;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 多线程密码字典生成器，移植自 freeclient/internal/cli/crunch.go 的
 * generatePasswordsWithThreads 与 numberToPassword。
 *
 * <p>字符集按 UTF-8 字节处理，与 Go 的 {@code len(charset)} / {@code charset[i]}
 * 字节语义逐字节一致。
 */
public final class CrunchGenerator {

    private CrunchGenerator() {
    }

    /**
     * 使用多线程生成密码（移植 Go 的 generatePasswordsWithThreads）。
     *
     * <p>按长度分配任务：对每个长度把下标区间 {@code [0, count)} 切成 threads 份，
     * 余数分给前 remainder 个线程（每个多一个）。每个任务自带 1MB 缓冲区，
     * 每次刷写都在互斥锁下进行，保证所有密码恰好各写一次。
     *
     * @param out      输出文件（调用方负责打开与关闭）
     * @param charset  字符集的 UTF-8 字节
     * @param minLen   密码最小长度
     * @param maxLen   密码最大长度
     * @param threads  线程数（调用方已保证 >= 1）
     * @return 实际生成的密码数量
     * @throws Exception 任一任务写文件失败时抛出（对应 Go 的 "生成密码失败: %v"）
     */
    public static long generatePasswordsWithThreads(OutputStream out, byte[] charset,
                                                    int minLen, int maxLen, int threads) throws Exception {
        AtomicLong totalCount = new AtomicLong(0);
        Object mu = new Object(); // 用于保护文件写入

        // 工作线程设为守护线程：即使个别任务出错退出，也不会阻塞 JVM 结束
        ThreadFactory factory = r -> {
            Thread t = new Thread(r, "crunch-worker");
            t.setDaemon(true);
            return t;
        };
        ExecutorService pool = Executors.newFixedThreadPool(threads, factory);
        boolean completed = false;
        try {
            List<Future<?>> futures = new ArrayList<>();

            // 按长度分配任务
            for (int length = minLen; length <= maxLen; length++) {
                final int len = length;
                // 计算此长度下的总密码数
                long countForLength = (long) Math.pow(charset.length, (double) length);

                // 确定每个线程处理的密码数量
                long passwordsPerThread = countForLength / threads;
                long remainder = countForLength % threads;

                // 为每个线程创建任务
                for (int threadID = 0; threadID < threads; threadID++) {
                    final int id = threadID;

                    // 计算此线程的起始和结束位置：
                    // start 要加上前面线程分到的余数（余数给前 remainder 个线程），
                    // 这样 [0, count) 被不重不漏地切分
                    long start = (long) id * passwordsPerThread + Math.min((long) id, remainder);
                    long end = start + passwordsPerThread + (id < remainder ? 1 : 0);

                    // 确保不会超出范围
                    if (start >= countForLength) {
                        continue;
                    }
                    if (end > countForLength) {
                        end = countForLength;
                    }
                    final long taskStart = start;
                    final long taskEnd = end;

                    futures.add(pool.submit(() -> {
                        // 为每个线程创建一个缓冲区
                        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                        long localCount = 0;

                        // 生成此范围内的密码
                        for (long i = taskStart; i < taskEnd; i++) {
                            if (Thread.currentThread().isInterrupted()) {
                                // 被中断（其他任务出错后取消），提前退出
                                break;
                            }
                            // 将数字转换为密码
                            byte[] password = numberToPassword(i, charset, len);
                            buffer.write(password, 0, password.length);
                            buffer.write('\n');
                            localCount++;

                            // 当缓冲区达到一定大小时，写入文件
                            if (buffer.size() >= 1024 * 1024) { // 1MB
                                synchronized (mu) {
                                    out.write(buffer.toByteArray());
                                }
                                buffer.reset(); // 清空缓冲区
                            }
                        }

                        // 写入剩余的缓冲区内容
                        if (buffer.size() > 0) {
                            synchronized (mu) {
                                out.write(buffer.toByteArray());
                            }
                        }

                        // 更新总计数
                        totalCount.addAndGet(localCount);
                        return null;
                    }));
                }
            }

            // 等待所有线程完成
            for (Future<?> future : futures) {
                try {
                    future.get();
                } catch (ExecutionException e) {
                    // 抛出任务里的原始异常，让上层打印 "生成密码失败: %v"
                    Throwable cause = e.getCause();
                    if (cause instanceof Exception ex) {
                        throw ex;
                    }
                    if (cause instanceof Error err) {
                        throw err;
                    }
                    throw e;
                }
            }
            completed = true;
        } finally {
            if (completed) {
                pool.shutdown();
            } else {
                pool.shutdownNow(); // 出错时取消剩余任务
            }
        }

        return totalCount.get();
    }

    /**
     * 将数字转换为密码（移植 Go 的 numberToPassword）：
     * 把数字看作 charsetLen 进制数，从右向左填充；
     * 位数不足 length 时左侧补 charset[0]，保证输出始终是 length 个字符。
     */
    public static byte[] numberToPassword(long num, byte[] charset, int length) {
        byte[] password = new byte[length];
        long charsetLen = charset.length;

        // 从右到左填充密码字符
        for (int i = length - 1; i >= 0; i--) {
            long charIndex = num % charsetLen;
            password[i] = charset[(int) charIndex];
            num = num / charsetLen;
        }

        return password;
    }

    /** 关闭资源并忽略错误（对应 Go 的 {@code defer file.Close()}）。 */
    public static void closeQuietly(OutputStream out) {
        try {
            out.close();
        } catch (IOException ignored) {
            // Go 的 defer file.Close() 同样忽略关闭错误
        }
    }
}

package space.jyscan.modules.crunch;

import space.jyscan.core.util.Fmt;

/**
 * crunch 命令的预估计算，移植自 freeclient/internal/cli/crunch.go。
 *
 * <p>包含 Go 源码中的三个纯函数：calculatePasswordCount / calculateFileSize /
 * formatFileSize，全部按 Go 的 uint64 语义实现（乘法自然回绕、按无符号比较）。
 */
public final class CrunchEstimator {

    private CrunchEstimator() {
    }

    /**
     * 计算预估的密码数量（移植 Go 的 calculatePasswordCount）。
     *
     * @return uint64 语义的密码总数；单个长度的 math.Pow 溢出时饱和为 2^64-1
     */
    public static long calculatePasswordCount(int minLen, int maxLen, int charsetLen) {
        long total = 0;
        for (int length = minLen; length <= maxLen; length++) {
            // 计算每个长度的密码数量：charsetLen^length
            double count = Math.pow((double) charsetLen, (double) length);
            if (count > 0x1p64) { // Go: count > float64(math.MaxUint64)（即 2^64）
                return 0xFFFFFFFFL; // 溢出
            }
            total += (long) count; // Go 的 uint64 加法自然回绕，Java long 同样回绕
        }
        return total;
    }

    /**
     * 计算预估的文件大小（基于平均密码长度），移植 Go 的 calculateFileSize。
     */
    public static long calculateFileSize(long passwordCount, int minLen, int maxLen) {
        // 计算平均密码长度（用 long 求和，避免 Java int 溢出；正值下与 Go 的 64 位 int 一致）
        long averageLength = ((long) minLen + (long) maxLen) / 2;
        // 每个密码后面加一个换行符，假设UTF-8编码（uint64 乘法回绕，Java long 同样回绕）
        return passwordCount * (averageLength + 1);
    }

    /**
     * 格式化文件大小显示，移植 Go 的 formatFileSize。
     *
     * <p>阈值与 Go 相同：字节 / KB / MB / GB / TB / PB，按 1024 的幂分级，小数保留两位。
     * 因 Go 参数是 uint64，这里一律按无符号语义比较与换算。
     */
    public static String formatFileSize(long size) {
        if (Long.compareUnsigned(size, 1024L) < 0) {
            // 走到该分支说明无符号值 < 1024，一定是小的正数，可直接 %d
            return Fmt.format("%d 字节", size);
        } else if (Long.compareUnsigned(size, 1024L * 1024L) < 0) {
            return Fmt.format("%.2f KB", unsignedToDouble(size) / 1024.0);
        } else if (Long.compareUnsigned(size, 1024L * 1024L * 1024L) < 0) {
            return Fmt.format("%.2f MB", unsignedToDouble(size) / (1024.0 * 1024.0));
        } else if (Long.compareUnsigned(size, 1024L * 1024L * 1024L * 1024L) < 0) {
            return Fmt.format("%.2f GB", unsignedToDouble(size) / (1024.0 * 1024.0 * 1024.0));
        } else if (Long.compareUnsigned(size, 1024L * 1024L * 1024L * 1024L * 1024L) < 0) {
            return Fmt.format("%.2f TB", unsignedToDouble(size) / (1024.0 * 1024.0 * 1024.0 * 1024.0));
        } else {
            return Fmt.format("%.2f PB", unsignedToDouble(size)
                    / (1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0));
        }
    }

    /** uint64 转 double：最高位为 1 时按无符号拆位换算，避免变成负数。 */
    private static double unsignedToDouble(long v) {
        if (v >= 0) {
            return (double) v;
        }
        return (double) (v >>> 1) * 2.0 + (double) (v & 1L);
    }
}

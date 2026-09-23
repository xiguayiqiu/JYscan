package space.jyscan.modules.dns;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;

/**
 * 域名过滤器，移植自 freeclient/internal/dns/filter.go。
 *
 * <p>{@code Match} 的语义与 Go 一致：返回 {@code true} 表示该域名应该被记录。
 * <ul>
 *   <li>disabled → 恒 true；</li>
 *   <li>未初始化或无规则 → 白名单 false、黑名单 true；</li>
 *   <li>白名单 → 只放行命中规则的域名；黑名单 → 排除命中规则的域名。</li>
 * </ul>
 */
public final class DomainFilter {

    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private FilterMode mode;
    private final List<FilterRule> rules = new ArrayList<>();
    private final List<Pattern> compiled = new ArrayList<>();
    private boolean initialized;

    public DomainFilter(FilterMode mode, List<FilterRule> rules) {
        this.mode = mode == null ? FilterMode.DISABLED : mode;
        if (rules != null) {
            this.rules.addAll(rules);
        }
        compile();
    }

    /** 把通配符模式转换为正则表达式，对应 Go 的 {@code wildcardToRegex}。 */
    static String wildcardToRegex(String pattern) {
        StringBuilder sb = new StringBuilder("^");
        for (int i = 0; i < pattern.length(); ) {
            int cp = pattern.codePointAt(i);
            i += Character.charCount(cp);
            char ch = (char) cp;
            switch (ch) {
                case '*' -> sb.append(".*");
                case '?' -> sb.append('.');
                case '.' -> sb.append("\\.");
                default -> {
                    if ("\\+()^$[]{}|".indexOf(ch) >= 0) {
                        sb.append('\\');
                    }
                    sb.appendCodePoint(cp);
                }
            }
        }
        sb.append("$");
        return sb.toString();
    }

    /** 编译所有规则，对应 Go 的 {@code (*Filter).compile}。 */
    private void compile() {
        lock.writeLock().lock();
        try {
            compiled.clear();
            for (FilterRule rule : rules) {
                String pattern = rule.regex ? rule.pattern : wildcardToRegex(rule.pattern);
                try {
                    compiled.add(Pattern.compile(pattern));
                } catch (Exception ignored) {
                    // Go: regexp.Compile 出错时丢弃该规则（f.compiled 不追加）
                }
            }
            initialized = true;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 添加过滤规则，对应 Go 的 {@code AddRule}。 */
    public void addRule(FilterRule rule) {
        lock.writeLock().lock();
        try {
            rules.add(rule);
            String pattern = rule.regex ? rule.pattern : wildcardToRegex(rule.pattern);
            try {
                compiled.add(Pattern.compile(pattern));
            } catch (Exception ignored) {
                // 与 Go 一致：编译失败的规则不进入 compiled，但保留在 rules 里
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * 移除过滤规则，对应 Go 的 {@code RemoveRule}。
     *
     * <p>与 Go 的实现细节保持一致：按下标在 rules / compiled 上同时删除。
     * 注意 Go 只遍历 rules 找首个匹配，因此 compiled 中可能因历史编译失败而错位 ——
     * 这一行为在本实现里同样被复现（按 rules 下标去删 compiled 同下标元素）。
     */
    public void removeRule(String pattern) {
        lock.writeLock().lock();
        try {
            for (int i = 0; i < rules.size(); i++) {
                if (rules.get(i).pattern.equals(pattern)) {
                    rules.remove(i);
                    if (i < compiled.size()) {
                        compiled.remove(i);
                    }
                    break;
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 设置过滤模式，对应 Go 的 {@code SetMode}。 */
    public void setMode(FilterMode mode) {
        lock.writeLock().lock();
        try {
            this.mode = mode;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 当前过滤模式，对应 Go 的 {@code Mode}。 */
    public FilterMode mode() {
        lock.readLock().lock();
        try {
            return mode;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * 域名是否应该被记录，对应 Go 的 {@code Match}。
     *
     * @return {@code true} 表示记录该域名
     */
    public boolean match(String domain) {
        lock.readLock().lock();
        try {
            if (mode == FilterMode.DISABLED) {
                return true;
            }

            if (!initialized || compiled.isEmpty()) {
                return mode != FilterMode.WHITELIST;
            }

            boolean matched = false;
            for (Pattern p : compiled) {
                if (p.matcher(domain == null ? "" : domain).find()) {
                    matched = true;
                    break;
                }
            }

            return switch (mode) {
                case WHITELIST -> matched;
                case BLACKLIST -> !matched;
                case DISABLED -> true;
            };
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 规则数量，对应 Go 的 {@code RulesCount}。 */
    public int rulesCount() {
        lock.readLock().lock();
        try {
            return rules.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 过滤器是否为空，对应 Go 的 {@code IsEmpty}。 */
    public boolean isEmpty() {
        return rulesCount() == 0;
    }
}

package space.jyscan.modules.nuclei.model;

import java.util.List;

/**
 * 所有协议请求的通用接口，对应 Go 的 {@code model.Request} interface。
 *
 * <p>Go 侧在 {@code interface.go} 末尾用 {@code var _ Request = (*HTTPRequest)(nil)} 等
 * 8 条编译期断言保证每个请求类型都实现本接口；Java 由 {@link HTTPRequest} 等
 * 8 个实现类的 {@code implements} 声明承担同一职责。
 */
public interface Request {

    /** 获取匹配器列表，对应 Go 的 {@code GetMatchers() []*Matcher}。 */
    List<Matcher> getMatchers();

    /** 获取提取器列表，对应 Go 的 {@code GetExtractors() []*Extractor}。 */
    List<Extractor> getExtractors();

    /**
     * 获取匹配器条件（and/or），对应 Go 的 {@code GetMatchersCondition() string}。
     *
     * <p>注意 Go 的 {@code CodeRequest} 实现直接返回 {@code ""} 而非自身字段，
     * 因为 {@code CodeRequest} 结构体没有 {@code MatchersCondition} 字段。
     */
    String getMatchersCondition();
}

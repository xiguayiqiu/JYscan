package space.jyscan.modules.nuclei.model;

/**
 * 模板协议类型，对应 Go 的 {@code model.templateTypes}（小写开头，Go 侧为包内私有）。
 *
 * <p>本枚举保持包内可见（无 {@code public}），与 Go 的可见性一致；
 * {@link #label()} 对应 Go 的 {@code (t templateTypes) String()}。
 * 仅 {@link TemplateIndex#types} 引用，故不对外暴露。
 */
enum TemplateType {

    /** {@code TypeHTTP}，iota 序号 0。 */
    HTTP("http"),
    /** {@code TypeDNS}，iota 序号 1。 */
    DNS("dns"),
    /** {@code TypeTCP}，iota 序号 2。 */
    TCP("tcp"),
    /** {@code TypeSSL}，iota 序号 3。 */
    SSL("ssl"),
    /** {@code TypeWebSocket}，iota 序号 4。 */
    WEBSOCKET("websocket"),
    /** {@code TypeWhois}，iota 序号 5。 */
    WHOIS("whois"),
    /** {@code TypeFile}，iota 序号 6。 */
    FILE("file"),
    /** {@code TypeCode}，iota 序号 7。 */
    CODE("code"),
    /** {@code TypeHeadless}，iota 序号 8。 */
    HEADLESS("headless");

    private final String label;

    TemplateType(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    @Override
    public String toString() {
        return label;
    }
}

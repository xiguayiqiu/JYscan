package space.jyscan.modules.nuclei.protocol;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * 跳过全部证书校验的 {@link SSLContext}（懒加载 + 进程内共享）。
 *
 * <p>对应 Go 各处的 {@code &tls.Config{InsecureSkipVerify: true}}
 * （{@code protocol.go} 中 {@code NewHTTPExecutor}/{@code buildRedirectClient}/
 * {@code SSLExecutor.Execute} 三处）。包内私有，仅供本包执行器使用。
 */
final class TrustAll {

    /** 懒加载缓存，避免每次执行器构造都重复初始化。 */
    private static volatile SSLContext cached;

    private TrustAll() {
    }

    /** 返回信任全部证书的 {@link SSLContext}。 */
    static SSLContext context() {
        SSLContext ctx = cached;
        if (ctx == null) {
            synchronized (TrustAll.class) {
                ctx = cached;
                if (ctx == null) {
                    ctx = create();
                    cached = ctx;
                }
            }
        }
        return ctx;
    }

    private static SSLContext create() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    // InsecureSkipVerify 等价：不校验
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // InsecureSkipVerify 等价：不校验
                }
            }}, new SecureRandom());
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("初始化信任全部证书的 SSLContext 失败", e);
        }
    }
}

package space.jyscan.modules.nuclei.protocol;

import space.jyscan.modules.nuclei.model.TCPRequest;
import space.jyscan.modules.nuclei.variable.Engine;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * TCP 协议执行器，对应 Go 的 {@code protocol.TCPExecutor}。
 *
 * <p>跨包契约：runner 持有字段 {@code tcpExec} 并调用
 * {@link #execute(TCPRequest, String, Map)}。
 *
 * <p>Go 侧 {@code NewTCPExecutor()} 构造 {@code variable.NewEngine()} 作为 {@code varEngine}；
 * {@code Execute} 中 {@code host} 取 target，{@code port} 缺省 {@code "80"}、
 * 取 {@code req.Ports} 首项（经 {@code strings.TrimSpace}）。
 *
 * <p>Java 侧技术映射：
 * <ul>
 *   <li>Go {@code net.DialTimeout("tcp", addr, 10s)} → {@code Socket.connect(..., 10s)}；</li>
 *   <li>Go {@code SetWriteDeadline(now+5s)} → Java 无写超时对应项（已知偏差），仅写失败报错；</li>
 *   <li>Go {@code SetReadDeadline(now+5s)} → {@code Socket.setSoTimeout(5s)}；
 *       读失败/超时按 Go {@code n, _ := conn.Read(...)} 忽略，{@code raw} 为空串；</li>
 *   <li>Go {@code make([]byte, 4096) + Read(buf[:readSize])} → 单次读入
 *       {@code byte[readSize]}（{@code readSize <= 0} 取 4096）。
 *       已知偏差：Go 侧 {@code readSize > 4096} 会 panic（切片越界），Java 侧直接按 {@code readSize} 分配。</li>
 * </ul>
 *
 * <p>移植自 {@code freeclient/pkg/nuclei/protocol/protocol.go}。
 */
public class TCPExecutor {

    /** 对应 Go 的 {@code NewTCPExecutor() *TCPExecutor}。 */
    public TCPExecutor() {
        this.varEngine = new Engine();
    }

    private final Engine varEngine;

    /**
     * 执行一次 TCP 交互。
     *
     * <p>对应 Go 的 {@code (e *TCPExecutor) Execute(req *model.TCPRequest, target string, vars map[string]interface{}) *ProtocolResult}。
     * 错误按 Go 的方式放在 {@link ProtocolResult#error} 字段内。
     */
    public ProtocolResult execute(TCPRequest req, String target, Map<String, Object> vars) {
        long start = System.nanoTime();

        String host = target;
        String port = "80"; // Go: port := "80"
        if (req.ports != null && !req.ports.isEmpty()) {
            String first = req.ports.get(0);
            port = first == null ? "" : first.trim(); // Go: strings.TrimSpace(req.Ports[0])
        }
        if (req.host != null && !req.host.isEmpty()) {
            String first = req.host.get(0);
            host = varEngine.render(first == null ? "" : first, vars);
        }

        byte[] data = new byte[0];
        if (req.data != null && !req.data.isEmpty()) {
            data = req.data.getBytes(StandardCharsets.UTF_8);
        } else if (req.inputs != null && !req.inputs.isEmpty()) {
            String first = req.inputs.get(0);
            data = varEngine.render(first == null ? "" : first, vars).getBytes(StandardCharsets.UTF_8);
        }

        int portNum;
        try {
            portNum = Integer.parseInt(port);
        } catch (NumberFormatException e) {
            // Go: net.Dial 对非法端口返回 err
            return ProtocolResult.failure("tcp", e, start);
        }

        try (Socket conn = new Socket()) {
            try {
                // Go: net.DialTimeout("tcp", addr, 10*time.Second)
                conn.connect(new InetSocketAddress(host, portNum), 10_000);
            } catch (IOException e) {
                return ProtocolResult.failure("tcp", e, start);
            }

            if (data.length > 0) {
                try {
                    // Go: conn.SetWriteDeadline(now+5s); conn.Write([]byte(data))
                    OutputStream out = conn.getOutputStream();
                    out.write(data);
                    out.flush();
                } catch (IOException e) {
                    return ProtocolResult.failure("tcp", e, start);
                }
            }

            String raw = "";
            try {
                // Go: conn.SetReadDeadline(now+5s)
                conn.setSoTimeout(5_000);
                int readSize = req.readSize;
                if (readSize <= 0) {
                    readSize = 4096;
                }
                byte[] buf = new byte[readSize];
                InputStream in = conn.getInputStream();
                int n = in.read(buf);
                if (n > 0) {
                    raw = new String(buf, 0, n, StandardCharsets.UTF_8);
                }
            } catch (IOException e) {
                // Go: n, _ := conn.Read(buf[:readSize]) —— 读错误（含超时）被忽略，raw 保持空串
                raw = "";
            }

            Map<String, Object> resultData = new LinkedHashMap<>();
            resultData.put("host", host);
            resultData.put("matched", host);
            resultData.put("port", port);
            resultData.put("raw", raw);
            resultData.put("body", raw);
            resultData.put("all", raw);
            return ProtocolResult.success("tcp", resultData, raw, start);
        } catch (IOException e) {
            return ProtocolResult.failure("tcp", e, start);
        }
    }
}

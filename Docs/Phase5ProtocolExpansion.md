# Phase 5：协议与兼容性扩展计划

> **给 Hermes 的指示：** 仅在用户接受本计划后实施；如果用户需要常规的阶段门控，则在本文件单独提交之后实施。不要把实现混入计划提交。不要执行 `git reset` / `git clean`。本阶段不得触碰 SbieDrv / SbieSvc / WFP。

**目标：** 扩展 Phase 4 的 HTTPS broker，使其在 HTTP/1.1 之外还能检查 **HTTP/2**（含 HPACK）、隧道并记录 **WebSocket**（基于 HTTP/1.1）、记录 **gRPC** 流帧；新增 **Firefox/NSS 信任**、面向证书固定应用的**可选 TLS key-log 导出**，并产出一份书面 **QUIC/HTTP/3 评估**（不承诺实现）。退出标准：选定沙箱内的代表性 `curl --http2`、Chromium h2 客户端与 gRPC 客户端被解码进 HAR（gRPC 只记元数据 + trailers，不解 protobuf）；WebSocket 握手被记录并隧道转发；boxed Firefox 在 opt-in 后信任会话 CA；`SSLKEYLOGFILE` 可在 Wireshark 中解密捕获的 PCAPNG。

**架构：** Phase 5 的全部工作都在 `SbieCapture.exe` 及其用户态测试套件中。SbieDrv、SbieSvc、LPC 线格式与 WFP 重定向路径均不变。broker 的 ALPN 回调在 `http/1.1` 之外同时通告 `h2`。新的 HTTP/2 中继对下游流解复用、把 HPACK 解码进既有的逻辑请求/响应模型、并为每个流写一条 HAR 条目。上游在首个交付物中保持 HTTP/1.1（翻译模式）；后续 slice 增加 h2→h2 上游以让 gRPC 存活。WebSocket 是 HTTP/1.1 升级：101 之后切换到透明字节隧道。无新驱动代码、无新 LPC 消息、MVP 中不新增通告能力位。

**技术栈：** 现有 `SbieCapture.exe`（C 语言，`cl.exe` /W4 /WX，Win32 sockets，SbieDll 无 CRT 但 broker 有完整 CRT），OpenSSL 3.x 来自 `D:\vcpkg\installed\x64-windows`（libssl-3-x64 / libcrypto-3-x64），仅手写解析器（默认计划不用 nghttp2——见开放问题）。

---

## 已锁定的决策

以下不是开放问题。实现过程中不得重新争论。

1. **驱动 / SbieSvc / WFP 不变。** Phase 5 只改 broker。不新增 callout、LPC 消息 ID 或 QSbieAPI 虚函数。唯一可接受的线面改动是 key-log 文件的*尾部*启动标志或新的 SET-export 句柄，且可推迟到 broker 各部件被证明可用之后。
2. **手写编解码器，不用库。** HPACK（RFC 7541）与 HTTP/2 帧在 `hpack.c` 与 `http2.c` 中实现并带单元测试，与 Phase 4 的 `http11.c` / `redact.c` / `har.c` 完全一致。这让安全相关的解析面保持小而可审查。若 Huffman/编解码器体量成为阻塞（见开放问题），nghttp2 是文档化的逃生通道；若采用，只链接进 `SbieCapture.exe`。
3. **HTTP/2 = 先终止并翻译，h2→h2 后做。** 下游（客户端）HTTP/2 被完全终止并映射为逻辑请求/响应消息。首个 h2 交付物中上游（源站）腿说 HTTP/1.1；这需要把 `:method`/`:scheme`/`:authority`/`:path` 伪头翻译为请求行、把状态码翻译回 `:status`，并丢弃 connection 专属头。后续 slice 增加 h2→h2 上游以保真，且 gRPC 需要它。
4. **gRPC = 元数据 + trailers + 正文隧道，绝不解 protobuf。** 请求 `content-type` 为 `application/grpc` 的流被记录为一条 HAR 条目，含 `:path`（方法）、请求/响应头、`grpc-status`/`grpc-message` trailers 与消息计数；正文字节仅在 `CAPTURE_FLAG_INCLUDE_BODIES` 且受每正文上限约束时捕获。protobuf 解码超出范围（按架构文档需要描述符）。
5. **WebSocket = 升级检测 + 字节隧道。** 在 HTTP/1.1 上检测 `Upgrade: websocket` + `Connection: Upgrade` + `Sec-WebSocket-Key`。握手原样透传，然后切换到透明双向中继。HAR 中记录握手与最终隧道字节计数；MVP 不做逐消息帧/解码。
6. **Firefox/NSS 是 opt-in 且仅限 boxed profile。** 主要机制：在沙箱化 Firefox profile 中设置 `security.enterprise_roots.enabled = true`，使其信任宿主 Root store（Phase 4 持久会话 CA 已在那里）。更强机制（若 NSS `certutil` 可用）：把 CA 公钥证书注入 boxed profile 的 `cert9.db`。绝不触碰宿主 Firefox profile 或宿主 NSS 数据库。文档须说明 Firefox 在 CA 导入后必须（重新）启动。
7. **TLS key-log 显式启用且默认关闭。** broker 在两个上下文（下游与上游）都挂 `SSL_CTX_set_keylog_callback`，并把 `CLIENT_RANDOM` 行追加到调用方打开的 key-log 文件。LocalSystem 绝不创建或覆盖客户端提供的路径。会话启动时无显式 opt-in 则无 key-log。
8. **能力位保持原样。** `CAPTURE_CAP_HTTPS_INSPECTION` / `CAPTURE_CAP_HAR_EXPORT` 仍是仅有的通告位。HTTP/2、WebSocket 与 gRPC 属于"更好的 HTTPS 检查"，不是新能力。Firefox 信任与 key-log 是 broker 内部/启动标志功能，在实机验证通过前不通告。
9. **Phase 4 不变量不变。** 任何服务之前先做重定向上下文认证；broker 死亡 fail-closed；默认头脱敏；正文 opt-in；每正文 64 KiB 上限；HAR 64 MiB 上限；最长 300 s；64 路并发 MITM 连接（映射到 h2 流）；仅 loopback 监听；仍提供 ALPN `http/1.1` 让纯 h1 客户端继续可用。
10. **个人宿主约束：** 无 ARM64 完整链接、无官方驱动签名、无 `git reset` / `git clean`、保持 `NetworkEnableWFP=y`、不使用已安装的 `Start.exe`、不把解析器/OpenSSL 加载进 `SbieDrv`/`SbieSvc`。按 `HttpsMitmTests/build_https_mitm_tests.cmd` 的方式用 `cl.exe` + vcpkg OpenSSL 测试构建。

---

## 当前基线（不得回归）

| 部件 | 现状（Phase 4，HEAD `3e6552c6`） |
| --- | --- |
| 下游 ALPN | 仅 `http/1.1`（`HttpsMitm_AlpnSelect`，`https_mitm.c:100`） |
| 中继 | 每个 `HttpsMitm_ServeOnce` 单请求/响应；只读头 + `Content-Length`；无 chunked、无 keep-alive、无多路复用 |
| 上游连接 | 仅 IPv4（`HttpsMitm_ConnectTcp`） |
| HAR | 仅 HTTP/1.1（`har.h` 包含 `http11.h`；`HAR_EXCHANGE` 持有 `HTTP11_REQUEST`/`HTTP11_RESPONSE`） |
| broker 分发 | `capture_https_broker.c` accept 循环 → `HttpsMitm_ServeOnce` |
| 能力位 | Phase 4 Slice 8 后（11/11 实机隔离）`httpsInspection` / `harExport` 开启 |
| 测试 | `HarTests`、`HttpsMitmTests`、`CaptureQueueTests`（线格式/生命周期/视图）、`PcapngTests` |

Phase 5 必须补齐的已知 Phase 4 中继缺口（因为 h2→h1 与 WebSocket 路径依赖它们）：chunked 传输解码，以及单条 HTTP/1.1 连接上的多次顺序交换（keep-alive）。这些并入 Slice 3。

---

## 数据路径（HTTP/2，下游 h2 → 上游 h1，首个交付物）

```text
boxed 客户端 → WFP 重定向 → broker 监听套接字（不变）
    |
    +-- TLS accept（SNI 叶子签发，ALPN: h2 | http/1.1）
    |
    +-- 若 ALPN == "h2"：
            解复用帧（SETTINGS/WINDOW_UPDATE/PING 本地处理）
            每流：收集 HEADERS + CONTINUATION → HPACK 解码
                        → 构建逻辑请求（method/authority/path/headers）
            翻译为 HTTP/1.1 请求 → 上游 h1 套接字（既有）
            读 h1 响应（含 chunked）→ 翻译为 :status + headers
            HPACK 编码 → 下游 HEADERS + DATA 帧
            写 HAR 条目（serverIP = 原始远端，alpn = "h2"）
    +-- 若 ALPN == "http/1.1"：
            既有 h1 中继，为 chunked + keep-alive 加固
            若 Upgrade: websocket → 101 透传 → 字节隧道
```

### HPACK 范围（RFC 7541）

- 静态表：全部 61 项。
- 动态表：有界（默认 4096 字节）、LRU 淘汰、按方向独立编码器/解码器。
- 整数与字符串表示（索引、带/不带索引的字面量、永不索引、动态表大小更新）。
- Huffman 编解码（附录 B 表）。
- 解码限制：拒绝超大头块及超过 `HTTP11_MAX_*` 边界的名/值；畸形块使该流失败（RST_STREAM）并记为解码错误，绝不导致 broker 崩溃。

### HTTP/2 帧范围（RFC 7540）

- 帧头（9 字节）解析与序列化，带长度/类型/标志/流 ID 检查。
- SETTINGS（双向、ACK）、WINDOW_UPDATE、PING、GOAWAY、RST_STREAM 在连接级处理。
- HEADERS/CONTINUATION/DATA 按流组装。
- 流控：对下游发出的 DATA 尊重对端 WINDOW_UPDATE；首个交付物允许粗粒度流控实现（文档化），只要不使典型客户端死锁。
- 下游请求必须带 `:authority`；存在时用作 SNI/HAR 主机。

### HAR 记录新增（向后兼容）

- `alpn` 按协商结果变为 `"h2"` / `"http/1.1"` / `"grpc"`。
- h2 流的 `httpVersion` 为 `"HTTP/2"`。
- 新 `_sandboxie` 字段：`streamId`、`grpcStatus`、`grpcMessage`、`wsTunnelBytesIn`、`wsTunnelBytesOut`、`decodeError`（HPACK/帧解析失败但连接未拆除时置位）。

---

## 控制线格式

无新消息 ID。唯一推迟的增补（Slice 7，key-log）是：

```c
#define CAPTURE_FLAG_KEYLOG             0x00000010  /* broker 写 SSLKEYLOGFILE */
#define MSGID_CAPTURE_SET_KEYLOG_EXPORT 0x200B      /* 调用方打开的 key-log 文件句柄 */
```

在 broker key-log 路径被证明可用之前不实现；此前未知标志位仍返回 `STATUS_INVALID_PARAMETER`。

---

## 逐 slice 计划

每个 slice 是一个逻辑提交。Slice 9 之前不通告任何新东西。

### Slice 0 — 仅计划

本文件。无代码。

### Slice 1 — HPACK 编解码器（RFC 7541）

**目标：** HPACK 解码 + 编码的确定性用户态测试。

**文件：** `SandboxieTools/SbieCapture/hpack.h` / `hpack.c`、`SandboxieTools/HpackTests/`（+ `build_hpack_tests.cmd`）。

**行为：** 把 RFC 7541 附录 C 头块解码为名/值对；再编码回去；动态表淘汰；Huffman 往返；拒绝畸形整数/字符串。无 sockets、无 TLS。

**验证：** `HpackTests.exe` 打印 `hpack tests passed`；全部附录 C 向量匹配。

### Slice 2 — HTTP/2 帧编解码器

**目标：** 解析与序列化 HTTP/2 帧，以及每连接流表。

**文件：** `SandboxieTools/SbieCapture/http2.h` / `http2.c`、`SandboxieTools/Http2Tests/`。

**行为：** 带边界检查的头解析/序列化；SETTINGS/WINDOW_UPDATE/PING/GOAWAY/RST_STREAM；HEADERS+CONTINUATION 重组；带流控记账的 DATA 累积；流状态（idle/open/half-closed/closed）。无 sockets。

**验证：** `Http2Tests.exe` 通过；畸形帧被拒绝且不越界。

### Slice 3 — HTTP/1.1 chunked + keep-alive（中继加固）

**目标：** 关闭 h2→h1 与 WebSocket 依赖的两个 Phase 4 中继缺口。

**文件：** `http11.c` / `http11.h`（chunked 帧辅助函数）、`https_mitm.c`（`HttpsMitm_ReadMessage` → chunked + 多次交换）、`HarTests` + `HttpsMitmTests` 增补。

**行为：** 解码 chunked 请求/响应正文；`ServeOnce` 在 keep-alive 交换上循环直至关闭；保留 Phase 4 单交换测试。

**验证：** 既有 `HarTests` / `HttpsMitmTests` 保持绿；新 chunked + 单连接两次交换测试通过。

### Slice 4 — WebSocket 升级隧道

**目标：** 检测并隧道转发基于 HTTP/1.1 的 WebSocket。

**文件：** `https_mitm.c`（升级检测 + 中继）、`har.c`（ws 字节计数字段）、`HttpsMitmTests` 增补。

**行为：** 有效 101 之后停止 HTTP 解析，双向中继字节直至任一侧关闭；HAR 记录握手 + 隧道字节计数。不做消息解码。

**验证：** loopback WebSocket 握手测试双向隧道 N 字节；HAR 显示 `wsTunnelBytesIn/Out` 且无正文解码。

### Slice 5 — HTTP/2 下游终止 → HAR（上游 h1）

**目标：** 通告 `h2` 并通过 h1 上游把下游 HTTP/2 解码进 HAR。

**文件：** `https_mitm.c`（ALPN 提供 `h2`；新 h2 中继路径）、新 `http2_relay.c`（或并入 `https_mitm.c`）、`har.c`（h2 字段）、`HttpsMitmTests` h2 客户端增补。

**行为：** 完整下游 h2 终止、伪头 → 请求行翻译、上游 h1、h1 响应 → h2 HEADERS/DATA、每流一条 HAR 条目、应用脱敏、正文 opt-in。

**验证：** 针对本地 h1 上游的 h2 客户端（curl `--http2` 或小型测试 h2 客户端）产生正确 HAR；纯 h1 客户端仍可用；pinning/握手失败仍保留 PCAPNG。

### Slice 6 — h2 → h2 上游 + gRPC 流捕获

**目标：** 上游 ALPN 提供 `h2`；协商成功则 h2 上游；识别 gRPC。

**文件：** `https_mitm.c`（上游 ALPN）、`http2_relay.c`（上游 h2 + gRPC 检测）、`har.c`（grpc 字段）、`HttpsMitmTests` + 小型 gRPC echo fixture。

**行为：** 上游 h2 保真；`application/grpc` 流记录 `:path`、头、`grpc-status`/`grpc-message` trailers 与消息计数；正文隧道转发（opt-in 字节）但不做 protobuf。

**验证：** 本地 gRPC echo 往返；HAR 有 `grpcStatus=0` 与正确方法；非 gRPC 的 h2 上游仍产出干净 HAR。

### Slice 7 — TLS key-log 导出

**目标：** 为 Wireshark 输出 `CLIENT_RANDOM` key-log 行。

**文件：** `https_mitm.c`（两个上下文都挂 `SSL_CTX_set_keylog_callback`）、`capture_https_broker.c` / `main.c`（key-log 句柄/路径管道）、`HttpsMitmTests` 增补。

**行为：** 在 `CAPTURE_FLAG_KEYLOG` 下，每次握手向调用方打开的文件追加 `CLIENT_RANDOM <hex> <hex>`；否则无 key-log。

**验证：** loopback MITM 会话写出 ≥2 条 `CLIENT_RANDOM` 行；Wireshark 用 key-log 打开 Phase 4 PCAPNG 并解密。

### Slice 8 — Firefox/NSS 信任

**目标：** boxed Firefox 信任会话 CA，opt-in、仅限 boxed profile。

**文件：** 小型辅助（扩展现有 `SbieCapture --import-ca` 或脚本）实现 `security.enterprise_roots.enabled` 与可选 `certutil` cert9.db 注入；`Docs/SandboxCaptureMcp.md` 指南。

**验证（实机）：** boxed Firefox 在 CA 导入一次后加载 `https://example.com`（宿主 Root 已有 Phase 4 的 CA）；宿主 Firefox profile 与 NSS 文件 hash 不变；移除/重启行为已文档化。

### Slice 9 — 实机隔离 + 文档

**目标：** 证明无隔离回归，然后更新状态文档。

**测试：** 重跑 Phase 4 Slice 8 实机隔离套件（Box A / Box B / 宿主、pinning、broker 击杀、cross-SID），外加盒内新的 h2/ws/grpc 探针。更新 `Docs/SandboxCaptureMcp.md`（Phase 5 状态）、`CHANGELOG.md`。之后才决定 Firefox/key-log 是否需要新能力位或 MCP 标志。

**验证：** Phase 4 隔离仍 11/11；新 h2/ws/grpc 流量只出现在选定盒的 HAR 中；`git diff --check` 干净。

---

## 可能变更的文件

### 新增

- `SandboxieTools/SbieCapture/hpack.h` / `hpack.c`
- `SandboxieTools/SbieCapture/http2.h` / `http2.c`
- `SandboxieTools/SbieCapture/http2_relay.c`（必要时带头文件）
- `SandboxieTools/HpackTests/`
- `SandboxieTools/Http2Tests/`
- `Docs/Phase5ProtocolExpansion.md` — 本文件

### 修改

- `SandboxieTools/SbieCapture/https_mitm.c` / `https_mitm.h` — ALPN h2、h2 中继、WebSocket、key-log
- `SandboxieTools/SbieCapture/http11.c` / `http11.h` — chunked 辅助函数
- `SandboxieTools/SbieCapture/har.c` / `har.h` — h2/ws/grpc 字段
- `SandboxieTools/SbieCapture/capture_https_broker.c` / `main.c` — key-log 句柄（Slice 7）
- `SandboxieTools/HttpsMitmTests/`、`HarTests/` — 新用例
- `Docs/SandboxCaptureMcp.md`、`CHANGELOG.md` — 后端真实落地之后

### 除非编译强制，否则不触碰

- `SbieDrv` / `SbieSvc` / `capture.c` / `wfp.c` / `api_defs.h` / `msgids.h`（Slice 7 推迟的标志/消息 ID 除外，且须在 broker 证明之后）
- `NetworkAccess` 允许/拒绝逻辑
- `CCaptureView` / `CPacketCaptureView` / `CHttpsCaptureView` 行为（SandMan UI 不在 Phase 5 范围，除非明确要求）
- 安装器打包 / 签名 / ARM64 默认值

---

## 明确排除在范围之外

- QUIC 终止与 HTTP/3 解析（仅评估；UDP 443 在 Phase 3 被动路径上保持密文）
- gRPC 正文的 protobuf 解码（需要描述符）
- WebSocket 逐消息帧/解码
- 超出既有 opt-in + 上限的逐流正文内容
- Slice 9 实机证明前的新通告能力位
- Win7 SOCKS5 捕获回退
- 机器级嗅探
- 官方 EV 签名、ARM64 完整链接、安装器打包

---

## 风险

| 风险 | 缓解 |
| --- | --- |
| 手写 HPACK/Huffman 体量大且易错 | 附录 C 向量 + 类模糊畸形输入；nghttp2 作为文档化回退 |
| h2 多路复用重写单交换中继 | 保持 h1 路径完好；h2 是独立中继路径；每个 slice 回归跑 Phase 4 测试 |
| h2→h1 翻译丢失语义（cookie、顺序、connection 头） | 剥离 connection 专属头；文档化；Slice 6 的 h2→h2 上游恢复保真 |
| 下游 DATA 流控死锁 | 先做粗粒度窗口记账；声称 h2 可用前用真实浏览器客户端验证 |
| Firefox enterprise-roots 把信任范围扩大到我们的 CA 之外 | 仅 boxed profile 的偏好；验证宿主 profile + NSS hash 不变 |
| key-log 在磁盘泄漏会话密钥 | 显式 opt-in；调用方打开的文件；文档化风险（标准 Wireshark 工作流） |
| 新解析器使 broker 崩溃 | 所有解析器在实机前于单元测试中做模糊边界测试；broker 运行在既有 kill-on-close job 中 |

---

## 开放问题（不阻塞 Slice 1–2）

1. **手写 HPACK 还是 nghttp2。** 默认手写以保证可审查性，延续 Phase 4 的不用库约定。若 Huffman 表 + 编解码器膨胀超过约 1,500 行或测试变得不稳定，切换到 nghttp2（仅链接进 `SbieCapture.exe`）并在此注明。
2. **h2→h2 上游优先级。** Slice 6（h2→h2 + gRPC）是最大的 slice。与用户确认 gRPC 是 Phase 5 硬性要求还是可以滑到 Phase 5.1；若滑期，Slice 5（h2→h1）仍为浏览器/curl 交付 HTTP/2 检查。
3. **Firefox 机制。** `security.enterprise_roots.enabled` 侵入最小但信任整个宿主 Root store；`certutil` cert9.db 注入更精准但盒内需要 NSS 工具。Slice 8 期间决定哪个是 MVP。
4. **key-log 面。** key-log 需要新 SET-export 消息还是可复用既有句柄，在 Slice 7 broker 回调可用后决定。

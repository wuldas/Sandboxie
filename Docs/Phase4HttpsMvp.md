# Phase 4：HTTPS MVP 实施计划

> **给 Hermes 的指示：** 仅在用户接受本计划后实施；如果用户需要常规的阶段门控，则在本文件单独提交之后实施。不要把实现混入计划提交。不要执行 `git reset` / `git clean`。不要开始 HTTP/2、HPACK、WebSocket、gRPC、HTTP/3、Firefox/NSS 或 QUIC 终止。

**目标：** 交付 `Docs/SandboxCaptureMcp.md` 中的 Phase 4 HTTPS MVP：WFP connect-redirect + broker 认证、仅限沙箱的 CA 生命周期、TLS 1.2/1.3 与 HTTP/1.1 检查、HAR 导出与默认头脱敏。退出标准：选定沙箱内的代表性 Chromium、WinHTTP 与 curl 流量被解码进 HAR；证书固定被报告为 MITM 失败且密文 PCAPNG 保留；broker 故障不会恢复直连 HTTPS 出口。

**架构：** Phase 2 ALE 连接审计与 Phase 3 仅检查的包/流环完全保持原样。新增第三条路径——*不是*驱动 TLS 解析：`ALE_CONNECT_REDIRECT` 把匹配的出站 TCP/443 重写到 `SbieCapture.exe` 拥有的随机 loopback 监听器。broker 认证 WFP 重定向上下文、用会话 CA 终止下游 TLS、把 WFP 重定向记录复制到上游套接字后打开原始目的地、解析 HTTP/1.1、写 HAR，并继续从既有传输环写密文 PCAPNG。`SbieDrv` / `SbieSvc` 绝不解析 TLS 或 HTTP。OpenSSL 只存在于 `SbieCapture.exe`。能力位 `CAPTURE_CAP_HTTPS_INSPECTION` 与 `CAPTURE_CAP_HAR_EXPORT` 在实机隔离、fail-closed 与宿主存储完整性测试通过前保持关闭。

**技术栈：** 现有 SbieDrv WFP（`FwpsCalloutRegister1` 仍是 Win7 基线；redirect-handle API 是 Win8+ 且须能力门控）、SbieSvc CaptureServer LPC（`MSGID_CAPTURE` 0x2000）、QSbieAPI 非虚包装、`SandboxieTools` 下的 `SbieCapture.exe` 加来自 `Installer/buildVariables.cmd` 的 OpenSSL 3.4.0、SandMan Qt 6.8.3 MSVC 视图。个人宿主：仅 x64 / Windows 11、WDK 测试证书、无官方签名、无 ARM64 完整链接。

---

## 已锁定的决策

以下不是开放问题。实现过程中不得重新争论。

1. **HTTPS 是 connect-redirect + broker MITM。** 不要在驱动里实现 `FWPS_STREAM_ACTION_NEED_MORE_DATA`。Phase 3 注释里"NEED_MORE_DATA 属于 Phase 4"已被取代：驱动仍然绝不解析 TLS。STREAM/TRANSPORT 保持复制后放行的检查模式。
2. **不要复用 `WFP_classify`。** 该函数是 ALE AUTH CONNECT/RECV_ACCEPT 的终止策略 callout。重定向使用新的 classify，可改写远端端点。包/流/传输/数据报 callout 保持 `FWP_ACTION_CALLOUT_INSPECTION`，绝不改变裁决。
3. **先评估原始 `NetworkAccess` / `AllowNetworkAccess`。** 被拒绝的目的地保持拒绝。重定向只在 ALE AUTH 已允许原始五元组之后发生。
4. **Fail-closed。** HTTPS 会话处于 `RUNNING` 或 `FAILED` 期间，即使 broker 进程已死，匹配的 TCP/443 仍继续重定向到 broker 监听器。连接随即失败。不要因 broker 死亡而注销重定向过滤器。只有显式 stop 才拆除重定向。
5. **broker 只接受被重定向的连接。** 缺少绑定到本捕获 id + generation 的有效 WFP 重定向上下文的连接被丢弃。不存在"loopback 上的开放代理"。
6. **递归重定向由 WFP 重定向记录防止。** broker 把入站重定向记录复制到上游套接字。驱动 classify 必须跳过已被自己 `FwpsRedirectHandle` 重定向的流。
7. **仅 TCP 443。** 不要重定向所有 TCP。QUIC/UDP 443 留在 Phase 3 被动路径（仅密文）。非 443 的 TLS 超出 MVP。
8. **ALPN 仅 `http/1.1`。** broker 不通告 `h2`。拒绝 HTTP/1.1 的 HTTP/2 客户端 fail closed 且仍有 PCAPNG。
9. **`CAPTURE_MODE_HTTPS` 同时启动既有包后端。** 固定/ MITM 失败必须保留密文 PCAPNG。HTTPS 不是包捕获的替代品。
10. **两个调用方打开的导出文件。** `SET_EXPORT` 仍是 PCAPNG。新 `MSGID_CAPTURE_SET_HAR_EXPORT`（`0x200A`）是 HAR 文件。LocalSystem 绝不创建或覆盖客户端提供的路径。两个句柄都设置之前，HTTPS 启动不能离开 `WAITING_FOR_BACKEND`。
11. **正文 opt-in。脱敏默认开启。** `Authorization`、`Proxy-Authorization`、`Cookie`、`Set-Cookie` 与常见 API 密钥头在无显式标志禁用脱敏前被替换为 `[REDACTED]`。除非设置 `CAPTURE_FLAG_INCLUDE_BODIES`，否则省略正文字节，且即使设置也只到每正文上限。
12. **持久会话 CA。** 单个 SbieCapture CA（10 年有效期）在首次使用时生成并存储在所有者 `%LOCALAPPDATA%\SbieCapture\` 下（`ca.crt` + `ca.key`），之后跨捕获会话复用。只有 CA *公钥*证书被导入宿主用户的 Root store（经 SYSTEM store provider）；首次导入会弹出 Windows 根证书安装提示，后续会话幂等且不再提示。盒的虚拟 Root store 不被修改。私钥存在于所有者 profile 的磁盘上，因此任何具有该 profile 读权限的进程理论上都能铸造 MITM 证书——这是标准 mitmproxy/Fiddler 信任模型，在此接受并文档化。
13. **OpenSSL 3.4.0 仅存在于 `SbieCapture.exe`。** 不要把 OpenSSL、解析器或 HAR 写入器链接进 `SbieDrv` 或 `SbieSvc`。使用 `Installer/buildVariables.cmd` 中的版本；不要在该文件硬编码不同版本。
14. **Win8+ 重定向是 MVP 路径。** `FwpsRedirectHandleCreate0` / `FwpsQueryConnectionRedirectState0` 在运行时解析。若缺失，HTTPS 能力保持关闭且 start 返回 `STATUS_NOT_SUPPORTED`。架构文档中的 Win7 SOCKS5 回退属于 Phase 4.1 / 之后，不是本 MVP。
15. **不要提升 `CAPTURE_WIRE_VERSION`。** 旧的 112 字节 `CAPTURE_START_REQ` 仍可启动连接审计。扩展 start 保持 132 字节，且仅当新*尾部*标志不移动既有字段时才能添加。倾向新标志位 + 新 SET 消息，而不是调整 start 大小。
16. **QSbieAPI 保持非虚。** 追加字段 / 追加非虚方法。不要在 `CSbieAPI` 上插入虚函数。
17. **新 SandMan 视图。** `CHttpsCaptureView` / `CHttpsCaptureWindow`。不要复用 `CCaptureView`、`CPacketCaptureView` 或 `CTraceEntry` 作为 HAR 表。Packet Capture 与 Connection Audit 行为不变，除新增独立 HTTPS 动作外。
18. **能力位保持关闭**（`CAPTURE_CAP_HTTPS_INSPECTION`、`CAPTURE_CAP_HAR_EXPORT`）直到 Slice 8 实机测试通过。此前公开的 `CAPTURE_MODE_HTTPS` 保持 `STATUS_NOT_SUPPORTED`。
19. **个人宿主约束：** 无 ARM64 完整链接、无官方驱动签名、无 `git reset` / `git clean`、保持 `NetworkEnableWFP=y`、不使用已安装的 `Start.exe`、不把解析器/OpenSSL 加载进 `SbieDrv`/`SbieSvc`。每次实机驱动改动仍需回滚路径与重载后 hash 检查。使用 `kmdutil-driver-reload` 工作流；先停 `SbieSvc`；注意 `SandMan.exe` 重新持有 `\\Device\\SandboxieDriverApi`。

---

## 当前基线（不得回归）

| 部件 | 现状 |
| --- | --- |
| ALE AUTH CONNECT/RECV_ACCEPT v4/v6 | 策略 + 80 字节连接审计 |
| FLOW / TRANSPORT / STREAM / DATAGRAM | 检查复制进包/流环 |
| Connect-redirect 层 | 未注册 |
| `FwpsRedirectHandle*` | 未使用 |
| `SbieSvc` start | `mode` 非 CONNECTIONS/PACKETS → `STATUS_NOT_SUPPORTED` |
| 能力位 | CONTROL + CONNECTION_AUDIT + PACKET/PCAPNG（门 + 载荷 callout 健康时） |
| `httpsInspection` / `harExport` | false |
| Broker | 仅 PCAPNG 排空；无监听套接字；无 OpenSSL |
| SandMan | Connection Audit + Packet Capture |
| MCP `mode=https` | Schema 接受，服务拒绝 |
| OpenSSL | 仅为 Qt/SandMan TLS 插件捆绑 3.4.0 |
| SOCKS5 | 既有 `SbieDll` `NetworkUseProxy` 路径；不是捕获能力 |

Phase 3 在本宿主上的实机证据已覆盖 Box A / Box B / 宿主隔离、IPv4/IPv6 TCP/UDP、snaplen/rotate/time、进程级与盒级作用域、溢出 `droppedCount`、broker 击杀与 cross-SID / cross-session 拒绝。这些脚本在每次驱动更换后仍是硬门。

---

## 数据路径

```text
boxed TCP/443（ALE AUTH 已允许）
    |
    +-- 既有 ALE AUTH -----> WFP_classify -----> 80 字节审计队列
    |
    +-- 既有 FLOW/TRANSPORT/STREAM --> 包/流环 --> PCAPNG
    |
    +-- ALE CONNECT_REDIRECT v4/v6
            若已被自己重定向 -> 继续
            若 HTTPS 会话匹配（box/SID/session/PID+createTime）
               且 proto=TCP 且 remote_port=443
               且目的不是 broker 监听器
               -> 改写为 127.0.0.1/::1 : broker_port
               -> 附加重定向上下文
            否则继续

SbieSvc CaptureServer
    |-- 授权所有者（Phase 2 规则不变）
    |-- 启动包会话（既有）
    |-- 启动 HTTPS 重定向会话（新驱动控制）
    |-- 生成 SbieCapture.exe（包排空 + HTTPS 监听）
    |-- DuplicateHandle(pcapng) + DuplicateHandle(har) + section
    |-- 在盒内启动辅助进程仅导入 CA 公钥证书
    |-- stop / 失败 / 所有者断连 => 击杀 job，然后拆除重定向

SbieCapture.exe
    |-- 映射包环，写 PCAPNG（既有）
    |-- 在临时端口的 127.0.0.1 与 [::1] 上监听
    |-- 只接受 WFP 重定向的套接字
    |-- SNI 回调：从会话 CA 铸造叶子
    |-- 下游 TLS（OpenSSL 3.4.0）
    |-- 带重定向记录复制的上游 TLS 到原始目的
    |-- HTTP/1.1 解析、脱敏、可选正文、HAR 写入器
    |-- 固定/握手失败：记录事件、保留 PCAPNG、不泄漏
```

### 重定向上下文（固定大小，复制进 WFP classify 上下文）

```text
捕获 id 高/低
捕获 generation
策略 generation
进程 id
进程创建时间
会话 id
盒名（BOXNAME_COUNT）或盒 hash
原始远端地址[16]
原始远端端口
地址族
```

broker 通过 `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`（或文档化等价物）读取它，若与继承的捕获 id + generation 不匹配则拒绝该套接字。

### HAR 记录（仅 broker，绝不走 LPC）

每个 HTTP/1.1 交换一个 HAR 1.2 `log.entries[]` 对象：

- `startedDateTime`、`time`
- `request.method`、`url`（来自 SNI + 请求目标）、`httpVersion`
- 脱敏后的 `request.headers` / `response.headers`
- 从请求目标解析的 `request.queryString`
- `response.status`、`statusText`
- `serverIPAddress` = 原始远端，而非 127.0.0.1
- `_sandboxie` 自定义字段：pid、createTime、box、sid、session、sni、alpn、tlsVersion、pinningFailed
- 仅当启用正文且在每正文上限内时才有 `content.text`；否则省略 `text` 并记录 `_omitted` / `size`

不要把 HAR 条目经 LPC 发送。SandMan 尾随调用方拥有的 HAR 文件，或 broker 在其旁追加的 sidecar JSONL。倾向 JSONL 条目 + stop 时闭合的 HAR 包装，这样崩溃仍留下可读交换。

### 限制

- 最大并发 HTTPS 会话：每所有者 1 个，全局 2 个
- broker accept 积压：32
- 最大并发 MITM 连接：64；溢出使新连接失败，不拆除重定向
- 默认每正文上限：64 KiB
- 默认 HAR 最大文件：64 MiB（与 PCAPNG 相同的轮转规则）
- 默认最大秒数：300
- CA 密钥：2048 位 RSA 或 P-256；叶子 SAN = SNI；有效期 ≤ 24 h
- 监听地址：仅 loopback

---

## 控制线格式

保持消息族 `0x2000`。新增：

```text
MSGID_CAPTURE_SET_HAR_EXPORT   0x200A
```

`0x20FF` 仍是断连通知。

### 新启动标志（既有 `flags` 字段，无尺寸变化）

```c
#define CAPTURE_FLAG_INCLUDE_BODIES     0x00000004
#define CAPTURE_FLAG_DISABLE_REDACTION  0x00000008
```

未知标志位仍返回 `STATUS_INVALID_PARAMETER`。不设置这些位的旧包/连接客户端保持现行为。

### `CAPTURE_SET_HAR_EXPORT`

与 `CAPTURE_SET_EXPORT` 同形：调用方相对文件句柄 + 捕获 id。SbieSvc 从 LPC 客户端 `DuplicateHandle`。若句柄不是可写磁盘文件、或调用方被沙箱化则拒绝。无路径字符串。

HTTPS 启动序列：

1. 以 `mode = CAPTURE_MODE_HTTPS` `START` → 会话 `WAITING_FOR_BACKEND`（或直到 Slice 8 都是 `STATUS_NOT_SUPPORTED`）。
2. `SET_EXPORT`（PCAPNG）+ `SET_HAR_EXPORT`（HAR），顺序任意。
3. broker 监听端口绑定、CA 铸造、重定向句柄创建、盒内证书辅助成功。
4. 只有这些步骤完成后会话才变 `RUNNING`。任何失败都是 `FAILED` 且 fail-closed 直到 `STOP`。

不要加"经 LPC 读 HAR"。

---

## 可能变更的文件

### 新增

- `SandboxieTools/SbieCapture/har.h` / `har.c` — HAR/JSONL 写入器，若存在极小的既有辅助则不用第三方 JSON 库；否则用带测试的有界写入器
- `SandboxieTools/SbieCapture/http11.h` / `http11.c` — 仅 HTTP/1.1 请求/响应帧
- `SandboxieTools/SbieCapture/redact.h` / `redact.c` — 头脱敏
- `SandboxieTools/SbieCapture/capture_ca.h` / `capture_ca.c` — 会话 CA + SNI 叶子（OpenSSL）
- `SandboxieTools/SbieCapture/https_mitm.h` / `https_mitm.c` — 监听、重定向上下文认证、TLS、上游
- `SandboxieTools/HarTests/` — 用户态 HAR / redact / http11 测试（无驱动）
- `SandboxieTools/HttpsMitmTests/` — 针对本地 OpenSSL 服务器的 loopback TLS 1.2/1.3 + HTTP/1.1 测试
- `Sandboxie/core/drv/capture_https.h` / `capture_https.c` — 重定向会话表（尽可能双编译）
- `SandboxiePlus/SandMan/Views/HttpsCaptureView.h` / `.cpp`
- `Docs/Phase4HttpsMvp.md` — 本文件

### 修改

- `Sandboxie/core/drv/wfp.c` / `wfp.h` — 新 CONNECT_REDIRECT GUID、重定向 classify、Win8+ API 运行时解析
- `Sandboxie/core/drv/capture.c` / `capture.h` / `api_defs.h` / `api.c` — HTTPS 会话启停、重定向句柄、监听端口发布
- `Sandboxie/core/drv/SboxDrv.vcxproj` — 新 TU
- `Sandboxie/core/svc/msgids.h` — `0x200A`
- `Sandboxie/core/svc/capturewire.h` — 新标志位、SET_HAR_EXPORT、static_asserts
- `Sandboxie/core/svc/CaptureServer.cpp` — HTTPS 模式、第二导出句柄、证书辅助、就绪前仍 `NOT_SUPPORTED`
- `SandboxieTools/SbieCapture/*` — 既有环排空旁的 HTTPS 监听模式
- `SandboxieTools/SbieCapture/SbieCapture.vcxproj` — 仅 broker 的 OpenSSL include/lib
- `SandboxieTools/CaptureQueueTests/CaptureWireTests.cpp` — 新 msgid + 标志契约
- `SandboxiePlus/QSbieAPI/SbieCapture.h` / `SbieAPI.h` / `SbieAPI.cpp`
- `SandboxiePlus/SbieMcp/main.cpp` — HAR 路径 + 正文/脱敏参数；Slice 8 前隐藏能力
- `SandboxiePlus/SandMan/SandMan.cpp` / `.h` / `SandMan.pri` / `Views/SbieView.*`
- `Docs/SandboxCaptureMcp.md` — 后端真实落地后的状态段落
- `CHANGELOG.md` — 在可用 x64 路径存在之后，而非仅计划提交中

### 除非编译强制，否则不触碰

- `CCaptureView.*` / `CPacketCaptureView.*` 行为
- `WFP_classify` 内部的 `NetworkAccess` 允许/拒绝逻辑
- `SbieDll` SOCKS5（`net.c` / `proxy.c`）— 不是 MVP 路径
- `DefaultBox` / `Sandboxie.ini` 内容（可文档化回滚的测试盒除外）
- 安装器打包 / 官方签名 / ARM64 工程默认值
- Firefox NSS 数据库

---

## 逐 slice 计划

按此顺序实现。每个 slice 是一个逻辑提交。Slice 8 之前不要通告 HTTPS 能力。

### Slice 0 — 仅计划

本文件。无代码。

### Slice 1 — HAR 写入器、HTTP/1.1 帧、脱敏（无驱动、无 OpenSSL）

**目标：** 把合成 HTTP/1.1 交换转成脱敏 HAR/JSONL 文件的确定性用户态测试。

**文件：** `SandboxieTools/SbieCapture/http11.*`、`redact.*`、`har.*`、`SandboxieTools/HarTests/`

**行为：**

- 从字节缓冲解析一个请求与一个响应；拒绝折叠头与超长行
- 默认脱敏列表不区分大小写应用
- `DISABLE_REDACTION` 保留原始头值
- 默认省略正文；包含时在上限截断并记录原始大小
- 写入器产出 `har.2` 解析器 / 小型自检可重开读的文件
- 无 TLS、无 sockets

**验证：**

```text
cl /nologo /W4 /WX /DUNICODE /D_UNICODE HarTests.c http11.c redact.c har.c
HarTests.exe
```

预期：全部用例通过；golden HAR 含 `Authorization: ***` 且无 cookie 明文。

### Slice 2 — 会话 CA + loopback MITM（OpenSSL 仅在 broker/测试中）

**目标：** `SbieCapture` 可铸造会话 CA、出示 SNI 叶子、完成 TLS 1.2 与 TLS 1.3、把 HTTP/1.1 代理到本地上游并写 HAR。

**文件：** `capture_ca.*`、`https_mitm.*`、`HttpsMitmTests/`、broker vcxproj OpenSSL 链接

**规则：**

- 只把 OpenSSL 3.4.0 链接进 `SbieCapture` 与 MITM 测试 exe
- 下游 ALPN = `http/1.1`
- 上游验证真实本地测试服务器证书
- 测试使用真实 WFP 会提供给 acceptor 的假重定向上下文 blob
- 无该 blob 的 acceptor 被拒绝

**验证：**

```text
HttpsMitmTests.exe
```

预期：TLS 1.2 与 1.3 GET `/` 往返；HAR URL 使用 SNI 主机而非 127.0.0.1；缺失上下文被拒绝；CA 私钥绝不写入沙箱路径之下。

### Slice 3 — 线格式 + QSbieAPI + MCP 形态（仍 NOT_SUPPORTED）

**目标：** 标志位、`MSGID_CAPTURE_SET_HAR_EXPORT`、QSbieAPI 方法、MCP `outputHarPath` / `includeBodies` / `disableRedaction`。服务对 `MODE_HTTPS` 仍返回 `STATUS_NOT_SUPPORTED`。能力位仍关闭。

**文件：** `capturewire.h`、`msgids.h`、`CaptureServer.cpp`（解析并拒绝）、`SbieCapture.h`、`SbieAPI.cpp`、`SbieMcp/main.cpp`、`CaptureWireTests.cpp`

**验证：**

- 既有连接审计与包启动对当前实机服务/驱动仍可用
- `mode=https` 仍 `0xC00000BB`
- `CaptureWireTests.exe` 带 `0x200A` 与不变的 v1 start 尺寸 112 / start 尺寸 132 通过
- `CSbieAPI` 无 vtable 变化

### Slice 4 — Broker HTTPS 进程模式（尚无实机 WFP）

**目标：** `SbieCapture.exe` 接受 `--https-listen` 加继承的 HAR 句柄、铸造 CA、把公钥证书写入继承的证书文件句柄、照常排空 PCAPNG、并服务 Slice 2 的 MITM 路径。

**文件：** `SandboxieTools/SbieCapture/main.c`、`capture_broker.*`

**SbieSvc 生成规则（Slice 6 实现，此处设计）：**

- 路径仅限安装目录 `SbieCapture.exe`
- 客户端不能提供 exe 路径或命令行
- kill-on-close job
- 调用方主令牌，而非 LocalSystem
- 监听套接字由 broker 生成后绑定；端口通过既有共享 section 头或 SbieSvc 已映射的极小 broker 自有字段回传（不要新增 LPC 载荷排空）

**验证：** 带假重定向上下文 + 本地上游的 harness 产出 HAR + PCAPNG。击杀 broker 后 HAR JSONL 仍可读。

### Slice 5 — 驱动 connect-redirect（危险 slice）

**目标：** 注册 `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6`。把匹配 TCP/443 改写为 broker loopback 端口。附加上下文。跳过自身重定向的流。不改变 ALE 策略。

**文件：** `wfp.c`、`wfp.h`、`capture.c`、`capture_https.*`、`api_defs.h`

**必需拆分：**

| Callout | 层 | 动作类型 | Classify |
| --- | --- | --- | --- |
| 既有 send/recv | ALE AUTH CONNECT/RECV_ACCEPT | TERMINATING（不变） | `WFP_classify` 不变 |
| 既有包路径 | FLOW / TRANSPORT / STREAM / DATAGRAM | INSPECTION | 不变 |
| 新 | ALE CONNECT_REDIRECT v4/v6 | TERMINATING 改写 | `WFP_https_redirect_classify` |

新 GUID：延续 `0bf56435-71e4-4de7-bd0b-1af0b4cbb8f6` 族；不复用 ALE 或包 GUID。

运行时：用 `MmGetSystemRoutineAddress`（或工程既有动态解析模式）解析 `FwpsRedirectHandleCreate0`、`FwpsRedirectHandleDestroy0`、`FwpsQueryConnectionRedirectState0`。若缺失，HTTPS 启动失败 `STATUS_NOT_SUPPORTED` 且不注册重定向 callout。

过滤器身份：复用 `CaptureFilter_Matches`。仅 PID 永远不够。远端端口必须是 443。等于会话监听器的目的永不被重定向。

**验证（编译 + 加载，不声称 HTTPS 可用）：**

- x64 `SbieDrv.sys` 以 WDK 测试签名构建
- 用户态 HAR / 线格式 / 队列测试仍通过
- `git diff --check` 干净
- 重载后：连接审计 `e2e_silent` 与 Phase 3 包隔离探针仍通过
- 无 HTTPS 会话时，盒内 TCP/443 不变（直连）
- 不要声称"能解密了"

### Slice 6 — CaptureServer HTTPS 生命周期 + 仅沙箱 CA 导入

**目标：** `MODE_HTTPS` 启动创建包 + HTTPS 驱动状态、生成 broker、等待监听端口 + CA 公钥证书、在调用方令牌下启动盒内辅助仅把该证书导入虚拟当前用户 Root store、然后启用重定向。所有者断连 / stop / 辅助失败 → `FAILED` 或 `STOPPED`、job 击杀、仅 stop 时拆除重定向。

**文件：** `CaptureServer.cpp`、`api_defs.h`、`capture.c`、小型盒内证书辅助（倾向用既有 `MSGID_PROCESS_RUN_SANDBOXED` 在盒*内*启动的 `SbieCapture --import-ca` 模式，而非第二个已安装 exe）

**授权：** 与 Phase 2/3 相同。沙箱化调用方不能启动。Cross-SID / cross-session 拒绝。进程作用域绑定 PID+createTime。盒作用域要求 `INCLUDE_FUTURE_PROCESSES`。规范盒名。

**Fail-closed：** broker 在 `RUNNING` 期间被击杀 → 会话 `FAILED`、重定向过滤器保留、新 443 连接失败、ALE 审计仍工作、包环在 `STOP` 前仍存在。

**验证：**

- 无两个导出句柄的 HTTPS 启动保持 `WAITING_FOR_BACKEND` 或 fail closed
- `SbieCapture.exe` 旁缺 OpenSSL DLL → `FAILED`，而非 `RUNNING`
- 无监听端口的连接审计与纯包会话仍可启动
- 成功导入后宿主 Root store hash 不变；第二个盒的虚拟 store 不变

### Slice 7 — SandMan HTTPS 视图

**目标：** 启动 HTTPS 会话、显示有界 HAR 条目表并指向两个输出文件的独立视图。

**文件：** `HttpsCaptureView.*`、`SandMan.cpp`、`SandMan.h`、`SandMan.pri`、`SbieView.*`

**UI 契约：**

- `View → HTTPS Capture` 与一个日志标签页，与 Packet Capture 和 Connection Audit 分离
- 盒下拉用 `I.value()->GetName()`，绝不用 `I.key()`
- 盒上下文：HTTPS Capture（整盒 + 未来进程）
- 进程上下文：仅该 PID+createTime 的 HTTPS Capture
- 控件：最大时间、最大文件、轮转、包含 loopback、包含正文（关）、禁用脱敏（关，危险）
- Start 前用户选*两个*输出文件（PCAPNG + HAR）
- 表列：时间、PID、进程、方法、状态、主机、路径、TLS、pinning
- 表中无 cookie / authorization 明文
- 有界 UI 队列；表中不 dump 正文
- 状态：交换数 / 丢弃数 / 当前 HAR / "pinning 失败保留 PCAPNG"
- 能力位开启（Slice 8）前隐藏或禁用 Start

`SandMan.exe`、`QSbieAPI.dll`、`SbieCapture.exe` 与 broker 需要的 OpenSSL 3.4.0 DLL 一起部署。

### Slice 8 — 实机隔离，然后能力位

**目标：** 在个人宿主机上证明安全不变量，然后才通告 `httpsInspection` / `harExport`。

**测试（静默盒内 runner，非已安装 `Start.exe`）：**

1. 连接审计与包捕获回归仍通过。
2. Box A `curl -I https://example.com`、Box B `curl -I https://1.1.1.1`、宿主 `curl -I https://9.9.9.9`。Box A HAR 只含 Box A PID/createTime 与 example.com。Box B HAR 不含 example.com。宿主 PID 绝不出现。每个 PCAPNG 仍隔离密文。
3. 进程作用域会话：后来的盒内子进程不被解密且不出现于 HAR。
4. 盒作用域会话：后来的子进程在重启 / 拾取沙箱 CA 后*确实*出现（若运行中的 Chromium 必须重启则文档化）。
5. 盒内 WinHTTP 与 Chromium 系客户端：各自至少一次成功的 HTTP/1.1 HTTPS 交换。若 Chromium 只提供 HTTP/2 并拒绝 HTTP/1.1，记为已知 MVP 限制并仍要求 curl + WinHTTP。
6. 固定：固定（或 `curl --pinnedpubkey`）的客户端使 MITM 握手失败；会话保持；PCAPNG 有密文；HAR 记录 `pinningFailed`。
7. Broker 击杀：会话 `FAILED`、新盒内 curl 到 443 失败、宿主 curl 仍工作、ALE 审计仍工作。`STOP` 后盒内 curl 到 443 恢复。
8. 无 WFP 上下文直连 broker loopback 端口被拒绝。
9. 被拒绝的 `NetworkAccess` 目的仍被拒绝（无重定向绕过）。
10. 宿主 `HKCU` Root store 运行期间与之后都含持久会话 CA（幂等，stop 不删除）。第二个沙箱的虚拟 Root store 不变。盒的虚拟 Root store 不被捕获修改。
11. Cross-SID / cross-session **进程作用域** HTTPS 启动仍 `0xC0000022`。
12. IPv4 与（若宿主有可用 IPv6 出口）IPv6。只声称实际跑过的地址族。

只有 1–11 通过后能力位才开启。MCP `httpsInspection` / `harExport` 变 true。SandMan HTTPS Start 可启用。HTTP/2、Firefox/NSS 与 Win7 SOCKS5 仍超出范围。

---

## 验证命令（个人宿主）

构建 / 部署遵循 Phase 3 配方与 `kmdutil-driver-reload`。

- 驱动更换：签名 x64 `SbieDrv.sys`、停 `SbieSvc`、确认无 `SandMan` / 残留句柄在 `\\Device\\SandboxieDriverApi`、`KmdUtil stop SbieDrv`、复制、hash、`KmdUtil start SbieDrv`、启动 `SbieSvc`。
- 若只改了 `SbieSvc` / `SbieCapture.exe`，**不要**卸载驱动。
- 单独构建 `SboxSvc.vcxproj` 会失败（`SbieDll.lib`）；用 `Sandbox.sln | SbieRelease|x64`。
- Qt：Community `vcvars64.bat` + 本机 Qt 6.8.3 MSVC kit（不要复用旧 PC 的 `C:\Users\Wuldas\.AA\Qt\...` 路径）。
- 证据目录：`%LOCALAPPDATA%\Temp\hermes-sandbox-capture-red\`
- 每个 slice `git diff --check`。
- 只报告实际构建过的架构（x64）。

---

## 明确排除在范围之外（Phase 5 / 4.1）

- HTTP/2、HPACK、WebSocket、gRPC、HTTP/3、QUIC 终止
- Firefox / NSS 信任注入
- Win7 SOCKS5 捕获回退
- 重定向 TCP 443 之外的端口
- 机器级嗅探
- 保证解密固定、mTLS 或仅 ECH 的客户端
- 官方 EV 签名、ARM64 完整链接、安装器打包
- 改变 `NetworkAccess` 语义使捕获可绕过拒绝
- `SbieDrv` / `SbieSvc` 中的 OpenSSL 或 HTTP 解析器
- `FWPS_STREAM_ACTION_NEED_MORE_DATA`
- IP 字面量 HTTPS 目标（如 `https://1.1.1.1`）：Schannel 对 IP 地址省略 SNI 并按叶子 SAN 匹配主体，但 broker 从 SNI 铸造 `DNS:` SAN；握手以 `SEC_E_WRONG_PRINCIPAL` 失败。DNS 名目标可用，且正是 Slice 8 所练习的。
- 吊销软失败容忍：沙箱化 Schannel 出站凭据无条件获得 `SCH_CRED_IGNORE_NO_REVOCATION_CHECK | SCH_CRED_IGNORE_REVOCATION_OFFLINE`（MITM 叶子无 CRL/OCSP 端点）；这只抑制"无法检查吊销"软错误，绝不抑制 `CRYPT_E_REVOKED`，也不改变信任锚。

---

## 风险

| 风险 | 缓解 |
| --- | --- |
| 重定向 classify 意外绕过 `NetworkAccess` | ALE AUTH 仍最先且不变；重定向只在允许之后 |
| broker 死亡恢复直连 443 | Fail-closed：`STOP` 前保持重定向到死监听器 |
| Loopback 监听器变成开放代理 | 拒绝无匹配重定向上下文的套接字 |
| broker 上游的递归重定向 | 复制 WFP 重定向记录；跳过 `REDIRECTED_BY_SELF` |
| 宿主或其它盒信任 CA | 持久 CA 只导入宿主用户 Root store（一次，弹窗）；盒的虚拟 Root 永不被修改 |
| CA 私钥落进盒 | 辅助只接收公钥证书字节 |
| 仅 HTTP/2 的 Chromium | 强制 ALPN http/1.1；把拒绝文档化为 MVP 限制；仍要求 curl + WinHTTP |
| 新终止 callout 后包隔离回归 | Slice 5 在任何 HTTPS 流量测试前用 Phase 2/3 e2e 硬门 |
| OpenSSL 被拉进 SbieSvc | vcxproj 只在 `SbieCapture` / MITM 测试上链接 |
| 重载期间 `SandMan` 重新持有驱动 | 每次卸载前快照句柄 |

---

## 开放问题（不阻塞 Slice 0–2）

1. 若本宿主 Chromium 在 ALPN 降级后拒绝 HTTP/1.1，Slice 8 仍以 curl + WinHTTP 交付，并把 Chromium 记为"pinning-or-ALPN 失败 + PCAPNG 保留"。
2. 精确的盒内证书辅助启动 API（`MSGID_PROCESS_RUN_SANDBOXED` 对比既有 updater 辅助）在 Slice 6 从实机服务面选择；Slice 2 只需要用户态导入函数。
3. 发布监听端口的共享 section 字段在 Slice 4/5 于既有 broker 头旁选择；不要发明第二个 section。

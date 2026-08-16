# 沙箱捕获与 MCP 架构

## 状态

本文档定义沙箱作用域网络捕获、可选 HTTPS 检查与 Model Context Protocol（MCP）接口的架构与交付计划。

初始控制面与连接审计 slice 已实现。它们不声称支持包捕获：连接审计记录描述授权尝试，不含任何包载荷、TCP 流、TLS 明文或 HTTP 数据。

当前实现状态：

- Phase 1 控制线格式、所有者作用域服务会话、QSbieAPI 包装与 MCP stdio 可执行文件已实现。
- Phase 2 为 WFP ALE connect 与 receive/accept 授权元数据新增固定大小非分页每会话驱动队列。SbieSvc 是唯一驱动排空消费者，并在返回记录前应用所有者、盒、SID、Windows 会话、PID 与进程创建时间隔离。
- Slice 1–8 包捕获基础设施已就绪。`CAPTURE_PACKET_CAPTURE_RELEASE_GATE` 为 `1`：当 `NetworkEnablePacketCapture=y` 且载荷 callout 已注册时，MCP 通告 `packetCapture`/`pcapngExport` 且允许公开包启动。把门设为 `0` 硬禁用这些位并返回 `STATUS_NOT_SUPPORTED`。
- 共享 section 已版本化并绑定到捕获 id 加 generation。驱动用 MDL 在 `DISPATCH_LEVEL` 写时锁定映射视图。驱动拥有的容量/写入状态保持在 broker 可写头之外；环覆盖递增 `section->dropped_count`。SbieSvc 把该计数器复制进公开会话，且不得在包停止时用连接审计丢弃计数替换它。broker 仍是唯一载荷消费者与 PCAPNG 写入器。
- 本宿主 x64 实机证据已接受：Box A / Box B / 宿主隔离；IPv4/IPv6 TCP 与 UDP；loopback/snaplen/size/rotate/time 限制；进程作用域排除后来的子进程；盒作用域包含后来的子进程；broker 停滞溢出在 4096 环上报告 `droppedCount=904`（5000 数据报）；broker 击杀产生 `state=5` / `0xC0000001`；cross-SID 与 cross-session 进程作用域启动返回 `0xC0000022`。
- SandMan 可带或不带 `translations.7z` 启动。语言与故障排除归档经 `CArchive::ExtractToCache` 解压到真实目录；SandMan 不再构造 `QAbstractFileEngineHandler`。HTTPS 检查仍超出范围。
- Connection Audit 仍是独立路径，每次驱动更换后必须重跑。

## 目标

- 只捕获归属于选定沙箱或该沙箱中选定进程的流量。
- 请求时包含在捕获启动后加入选定沙箱的进程。
- 支持 IPv4、IPv6、TCP 与 UDP，不收集无关宿主流量。
- 把被动捕获导出为 PCAPNG。
- 可选检查 HTTPS 流量，不在宿主或其它沙箱安装信任材料。
- 通过 SandMan 与本地 MCP 服务器暴露有界、可审计的捕获操作。
- 把不可信包、TLS 与 HTTP 解析保持在 SbieDrv 与 SbieSvc 之外。
- 为既有核心保留 Windows 7 支持。需要更新 WFP API 的功能必须在运行时能力门控。

## 非目标

- 机器级包嗅探器。
- 保证解密证书固定、相互认证、仅 ECH 或应用专属 TLS 实现的 HTTPS。
- 首个版本中的 HTTP/3 解密。
- 经 MCP 的任意命令执行、沙箱删除或无限制配置变更。
- 把包解析器、OpenSSL 或其它大型第三方库加载进 SbieSvc 或内核驱动。

## 既有基础

Sandboxie 已提供若干积木：

- SbieDrv 跟踪沙箱进程创建、进程创建时间、盒名、用户 SID 与 Windows 会话。
- `Sandboxie/core/drv/wfp.c` 维护非分页 PID 查找以用于网络策略，并分类出站 connect 与入站 accept 授权事件。
- SbieDll 为兼容应用实现 TCP SOCKS5 重定向。
- SbieSvc 经其 LPC 端口提供按上下文认证的请求路由。
- QSbieAPI 提供分块 SbieSvc 请求以及 SandMan 侧进程与沙箱模型。

当前 WFP 实现是策略 callout，不是包捕获实现。它注册 ALE 授权层，不消费 `layerData` 或关联流上下文。当前监视环从分页池分配，因此不能在可能运行于 `DISPATCH_LEVEL` 的 WFP 分类路径上写入。

## 安全不变量

以下不变量是发布阻塞项：

1. Box A 的捕获不得包含宿主、Box B 或其它用户的流量。
2. PID 单独永不足够作为身份。归属使用 PID 加进程创建时间，以及盒名、SID 与 Windows 会话组成的沙箱身份元组。
3. 任何代理重定向前先评估原始网络策略。代理不能把被拒绝的目的地变成允许的目的地。
4. 捕获 broker 只接受携带有效 WFP 重定向上下文或其它服务签发、一次性、绑定到原始进程与目的地的能力连接。
5. broker 故障不得在 HTTPS 检查模式下静默恢复直连网络访问。
6. 宿主证书存储与其它沙箱绝不信任捕获 CA。
7. CA 私钥、生成的叶子私钥与捕获正文不可被沙箱化进程读取。
8. SbieSvc 不解析包载荷、TLS 记录、HTTP 消息或 MCP JSON。
9. 内核捕获缓冲区有界。被动捕获溢出递增丢弃计数器，而非阻断网络流量或分配无界内存。
10. 所有服务请求使用 LPC 提供的调用方身份。请求载荷不能断言受信任的 PID、SID、会话或所有权身份。

## 架构

```text
沙箱化进程
    |
    +-- ALE 审计 ------> SbieDrv WFP --> 有界非分页队列
    |                                      |
    |                                      v
    |                               SbieSvc CaptureServer
    |                                      |
    |                                      v
    |                               QSbieAPI / SbieMcp
    |
    +-- 未来载荷 -> SbieDrv WFP --> SbieCaptureBroker --> PCAPNG
    |
    +-- HTTPS 路径 ----> WFP connect 重定向 --> SbieCaptureBroker
                                                  |          |
                                                  |          +--> HTTP/HAR 事件
                                                  +-------------> 上游 TLS

SandMan / SbieMcp
    |
    +--> QSbieAPI --> SbieSvc CaptureServer --> 会话与授权控制
```

### SbieDrv

驱动拥有权威进程归属与强制。Phase 2 后端观察既有 ALE 授权 callout 而不改变它们的允许/拒绝结果。后续 WFP 层为：

- ALE connect 与 receive/accept 已实现，用于策略与有界连接尝试元数据。
- ALE flow-established 用于关联稳定流上下文。
- 流层用于双向 TCP 应用字节。
- 数据报数据层用于 UDP 与 QUIC 数据报。
- 传输层用于 PCAPNG 输出需要包边界与头之处。
- Connect-redirect 层用于 OS 支持所需重定向 API 处的透明本地 HTTPS 检查。

流上下文将只包含热路径所需固定大小数据：

```text
捕获会话 id
盒身份 hash
进程 id
进程创建时间
地址族与协议
本地与远端端点
方向
策略 generation
```

驱动不执行 TLS 或应用协议解析。

### SbieSvc CaptureServer

`CaptureServer` 是独立 SbieSvc 消息族。它拥有：

- 线格式版本协商与能力报告；
- 调用方与目标授权；
- 捕获会话标识符与所有权；
- 后端生命周期与健康状态；
- 事件游标、计数器与导出句柄中介；
- 拥有客户端断连时的清理。

LPC 端口可被不可信本地进程连接，因此每个操作执行自身授权。初始策略刻意收窄：

- 沙箱化调用方不能创建或控制捕获；
- 普通调用方只能以调用方的确切用户 SID 与 Windows 会话为目标已启用沙箱；
- PID 目标当前必须属于该沙箱、SID 与会话；
- 线格式版本 1 中拒绝跨用户与跨会话访问，包括提权调用方；
- stop 与 status 操作要求原始所有者进程与进程创建时间；管理员恢复保留给后续显式 API。

控制面支持查询、启动、停止、状态、所有者作用域列举与有界连接事件排空。调用方身份从 LPC 客户端安全上下文获取，并与活动主进程令牌及进程创建时间交叉核对。沙箱启用以调用方的 SID 与会话评估，而非 LocalSystem 服务身份。包与 HTTPS 能力保持关闭。

捕获请求独立于历史最大 LPC 消息大小设上限。活动会话有每所有者与全局限制，停止的会话历史在固定边界内淘汰。

### SbieCaptureBroker

broker 是已签名、独立构建的进程。它以能完成工作所需的最低特权用户令牌运行，并置于 SbieSvc 控制的 kill-on-close job 中。

计划职责：

- 排空驱动捕获记录；
- 写 PCAPNG 与索引元数据；
- 为显式启用的 HTTPS 会话终止下游与上游 TLS；
- 先解析 HTTP/1.1，后续阶段再解析 HTTP/2 与 WebSocket；
- 执行正文大小、文件大小、时间与内存限制；
- 默认脱敏敏感头；
- 通过继承或复制句柄向 CaptureServer 暴露记录。

broker 可执行文件路径固定相对 Sandboxie 安装目录。客户端不能为 LocalSystem 启动提供可执行文件路径或命令行。

### QSbieAPI 与 SandMan

QSbieAPI 暴露类型化捕获请求，并把版本化线格式结构规范化为 Qt 值类型。SandMan 接收专属捕获模型与视图，而非复用 `CTraceEntry`，因为包流、HTTP 交换与丢弃记录记账有不同身份与保留规则。

UI 将区分：

- 连接审计；
- 被动 PCAPNG 捕获；
- HTTPS 检查。

不支持的功能基于服务能力标志保持禁用。

### MCP 服务器

`SbieMcp` 是独立、普通用户进程。它使用 QSbieAPI，绝不直接打开驱动设备或与特权捕获后端对话。

首个传输是 MCP stdio：

- stdin 与 stdout 只含换行分隔的 JSON-RPC 消息；
- 诊断走 stderr；
- 不创建监听套接字；
- 输入消息有固定大小限制，工具参数在运行时验证而非仅依赖通告的 JSON Schema；
- 在 initialize 响应之后跟随 `notifications/initialized` 之前拒绝正常操作；
- 改变捕获的工具保留 SbieSvc 所有权与授权检查。

初始工具与资源刻意有界：

```text
工具
  sandboxie_list_boxes
  sandboxie_list_processes
  capture_capabilities
  capture_start
  capture_stop
  capture_status
  capture_read_events

资源
  sandboxie://boxes
  sandboxie://boxes/{box}/processes
  capture://sessions
  capture://sessions/{id}/summary
```

包列表与 HTTP 正文在其后端实现后使用游标或偏移分页。整个捕获文件导出到用户选择的文件，而非嵌入单个 MCP 响应。

## 控制线格式版本 1

SbieSvc 消息族从 `0x2000` 开始。低字节 `0xFF` 由 PipeServer 保留用于进程断连通知。

每个版本化请求以：

```c
MSG_HEADER h;
ULONG wire_version;
ULONG struct_size;
```

开头。

规则：

- 线格式字段使用定宽 Windows 整数类型；
- 64 位字段显式对齐到 8 字节；
- 结构不含指针、`HANDLE`、`size_t`、C++ `bool` 或编译器相关枚举值；
- 字符串仅对 v1 沙箱名使用固定大小；未来可变数据使用带检查的偏移与长度对；
- 服务接受已知最小 `struct_size`，且当线格式版本受支持时忽略未知尾随字段；
- 客户端验证通告的回复长度与实际收到字节数；
- 未知操作返回 `STATUS_INVALID_SYSTEM_SERVICE`；
- 后端不可用返回 `STATUS_DEVICE_NOT_READY` 或会话错误状态，绝不返回成功的活动捕获状态。

## HTTPS 检查

### 首选路径

在受支持系统上，SbieDrv 用 WFP ALE connect 重定向到 broker 拥有的随机 loopback 监听器。重定向上下文把原始目的地绑定到沙箱身份、进程 generation、策略 generation 与会话。broker 把 WFP 重定向记录复制到其上游套接字，以防止递归重定向并保持流关系。

### Windows 7 路径

核心仍支持 Windows 7，但首选路径使用的现代重定向句柄 API 不可用。首个兼容回退是既有注入 SOCKS5 路径，辅以服务签发、一次性、绑定原始目的地的授权。该回退活动期间直连出口必须保持阻断。

### 证书隔离

- 为每次捕获会话或一次性捕获沙箱生成唯一 CA。
- 私钥保留在沙箱之外。
- 只把 CA 公钥证书导入选定沙箱的虚拟当前用户 Root store。
- 通过在该沙箱内、以原始用户令牌启动的辅助进程执行导入。
- 捕获结束时移除沙箱化 CA，并在目标应用信任缓存需要时要求其重启。
- 通过注册表与文件哈希验证宿主证书存储与 Firefox NSS 数据库不变。

### 协议矩阵

| 能力 | 计划支持 |
| --- | --- |
| 基于 TCP 的 TLS 1.2 | HTTPS MVP |
| 基于 TCP 的 TLS 1.3 | HTTPS MVP，用构建变量中的捆绑 OpenSSL 版本 |
| HTTP/1.1 | HTTPS MVP（chunked + keep-alive） |
| HTTP/2 与 HPACK | Phase 5（手写编解码器；下游终止，h1 或 h2 上游） |
| 基于 HTTP/1.1 的 WebSocket | Phase 5（升级检测 + 透明字节隧道） |
| gRPC 帧 | Phase 5（元数据 + trailers + 消息计数）；protobuf 解码需要描述符 |
| HTTP/3 与 QUIC 解密 | 首个版本不做；仅被动 UDP 捕获 |
| TLS key-log（SSLKEYLOGFILE） | Phase 5（opt-in，调用方打开的句柄） |
| 证书固定 | 预期 MITM 失败；保留被动捕获 |
| 无其它可信主机名来源的 ECH | 不保证 |
| 相互 TLS | 透明 MITM 不保证 |
| Firefox/NSS 信任 | Phase 5（boxed profile opt-in：enterprise roots 或 certutil） |

## 数据保留与脱敏

默认隐私保护：

- 正文之前先捕获元数据；
- `Authorization`、`Proxy-Authorization`、`Cookie`、`Set-Cookie` 与常见 API 密钥头被脱敏；
- 正文要求显式 opt-in；
- 每正文、每流、每会话与输出文件限制为强制；
- 捕获文件在调用方安全上下文中创建，或通过调用方打开、SbieSvc 复制的文件句柄创建；
- LocalSystem 绝不创建或覆盖任意客户端提供的路径。

## 交付计划

### Phase 0：Spike 与安全证明

- 用 PID 复用测试证明稳定沙箱流归属。
- 证明来自 WFP 分类路径的非分页有界缓冲。
- 证明 Windows 8+ connect 重定向与递归防止。
- 证明仅沙箱证书信任，宿主注册表与 NSS 文件 diff 干净。

退出标准：进程更替、IPv4/IPv6 与 broker 故障下 Box A、Box B 与宿主流量仍可区分。

### Phase 1：版本化控制面

- 添加 CaptureServer 线格式版本 1。
- 添加调用方授权与所有者作用域会话生命周期。
- 添加 QSbieAPI 包装。
- 添加暴露能力与生命周期操作的 MCP stdio 骨架。
- 在其后端存在前保持包与 HTTPS 能力位关闭。

退出标准：非沙箱化同 SID、同会话客户端可创建、查询、列举并停止自己的无后端会话；沙箱化、跨用户与跨会话调用方被拒绝。畸形线格式消息与畸形 MCP 参数不能把进程作用域请求扩大为盒作用域请求。

### Phase 2：连接审计

- 添加专属固定容量非分页连接事件队列。已实现。
- 每个事件关联盒、SID、Windows 会话、PID 与进程创建时间。已实现。
- 只允许经认证的 SbieSvc 破坏性排空有界批次并经 QSbieAPI 与 MCP 暴露。已实现。
- 添加 SandMan 连接视图。已实现。
- 完成实机驱动 Box A/Box B/宿主隔离与进程更替测试。隔离与进程更替已在个人测试宿主验证。更替运行证明盒作用域会话中出现后来的盒内子进程、宿主流量不出现、进程作用域会话保持绑定 PID 加进程创建时间、目标退出后的后来的盒内进程不泄漏进来。该次运行未观察到 OS 级 PID 复用。

退出标准：只有选定沙箱连接出现，包括后来的子进程，且丢弃事件记账正确。

### Phase 3：被动包捕获

- 添加 TCP 流、UDP 数据报与传输捕获层。
- 产出带 IPv4/IPv6 与每进程元数据的 PCAPNG。
- 添加快照长度、文件轮转与时间限制。

退出标准：Wireshark 打开输出且无无关流量。

### Phase 4：HTTPS MVP

- 添加 connect 重定向与 broker 认证。
- 添加仅沙箱 CA 生命周期。
- 支持 TLS 1.2/1.3 与 HTTP/1.1。
- 添加 HAR 导出与默认脱敏。

退出标准：代表性 Chromium、WinHTTP 与 curl 流量被解码；固定失败被报告；broker 故障不泄漏直连流量。

### Phase 5：协议与兼容性扩展

- HTTP/2、HPACK、WebSocket 与 gRPC 帧。
- Firefox/NSS 兼容性。
- 为选定固定应用提供可选 TLS key-log 适配器。
- 评估但不承诺 QUIC 终止与 HTTP/3 解析。

### Firefox/NSS 信任（boxed profile，opt-in）

Firefox 默认不读 Windows Root store，因此 boxed Firefox 即使执行 `--https-import-host-root` 后也不会自动信任 Phase 4 会话 CA。存在两种 opt-in 机制，均仅限 boxed profile（绝不触碰宿主 Firefox profile 或宿主 NSS 数据库）：

1. **Enterprise roots（首选）。** 让 Firefox 指向宿主 Root store（会话 CA 已在那里）：

   ```
   SbieCapture.exe --firefox-enterprise-roots <boxed-profile-dir>
   ```

   这会把 `user_pref("security.enterprise_roots.enabled", true);` 写入 profile 的 `user.js`（幂等；`prefs.js` 保持不动）。

2. **NSS cert9.db 注入（更强，需要 NSS 工具）。** 用 `certutil` 把 CA 公钥证书直接导入 profile 的 `cert9.db`：

   ```
   SbieCapture.exe --firefox-import-ca <boxed-profile-dir> \
       --import-ca-path <ca-public.pem> [--certutil <path-to-certutil>]
   ```

   `certutil` 默认从 PATH 解析；修改 `cert9.db` 时 profile 必须关闭。

任一种改动后 Firefox 必须（重新）启动。移除则恢复 profile 的 `user.js` / `cert9.db` 并重启 Firefox。宿主 profile 与宿主 NSS 哈希必须保持不变（已在实机隔离套件中验证）。

## 验证矩阵

必需验证包括：

- 宿主、其它沙箱、其它用户与其它会话排除；
- 进程退出与 PID 复用；
- 未来子进程包含与仅 PID 目标行为；
- IPv4、IPv6、TCP、UDP、loopback 与代理路径；
- 重定向前后的既有 `NetworkAccess` 决策；
- broker 崩溃、SbieSvc 重启、BFE 重启与策略重载；
- VPN、防火墙、杀毒与其它 WFP 重定向 callout 共存；
- 缓冲耗尽与输出文件耗尽；
- 宿主证书存储与 Firefox profile 完整性；
- 畸形捕获记录、TLS 记录、HTTP 消息与压缩正文；
- Win32、x64、ARM64 与受影响的 ARM64EC 构建配置；
- 缺少新 WFP API 时的 Windows 7 加载兼容性。

## 变更隔离

因为 SbieDrv 与驱动/服务协议是安全边界，工作拆分为可独立审查的变更：

1. 架构文档与控制面 ABI；
2. QSbieAPI 与 MCP 控制客户端；
3. 驱动连接审计队列；
4. 被动包后端；
5. HTTPS broker 与证书生命周期；
6. 更高层协议解析器与 UI。

任何阶段不得在其安全与故障模式测试通过前通告能力。

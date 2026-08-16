# Phase 3：被动包捕获实施计划

> **给 Hermes 的指示：** 仅在用户接受本计划后实施；如果用户需要常规的阶段门控，则在本文件单独提交之后实施。不要把实现混入计划提交。不要执行 `git reset` / `git clean`。不要开始 HTTPS / Phase 4。

**目标：** 交付 `Docs/SandboxCaptureMcp.md` 中的完整 Phase 3：TCP 流、UDP 数据报与传输捕获、带 IPv4/IPv6 与每进程元数据的 PCAPNG、快照长度、文件轮转、时间限制，以及 SandMan Packet Capture 视图。退出标准：Wireshark/tshark 可打开文件，且其中不含宿主 / 其它盒 / 其它 SID / 其它会话的流量。

**架构：** Phase 2 ALE 连接审计完全保持原样。新增第二条仅检查的 WFP 路径：`ALE_FLOW_ESTABLISHED` 绑定固定流上下文；`INBOUND/OUTBOUND_TRANSPORT` 把包形字节复制进有界非分页环；`STREAM` 与 `DATAGRAM_DATA` 把应用字节复制进并行的有界环。`SbieCaptureBroker`（`SbieCapture.exe`）是唯一载荷消费者与唯一 PCAPNG 写入器。`SbieDrv` / `SbieSvc` 绝不解析包、TLS 或 HTTP 字节。能力位在 Box A / Box B / 宿主隔离对实机驱动通过之前保持关闭。

**技术栈：** 现有 SbieDrv WFP（`FwpsCalloutRegister1`，Windows 7）、双编译 C 队列、SbieSvc CaptureServer LPC（`MSGID_CAPTURE` 0x2000）、QSbieAPI 非虚包装、`SandboxieTools` 下新 `SbieCapture.exe`、SandMan Qt 6.8.3 MSVC 视图。个人宿主：仅 x64、WDK 测试证书、无官方签名、无 ARM64 完整链接。

---

## 已锁定的决策

以下不是开放问题。实现过程中不得重新争论。

1. **传输层是唯一 PCAPNG 来源。** 流/数据报记录不得作为额外包写入。否则 UDP 会出现两次。
2. **新的 classify 函数。** 不要复用 `WFP_classify`。该函数注册在 `FWP_ACTION_CALLOUT_TERMINATING` 的 ALE 过滤器上并写允许/拒绝。包/流/传输/数据报 callout 是 `FWP_ACTION_CALLOUT_INSPECTION`，绝不改变裁决。
3. **无流上下文的入站不捕获。** 不要从包中臆造 PID。把该 classify 当作"不捕获"丢弃，而非网络阻断。
4. **独立的包/流队列。** 不要扩大或复用 `CAPTURE_QUEUE_RECORD`（80 字节）或 `API_CAPTURE_READ`。连接审计排空仍仅限 SbieSvc 且为 32×80 字节批次。
5. **对载荷而言 SbieSvc 只是控制面。** 它启停会话、授权所有者、把调用方的文件句柄与驱动 section 句柄复制进 broker。它不 memcpy 包字节也不解析它们。
6. **broker 不打开 `\\Device\\SandboxieDriverApi`。** SbieSvc 仍是唯一驱动客户端。broker 映射它继承的 section 句柄。
7. **调用方打开第一个输出文件。** LocalSystem 绝不创建或覆盖客户端提供的路径。轮转文件由 broker 在调用方令牌下创建于该第一个文件的同一目录。
8. **能力位保持关闭**（`CAPTURE_CAP_PACKET_CAPTURE`、`CAPTURE_CAP_PCAPNG_EXPORT`）直到实机隔离与进程更替测试通过。此前公开启动路径上 `CAPTURE_MODE_PACKETS` 保持 `STATUS_NOT_SUPPORTED`（仅在 bring-up 需要时允许在显式内部标志后做私有/测试启动，且不得通告）。
9. **新 SandMan 视图。** `CPacketCaptureView` / `CPacketCaptureWindow`。不要复用 `CCaptureView` 或 `CTraceEntry`。除新增*独立* Packet Capture 动作外，不改变 Connection Audit 行为、过滤器、CSV 或上下文菜单。
10. **QSbieAPI 保持非虚。** 向 `SSbieCaptureStart` 追加字段 / 追加新非虚方法。不要在 `CSbieAPI` 上插入虚函数。
11. **Wire v1 尾部字段。** 除非不可避免的破坏性变更，否则不要提升 `CAPTURE_WIRE_VERSION`。旧 `CAPTURE_START_REQ`（112 字节）必须仍能启动连接审计。
12. **个人宿主约束：** 无 ARM64 完整链接、无官方驱动签名、无 `git reset` / `git clean`、保持 `NetworkEnableWFP=y`、不使用已安装的 `Start.exe`、不把解析器/OpenSSL 加载进 `SbieDrv`/`SbieSvc`。用户已明确授权 Slice 8 的 x64 驱动更换、重启与受控 `DefaultBox` 改动；每次实机改动仍需回滚路径与重启后 hash 检查。

---

## 当前基线（不得回归）

| 部件 | 现状 |
| --- | --- |
| ALE AUTH CONNECT/RECV_ACCEPT v4/v6 | 策略 + 80 字节 `connect_attempt` / `accept_attempt` |
| `layerData` / `flowContext` | 忽略（`UNREFERENCED_PARAMETER`） |
| `WFP_flow_delete` | Stub 成功 |
| 传输 5 元组索引 | 已在 `GetNetwork5TupleIndexesForLayer`，未用 |
| `capture_network.c` | 仅 IPv4 编码 |
| 驱动队列 | 256 × 80 字节、非分页、覆盖最旧 + 丢弃 |
| SbieSvc start | `mode & ~CONNECTIONS` → `STATUS_NOT_SUPPORTED` |
| 能力位 | WFP 就绪时 `CONTROL` + `CONNECTION_AUDIT` |
| Broker | 不存在 |
| SandMan | 仅 Connection Audit |
| MCP `packetCapture` | false |

实机驱动的连接审计隔离与进程更替已在本宿主通过。把这些 e2e 脚本视为每次驱动更换后的回归门。

---

## 数据路径

```text
boxed TCP/UDP
    |
    +-- 既有 ALE AUTH -----> WFP_classify -----> 80 字节审计队列
    |                                                 |
    |                                                 v
    |                                          SbieSvc CaptureServer
    |                                                 |
    |                                                 v
    |                                          Connection Audit UI / MCP
    |
    +-- ALE FLOW_ESTABLISHED --> WFP_flow_establish_classify
    |                               FwpsFlowAssociateContext(固定 ctx)
    |
    +-- TRANSPORT in/out -------> WFP_packet_classify
    |                               复制 NBL <= snaplen --> 包环
    |
    +-- STREAM / DATAGRAM ------> WFP_appdata_classify
                                    复制应用字节 <= snaplen --> 流环

SbieSvc CaptureServer
    |-- 授权所有者（SID+session、盒启用、PID+createTime）
    |-- API_CAPTURE_CONTROL 启动包会话
    |-- 在 kill-on-close job 中生成 SbieCapture.exe，调用方令牌
    |-- DuplicateHandle(file) + DuplicateHandle(section) 进 broker
    |-- stop / 失败 / 所有者断连 => 终止 job

SbieCapture.exe
    |-- 映射包环 + 流环
    |-- 把 TRANSPORT 记录写为 PCAPNG EPB（LINKTYPE_RAW / 101）
    |-- 附加每进程元数据（PID、createTime、box、SID、session）
    |-- 按大小与时间轮转 / 停止
    |-- 绝不解析 TLS/HTTP
```

### 流上下文（固定、非分页）

```text
捕获 generation / 策略 generation
进程 id
进程创建时间
会话 id
盒名 hash 或内联盒名（BOXNAME_COUNT）
SID 字符串或 SID hash
地址族、协议
本地/远端地址[16]、本地/远端端口
方向
```

在既有进程/WFP 锁下复制身份快照、释放该锁、然后关联上下文。`WFP_flow_delete` 释放上下文。限制存活流上下文（建议 4096）。溢出时：不关联、不捕获该流、不触碰允许/拒绝。

### 包记录（新队列）

固定大小 = 头 + `CAPTURE_PACKET_SNAPLEN_MAX`（1514）。

头必须包含：序号、时间戳、PID、createTime、session、AF、proto、方向、本地/远端端点、`original_length`、`captured_length`、层（`transport` / `stream` / `datagram`）、loopback、标志。载荷字节随后。会话 snaplen 可小于最大值；未用尾部保持零。

建议：

- 包环容量 4096
- 流环容量 2048
- 最大并发包会话：每所有者 2 个，全局 4 个
- 默认 snaplen 256（头 + HTTP 行 / ClientHello SNI）
- 允许 snaplen 64..1514
- 默认最大文件 64 MiB
- 默认最大时间 300 s
- `rotate_count = 0` 表示到达大小限制即停止；`N` 保留最近 N 个文件

溢出覆盖最旧记录并饱和 `dropped_count`。绝不阻断网络。除认领预分配环槽外，绝不在 classify 路径上分配。

### 入站传输复制

`layerData` 是 `NET_BUFFER_LIST *`。入站传输 NBL 从传输头开始。用 `FWPS_METADATA_FIELD_IP_HEADER_SIZE`（存在时加传输头大小）回退、复制 `min(snaplen, original)`、恢复。出站通常已含 IP 头。classify 返回后不得保留 NBL。不要克隆并挂起。

流 classify 用 `FWPS_STREAM_CALLOUT_IO_PACKET`。复制后继续。Phase 3 中绝不 `FWPS_STREAM_ACTION_NEED_MORE_DATA`（那属于 Phase 4）。

---

## 控制线格式

保持消息族 `0x2000`。新增：

```text
MSGID_CAPTURE_SET_EXPORT   0x2007
```

`0x20FF` 仍是断连通知。

### `CAPTURE_START_REQ` 尾部字段（既有 112 字节 v1 之后）

```c
ULONG snap_length;       /* 0 = 默认 256 */
ULONG max_file_bytes;    /* 0 = 默认 64MiB */
ULONG max_seconds;       /* 0 = 默认 300 */
ULONG rotate_count;      /* 0 = 到达限制即停止 */
ULONG reserved;
```

旧客户端发送 `struct_size == 112` 且只能启动 `MODE_CONNECTIONS`。新包启动要求扩展尺寸且会话离开 `WAITING_FOR_BACKEND` 前有一次成功的 `SET_EXPORT`。

### `CAPTURE_SET_EXPORT`

调用方相对文件句柄值 + 捕获 id。SbieSvc 从 LPC 客户端进程 `DuplicateHandle`。若句柄不是可写磁盘文件、或进程被沙箱化则拒绝。请求中无路径字符串。

`CAPTURE_SESSION_INFO` 已有 `packet_count`、`byte_count`、`dropped_count`。仅当 UI 需要当前文件索引 / 当前文件字节数时才用尾部字段扩展。倾向把这些放进 status（reserved-后-尾部），使旧 184 字节 info 仍可解析。

不要加"经 LPC 读包"消息。64 KiB LPC 承载不了百度级流量。

---

## 可能变更的文件

### 新增

- `Sandboxie/core/drv/capture_packet.h`
- `Sandboxie/core/drv/capture_packet.c` — 环 + 记录（双编译，驱动 TU 无 `windows.h`）
- `Sandboxie/core/drv/capture_stream.h`
- `Sandboxie/core/drv/capture_stream.c` — 流/数据报环（双编译）
- `SandboxieTools/SbieCapture/SbieCapture.vcxproj`
- `SandboxieTools/SbieCapture/main.cpp`（或 `.c`）— 映射环、写 PCAPNG、轮转、遵守时间/大小
- `SandboxieTools/SbieCapture/pcapng.c` + `pcapng.h` — 无第三方库
- `SandboxieTools/PcapngTests/` — 用户态写入器测试
- `SandboxiePlus/SandMan/Views/PacketCaptureView.h`
- `SandboxiePlus/SandMan/Views/PacketCaptureView.cpp`

### 修改

- `Sandboxie/core/drv/wfp.c` / `wfp.h` — 新 GUID、检查 callout、拆分 classify、实现 `WFP_flow_delete`
- `Sandboxie/core/drv/capture.c` / `capture.h` — 包会话启停、section 对象、不破坏 ALE 会话
- `Sandboxie/core/drv/api_defs.h` — `API_CAPTURE_MAP` 或给 `API_CAPTURE_CONTROL` 扩展映射操作；新打包结构；`C_ASSERT` 尺寸
- `Sandboxie/core/drv/api.c` — 若新增则注册新 API
- `Sandboxie/core/drv/SboxDrv.vcxproj` — 新 ClCompile 条目
- `Sandboxie/core/drv/capture_network.c` / `.h` — 测试需要的 IPv6 编码辅助
- `Sandboxie/core/svc/msgids.h` — `0x2007`
- `Sandboxie/core/svc/capturewire.h` — 尾部启动字段、导出请求/回复、static_asserts
- `Sandboxie/core/svc/CaptureServer.cpp` — 包模式、broker job、句柄复制、就绪前仍 `NOT_SUPPORTED`
- `Sandboxie/core/dll/trace.c` — API 名字符串
- `SandboxiePlus/QSbieAPI/SbieCapture.h` / `SbieAPI.h` / `SbieAPI.cpp`
- `SandboxiePlus/SbieMcp/main.cpp` — 启动参数 + 测试通过前仍隐藏能力
- `SandboxiePlus/SandMan/SandMan.cpp` / `.h` / `SandMan.pri` — View 菜单、日志标签页、盒/进程上下文动作
- `SandboxieTools/CaptureQueueTests/CaptureQueueTests.c` — 包/流队列测试
- `SandboxieTools/SandboxieTools.sln` — 添加 SbieCapture + 测试（x64 Release 必需；ARM64 配置可存在但本宿主不构建）
- `Docs/SandboxCaptureMcp.md` — 后端真实落地后的状态段落
- `CHANGELOG.md` — 在可用 x64 路径存在之后，而非仅计划提交中

### 除非编译强制，否则不触碰

- `CCaptureView.*` 行为
- `WFP_classify` 内部的 `NetworkAccess` 允许/拒绝逻辑
- `DefaultBox` / `Sandboxie.ini` 内容
- 安装器 / 官方签名 / ARM64 工程默认值

---

## 逐 slice 计划

按此顺序实现。每个 slice 是一个逻辑提交。Slice 8 之前不要通告能力。

### Slice 0 — 仅计划

本文件。无代码。

### Slice 1 — 用户态 PCAPNG 写入器 + 测试（无驱动）

**目标：** 把合成包记录转成 tshark 可打开文件的有界写入器。

**文件：** `SandboxieTools/SbieCapture/pcapng.*`、`SandboxieTools/PcapngTests/`

**行为：**

- SHB + IDB（`LINKTYPE_RAW` = 101）
- 每个传输记录一个 EPB
- EPB 注释或自定义选项：`pid=… createTime=… box=… sid=… session=…`
- 遵守 Snaplen；`original_length` 与 `captured_length` 都写入
- 轮转：关闭文件、打开下一个名字、写全新 SHB+IDB
- 时间/大小停止
- 无协议解析

**验证：**

```text
cl /nologo /W4 /WX /DUNICODE /D_UNICODE PcapngTests.c pcapng.c
PcapngTests.exe
tshark -r <out>.pcapng -T fields -e frame.number -e ip.src -e ip.dst -e tcp.dstport
```

预期：tshark 退出 0，只有注入的 5 元组，无额外包。

### Slice 2 — 双编译包/流队列（尚无 WFP）

**目标：** 与 `capture_queue.c` 相同双编译规则的固定容量非分页安全环，带 push/drain/drop。

**文件：** `capture_packet.*`、`capture_stream.*`、`CaptureQueueTests.c`、`SboxDrv.vcxproj`

**规则：** 驱动 TU 不得包含 `windows.h`。检测 `_NTDDK_` / `_NTIFS_` / `_WDMDDK_`。`/W4 /WX` 用户态测试。

**验证：** 溢出饱和 drop、顺序保留、snaplen 钳制、剩余计数、重置。

### Slice 3 — 线格式 + QSbieAPI + MCP 形态（仍 NOT_SUPPORTED）

**目标：** 扩展启动字段、`MSGID_CAPTURE_SET_EXPORT`、QSbieAPI 结构/方法、MCP 参数验证。服务对 `MODE_PACKETS` 仍返回 `STATUS_NOT_SUPPORTED`。能力位仍关闭。

**文件：** `capturewire.h`、`msgids.h`、`CaptureServer.cpp`（仅解析并拒绝路径）、`SbieCapture.h`、`SbieAPI.cpp`、`SbieMcp/main.cpp`

**验证：** 既有连接审计启动/读取对当前实机驱动仍可用。新包启动仍 `0xC00000BB`。`static_assert` 尺寸更新。`CSbieAPI` 无 vtable 变化。

### Slice 4 — SbieCapture.exe broker 进程（尚无实机包）

**目标：** 独立构建的 x64 可执行文件。接受继承句柄（section + 第一个文件）。以调用方身份运行。执行大小/时间/轮转。section 关闭或 stop 事件发出时退出。

**文件：** `SandboxieTools/SbieCapture/*`、`SandboxieTools.sln`

**SbieSvc 生成规则（Slice 6 实现，此处设计）：**

- 路径仅限安装目录 `SbieCapture.exe`
- 客户端不能提供 exe 路径或命令行
- Kill-on-close job
- 调用方主令牌，而非 LocalSystem
- stdin/stdout 不是协议面

**验证：** 用 Slice 2 记录的假映射环做单元/harness，产出 tshark 可读 PCAPNG 并轮转。

### Slice 5 — 驱动检查 callout（危险 slice）

**目标：** 注册流 + 传输 + 流 + 数据报层。复制进新环。不改变 ALE 策略。

**文件：** `wfp.c`、`wfp.h`、`capture.c`、`api_defs.h`

**必需拆分：**

| Callout | 层 | 动作类型 | Classify |
| --- | --- | --- | --- |
| 既有 send/recv | ALE AUTH CONNECT/RECV_ACCEPT | TERMINATING（不变） | `WFP_classify` 不变 |
| 新 | ALE FLOW_ESTABLISHED v4/v6 | INSPECTION | 仅关联上下文 |
| 新 | INBOUND/OUTBOUND TRANSPORT v4/v6 | INSPECTION | 复制 NBL 到包环 |
| 新 | STREAM v4/v6 | INSPECTION | 复制应用字节到流环 |
| 新 | DATAGRAM_DATA v4/v6 | INSPECTION | 复制应用字节到流环 |

新 GUID：延续既有 `0bf56435-71e4-4de7-bd0b-1af0b4cbb8f6` 族；不复用 ALE GUID。

`WFP_RegisterCallout` 目前硬编码 `WFP_classify` 与 `FWP_ACTION_CALLOUT_TERMINATING`。加参数化注册器。在 `WFP_Uninstall_Callbacks` 中注销全部新 id。

过滤器身份：复用 `CaptureFilter_Matches`（盒 + SID + session + PID + createTime + loopback 标志）。仅 PID 永远不够。

**验证（本 slice 仅编译，除非已计划排队重启）：**

- x64 `SbieDrv.sys` 以 WDK 测试签名构建
- 用户态队列测试仍通过
- `git diff --check` 干净
- 不要声称"能抓包了"

实机加载使用 `sandboxie-core-build` `references/runtime-connection-audit.md` 中的既有 `MoveFileEx(..., 5)` + 重启配方。重启后确认 SHA-256。然后立即重跑连接审计 `e2e_silent.py`——若回归，先停止并修复再启用包启动。

### Slice 6 — CaptureServer broker 生命周期

**目标：** `MODE_PACKETS` 启动创建驱动包会话、映射 section、复制句柄、生成 `SbieCapture.exe`、仅当 broker 存活时进入 `RUNNING`。所有者断连 / stop / broker 崩溃 → `STOPPED` / `FAILED`、job 击杀、环拆除。网络策略不变。

**文件：** `CaptureServer.cpp`、`api_defs.h`、`capture.c`

**授权：** 与 Phase 2 相同。沙箱化调用方不能启动。Cross-SID / cross-session 拒绝。进程作用域绑定 PID+createTime。盒作用域要求 `INCLUDE_FUTURE_PROCESSES`。规范盒名（`DefaultBox`，而非 `defaultbox`）。

**验证：** 无导出句柄的启动保持 `WAITING_FOR_BACKEND` 或 fail closed。缺 `SbieCapture.exe` → `FAILED`，而非成功的运行中捕获。无 broker 时连接审计会话仍可启动。

### Slice 7 — SandMan Packet Capture 视图

**目标：** 可启动包会话、显示有界包表并指向 PCAPNG 输出的独立视图。

**文件：** `PacketCaptureView.*`、`SandMan.cpp`、`SandMan.h`、`SandMan.pri`

**UI 契约：**

- `View → Packet Capture` 与一个日志标签页，与 Connection Audit 分离
- 盒下拉用 `I.value()->GetName()`，绝不用 `I.key()`
- 盒上下文菜单：Packet Capture（整盒 + 未来进程）
- 进程上下文菜单：仅该 PID+createTime 的 Packet Capture
- 控件：snaplen、最大时间、最大文件大小、轮转数、包含 loopback
- Start *之前*用户选择输出文件（这样 QSbieAPI 可传句柄）
- 表列：时间、PID、进程、proto、src、dst、原始长度、捕获长度
- 有界 UI 队列（与 Connection Audit 同思路：限制待处理、时间预算刷新）。表中无 hex dump
- 状态：包数 / 字节数 / 丢弃数 / 当前文件 / "TLS 为密文；不是 HTTPS 检查"
- Save 即 broker 已在写的 PCAPNG，而非元数据 CSV
- 能力位开启（Slice 8）前隐藏或禁用 Start。此前视图可存在但不得假装后端就绪

`SandMan.exe` **和** `QSbieAPI.dll` **和** `SbieCapture.exe` 一起部署。Community `vcvars64.bat`，而非 `qmake_plus.cmd`。

### Slice 8 — 实机隔离，然后能力位

**目标：** 在个人宿主机上证明安全不变量，然后才通告 `packetCapture` / `pcapngExport`。

**测试（静默盒内 runner，非 `Start.exe`）：**

1. 连接审计回归：`e2e_silent.py` 仍 `eventCount > 0`。
2. Box A curl 到 `1.1.1.1`、Box B curl 到 `8.8.8.8`、宿主 curl 到 `9.9.9.9`。每个 PCAPNG 只含自己的 PID、createTime 与远端。宿主 PID 绝不出现。
3. 进程作用域会话：后来的盒内子进程不出现。目标退出后，复用 PID 的新盒内进程仍被排除（createTime 不匹配）。
4. 盒作用域会话：后来的子进程*确实*出现。
5. Loopback 默认排除，加标志后包含。
6. IPv4 TCP 与 UDP。驱动中注册 IPv6；仅当本宿主实际跑过 IPv6 目标才声称 IPv6 e2e。
7. Snaplen：捕获长度 ≤ snaplen、原始长度保留、tshark 仍打开文件。
8. 大小限制 + `rotate_count=0` 停止。`rotate_count>=1` 产出第二个文件且 tshark 也能打开。
9. 时间限制停止会话。
10. 环溢出：丢弃计数增加、网络仍工作、无蓝屏。
11. Broker 击杀：会话 `FAILED`、无直接策略变化、ALE 审计仍工作。
12. Cross-SID / cross-session 启动仍被拒绝。

**实机证据（2026-08-15，x64，本宿主）：** 第 1–2 项与第 4–12 项通过。第 3 项"后来的盒内子进程不出现"通过（进程作用域 PCAP 注释只含目标 PID+createTime）。未观察到复用 PID 碰撞；后来的子进程用了不同 PID。`CAPTURE_PACKET_CAPTURE_RELEASE_GATE` 保持 `1`，使健康后端可通告 `packetCapture`/`pcapngExport`。不要将该门设为 `0`——那会把包启动编译回 `STATUS_NOT_SUPPORTED`。

包后端健康时能力位开启。MCP `packetCapture` 为 true。SandMan Start 可启用。HTTPS 仍超出范围。SandMan 不再构造 Qt 私有 `QAbstractFileEngineHandler`；归档解压到缓存目录。

---

## 验证命令（个人宿主）

构建 / 部署遵循 `sandboxie-core-build` `references/x64-official-build.md` 与 `references/runtime-connection-audit.md`。

- 驱动更换：签名 x64 `SbieDrv.sys`、`MoveFileEx` 标志 `5`、重启、比较 SHA-256。不要在 `KmdUtil stop` 上循环。
- `SbieSvc` 可不重启直接重启动；驱动通常不行。
- Qt：Community `vcvars64.bat` + `C:\Users\Wuldas\.AA\Qt\6.8.3\msvc2022_64`。
- Phase 2 已用的证据目录：`%LOCALAPPDATA%\Temp\hermes-sandbox-capture-red\`。
- tshark 经本地 Wireshark 安装 / `mcp__wireshark__*` 工具。
- 每个 slice `git diff --check`。
- 只报告实际构建过的架构（x64）。

---

## 明确排除在范围之外（Phase 4+）

- WFP connect-redirect、仅沙箱 CA、TLS MITM、HAR、明文 HTTP 头脱敏
- 任何 Sandboxie 进程中的 OpenSSL
- HTTP/2、HPACK、WebSocket、gRPC、HTTP/3 解密
- 机器级嗅探
- 官方 EV 签名、ARM64 完整链接、安装器打包
- 改变 `NetworkAccess` 语义使捕获可绕过拒绝

---

## 风险

| 风险 | 缓解 |
| --- | --- |
| 在传输层复用 `WFP_classify` 意外 TERMINATE / 阻断 | 独立检查 classify；包路径上绝不写 `classifyOut->action` |
| 入站 PID 缺失 → 宿主或错盒泄漏 | 需要流上下文；无上下文 ⇒ 不捕获 |
| LPC 排空载荷 | 不用。映射环 + broker |
| 百度级溢出 / UI 冻结 | 4096 槽环、丢弃计数、有界 SandMan 表、默认 snaplen 256 |
| `SbieSvc` 以 SYSTEM 复制载荷 | 禁止。broker 以调用方身份运行 |
| 轮转路径穿越 | broker 用调用方令牌 + 调用方打开文件所在目录 |
| 新 callout 后连接审计回归 | e2e_silent / 隔离 / 更替在能力位前是硬门 |
| `defaultbox` 对比 `DefaultBox` | 下拉与 MCP 发送 `GetName()` |
| `KmdUtil stop` 循环 | 仅 DELAY_UNTIL_REBOOT |
| 编译后就声称包捕获 | 能力位与用户可见文案在 Slice 8 前保持关闭 |

---

## 开放问题（不阻塞计划）

无改变首个实现的问题。若后续 slice 遇到 Win7 STREAM 检查限制，保留 TRANSPORT+PCAPNG（退出标准）并能力门控 STREAM，而不是在核心路径上扩大到仅 Win8 的 API。

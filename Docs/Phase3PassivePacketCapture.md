# Phase 3: Passive Packet Capture Implementation Plan

> **For Hermes:** Implement only after the user accepts this plan and, if they want the usual stage gate, after this file is committed alone. Do not mix implementation into the plan commit. Do not `git reset` / `git clean`. Do not start HTTPS / Phase 4.

**Goal:** Deliver the full Phase 3 in `Docs/SandboxCaptureMcp.md`: TCP stream, UDP datagram, and transport capture, PCAPNG with IPv4/IPv6 plus per-process metadata, snap length, file rotation, time limits, and a SandMan Packet Capture view. Exit: Wireshark/tshark opens the file and it contains no host / other-box / other-SID / other-session traffic.

**Architecture:** Keep Phase 2 ALE connection-audit exactly as-is. Add a second, inspect-only WFP path: `ALE_FLOW_ESTABLISHED` binds a fixed flow context; `INBOUND/OUTBOUND_TRANSPORT` copies packet-shaped bytes into a bounded nonpaged ring; `STREAM` and `DATAGRAM_DATA` copy application bytes into a parallel bounded ring. `SbieCaptureBroker` (`SbieCapture.exe`) is the only payload consumer and the only PCAPNG writer. `SbieDrv` / `SbieSvc` never parse packet, TLS, or HTTP bytes. Capability bits stay clear until Box A / Box B / host isolation passes against a live driver.

**Tech Stack:** Existing SbieDrv WFP (`FwpsCalloutRegister1`, Windows 7), dual-compile C queues, SbieSvc CaptureServer LPC (`MSGID_CAPTURE` 0x2000), QSbieAPI non-virtual wrappers, new `SbieCapture.exe` under `SandboxieTools`, SandMan Qt 6.8.3 MSVC view. Personal host: x64 only, WDK test certificate, no official signing, no ARM64 full link.

---

## Locked decisions

These are not open questions. Do not re-litigate them while implementing.

1. **Transport is the only PCAPNG source.** Stream/datagram records must not be written as extra packets. Otherwise UDP appears twice.
2. **New classify functions.** Do not reuse `WFP_classify`. That function is registered on `FWP_ACTION_CALLOUT_TERMINATING` ALE filters and writes permit/block. Packet/flow/stream/datagram callouts are `FWP_ACTION_CALLOUT_INSPECTION` and must never change the verdict.
3. **Inbound without flow context is not captured.** Do not invent a PID from the packet. Drop that classify as “no capture”, not as a network block.
4. **Independent packet/stream queues.** Do not enlarge or reuse `CAPTURE_QUEUE_RECORD` (80 bytes) or `API_CAPTURE_READ`. Connection-audit drain stays exclusive to SbieSvc and 32×80-byte batches.
5. **SbieSvc is control plane only for payloads.** It starts/stops sessions, authorizes the owner, duplicates the caller’s file handle and a driver section handle into the broker. It does not memcpy packet bytes and does not parse them.
6. **Broker does not open `\\Device\\SandboxieDriverApi`.** SbieSvc is still the only driver client. The broker maps a section handle it inherited.
7. **Caller opens the first output file.** LocalSystem never creates or overwrites a client-supplied path. Rotation files are created by the broker under the caller’s token in the same directory as that first file.
8. **Capability bits stay off** (`CAPTURE_CAP_PACKET_CAPTURE`, `CAPTURE_CAP_PCAPNG_EXPORT`) until live isolation and churn tests pass. Until then `CAPTURE_MODE_PACKETS` remains `STATUS_NOT_SUPPORTED` on the public start path (a private/test start is allowed behind an explicit internal flag only if needed for bring-up, and must not be advertised).
9. **New SandMan view.** `CPacketCaptureView` / `CPacketCaptureWindow`. Do not reuse `CCaptureView` or `CTraceEntry`. Do not change Connection Audit behaviour, filters, CSV, or context menus except to add *separate* Packet Capture actions.
10. **QSbieAPI stays non-virtual.** Append fields to `SSbieCaptureStart` / add new non-virtual methods. Do not insert virtuals on `CSbieAPI`.
11. **Wire v1 trailing fields.** Do not bump `CAPTURE_WIRE_VERSION` unless a breaking change is unavoidable. Old `CAPTURE_START_REQ` (112 bytes) must still start connection-audit.
12. **Personal host constraints:** no ARM64 full link, no official driver signing, no `git reset` / `git clean`, no `DefaultBox` config edits, keep `NetworkEnableWFP=y`, do not use installed `Start.exe`, do not load parsers/OpenSSL into `SbieDrv`/`SbieSvc`.

---

## Current baseline (do not regress)

| Piece | Today |
| --- | --- |
| ALE AUTH CONNECT/RECV_ACCEPT v4/v6 | Policy + 80-byte `connect_attempt` / `accept_attempt` |
| `layerData` / `flowContext` | Ignored (`UNREFERENCED_PARAMETER`) |
| `WFP_flow_delete` | Stub success |
| Transport 5-tuple indexes | Already in `GetNetwork5TupleIndexesForLayer`, unused |
| `capture_network.c` | IPv4 encode only |
| Driver queue | 256 × 80 bytes, nonpaged, overwrite-oldest + drop |
| SbieSvc start | `mode & ~CONNECTIONS` → `STATUS_NOT_SUPPORTED` |
| Caps | `CONTROL` + `CONNECTION_AUDIT` when WFP ready |
| Broker | Does not exist |
| SandMan | Connection Audit only |
| MCP `packetCapture` | false |

Live-driver connection-audit isolation and process-churn already passed on this host. Treat those e2e scripts as a regression gate after every driver swap.

---

## Data path

```text
boxed TCP/UDP
    |
    +-- existing ALE AUTH -----> WFP_classify -----> 80-byte audit queue
    |                                                 |
    |                                                 v
    |                                          SbieSvc CaptureServer
    |                                                 |
    |                                                 v
    |                                          Connection Audit UI / MCP
    |
    +-- ALE FLOW_ESTABLISHED --> WFP_flow_establish_classify
    |                               FwpsFlowAssociateContext(fixed ctx)
    |
    +-- TRANSPORT in/out -------> WFP_packet_classify
    |                               copy NBL <= snaplen --> packet ring
    |
    +-- STREAM / DATAGRAM ------> WFP_appdata_classify
                                    copy app bytes <= snaplen --> stream ring

SbieSvc CaptureServer
    |-- authorize owner (SID+session, box enabled, PID+createTime)
    |-- API_CAPTURE_CONTROL start packet session
    |-- spawn SbieCapture.exe in kill-on-close job, caller token
    |-- DuplicateHandle(file) + DuplicateHandle(section) into broker
    |-- stop / fail / owner disconnect => terminate job

SbieCapture.exe
    |-- map packet ring + stream ring
    |-- write TRANSPORT records as PCAPNG EPB (LINKTYPE_RAW / 101)
    |-- attach per-process metadata (PID, createTime, box, SID, session)
    |-- rotate / stop on size and time
    |-- never parse TLS/HTTP
```

### Flow context (fixed, nonpaged)

```text
capture-generation / policy generation
process id
process creation time
session id
box name hash or inline box name (BOXNAME_COUNT)
SID string or SID hash
address family, protocol
local/remote address[16], local/remote port
direction
```

Copy the identity snapshot under the existing process/WFP lock, release that lock, then associate context. `WFP_flow_delete` frees the context. Cap live flow contexts (recommend 4096). On overflow: do not associate, do not capture that flow, do not touch permit/block.

### Packet record (new queue)

Fixed size = header + `CAPTURE_PACKET_SNAPLEN_MAX` (1514).

Header must include: sequence, timestamp, PID, createTime, session, AF, proto, direction, local/remote endpoints, `original_length`, `captured_length`, layer (`transport` / `stream` / `datagram`), loopback, flags. Payload bytes follow. Session snaplen may be smaller than max; unused tail stays zero.

Recommend:

- packet ring capacity 4096
- stream ring capacity 2048
- max concurrent packet sessions: 2 per owner, 4 global
- default snaplen 256 (headers + HTTP line / ClientHello SNI)
- allowed snaplen 64..1514
- default max file 64 MiB
- default max time 300 s
- `rotate_count = 0` means stop at the size limit; `N` keeps the last N files

Overflow overwrites the oldest record and saturates `dropped_count`. Never block the network. Never allocate on the classify path except by claiming a preallocated ring slot.

### Inbound transport copy

`layerData` is `NET_BUFFER_LIST *`. Inbound transport NBL starts at the transport header. Use `FWPS_METADATA_FIELD_IP_HEADER_SIZE` (and transport header size when present), retreat, copy `min(snaplen, original)`, restore. Outbound typically already includes the IP header. Do not keep the NBL after classify returns. Do not clone-and-pend.

Stream classify uses `FWPS_STREAM_CALLOUT_IO_PACKET`. Copy then continue. Never `FWPS_STREAM_ACTION_NEED_MORE_DATA` in Phase 3 (that is Phase 4).

---

## Control wire

Keep family `0x2000`. Add:

```text
MSGID_CAPTURE_SET_EXPORT   0x2007
```

`0x20FF` remains disconnect notification.

### `CAPTURE_START_REQ` trailing fields (after existing 112-byte v1)

```c
ULONG snap_length;       /* 0 = default 256 */
ULONG max_file_bytes;    /* 0 = default 64MiB */
ULONG max_seconds;       /* 0 = default 300 */
ULONG rotate_count;      /* 0 = stop at limit */
ULONG reserved;
```

Old clients send `struct_size == 112` and can only start `MODE_CONNECTIONS`. New packet start requires the extended size plus a successful `SET_EXPORT` before the session leaves `WAITING_FOR_BACKEND`.

### `CAPTURE_SET_EXPORT`

Caller-relative file handle value + capture id. SbieSvc `DuplicateHandle` from the LPC client process. Reject if the handle is not a writable disk file, or if the process is sandboxed. No path string in the request.

`CAPTURE_SESSION_INFO` already has `packet_count`, `byte_count`, `dropped_count`. Extend with trailing fields only if the UI needs current file index / current file bytes. Prefer putting those in status via reserved-then-trailing so old 184-byte info still parses.

Do not add a “read packets over LPC” message. 64 KiB LPC cannot carry Baidu-rate traffic.

---

## Files likely to change

### New

- `Sandboxie/core/drv/capture_packet.h`
- `Sandboxie/core/drv/capture_packet.c` — ring + record (dual-compile, no `windows.h` in driver TU)
- `Sandboxie/core/drv/capture_stream.h`
- `Sandboxie/core/drv/capture_stream.c` — stream/datagram ring (dual-compile)
- `SandboxieTools/SbieCapture/SbieCapture.vcxproj`
- `SandboxieTools/SbieCapture/main.cpp` (or `.c`) — map rings, write PCAPNG, rotate, honor time/size
- `SandboxieTools/SbieCapture/pcapng.c` + `pcapng.h` — no third-party lib
- `SandboxieTools/PcapngTests/` — user-mode writer tests
- `SandboxiePlus/SandMan/Views/PacketCaptureView.h`
- `SandboxiePlus/SandMan/Views/PacketCaptureView.cpp`

### Modify

- `Sandboxie/core/drv/wfp.c` / `wfp.h` — new GUIDs, inspection callouts, split classify, implement `WFP_flow_delete`
- `Sandboxie/core/drv/capture.c` / `capture.h` — packet-session start/stop, section objects, do not break ALE sessions
- `Sandboxie/core/drv/api_defs.h` — `API_CAPTURE_MAP` or extend `API_CAPTURE_CONTROL` with a map operation; new packed structs; `C_ASSERT` sizes
- `Sandboxie/core/drv/api.c` — register new API if added
- `Sandboxie/core/drv/SboxDrv.vcxproj` — new ClCompile entries
- `Sandboxie/core/drv/capture_network.c` / `.h` — IPv6 encode helper for tests if needed
- `Sandboxie/core/svc/msgids.h` — `0x2007`
- `Sandboxie/core/svc/capturewire.h` — trailing start fields, export req/rpl, static_asserts
- `Sandboxie/core/svc/CaptureServer.cpp` — packet mode, broker job, handle duplication, still `NOT_SUPPORTED` until ready
- `Sandboxie/core/dll/trace.c` — API name strings
- `SandboxiePlus/QSbieAPI/SbieCapture.h` / `SbieAPI.h` / `SbieAPI.cpp`
- `SandboxiePlus/SbieMcp/main.cpp` — start args + still hide capability until tests pass
- `SandboxiePlus/SandMan/SandMan.cpp` / `.h` / `SandMan.pri` — View menu, log tab, box/process context actions
- `SandboxieTools/CaptureQueueTests/CaptureQueueTests.c` — packet/stream queue tests
- `SandboxieTools/SandboxieTools.sln` — add SbieCapture + tests (x64 Release required; ARM64 configs may exist but this host does not build them)
- `Docs/SandboxCaptureMcp.md` — status paragraph after the backend is real
- `CHANGELOG.md` — after a working x64 path exists, not in the plan-only commit

### Do not touch unless a compile forces it

- `CCaptureView.*` behaviour
- `NetworkAccess` permit/block logic inside `WFP_classify`
- `DefaultBox` / `Sandboxie.ini` contents
- installer / official signing / ARM64 project defaults

---

## Slice-by-slice plan

Implement in this order. Each slice is one logical commit. Do not advertise capability until Slice 8.

### Slice 0 — Plan only

This file. No code.

### Slice 1 — User-mode PCAPNG writer + tests (no driver)

**Objective:** A bounded writer that turns synthetic packet records into a file tshark can open.

**Files:** `SandboxieTools/SbieCapture/pcapng.*`, `SandboxieTools/PcapngTests/`

**Behaviour:**

- SHB + IDB (`LINKTYPE_RAW` = 101)
- One EPB per transport record
- EPB comment or custom option: `pid=… createTime=… box=… sid=… session=…`
- Snaplen respected; `original_length` vs `captured_length` both written
- Rotation: close file, open next name, write a fresh SHB+IDB
- Time/size stop
- No protocol parsing

**Verify:**

```text
cl /nologo /W4 /WX /DUNICODE /D_UNICODE PcapngTests.c pcapng.c
PcapngTests.exe
tshark -r <out>.pcapng -T fields -e frame.number -e ip.src -e ip.dst -e tcp.dstport
```

Expected: tshark exit 0, only the injected 5-tuples, no extra packets.

### Slice 2 — Dual-compile packet/stream queues (no WFP yet)

**Objective:** Fixed-capacity nonpaged-safe rings with push/drain/drop, same dual-compile rules as `capture_queue.c`.

**Files:** `capture_packet.*`, `capture_stream.*`, `CaptureQueueTests.c`, `SboxDrv.vcxproj`

**Rules:** Driver TU must not include `windows.h`. Detect `_NTDDK_` / `_NTIFS_` / `_WDMDDK_`. `/W4 /WX` user-mode tests.

**Verify:** overflow saturates drop, order preserved, snaplen clamp, remaining count, reset.

### Slice 3 — Wire + QSbieAPI + MCP shapes (still NOT_SUPPORTED)

**Objective:** Extended start fields, `MSGID_CAPTURE_SET_EXPORT`, QSbieAPI structs/methods, MCP argument validation. Service still returns `STATUS_NOT_SUPPORTED` for `MODE_PACKETS`. Capability bits still clear.

**Files:** `capturewire.h`, `msgids.h`, `CaptureServer.cpp` (parse-and-reject path only), `SbieCapture.h`, `SbieAPI.cpp`, `SbieMcp/main.cpp`

**Verify:** existing connection-audit start/read still works against the current live driver. New packet start still `0xC00000BB`. `static_assert` sizes updated. No vtable change on `CSbieAPI`.

### Slice 4 — SbieCapture.exe broker process (no live packets yet)

**Objective:** Independently built x64 executable. Accept inherited handles (section + first file). Run as the caller. Enforce size/time/rotate. Exit when the section is closed or a stop event is signalled.

**Files:** `SandboxieTools/SbieCapture/*`, `SandboxieTools.sln`

**SbieSvc spawn rules (implemented in Slice 6, designed here):**

- Path is install-dir `SbieCapture.exe` only
- Client cannot supply exe path or command line
- Kill-on-close job
- Caller primary token, not LocalSystem
- stdin/stdout not a protocol surface

**Verify:** unit/harness with a fake mapped ring of Slice 2 records produces a tshark-readable PCAPNG and rotates.

### Slice 5 — Driver inspection callouts (the dangerous slice)

**Objective:** Register flow + transport + stream + datagram layers. Copy into the new rings. Do not change ALE policy.

**Files:** `wfp.c`, `wfp.h`, `capture.c`, `api_defs.h`

**Required split:**

| Callout | Layer | Action type | Classify |
| --- | --- | --- | --- |
| existing send/recv | ALE AUTH CONNECT/RECV_ACCEPT | TERMINATING (unchanged) | `WFP_classify` unchanged |
| new | ALE FLOW_ESTABLISHED v4/v6 | INSPECTION | associate context only |
| new | INBOUND/OUTBOUND TRANSPORT v4/v6 | INSPECTION | copy NBL to packet ring |
| new | STREAM v4/v6 | INSPECTION | copy app bytes to stream ring |
| new | DATAGRAM_DATA v4/v6 | INSPECTION | copy app bytes to stream ring |

New GUIDs: follow the existing `0bf56435-71e4-4de7-bd0b-1af0b4cbb8f6` family; do not reuse ALE GUIDs.

`WFP_RegisterCallout` currently hardcodes `WFP_classify` and `FWP_ACTION_CALLOUT_TERMINATING`. Add a parameterised registrar. Unregister all new ids in `WFP_Uninstall_Callbacks`.

Filter identity: reuse `CaptureFilter_Matches` (box + SID + session + PID + createTime + loopback flag). PID alone is never enough.

**Verify (compile only in this slice, unless a queued reboot is already planned):**

- x64 `SbieDrv.sys` builds with WDK test signature
- user-mode queue tests still pass
- `git diff --check` clean
- Do not claim “能抓包了”

Live load uses the existing `MoveFileEx(..., 5)` + reboot recipe in `sandboxie-core-build` `references/runtime-connection-audit.md`. Confirm SHA-256 after reboot. Then immediately re-run connection-audit `e2e_silent.py` — if that regresses, stop and fix before enabling packet start.

### Slice 6 — CaptureServer broker lifecycle

**Objective:** `MODE_PACKETS` start creates the driver packet session, maps the section, duplicates handles, spawns `SbieCapture.exe`, moves to `RUNNING` only when the broker is alive. Owner disconnect / stop / broker crash → `STOPPED` / `FAILED`, job killed, rings torn down. Network policy unchanged.

**Files:** `CaptureServer.cpp`, `api_defs.h`, `capture.c`

**Authorization:** identical to Phase 2. Sandboxed callers cannot start. Cross-SID / cross-session rejected. Process scope binds PID+createTime. Box scope requires `INCLUDE_FUTURE_PROCESSES`. Canonical box name (`DefaultBox`, not `defaultbox`).

**Verify:** start without export handle stays `WAITING_FOR_BACKEND` or fails closed. Missing `SbieCapture.exe` → `FAILED`, not a successful running capture. Connection-audit sessions still start without a broker.

### Slice 7 — SandMan Packet Capture view

**Objective:** A distinct view that can start a packet session, show a bounded packet table, and point at the PCAPNG output.

**Files:** `PacketCaptureView.*`, `SandMan.cpp`, `SandMan.h`, `SandMan.pri`

**UI contract:**

- `View → Packet Capture` and a log tab, separate from Connection Audit
- Box combo uses `I.value()->GetName()`, never `I.key()`
- Box context menu: Packet Capture (whole box + future processes)
- Process context menu: Packet Capture for that PID+createTime only
- Controls: snaplen, max time, max file size, rotate count, include loopback
- User picks the output file *before* Start (so QSbieAPI can pass a handle)
- Table columns: time, PID, process, proto, src, dst, orig len, captured len
- Bounded UI queue (same idea as Connection Audit: cap pending, time-budgeted flush). No hex dump in the table
- Status: packets / bytes / dropped / current file / “ciphertext for TLS; not HTTPS inspection”
- Save is the PCAPNG the broker is already writing, not a CSV of metadata
- Hide or disable Start until capability bits are on (Slice 8). Until then the view may exist but must not pretend the backend is ready

Deploy `SandMan.exe` **and** `QSbieAPI.dll` **and** `SbieCapture.exe` together. Community `vcvars64.bat`, not `qmake_plus.cmd`.

### Slice 8 — Live isolation, then capability bits

**Objective:** Prove the security invariants on the personal host, then and only then advertise `packetCapture` / `pcapngExport`.

**Tests (silent boxed runner, not `Start.exe`):**

1. Connection-audit regression: `e2e_silent.py` still `eventCount > 0`.
2. Box A curl to `1.1.1.1`, Box B curl to `8.8.8.8`, host curl to `9.9.9.9`. Each PCAPNG contains only its own PID, createTime, and remote. Host PID never appears.
3. Process-scoped session: later boxed children do not appear. After target exit, a new boxed process with a recycled PID story is still excluded (createTime mismatch).
4. Box-scoped session: later children *do* appear.
5. Loopback excluded by default, included when flagged.
6. IPv4 TCP and UDP. IPv6 registered in the driver; only claim IPv6 e2e if this host actually ran an IPv6 target.
7. Snaplen: captured length ≤ snaplen, original length preserved, tshark still opens the file.
8. Size limit + `rotate_count=0` stops. `rotate_count>=1` produces a second file that tshark also opens.
9. Time limit stops the session.
10. Ring overflow: drop counter increases, network still works, no BSOD.
11. Broker kill: session `FAILED`, no direct-policy change, ALE audit still works.
12. Cross-SID / cross-session start still denied.

**After those pass:** set the two capability bits when the packet backend is healthy. MCP `packetCapture` becomes true. SandMan Start enables. `CHANGELOG.md` and the status section of `Docs/SandboxCaptureMcp.md` are updated.

Until Slice 8 passes, do not tell the user “能抓包了”.

---

## Verification commands (personal host)

Build / deploy follow `sandboxie-core-build` `references/x64-official-build.md` and `references/runtime-connection-audit.md`.

- Driver swap: sign x64 `SbieDrv.sys`, `MoveFileEx` flags `5`, reboot, compare SHA-256. Do not loop on `KmdUtil stop`.
- `SbieSvc` can be restarted without reboot; the driver usually cannot.
- Qt: Community `vcvars64.bat` + `C:\Users\Wuldas\.AA\Qt\6.8.3\msvc2022_64`.
- Evidence dir already used for Phase 2: `%LOCALAPPDATA%\Temp\hermes-sandbox-capture-red\`.
- tshark via the local Wireshark install / `mcp__wireshark__*` tools.
- `git diff --check` on every slice.
- Report only architectures that were actually built (x64).

---

## Explicitly out of scope (Phase 4+)

- WFP connect-redirect, sandbox-only CA, TLS MITM, HAR, header redaction of plaintext HTTP
- OpenSSL in any Sandboxie process
- HTTP/2, HPACK, WebSocket, gRPC, HTTP/3 decryption
- Machine-wide sniffing
- Official EV signing, ARM64 full link, installer packaging
- Changing `NetworkAccess` semantics so that capture can bypass a deny

---

## Risks

| Risk | Mitigation |
| --- | --- |
| Reusing `WFP_classify` on transport accidentally TERMINates / blocks | Separate inspect classify; never write `classifyOut->action` on packet path |
| Inbound PID missing → host or wrong-box leak | Flow context required; no context ⇒ no capture |
| LPC drain of payloads | Not used. Mapped ring + broker |
| Baidu-rate overflow / UI freeze | 4096-slot ring, drop counter, bounded SandMan table, snaplen default 256 |
| `SbieSvc` copies payloads as SYSTEM | Forbidden. Broker runs as caller |
| Path traversal via rotation | Broker uses caller token + directory of the caller-opened file |
| Connection-audit regression after new callouts | e2e_silent / isolation / churn are a hard gate before capability bits |
| `defaultbox` vs `DefaultBox` | Combo and MCP send `GetName()` |
| `KmdUtil stop` loops | DELAY_UNTIL_REBOOT only |
| Declaring packet capture after a compile | Capability bits and user-facing copy stay off until Slice 8 |

---

## Open questions (do not block the plan)

None that change the first implementation. If a later slice hits a Win7 STREAM inspect limitation, keep TRANSPORT+PCAPNG (the exit criterion) and capability-gate STREAM rather than widening to Win8-only APIs in the core path.

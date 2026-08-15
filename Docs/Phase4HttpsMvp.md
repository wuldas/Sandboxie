# Phase 4: HTTPS MVP Implementation Plan

> **For Hermes:** Implement only after the user accepts this plan and, if they want the usual stage gate, after this file is committed alone. Do not mix implementation into the plan commit. Do not `git reset` / `git clean`. Do not start HTTP/2, HPACK, WebSocket, gRPC, HTTP/3, Firefox/NSS, or QUIC termination.

**Goal:** Deliver the Phase 4 HTTPS MVP in `Docs/SandboxCaptureMcp.md`: WFP connect-redirect plus broker authentication, sandbox-only CA lifecycle, TLS 1.2/1.3 and HTTP/1.1 inspection, HAR export, and default header redaction. Exit: representative Chromium, WinHTTP, and curl traffic in the selected sandbox is decoded into HAR; certificate pinning is reported as a MITM failure while ciphertext PCAPNG is retained; broker failure does not restore direct HTTPS egress.

**Architecture:** Keep Phase 2 ALE connection-audit and Phase 3 inspect-only packet/stream rings exactly as-is. Add a third path that is *not* driver TLS parsing: `ALE_CONNECT_REDIRECT` rewrites matching outbound TCP/443 to a random loopback listener owned by `SbieCapture.exe`. The broker authenticates the WFP redirect context, terminates downstream TLS with a session CA, opens the original destination with the WFP redirect records copied onto the upstream socket, parses HTTP/1.1, writes HAR, and keeps writing ciphertext PCAPNG from the existing transport ring. `SbieDrv` / `SbieSvc` never parse TLS or HTTP. OpenSSL lives only in `SbieCapture.exe`. Capability bits `CAPTURE_CAP_HTTPS_INSPECTION` and `CAPTURE_CAP_HAR_EXPORT` stay clear until live isolation, fail-closed, and host-store integrity tests pass.

**Tech Stack:** Existing SbieDrv WFP (`FwpsCalloutRegister1` remains the Win7 baseline; redirect-handle APIs are Win8+ and capability-gated), SbieSvc CaptureServer LPC (`MSGID_CAPTURE` 0x2000), QSbieAPI non-virtual wrappers, `SbieCapture.exe` under `SandboxieTools` plus OpenSSL 3.4.0 from `Installer/buildVariables.cmd`, SandMan Qt 6.8.3 MSVC view. Personal host: x64 / Windows 11 only, WDK test certificate, no official signing, no ARM64 full link.

---

## Locked decisions

These are not open questions. Do not re-litigate them while implementing.

1. **HTTPS is connect-redirect + broker MITM.** Do not implement `FWPS_STREAM_ACTION_NEED_MORE_DATA` in the driver. The Phase 3 comment that “NEED_MORE_DATA is Phase 4” is superseded: the driver still never parses TLS. STREAM/TRANSPORT stay copy-then-continue inspection.
2. **Do not reuse `WFP_classify`.** That function is the ALE AUTH CONNECT/RECV_ACCEPT terminating policy callout. Redirect uses a new classify that may rewrite the remote endpoint. Packet/flow/stream/datagram callouts stay `FWP_ACTION_CALLOUT_INSPECTION` and must never change the verdict.
3. **Original `NetworkAccess` / `AllowNetworkAccess` is evaluated first.** A denied destination stays denied. Redirect happens only after ALE AUTH has permitted the original 5-tuple.
4. **Fail-closed.** While an HTTPS session is `RUNNING` or `FAILED`, matching TCP/443 continues to redirect to the broker listener even if the broker process is dead. Connections then fail. Do not unregister the redirect filter as a side-effect of broker death. Only an explicit stop tears the redirect down.
5. **Broker accepts only redirected connections.** A connect that lacks a valid WFP redirect context bound to this capture id + generation is dropped. No “open proxy on loopback”.
6. **Recursive redirect is prevented by WFP redirect records.** The broker copies the inbound redirect records onto the upstream socket. The driver classify must skip flows already redirected by its own `FwpsRedirectHandle`.
7. **TCP 443 only.** Do not redirect all TCP. QUIC/UDP 443 stays on the Phase 3 passive path (ciphertext only). Non-443 TLS is out of MVP.
8. **ALPN is `http/1.1` only.** The broker does not advertise `h2`. HTTP/2 clients that refuse HTTP/1.1 fail closed and still have PCAPNG.
9. **`CAPTURE_MODE_HTTPS` also starts the existing packet backend.** Pinning / MITM failure must retain ciphertext PCAPNG. HTTPS is not a replacement for packet capture.
10. **Two caller-opened export files.** `SET_EXPORT` remains PCAPNG. New `MSGID_CAPTURE_SET_HAR_EXPORT` (`0x200A`) is the HAR file. LocalSystem never creates or overwrites a client-supplied path. HTTPS start cannot leave `WAITING_FOR_BACKEND` until both handles are set.
11. **Bodies are opt-in. Redaction is on by default.** `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, and common API-key headers are replaced with `[REDACTED]` unless an explicit flag disables redaction. Body bytes are omitted unless `CAPTURE_FLAG_INCLUDE_BODIES` is set, and then only up to a per-body cap.
12. **One CA per capture session.** Private key stays in broker memory (and a caller-protected temp file outside every sandbox if a restart helper needs it). Only the CA *public* certificate is imported into the selected sandbox’s virtual current-user Root store. Host stores and other boxes must hash-compare unchanged.
13. **OpenSSL 3.4.0 only in `SbieCapture.exe`.** Do not link OpenSSL, parsers, or HAR writers into `SbieDrv` or `SbieSvc`. Use the version in `Installer/buildVariables.cmd`; do not hard-code a different version in that file.
14. **Win8+ redirect is the MVP path.** `FwpsRedirectHandleCreate0` / `FwpsQueryConnectionRedirectState0` are resolved at runtime. If they are absent, HTTPS capability stays clear and start returns `STATUS_NOT_SUPPORTED`. The Win7 SOCKS5 fallback from the architecture doc is Phase 4.1 / later, not this MVP.
15. **Do not bump `CAPTURE_WIRE_VERSION`.** Old 112-byte `CAPTURE_START_REQ` still starts connection-audit. Extended start stays 132 bytes plus new *trailing* flags only if they fit without moving existing fields. Prefer a new flag bit and a new SET message over resizing start.
16. **QSbieAPI stays non-virtual.** Append fields / add non-virtual methods. Do not insert virtuals on `CSbieAPI`.
17. **New SandMan view.** `CHttpsCaptureView` / `CHttpsCaptureWindow`. Do not reuse `CCaptureView`, `CPacketCaptureView`, or `CTraceEntry` as the HAR table. Packet Capture and Connection Audit behaviour stay unchanged except for a separate HTTPS action.
18. **Capability bits stay off** (`CAPTURE_CAP_HTTPS_INSPECTION`, `CAPTURE_CAP_HAR_EXPORT`) until Slice 8 live tests pass. Until then public `CAPTURE_MODE_HTTPS` remains `STATUS_NOT_SUPPORTED`.
19. **Personal host constraints:** no ARM64 full link, no official driver signing, no `git reset` / `git clean`, keep `NetworkEnableWFP=y`, do not use installed `Start.exe`, do not load parsers/OpenSSL into `SbieDrv`/`SbieSvc`. Every live driver change still requires a rollback path and post-reload hash check. Use the `kmdutil-driver-reload` workflow; stop `SbieSvc` first; watch for `SandMan.exe` re-holding `\\Device\\SandboxieDriverApi`.

---

## Current baseline (do not regress)

| Piece | Today |
| --- | --- |
| ALE AUTH CONNECT/RECV_ACCEPT v4/v6 | Policy + 80-byte connection audit |
| FLOW / TRANSPORT / STREAM / DATAGRAM | Inspection copy into packet/stream rings |
| Connect-redirect layers | Not registered |
| `FwpsRedirectHandle*` | Not used |
| `SbieSvc` start | `mode` other than CONNECTIONS/PACKETS → `STATUS_NOT_SUPPORTED` |
| Caps | CONTROL + CONNECTION_AUDIT + PACKET/PCAPNG when gate + payload callouts are healthy |
| `httpsInspection` / `harExport` | false |
| Broker | PCAPNG drain only; no listen socket; no OpenSSL |
| SandMan | Connection Audit + Packet Capture |
| MCP `mode=https` | Accepted by schema, rejected by service |
| OpenSSL | Bundled 3.4.0 for Qt/SandMan TLS plugin only |
| SOCKS5 | Existing `SbieDll` `NetworkUseProxy` path; not a capture capability |

Phase 3 live evidence on this host already covers Box A / Box B / host isolation, IPv4/IPv6 TCP/UDP, snaplen/rotate/time, process- vs box-scope, overflow `droppedCount`, broker kill, and cross-SID / cross-session denial. Those scripts remain a hard gate after every driver swap.

---

## Data path

```text
boxed TCP/443 (ALE AUTH already permitted)
    |
    +-- existing ALE AUTH -----> WFP_classify -----> 80-byte audit queue
    |
    +-- existing FLOW/TRANSPORT/STREAM --> packet/stream rings --> PCAPNG
    |
    +-- ALE CONNECT_REDIRECT v4/v6
            if redirected_by_self -> continue
            if HTTPS session matches (box/SID/session/PID+createTime)
               and proto=TCP and remote_port=443
               and dest is not the broker listener
               -> rewrite to 127.0.0.1/::1 : broker_port
               -> attach redirect context
            else continue

SbieSvc CaptureServer
    |-- authorize owner (unchanged Phase 2 rules)
    |-- start packet session (existing)
    |-- start HTTPS redirect session (new driver control)
    |-- spawn SbieCapture.exe (packet drain + HTTPS listen)
    |-- DuplicateHandle(pcapng) + DuplicateHandle(har) + section
    |-- launch in-box helper to import CA public cert only
    |-- stop / fail / owner disconnect => kill job, then drop redirect

SbieCapture.exe
    |-- map packet ring, write PCAPNG (existing)
    |-- listen 127.0.0.1 and [::1] on an ephemeral port
    |-- accept only WFP-redirected sockets
    |-- SNI callback: mint leaf from session CA
    |-- downstream TLS (OpenSSL 3.4.0)
    |-- upstream TLS to original dest with redirect records copied
    |-- HTTP/1.1 parse, redact, optional body, HAR writer
    |-- pinning / handshake failure: log event, keep PCAPNG, do not leak
```

### Redirect context (fixed, copied into WFP classify context)

```text
capture id high/low
capture generation
policy generation
process id
process creation time
session id
box name (BOXNAME_COUNT) or box hash
original remote address[16]
original remote port
address family
```

The broker reads this via `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` (or the documented equivalent) and refuses the socket if it does not match the inherited capture id + generation.

### HAR record (broker-only, never LPC)

One HAR 1.2 `log.entries[]` object per HTTP/1.1 exchange:

- `startedDateTime`, `time`
- `request.method`, `url` (from SNI + request-target), `httpVersion`
- `request.headers` / `response.headers` after redaction
- `request.queryString` parsed from the request-target
- `response.status`, `statusText`
- `serverIPAddress` = original remote, not 127.0.0.1
- `_sandboxie` custom field: pid, createTime, box, sid, session, sni, alpn, tlsVersion, pinningFailed
- `content.text` only when bodies are enabled and under the per-body cap; otherwise `text` omitted and `_omitted` / `size` recorded

Do not send HAR entries over LPC. SandMan tails the caller-owned HAR file or a sidecar JSONL the broker appends next to it. Prefer JSONL-of-entries plus a closing HAR wrapper on stop, so a crash still leaves readable exchanges.

### Limits

- max concurrent HTTPS sessions: 1 per owner, 2 global
- broker accept backlog: 32
- max concurrent MITM connections: 64; overflow fails the new connect, does not drop redirect
- default per-body cap: 64 KiB
- default HAR max file: 64 MiB (same rotation rules as PCAPNG)
- default max seconds: 300
- CA key: 2048-bit RSA or P-256; leaf SAN = SNI; validity ≤ 24 h
- listen address: loopback only

---

## Control wire

Keep family `0x2000`. Add:

```text
MSGID_CAPTURE_SET_HAR_EXPORT   0x200A
```

`0x20FF` remains disconnect notification.

### New start flags (existing `flags` field, no size change)

```c
#define CAPTURE_FLAG_INCLUDE_BODIES     0x00000004
#define CAPTURE_FLAG_DISABLE_REDACTION  0x00000008
```

Unknown flag bits still return `STATUS_INVALID_PARAMETER`. Old packet/connection clients that do not set these bits keep current behaviour.

### `CAPTURE_SET_HAR_EXPORT`

Same shape as `CAPTURE_SET_EXPORT`: caller-relative file handle + capture id. SbieSvc `DuplicateHandle` from the LPC client. Reject if the handle is not a writable disk file, or if the caller is sandboxed. No path string.

HTTPS start sequence:

1. `START` with `mode = CAPTURE_MODE_HTTPS` → session `WAITING_FOR_BACKEND` (or `STATUS_NOT_SUPPORTED` until Slice 8).
2. `SET_EXPORT` (PCAPNG) + `SET_HAR_EXPORT` (HAR), either order.
3. Broker listen port is bound, CA minted, redirect handle created, in-box cert helper succeeds.
4. Session becomes `RUNNING` only after those steps. Any failure is `FAILED` and fail-closed until `STOP`.

Do not add “read HAR over LPC”.

---

## Files likely to change

### New

- `SandboxieTools/SbieCapture/har.h` / `har.c` — HAR/JSONL writer, no third-party JSON lib if a tiny existing helper exists; otherwise a bounded writer with tests
- `SandboxieTools/SbieCapture/http11.h` / `http11.c` — HTTP/1.1 request/response framing only
- `SandboxieTools/SbieCapture/redact.h` / `redact.c` — header redaction
- `SandboxieTools/SbieCapture/capture_ca.h` / `capture_ca.c` — session CA + SNI leaf (OpenSSL)
- `SandboxieTools/SbieCapture/https_mitm.h` / `https_mitm.c` — listen, redirect-context auth, TLS, upstream
- `SandboxieTools/HarTests/` — user-mode HAR / redact / http11 tests (no driver)
- `SandboxieTools/HttpsMitmTests/` — loopback TLS 1.2/1.3 + HTTP/1.1 tests against a local OpenSSL server
- `Sandboxie/core/drv/capture_https.h` / `capture_https.c` — redirect session table (dual-compile where possible)
- `SandboxiePlus/SandMan/Views/HttpsCaptureView.h` / `.cpp`
- `Docs/Phase4HttpsMvp.md` — this file

### Modify

- `Sandboxie/core/drv/wfp.c` / `wfp.h` — new CONNECT_REDIRECT GUIDs, redirect classify, runtime resolve of Win8+ APIs
- `Sandboxie/core/drv/capture.c` / `capture.h` / `api_defs.h` / `api.c` — HTTPS session start/stop, redirect handle, listen-port publish
- `Sandboxie/core/drv/SboxDrv.vcxproj` — new TU
- `Sandboxie/core/svc/msgids.h` — `0x200A`
- `Sandboxie/core/svc/capturewire.h` — new flag bits, SET_HAR_EXPORT, static_asserts
- `Sandboxie/core/svc/CaptureServer.cpp` — HTTPS mode, second export handle, cert helper, still `NOT_SUPPORTED` until ready
- `SandboxieTools/SbieCapture/*` — HTTPS listen mode beside existing ring drain
- `SandboxieTools/SbieCapture/SbieCapture.vcxproj` — OpenSSL include/lib for the broker only
- `SandboxieTools/CaptureQueueTests/CaptureWireTests.cpp` — new msgid + flag contract
- `SandboxiePlus/QSbieAPI/SbieCapture.h` / `SbieAPI.h` / `SbieAPI.cpp`
- `SandboxiePlus/SbieMcp/main.cpp` — HAR path + body/redact args; hide capability until Slice 8
- `SandboxiePlus/SandMan/SandMan.cpp` / `.h` / `SandMan.pri` / `Views/SbieView.*`
- `Docs/SandboxCaptureMcp.md` — status paragraph after the backend is real
- `CHANGELOG.md` — after a working x64 path exists, not in the plan-only commit

### Do not touch unless a compile forces it

- `CCaptureView.*` / `CPacketCaptureView.*` behaviour
- `NetworkAccess` permit/block logic inside `WFP_classify`
- `SbieDll` SOCKS5 (`net.c` / `proxy.c`) — not the MVP path
- `DefaultBox` / `Sandboxie.ini` contents except a documented rollback-able test box
- installer packaging / official signing / ARM64 project defaults
- Firefox NSS databases

---

## Slice-by-slice plan

Implement in this order. Each slice is one logical commit. Do not advertise HTTPS capability until Slice 8.

### Slice 0 — Plan only

This file. No code.

### Slice 1 — HAR writer, HTTP/1.1 framing, redaction (no driver, no OpenSSL)

**Objective:** Deterministic user-mode tests that turn synthetic HTTP/1.1 exchanges into a redacted HAR/JSONL file.

**Files:** `SandboxieTools/SbieCapture/http11.*`, `redact.*`, `har.*`, `SandboxieTools/HarTests/`

**Behaviour:**

- Parse one request and one response from byte buffers; reject folded headers and oversize lines
- Default redact list applied case-insensitively
- `DISABLE_REDACTION` keeps original header values
- Bodies omitted by default; when included, truncate at cap and record original size
- Writer produces a file `har.2` parsers / a small self-check can reopen
- No TLS, no sockets

**Verify:**

```text
cl /nologo /W4 /WX /DUNICODE /D_UNICODE HarTests.c http11.c redact.c har.c
HarTests.exe
```

Expected: all cases pass; a golden HAR contains `Authorization: [REDACTED]` and no cookie plaintext.

### Slice 2 — Session CA + loopback MITM (OpenSSL in broker/tests only)

**Objective:** `SbieCapture` can mint a session CA, present an SNI leaf, complete TLS 1.2 and TLS 1.3, proxy HTTP/1.1 to a local upstream, and write HAR.

**Files:** `capture_ca.*`, `https_mitm.*`, `HttpsMitmTests/`, broker vcxproj OpenSSL linkage

**Rules:**

- Link OpenSSL 3.4.0 only into `SbieCapture` and the MITM test exe
- Downstream ALPN = `http/1.1`
- Upstream verifies the real local test-server cert
- Tests use a fake redirect-context blob the acceptor would normally get from WFP
- Acceptor without that blob is refused

**Verify:**

```text
HttpsMitmTests.exe
```

Expected: TLS 1.2 and 1.3 GET `/` round-trip; HAR URL uses the SNI host, not 127.0.0.1; missing context is rejected; CA private key never written under a sandbox path.

### Slice 3 — Wire + QSbieAPI + MCP shapes (still NOT_SUPPORTED)

**Objective:** Flag bits, `MSGID_CAPTURE_SET_HAR_EXPORT`, QSbieAPI methods, MCP `outputHarPath` / `includeBodies` / `disableRedaction`. Service still returns `STATUS_NOT_SUPPORTED` for `MODE_HTTPS`. Capability bits still clear.

**Files:** `capturewire.h`, `msgids.h`, `CaptureServer.cpp` (parse-and-reject), `SbieCapture.h`, `SbieAPI.cpp`, `SbieMcp/main.cpp`, `CaptureWireTests.cpp`

**Verify:**

- Existing connection-audit and packet start still work against the current live service/driver
- `mode=https` still `0xC00000BB`
- `CaptureWireTests.exe` passes with `0x200A` and unchanged v1 start size 112 / start size 132
- No vtable change on `CSbieAPI`

### Slice 4 — Broker HTTPS process mode (no live WFP yet)

**Objective:** `SbieCapture.exe` accepts `--https-listen` plus inherited HAR handle, mints CA, writes the public cert to an inherited cert-file handle, drains PCAPNG as today, and serves the Slice 2 MITM path.

**Files:** `SandboxieTools/SbieCapture/main.c`, `capture_broker.*`

**SbieSvc spawn rules (implemented in Slice 6, designed here):**

- Path is install-dir `SbieCapture.exe` only
- Client cannot supply exe path or command line
- Kill-on-close job
- Caller primary token, not LocalSystem
- Listen sockets are bound by the broker after spawn; port is published back through the existing shared section header or a tiny broker-owned field SbieSvc already maps (do not add a new LPC payload drain)

**Verify:** harness with a fake redirect context + local upstream produces HAR + PCAPNG. Killing the broker leaves the HAR JSONL readable.

### Slice 5 — Driver connect-redirect (the dangerous slice)

**Objective:** Register `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6`. Rewrite matching TCP/443 to the broker loopback port. Attach context. Skip self-redirected flows. Do not change ALE policy.

**Files:** `wfp.c`, `wfp.h`, `capture.c`, `capture_https.*`, `api_defs.h`

**Required split:**

| Callout | Layer | Action type | Classify |
| --- | --- | --- | --- |
| existing send/recv | ALE AUTH CONNECT/RECV_ACCEPT | TERMINATING (unchanged) | `WFP_classify` unchanged |
| existing packet path | FLOW / TRANSPORT / STREAM / DATAGRAM | INSPECTION | unchanged |
| new | ALE CONNECT_REDIRECT v4/v6 | TERMINATING rewrite | `WFP_https_redirect_classify` |

New GUIDs: continue the `0bf56435-71e4-4de7-bd0b-1af0b4cbb8f6` family; do not reuse ALE or packet GUIDs.

Runtime: `MmGetSystemRoutineAddress` (or the project’s existing dynamic-resolve pattern) for `FwpsRedirectHandleCreate0`, `FwpsRedirectHandleDestroy0`, `FwpsQueryConnectionRedirectState0`. If missing, HTTPS start fails `STATUS_NOT_SUPPORTED` and no redirect callout is registered.

Filter identity: reuse `CaptureFilter_Matches`. PID alone is never enough. Remote port must be 443. Destination equal to the session listener is never redirected.

**Verify (compile + load, do not claim HTTPS works):**

- x64 `SbieDrv.sys` builds with WDK test signature
- user-mode HAR / wire / queue tests still pass
- `git diff --check` clean
- After reload: connection-audit `e2e_silent` and a Phase 3 packet isolation probe still pass
- With no HTTPS session, TCP/443 from a box is unchanged (direct)
- Do not claim “能解密了”

### Slice 6 — CaptureServer HTTPS lifecycle + sandbox-only CA import

**Objective:** `MODE_HTTPS` start creates packet + HTTPS driver state, spawns the broker, waits for listen port + CA public cert, launches an in-box helper under the caller token to import only that cert into the virtual current-user Root store, then enables redirect. Owner disconnect / stop / helper failure → `FAILED` or `STOPPED`, job killed, redirect torn down only on stop.

**Files:** `CaptureServer.cpp`, `api_defs.h`, `capture.c`, small in-box cert helper (prefer a `SbieCapture --import-ca` mode launched *inside* the box via existing `MSGID_PROCESS_RUN_SANDBOXED`, not a second installed exe)

**Authorization:** identical to Phase 2/3. Sandboxed callers cannot start. Cross-SID / cross-session rejected. Process scope binds PID+createTime. Box scope requires `INCLUDE_FUTURE_PROCESSES`. Canonical box name.

**Fail-closed:** broker kill while `RUNNING` → session `FAILED`, redirect filter stays, new 443 connects fail, ALE audit still works, packet ring still exists until `STOP`.

**Verify:**

- HTTPS start without both export handles stays `WAITING_FOR_BACKEND` or fails closed
- Missing OpenSSL DLLs next to `SbieCapture.exe` → `FAILED`, not `RUNNING`
- Connection-audit and packet-only sessions still start without a listen port
- After a successful import, host Root store hash is unchanged; a second box’s virtual store is unchanged

### Slice 7 — SandMan HTTPS view

**Objective:** A distinct view that starts an HTTPS session, shows a bounded HAR-entry table, and points at both output files.

**Files:** `HttpsCaptureView.*`, `SandMan.cpp`, `SandMan.h`, `SandMan.pri`, `SbieView.*`

**UI contract:**

- `View → HTTPS Capture` and a log tab, separate from Packet Capture and Connection Audit
- Box combo uses `I.value()->GetName()`, never `I.key()`
- Box context: HTTPS Capture (whole box + future processes)
- Process context: HTTPS Capture for that PID+createTime only
- Controls: max time, max file, rotate, include loopback, include bodies (off), disable redaction (off, scary)
- User picks *two* output files before Start (PCAPNG + HAR)
- Table columns: time, PID, process, method, status, host, path, TLS, pinning
- No cookie / authorization plaintext in the table
- Bounded UI queue; no body dump in the table
- Status: exchanges / dropped / current HAR / “pinning failures keep PCAPNG”
- Hide or disable Start until capability bits are on (Slice 8)

Deploy `SandMan.exe`, `QSbieAPI.dll`, `SbieCapture.exe`, and the OpenSSL 3.4.0 DLLs the broker needs, together.

### Slice 8 — Live isolation, then capability bits

**Objective:** Prove the security invariants on the personal host, then and only then advertise `httpsInspection` / `harExport`.

**Tests (silent boxed runner, not installed `Start.exe`):**

1. Connection-audit and packet-capture regressions still pass.
2. Box A `curl -I https://example.com`, Box B `curl -I https://1.1.1.1`, host `curl -I https://9.9.9.9`. Box A HAR contains only Box A PID/createTime and example.com. Box B HAR does not contain example.com. Host PID never appears. Each PCAPNG still isolates ciphertext.
3. Process-scoped session: later boxed children are not decrypted and do not appear in HAR.
4. Box-scoped session: later children *do* appear after they restart / pick up the sandboxed CA (document if a running Chromium must be restarted).
5. WinHTTP and a Chromium-based client in the box: at least one successful HTTP/1.1 HTTPS exchange each. If Chromium offers only HTTP/2 and refuses HTTP/1.1, record that as a known MVP limit and still require curl + WinHTTP.
6. Pinning: a client that pins (or `curl --pinnedpubkey`) fails the MITM handshake; session stays up; PCAPNG has the ciphertext; HAR records `pinningFailed`.
7. Broker kill: session `FAILED`, new boxed curl to 443 fails, host curl still works, ALE audit still works. After `STOP`, boxed curl to 443 works again.
8. Direct connect to the broker loopback port without WFP context is refused.
9. Denied `NetworkAccess` destination is still denied (no redirect bypass).
10. Host `HKCU`/`HKLM` Root store hashes unchanged. A second sandbox’s virtual Root store unchanged. Target box virtual Root contains the session CA during the run and is removed on stop.
11. Cross-SID / cross-session HTTPS start still `0xC0000022`.
12. IPv4 and, if the host has working IPv6 egress, IPv6. Only claim the families actually run.

Capability bits turn on only after 1–11 pass. MCP `httpsInspection` / `harExport` become true. SandMan HTTPS Start can enable. HTTP/2, Firefox/NSS, and Win7 SOCKS5 remain out of scope.

---

## Verification commands (personal host)

Build / deploy follow the Phase 3 recipes and `kmdutil-driver-reload`.

- Driver swap: sign x64 `SbieDrv.sys`, stop `SbieSvc`, confirm no `SandMan` / leftover handle on `\\Device\\SandboxieDriverApi`, `KmdUtil stop SbieDrv`, copy, hash, `KmdUtil start SbieDrv`, start `SbieSvc`.
- If only `SbieSvc` / `SbieCapture.exe` changed, do **not** unload the driver.
- Building `SboxSvc.vcxproj` alone fails (`SbieDll.lib`); use `Sandbox.sln | SbieRelease|x64`.
- Qt: Community `vcvars64.bat` + the machine’s Qt 6.8.3 MSVC kit (do not reuse the old-PC `C:\Users\Wuldas\.AA\Qt\...` path).
- Evidence dir: `%LOCALAPPDATA%\Temp\hermes-sandbox-capture-red\`
- `git diff --check` on every slice.
- Report only architectures that were actually built (x64).

---

## Explicitly out of scope (Phase 5 / 4.1)

- HTTP/2, HPACK, WebSocket, gRPC, HTTP/3, QUIC termination
- Firefox / NSS trust injection
- Win7 SOCKS5 capture fallback
- Redirect of ports other than TCP 443
- Machine-wide sniffing
- Guaranteed decryption of pinned, mTLS, or ECH-only clients
- Official EV signing, ARM64 full link, installer packaging
- Changing `NetworkAccess` semantics so capture can bypass a deny
- OpenSSL or HTTP parsers in `SbieDrv` / `SbieSvc`
- `FWPS_STREAM_ACTION_NEED_MORE_DATA`

---

## Risks

| Risk | Mitigation |
| --- | --- |
| Redirect classify accidentally bypasses `NetworkAccess` | ALE AUTH remains first and unchanged; redirect only after permit |
| Broker death restores direct 443 | Fail-closed: keep redirect to the dead listener until `STOP` |
| Loopback listener becomes an open proxy | Reject sockets without matching redirect context |
| Recursive redirect of broker upstream | Copy WFP redirect records; skip `REDIRECTED_BY_SELF` |
| Host or other-box trusts the CA | Import only via in-box helper into virtual CU Root; hash host + other box |
| CA private key lands in the box | Helper receives only the public cert bytes |
| HTTP/2-only Chromium | Force ALPN http/1.1; document refusal as MVP limit; still require curl + WinHTTP |
| Packet isolation regresses after new terminating callout | Slice 5 hard-gates Phase 2/3 e2e before any HTTPS traffic test |
| OpenSSL pulled into SbieSvc | vcxproj linkage only on `SbieCapture` / MITM tests |
| `SandMan` re-holds the driver during reload | Snapshot handles before every unload |

---

## Open questions (do not block Slice 0–2)

1. If Chromium on this host refuses HTTP/1.1 after ALPN downgrade, Slice 8 still ships on curl + WinHTTP and records Chromium as “pinning-or-ALPN failure + PCAPNG retained”.
2. Exact in-box cert helper launch API (`MSGID_PROCESS_RUN_SANDBOXED` vs an existing updater helper) is chosen in Slice 6 from the live service surface; Slice 2 only needs a user-mode import function.
3. Shared-section field for publishing the listen port is chosen in Slice 4/5 next to the existing broker header; do not invent a second section.

# Phase 5: Protocol & Compatibility Expansion Plan

> **For Hermes:** Implement only after the user accepts this plan and, if they want the usual stage gate, after this file is committed alone. Do not mix implementation into the plan commit. Do not `git reset` / `git clean`. Do not touch SbieDrv / SbieSvc / WFP in this phase.

**Goal:** Extend the Phase 4 HTTPS broker so that, in addition to HTTP/1.1, it inspects **HTTP/2** (with HPACK), tunnels and records **WebSocket** (over HTTP/1.1), and records **gRPC** stream framing; add **Firefox/NSS trust**, an optional **TLS key-log export** for pinned applications, and produce a written **QUIC/HTTP/3 evaluation** (no implementation promised). Exit: representative `curl --http2`, a Chromium h2 client, and a gRPC client in the selected sandbox are decoded into HAR (gRPC as metadata + trailers, no protobuf); WebSocket handshakes are recorded and tunneled; boxed Firefox trusts the session CA after an opt-in; `SSLKEYLOGFILE` decrypts the captured PCAPNG in Wireshark.

**Architecture:** All Phase 5 work lives in `SbieCapture.exe` and its user-mode test suites. SbieDrv, SbieSvc, the LPC wire, and the WFP redirect path are unchanged. The broker's ALPN callback advertises `h2` alongside `http/1.1`. A new HTTP/2 relay demultiplexes downstream streams, decodes HPACK into the existing logical request/response model, and writes one HAR entry per stream. Upstream stays HTTP/1.1 (translate) for the first deliverable; a later slice adds h2→h2 upstream so gRPC survives. WebSocket is an HTTP/1.1 upgrade that switches to a transparent byte tunnel after the 101. No new driver code, no new LPC message, no new advertised capability bit in the MVP.

**Tech Stack:** Existing `SbieCapture.exe` (C, `cl.exe` /W4 /WX, Win32 sockets, no CRT in SbieDll but full CRT in the broker), OpenSSL 3.x from `D:\vcpkg\installed\x64-windows` (libssl-3-x64 / libcrypto-3-x64), hand-rolled parsers only (no nghttp2 in the default plan — see Open Questions).

---

## Locked decisions

These are not open questions. Do not re-litigate them while implementing.

1. **Driver / SbieSvc / WFP unchanged.** Phase 5 is broker-only. Do not add callouts, LPC message IDs, or QSbieAPI virtuals. The only acceptable wire-surface change is a *trailing* start flag or a new SET-export handle for the key-log file, and that can be deferred until the broker pieces are proven.
2. **Hand-rolled codecs, not libraries.** HPACK (RFC 7541) and HTTP/2 framing are implemented in `hpack.c` and `http2.c` with unit tests, exactly as `http11.c` / `redact.c` / `har.c` were in Phase 4. This keeps the security-relevant parser surface small and reviewable. nghttp2 is the documented escape hatch if Huffman/codec size becomes a blocker (Open Questions), and if adopted it links into `SbieCapture.exe` only.
3. **HTTP/2 = terminate-and-translate first, h2→h2 later.** Downstream (client) HTTP/2 is fully terminated and mapped to logical request/response messages. For the first h2 deliverable the upstream (origin) leg speaks HTTP/1.1; this requires translating `:method`/`:scheme`/`:authority`/`:path` pseudo-headers to a request line and status back to `:status`, and dropping connection-specific headers. A later slice adds h2→h2 upstream for fidelity and because gRPC requires it.
4. **gRPC = metadata + trailers + body tunnel, never protobuf.** A stream whose request `content-type` is `application/grpc` is recorded as a HAR entry with `:path` (method), request/response headers, `grpc-status`/`grpc-message` trailers, and a message count; body bytes are captured only under `CAPTURE_FLAG_INCLUDE_BODIES` and the per-body cap. Protobuf decoding is out of scope (needs descriptors, per the architecture doc).
5. **WebSocket = upgrade detect + byte tunnel.** On HTTP/1.1, detect `Upgrade: websocket` + `Connection: Upgrade` + `Sec-WebSocket-Key`. Pass the handshake through unchanged, then switch to a transparent bidirectional relay. Record the handshake and final tunneled byte counts in HAR; no per-message framing/decoding in the MVP.
6. **Firefox/NSS is opt-in and boxed-profile-only.** Primary mechanism: set `security.enterprise_roots.enabled = true` in the sandboxed Firefox profile so it trusts the host Root store where the Phase 4 persistent session CA already lives. Stronger mechanism (if NSS `certutil` is available): inject the CA public cert into the boxed profile's `cert9.db`. Never touch the host Firefox profile or host NSS databases. Document that Firefox must be (re)started after the CA is imported.
7. **TLS key-log is explicit and off by default.** The broker attaches `SSL_CTX_set_keylog_callback` to both downstream and upstream contexts and appends `CLIENT_RANDOM` lines to a caller-opened key-log file. LocalSystem never creates or overwrites a client-supplied path. No key-log without an explicit opt-in at session start.
8. **Capability bits stay as-is.** `CAPTURE_CAP_HTTPS_INSPECTION` / `CAPTURE_CAP_HAR_EXPORT` remain the only advertised bits. HTTP/2, WebSocket, and gRPC are "better HTTPS inspection", not new capabilities. Firefox trust and key-log are broker-internal/start-flag features and are not advertised until live-verified.
9. **Phase 4 invariants are unchanged.** Redirect-context auth before any serve, fail-closed on broker death, default header redaction, bodies opt-in, 64 KiB per-body cap, 64 MiB HAR cap, 300 s max, 64 concurrent MITM connections (mapped to h2 streams), loopback-only listener, ALPN `http/1.1` remains offered so h1-only clients keep working.
10. **Personal host constraints:** no ARM64 full link, no official driver signing, no `git reset` / `git clean`, keep `NetworkEnableWFP=y`, do not use installed `Start.exe`, do not load parsers/OpenSSL into `SbieDrv`/`SbieSvc`. Test-build with `cl.exe` + vcpkg OpenSSL as in `HttpsMitmTests/build_https_mitm_tests.cmd`.

---

## Current baseline (do not regress)

| Piece | Today (Phase 4, HEAD `3e6552c6`) |
| --- | --- |
| Downstream ALPN | `http/1.1` only (`HttpsMitm_AlpnSelect`, `https_mitm.c:100`) |
| Relay | single request/response per `HttpsMitm_ServeOnce`; reads header + `Content-Length` only; no chunked, no keep-alive, no multiplexing |
| Upstream connect | IPv4 only (`HttpsMitm_ConnectTcp`) |
| HAR | HTTP/1.1 only (`har.h` includes `http11.h`; `HAR_EXCHANGE` holds `HTTP11_REQUEST`/`HTTP11_RESPONSE`) |
| Broker dispatch | `capture_https_broker.c` accept loop → `HttpsMitm_ServeOnce` |
| Capability bits | `httpsInspection` / `harExport` on after Phase 4 Slice 8 (11/11 live isolation) |
| Tests | `HarTests`, `HttpsMitmTests`, `CaptureQueueTests` (wire/lifecycle/view), `PcapngTests` |

Known Phase 4 relay gaps that Phase 5 must close because the h2→h1 and WebSocket paths depend on them: chunked transfer decoding, and multiple sequential exchanges on one HTTP/1.1 connection (keep-alive). These are folded into Slice 3.

---

## Data path (HTTP/2, downstream h2 → upstream h1, first deliverable)

```text
boxed client → WFP redirect → broker listen socket (unchanged)
    |
    +-- TLS accept (SNI leaf mint, ALPN: h2 | http/1.1)
    |
    +-- if ALPN == "h2":
            demux frames (SETTINGS/WINDOW_UPDATE/PING handled locally)
            per stream: collect HEADERS + CONTINUATION → HPACK decode
                        → build logical request (method/authority/path/headers)
            translate to HTTP/1.1 request → upstream h1 socket (existing)
            read h1 response (incl. chunked) → translate to :status + headers
            HPACK encode → downstream HEADERS + DATA frames
            write HAR entry (serverIP = original remote, alpn = "h2")
    +-- if ALPN == "http/1.1":
            existing h1 relay, hardened for chunked + keep-alive
            if Upgrade: websocket → 101 pass-through → byte tunnel
```

### HPACK scope (RFC 7541)

- Static table: all 61 entries.
- Dynamic table: bounded (default 4096 bytes), LRU eviction, per-direction encoder/decoder.
- Integer and string representations (indexed, literal with/without indexing, never-indexed, dynamic-size-update).
- Huffman encode/decode (Appendix B table).
- Decode limits: reject oversized header blocks and name/value over `HTTP11_MAX_*` bounds; a malformed block fails the stream (RST_STREAM) and is recorded as a decode error, never a broker crash.

### HTTP/2 frame scope (RFC 7540)

- Frame header (9 bytes) parse + serialize with length/type/flag/stream-id checks.
- SETTINGS (both directions, ACK), WINDOW_UPDATE, PING, GOAWAY, RST_STREAM handled at the connection level.
- HEADERS/CONTINUATION/DATA assembled per stream.
- Flow control: honor peer WINDOW_UPDATE for downstream DATA we emit; a coarse flow-control pass is acceptable for the first deliverable (documented) as long as it does not deadlock typical clients.
- `:authority` is required on downstream requests; use it as the SNI/HAR host when present.

### HAR record additions (backward compatible)

- `alpn` becomes `"h2"` / `"http/1.1"` / `"grpc"` as negotiated.
- `httpVersion` is `"HTTP/2"` for h2 streams.
- New `_sandboxie` fields: `streamId`, `grpcStatus`, `grpcMessage`, `wsTunnelBytesIn`, `wsTunnelBytesOut`, `decodeError` (set when HPACK/frame parsing failed but the connection was not torn down).

---

## Control wire

No new message IDs. The only deferred additions (Slice 7, key-log) are:

```c
#define CAPTURE_FLAG_KEYLOG             0x00000010  /* broker writes SSLKEYLOGFILE */
#define MSGID_CAPTURE_SET_KEYLOG_EXPORT 0x200B      /* caller-opened key-log file handle */
```

These are not implemented until the broker key-log path is proven; unknown flag bits still return `STATUS_INVALID_PARAMETER` before then.

---

## Slice-by-slice plan

Each slice is one logical commit. Do not advertise anything new until Slice 9.

### Slice 0 — Plan only

This file. No code.

### Slice 1 — HPACK codec (RFC 7541)

**Objective:** Deterministic user-mode tests for HPACK decode + encode.

**Files:** `SandboxieTools/SbieCapture/hpack.h` / `hpack.c`, `SandboxieTools/HpackTests/` (+ `build_hpack_tests.cmd`).

**Behaviour:** decode RFC 7541 Appendix C header blocks into name/value pairs; encode back; dynamic-table eviction; Huffman round-trip; reject malformed integers/strings. No sockets, no TLS.

**Verify:** `HpackTests.exe` prints `hpack tests passed`; all Appendix C vectors match.

### Slice 2 — HTTP/2 frame codec

**Objective:** Parse and serialize HTTP/2 frames and a per-connection stream table.

**Files:** `SandboxieTools/SbieCapture/http2.h` / `http2.c`, `SandboxieTools/Http2Tests/`.

**Behaviour:** header parse/serialize with bounds; SETTINGS/WINDOW_UPDATE/PING/GOAWAY/RST_STREAM; HEADERS+CONTINUATION reassembly; DATA accumulation with flow-control accounting; stream state (idle/open/half-closed/closed). No sockets.

**Verify:** `Http2Tests.exe` passes; malformed frames are rejected without overrun.

### Slice 3 — HTTP/1.1 chunked + keep-alive (relay hardening)

**Objective:** Close the two Phase 4 relay gaps that h2→h1 and WebSocket depend on.

**Files:** `http11.c` / `http11.h` (chunked framing helpers), `https_mitm.c` (`HttpsMitm_ReadMessage` → chunked + multiple exchanges), `HarTests` + `HttpsMitmTests` additions.

**Behaviour:** decode chunked request/response bodies; loop `ServeOnce` over keep-alive exchanges until close; preserve Phase 4 single-exchange tests.

**Verify:** existing `HarTests` / `HttpsMitmTests` stay green; new chunked + two-exchange-in-one-connection tests pass.

### Slice 4 — WebSocket upgrade tunnel

**Objective:** Detect and tunnel WebSocket over HTTP/1.1.

**Files:** `https_mitm.c` (upgrade detect + relay), `har.c` (ws byte-count fields), `HttpsMitmTests` additions.

**Behaviour:** after a valid 101, stop HTTP parsing and relay bytes bidirectionally until either side closes; record handshake + tunneled byte counts in HAR. No message decode.

**Verify:** loopback WebSocket handshake test tunnels N bytes both ways; HAR shows `wsTunnelBytesIn/Out` and no body decode.

### Slice 5 — HTTP/2 downstream termination → HAR (upstream h1)

**Objective:** Advertise `h2` and decode downstream HTTP/2 into HAR via h1 upstream.

**Files:** `https_mitm.c` (ALPN offers `h2`; new h2 relay path), new `http2_relay.c` (or inside `https_mitm.c`), `har.c` (h2 fields), `HttpsMitmTests` h2-client additions.

**Behaviour:** full downstream h2 termination, pseudo-header → request-line translation, upstream h1, h1 response → h2 HEADERS/DATA, one HAR entry per stream, redaction applied, bodies opt-in.

**Verify:** an h2 client (curl `--http2` or a small test h2 client) against a local h1 upstream produces correct HAR; h1-only clients still work; pinning/handshake failures still retain PCAPNG.

### Slice 6 — h2 → h2 upstream + gRPC stream capture

**Objective:** Upstream ALPN offers `h2`; when negotiated, h2 upstream; recognize gRPC.

**Files:** `https_mitm.c` (upstream ALPN), `http2_relay.c` (upstream h2 + gRPC detection), `har.c` (grpc fields), `HttpsMitmTests` + a small gRPC echo fixture.

**Behaviour:** upstream h2 for fidelity; `application/grpc` streams recorded with `:path`, headers, `grpc-status`/`grpc-message` trailers, and message count; body tunneled (opt-in bytes) without protobuf.

**Verify:** local gRPC echo round-trips; HAR has `grpcStatus=0` and correct method; a non-gRPC h2 upstream still produces clean HAR.

### Slice 7 — TLS key-log export

**Objective:** Emit `CLIENT_RANDOM` key-log lines for Wireshark.

**Files:** `https_mitm.c` (`SSL_CTX_set_keylog_callback` on both contexts), `capture_https_broker.c` / `main.c` (key-log handle/path plumbing), `HttpsMitmTests` additions.

**Behaviour:** on `CAPTURE_FLAG_KEYLOG`, append `CLIENT_RANDOM <hex> <hex>` per handshake to the caller-opened file; no key-log otherwise.

**Verify:** a loopback MITM session writes ≥2 `CLIENT_RANDOM` lines; Wireshark opens the Phase 4 PCAPNG with the key-log and decrypts.

### Slice 8 — Firefox/NSS trust

**Objective:** Boxed Firefox trusts the session CA, opt-in, boxed-profile-only.

**Files:** a small helper (extend `SbieCapture --import-ca` or a script) for `security.enterprise_roots.enabled` and optional `certutil` cert9.db injection; `Docs/SandboxCaptureMcp.md` guidance.

**Verify (live):** boxed Firefox loads `https://example.com` with the CA imported once (host Root already has it from Phase 4); host Firefox profile and NSS files hash-unchanged; removal/restart behaviour documented.

### Slice 9 — Live isolation + docs

**Objective:** Prove no isolation regression, then update status docs.

**Tests:** re-run the Phase 4 Slice 8 live isolation suite (Box A / Box B / host, pinning, broker kill, cross-SID) plus new h2/ws/grpc probes inside a box. Update `Docs/SandboxCaptureMcp.md` (Phase 5 status), `CHANGELOG.md`. Only then decide whether Firefox/key-log warrant new capability bits or MCP flags.

**Verify:** Phase 4 isolation still 11/11; new h2/ws/grpc traffic appears only in the selected box's HAR; `git diff --check` clean.

---

## Files likely to change

### New

- `SandboxieTools/SbieCapture/hpack.h` / `hpack.c`
- `SandboxieTools/SbieCapture/http2.h` / `http2.c`
- `SandboxieTools/SbieCapture/http2_relay.c` (and header if needed)
- `SandboxieTools/HpackTests/`
- `SandboxieTools/Http2Tests/`
- `Docs/Phase5ProtocolExpansion.md` — this file

### Modify

- `SandboxieTools/SbieCapture/https_mitm.c` / `https_mitm.h` — ALPN h2, h2 relay, WebSocket, key-log
- `SandboxieTools/SbieCapture/http11.c` / `http11.h` — chunked helpers
- `SandboxieTools/SbieCapture/har.c` / `har.h` — h2/ws/grpc fields
- `SandboxieTools/SbieCapture/capture_https_broker.c` / `main.c` — key-log handle (Slice 7)
- `SandboxieTools/HttpsMitmTests/`, `HarTests/` — new cases
- `Docs/SandboxCaptureMcp.md`, `CHANGELOG.md` — after the backend is real

### Do not touch unless a compile forces it

- `SbieDrv` / `SbieSvc` / `capture.c` / `wfp.c` / `api_defs.h` / `msgids.h` (except Slice 7's deferred flag/msgid, and only then after broker proof)
- `NetworkAccess` permit/block logic
- `CCaptureView` / `CPacketCaptureView` / `CHttpsCaptureView` behaviour (SandMan UI is out of Phase 5 scope unless explicitly requested)
- installer packaging / signing / ARM64 defaults

---

## Explicitly out of scope

- QUIC termination and HTTP/3 parsing (evaluate only; UDP 443 stays ciphertext on the Phase 3 passive path)
- Protobuf decoding of gRPC bodies (needs descriptors)
- WebSocket per-message framing/decoding
- Per-stream body content beyond the existing opt-in + cap
- New advertised capability bits before Slice 9 live proof
- Win7 SOCKS5 capture fallback
- Machine-wide sniffing
- Official EV signing, ARM64 full link, installer packaging

---

## Risks

| Risk | Mitigation |
| --- | --- |
| Hand-rolled HPACK/Huffman is large and bug-prone | Appendix C vectors + fuzz-ish malformed inputs; nghttp2 as documented fallback |
| h2 multiplexing rewrites the single-exchange relay | Keep the h1 path intact; h2 is a separate relay path; regression-run Phase 4 tests every slice |
| h2→h1 translation loses semantics (cookies, ordering, connection headers) | Strip connection-specific headers; document; h2→h2 upstream in Slice 6 restores fidelity |
| Flow-control deadlock on downstream DATA | Coarse window accounting first; verify with a real browser client before claiming h2 works |
| Firefox enterprise-roots changes trust scope beyond our CA | Boxed-profile-only preference; verify host profile + NSS hashes unchanged |
| Key-log leaks session keys on disk | Explicit opt-in; caller-opened file; documented risk (standard Wireshark workflow) |
| New parser crashes the broker | All parsers fuzz-bounded in unit tests before live; broker runs in the existing kill-on-close job |

---

## Open questions (do not block Slice 1–2)

1. **Hand-roll HPACK vs nghttp2.** Default is hand-rolled for reviewability, matching Phase 4's no-library convention. If the Huffman table + codec balloons past ~1,500 lines or tests get flaky, switch to nghttp2 (link into `SbieCapture.exe` only) and note it here.
2. **h2→h2 upstream priority.** Slice 6 (h2→h2 + gRPC) is the largest slice. Confirm with the user whether gRPC is a hard Phase 5 requirement or can slip to Phase 5.1; if it slips, Slice 5 (h2→h1) still delivers HTTP/2 inspection for browsers/curl.
3. **Firefox mechanism.** `security.enterprise_roots.enabled` is the least invasive but trusts the whole host Root store; `certutil` cert9.db injection is more targeted but needs NSS tools in the box. Decide which is the MVP during Slice 8.
4. **Key-log surface.** Whether key-log needs a new SET-export message or can ride on an existing handle is decided in Slice 7 after the broker callback works.

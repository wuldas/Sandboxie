# Sandbox Capture and MCP Architecture

## Status

This document defines the architecture and delivery plan for sandbox-scoped
network capture, optional HTTPS inspection, and a Model Context Protocol (MCP)
interface.

The first two implementation slices establish the versioned control plane and
a bounded WFP ALE connection-audit backend. They do not claim packet-capture
support: connection-audit records describe authorization attempts and contain
no packet payload, TCP stream, TLS plaintext, or HTTP data.

Current implementation status:

- Phase 1 control wire, owner-scoped service sessions, QSbieAPI wrappers, and
  the MCP stdio executable are implemented.
- Phase 2 adds fixed-size nonpaged per-session driver queues for WFP ALE connect
  and receive/accept authorization metadata. SbieSvc is the only driver drain
  consumer and applies owner, box, SID, Windows-session, PID, and process-
  creation-time isolation before returning records.
- The service advertises `CAPTURE_CAP_CONNECTION_AUDIT` only while the WFP
  backend is ready. WFP must be enabled through `NetworkEnableWFP` before the
  driver starts; otherwise start returns `STATUS_DEVICE_NOT_READY`.
- QSbieAPI and the MCP `capture_read_events` tool destructively drain at most
  32 fixed 80-byte records per request. Driver retention is capped at 256
  records per active capture and overflow only increments a drop counter.
- Packet and HTTPS start requests still return `STATUS_NOT_SUPPORTED`.
  PCAPNG/HAR export, payload capture, and TLS interception remain future
  phases.
- SandMan now has a Connection Audit view, menu entry, sandbox context-menu
  action, and process context-menu action. It records authorization-attempt
  metadata only. The view drains driver events into a bounded UI queue,
  paints them in time-budgeted batches, can filter the visible table, and
  can export the currently visible rows as UTF-8 CSV.
- Live-driver Box A / Box B / host isolation was verified on a personal
  test system. Process-churn was verified on the same host: later children
  are included, host traffic is excluded, and process-scoped sessions stay
  bound to PID plus creation time. OS-level PID reuse was not observed.

## Goals

- Capture only traffic attributed to a selected sandbox or selected process in
  that sandbox.
- Include processes that join the selected sandbox after a capture starts when
  requested.
- Support IPv4, IPv6, TCP, and UDP without collecting unrelated host traffic.
- Export passive captures as PCAPNG.
- Optionally inspect HTTPS traffic without installing trust material on the
  host or in another sandbox.
- Expose bounded, auditable capture operations through SandMan and a local MCP
  server.
- Keep untrusted packet, TLS, and HTTP parsing outside SbieDrv and SbieSvc.
- Preserve Windows 7 support for the existing core. Features that require newer
  WFP APIs must be capability-gated at runtime.

## Non-Goals

- A machine-wide packet sniffer.
- Guaranteed HTTPS decryption for certificate-pinned, mutually authenticated,
  ECH-only, or application-specific TLS implementations.
- HTTP/3 decryption in the first release.
- Arbitrary command execution, sandbox deletion, or unrestricted configuration
  mutation through MCP.
- Loading packet parsers, OpenSSL, or other large third-party libraries into
  SbieSvc or the kernel driver.

## Existing Foundations

Sandboxie already provides several building blocks:

- SbieDrv tracks sandbox process creation, process creation time, box name, user
  SID, and Windows session.
- `Sandboxie/core/drv/wfp.c` maintains a nonpaged PID lookup for network policy
  and classifies outbound connect and inbound accept authorization events.
- SbieDll implements TCP SOCKS5 redirection for compatible applications.
- SbieSvc provides authenticated-by-context request routing over its LPC port.
- QSbieAPI provides chunked SbieSvc requests and the SandMan-side process and
  sandbox model.

The current WFP implementation is a policy callout, not a packet capture
implementation. It registers ALE authorization layers and does not consume
`layerData` or associate flow context. The current monitor ring is allocated
from paged pool and therefore cannot be written from WFP classification paths
that may run at DISPATCH_LEVEL.

## Security Invariants

The following invariants are release blockers:

1. A capture for Box A must not contain host, Box B, or another user's traffic.
2. A PID is never a sufficient identity by itself. Attribution uses PID plus
   process creation time and the sandbox identity tuple of box name, SID, and
   Windows session.
3. Original network policy is evaluated before any proxy redirection. A proxy
   cannot turn a denied destination into an allowed destination.
4. A capture broker accepts only connections carrying a valid WFP redirect
   context or another service-issued, single-use capability bound to the
   original process and destination.
5. Broker failure cannot silently restore direct network access in HTTPS
   inspection mode.
6. The host certificate stores and other sandboxes never trust a capture CA.
7. CA private keys, generated leaf private keys, and captured bodies are not
   readable by sandboxed processes.
8. SbieSvc does not parse packet payloads, TLS records, HTTP messages, or MCP
   JSON.
9. Kernel capture buffers are bounded. Passive-capture overflow increments a
   drop counter instead of blocking network traffic or allocating unbounded
   memory.
10. All service requests use the caller identity supplied by LPC. Request
    payloads cannot assert a trusted PID, SID, session, or ownership identity.

## Architecture

```text
Sandboxed process
    |
    +-- ALE audit ------> SbieDrv WFP --> bounded nonpaged queue
    |                                      |
    |                                      v
    |                               SbieSvc CaptureServer
    |                                      |
    |                                      v
    |                               QSbieAPI / SbieMcp
    |
    +-- future payload -> SbieDrv WFP --> SbieCaptureBroker --> PCAPNG
    |
    +-- HTTPS path ----> WFP connect redirect --> SbieCaptureBroker
                                                  |          |
                                                  |          +--> HTTP/HAR events
                                                  +-------------> upstream TLS

SandMan / SbieMcp
    |
    +--> QSbieAPI --> SbieSvc CaptureServer --> session and authorization control
```

### SbieDrv

The driver owns authoritative process attribution and enforcement. The Phase 2
backend observes the existing ALE authorization callouts without changing their
permit/block result. Later WFP layers are:

- ALE connect and receive/accept are implemented for policy and bounded
  connection-attempt metadata.
- ALE flow-established for associating stable flow context.
- Stream layers for bidirectional TCP application bytes.
- Datagram-data layers for UDP and QUIC datagrams.
- Transport layers where PCAPNG output requires packet boundaries and headers.
- Connect-redirect layers for transparent local HTTPS inspection where the OS
  supports the required redirect APIs.

The flow context will contain only fixed-size data needed in hot paths:

```text
capture session id
box identity hash
process id
process creation time
address family and protocol
local and remote endpoints
direction
policy generation
```

The driver will not perform TLS or application-protocol parsing.

### SbieSvc CaptureServer

`CaptureServer` is a separate SbieSvc message family. It owns:

- wire-version negotiation and capability reporting;
- caller and target authorization;
- capture-session identifiers and ownership;
- backend lifecycle and health state;
- event cursors, counters, and export-handle brokering;
- cleanup when the owning client disconnects.

The LPC port is connectable by untrusted local processes, so every operation
performs its own authorization. Initial policy is deliberately narrow:

- sandboxed callers cannot create or control captures;
- a normal caller can target only an enabled sandbox for the caller's exact
  user SID and Windows session;
- a PID target must currently belong to that sandbox, SID, and session;
- cross-user and cross-session access is rejected in wire version 1, including
  for elevated callers;
- stop and status operations require the original owner process and process
  creation time; administrator recovery is reserved for a later explicit API.

The control plane supports query, start, stop, status, owner-scoped listing, and
bounded connection-event drain. Caller identity is obtained from the LPC
client security context and cross-checked against the live primary process
token and process creation time. Sandbox enablement is evaluated with the
caller's SID and session rather than the LocalSystem service identity. Packet
and HTTPS capabilities remain clear.

Capture requests are capped independently of the historical maximum LPC
message size. Active sessions have per-owner and global limits, while stopped
session history is evicted within fixed bounds.

### SbieCaptureBroker

The broker is a signed, independently built process. It runs with the least
privileged user token that can perform its job and is placed in a kill-on-close
job controlled by SbieSvc.

Planned responsibilities:

- drain driver capture records;
- write PCAPNG and indexed metadata;
- terminate downstream and upstream TLS for explicitly enabled HTTPS sessions;
- parse HTTP/1.1 first, then HTTP/2 and WebSocket in later phases;
- enforce body-size, file-size, time, and memory limits;
- redact sensitive headers by default;
- expose records to CaptureServer through inherited or duplicated handles.

The broker executable path is fixed relative to Sandboxie's installation
directory. A client cannot provide an executable path or command line for a
LocalSystem launch.

### QSbieAPI and SandMan

QSbieAPI exposes typed capture requests and normalizes the versioned wire
structures into Qt value types. SandMan receives a dedicated capture model and
view rather than reusing `CTraceEntry`, because packet flows, HTTP exchanges,
and dropped-record accounting have different identity and retention rules.

The UI will distinguish:

- connection audit;
- passive PCAPNG capture;
- HTTPS inspection.

Unsupported features remain disabled based on service capability flags.

### MCP Server

`SbieMcp` is a separate, normal-user process. It uses QSbieAPI and never opens
the driver device or talks to a privileged capture backend directly.

The first transport is MCP stdio:

- stdin and stdout contain newline-delimited JSON-RPC messages only;
- diagnostics go to stderr;
- no listening socket is created;
- input messages have a fixed size limit and tool arguments are validated at
  runtime instead of relying only on the advertised JSON Schema;
- normal operations are rejected until the initialize response is followed by
  `notifications/initialized`;
- capture-changing tools retain SbieSvc ownership and authorization checks.

Initial tools and resources are intentionally bounded:

```text
Tools
  sandboxie_list_boxes
  sandboxie_list_processes
  capture_capabilities
  capture_start
  capture_stop
  capture_status
  capture_read_events

Resources
  sandboxie://boxes
  sandboxie://boxes/{box}/processes
  capture://sessions
  capture://sessions/{id}/summary
```

Packet lists and HTTP bodies will use cursor or offset pagination when their
backends are implemented. Whole capture files are exported to user-selected
files rather than embedded in a single MCP response.

## Control Wire Version 1

The SbieSvc message family starts at `0x2000`. Low byte `0xFF` is reserved by
PipeServer for process-disconnect notification.

Every versioned request starts with:

```c
MSG_HEADER h;
ULONG wire_version;
ULONG struct_size;
```

Rules:

- wire fields use fixed-width Windows integer types;
- 64-bit fields are explicitly aligned to 8 bytes;
- structures contain no pointer, `HANDLE`, `size_t`, C++ `bool`, or compiler-
  dependent enum values;
- strings are fixed-size only for the v1 sandbox name; future variable data
  uses checked offset and length pairs;
- services accept a known minimum `struct_size` and ignore unknown trailing
  fields when the wire version is supported;
- clients validate both the advertised reply length and the actual number of
  bytes received;
- unknown operations return `STATUS_INVALID_SYSTEM_SERVICE`;
- an unavailable backend returns `STATUS_DEVICE_NOT_READY` or a session error
  state, never a successful active capture state.

## HTTPS Inspection

### Preferred Path

On supported systems, SbieDrv uses WFP ALE connect redirection to a random
loopback listener owned by the broker. The redirect context binds the original
destination to the sandbox identity, process generation, policy generation,
and capture session. The broker copies WFP redirect records to its upstream
socket to prevent recursive redirection and preserve flow relationships.

### Windows 7 Path

Windows 7 remains supported by the core, but the modern redirect-handle APIs
used by the preferred path are not available. The first compatible fallback is
the existing injected SOCKS5 path, augmented with a service-issued, single-use
authorization that binds the original destination. Direct egress must remain
blocked while that fallback is active.

### Certificate Isolation

- Generate a unique CA per capture session or per disposable capture sandbox.
- Keep private keys outside the sandbox.
- Import only the CA public certificate into the selected sandbox's virtual
  current-user Root store.
- Perform the import through a helper launched inside that sandbox under the
  original user's token.
- Remove the sandboxed CA when the capture ends and require target applications
  to restart when their trust cache requires it.
- Verify by registry and file hashing that host certificate stores and Firefox
  NSS databases are unchanged.

### Protocol Matrix

| Capability | Planned support |
| --- | --- |
| TLS 1.2 over TCP | HTTPS MVP |
| TLS 1.3 over TCP | HTTPS MVP with bundled OpenSSL version from build variables |
| HTTP/1.1 | HTTPS MVP |
| HTTP/2 and HPACK | Later protocol phase |
| WebSocket over HTTP/1.1 | Later protocol phase |
| gRPC framing | Later protocol phase; protobuf decoding needs descriptors |
| HTTP/3 and QUIC decryption | Not in the first release; passive UDP capture only |
| Certificate pinning | Expected MITM failure; retain passive capture |
| ECH without another trusted hostname source | Not guaranteed |
| Mutual TLS | Not guaranteed for transparent MITM |
| Firefox/NSS trust | Separate compatibility phase |

## Data Retention and Redaction

Defaults are privacy-preserving:

- metadata is captured before bodies;
- `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, and common API
  key headers are redacted;
- bodies require explicit opt-in;
- per-body, per-flow, per-session, and output-file limits are mandatory;
- capture files are created in the caller's security context or through a file
  handle opened by the caller and duplicated by SbieSvc;
- LocalSystem never creates or overwrites an arbitrary client-supplied path.

## Delivery Plan

### Phase 0: Spikes and Safety Proofs

- Prove stable sandbox flow attribution with PID reuse tests.
- Prove nonpaged bounded buffering from WFP classification paths.
- Prove Windows 8+ connect redirection and recursion prevention.
- Prove sandbox-only certificate trust with host registry and NSS file diffs.

Exit criteria: Box A, Box B, and host traffic remain distinguishable under
process churn, IPv4/IPv6, and broker failure.

### Phase 1: Versioned Control Plane

- Add CaptureServer wire version 1.
- Add caller authorization and owner-scoped session lifecycle.
- Add QSbieAPI wrappers.
- Add an MCP stdio skeleton exposing capability and lifecycle operations.
- Keep packet and HTTPS capability bits clear until their backends exist.

Exit criteria: an unsandboxed same-SID, same-session client can create, query,
list, and stop its own inactive-backend session; sandboxed, cross-user, and
cross-session callers are rejected. Malformed wire messages and malformed MCP
arguments cannot broaden a process-scoped request into a box-scoped request.

### Phase 2: Connection Audit

- Add a dedicated fixed-capacity nonpaged connection-event queue. Implemented.
- Associate box, SID, Windows session, PID, and process creation time with each
  event. Implemented.
- Allow only authenticated SbieSvc to destructively drain bounded batches and
  expose them through QSbieAPI and MCP. Implemented.
- Add the SandMan connection view. Implemented.
- Complete real-driver Box A/Box B/host isolation and process-churn tests.
  Isolation and process-churn were verified on a personal test host. The
  churn run proved later boxed children appear in a box-scoped session,
  host traffic does not, process-scoped sessions stay bound to PID plus
  process creation time, and later boxed processes after the target exits
  do not leak in. OS-level PID reuse was not observed in that run.

Exit criteria: only selected sandbox connections appear, including later child
processes, with correct dropped-event accounting.

### Phase 3: Passive Packet Capture

- Add TCP stream, UDP datagram, and transport capture layers.
- Produce PCAPNG with IPv4/IPv6 and per-process metadata.
- Add snap length, file rotation, and time limits.

Exit criteria: Wireshark opens the output and no unrelated traffic is present.

### Phase 4: HTTPS MVP

- Add connect redirect and broker authentication.
- Add sandbox-only CA lifecycle.
- Support TLS 1.2/1.3 and HTTP/1.1.
- Add HAR export and default redaction.

Exit criteria: representative Chromium, WinHTTP, and curl traffic is decoded;
pinning failures are reported; broker failure does not leak direct traffic.

### Phase 5: Protocol and Compatibility Expansion

- HTTP/2, HPACK, WebSocket, and gRPC framing.
- Firefox/NSS compatibility.
- Optional TLS key-log adapters for selected pinned applications.
- Evaluate, but do not promise, QUIC termination and HTTP/3 parsing.

## Verification Matrix

Required validation includes:

- host, other-sandbox, other-user, and other-session exclusion;
- process exit and PID reuse;
- future child inclusion and PID-only target behavior;
- IPv4, IPv6, TCP, UDP, loopback, and proxy paths;
- existing `NetworkAccess` decisions before and after redirection;
- broker crash, SbieSvc restart, BFE restart, and policy reload;
- VPN, firewall, antivirus, and other WFP redirect callout coexistence;
- buffer exhaustion and output-file exhaustion;
- host certificate-store and Firefox profile integrity;
- malformed capture records, TLS records, HTTP messages, and compressed bodies;
- Win32, x64, ARM64, and affected ARM64EC build configurations;
- Windows 7 load compatibility when newer WFP APIs are absent.

## Change Isolation

Because SbieDrv and the driver/service protocol are security boundaries, work is
split into independently reviewable changes:

1. architecture document and control-plane ABI;
2. QSbieAPI and MCP control clients;
3. driver connection-audit queue;
4. passive packet backend;
5. HTTPS broker and certificate lifecycle;
6. higher-level protocol parsers and UI.

No phase may advertise a capability before its security and failure-mode tests
pass.

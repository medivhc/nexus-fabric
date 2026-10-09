# Nexus Fabric Current State — Deep Audit Continuation

> Continuation of `CURRENT_STATE.md` after section 54.
> Source baseline remains `48918863e70ef8589fbca6075c7ec11ca07e85a3` on `master` unless a section says otherwise.
> This file is a staging continuation only; it is intended to be merged back into `CURRENT_STATE.md` after the remaining source sweep so the established sections 1–54 are not accidentally overwritten while the GitHub connector requires whole-file replacement.

## 55. Small crate names hide very different maturity levels

A source-level sweep of the remaining portable crates confirms that workspace membership and module naming are extremely weak proxies for implementation maturity. Several crates that look symmetric in the architecture diagram are not symmetric in executable depth.

### 55.1 `nexus-diagnostics` is currently a compile anchor, not a diagnostics subsystem

`crates/nexus-diagnostics/src/lib.rs` contains only crate documentation and `#![forbid(unsafe_code)]`. The corresponding MODULE contract describes the desired responsibility — unified diagnostic DTOs, categories, cheap/deep diagnostic interfaces, and reason distinctions such as unknown/unreachable/unauthorized/no-valid-plan/crash-recovery — but explicitly says the skeleton provides only a minimal compile anchor and business APIs are to be added incrementally.

Therefore the current status is:

- diagnostics architecture/contract: **Contract**;
- executable unified diagnostic DTO/API implementation: **not present in the inspected `lib.rs`**;
- daemon/product diagnostics closure: **must not be inferred from the crate name**.

Any older architecture description that lists Diagnostics beside mature runtime components without a maturity qualifier overstates the implementation.

### 55.2 `nexus-delivery` is also still essentially a contract boundary

`crates/nexus-delivery/src/lib.rs` likewise contains only module documentation and the unsafe-code prohibition. Its MODULE contract defines a shared, domain-neutral Link/Path/Connection/Delivery-Request abstraction and explicitly forbids reverse dependency on Workspace/Compute/Service, but also labels the public API as a minimal compile anchor whose business surface will be added incrementally.

This matters because the repository already has several concrete delivery mechanisms — Fabric, TCP `FrameStream`, proxy transports, TURN, workspace sync streams — while the nominal shared `nexus-delivery` abstraction itself is not yet the concrete convergence point for all of them.

Current-state conclusion: **the architectural concept “shared Delivery layer” is stronger than the implementation of the `nexus-delivery` crate itself**.

### 55.3 `nexus-service` is implemented, but only the connect half of the declared responsibility

`nexus-service` is materially more implemented than the two crates above. It defines a `ServiceTransport` injection seam, `ServicePhase`, structured `ServiceError`, and a concrete `ServiceSession::connect` handshake. The current frozen behavior sends `CONNECT`, waits for `READY`, and enters `Active`; any other response is `Unauthorized` and transport failures remain distinct.

However, both source comments and MODULE contract say `connect != forward`, and the current frozen P0 only implements/connect-freezes the connect semantics. Forwarding is explicitly postposed.

So “Service Resource is implemented” is too broad. A more accurate statement is:

- portable service connect handshake: **Implemented**;
- transport dependency inversion: **Implemented**;
- service forwarding/data-plane behavior promised by the broader Responsibility line: **not established by this crate**;
- production composition and listener authorization: **must be proven separately**.

## 56. Discovery has evolved beyond its old P0 wording, but production use must still be traced

The top comments of `nexus-discovery` still describe a frozen remote-P0 static-discovery contract and say the discovery protocol is postposed. That statement is historically useful but no longer describes the entire crate.

The current source exports additional modules for aggregate discovery, LSA, mDNS, explicit pairing, and routing. The root module also contains:

- `StaticDiscovery` with explicit `PeerId -> SocketAddr` mapping;
- a generalized `Discovery` trait returning zero or more addresses;
- source attribution with priority ordering `Paired > Static > Lsa > Mdns`;
- per-source hit/miss metrics;
- dynamic `PresenceRegistry` with TTL and explicit `PeerUnknown` versus `PeerExpired` semantics;
- a strict `Identity != Locator` model.

This is a significant maturity jump relative to the old “static lookup only” description.

The important boundary remains unchanged: discovery resolves candidate locators/presence; it does not establish Connectivity. `resolve` APIs are intentionally query operations, and established data sessions should not depend permanently on bootstrap/discovery availability.

Current status should therefore be split:

- static discovery: **Implemented**;
- dynamic presence and TTL semantics: **Implemented**;
- aggregate/paired/LSA/mDNS/routing source code: **present and executable at crate level**;
- actual daemon/CLI production ownership and continuous network operation of every discovery source: **requires composition-root tracing; do not infer from module presence**.

This is another example where an old top-of-file “P0 frozen” statement and a much richer later implementation coexist in one source tree.

## 57. `nexus-connectivity` is a mixed-maturity mega-crate, not one uniformly finished subsystem

`nexus-connectivity` contains a large amount of functionality under one architectural layer: connectivity evaluation, virtual subnet primitives, relay/TURN, encryption/identity, dynamic routing, mesh DNS, firewall, token-bucket QoS, CAKE-like scheduling, reconnect, node tags, connection pooling, health checks, node priority, config-hot-reload logic, graceful-exit state, traffic statistics, group isolation, bandwidth policy, retry/failover, compression, fragmentation, certificate management, discovery enhancement and a data-plane pipeline.

The source itself is unusually explicit about maturity differences. Multiple module groups are labelled **“纯逻辑骨架”**. Later a `dataplane_pipeline` module is described as the real attachment point that wires firewall/QoS/compression/fragmentation into per-packet tunnel processing.

The root also implements a deterministic, zero-I/O `establish` contract: invalid locator and missing required authentication fail before `Established`; successful evaluation emits a structured replayable event sequence. This function is a connectivity state-machine/evaluation primitive, not proof that a real socket was opened.

This means the phrase “Connectivity implements X” must always be qualified with one of the following:

1. **pure model/state machine exists**;
2. **runtime adapter exists**;
3. **pipeline wiring exists**;
4. **composition root enables it**;
5. **current scenario/evidence proves it**.

Without that qualifier, the current crate layout makes it very easy to confuse a deterministic model with a production network mechanism.

A key architectural observation is that `nexus-connectivity` has accumulated both foundational delivery semantics and many product/network features. That does not automatically mean the boundary is wrong, but it does mean future refactoring should be evaluated against actual ownership and hot-path composition rather than the number of files or feature names.

## 58. Ingress is substantially implemented, but remains intentionally transport-neutral

`nexus-ingress` is not a listener/socket runtime. It is a portable protocol/classification layer that turns decoded input into neutral `FlowContext` values.

Current source includes:

- FlowContext construction for SOCKS5, HTTP, virtual packet interface and Native API origins;
- IPv4 packet decoding under `ip_packet`;
- an incremental SOCKS5 state machine with explicit protocol errors;
- RFC 1929 frame parsing;
- IPv4/domain/IPv6 destination decoding.

The SOCKS5 contract has two important limitations that should stay visible in the baseline:

- only CONNECT is accepted; BIND and UDP ASSOCIATE are explicitly rejected as unsupported commands;
- the state machine validates username/password frame format, but actual credential authorization is delegated upward; successful RFC 1929 frame parsing is not itself an authorization decision.

The crate explicitly does not call Core Planner and does not own platform transparent-interception APIs. That separation is real in source: Ingress emits neutral context, while policy/planning/session ownership sits above it.

## 59. Proxy configuration and proxy path transport contain a concrete internal drift

`nexus-proxy-config` is a relatively substantial typed configuration layer rather than a YAML placeholder. It parses a deterministic YAML subset and validates typed inbounds, rules, groups, outbounds, DNS, speed-test and rule-provider configuration. Rule kinds now include domain/domain-suffix/IP-CIDR/GEOIP/GEOSITE/rule-set/source-port/destination-port/process-name/MATCH. Group types include selector, urltest, load-balance and relay.

Most importantly, current `OutboundKind` explicitly contains:

`Direct`, `Relay`, `Shadowsocks`, `Vmess`, `Trojan`, `Socks5`, `Anytls`, `Vless`, `Hysteria2`.

However, `nexus-proxy-transport/src/lib.rs` still contains a comment claiming that no SOCKS5 outbound structure exists in `nexus-proxy-config` and that `OutboundKind` has no `Socks5` variant. That statement is demonstrably stale relative to the current proxy-config source.

This is a high-quality drift example because it is not a difference between a design document and code; it is **a contradiction between two executable crates' current source comments**.

`nexus-proxy-transport` itself is a per-link path transport, distinct from per-flow proxy egress. It wraps a connected TCP stream with a two-byte big-endian datagram framing layer implementing Fabric's `UdpTransport`, allowing QUIC/Fabric traffic to traverse a proxy without changing the Fabric driver. The proxy sees outer transport traffic while Fabric remains the end-to-end encryption boundary.

The crate currently provides SOCKS5, Shadowsocks and Trojan transport paths, including a `trojan_tls` module and exported TLS transport types. Its top comment still describes Trojan as plaintext “this phase” with TLS postponed, which is also stale relative to the exported `trojan_tls` implementation.

Two source-comment drifts are therefore confirmed in the same crate:

1. “proxy-config has no SOCKS5 outbound” — false in current source;
2. “Trojan TLS postponed” — inconsistent with the current `trojan_tls` module/export.

The baseline must use executable symbols and current config enums as the stronger evidence.

## 60. Measurement and Scheduler are deliberately small portable cores

### 60.1 Measurement records facts, not policy

`nexus-measurement` is a zero-I/O portable facts store. `LinkMeasurement` contains optional RTT/loss/jitter/throughput plus confidence. Unknown values remain `None`; unknown RTT sorts after known RTT rather than being silently treated as good.

`MeasurementTable` performs deterministic per-provider overwrite/get. No business weights or score fields are present. A `LatencyProbe` trait exists, but the actual I/O implementation is explicitly delegated to the composition root.

Therefore the architecture invariant `Measurement != Score` is not merely documentary; it is reflected in the type surface.

### 60.2 Scheduler schedules submission; it does not execute work

`nexus-scheduler` is also a portable core with no Nexus internal dependency. It implements one-shot `At` and periodic `Every` schedules, registration/cancellation/list/get, deterministic `tick`, serializable `SchedulerSnapshot`, and restore.

The trigger action is an injected `SubmitFn`. The scheduler decides when to submit and how to advance the next-fire state; it does not execute the Task itself.

Important runtime semantics include:

- successful `At` fires once and becomes `Fired`;
- successful `Every` advances `next_run_secs` by exactly one interval;
- failed submission leaves the schedule due and `Scheduled`, so a later tick retries;
- persistence is a caller/composition-root responsibility through `SchedulerSnapshot`.

The `apps/nexus` crate declares a dependency on `nexus-scheduler`, but this source audit has not yet proven a daemon-owned durable scheduler loop. Therefore “scheduler logic implemented” must not be upgraded to “daemon scheduler service production-closed” without tracing its composition and persistence owner.

## 61. A package exists outside the root's explicit 50-member list: `nexus-workspace-intel`

The root `Cargo.toml` explicitly lists 50 workspace member paths. However, the repository also contains `crates/nexus-workspace-intel`, and `apps/nexus/Cargo.toml` declares it as a path dependency.

This package is not a placeholder. Its source is split into `trace`, `graph`, `profile`, `estimator`, `prefetch`, `delivery` and `store` modules. Its stated architecture is deliberately non-authoritative and deletion-safe:

AccessTrace
→ WorkspaceGraph
→ WorkingSetEstimator
→ PrefetchScheduler
→ missing object/chunk `ResourceDeliveryRequest`
→ Core Planner.

The authoritative Workspace DAG/HeadSet/Journal remains in `nexus-workspace`; intelligence state can be deleted and rebuilt. `PrefetchScheduler` decides what/when/how much to prefetch but must not select Provider or Path. `IntelStore` is physically separate non-authoritative persistence.

This reveals two useful current-state facts:

1. the earlier “50 workspace members” statement is precisely an **explicit root-member-list count**, not a complete inventory of every Nexus package under `crates/` that product code consumes;
2. Workspace intelligence is already a real implementation area and should be represented in architecture diagrams even though it is intentionally outside correctness authority.

Because Cargo can automatically enroll path dependencies located under the workspace root unless excluded, the exact machine-resolved workspace-member count should ultimately be taken from `cargo metadata`, not inferred solely from the literal `members = [...]` array. No `exclude` entry is present in the inspected root manifest.

## 62. Updated maturity map for the newly audited crates

| Area | Contract | Executable source | Product wiring established by this pass? | Current interpretation |
|---|---:|---:|---:|---|
| diagnostics | yes | minimal compile anchor only | no | Contract-only/minimal |
| delivery abstraction crate | yes | minimal compile anchor only | no | Architectural seam stronger than crate implementation |
| service connect | yes | yes | not proven here | Implemented connect-only; forward still separate |
| discovery static/presence | yes | yes | partially known | Implemented |
| discovery aggregate/paired/LSA/mDNS | yes/source present | yes | not fully traced | Implemented source, wiring pending audit |
| connectivity deterministic establish | yes | yes | consumed by higher layers in places | Pure/state-machine primitive |
| connectivity feature modules | mixed | broad | mixed | Must classify module-by-module |
| ingress protocol/classification | yes | yes | used by proxy/TUN composition elsewhere | Implemented portable layer |
| proxy config | yes | substantial | loaded by app/daemon composition | Implemented typed config |
| proxy path transport | yes | substantial | exact fallback selection still to trace | Implemented transport mechanisms |
| measurement | yes | yes | producer ownership not fully traced | Facts layer implemented |
| scheduler | yes | yes | daemon durable loop not proven | Portable scheduling core implemented |
| workspace intelligence | yes | substantial | app dependency exists | Non-authoritative intelligence layer implemented |

The recurring theme is now strong enough to treat as a repository-wide audit rule: **Nexus Fabric cannot be accurately described by a flat list of crates. Every architecture diagram needs a maturity/ownership dimension, because similarly named boxes range from contract-only skeletons to production-owned long-running runtime components.**

## 63. New drift register entries from this sweep

The following contradictions or stale statements were added by this pass:

1. `nexus-proxy-transport` says proxy config has no SOCKS5 outbound; current `nexus-proxy-config::OutboundKind` does contain `Socks5`.
2. `nexus-proxy-transport` top comment says Trojan TLS is postponed; current source exports `trojan_tls`, `TlsTrojanTransport` and TLS configuration.
3. `nexus-discovery` top comments emphasize static P0/postponed discovery protocol, while the crate now contains aggregate, pairing, LSA, mDNS, routing and dynamic presence implementations.
4. A literal root `members` count of 50 omits the physically present and product-consumed `nexus-workspace-intel` package, so “50 members” must be labelled as the explicit manifest-list count rather than a total package inventory.
5. `nexus-diagnostics` and `nexus-delivery` have strong MODULE responsibility text but essentially empty executable `lib.rs` surfaces; diagrams that present them as peers of mature runtime crates overstate current implementation.

These are not cosmetic documentation issues. They are exactly the class of drift that caused the old architecture document to become unreliable: a reader can derive materially wrong implementation conclusions from comments or box names that were once true but no longer track executable reality.

## 64. Platform maturity is more asymmetric than the architecture names suggest

A direct source-level comparison of the five platform crates makes the asymmetry unambiguous.

### 64.1 Linux is a real platform runtime

`nexus-platform-linux` exports concrete modules for address assignment, transactional OS assembly, daemon/PID lifecycle, DNS, file leases, FUSE workspace projection, netlink, operation logging, route snapshot/apply/rollback, secure store, TUN and the VirtualPacketInterface adapter.

The crate therefore owns actual host side effects and recovery/rollback-sensitive behavior. Its maturity is qualitatively different from a contract-only adapter.

### 64.2 Windows also has concrete host integration, but a narrower scope

`nexus-platform-windows` exports scheduled-task autostart, DPAPI, network configuration, secure store, WinINET system proxy, Wintun VPI and the narrow Wintun FFI module. Unsafe code is intentionally concentrated in `wintun.rs`, while the rest of the crate consumes safe wrappers.

The separate `nexus-platform-host` executable is also much narrower than its name may imply: current source primarily exposes a Windows `vpi-capabilities` command for machine-verifiable capability declaration. The default path prints a repository-contract bootstrap string. It is not a general cross-platform host daemon.

### 64.3 macOS, Android and iOS remain source-level skeletons in their root crates

The inspected `src/lib.rs` files for `nexus-platform-macos`, `nexus-platform-android` and `nexus-platform-ios` contain only crate-level responsibility comments and `#![forbid(unsafe_code)]`; they do not expose concrete adapter modules in their root source.

Their MODULE contracts may describe Packet Tunnel/VPN lifecycle, underlay bypass, file projection and secure storage boundaries, but those contracts must not be represented as implemented parity with Linux/Windows.

A stronger platform matrix is therefore:

| Platform | Source maturity | Honest current statement |
|---|---|---|
| Linux | broad concrete adapters and host side effects | Runtime implementation |
| Windows | concrete VPI/proxy/secure-store/autostart/network adapters | Runtime implementation, narrower than Linux |
| macOS | root compile skeleton | Contract/skeleton |
| Android | root compile skeleton | Contract/skeleton |
| iOS | root compile skeleton | Contract/skeleton |

This is a larger difference than “some features missing per platform”; it is a difference in implementation generation.

## 65. `nexus-proto` is not yet the repository's real wire-schema authority

`nexus-proto/src/lib.rs` currently contains only module documentation, the unsafe-code prohibition and a statement that the crate defines a portable wire/control schema boundary and code-generation placeholder.

No executable schema types or generated protocol bindings are exposed in the inspected root source.

Meanwhile, real wire contracts already exist elsewhere: registry control frames, Fabric framing/QUIC semantics, N3 HTTP DTOs, workspace sync frames, proxy protocol implementations and various domain-local encoders/decoders.

Therefore a future architecture diagram must distinguish:

- the **intended centralized protocol-schema boundary** (`nexus-proto` contract);
- the **actual current wire contracts**, which are distributed across multiple crates.

Calling `nexus-proto` the current wire source of truth would be inaccurate.

## 66. Plugin support is real, but intentionally narrow and compile-time oriented

`nexus-plugin` has a concrete implementation, unlike the diagnostics/proto skeletons. It currently provides a versioned in-process obfuscation transport plugin point:

- hard API version check (`OBFUSCATE_API_VERSION`);
- static registry with duplicate/version rejection;
- `ObfuscateTransport` wrapping an already-established `TcpStream`;
- `ObfuscatedStream` preserving normal Read/Write stream semantics;
- builtin/dial/registry modules and success/failure counters.

The implementation is explicitly not a general dynamic extension platform. Its first-phase scope is obfuscation transport, synchronous std I/O and compile-time/static registration.

This matters for architecture wording: “Nexus has a plugin system” is true only with a scope qualifier. The current plugin mechanism should not be interpreted as arbitrary runtime-loaded business modules, WASM extensions, or a general MCP-like extension layer.

## 67. Updated architecture drift themes

After the platform/proto/plugin pass, the drift pattern can be grouped into four recurring classes:

1. **historical comments lag executable code** — e.g. discovery, nexusd and proxy-transport;
2. **contracts run ahead of implementation** — e.g. diagnostics, delivery, proto, macOS/Android/iOS;
3. **code exists but production ownership is not proven** — e.g. scheduler loop, several discovery sources, flow-session activation, workspace sync binding;
4. **one architectural box contains multiple maturity generations** — especially `nexus-connectivity` and `nexus-compute`.

This four-class model should be used during the rest of the audit. Every contradiction found should be assigned to one of these classes rather than being recorded as an undifferentiated “documentation mismatch”.

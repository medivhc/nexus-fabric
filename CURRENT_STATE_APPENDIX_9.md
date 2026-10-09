# CURRENT_STATE continuation — sections 134–143

> This file is a temporary continuation of `CURRENT_STATE.md`. It records code-first findings against the audited `master` source revision and must be merged back into the canonical baseline after the source sweep. Status words retain the baseline meanings: Contract / Implemented / Wired / Scenario-targeted / Verified / Production-closed.

## 134. `nexus-proxy-transport` is a real per-link transport, but automatic Path integration is still explicitly postposed

`crates/nexus-proxy-transport` is not a placeholder. It implements a synchronous `nexus_fabric::UdpTransport` over proxy-established TCP streams using two-byte big-endian datagram framing. The public surface includes SOCKS5 CONNECT, Shadowsocks transport, plaintext Trojan, and Trojan-over-TLS. The QUIC/Fabric layer is intentionally unchanged: callers can inject the transport through `FabricConn::connect_with_transport`.

Important layer boundary:

- this crate is **per-link transport** for carrying Fabric/QUIC through a proxy;
- `nexus-proxy` / `nexus proxy` are **per-flow egress** routing and forwarding;
- the two mechanisms solve different problems and must not be combined into one generic “proxy support” status.

The module contract itself explicitly says that `PathKind::Proxy` exists but automatic `PathManager` fallback linkage is postposed. `nexus-proxy-transport` is also forbidden from depending on `nexus-path`; the composition root must own that linkage.

Current status:

- SOCKS5 / SS / Trojan / Trojan-TLS per-link transport mechanism: **Implemented**;
- Fabric injection API compatibility: **Implemented**;
- PathManager automatic fallback to proxy transport: **Not Wired / explicitly postposed**;
- normal `nexusd` N1 composition consuming this transport: **not demonstrated by the inspected source**.

This is a concrete example where a production-grade transport primitive exists without the system-level route-selection ownership needed to make it part of the normal runtime.

## 135. `nexusd` declares `nexus-proxy-transport`, but its inspected dataplane/N1 composition does not consume it

`apps/nexusd/Cargo.toml` declares `nexus-proxy-transport` as a direct dependency. However, the inspected active composition surfaces do not show the crate being used:

- `main.rs`: no `nexus_proxy_transport` reference found in the inspected daemon root;
- `assembly.rs`: N1 is assembled through `nexus::network::build_session_manager` + `N1MeshBridge`; it does not construct a proxy transport;
- `dataplane.rs`: mesh forwarding is via `N1Sender`, while proxy-classified traffic is sent to the separate per-flow `ProxyEngine`;
- `proxy_fwd.rs`: implements its own per-flow proxy dial/relay logic and does not wrap Fabric QUIC in `nexus-proxy-transport`.

Therefore the direct Cargo dependency is not evidence of production attachment. The strongest current statement is:

> `nexus-proxy-transport` is available to `nexusd` at build time, but the audited daemon hot path does not establish a confirmed consumer.

This should remain **Implemented, not Production Wired** until an actual composition call is traced.

## 136. Corrected proxy capability matrix: foreground `nexus proxy` is broader than the daemon TUN `ProxyEngine`

Earlier audit stages risked collapsing two different product runtimes into one support table. The current source requires two matrices.

### Foreground `nexus proxy`

The CLI path calls `proxy_serve_once`, which:

1. accepts a real TCP client;
2. performs SOCKS5 or HTTP proxy ingress negotiation;
3. parses the full proxy config;
4. constructs `nexus_proxy::ProxyService` and performs per-flow rule/group routing;
5. creates a Session;
6. executes the selected outbound's real data path.

Confirmed foreground outbound implementations include:

- Direct;
- Shadowsocks;
- Trojan over TLS;
- AnyTLS;
- VLESS (TCP/TLS; Vision splice still partial);
- Hysteria2 (QUIC/H3 auth + TCP stream relay; UDP ingress integration still absent).

VMess remains materially weaker: the repository contains protocol/crypto implementation and self-consistency coverage, but the audited foreground product path still does not provide an equivalent real-server data-plane closure.

### `nexusd` TUN `ProxyEngine`

The daemon path is a separate engine. It selects the **first supported outbound entry in config order**, not the outbound selected by `ProxyService`'s per-flow rule result. Its current dial set is narrower:

- Shadowsocks (`chacha20-ietf-poly1305` only in this engine);
- Trojan plaintext;
- Trojan TLS under its local heuristic;
- SOCKS5.

It skips Direct, Relay, VMess, AnyTLS, VLESS and Hysteria2.

Consequently protocol maturity must be stated per runtime, not globally.

## 137. The daemon TUN proxy path does not currently honor the configured rule engine's outbound selection

`proxy.yaml` contains a rule engine and group model, and the foreground `nexus proxy` runtime actually evaluates it through `ProxyService::route()`.

`nexusd::proxy_fwd::ProxyEngine`, however, constructs itself by parsing `proxy.yaml` and calling `config.outbounds.iter().find_map(dial_config_from_outbound)`. This means it chooses the first outbound that its local engine can instantiate. It does **not** consume the per-flow rule decision that selected a tag.

This creates an important semantic split:

- configuration/rule layer may say a specific flow should use outbound `X`;
- daemon TUN proxy forwarding can instead use the first locally supported outbound `Y`.

So, for `nexusd` TUN proxying, “Clash-style rules configured” is not equivalent to “Clash-style per-flow rule routing enforced in the forwarding hot path”. This is a production-integration gap, not merely a missing protocol adapter.

## 138. `nexusd::ProxyEngine` Trojan TLS selection uses a local heuristic rather than a dedicated explicit transport selector

The daemon's `dial_config_from_outbound` maps `OutboundKind::Trojan` to TLS only when `skip_cert_verify` is true or `alpn` is present; otherwise it selects plaintext Trojan. The comments explicitly call plaintext the default.

This behavior differs from the richer foreground Trojan path, which constructs an actual rustls client and treats TLS settings as part of the outbound implementation.

Implication for CURRENT_STATE:

> Trojan support exists in both runtimes, but they do not share one canonical transport-selection implementation or identical semantics.

This is another duplicated composition decision that should not be hidden under one “Trojan = Wired” status.

## 139. Scheduler correction: persistent registry is real, autonomous scheduling and task submission are not

The Scheduler composition root is now precisely bounded:

- `schedule at/every/list/cancel/tick`: **Implemented and CLI Wired**;
- local snapshot persistence: **Implemented**;
- corrupt snapshot handling: **fail-loud**;
- atomic temp-file + rename update: **Implemented**;
- autonomous daemon timer / background tick ownership: **not found**;
- actual N3 task submission from the Scheduler: **not implemented**.

`make_submit()` currently returns a generated string `task-<resource>` and performs no execution. Therefore a successful `schedule tick` means the scheduling state machine fired successfully; it does **not** mean a Task was accepted or a command ran.

The accurate production statement is:

> Scheduler is a persistent manually-driven scheduling registry, not yet a closed autonomous job scheduler.

## 140. N3 CLI help text is materially stale relative to the executable implementation

`apps/nexus/src/main.rs` still advertises:

- `task submit --request ...` as “完整执行接线尚未装配”;
- `artifact get ...` as “完整下载尚未装配”.

The current executable code contradicts both statements.

`task_cli::run()` is a real thin client to the authenticated/versioned daemon N3 LocalAPI. Submit/show/cancel/artifacts/logs are converted into strict `TaskRequest` DTOs and executed via `task_localapi::execute`.

On Linux, `artifact get` performs a complete verified receiver flow:

- initial authorization/probe before output I/O;
- resumable page retrieval;
- record stability checks;
- durable receiver offset validation;
- final remote authorization at EOF;
- SHA-256 / size validation and no-replace atomic publication through the artifact receiver.

On non-Linux, verified Artifact download returns an explicit `UnsupportedCapability` rather than pretending success.

Therefore the CLI usage text is historical drift and must not be used as evidence of current N3 maturity.

## 141. `apps/nexus` is no longer accurately described as a generally “thin client”

The `main.rs` module header describes the CLI as a thin-client frontend, but executable dispatch contains many intentionally in-process product roots:

- `subnet`;
- `schedule`;
- `proxy`;
- `system-proxy`;
- `autostart`;
- `config`;
- `pair`;
- `node`;
- `plan`;
- `use`;
- `session`;
- `resource`;
- `grant`;
- `provider`;
- `run`;
- `network up/status`.

Only specific command families route through daemon LocalAPI. This reinforces the earlier finding that runtime ownership is intentionally or historically split across daemon-owned and CLI-owned composition roots.

Status implication:

> “CLI thin-client mode” is a partial architectural direction, not the current whole-product execution model.

## 142. Linux and Windows are both non-placeholder platforms, but their system-integration surfaces are different

The platform asymmetry should be represented by capabilities, not a single maturity rank.

Linux currently contains concrete source modules for, among others:

- address and route management;
- daemon/system integration;
- DNS integration;
- file lease;
- FUSE Workspace projection;
- netlink;
- operation logging;
- secure store;
- TUN and TUN-backed VPI assembly.

Windows currently contains concrete source modules for:

- Wintun;
- VPI;
- NetCfg/network configuration;
- DPAPI and secure-store integration;
- WinINET system proxy;
- Task Scheduler autostart.

Windows therefore should not be described as a skeleton platform. But it does not have the same Workspace/FUSE and Linux-specific durable execution integration that the N3/Workspace production path currently relies on.

The more useful platform statement is:

> Linux is the most complete server/daemon + Workspace/N3 execution platform; Windows has substantial networking/desktop-integration adapters; macOS/Android/iOS remain near-placeholder in the audited executable source.

## 143. Updated convergence risks before canonical merge

The remaining CURRENT_STATE convergence risks are now concentrated rather than broad:

1. **Two proxy product runtimes** — foreground `nexus proxy` and daemon TUN `ProxyEngine` have different routing semantics and protocol coverage.
2. **Per-link proxy transport not composed** — `nexus-proxy-transport` is substantial, but automatic Path/Fabric fallback is explicitly postposed and no normal daemon consumer is confirmed.
3. **N1 has multiple runtime shapes** — `network up` / `VpiPump` and daemon `Dataplane + N1MeshBridge` remain independently product-reachable.
4. **Workspace sync remains protocol-complete but normal lifecycle-unwired** — plus inbound authenticated PeerId enforcement remains incomplete.
5. **Scheduler is manually clocked** — persistence exists, but no autonomous executor binding exists.
6. **N3 implementation is ahead of CLI/help comments** — source comments and usage text materially understate current wiring.
7. **CLI/daemon ownership remains fragmented** — some fragmentation is deliberate local-authority design, some is migration residue.
8. **Platform closure is Linux-centric** — Windows has meaningful adapters but cannot currently inherit Linux Workspace/N3 closure claims.
9. **Verification still must be revision-bound** — scenario existence, implementation depth and historical agent evidence remain separate from a current verified verdict.

At this point the source audit is sufficiently mature that the next phase should prefer consolidation over indefinitely adding new maturity prose. Remaining sweeps should target only unresolved ownership edges or contradictions that can change the canonical architecture map.
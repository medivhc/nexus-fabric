# Nexus Fabric CURRENT_STATE — Canonical Code-First Baseline

> Reviewed source revision: `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573` (`master`).
>
> Purpose: describe what the repository **currently implements and wires**, not what the target architecture intends to become. This file supersedes contradictory current-state statements in the earlier `CURRENT_STATE.md` and `CURRENT_STATE_APPENDIX*.md` staging files.
>
> Evidence rule: executable code and current machine-readable configuration outrank comments and historical design prose. `Verified` is reserved for revision/config/platform-bound evidence; code presence, scenario presence, tests mentioned in commit prose, and module contracts do not by themselves establish `Verified`.

## 1. Status vocabulary and evidence discipline

The baseline uses six states consistently:

- **Contract** — a current explicit boundary/invariant exists in executable-adjacent policy or module contract.
- **Implemented** — executable mechanism exists in source.
- **Wired** — a product-reachable composition root actually constructs/calls the mechanism in the inspected path.
- **Scenario-targeted** — Harness/example/scenario explicitly exercises the mechanism, without implying current revision evidence.
- **Verified** — evidence is bound to the reviewed revision and relevant platform/configuration.
- **Production-closed** — ownership, lifecycle, security, recovery, observability, and real product composition are all closed for the stated path.

Negative statements derived from inspection use `not found in the inspected path` / `wiring unproven` unless the source explicitly says the work is postposed.

The generated Harness evidence root `/.evidence` is gitignored. [`.gitignore` L1-L3](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/.gitignore#L1-L3) The reviewed `master` commit message reports passing tests/gates, but commit-message prose is historical context, not a substitute for revision/config/platform-bound Harness Evidence. This baseline therefore does not upgrade the product to `Verified` from the commit subject alone.

## 2. Repository shape

The root Cargo workspace currently has **51 explicit members**, including `crates/nexus-workspace-intel`. This supersedes all older staging statements that counted 50 members or described workspace-intel as omitted. [`Cargo.toml` L1-L52](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/Cargo.toml#L1-L52)

The repository is not one runtime. Its executable structure contains portable/core crates, runtime/domain crates, platform adapters, multiple product composition roots (`apps/nexus`, `apps/nexusd`, `apps/nexus-platform-host`) and engineering/Harness infrastructure. The important audit question is therefore **composition reachability**, not whether a crate or API exists.

## 3. Stable Core and architectural invariants

`nexus-domain` is a zero-I/O portable core. Resource, Provider, Session, Node, ResourceRef and ResourceKind are separate types; `ResourceKind` covers Network, Service, Workspace, Compute and Device. [`crates/nexus-domain/src/lib.rs` L1-L162](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-domain/src/lib.rs#L1-L162)

The codebase consistently relies on these conceptual separations:

- Resource != Provider;
- Provider != Node;
- Identity != Locator;
- Plan != Session;
- Measurement != Score;
- Policy != Path;
- Planner != Estimator;
- Planner != Scheduler;
- TerminalOutcome != LifecyclePhase;
- Portable Core != Platform Runtime.

The intended executable order represented across current implementations is `Resolve candidates -> Plan placement/path -> Create Session -> Establish connectivity -> Execute`.

## 4. Core Planner

`nexus-planner` identifies itself as the system-level Core Planner. It is deterministic and zero-I/O, performing hard Filter -> connectivity feasibility gate -> Score, with structured rejection reasons and score breakdowns. `LOCALITY_BONUS` is 1000. [`crates/nexus-planner/src/lib.rs` L1-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-planner/src/lib.rs#L1-L112)

Connectivity evaluation is planning input rather than a dial. Explicitly evaluated candidates with no feasible path are rejected as `NoFeasibleConnectivityPath`; candidates without an evaluation remain unknown, not automatically unreachable. [`crates/nexus-planner/src/lib.rs` L167-L194](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-planner/src/lib.rs#L167-L194)

Status: **Implemented** as the deterministic system planner, but not every current product path is routed through one canonical system-level composition owner.

## 5. Session semantics

`nexus-session` separates lifecycle phase from terminal outcome. Workers report events; `SessionOwner` is the commit-once terminal-outcome owner. Cancellation is cooperative; `AbortOnDropHandle` requests cancellation when ownership disappears. [`crates/nexus-session/src/lib.rs` L1-L48](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-session/src/lib.rs#L1-L48) [`crates/nexus-session/src/lib.rs` L145-L255](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-session/src/lib.rs#L145-L255)

This distinction matters because the repository also has N1 peer connection sessions, N2 resource sessions, flow sessions and N3 task runtime state. Those are different ownership domains despite similar naming.

## 6. Product ownership is split between `nexus` and `nexusd`

The `nexus` header presents a thin-client direction, but the actual dispatcher has many in-process product roots. N3 Task/Artifact is sent to daemon LocalAPI, while subnet, schedule, proxy, system-proxy, autostart, config, pair, node, plan, use, session, resource, grant and provider have local/in-process routes; `run` also retains a local SDK path. [`apps/nexus/src/main.rs` L1-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L1-L112) [`apps/nexus/src/main.rs` L197-L329](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L197-L329)

`nexusd` simultaneously owns real long-lived state: a process-global N2 `SessionManager`, detached-session sweeper, LocalAPI, integrated dataplane and Linux Workspace lifecycle. Its opening “runtime later” wording is therefore stale/partial. [`apps/nexusd/src/main.rs` L1-L108](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L1-L108)

Current-state conclusion: neither “`nexus` is just a thin client” nor “`nexusd` owns all runtime” is accurate.

## 7. Daemon configuration, recovery, startup and control-plane lifecycle

The daemon owns a configuration directory with optional `daemon.toml`, `network.toml`, `proxy.yaml`, `dns.toml` and `workspace.toml`. Hot reload is classified: data-only changes can apply hot, TUN/listener/LocalAPI changes require restart, and invalid changes are rejected while old configuration remains active. [`apps/nexusd/src/config.rs` L1-L18](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/config.rs#L1-L18)

The main daemon path performs boot reconciliation before accepting new work, then assembles the sole daemon N2 SessionManager and detached-session sweeper, builds dataplane configuration, attempts N1 assembly with explicit degraded behavior on failure, starts the TUN/dataplane when enabled, then starts LocalAPI and later Workspace lifecycle. [`apps/nexusd/src/main.rs` L250-L650](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L250-L650)

The same source documents the intended shutdown ordering around LocalAPI, Workspace unmount, dataplane and N1. The important baseline is ownership: recovery/session reconciliation occurs before new work, and subsystem failure can be explicitly degraded instead of silently represented as healthy.

## 8. LocalAPI trust boundary

LocalAPI is a local control-plane trust model, not a remote TLS service. The server loads a bearer token, applies bounded I/O timeouts and routes N3 task HTTP through the specialized `task_http::dispatch` before the ordinary GET control router. Unix socket mode uses a safe per-user runtime path when available and hardens the socket to 0600; without a safe Unix socket directory the historical `serve` path falls back to loopback TCP rather than predictable `/tmp`. Windows named-pipe support is explicitly absent in this path and `--addr`/TCP is required. [`apps/nexusd/src/main.rs` L780-L1150](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L780-L1150)

This establishes a local bearer + local transport-permission model; it must not be described as mTLS control-plane security.

## 9. `nexusd::Dataplane` is the main daemon TUN owner

The daemon dataplane owns one TUN abstraction plus classifier/routing, DNS, CAKE-like QoS, N1 sender, daemon ProxyEngine, smoltcp TCP termination, statistics and optional flow-session state. [`apps/nexusd/src/dataplane.rs` L1-L184](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L1-L184)

It directly reuses lower-level `nexus-projection` primitives (`TunDevice`, classifier, CIDR routing and TCP terminator), so the daemon dataplane and projection crate are not wholly independent implementations. [`apps/nexusd/src/dataplane.rs` L20-L35](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L20-L35)

The normal daemon `run_dataplane` creates the real TUN, constructs `Dataplane`, publishes stats, injects N1 sender when available and injects `ProxyEngine` when `proxy.yaml` has a usable outbound. The inspected production function does **not** call `enable_flow_sessions()`. [`apps/nexusd/src/main.rs` L300-L420](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L300-L420)

## 10. Flow-session chain is implemented but not activated by normal daemon composition

`Dataplane` initializes `flow_mgr` and `flow_chain_deps` to `None`; `enable_flow_sessions()` can install a first-packet planning/session chain. [`apps/nexusd/src/dataplane.rs` L218-L278](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L218-L278)

That chain currently constructs an in-memory registry containing fixed providers `provider-edge-a` and `provider-relay-b` and applies the default network policy before creating the flow `SessionManager`. [`apps/nexusd/src/dataplane.rs` L255-L319](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L255-L319)

N1/proxy injection only updates upstream-availability flags for the default `NexusdEstablisher`; that establisher returns “mesh” or “proxy” based on availability and does not itself perform a transport-specific dial. [`apps/nexusd/src/dataplane.rs` L101-L132](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L101-L132) [`apps/nexusd/src/dataplane.rs` L321-L336](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L321-L336)

Status: flow-session mechanism **Implemented** and scenario/test hooks exist; normal `run_dataplane` activation is **Not Wired** at this revision.

## 11. N1 has multiple product-reachable runtime shapes

### 11.1 `VpiPump`

`nexus-network::n1::VpiPump` is a real VPI <-> per-peer connection packet runtime. Uplink performs IPv4 parsing and longest-prefix routing; downlink uses per-peer workers; supervisors restart failed workers; poisoned VPI locks are recovered; shutdown closes peer connections before supervisor collection. [`crates/nexus-network/src/n1/pump.rs` L1-L27](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-network/src/n1/pump.rs#L1-L27) [`crates/nexus-network/src/n1/pump.rs` L100-L254](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-network/src/n1/pump.rs#L100-L254)

Routes are explicit IPv4 subnet -> peer mappings with longest-prefix match. [`crates/nexus-network/src/n1/pump.rs` L38-L126](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-network/src/n1/pump.rs#L38-L126) The known shutdown limitation is explicit: portable blocking VPI receive cannot always be interrupted, so uplink shutdown uses bounded wait and may detach. [`crates/nexus-network/src/n1/pump.rs` L18-L27](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-network/src/n1/pump.rs#L18-L27)

### 11.2 `AutoMeshController` / VirtualSubnetTunnel

`apps/nexus::mesh::AutoMeshController` is another foreground owner around `VirtualSubnetTunnel`: it owns reconnect state, optional LAN discovery, optional WAN bootstrap, packet receive/delivery and punch driving. [`apps/nexus/src/mesh.rs` L1-L27](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/mesh.rs#L1-L27) [`apps/nexus/src/mesh.rs` L116-L230](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/mesh.rs#L116-L230)

### 11.3 daemon `Dataplane + N1Sender/N1MeshBridge`

The daemon path instead injects an `N1Sender` into `Dataplane` and forwards Mesh-classified traffic through daemon-owned packet orchestration. [`apps/nexusd/src/dataplane.rs` L133-L184](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L133-L184)

Current conclusion: there is no single N1 packet owner. Foreground VPI/AutoMesh shapes and daemon Dataplane shape must be evaluated separately.

## 12. Connectivity and ingress are mixed-maturity portable layers

`nexus-connectivity` is a delivery-layer shared base rather than a product composition owner. Its root explicitly exposes evaluation, VirtualSubnet/NAT, relay/TURN, encryption/identity, routing, firewall, QoS/CAKE, reconnect and many later modules. It also labels several batches as “pure logic skeleton”, while the source sweep found some of those modules have since grown realized implementations. The accurate crate-level description is therefore **mixed maturity**, not “implemented” or “skeleton” as one boolean. [`crates/nexus-connectivity/src/lib.rs` L1-L145](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-connectivity/src/lib.rs#L1-L145)

`nexus-ingress` is much cleaner: it creates neutral `FlowContext` for SOCKS5/HTTP/VPI/Native input, is zero-I/O, does not invoke Core Planner, and does not own platform interception. [`crates/nexus-ingress/src/lib.rs` L1-L55](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-ingress/src/lib.rs#L1-L55) Its SOCKS5 state machine supports CONNECT and explicitly rejects unsupported commands such as BIND/UDP ASSOCIATE; RFC1929 processing validates framing while credential authorization remains upper-layer policy. [`crates/nexus-ingress/src/lib.rs` L56-L220](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-ingress/src/lib.rs#L56-L220)

## 13. Fabric transport and identity boundary

Fabric exposes the connection/stream/datagram substrate and an injected `UdpTransport` seam. `nexus-proxy-transport` relies on this seam so QUIC can run above a proxy-carried framed transport without changing QUIC logic. [`crates/nexus-proxy-transport/src/lib.rs` L1-L18](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/src/lib.rs#L1-L18)

A critical security limit comes from Workspace sync: current Fabric P0 server side cannot trust client PeerId, so the repository must not globally be described as providing completed mutual peer identity for every server-side consumer. [`apps/nexusd/src/sync_transport.rs` L172-L211](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L172-L211)

## 14. NAT/path switching is implemented but normal daemon activation is incomplete

`NatSwitching` composes `PunchManager`, `PathLink` and `QualityMonitor`. Its own source explicitly says normal `nexusd main.rs` does not instantiate it because daemon TURN client/config/credential lifecycle is not yet present. [`apps/nexusd/src/nat_switch.rs` L1-L24](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/nat_switch.rs#L1-L24)

When instantiated, relay registration may start background punching. `Migrated` registers a direct connection as a candidate; punch success alone does not switch traffic — PathManager hysteresis decides promotion. [`apps/nexusd/src/nat_switch.rs` L133-L221](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/nat_switch.rs#L133-L221) Active traffic uses whichever connection `PathLink` marks active, direct or relay. [`apps/nexusd/src/nat_switch.rs` L223-L242](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/nat_switch.rs#L223-L242)

Status: punching/wire-up/quality/switching mechanisms **Implemented**; normal daemon TURN/STUN lifecycle and `NatSwitching` activation **Not Wired**.

## 15. Proxy has three distinct ownership planes

### 15.1 Foreground per-flow `nexus proxy`

The CLI routes `proxy` in process. [`apps/nexus/src/main.rs` L247-L253](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L247-L253) `proxy_serve_once` performs real SOCKS5/HTTP ingress, builds `ProxyService`, evaluates `route(&flow, None)`, finds the exact outbound whose tag matches `decision.selected_outbound_tag`, and then executes that selected outbound. [`apps/nexus/src/lib.rs` L4684-L4815](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/lib.rs#L4684-L4815)

Direct, Shadowsocks and Trojan have real foreground data paths; Relay and VMess explicitly return structured deferred failures. Foreground SOCKS5 outbound is also explicitly deferred in this app path even though daemon ProxyEngine supports SOCKS5. [`apps/nexus/src/lib.rs` L4816-L5206](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/lib.rs#L4816-L5206)

AnyTLS has a real TCP -> TLS -> AnyTLS handshake/stream/framing relay. [`apps/nexus/src/lib.rs` L5207-L5480](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/lib.rs#L5207-L5480) VLESS has real TCP/optional TLS handshake and relay, while XTLS-Vision splice/direct transition is explicitly still partial. [`apps/nexus/src/lib.rs` L5520-L5755](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/lib.rs#L5520-L5755) Hysteria2 performs QUIC connection, minimal H3 auth and TCP-proxy stream relay; UDP ingress composition, port hopping and Brutal CC remain unimplemented in this product arm. [`apps/nexus/src/lib.rs` L5756-L5865](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/lib.rs#L5756-L5865)

### 15.2 daemon TUN `ProxyEngine`

The daemon engine has different semantics. It parses `proxy.yaml`, scans `config.outbounds`, and takes the **first locally realizable** dial config. It supports Shadowsocks (`chacha20-ietf-poly1305` in this path), Trojan plaintext/TLS and SOCKS5; Direct, Relay, VMess, AnyTLS, VLESS and Hysteria2 return `None`. [`apps/nexusd/src/proxy_fwd.rs` L1-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/proxy_fwd.rs#L1-L112)

Therefore parsing Clash-style rules does not mean the daemon TUN hot path enforces the foreground `ProxyService` selected tag. This is a semantic integration gap. Trojan semantics also differ: this engine chooses TLS only if `skip_cert_verify` or ALPN is set; otherwise plaintext is the default. [`apps/nexusd/src/proxy_fwd.rs` L52-L85](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/proxy_fwd.rs#L52-L85)

### 15.3 per-link Fabric-over-proxy

`nexus-proxy-transport` creates SOCKS5/Shadowsocks/Trojan/Trojan-TLS proxy connections, frames datagrams and implements `nexus_fabric::UdpTransport`; this carries Fabric/QUIC through a proxy and is not per-flow Internet egress. [`crates/nexus-proxy-transport/src/lib.rs` L1-L48](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/src/lib.rs#L1-L48)

Its contract explicitly says Path selection/fallback is not owned there and automatic `PathManager` linkage is postposed. [`crates/nexus-proxy-transport/MODULE.md` L3-L17](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/MODULE.md#L3-L17)

Status: mechanism **Implemented**; automatic Path/Fabric proxy fallback **Not Wired / explicitly postposed**.

## 16. Proxy capability is runtime-specific

| Protocol | foreground `nexus proxy` | daemon TUN `ProxyEngine` |
|---|---|---|
| Direct | Wired | not a dial config in this engine |
| Relay | deferred | no |
| Shadowsocks | Wired | Wired, restricted method |
| Trojan | Wired TLS path | Wired plaintext/TLS heuristic |
| SOCKS5 outbound | deferred in foreground app path | Wired |
| VMess | real node tunnel deferred | no |
| AnyTLS | Wired | no |
| VLESS | Wired TCP/TLS; Vision transition partial | no |
| Hysteria2 | Wired TCP-proxy use case; UDP/port-hop/Brutal incomplete | no |

The table is implementation/wiring status, not `Verified` evidence.

## 17. Linux Workspace local lifecycle is wired

`apps/nexusd::workspace` owns Linux Workspace configuration, on-disk CAS, per-workspace `state_root` anchors, FUSE projection, optional auto-commit and explicit shutdown. Absence of `/dev/fuse` disables the subsystem explicitly instead of silently changing semantics. [`apps/nexusd/src/workspace.rs` L1-L13](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/workspace.rs#L1-L13)

Commit is serialized by `commit_mu`; source documents a crash window between durable `fs.commit()` CAS state and later `state_root` anchor rewrite. A crash there can restart from the old anchor while the new commit remains in CAS but unreachable. HTTP acknowledgement occurs only after the anchor update. [`apps/nexusd/src/workspace.rs` L126-L166](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/workspace.rs#L126-L166)

Status: local Workspace CAS/FUSE lifecycle **Wired on Linux**, with an explicit remaining durability window.

## 18. Workspace Fabric sync is separate and not normal WorkspaceManager lifecycle

`sync_transport.rs` implements real `WorkspaceTransport` over Fabric bi-streams, but explicitly leaves active-connection acquisition to the caller (`NatSwitching::active_conn(peer)`) and passive stream routing to the caller through unclaimed/accepted stream dispatch of type `0x03`. [`apps/nexusd/src/sync_transport.rs` L1-L24](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L1-L24)

The adapter reuses an existing Fabric connection, uses a 64 KiB frame bound and a 30 s receive deadline. [`apps/nexusd/src/sync_transport.rs` L27-L42](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L27-L42) [`apps/nexusd/src/sync_transport.rs` L75-L170](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L75-L170)

`WorkspaceManager` itself documents local mount/CAS/commit ownership rather than sync-server/client lifecycle. [`apps/nexusd/src/workspace.rs` L1-L13](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/workspace.rs#L1-L13) Safe status: sync protocol/adapter **Implemented**; normal automatic Workspace sync lifecycle **wiring unproven**.

## 19. Workspace sync authorization is not security-closed

`SyncAuthorizer` and `serve_sync_authorized` are real; a non-member is rejected before Workspace commit/object serving. [`apps/nexusd/src/sync_transport.rs` L213-L255](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L213-L255)

But the same file explicitly states current Fabric P0 server side cannot trust client PeerId; strong enforcement awaits client authentication. [`apps/nexusd/src/sync_transport.rs` L172-L211](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L172-L211)

Therefore Workspace sync security is **not Production-closed**.

## 20. Legacy Workspace content identity differs from N3 strong content identity

Legacy `nexus-storage::ObjectId` uses FNV-1a 64-bit and formats it as 16 hex characters. [`crates/nexus-storage/src/lib.rs` L1-L46](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-storage/src/lib.rs#L1-L46)

N3 deliberately defines a separate `StrongContentStore` namespace using SHA-256 digest plus expected content length, and verifies both on read/publication. [`crates/nexus-storage/src/strong.rs` L1-L28](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-storage/src/strong.rs#L1-L28)

These are different integrity contracts. The repository must not be described as having one universal collision/integrity property across Workspace CAS and N3 Task/Artifact content.

## 21. N2 identity is durable but cold initialization coordination is process-local

N2 authorization identity is ed25519. `Principal` is derived from the ed25519 public key rather than accepting requester self-claims; the durable record is stored under `n2/auth-identity`. [`apps/nexus/src/n2_identity.rs` L1-L16](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_identity.rs#L1-L16)

`ensure_auth_identity` is idempotent, generates a random 32-byte seed, reconstructs/validates public key consistency and tightens the stored private record to 0600 on Unix. Its initialization mutex protects only the current process; source explicitly says cross-process cold initialization of a shared node directory still requires node-owner coordination. [`apps/nexus/src/n2_identity.rs` L68-L132](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_identity.rs#L68-L132)

## 22. N2 cross-machine admission provides mutual identity, not a confidential channel

`n2_admission` implements a separate length-prefixed JSON/TCP admission protocol. The requester signs a provider challenge; the provider derives the principal from the verified requester public key, evaluates local grants and audits the decision. Protocol v2 additionally has the provider sign the requester challenge, and the requester validates the provider through `TrustStore` with explicit TOFU behavior rather than silent trust. [`apps/nexus/src/n2_admission.rs` L1-L31](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_admission.rs#L1-L31)

The security boundary is explicit: this protocol supplies identity authentication but **no confidentiality and no forward secrecy**; authenticated QUIC reuse is an evolution direction. The current P0 threat model is single Workspace/single administrator. [`apps/nexus/src/n2_admission.rs` L14-L31](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_admission.rs#L14-L31)

Admission is bounded: the source fixes provider lease TTL to one hour, caps concurrent admissions at 64 and documents per-connection read timeout/fail-closed behavior. [`apps/nexus/src/n2_admission.rs` L50-L82](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_admission.rs#L50-L82)

## 23. N2 durable store and recovery

`N2Store` is a `FileKvStore`-backed authority for Session records including full `PlanSnapshot`, grants, auth audit, provider advertisements, name table, directory audit and a durable control-frame outbox. The documented boot model is KV truth + journal replay + idempotent session reconciliation before accepting new work. [`apps/nexus/src/n2_store.rs` L1-L27](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_store.rs#L1-L27)

One durability fidelity limit is explicit: persisted `TerminalOutcome::Failed(NexusError)` stores a reason/debug string and reload reconstructs `NexusError::Internal`; the exact typed failure variant is not round-tripped. [`apps/nexus/src/n2_store.rs` L102-L141](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_store.rs#L102-L141)

The daemon owns one process-global N2 SessionManager plus a detached-session sweeper, but several N2 CLI command families remain local/in-process. [`apps/nexusd/src/main.rs` L35-L108](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L35-L108) [`apps/nexus/src/main.rs` L271-L322](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L271-L322)

Thus N2 mechanism maturity is high, but authority/composition ownership is still split.

## 24. N3 Task LocalAPI is real, but public Submit is not execution-closed

The CLI help still says Task submission and Artifact download are not fully wired. [`apps/nexus/src/main.rs` L61-L77](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L61-L77) Executable `task_cli` nevertheless strictly parses and validates Task/Artifact requests and sends them through daemon LocalAPI. [`apps/nexus/src/task_cli.rs` L1-L170](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/task_cli.rs#L1-L170)

The provider service is Linux-gated and, in production composition, receives the existing resource Session manager rather than creating an unrelated second owner. `task-api.toml` is strict and scopes exactly provider/workspace. [`apps/nexusd/src/task_service.rs` L1-L95](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/task_service.rs#L1-L95) [`apps/nexusd/src/task_service.rs` L100-L170](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/task_service.rs#L100-L170)

However normal `TaskRequest::Submit` currently authenticates/authorizes scope and then explicitly refuses because real capacity, Session and authenticated input transport prerequisites are not assembled. Query, cancel, logs and Artifact paths are implemented for existing accepted Tasks. [`apps/nexusd/src/task_service_provider.rs` L170-L250](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/task_service_provider.rs#L170-L250)

Therefore the accurate status is:

- Task/Artifact LocalAPI and CLI transport: **Wired**;
- provider authority/query/cancel/log/artifact service: **Implemented/Wired for existing authority**;
- normal public Submit -> accepted capacity/session/input -> execution: **Not Production-closed; currently explicitly refused at missing prerequisites**.

The stale help text is still drift because it understates Artifact and existing-task operations, but it accidentally points at a real remaining Submit closure gap.

## 25. N3 provider persistence is strongly fail-closed

`FileTaskAcceptanceStore` is Linux-only durable provider authority. It requires a private real 0700 root, uses a stable acceptance lock inode, publishes/validates initialization receipts and authority images, and refuses to reinterpret missing authority beside existing runtime/artifact/capacity state as a fresh provider. [`apps/nexusd/src/task_store.rs` L1-L145](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/task_store.rs#L1-L145) [`apps/nexusd/src/task_store.rs` L145-L280](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/task_store.rs#L145-L280)

`ProviderService::open` opens existing authority, validates private directory ancestors, verifies input snapshots, reconciles executor state, reconciles Task<->resource Session bridge when present and finishes capacity-owner recovery before serving. [`apps/nexusd/src/task_service_provider.rs` L1-L124](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/task_service_provider.rs#L1-L124)

## 26. N3 execution records intent before irreversible start and does not silently re-execute ambiguity

`LinuxTaskExecutor::run` rejects a fresh execution if an execution handle, terminal outcome, incompatible phase, cancellation or other existing execution authority exists; prior execution/log authority requires reconciliation rather than replacement execution. [`apps/nexusd/src/task_executor.rs` L118-L220](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/task_executor.rs#L118-L220)

The execution adapter verifies materialized input digest/length/mode, rechecks authorization/capacity, then durably records `RuntimeAction::StartIntent` **before** `start_exec`. It writes engine identity before starting; from that point failures are treated as ambiguous and retry/new execution ID is prohibited. [`apps/nexusd/src/task_executor_run.rs` L1-L125](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/task_executor_run.rs#L1-L125)

During observation it records start proof only after real PID observation, stages explicit outputs after actual exit, stops/reaps the container subtree, waits for log EOF/sealing, then records `Exited` or `Stopped`; an attempt that ends without confirmed process start is treated as corruption requiring reconciliation. [`apps/nexusd/src/task_executor_run.rs` L126-L290](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/task_executor_run.rs#L126-L290)

This is a strong crash/recovery model even though public Submit composition is not yet closed.

## 27. N3 requester Artifact receiver is separately strong

Linux `artifact get` probes remote authorization before output I/O, resumes from an exact durable offset, rejects record/page changes, requires final remote re-authorization at EOF and only then completes the receiver. [`apps/nexus/src/task_cli.rs` L172-L239](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/task_cli.rs#L172-L239)

Combined with the separate SHA-256 strong-content namespace, this is materially stronger integrity semantics than legacy Workspace FNV object IDs. [`crates/nexus-storage/src/strong.rs` L1-L28](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-storage/src/strong.rs#L1-L28)

## 28. Scheduler is a durable manual registry, not an autonomous job executor

The Scheduler CLI persists under `$NEXUS_HOME/schedule.json` or `~/.nexus/schedule.json`, fails loudly on corrupt state and commits replacements through temp file + rename. [`apps/nexus/src/schedule_cli.rs` L1-L105](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/schedule_cli.rs#L1-L105)

Its default submit callback returns only a synthetic `task-<resource>` string and performs no Task execution. [`apps/nexus/src/schedule_cli.rs` L106-L118](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/schedule_cli.rs#L106-L118) `schedule` is an in-process CLI family rather than a daemon-owned periodic loop in the inspected dispatcher. [`apps/nexus/src/main.rs` L239-L246](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L239-L246)

Status: model **Implemented**; local persistence/manual tick **Wired**; autonomous clock and real N3 task submission **Not Wired**.

## 29. Service/Delivery/Diagnostics/Proto maturity differs sharply

`nexus-service` has real executable semantics: injected `ServiceTransport`, `CONNECT` -> `READY`, then `ServicePhase::Active`; its source explicitly says `connect != forward` and forwarding is postposed. [`crates/nexus-service/src/lib.rs` L1-L10](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-service/src/lib.rs#L1-L10) [`crates/nexus-service/src/lib.rs` L60-L105](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-service/src/lib.rs#L60-L105)

By contrast, `nexus-delivery`, `nexus-diagnostics` and `nexus-proto` root bodies are currently documentation plus `forbid(unsafe_code)` only; their architectural names are ahead of executable crate bodies. [`crates/nexus-delivery/src/lib.rs` L1-L7](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-delivery/src/lib.rs#L1-L7) [`crates/nexus-diagnostics/src/lib.rs` L1-L7](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-diagnostics/src/lib.rs#L1-L7) [`crates/nexus-proto/src/lib.rs` L1-L7](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proto/src/lib.rs#L1-L7)

This is why crate existence cannot be used as architecture-completion evidence.

## 30. Workspace Intelligence is now a first-class workspace member

`crates/nexus-workspace-intel` is explicitly in root workspace membership at the reviewed revision. [`Cargo.toml` L1-L52](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/Cargo.toml#L1-L52) Older staging text describing it as omitted is obsolete.

## 31. Platform reality

Linux exports concrete addr/route, OS assembly, daemon, DNS, file lease, FUSE Workspace, netlink, operation log, secure store, TUN and VPI modules. [`crates/nexus-platform-linux/src/lib.rs` L1-L39](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-platform-linux/src/lib.rs#L1-L39)

Windows exports concrete Task Scheduler autostart, DPAPI, netcfg, secure store, VPI, WinINET proxy and Wintun modules. [`crates/nexus-platform-windows/src/lib.rs` L1-L23](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-platform-windows/src/lib.rs#L1-L23)

macOS, Android and iOS root source bodies currently contain only documentation plus `forbid(unsafe_code)`, despite documentation naming future/native capabilities. [`crates/nexus-platform-macos/src/lib.rs` L1-L7](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-platform-macos/src/lib.rs#L1-L7) [`crates/nexus-platform-android/src/lib.rs` L1-L7](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-platform-android/src/lib.rs#L1-L7) [`crates/nexus-platform-ios/src/lib.rs` L1-L7](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-platform-ios/src/lib.rs#L1-L7)

Accurate summary: Linux is the most complete daemon/server + Workspace/N3 execution platform; Windows has substantial networking/desktop integration; macOS/Android/iOS remain near-placeholder at executable-source level.

## 32. Engineering Harness

Scenario gate execution is now bounded-parallel by default. `NEXUS_HARNESS_JOBS` overrides worker count; `1` preserves serial operation; otherwise CPU parallelism is used with cap 16, and reports are reassembled in declaration order. [`engineering/nexus-harness/src/scenario.rs` L606-L704](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/engineering/nexus-harness/src/scenario.rs#L606-L704)

This changes engineering execution time, not product maturity. Scenario existence or a commit subject reporting PASS does not satisfy the baseline definition of `Verified`.

## 33. High-confidence drift register

Known source/comment/help drift includes:

1. `apps/nexus/src/main.rs` “thin client” wording vs many in-process composition roots. [`apps/nexus/src/main.rs` L1-L17](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L1-L17) [`apps/nexus/src/main.rs` L197-L329](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L197-L329)
2. `apps/nexusd/src/main.rs` opening “runtime later” prose vs current N2/dataplane/Workspace ownership. [`apps/nexusd/src/main.rs` L1-L108](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L1-L108)
3. CLI help says N3 submit/download are not fully wired; executable reality is mixed: Artifact/existing-task operations are real, while public Submit still hits an explicit missing-prerequisites refusal. [`apps/nexus/src/main.rs` L61-L77](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L61-L77) [`apps/nexusd/src/task_service_provider.rs` L170-L250](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/task_service_provider.rs#L170-L250)
4. `nexus-proxy-transport` contains a stale comment claiming shared config lacks SOCKS5; current config vocabulary has already evolved beyond that comment. [`crates/nexus-proxy-transport/src/lib.rs` L39-L48](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/src/lib.rs#L39-L48)
5. `nexus-connectivity` root still labels several batches “pure logic skeleton” even though later file bodies in parts of those batches have evolved; executable bodies outrank the batch comments. [`crates/nexus-connectivity/src/lib.rs` L80-L145](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-connectivity/src/lib.rs#L80-L145)

## 34. Current runtime ownership matrix

| Concern | Current owner(s) | Status |
|---|---|---|
| Stable Resource/Plan vocabulary | `nexus-domain` | Implemented |
| System planning | `nexus-planner` | Implemented; not universally consumed |
| Session semantics | `nexus-session` | Implemented |
| Config/recovery/LocalAPI | `nexusd` | Wired |
| Daemon TUN pipeline | `nexusd::Dataplane` + projection primitives | Wired |
| Flow-session gate | optional `Dataplane` chain | Implemented; normal daemon activation Not Wired |
| Foreground N1 packet paths | `VpiPump`, AutoMesh/VirtualSubnet | Wired in their own roots |
| Daemon N1 | Dataplane + N1Sender/N1MeshBridge | Wired |
| NAT direct/relay switching | `NatSwitching` | Implemented; normal daemon activation Not Wired |
| Foreground Internet proxy | `nexus proxy` + ProxyService | Wired |
| Daemon TUN proxy | `nexusd::ProxyEngine` | Wired, narrower/different semantics |
| Fabric-over-proxy | `nexus-proxy-transport` | Implemented; Path fallback Not Wired |
| Linux Workspace mount/commit | `WorkspaceManager` | Wired |
| Workspace Fabric sync | caller + `sync_transport` | Implemented; automatic lifecycle unproven |
| N2 identity/admission/store | `apps/nexus` + daemon Session owner | Implemented/Wired, ownership split |
| N3 LocalAPI/existing-task ops | CLI + `LocalTaskService` | Wired on Linux-supported path |
| N3 public Submit | provider service | explicitly not execution-closed |
| N3 durable runtime/executor | Task store + Linux executor | substantial Implemented/recovery semantics |
| Scheduler | CLI local registry/manual tick | Wired as registry, not autonomous execution |
| Linux platform | Linux adapter | substantial |
| Windows platform | Windows adapter | substantial, different scope |
| macOS/Android/iOS | OS adapter roots | skeleton/near-placeholder |

## 35. Highest-confidence production gaps

1. **Runtime ownership fragmentation** — CLI-local and daemon-owned roots coexist for N1, N2, proxy and system integration.
2. **Daemon TUN proxy semantic mismatch** — it does not consume foreground ProxyService per-flow selected tags and has narrower protocol coverage.
3. **Fabric-over-proxy is not an automatic Path fallback** — mechanism exists; linkage is explicitly postposed.
4. **NAT switching is not normal-daemon activated** — TURN client/config/credential and STUN/srflx lifecycle remain open.
5. **Workspace sync is not owned by normal WorkspaceManager lifecycle** — callers must acquire active Fabric connection and route passive streams.
6. **Workspace sync client identity is not production-authenticated at Fabric server side**.
7. **Flow-session mechanism is not enabled by normal daemon `run_dataplane` and its current provider snapshot is synthetic**.
8. **N3 public Submit is not closed** despite strong durable provider/runtime machinery and real existing-task/Artifact operations.
9. **Scheduler has no autonomous clock or real task-submission binding**.
10. **Platform closure is Linux-centric for Workspace/N3; macOS/mobile roots are mostly empty**.
11. **Several comments/help strings materially lag executable implementation**.

## 36. Explicit non-claims

This baseline does **not** claim:

- every implemented crate is product wired;
- every scenario currently passes;
- the current commit message’s PASS statement is bound Harness Evidence;
- Fabric provides trustworthy mutual peer identity for every server-side consumer;
- successful NAT punching forces path promotion;
- foreground and daemon proxy runtimes have identical rules/protocol semantics;
- N3 public Submit currently launches a Task from the ordinary LocalAPI path;
- Scheduler executes commands because `schedule tick` advances state;
- Workspace local durability closes the documented commit/anchor crash window;
- all Nexus content stores have SHA-256 collision/integrity semantics;
- macOS/Android/iOS implement the capabilities named by their crate documentation;
- absence found by source search proves global nonexistence.

## 37. Baseline conclusion

At revision `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573`, Nexus Fabric contains substantial executable machinery: stable Core and Planner/Session semantics, daemon TUN forwarding, multiple N1 runtimes, proxy engines/protocols, Linux Workspace projection, N2 identity/admission/durable store, N3 durable task/executor/artifact machinery, Fabric/NAT/path components and substantive Linux/Windows adapters.

The dominant current-state problem is not simply missing mechanism code. Mature mechanisms often stop one composition layer before system ownership closes: multiple roots coexist, richer adapters are not always consumed by the dominant daemon path, security identity properties differ by layer, and wiring/verification trails implementation depth.

This is the correct boundary for the later TARGET_STATE exercise: target design should choose canonical ownership and deletion/migration paths without rewriting these current facts.

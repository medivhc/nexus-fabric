# Nexus Fabric CURRENT_STATE — Canonical Code-First Baseline

> Reviewed source revision: `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573` (`master`).
>
> Purpose: describe what the repository **currently implements and wires**, not what the target architecture intends to become. This file supersedes contradictory current-state statements in the earlier `CURRENT_STATE.md` and `CURRENT_STATE_APPENDIX*.md` staging files.
>
> Evidence rule: executable code and current machine-readable configuration outrank comments and historical design prose. `Verified` is reserved for revision/config/platform-bound evidence; code presence, scenario presence, tests mentioned in commit prose, and module contracts do not by themselves establish `Verified`.

## 1. Status vocabulary and evidence discipline

The baseline uses the following meanings consistently:

- **Contract** — a current explicit boundary/invariant exists in executable-adjacent policy or module contract.
- **Implemented** — executable mechanism exists in source.
- **Wired** — a product-reachable composition root actually constructs/calls the mechanism in the inspected path.
- **Scenario-targeted** — Harness/example/scenario explicitly exercises the mechanism, without implying current revision evidence.
- **Verified** — evidence is bound to the reviewed revision and relevant platform/configuration.
- **Production-closed** — ownership, lifecycle, security, recovery, observability, and real product composition are all closed for the stated path.

Negative statements derived from source inspection use `not found in the inspected path` / `wiring unproven` unless source explicitly says the work is postposed. Source line anchors are immutable commit-pinned links.

The root generated evidence path `/.evidence` is gitignored, so generated Harness output is not treated as normal checked-in source authority. [`.gitignore` L1-L3](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/.gitignore#L1-L3)

## 2. Repository shape

The root Cargo workspace currently contains **51 explicit members**, including `crates/nexus-workspace-intel`. This supersedes the earlier 50-member / workspace-intel-omitted staging conclusion. [`Cargo.toml` L1-L52](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/Cargo.toml#L1-L52)

The repository is not a single runtime. It contains:

1. portable/core crates (`nexus-domain`, planner, session, measurement, policy, registry, scheduler, etc.);
2. runtime/domain crates (`nexus-network`, `nexus-service`, workspace, compute, connectivity, proxy, projection, Fabric/NAT/path);
3. OS adapters (Linux, Windows, macOS, Android, iOS);
4. product composition roots (`apps/nexus`, `apps/nexusd`, `apps/nexus-platform-host`);
5. engineering/Harness infrastructure.

The most important current-state property is therefore **composition reachability**, not crate existence.

## 3. Stable Core invariants

`nexus-domain` is a zero-I/O portable core and explicitly keeps identities/concepts separate: Resource, Provider, Session, Node, ResourceRef and ResourceKind are distinct types. `ResourceKind` currently covers Network, Service, Workspace, Compute and Device. [`crates/nexus-domain/src/lib.rs` L1-L162](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-domain/src/lib.rs#L1-L162)

The repository-wide conceptual invariants established by executable types and consumers are:

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

The operational sequence represented across the codebase is:

`Resolve candidates -> Plan placement/path -> Create Session -> Establish connectivity -> Execute`.

## 4. Core Planner

`nexus-planner` identifies itself as the single system-level Core Planner, remains zero-I/O and deterministic, and performs hard Filter -> connectivity feasibility gate -> Score. It records structured rejection reasons and score components in `DecisionTrace`; `LOCALITY_BONUS` is 1000. [`crates/nexus-planner/src/lib.rs` L1-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-planner/src/lib.rs#L1-L112)

Connectivity evaluation is a planning input rather than a dial operation. For candidates that have an explicit evaluation, no feasible path produces `NoFeasibleConnectivityPath`; an unassessed candidate remains unknown rather than being treated as unreachable. [`crates/nexus-planner/src/lib.rs` L167-L194](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-planner/src/lib.rs#L167-L194)

Current maturity: **Implemented** as a deterministic planning core; product paths do not all route through one single composition owner yet.

## 5. Session semantics

`nexus-session` separates lifecycle phase from terminal outcome. Workers emit events; `SessionOwner` is the commit-once terminal-outcome owner. Cancellation is cooperative through `CancelToken`; `AbortOnDropHandle` requests cancellation on owner loss. [`crates/nexus-session/src/lib.rs` L1-L48](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-session/src/lib.rs#L1-L48) [`crates/nexus-session/src/lib.rs` L145-L255](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-session/src/lib.rs#L145-L255)

This is an important semantic baseline because the repository contains multiple higher-level `SessionManager` concepts; N1 peer connection sessions, N2 resource sessions, flow sessions and N3 task runtime state are not interchangeable merely because they all contain the word “session”.

## 6. Product ownership is split between `nexus` and `nexusd`

The `nexus` header still presents a thin-client direction, but the actual dispatcher owns numerous in-process product roots. N3 Task/Artifact goes to daemon LocalAPI, while subnet, schedule, proxy, system-proxy, autostart, config, pair, node, plan, use, session, resource, grant and provider have local/in-process paths; `run` also retains a local SDK path. [`apps/nexus/src/main.rs` L1-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L1-L112) [`apps/nexus/src/main.rs` L197-L329](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L197-L329)

`nexusd` simultaneously owns concrete long-lived runtime state even though its opening comment still says several runtimes are future work. It owns process-global N2 `SessionManager` state, an N2 detached-session sweeper, LocalAPI, integrated dataplane state and Linux Workspace runtime elsewhere in the file. [`apps/nexusd/src/main.rs` L1-L108](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L1-L108)

Therefore neither “`nexus` is just a thin client” nor “`nexusd` owns all runtime” is an accurate whole-product statement.

## 7. LocalAPI trust boundary

The inspected LocalAPI is a local control-plane trust model rather than a network service with TLS. Unix socket mode hardens the socket to 0600 and fails closed if permission hardening fails. Windows named-pipe mode is not implemented in this path; the explicit fallback is TCP `--addr`. [`apps/nexusd/src/main.rs` L950-L1035](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L950-L1035)

Bearer authorization is performed before the ordinary GET control routes are served; task HTTP has its own stricter versioned path/authority integration. The trust model is therefore local bearer + local transport permissions, not remote mutual TLS.

## 8. `nexusd::Dataplane` is the main daemon TUN owner

The daemon dataplane owns one TUN abstraction plus classifier/routing, DNS, CAKE-like QoS, N1 sender, daemon ProxyEngine, smoltcp TCP termination, statistics and optional flow-session state. [`apps/nexusd/src/dataplane.rs` L1-L184](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L1-L184)

It is not independent of `nexus-projection`: it imports and reuses `TunDevice`, packet classification, CIDR routing and TCP termination primitives from that crate. [`apps/nexusd/src/dataplane.rs` L20-L35](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L20-L35)

Current high-level packet ownership is approximately:

`TUN -> DNS short-circuit -> classify Mesh/Proxy/Direct -> QoS/TCP termination as applicable -> N1 / daemon ProxyEngine / direct handling -> TUN responses`.

The important duplication is therefore top-level orchestration/ownership, not complete duplication of lower-level projection primitives.

## 9. Flow-session chain exists but is opt-in in `Dataplane`

`Dataplane` initializes `flow_mgr` and `flow_chain_deps` to `None`. `enable_flow_sessions()` exists and can install an establisher plus a first-packet planning chain. [`apps/nexusd/src/dataplane.rs` L218-L278](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L218-L278)

The current chain is not yet a transparent reflection of the real production registry: it constructs an in-memory registry with two fixed providers (`provider-edge-a`, `provider-relay-b`) and applies default network policy before creating the flow `SessionManager`. [`apps/nexusd/src/dataplane.rs` L255-L319](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L255-L319)

N1/proxy injection updates upstream availability flags; the default `NexusdEstablisher` accepts “mesh” or “proxy” based on those flags rather than itself performing a transport-specific dial. [`apps/nexusd/src/dataplane.rs` L101-L132](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L101-L132) [`apps/nexusd/src/dataplane.rs` L321-L336](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L321-L336)

Current status: flow-session mechanism **Implemented** and scenario/test hooks exist; default activation in the normal inspected daemon composition remains **not established**.

## 10. N1 has more than one product-reachable runtime shape

### 10.1 `VpiPump`

`nexus-network::n1::VpiPump` is a real packet runtime: VPI uplink performs IPv4 parsing and longest-prefix routing to a peer connection, downlink has per-peer workers, supervisors restart failed workers, poison recovery prevents cascade failure, and shutdown closes peer connections before joining supervisors. [`crates/nexus-network/src/n1/pump.rs` L1-L27](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-network/src/n1/pump.rs#L1-L27) [`crates/nexus-network/src/n1/pump.rs` L100-L254](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-network/src/n1/pump.rs#L100-L254)

The routing table is explicit IPv4 subnet -> peer identity with longest-prefix match; no route/connection leads to drop/count rather than hidden fallback. [`crates/nexus-network/src/n1/pump.rs` L38-L126](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-network/src/n1/pump.rs#L38-L126)

Known lifecycle limitation is explicit: a portable VPI blocking `receive()` cannot always be interrupted; uplink supervisor uses bounded wait then detach on shutdown. [`crates/nexus-network/src/n1/pump.rs` L18-L27](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-network/src/n1/pump.rs#L18-L27)

### 10.2 `AutoMeshController` / VirtualSubnetTunnel

`apps/nexus::mesh::AutoMeshController` is another concrete foreground owner around `VirtualSubnetTunnel`: reconnect state, optional LAN discovery, optional WAN bootstrap, receive/deliver loop and automatic punch driving live here. [`apps/nexus/src/mesh.rs` L1-L27](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/mesh.rs#L1-L27) [`apps/nexus/src/mesh.rs` L116-L230](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/mesh.rs#L116-L230)

### 10.3 daemon `Dataplane + N1MeshBridge`

The daemon path instead injects an `N1Sender` into `Dataplane`, so Mesh-classified packets are forwarded through daemon-owned pipeline state rather than through the `VpiPump` orchestration. [`apps/nexusd/src/dataplane.rs` L20-L35](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L20-L35) [`apps/nexusd/src/dataplane.rs` L133-L184](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L133-L184)

Canonical implication: there is no single N1 packet owner yet. The runtime shapes share lower-level N1/Fabric concepts but must be evaluated independently.

## 11. Discovery maturity is mixed

The repository contains Static, aggregate-priority, Presence TTL, LSA and mDNS mechanisms, but source presence is not the same as live product population. The foreground/AutoMesh paths can own explicit static locators and optional discovery drivers; mDNS-style logic that requires socket membership/receive pumping must be composed by the owner before it becomes live discovery.

Current status should be read per source: **mechanisms implemented; live source ownership varies by composition root**.

## 12. Fabric transport

`nexus-fabric` provides the underlying QUIC/Fabric connection abstraction and the `UdpTransport` seam used by native UDP and proxy-carried transport adapters. The system intentionally allows transport injection below QUIC so the QUIC protocol logic does not need to know whether its datagrams travel over a native socket or a framed proxy stream. This seam is directly referenced by `nexus-proxy-transport`. [`crates/nexus-proxy-transport/src/lib.rs` L1-L18](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/src/lib.rs#L1-L18)

A security caveat is important: Workspace sync source explicitly states current Fabric P0 server side cannot trust client PeerId, so the baseline must not globally describe Fabric as providing completed bidirectional peer authentication for every server-side consumer. [`apps/nexusd/src/sync_transport.rs` L172-L211](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L172-L211)

## 13. Path/NAT mechanisms are deep but normal daemon activation is incomplete

`apps/nexusd::NatSwitching` is a real composition object combining `PunchManager`, `PathLink` and `QualityMonitor`. Its file is unusually explicit about the production boundary: normal `nexusd main.rs` does **not** instantiate this stack yet because the daemon does not have a TURN client plus TURN config/credential lifecycle. [`apps/nexusd/src/nat_switch.rs` L1-L24](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/nat_switch.rs#L1-L24)

When used, relay registration can start bounded background punching. `Migrated` registers a direct connection as a candidate; punch success alone does not force switching — PathManager hysteresis decides whether the direct path replaces relay. [`apps/nexusd/src/nat_switch.rs` L133-L221](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/nat_switch.rs#L133-L221)

Production traffic lookup returns the connection that `PathLink` currently marks active, either direct or relay. [`apps/nexusd/src/nat_switch.rs` L223-L242](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/nat_switch.rs#L223-L242)

Current status:

- punching algorithms/wire-up: **Implemented**;
- relay/direct quality-based switching object: **Implemented**;
- normal daemon TURN/STUN lifecycle: **Not Wired**;
- normal daemon `NatSwitching` activation: **explicitly not instantiated**.

## 14. Proxy has three distinct ownership planes

### 14.1 Foreground per-flow `nexus proxy`

The CLI routes `proxy` as an in-process product runtime. [`apps/nexus/src/main.rs` L247-L253](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L247-L253)

`proxy_serve_once` performs real SOCKS5/HTTP ingress, builds `ProxyService`, evaluates `route(&flow, None)`, finds the exact outbound whose tag equals `decision.selected_outbound_tag`, then executes the selected outbound. [`apps/nexus/src/lib.rs` L4684-L4815](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/lib.rs#L4684-L4815)

The foreground path has real Direct and Shadowsocks data paths in the same function and deeper protocol arms later in the file. Trojan uses rustls/TLS and a real bidirectional relay; Relay and VMess explicitly return structured “deferred” failures in the inspected code. [`apps/nexus/src/lib.rs` L4816-L5140](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/lib.rs#L4816-L5140)

Earlier source audit also established substantive AnyTLS, VLESS and Hysteria2 foreground arms; support is therefore runtime-specific and not expressible as one repository-wide boolean.

### 14.2 daemon TUN `ProxyEngine`

`nexusd::proxy_fwd::ProxyEngine` has different semantics. It parses `proxy.yaml`, scans `config.outbounds`, and uses the **first locally realizable** dial config. It supports Shadowsocks (`chacha20-ietf-poly1305` in this path), Trojan plaintext/TLS and SOCKS5. Direct, Relay, VMess, AnyTLS, VLESS and Hysteria2 return `None`. [`apps/nexusd/src/proxy_fwd.rs` L1-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/proxy_fwd.rs#L1-L112)

Therefore Clash-style rules may be parseable while this daemon forwarding path does not enforce the foreground `ProxyService` selected tag. This is a semantic integration gap, not merely missing protocol adapters.

Trojan transport selection also differs: daemon code chooses TLS only when `skip_cert_verify` is true or ALPN is present, otherwise plaintext is the default in this engine. [`apps/nexusd/src/proxy_fwd.rs` L52-L85](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/proxy_fwd.rs#L52-L85)

### 14.3 per-link Fabric-over-proxy

`nexus-proxy-transport` is neither of the above. It creates SOCKS5/Shadowsocks/Trojan/Trojan-TLS proxy connections, frames datagrams with a 2-byte length prefix and exposes `nexus_fabric::UdpTransport`, allowing Fabric QUIC to run above the proxy connection unchanged. [`crates/nexus-proxy-transport/src/lib.rs` L1-L48](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/src/lib.rs#L1-L48)

Its contract explicitly says Path selection/fallback is not owned by this crate and automatic `PathManager` linkage is postposed. [`crates/nexus-proxy-transport/MODULE.md` L3-L17](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/MODULE.md#L3-L17)

Current status: per-link proxy transport **Implemented**; automatic Path/Fabric fallback **Not Wired / explicitly postposed**.

## 15. Proxy protocol maturity must be stated per runtime

A concise current matrix is:

| Protocol | Config vocabulary | Protocol/mechanism | foreground `nexus proxy` | daemon TUN ProxyEngine |
|---|---|---|---|---|
| Direct | yes | yes | Wired | not a dial config in this engine |
| Relay | yes | mechanisms elsewhere | deferred in inspected foreground arm | no |
| Shadowsocks | yes | substantive | Wired | Wired, restricted method |
| Trojan | yes | substantive + TLS | Wired TLS path | Wired plaintext/TLS heuristic |
| SOCKS5 | yes | substantive | ingress/runtime support | Wired |
| VMess | yes | local AEAD/self-consistency | real node tunnel deferred | no |
| AnyTLS | yes | substantive adapter | Wired in foreground audit | no |
| VLESS | yes | substantial protocol-over-stream | Wired TCP/TLS; Vision direct transition partial | no |
| Hysteria2 | yes | QUIC/H3 client machinery | Wired TCP-proxy use case; UDP/port-hop/Brutal incomplete | no |

The daemon engine subset is directly evidenced in [`apps/nexusd/src/proxy_fwd.rs` L52-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/proxy_fwd.rs#L52-L112). Foreground selection through exact rule-engine tag is evidenced in [`apps/nexus/src/lib.rs` L4745-L4815](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/lib.rs#L4745-L4815).

## 16. Workspace local lifecycle is genuinely production-wired on Linux

`apps/nexusd::workspace` owns Linux Workspace configuration, shared on-disk CAS, per-workspace state-root anchors, FUSE projection, optional auto-commit and explicit shutdown behavior. Lack of `/dev/fuse` disables the subsystem with an explicit warning rather than silently substituting another semantic. [`apps/nexusd/src/workspace.rs` L1-L13](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/workspace.rs#L1-L13)

Commit is serialized by `commit_mu`; the implementation documents a remaining crash window: `fs.commit()` can make new durable CAS state before the `state_root` anchor is atomically rewritten. A crash in that interval can restart from the old anchor while the new commit remains in CAS but unreachable. HTTP acknowledgement is deliberately after anchor update. [`apps/nexusd/src/workspace.rs` L126-L166](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/workspace.rs#L126-L166)

Current status: local Workspace CAS/FUSE lifecycle **Wired on Linux**; the crash window is an explicit durability limitation, not hidden.

## 17. Workspace Fabric sync is a separate adapter and is not the same as WorkspaceManager lifecycle

`sync_transport.rs` implements a real `WorkspaceTransport` over Fabric bi-streams. Crucially, its own documentation says active connection acquisition remains **caller-owned** (`NatSwitching::active_conn(peer)`), and passive routing requires callers to consume unclaimed/accepted streams and dispatch type `0x03` to sync serving. [`apps/nexusd/src/sync_transport.rs` L1-L24](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L1-L24)

The adapter reuses an existing Fabric connection, uses stream type `0x03`, a 64 KiB frame bound and a 30 s per-frame receive deadline. [`apps/nexusd/src/sync_transport.rs` L27-L42](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L27-L42) [`apps/nexusd/src/sync_transport.rs` L75-L170](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L75-L170)

No automatic sync-server/client ownership is described by `WorkspaceManager`; its production responsibilities are local mount/CAS/commit lifecycle. [`apps/nexusd/src/workspace.rs` L1-L13](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/workspace.rs#L1-L13)

Safe status: sync protocol/adapter **Implemented**; normal WorkspaceManager auto-sync lifecycle **wiring unproven**.

## 18. Workspace sync authorization has an unresolved server identity boundary

`SyncAuthorizer` is real and `serve_sync_authorized` rejects a non-member before serving workspace objects. [`apps/nexusd/src/sync_transport.rs` L213-L255](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L213-L255)

However the source explicitly states current Fabric P0 server side cannot trust client PeerId; `ConnShared::peer` is not yet a trustworthy authenticated client identity there. The authorizer is therefore “mechanism ready; strong production enforcement awaits client-auth”. [`apps/nexusd/src/sync_transport.rs` L172-L211](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L172-L211)

This prevents describing Workspace sync security as Production-closed.

## 19. N2 identity/authentication model

N2 uses a separate ed25519-oriented resource-access identity/grant model rather than relying on client-supplied principal strings. The provider-side admission protocol is challenge-response and derives the principal from verified key material; grants are scoped to resource/workspace/operation and Manage implies Use in the established auth semantics.

A key boundary from the audited implementation is that N2 admission authentication is application-protocol authentication and does not itself imply transport confidentiality or forward secrecy. Consequently “mutually authenticated admission” must not be restated as “encrypted secure channel” unless the underlying channel independently provides it.

The daemon owns one process-global N2 `SessionManager` plus a sweeper for detached sessions. [`apps/nexusd/src/main.rs` L35-L108](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L35-L108)

At the same time, several `nexus` N2 command families (`use`, `session`, resource/grant/provider administration) remain in-process rather than universally routed through daemon LocalAPI. [`apps/nexus/src/main.rs` L271-L322](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L271-L322)

Thus N2 runtime authority is still split across daemon-owned and CLI-local surfaces.

## 20. N3 Task control path is real and ahead of its help text

The CLI help still says Task submit and Artifact download are not fully wired. [`apps/nexus/src/main.rs` L61-L77](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L61-L77)

Executable code contradicts that wording. `task_cli` strictly parses Task/Artifact operations, validates/decodes bounded versioned DTOs and executes requests through daemon LocalAPI. [`apps/nexus/src/task_cli.rs` L1-L170](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/task_cli.rs#L1-L170)

Linux Artifact download probes before output I/O, supports durable resume by exact offset, rejects record/page inconsistencies, requires final remote re-authorization at EOF and only then completes the verified receiver. [`apps/nexus/src/task_cli.rs` L172-L239](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/task_cli.rs#L172-L239)

Current interpretation: the help strings are **drift**; executable N3 Task/Artifact behavior is substantially more mature.

## 21. N3 durability model is stronger than legacy Workspace object identity

The audited N3 path deliberately uses stronger content/artifact integrity semantics (SHA-256 + size, durable receiver state, no-replace publication) than legacy Workspace CAS identity, which historically uses a lightweight object identifier. These are distinct storage/integrity domains and must not be collapsed into one repository-wide content-addressing guarantee.

The Artifact CLI behavior above provides the product-facing evidence for strong requester integrity. [`apps/nexus/src/task_cli.rs` L172-L239](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/task_cli.rs#L172-L239)

## 22. Scheduler is a durable manual registry, not an autonomous job executor

The Scheduler CLI loads/saves a local registry under `$NEXUS_HOME/schedule.json` or `~/.nexus/schedule.json`, fails loudly on corrupt JSON, and updates state with temp file + rename. [`apps/nexus/src/schedule_cli.rs` L1-L105](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/schedule_cli.rs#L1-L105)

Its default submit callback only returns a synthetic `task-<resource>` string and explicitly does not execute a Task. [`apps/nexus/src/schedule_cli.rs` L106-L118](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/schedule_cli.rs#L106-L118)

`schedule` is an in-process CLI command family, not a daemon-owned periodic loop in the inspected dispatch. [`apps/nexus/src/main.rs` L239-L246](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L239-L246)

Current status:

- scheduling model: **Implemented**;
- local persistence/manual tick: **Wired**;
- autonomous periodic clock ownership: **not established**;
- actual N3 task submission/execution: **Not Wired**.

## 23. Platform reality

Linux and Windows are both substantive but cover different surfaces.

Linux exports address/route setup, OS assembly, daemon integration, DNS, file leases, FUSE Workspace projection, netlink, operation log, secure store, TUN and TUN-backed VPI. [`crates/nexus-platform-linux/src/lib.rs` L1-L39](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-platform-linux/src/lib.rs#L1-L39)

Windows exports Task Scheduler autostart, DPAPI, netcfg, secure store, VPI, WinINET proxy and Wintun. [`crates/nexus-platform-windows/src/lib.rs` L1-L23](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-platform-windows/src/lib.rs#L1-L23)

Android source body currently contains documentation plus `forbid(unsafe_code)` only; earlier audit found macOS and iOS in the same source-level skeleton class. [`crates/nexus-platform-android/src/lib.rs` L1-L7](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-platform-android/src/lib.rs#L1-L7)

Accurate platform summary:

- Linux: most complete daemon/server + Workspace/N3 execution platform;
- Windows: substantial networking/desktop integration, not a skeleton;
- macOS/Android/iOS: near-placeholder in the audited executable source.

## 24. Windows autostart integration has a high-confidence caller/adapter mismatch

The prior source sweep found `nexus autostart install` using the current `nexus` executable while registering historical `serve --addr ...` arguments, whereas `serve` belongs to the daemon interface and is absent from the current `nexus` command list. The Windows adapter's own tests still model `nexusd.exe serve ...`.

This is classified as a **source-predicted integration defect**, not runtime-Verified on Windows. It demonstrates why adapter implementation and caller integration must be evaluated separately.

## 25. Connectivity crate maturity is per capability, not per crate

`nexus-connectivity` contains a mixture of pure state machines, realized implementations and scenario-targeted mechanisms. Some components have real transport/crypto behavior; others remain deterministic policy/state-machine slices awaiting a product owner.

A particularly important security distinction established in the source sweep is that Connectivity-level encryption uses X25519/HKDF/ChaCha20-Poly1305 semantics, while Fabric uses its own TLS/QUIC security and N2 admission uses ed25519 challenge-response. These are separate layers with different properties; they must not be summarized as one generic “Nexus encryption”.

For this crate family the canonical maturity model is four-dimensional:

`Mechanism Implemented -> Scenario-targeted -> Product Wired -> Revision-bound Verified`.

## 26. Ingress is a portable decode/classification layer, not the interception owner

`nexus-ingress` provides SOCKS5/HTTP/VPI/Native flow construction and protocol parsing without owning OS interception or system-level planning. SOCKS5 CONNECT is supported; BIND/UDP ASSOCIATE are explicitly outside the inspected handshake state machine, and RFC1929 framing validation is not equivalent to credential authorization.

Current role: protocol/classification **Implemented**; platform listener/TUN ownership lives elsewhere.

## 27. `nexus-service`, `nexus-delivery`, `nexus-diagnostics`, `nexus-proto`

The source sweep established materially different maturity despite similar architectural naming:

- `nexus-service`: real CONNECT -> READY -> Active service-transport lifecycle; forwarding is a separate concern.
- `nexus-delivery`: currently a minimal/skeleton architectural seam rather than a completed unified Delivery runtime.
- `nexus-diagnostics`: minimal/skeleton crate body.
- `nexus-proto`: centralized-schema intention exists, but actual wire contracts remain distributed across concrete modules.

The important baseline rule is that a crate name is not evidence that the architecture box is production-owned.

## 28. Workspace Intelligence is now a first-class workspace member

`nexus-workspace-intel` contains non-authoritative access-trace/graph/working-set/prefetch/delivery intelligence, and at the reviewed revision it is explicitly listed in root workspace members. [`Cargo.toml` L1-L52](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/Cargo.toml#L1-L52)

This supersedes all staging text that described it as physically present but omitted from root workspace membership.

## 29. Engineering Harness

Harness scenario execution now uses bounded parallel workers by default. `NEXUS_HARNESS_JOBS` can override worker count and `1` restores serial execution; results are placed back in scenario declaration order before gate aggregation. [`engineering/nexus-harness/src/scenario.rs` L606-L704](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/engineering/nexus-harness/src/scenario.rs#L606-L704)

This is an engineering performance/runtime fact, not a verification claim. The evidence model still requires revision/config/platform binding for `Verified`.

## 30. Drift register: comments/help that are known not to describe current executable truth

Known high-confidence drift includes:

1. `apps/nexus/src/main.rs` top-level “thin client” wording vs its many in-process composition roots. [`apps/nexus/src/main.rs` L1-L17](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L1-L17) [`apps/nexus/src/main.rs` L197-L329](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L197-L329)
2. `apps/nexusd/src/main.rs` opening “runtime later” language vs actual N2/session/dataplane/workspace ownership. [`apps/nexusd/src/main.rs` L1-L108](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L1-L108)
3. CLI help saying N3 submit/download is not fully wired vs executable `task_cli`. [`apps/nexus/src/main.rs` L61-L77](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L61-L77) [`apps/nexus/src/task_cli.rs` L1-L239](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/task_cli.rs#L1-L239)
4. `nexus-proxy-transport` comment claiming shared config lacks SOCKS5 even though current config vocabulary includes it; the stale comment is not used as capability truth. [`crates/nexus-proxy-transport/src/lib.rs` L39-L48](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/src/lib.rs#L39-L48)
5. compression/other connectivity modules contain historical “stub/pass-through” comments that later executable implementations have outgrown; executable bodies win.

## 31. Current runtime ownership matrix

| Concern | Main current owner(s) | Current status |
|---|---|---|
| Stable Resource/Plan types | `nexus-domain` | Implemented |
| System planning | `nexus-planner` | Implemented; not universally used by every product path |
| Session semantics | `nexus-session` | Implemented |
| Local control API | `nexusd` | Wired |
| Daemon TUN packet pipeline | `nexusd::Dataplane` + `nexus-projection` primitives | Wired |
| Flow-session gate | `nexusd::Dataplane` optional chain | Implemented; default activation not established |
| Foreground N1 packet pump | `VpiPump` / CLI composition | Wired in its own path |
| Daemon N1 packet forwarding | `Dataplane + N1Sender/N1MeshBridge` | Wired in daemon path |
| NAT direct/relay switching | `NatSwitching` | Implemented; explicitly not normal-daemon instantiated |
| Foreground Internet proxy | `nexus proxy` + `ProxyService` | Wired |
| Daemon TUN proxy | `nexusd::ProxyEngine` | Wired, narrower/different semantics |
| Fabric-over-proxy path | `nexus-proxy-transport` | Implemented; automatic Path fallback not wired |
| Linux Workspace mount/commit | `nexusd::WorkspaceManager` | Wired |
| Workspace Fabric sync | `sync_transport` + caller-owned connection/routing | Implemented; normal auto-lifecycle unproven |
| N2 daemon session owner | process-global `N2_SESSION_MANAGER` | Wired for daemon-owned routes/sweeper |
| N2 CLI admin/use/provider | `apps/nexus` local paths | Wired separately |
| N3 Task/Artifact control | `nexus task/artifact` -> daemon LocalAPI | Wired on supported platform path |
| Scheduler | local CLI registry/manual tick | Wired as registry, not autonomous execution |
| Linux adapters | `nexus-platform-linux` | substantial |
| Windows adapters | `nexus-platform-windows` | substantial, different scope |
| macOS/Android/iOS adapters | OS crates | skeleton/near-placeholder |

## 32. Highest-confidence production gaps

The current code-first gaps that materially affect architecture are:

1. **runtime ownership fragmentation** — CLI-local and daemon-owned composition roots coexist for N1, N2, proxy and system integration;
2. **daemon TUN proxy semantic mismatch** — it does not currently consume foreground ProxyService per-flow selected tags and supports a narrower outbound set;
3. **Fabric-over-proxy not selected by PathManager automatically** — mechanism exists but composition is explicitly postposed;
4. **NAT switch stack not activated in normal daemon** — TURN client/config/credential and STUN/srflx lifecycle remain open;
5. **Workspace sync not owned by normal WorkspaceManager lifecycle** — caller must acquire active connection and route passive streams;
6. **Workspace sync server identity not production-authenticated** — server-side peer identity is explicitly untrustworthy in Fabric P0;
7. **flow-session chain is optional and synthetic in provider construction** — it is not yet a transparent system-wide resource-session gate;
8. **Scheduler has no autonomous clock/execution binding**;
9. **platform closure is Linux-centric for Workspace/N3 while macOS/mobile adapters remain mostly empty**;
10. **source comments/help remain materially behind executable implementation in several high-value modules**.

## 33. What this baseline does not claim

This document intentionally does **not** claim:

- that every implemented crate is product wired;
- that every Harness scenario is currently passing;
- that a commit message mentioning passing tests is equivalent to bound Evidence;
- that Fabric currently provides trustworthy mutual peer identity for every server-side consumer;
- that successful NAT punching forces path promotion;
- that `proxy.yaml` rule semantics are identical in foreground and daemon TUN runtimes;
- that Scheduler runs commands merely because `schedule tick` advances state;
- that Workspace local durability closes the documented commit/anchor crash window;
- that macOS/Android/iOS currently implement the capabilities named in their crate documentation;
- that source absence found by search proves global nonexistence.

## 34. Baseline conclusion

At revision `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573`, Nexus Fabric is not a repository of empty architecture placeholders. Core planning/session semantics, daemon TUN forwarding, N1 packet machinery, proxy protocols, Linux Workspace projection, N2 admission/session state, N3 Task/Artifact paths, Fabric/NAT mechanisms and Windows/Linux adapters contain substantial executable code.

The dominant current-state problem is **not lack of mechanism implementation**. It is that mature mechanisms frequently terminate one layer before system-level ownership closes: multiple composition roots coexist, some richer adapters are not consumed by the dominant daemon path, security identities differ by layer, and product wiring/verification lags behind protocol depth.

This is the correct handoff point for a separate TARGET_STATE exercise: target design should decide canonical ownership and deletion/migration paths without rewriting these current facts.

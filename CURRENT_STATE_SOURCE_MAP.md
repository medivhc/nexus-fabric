# CURRENT_STATE source map

> Reviewed source revision: `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573`.
>
> This map is the citation backbone for the canonical CURRENT_STATE rewrite. Links are immutable commit-pinned GitHub line anchors. A statement in the canonical baseline should point either directly to one of these ranges or to a more specific range at the same revision.

## Repository and engineering surface

| Current-state fact | Source anchor |
|---|---|
| Root workspace has 51 explicit members and now explicitly includes `crates/nexus-workspace-intel` | [`Cargo.toml` L1-L52](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/Cargo.toml#L1-L52) |
| Generated Harness evidence root `/.evidence` is gitignored | [`.gitignore` L1-L3](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/.gitignore#L1-L3) |
| Harness scenario execution is bounded-parallel by default; `NEXUS_HARNESS_JOBS=1` forces serial behavior | [`engineering/nexus-harness/src/scenario.rs` L606-L704](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/engineering/nexus-harness/src/scenario.rs#L606-L704) |

## Stable Core / Planner / Session

| Current-state fact | Source anchor |
|---|---|
| Stable domain core defines Resource/Provider/Session identity separately; `ResourceKind` includes Network/Service/Workspace/Compute/Device; crate is zero-I/O portable core | [`crates/nexus-domain/src/lib.rs` L1-L162](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-domain/src/lib.rs#L1-L162) |
| Core Planner is explicitly system-level, deterministic, zero-I/O, with Filter → connectivity gate → Score and `LOCALITY_BONUS = 1000` | [`crates/nexus-planner/src/lib.rs` L1-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-planner/src/lib.rs#L1-L112) |
| Planner connectivity feasibility gate rejects evaluated candidates with no feasible path while leaving unknown/unassessed candidates unchanged | [`crates/nexus-planner/src/lib.rs` L167-L194](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-planner/src/lib.rs#L167-L194) |
| Session owner separates `LifecyclePhase` from terminal outcome; workers emit events; terminal outcome is commit-once through `SessionOwner` | [`crates/nexus-session/src/lib.rs` L1-L48](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-session/src/lib.rs#L1-L48), [`L145-L255`](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-session/src/lib.rs#L145-L255) |

## CLI / daemon ownership

| Current-state fact | Source anchor |
|---|---|
| `nexus` header/help describes a thin-client direction but also contains stale N3 help text | [`apps/nexus/src/main.rs` L1-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L1-L112) |
| Actual CLI dispatcher owns numerous in-process composition roots (`subnet`, `schedule`, `proxy`, system integration, N2 admin/use/provider, etc.) | [`apps/nexus/src/main.rs` L197-L329](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L197-L329) |
| `nexusd` header still contains historical “runtime later” wording while the same file immediately owns global N2 session state/sweeper and other concrete runtime responsibilities | [`apps/nexusd/src/main.rs` L1-L108](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L1-L108) |
| Unix LocalAPI socket is hardened to 0600; Windows socket target explicitly reports named pipe unimplemented and requires `--addr` | [`apps/nexusd/src/main.rs` L950-L1035](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L950-L1035) |

## Daemon dataplane

| Current-state fact | Source anchor |
|---|---|
| `nexusd::Dataplane` owns one TUN, DNS, QoS, N1 sender, daemon ProxyEngine, smoltcp terminator and optional flow-session state | [`apps/nexusd/src/dataplane.rs` L1-L184](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L1-L184) |
| The dataplane directly reuses `nexus-projection` primitives (`TunDevice`, classifier, CIDR routing, TCP terminator) rather than being wholly independent code | [`apps/nexusd/src/dataplane.rs` L20-L35](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L20-L35) |
| Upstream establishment in the optional flow-session chain is currently an availability gate over N1/proxy flags rather than a full transport-specific dial itself | [`apps/nexusd/src/dataplane.rs` L101-L132](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L101-L132) |

## Scheduler

| Current-state fact | Source anchor |
|---|---|
| Scheduler CLI owns persistent snapshot loading/saving, fail-loud corruption behavior and temp-file + rename commit | [`apps/nexus/src/schedule_cli.rs` L1-L105](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/schedule_cli.rs#L1-L105) |
| Scheduler submit callback only returns synthetic `task-<resource>` and does not execute the command/task | [`apps/nexus/src/schedule_cli.rs` L106-L118](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/schedule_cli.rs#L106-L118) |
| Scheduler command family is routed in-process by the CLI | [`apps/nexus/src/main.rs` L239-L246](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L239-L246) |

## Proxy: three different mechanisms

| Current-state fact | Source anchor |
|---|---|
| Foreground `nexus proxy` is routed as an in-process product data plane | [`apps/nexus/src/main.rs` L247-L253](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L247-L253) |
| Foreground proxy accepts SOCKS5/HTTP, invokes `ProxyService::route`, resolves the exact selected outbound tag, then enters the concrete outbound match | [`apps/nexus/src/lib.rs` L4684-L4815](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/lib.rs#L4684-L4815) |
| Daemon `ProxyEngine` chooses the first locally supported outbound, supports SS/Trojan/SOCKS5 shapes and returns `None` for Direct/Relay/VMess/AnyTLS/VLESS/Hysteria2 | [`apps/nexusd/src/proxy_fwd.rs` L1-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/proxy_fwd.rs#L1-L112) |
| Per-link `nexus-proxy-transport` implements proxy-established streams as Fabric `UdpTransport` adapters | [`crates/nexus-proxy-transport/src/lib.rs` L1-L48](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/src/lib.rs#L1-L48) |
| Automatic PathManager fallback to the per-link proxy transport is explicitly not owned/implemented by that crate | [`crates/nexus-proxy-transport/MODULE.md` L3-L17](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/MODULE.md#L3-L17) |
| `nexus-proxy-transport` contains a stale comment claiming shared config lacks SOCKS5; this comment must not override current config truth | [`crates/nexus-proxy-transport/src/lib.rs` L39-L48](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/src/lib.rs#L39-L48) |

## N3 Task / Artifact CLI

| Current-state fact | Source anchor |
|---|---|
| CLI help still says Task submit / Artifact download are not fully wired | [`apps/nexus/src/main.rs` L61-L77](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L61-L77) |
| Actual Task CLI parses strict versioned requests and executes them through daemon LocalAPI | [`apps/nexus/src/task_cli.rs` L1-L170](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/task_cli.rs#L1-L170) |
| Linux Artifact download probes authorization before output I/O, resumes by durable offset, verifies page consistency and re-authorizes final EOF | [`apps/nexus/src/task_cli.rs` L172-L239](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/task_cli.rs#L172-L239) |

## Platform reality

| Current-state fact | Source anchor |
|---|---|
| Linux adapter exports concrete addr/assemble/daemon/DNS/file-lease/FUSE/netlink/op-log/route/secure-store/TUN/VPI modules | [`crates/nexus-platform-linux/src/lib.rs` L1-L39](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-platform-linux/src/lib.rs#L1-L39) |
| Windows adapter exports substantive autostart/DPAPI/netcfg/secure-store/VPI/WinINET/Wintun modules | [`crates/nexus-platform-windows/src/lib.rs` L1-L23](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-platform-windows/src/lib.rs#L1-L23) |
| Android platform crate source body is documentation plus `forbid(unsafe_code)` only | [`crates/nexus-platform-android/src/lib.rs` L1-L7](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-platform-android/src/lib.rs#L1-L7) |

## Canonical citation rules

1. Prefer executable source over MODULE/comment prose when they disagree.
2. Use MODULE/contract line anchors to prove explicit non-responsibility or frozen boundary, not to prove runtime wiring.
3. For negative claims derived from inspection rather than an explicit source statement, write `not found in the inspected product path` or `production wiring unproven`; do not write categorical `does not exist`.
4. `Verified` requires evidence bound to this revision and relevant platform/config; code and scenario line anchors alone are not sufficient.
5. Every major runtime/capability paragraph in the canonical rewrite should contain at least one commit-pinned line anchor. Detailed subclaims should use narrower line ranges where practical.
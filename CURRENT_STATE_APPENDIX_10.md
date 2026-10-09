# CURRENT_STATE continuation — sections 144–151

> Pre-merge convergence pass. Unlike earlier appendices, every major claim here is connected to immutable code line anchors.
>
> Reviewed source revision: `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573`.
>
> This appendix supersedes contradictory staging statements where explicitly noted. It is not permission to retain both old and new claims in the eventual canonical file.

## 144. Baseline revision advanced; workspace membership is now explicit and the previous count is obsolete

The previous audit revision was `48918863e70ef8589fbca6075c7ec11ca07e85a3`. Current reviewed `master` is `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573`.

At this revision the root workspace literal contains **51 explicit members**, and `crates/nexus-workspace-intel` is directly listed. This invalidates the earlier current-state claims that the literal count is 50, that `nexus-workspace-intel` is absent from the member list, or that its membership remains unresolved because of that omission.

Source:

- [`Cargo.toml` L1-L52](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/Cargo.toml#L1-L52)

Canonical merge action: **replace**, do not append another caveat. The old 50-member/non-membership text becomes historical audit trail only.

## 145. Harness scenario execution is now bounded-parallel, but that does not change the meaning of Verified

The reviewed revision adds bounded parallel scenario execution:

- `NEXUS_HARNESS_JOBS` overrides worker count;
- `1` preserves serial behavior;
- otherwise available parallelism is used with an upper bound of 16;
- results are restored to declaration order before gate aggregation.

Source:

- [`engineering/nexus-harness/src/scenario.rs` L606-L704](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/engineering/nexus-harness/src/scenario.rs#L606-L704)

This is an **Implemented engineering-runtime change**. It does not by itself make product scenarios `Verified`.

The root generated-evidence directory remains ignored:

- [`.gitignore` L1-L3](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/.gitignore#L1-L3)

Therefore the baseline keeps the same verification rule: revision/config/platform-bound Evidence is required for `Verified`; source code, scenario declarations and commit-message prose are insufficient substitutes.

## 146. The canonical document now requires source-line traceability as part of its evidence model

The earlier baseline was code-first but not consistently line-addressable. The canonical rewrite must tighten that rule:

1. each major runtime/capability statement must include at least one immutable `commit/path#Lx-Ly` source anchor;
2. executable source outranks comments and historical docs when they conflict;
3. MODULE/contract text can prove explicit responsibility or non-responsibility, but not runtime wiring by itself;
4. negative inspection claims must be phrased as `not found in the inspected path` / `wiring unproven` unless source explicitly states the feature is postposed;
5. source anchors prove implementation/current structure, not `Verified` status.

The companion `CURRENT_STATE_SOURCE_MAP.md` is the citation backbone for this rule.

## 147. Three proxy mechanisms are now a stable current-state distinction, not a temporary audit hypothesis

The repository has three separate proxy-related ownership planes and the canonical architecture map must keep them separate.

### 147.1 Foreground per-flow proxy

`nexus proxy` is routed as an in-process product runtime rather than through daemon LocalAPI.

Source:

- [`apps/nexus/src/main.rs` L247-L253](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L247-L253)

The prior source sweep established that this runtime consumes `ProxyService` per-flow routing and has the broader concrete outbound set. That foreground support must not be generalized to the daemon TUN path.

### 147.2 Daemon TUN ProxyEngine

The daemon engine scans `config.outbounds` and takes the first outbound it can locally realize. In this inspected path it supports SS/Trojan/SOCKS5 shapes and returns `None` for Direct/Relay/VMess/AnyTLS/VLESS/Hysteria2.

Source:

- [`apps/nexusd/src/proxy_fwd.rs` L1-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/proxy_fwd.rs#L1-L112)

The consequence is stronger than “protocol coverage differs”: the daemon TUN path does not currently prove enforcement of the foreground rule engine's selected outbound tag.

### 147.3 Per-link Fabric-over-proxy transport

`nexus-proxy-transport` implements proxy-established streams as `nexus_fabric::UdpTransport` adapters for carrying Fabric/QUIC through a proxy.

Source:

- [`crates/nexus-proxy-transport/src/lib.rs` L1-L48](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/src/lib.rs#L1-L48)

Its own module contract explicitly says automatic PathManager fallback linkage is postposed:

- [`crates/nexus-proxy-transport/MODULE.md` L3-L17](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/MODULE.md#L3-L17)

Thus per-link proxy transport is **Implemented**, while automatic Path/Fabric product fallback remains **Not Wired / explicitly postposed**.

## 148. Scheduler remains a durable manual registry; synthetic submission must not be called task execution

The current Scheduler CLI persists state, fails loudly on corrupt snapshots and commits replacements with temp-file + rename.

Source:

- [`apps/nexus/src/schedule_cli.rs` L1-L105](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/schedule_cli.rs#L1-L105)

But its submit callback still returns only a generated `task-<resource>` string:

- [`apps/nexus/src/schedule_cli.rs` L106-L118](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/schedule_cli.rs#L106-L118)

And `schedule` remains an in-process CLI command family:

- [`apps/nexus/src/main.rs` L239-L246](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L239-L246)

Canonical status remains:

- scheduler model: **Implemented**;
- local persistence/manual tick: **Wired**;
- autonomous timer ownership: **not established in the inspected product path**;
- actual N3 Task submission: **Not Wired**.

## 149. N3 executable wiring is ahead of the CLI help text

The CLI help still labels N3 Task submission and Artifact download as incompletely wired:

- [`apps/nexus/src/main.rs` L61-L77](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L61-L77)

Executable `task_cli` contradicts that wording. It parses strict operation DTOs, prepares versioned Task requests and executes them through daemon LocalAPI:

- [`apps/nexus/src/task_cli.rs` L1-L170](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/task_cli.rs#L1-L170)

Linux Artifact download performs probe-before-output-I/O, durable resume, record/page consistency checking and final re-authorization before receiver completion:

- [`apps/nexus/src/task_cli.rs` L172-L239](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/task_cli.rs#L172-L239)

Canonical interpretation: the help strings are **drift**. They must not be used to downgrade the executable N3 current state.

## 150. Runtime ownership remains deliberately and historically split between `nexus` and `nexusd`

The `nexus` file header still presents a thin-client model:

- [`apps/nexus/src/main.rs` L1-L17](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L1-L17)

The actual dispatcher owns many local product roots:

- [`apps/nexus/src/main.rs` L197-L329](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L197-L329)

Conversely, `nexusd` owns process-global N2 session state and a sweeper despite its stale opening comments saying much runtime assembly is future work:

- [`apps/nexusd/src/main.rs` L1-L108](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L1-L108)

The integrated daemon dataplane itself owns TUN, DNS, QoS, N1 sender, daemon ProxyEngine, TCP termination and optional flow-session state, while reusing lower-level `nexus-projection` primitives:

- [`apps/nexusd/src/dataplane.rs` L1-L184](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L1-L184)
- [`apps/nexusd/src/dataplane.rs` L20-L35](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L20-L35)

Therefore “nexus is a thin client” and “nexusd owns all runtime” are both overstatements for the current repository.

## 151. Pre-merge review result

The source sweep is now mature enough to stop adding unconsolidated architecture prose. The canonical merge is gated on the following corrections:

1. source revision becomes `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573`;
2. workspace member count becomes **51** and workspace-intel omission language is deleted;
3. Harness bounded-parallel execution is added as an implementation fact, without upgrading verification status;
4. the three proxy ownership planes remain distinct;
5. Scheduler stays classified as manually ticked/non-executing;
6. N3 help text is explicitly marked drift;
7. split CLI/daemon ownership remains visible;
8. every major canonical capability paragraph receives a commit-pinned source-line anchor;
9. earlier staging claims contradicted by later source are removed during merge instead of preserved as parallel truth.

`CURRENT_STATE_MERGE_REVIEW.md` records the self-review gate, and `CURRENT_STATE_SOURCE_MAP.md` records the initial source-line backbone. The next operation should be canonical consolidation, not Appendix XI.
# CURRENT_STATE merge review

> Purpose: pre-generation self-review before replacing the staging `CURRENT_STATE.md` + appendices with one canonical baseline.
>
> Reviewed source revision: `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573` (`master`).
>
> This file is intentionally code-first. Every correction below is connected to an immutable source revision and code line range. Historical prose and commit messages are not used to upgrade implementation state to `Verified`.

## 1. Revision reconciliation

The previous baseline was pinned to `48918863e70ef8589fbca6075c7ec11ca07e85a3`. Current `master` is one commit ahead at `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573`.

The delta is material to two previously recorded facts:

1. `crates/nexus-workspace-intel` is now explicitly present in root `[workspace].members`.
2. the Harness now runs scenarios with bounded parallel workers by default, with `NEXUS_HARNESS_JOBS=1` preserving serial execution.

Source anchors:

- [`Cargo.toml` L1-L52](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/Cargo.toml#L1-L52)
- [`engineering/nexus-harness/src/scenario.rs` L606-L704](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/engineering/nexus-harness/src/scenario.rs#L606-L704)

### Required supersessions

The canonical merge must delete or rewrite all claims that say:

- the root workspace literal has 50 members;
- `nexus-workspace-intel` is omitted from `[workspace].members`;
- its resolved workspace membership is unknown solely because of that omission.

At the reviewed revision the literal workspace member count is **51**, and `crates/nexus-workspace-intel` is explicitly listed.

This supersedes the old `CURRENT_STATE.md` workspace-count wording and the staging correction in Appendix VIII §131.

## 2. Evidence wording review

`/.evidence` is explicitly ignored by the root `.gitignore`. Therefore generated Harness evidence must not be described as normal checked-in source authority unless a specific tracked file is independently demonstrated.

Source anchor:

- [`.gitignore` L1-L3](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/.gitignore#L1-L3)

Canonical rule remains:

- implementation source can establish `Implemented` / `Wired`;
- scenario definitions can establish `Scenario-targeted`;
- only evidence bound to the reviewed revision/config/platform can establish `Verified`.

The `master` commit message mentions test/gate success, but commit-message prose is not itself promoted to revision-bound Evidence in the baseline.

## 3. CLI ownership review

The top-level `nexus` file still describes a thin-client direction, but executable dispatch intentionally contains many in-process product roots.

Confirmed in-process command families include N3 local dispatch routing, subnet, schedule, proxy, system-proxy, autostart, config, pair, node, plan, use, session, resource, grant and provider; `run` and `network` also keep local composition paths.

Source anchors:

- stale/partial thin-client description and help: [`apps/nexus/src/main.rs` L1-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L1-L112)
- actual mixed dispatcher: [`apps/nexus/src/main.rs` L197-L329](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L197-L329)

Canonical statement should be: **the product currently has split CLI-owned and daemon-owned composition roots; “thin client” is not a whole-product runtime description.**

## 4. Scheduler review

The Scheduler is a persistent manually driven registry, not an autonomous job scheduler.

Source establishes:

- state lives in `$NEXUS_HOME/schedule.json` or `~/.nexus/schedule.json`;
- corrupt state is fail-loud;
- persistence uses temp file + rename;
- the submit callback only returns `task-<resource>` and does not execute a Task.

Source anchor:

- [`apps/nexus/src/schedule_cli.rs` L1-L118](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/schedule_cli.rs#L1-L118)

The CLI dispatcher exposes `schedule` as an in-process family rather than a daemon-owned timer loop:

- [`apps/nexus/src/main.rs` L239-L246](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L239-L246)

Canonical status:

- model/state machine: **Implemented**;
- local CLI persistence/manual tick: **Wired**;
- autonomous clock ownership: **Not Wired in inspected product path**;
- N3 Task submission: **Not Wired**.

## 5. Proxy ownership review

The canonical baseline must keep three different proxy mechanisms separate.

### 5.1 Foreground per-flow proxy

`nexus proxy` is a product-reachable foreground runtime and must not be conflated with the daemon TUN engine.

The CLI explicitly routes the proxy family in process:

- [`apps/nexus/src/main.rs` L247-L253](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L247-L253)

Its implementation later owns a real listener/service loop and product command family; the canonical baseline should preserve the detailed protocol matrix already established by the source sweep.

### 5.2 Daemon TUN ProxyEngine

The daemon engine does **not** consume a per-flow `ProxyService` selected tag. Its constructor scans `config.outbounds` and picks the first locally realizable dial config.

It supports in this engine:

- Shadowsocks (`chacha20-ietf-poly1305` only);
- Trojan plaintext;
- Trojan TLS under its local heuristic;
- SOCKS5.

It returns no dial config for Direct, Relay, VMess, AnyTLS, VLESS and Hysteria2.

Source anchor:

- [`apps/nexusd/src/proxy_fwd.rs` L1-L112](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/proxy_fwd.rs#L1-L112)

This is a current production-semantic gap: **Clash-style rules can be parsed without the daemon forwarding hot path enforcing the foreground rule-engine selection.**

### 5.3 Per-link Fabric-over-proxy transport

`nexus-proxy-transport` is a third mechanism. It implements proxy-established transports that satisfy `nexus_fabric::UdpTransport`; it is for carrying Fabric/QUIC over a proxy, not per-flow Internet egress.

Source anchors:

- adapter purpose and public transport surface: [`crates/nexus-proxy-transport/src/lib.rs` L1-L48](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/src/lib.rs#L1-L48)
- explicit non-responsibility for automatic Path fallback: [`crates/nexus-proxy-transport/MODULE.md` L3-L17](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-proxy-transport/MODULE.md#L3-L17)

Canonical status: mechanism **Implemented**; automatic `PathManager` fallback/product composition **Not Wired / explicitly postposed**.

## 6. N3 CLI/help drift review

The CLI help understates current N3 implementation. It still labels Task submit and Artifact download as incompletely wired:

- [`apps/nexus/src/main.rs` L61-L77](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/main.rs#L61-L77)

Actual `task_cli` code provides strict request parsing, daemon execution via `task_localapi::execute`, and a Linux Artifact receiver with probe/resume/re-authorization semantics:

- parse/prepare/daemon execution: [`apps/nexus/src/task_cli.rs` L1-L170](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/task_cli.rs#L1-L170)
- Linux Artifact retrieval loop: [`apps/nexus/src/task_cli.rs` L172-L239](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/task_cli.rs#L172-L239)

Canonical merge must classify the help strings as drift rather than as capability truth.

## 7. Daemon ownership/comment drift review

`apps/nexusd/src/main.rs` begins with historical wording that says long-running mesh/proxy/dns runtime assembly is future work, while the same executable now owns concrete N2 session state, LocalAPI, workspace state and the integrated dataplane elsewhere in the file.

Source anchor for the stale header plus current N2 ownership immediately below it:

- [`apps/nexusd/src/main.rs` L1-L108](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/main.rs#L1-L108)

The merge must not treat file-header architecture prose as stronger evidence than executable code below it.

## 8. Self-review findings before canonical generation

The following checks were applied to the planned merge:

1. **Revision check** — all new source anchors use immutable revision `e6ccf8b8...`, not moving `master` URLs.
2. **Supersession check** — old workspace count/non-membership claims are marked for deletion, not merely followed by another contradictory paragraph.
3. **Ownership check** — foreground proxy, daemon TUN proxy and per-link Fabric proxy transport remain separate runtime rows.
4. **Evidence check** — scenario existence or commit-message test claims are not upgraded to `Verified`.
5. **Absence check** — negative composition claims are phrased as “not found / not wired in inspected path” unless the source contract explicitly states postposition.
6. **Platform check** — Linux/Windows capability asymmetry is retained; Windows is not called a skeleton, while macOS/Android/iOS remain source-level skeletons from the prior audit.
7. **Drift check** — stale comments/help text are recorded as drift, not used as current capability evidence.
8. **Line-anchor check** — each correction in this review has a commit-pinned `path#Lx-Ly` source anchor.

## 9. Merge gate

The canonical `CURRENT_STATE.md` should only be regenerated after applying the following mandatory edits:

- baseline revision -> `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573`;
- explicit workspace member count -> **51**;
- remove all current-state claims that `nexus-workspace-intel` is absent from root workspace membership;
- add Harness bounded-parallel scenario execution as an engineering-runtime fact, without inferring `Verified` from the commit message;
- preserve the corrected three-way proxy ownership model;
- preserve Scheduler as manually ticked and not task-executing;
- preserve N3 help text as stale relative to executable code;
- attach code-line anchors to every major capability/ownership statement in the regenerated document.

This review is a gate, not another architecture appendix. Once the canonical document is regenerated, contradictory staging appendices should be retained only as audit history or deleted from the final baseline branch.
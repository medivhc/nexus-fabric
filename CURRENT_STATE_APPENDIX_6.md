# Nexus Fabric Current State — Deep Audit Continuation VI

> Continues `CURRENT_STATE_APPENDIX_5.md` after section 105.
> Source baseline: `48918863e70ef8589fbca6075c7ec11ca07e85a3` on `master`.
> This file remains staging material for the canonical `CURRENT_STATE.md`; findings here are source-derived current-state facts, not target-architecture decisions.

## 106. Several architecture-named crates are still materially different in implementation depth

A crate name, architecture-policy entry, or module-level description is not sufficient evidence that the named abstraction exists as executable code. Three small crates make this especially clear.

### 106.1 `nexus-delivery` is currently a named architectural slot, not an implemented shared delivery model

`crates/nexus-delivery/src/lib.rs` contains only crate documentation and `#![forbid(unsafe_code)]`. The comment says the crate defines common Link/Path/Connection, Delivery Request and binding abstractions, but the executable source defines none of those types.

Therefore, at the audited revision:

- the architectural concept of a shared Delivery layer is **Contract/architecture intent**;
- the `nexus-delivery` crate itself is **Skeleton-only**;
- concrete delivery/path/connection machinery is implemented elsewhere (`nexus-path`, `nexus-fabric`, NAT wire-up, projection, daemon composition, domain-specific adapters);
- no current-state statement should imply those mechanisms already converge through one implemented `nexus-delivery` API.

This also explains why `apps/nexusd/src/sync_transport.rs` explicitly says `nexus-delivery` is still a stub and treats eventual Delivery integration as a migration point rather than a current dependency path.

### 106.2 `nexus-diagnostics` is also a placeholder crate

`crates/nexus-diagnostics/src/lib.rs` likewise contains only crate documentation and `#![forbid(unsafe_code)]`. The comment claims unified diagnostic DTO/category/lightweight/deep diagnostic interfaces, but none are defined in executable source.

Current status is therefore **Skeleton-only**. Any diagnostics behavior exposed by `nexus`, `nexusd`, Harness, or control DTOs must be attributed to those concrete implementations; it must not be credited to `nexus-diagnostics` merely because the crate exists and is listed in the workspace/policy.

### 106.3 `nexus-service` is small but real, and its negative capability is explicit

`nexus-service` is not a placeholder. It defines:

- `ServicePhase::{Connecting, Active, Closed}`;
- typed `ServiceError`;
- an injected `ServiceTransport` frame interface;
- `ServiceSession::connect`, which sends literal `CONNECT`, waits for literal `READY`, and then returns an `Active` session.

However, the source explicitly freezes only connect semantics and says **connect != forward; forward is postponed**.

So the precise status is:

- service handshake semantics: **Implemented**;
- transport abstraction/injection: **Implemented**;
- full service byte forwarding owned by `nexus-service`: **Not implemented in this crate**;
- system-level session ownership: intentionally remains in `nexus-session`, not duplicated here.

This negative capability matters because the module header's first sentence says “connect/forward”, while the executable body deliberately stops at connect.

## 107. `nexus-scheduler` is a complete portable scheduling state machine, but not an execution runtime

`nexus-scheduler` is substantially implemented and should not be grouped with skeleton crates.

Its current model includes:

- one-shot `At { timestamp_secs }` schedules;
- periodic `Every { interval_secs }` schedules;
- structured `TaskIntent { resource, command, project }`;
- registration, cancellation, listing and lookup;
- deterministic `tick(now_secs, submit)` processing;
- explicit retry-on-submit-failure semantics;
- `SchedulerSnapshot` snapshot/restore support.

A successful one-shot trigger becomes `Fired`; a successful periodic trigger advances `next_run_secs`; failed submit leaves the entry `Scheduled` with the same due time so a later tick retries it.

The key ownership boundary is equally explicit: the crate does **not** execute tasks, read wall clock, run a background loop, persist files, or choose an executor. Trigger execution is an injected `SubmitFn` owned by a composition root.

Therefore the scheduler should be classified as:

- scheduling model/state machine: **Implemented**;
- persistence representation: **Implemented**;
- runtime clock/tick loop: **caller-owned**;
- task execution/submission adapter: **caller-owned**;
- normal `nexusd` production scheduling composition: **not yet established by this audit**.

Presence of PRODUCT references and unit tests does not by itself prove a long-running scheduler is started by the daemon.

## 108. `nexus-measurement` cleanly preserves Measurement != Score and is intentionally zero-I/O

`nexus-measurement` is a compact but important portable-core implementation.

`LinkMeasurement` carries objective facts only:

- RTT;
- loss permyriad;
- jitter;
- throughput;
- confidence percentage.

Unknown values remain `None`; they are not replaced with optimistic defaults. `rtt_sort_key` explicitly sends unknown RTT to the end by using `u64::MAX`.

`MeasurementTable` is a deterministic in-memory Provider-indexed fact table with overwrite-by-provider semantics.

The later `LatencyProbe` trait is only a contract for composition-root I/O. The crate itself remains zero-I/O and does not perform HTTP, socket, ICMP, STUN, or other probing.

This reinforces an architectural invariant already used by the Planner audit:

> Measurement is an observed fact. Score and provider selection are separate Planner concerns.

Any statement that Nexus “measures live RTT/loss” must therefore identify the concrete probe implementation/composition path; `nexus-measurement` alone does not create live measurements.

## 109. N3 now has an explicit Linux operator path for scoped N2 Use grants

`apps/nexus/src/task_provider_grant.rs` and its Linux implementation add a concrete operator surface that belongs in the N3 current-state model.

The command family is:

`nexus task-provider grant list|add|revoke --config <absolute-config> ...`

Its role is deliberately narrow: **explicit local operator access to the existing scoped N2 Use grant table**. The source explicitly excludes daemon RPC, identity provisioning, name resolution and Task ownership.

### 109.1 Command contract

The generic parser enforces:

- `--config` is required;
- config must be absolute and may not contain `..`;
- mutation requires `--resource` plus exactly one of `--self` or `--principal`;
- explicit principals use the frozen `ed25519:` + 32 lowercase-hex-character grammar;
- `--not-after` is accepted only for add and must stay inside the exact integer bound;
- non-Linux builds return structured `UnsupportedCapability` for the operator grant action.

Business failures are rendered as structured task errors with a phase and `mutation_may_have_applied` flag, while CLI syntax errors return exit 2.

### 109.2 Linux authority and mutation path

The Linux implementation treats `task-api.toml` as a fixed local scope authority and requires it to contain exactly `provider` and `workspace` fields. It snapshots and repeatedly re-checks the configured scope around mutations.

Mutation also requires an already-existing N2 auth identity; it derives the actor principal from those identity bytes rather than silently provisioning a new identity.

The command only creates/revokes canonical N2 `Use` grants. If an existing record contains `Manage` or a noncanonical operation set, the operator path refuses to replace/revoke it.

The write protocol is stronger than a simple file overwrite:

1. acquire a dedicated lease;
2. verify config/scope/identity authority;
3. read and validate the existing scoped grant;
4. create an audit mutation record;
5. append audit intent;
6. re-check authority and previous grant state;
7. atomically publish the grant;
8. re-check authority;
9. append audit applied record.

Failure reporting distinguishes whether a mutation may already have applied after the publication boundary.

### 109.3 Listing is scope-aware and bounded

Listing scans the N2 grant store but determines Workspace scope from the encoded filename before opening unrelated records. The code explicitly protects Workspace IDs containing `/` by right-splitting the final `%2F` separators instead of using a naive prefix match.

It caps a scoped listing at 4096 records and the response at 2 MiB.

### 109.4 What this does not prove

This command materially closes a local operator-management gap for N3 provider access, but it does not make N3 a complete remote administration/control plane. It is local CLI authority over existing N2 grant records.

It also does not change the broader current-state distinction between:

- N3 task submit/runtime/artifact protocols;
- N2 identity/grant authority;
- daemon LocalAPI;
- local operator CLI.

Those remain separate ownership domains.

## 110. `nexus-workspace-intel` is real source code but is not a root Cargo workspace member

A repository-level contradiction is now confirmed rather than inferred.

The `crates/` directory contains `nexus-workspace-intel`; it has a normal `Cargo.toml` and a substantive `src/lib.rs` exporting:

- access traces;
- Workspace graph;
- working-set estimator;
- profile/store state;
- prefetch scheduler/budget/plan;
- conversion to delivery snapshots.

Its own source clearly describes it as a non-authoritative, deletable/rebuildable Workspace intelligence layer.

However, the root `Cargo.toml`'s explicit 50-member workspace list does **not** include `crates/nexus-workspace-intel`.

At the same time, `policies/architecture.toml` contains an explicit `[[crate]]` entry for `nexus-workspace-intel`, including allowed internal dependencies and layer classification.

So three repository views disagree:

1. physical source tree: crate exists;
2. architecture policy: crate is governed as an internal domain-runtime crate;
3. Cargo workspace: crate is not a member.

This is a concrete repository-governance drift, not just stale prose.

Consequences of the omission include at least:

- root workspace-wide Cargo commands do not automatically build/test this crate as a workspace member;
- workspace-wide lint/test success cannot be assumed to cover it;
- architecture-policy presence does not compensate for Cargo exclusion;
- any claim that “the repository has 50 workspace members and all internal crates are represented” is false: there are 50 declared members plus at least this physical internal crate outside the member list.

The canonical baseline should retain both facts: **50 explicit Cargo members** and **an additional source crate `nexus-workspace-intel` outside that list**.

## 111. Mobile platform adapter source is far thinner than its crate descriptions imply

The source tree provides a particularly sharp platform-parity example.

### 111.1 Android

`nexus-platform-android/src/lib.rs` says the adapter includes VPN Service, underlay bypass, mobile lifecycle and file-access bridge functionality.

But the entire `src/` directory contains only that ~233-byte `lib.rs`, and the file defines no modules, types, functions or FFI bindings.

At this revision, the Android crate is therefore **documentation/skeleton only** at executable-source level.

It must not be described as an implemented Android VPN adapter merely because its crate description names those capabilities.

### 111.2 iOS

The iOS situation is the same pattern. `nexus-platform-ios/src/lib.rs` says it includes Packet Tunnel Extension, mobile lifecycle, file projection and secure-store bridge behavior, but the entire `src/` directory contains only that ~234-byte documentation-only `lib.rs`.

At executable-source level, the iOS platform adapter is also **documentation/skeleton only**.

This materially strengthens the earlier platform-parity conclusion: mobile parity is not merely “less mature than Linux”; the platform crates themselves currently contain no implementation body for the advertised native capabilities.

## 112. Windows is qualitatively different from the mobile placeholders

`nexus-platform-windows/src/lib.rs` exports actual implementation modules:

- `autostart`;
- `dpapi`;
- `netcfg`;
- `secure_store`;
- `vpi`;
- `wininet_proxy`;
- `wintun`.

It also re-exports concrete adapter types such as `TaskSchedulerAutostart`, `DpapiSecureStore`, `WintunVpiAdapter` and `WinInetSystemProxy`.

The Windows source therefore belongs in a different maturity class from Android/iOS. It has real platform implementation surface, including the explicitly isolated Wintun unsafe/FFI boundary.

This does **not** by itself prove every Windows capability is wired into all product roots, but it does prove that “all non-Linux platform crates are stubs” would be inaccurate.

The more precise platform statement is now:

- Linux: broadest product/runtime integration, including TUN/FUSE/N3 execution paths;
- Windows: significant adapter implementation exists, product wiring must be assessed capability-by-capability;
- macOS: current root source inspected so far is documentation-only and requires directory-level confirmation;
- Android/iOS: source directories confirmed documentation-only at this revision.

## 113. Repository truth must distinguish membership, policy registration, implementation and product wiring

The `nexus-workspace-intel` and platform findings expose another dimension that the earlier four-level feature model does not cover.

For a repository component, at least the following questions are independent:

1. **Physically present** — source directory exists.
2. **Cargo-member** — root workspace includes it.
3. **Policy-registered** — architecture/dependency governance knows about it.
4. **Implemented** — executable source contains the claimed mechanism.
5. **Scenario-targeted** — scenario contract exercises it.
6. **Product-wired** — a real composition root constructs/starts it.
7. **Revision-bound Verified** — evidence bound to the audited revision proves the route.

Examples at the current revision:

| Component | Present | Cargo member | Policy | Implemented | Product-wired conclusion |
|---|---:|---:|---:|---:|---|
| `nexus-delivery` | yes | yes | yes | no meaningful body | no shared Delivery runtime |
| `nexus-diagnostics` | yes | yes | yes | no meaningful body | cannot infer diagnostics runtime |
| `nexus-service` | yes | yes | yes | connect handshake yes | forwarding not owned here |
| `nexus-scheduler` | yes | yes | yes | state machine yes | daemon loop not yet established |
| `nexus-workspace-intel` | yes | **no** | yes | substantive source | product reachability unproven |
| Android platform crate | yes | yes | yes | documentation-only | no implemented Android adapter in crate |
| iOS platform crate | yes | yes | yes | documentation-only | no implemented iOS adapter in crate |
| Windows platform crate | yes | yes | yes | substantive modules | per-capability wiring still requires trace |

This table should guide the final canonical merge: repository inventory and implementation maturity must not be collapsed into a single “crate exists” column.

## 114. Updated remaining audit queue

After this continuation, the remaining high-value source sweep is narrower and more concrete.

### 114.1 Platform adapters

- confirm macOS `src/` directory contents rather than relying on the root file alone;
- inspect Windows adapter modules and identify which are used by actual product roots;
- inspect Linux platform exports systematically so the parity matrix names concrete capabilities rather than using a generic “Linux mature” label.

### 114.2 Proxy/ingress/outbound composition

The proxy family still deserves a full ownership map:

- `nexus-proxy-config` parse/validation and rule model;
- `nexus-ingress` role versus daemon TUN interception;
- `nexus-proxy` planner/policy ownership;
- `nexus-proxy-transport` concrete outbound adapters;
- which Shadowsocks/Trojan/VLESS/VMess/AnyTLS/Hysteria2 paths are actually constructible from production config.

### 114.3 Scheduler reachability

Search `apps/nexus`, `apps/nexusd` and LocalAPI/CLI code for concrete `Scheduler` construction, persisted snapshot ownership and a long-running tick loop. Until found, keep scheduler runtime composition **Unknown / not established**.

### 114.4 Workspace Intelligence reachability

Because `nexus-workspace-intel` is outside the Cargo workspace, determine whether anything invokes it through a separate Cargo manifest or external build path. If not, classify it as substantive but currently detached source.

### 114.5 N3 validation provenance

The source-level operator grant path is now captured. The next Evidence pass should separately record commit-level validation claims from the N3 implementation commits without upgrading them to current-baseline revision-bound verification.

### 114.6 Canonical merge work

Before finalizing `CURRENT_STATE.md`, corrections accumulated across appendices must be applied as replacements, not appended contradictions. In particular:

- `.evidence` is gitignored/local, not a checked-in authoritative current evidence set;
- Harness may depend on selected product crates;
- `VpiPump` remains product-reachable through foreground `network up`;
- Android/iOS advertised platform capabilities are not implemented in their current source crates;
- `nexus-workspace-intel` exists physically and in policy but is absent from the root 50-member Cargo workspace;
- `nexus-delivery` and `nexus-diagnostics` are named architecture slots with effectively empty executable bodies;
- Service connect exists, Service forwarding does not exist in `nexus-service`;
- scenario `E4` metadata means target strength, not automatically current revision-bound PASS evidence.

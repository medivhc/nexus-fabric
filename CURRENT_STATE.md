# Nexus Fabric Current State Baseline

> Baseline revision: `48918863e70ef8589fbca6075c7ec11ca07e85a3`
> Date: 2026-10-09
> Status: current-state baseline; descriptive, not target architecture.

## 1. Purpose and evidence rules

This document records what the repository currently is. It deliberately separates implemented behavior, machine-enforced engineering contracts, documentary claims, partial wiring, and unresolved drift. It must not be read as a target-state design.

Evidence precedence for this baseline:
1. executable code and current workspace/dependency structure;
2. machine-readable policy, harness configuration, tests and scenarios;
3. normative repository contracts such as AGENTS.md / MODULE.md;
4. comments and historical design documents only as supporting or drift evidence.

Presence of a crate, API, test, scenario, or a word such as “frozen” does not by itself prove end-to-end capability.

## 2. Repository shape

The Rust workspace is a multi-crate system rather than a single network library. The root workspace currently includes product applications (`nexus`, `nexusd`, platform host), domain/planning/session crates, connectivity/transport/network/fabric/NAT layers, proxy and DNS components, workspace/compute/storage domains, platform adapters for Linux/Windows/macOS/Android/iOS, diagnostics/protocol/plugin/projection/path components, and `engineering/nexus-harness`.

This establishes two simultaneously important systems:

- **Product/runtime system**: Nexus domain model, planning, sessions, connectivity, fabric, network/proxy/DNS, workspace/compute/storage, and platform composition.
- **Agent-native engineering system**: repository contracts, policies, scenarios, harness verification, Evidence, protected paths, review gates and recovery-oriented workflow.

The second system is not merely documentation: `AGENTS.md` defines the repository as an API for coding agents and explicitly denies implementation agents authority to self-certify Final PASS.

## 3. Current architectural invariants

The current repository contract explicitly distinguishes:

`Resource != Provider`; `Provider != Node`; `Identity != Locator`; `Plan != Session`; `Measurement != Score`; `Policy != Path`; `Planner != Estimator`; `Planner != Scheduler`; `TerminalOutcome != LifecyclePhase`; `Portable Core != Platform Runtime`.

The prescribed high-level execution order is:

Resolve Candidate Providers → Plan Placement + Path → Create Session → Establish Connectivity → Execute.

The repository contract states that there is one system-level Core Planner. Domain-local estimators/evaluators/schedulers may exist, but they must not create a second system-level Plan.

## 4. Session semantics

The session implementation materially reflects the repository contract that lifecycle and business outcome are separate dimensions. Lifecycle can continue through cleanup after a terminal outcome has been committed.

The owner state machine is the terminal-outcome writer. A terminal outcome is commit-once; worker-side activity is represented as events rather than independent terminal-state mutation. Cancellation requests likewise do not directly commit `Cancelled`.

This is stronger evidence than a design-only statement because the current implementation contains transition validation, outcome commit guards and post-terminal event gating.

## 5. Fabric data plane

`nexus-fabric` currently implements a QUIC-like peer connection layer using `quinn-proto` sans-I/O with its own std-thread driver. The public model is `FabricConn`, intentionally distinct from `nexus-session::Session`.

Implemented surface visible at the baseline revision includes:

- peer identity and logical connection identity decoupled from UDP five-tuple;
- reliable bidirectional streams;
- unreliable datagrams;
- TLS 1.3 based encryption and peer-key mechanisms;
- mTLS connection path;
- caller-provided UDP transport for relayed paths;
- active UDP rebind / migration support;
- sequenced datagram helper semantics;
- driver-level exports used by NAT punch-through wiring.

Important limitation: the ordinary connect path currently selects `config.addrs[0]`; the source itself labels candidate racing as not yet implemented there. Therefore multiple candidate addresses in the API must not be interpreted as proof of production-grade path racing.

## 6. Daemon composition and runtime truth

`nexusd` is the composition root and daemon process. Its source explicitly warns against equating configured subsystems with running subsystems.

At this baseline revision the daemon contains materially implemented runtime wiring beyond simple configuration loading:

- config-directory loading and validation;
- hot-reload infrastructure and LocalAPI;
- boot reconciliation before accepting new work;
- a daemon-owned N2 SessionManager with durable/reconciliation semantics and detached-session sweeping;
- a unified TUN/dataplane path;
- optional N1 sender injection;
- optional proxy forwarding engine injection;
- structured degraded behavior when optional subsystem assembly fails;
- workspace-related Linux integration paths;
- shutdown ownership and worker joining paths.

However, runtime completeness must be assessed per subsystem and scenario. The file-level “honest boundary” still warns that mesh/proxy/DNS long-running composition is not uniformly complete. Later code in the same file contains concrete N1/proxy/dataplane wiring, which means the header comment itself is partly stale or over-broad. This is a concrete example of why comments are lower-grade evidence than executable wiring.

## 7. Agent-native engineering system

The repository currently treats agent execution as an engineered subsystem. `AGENTS.md` establishes:

- contract-first development for user-visible features and requirement changes;
- Red Evidence and Spec-Freeze before implementation;
- protected product/scenario/module-contract paths;
- Candidate Completion versus independently verified Final PASS;
- Evidence levels E0–E5, with critical user-visible capability normally requiring E4 or stronger;
- architecture/dependency/quality gates;
- independent review before full verification;
- structured context retrieval through `nexus-harness`;
- explicit recovery/evidence requirements intended to survive session or agent interruption.

The stable engineering entry points named by the repository include `nexus-harness status`, `context`, `check`, `test affected`, `verify --fast`, `verify --full`, and `explain`, with structured JSON preferred where available.

Therefore Nexus Fabric's current architecture cannot be described accurately only through product crates. The harness, policies, scenarios and Evidence workflow are part of the repository's operational architecture.

## 8. Portability and platform boundary

The current contract places platform-specific implementation behind platform crates and composition roots. Portable core code is not supposed to directly depend on Linux-only APIs, Win32, Android framework APIs, Apple NetworkExtension APIs, or platform mount/secure-store APIs.

The workspace currently contains platform crates for Linux, Windows, macOS, Android and iOS. Their existence proves intended and partially implemented separation; it does not prove feature parity across those operating systems.

## 9. Crash consistency and ownership model

The repository contract rejects graceful-shutdown-only reasoning. Persistent critical paths are expected to use durable state/journal-style mechanisms and perform reconciliation before accepting new work.

The daemon currently performs boot reconciliation and the N2 session path contains durable/reconciliation-oriented ownership. This provides implementation evidence for part of the crash-consistency model, but should not be generalized to every subsystem without subsystem-specific verification.

Long-lived concurrency is intended to be owned and cancellable. The contract prohibits fire-and-forget long-running tasks whose owner, cancellation path, reclamation path and result handling cannot be identified.

## 10. Capability-status vocabulary

Future audits of this baseline should classify capabilities using these terms:

- **Implemented** — executable behavior exists and is directly supported by code.
- **Wired** — implementation is connected to a product/runtime composition path.
- **Verified** — current-revision Evidence demonstrates behavior at the stated level.
- **Partial** — important path exists but a required branch, platform, fallback or end-to-end closure is absent.
- **Contract-only** — normative requirement exists without sufficient implementation evidence.
- **Document-only** — non-executable documentation claims the behavior.
- **Unknown** — evidence inspected so far is insufficient.

These labels must not be collapsed. In particular, “Implemented” does not imply “Verified”, and “Verified E2” does not imply product-level E4 closure.

## 11. Known drift and contradictions

### 11.1 nexusd header versus body

The daemon header states broadly that actual long-running mesh/proxy/DNS runtime assembly is future work, while the current body contains concrete N1 bridge, dataplane and proxy-engine wiring. The safe conclusion is not that either side is wholly correct; the comment is stale/over-broad and subsystem completeness must be determined from composition plus scenarios.

### 11.2 Contract versus implementation versus Evidence

The repository deliberately has three different notions that older documents often conflate:

1. desired/normative contract;
2. code implementation and wiring;
3. independently verified current-revision Evidence.

Any future architecture document that says a capability “exists” must state which of these it means.

### 11.3 Workspace membership is authoritative only at the captured revision

At this revision the root `Cargo.toml` contains a large explicit workspace member list. Earlier observations from older revisions must not be carried forward without re-checking the current root manifest and policy files.

## 12. What this baseline does not claim

This baseline does **not** claim:

- that the old architecture vision is still the desired target;
- that every workspace crate is production-ready;
- that all platforms have equivalent runtime coverage;
- that every N1/N2/N3 capability is end-to-end closed;
- that an API or scenario name proves runtime behavior;
- that the current architecture should be preserved.

Those questions belong in a separate `TARGET_STATE` and subsequent gap/migration analysis.

## 13. Next audit passes

This first committed baseline establishes the semantic frame and high-confidence runtime facts. The next passes should deepen it with evidence tables for:

1. every workspace crate: responsibility, inbound/outbound dependencies, public surface and runtime owner;
2. N1/N2/N3 capability matrix: Contract / Implemented / Wired / E0–E5 / gaps;
3. CLI → LocalAPI → daemon → planner/session/connectivity/fabric execution traces;
4. scenario inventory and current-revision Evidence mapping;
5. platform capability matrix;
6. configuration/hot-reload behavior and degraded modes;
7. persistence/recovery ownership by subsystem;
8. explicit drift register linking stale documents/comments to contradictory executable facts.

Until those passes are complete, this file is a reliable baseline skeleton plus verified high-confidence findings, not an exhaustive certification of the repository.


## 14. Workspace inventory and implementation map

At the captured revision the root Cargo workspace explicitly contains 49 members: three applications, forty-five product/library crates, and the engineering harness. This list is an executable repository fact, not a design-document inventory.

### 14.1 Applications

- `apps/nexus`: formal user-facing CLI / thin client.
- `apps/nexusd`: daemon composition root. It owns configuration-root startup, LocalAPI exposure and runtime assembly. Its file-level introductory comment is stale in at least one important respect: later executable code contains concrete N1/N2/runtime wiring that is stronger than the comment's “future work” wording.
- `apps/nexus-platform-host`: platform-host process boundary.

### 14.2 Core decision and lifecycle layer

- `nexus-domain`: shared domain vocabulary and cross-domain identifiers/contracts.
- `nexus-registry`: provider records and candidate facts consumed by planning.
- `nexus-policy`: policy/constraint production; it is not the Core Planner.
- `nexus-measurement`: measurement facts. Measurements remain facts rather than policy scores.
- `nexus-planner`: the sole system-level Core Planner. The implementation is portable and I/O-free. Its `PlanningSnapshot` freezes candidates, hard constraints, optional per-provider connectivity evaluation and optional local-provider preference. Filtering happens before scoring. Connectivity evaluation can reject a provider with no feasible path. Scoring is deterministic integer arithmetic; the currently visible components are normalized RTT plus a locality bonus, and the breakdown is recorded in `DecisionTrace`.
- `nexus-scheduler`: scheduling concern remains distinct from planner by repository invariant.
- `nexus-session`: portable owner state machine for execution lifecycle. `SessionOwner` is the sole committer of `TerminalOutcome`; workers report `SessionEvent` rather than committing outcomes directly. Cancellation is cooperative through `CancelToken`; `AbortOnDropHandle` converts owner loss into cancellation request. Lifecycle phase and terminal outcome remain separate tracks, so cleanup/disposal can continue after an outcome has been committed.

### 14.3 Connectivity, path and transport layer

The workspace contains `nexus-connectivity`, `nexus-path`, `nexus-transport`, `nexus-fabric`, `nexus-turn`, `nexus-nat-traversal`, `nexus-nat-wireup` and `nexus-nat-quality`. These names do not by themselves prove end-to-end closure; runtime claims must be tied to assembly/scenario evidence.

`nexus-network` exposes N1 assembly through its `n1` module and deliberately consumes injected traits for fabric/path/discovery/platform rather than creating new architecture dependencies. Its simpler `NetworkSession` contract models Connecting → Active → Closed and only becomes Active after a request/response round trip yields a valid three-digit HTTP status.

### 14.4 Proxy and DNS layer

The workspace contains `nexus-ingress`, `nexus-proxy-config`, `nexus-proxy`, `nexus-proxy-transport`, `nexus-dns` and protocol-specific outbound crates for Shadowsocks, VMess, Trojan, AnyTLS, VLESS and Hysteria2.

The `nexus-proxy` implementation describes an explicit local pipeline:

SOCKS5 ingress → `FlowContext` → ordered `RuleEngine` → rule-action chain → `GroupRegistry` → injected `nexus-connectivity::LinkActivator`.

This is intentionally not a second Core Planner. Proxy rule selection is domain-local; urltest consumes injected measurements and does not perform live probing inside the rule engine.

### 14.5 Workspace, compute and storage layer

The workspace contains `nexus-workspace`, `nexus-compute` and `nexus-storage`.

`nexus-storage` implements a portable content-addressed store contract. Equal bytes deterministically map to equal `ObjectId` values. The current portable implementation includes protected roots and reachability-GC semantics; deletion is constrained to the GC path rather than exposed as an unrestricted product operation.

`nexus-workspace` contains immutable commit/DAG semantics and deterministic conflict identity. A `HeadSet` may contain more than one head during offline divergence; conflict identity normalizes local/remote ordering so the two endpoints can derive the same conflict id.

`nexus-compute` now contains both the older request/response job-session surface and newer N3 task-oriented modules: `task`, `task_artifact`, `task_requester`, and `task_runtime`. The task comments explicitly distinguish provider-owned durable acceptance from legacy job sessions. Therefore “compute exists” is too coarse a status: legacy session flow and durable N3 task semantics must be audited separately.

### 14.6 Platform layer

The root workspace explicitly includes the platform abstraction plus Linux, Windows, macOS, Android and iOS crates. Workspace membership proves source/build participation only; it does not prove equivalent runtime capability. Per-platform closure remains a separate evidence matrix.

### 14.7 Engineering layer

`engineering/nexus-harness` is a workspace member; `engineering/evidence-schema`, plugins and verifiers are repository engineering assets around it. This reinforces the earlier conclusion that the repository contains both a product runtime and an agent-native verification/governance runtime.

## 15. Concrete execution semantics verified from source

### 15.1 Planner execution model

The planner is not an abstract future interface. Source defines a concrete two-stage solver. `PlanningSnapshot` is frozen for one planning cycle; hard predicates reject candidates before score; optional connectivity evaluation gates infeasible candidates; scoring uses deterministic integer arithmetic; locality is a preference bonus rather than an absolute override; and `DecisionTrace` captures considered candidates, rejection reasons and score components. The planner performs no network I/O.

This gives a precise current-state boundary:

measurement/discovery/connectivity facts → frozen planning snapshot → Filter → connectivity feasibility gate → Score → Plan + DecisionTrace.

Estimation may feed typed plan-extension facts into planning, but an estimator is not allowed to emit a competing system-level Plan.

### 15.2 Session ownership model

`nexus-session` is also executable semantics rather than merely vocabulary. Workers emit structured events; `SessionOwner` owns phase and terminal outcome; `commit_outcome` is the commit-once authority. Cooperative cancellation and abort-on-owner-loss are explicit primitives. A terminal outcome does not imply immediate disposal, because lifecycle cleanup remains independently representable.

### 15.3 Network session semantics

The simple InternetAccess `NetworkSession::establish` sends a request through an injected `NetworkTransport`, receives one frame, parses the HTTP status from the first line, and only then transitions to Active. Transport failure, closed channel and invalid/unauthorized response are distinct errors. This is a useful narrow executable contract, but must not be mistaken for proof that the complete N1 product path is closed.

### 15.4 Compute session semantics

The legacy `ComputeJobSession::submit` similarly performs an explicit frame round trip. `OK:<result>` activates the session and records the result; `REJECTED` is a provider rejection; other response shapes are protocol errors. The session can then transition Active → Closed while retaining the result. New N3 durable-task modules coexist with this legacy surface and require separate status reporting.

## 16. Daemon ownership and current runtime facts

The daemon source now proves more runtime ownership than its introductory “honest boundary” comment claims.

A particularly concrete N2 example is `N2_SESSION_MANAGER`: it is a process-global `OnceLock` containing the daemon-owned shared session manager and its config root. The source comment records that an earlier implementation assembled and immediately dropped the manager, while the current implementation retains it. LocalAPI N2 session list/attach reads use this manager.

The daemon also owns a periodic N2 detached-session sweeper. It wakes on a fixed interval, exits cooperatively on daemon shutdown, calls `sweep_detached` through the retained manager, and converges sessions outside the attach window to a cancelled outcome rather than silently treating disconnect as failure.

Assembly failure is intentionally degraded rather than fatal: the daemon can continue while N2 integration exposes a structured failure path. The singleton also binds itself to one canonicalized config root; attempts to reuse it for a different root are refused rather than silently cross-wiring state.

These facts mean the file-level comment saying the daemon merely reports configured/unconfigured state must be classified as stale documentary evidence wherever it conflicts with later executable assembly.

## 17. Expanded drift register

### 17.1 nexusd header versus executable body

**Documentary claim:** the file header says mesh/proxy/dns long-lived runtime assembly is future work and status only reports configuration.

**Executable evidence:** the same current source contains retained daemon-owned N2 session state, LocalAPI integration, a background detached-session sweeper, degraded assembly behavior, and additional N1/runtime assembly code beyond that introductory statement.

**Baseline treatment:** executable code wins. The header is retained as evidence of historical intent/drift, not as authoritative current-state truth.

### 17.2 “crate exists” versus “capability closed”

The workspace has broad coverage—NAT traversal, TURN, proxy protocols, five platform crates, workspace, compute and storage—but membership is only evidence that the component participates in the Rust workspace. Every product-level claim still needs wiring and scenario/evidence status.

### 17.3 Compute has two semantic generations

The coexistence of `ComputeJobSession` and provider-owned durable N3 task modules means a single “Compute: implemented” label would erase an important migration boundary. Subsequent capability tables must split legacy remote-job round-trip semantics from N3 durable task acceptance/runtime/artifact/requester semantics.

## 18. Remaining exhaustive audit work

This pass materially expands the baseline from architecture skeleton into source-level implementation facts, but it is not yet the requested exhaustive repository certification. Remaining work is intentionally explicit:

1. enumerate every one of the 49 workspace members with public surface, allowed dependencies, runtime owner and status;
2. trace N1 end-to-end from CLI/LocalAPI through daemon assembly, planning/connectivity/path/fabric and failure/degraded paths;
3. trace N2 workspace/session operations including persistence, attach/re-attach, conflict and recovery;
4. trace N3 durable task acceptance, execution replay, artifacts, cancellation and write-back;
5. inventory all scenario files and map each capability to E0–E5 evidence at this exact revision;
6. build the Linux/Windows/macOS/Android/iOS capability matrix from executable platform code;
7. audit configuration load, validation, hot reload, rollback/rejection and subsystem restart semantics;
8. audit proxy/DNS/TUN composition and each outbound protocol's real wiring;
9. audit NAT traversal/TURN/path selection and roaming/rebind ownership;
10. audit shutdown ordering, task/thread ownership, persistence/recovery and crash-consistency boundaries.

The baseline should not be called exhaustive until these ten passes are represented with source-backed tables or traces.


## 19. Portable control, registry, policy, authorization and DNS facts

### 19.1 Domain and control API

`nexus-domain` is intentionally dependency-free inside Nexus and is the stable vocabulary layer. Beyond Resource/Provider/Session identifiers, the current contract includes typed Plan extensions for Network, Workspace, Compute and Service, structured `NexusError` and failure disposition, connectivity-evaluation DTOs, N2 resource addressing/authorization vocabulary, decision-trace DTOs, deterministic `PlanId`, and `PlanSnapshot`. N3 Task/Snapshot/Artifact DTOs are separated under the `task` module rather than being folded into the stable Core Plan.

`nexus-control-api` is the front-end contract layer for CLI/GUI/Agent/SDK. Current `ControlCommand` includes status, plan explain, session watch, connectivity status/candidates/probe/links, DNS status/resolve/providers/cache, workspace heads/conflicts/cache/commit, compute jobs, diagnose, platform capabilities and run. The module contract still labels the N3 Application Service operation set as “待实现”; therefore N3 control-plane completeness must be judged from actual LocalAPI/daemon code and scenarios, not inferred from the desired API list in this contract.

### 19.2 Registry and N2 control frames

`nexus-registry` stores facts and advertisements, not scores. `ProviderRecord` keeps identity, resource, placement, locator, capabilities and presence as separate fields. N2 additions include provider advertisements with discoverability/use grants/unavailability/expiry semantics, local human-name mapping, static-provider import, and five explicit control-frame kinds: RESOURCE_ANNOUNCE, RESOURCE_QUERY, AUTH_GRANT, AUTH_REVOKE and LEASE_RENEW.

The N2 control channel requires an already authenticated peer; registry does not invent a second authentication path. Human-readable names are not used as addressing keys on ResourceQuery. Grant announcements have a documented exception because they represent provider-side authorization state rather than requester addressing.

### 19.3 Policy

`nexus-policy` is a deterministic ordered action pipeline. It transforms flow/resource context into Intent + Constraint and explicitly does not choose transport/path/final provider. Rules are evaluated in order; non-terminal actions can add constraints or metadata, while SelectProvider and Reject terminate evaluation. This is a domain policy layer, not a competing planner.

### 19.4 Authorization

`nexus-auth` currently contains two deliberately separated generations/usages. The PSK `verify_token` path remains for frozen N1 remote-host scenarios. N2 authorization explicitly rejects PSK as its identity model: `Principal` is derived from a handshake-verified ed25519 public key; provider-side `GrantTable` authorizes resource operations and emits exactly-once audit records. TOFU for N2 is explicit: unknown identity is surfaced as `UnknownFirstSeen` and must be confirmed before trust is persisted.

### 19.5 DNS

`nexus-dns` is a portable DNS decision/cache layer rather than a real UDP/DoT/DoH transport implementation. The current runtime includes injected Resolver, TTL cache, negative cache, loop guard, IP-family preference, Exit-DNS Binding and multi-server routing. The unified module additionally exposes mesh/fake-IP/classification vocabulary. Real DNS transport remains outside this portable runtime and must be provided by composition.

## 20. Fabric, TURN and NAT traversal implementation

### 20.1 Fabric connection semantics

`nexus-fabric` is a synchronous QUIC-like session layer built around sans-I/O quinn-proto with std threads rather than Tokio. Its product connection identity is `(PeerId, ConnectionId)`, intentionally independent of the UDP 5-tuple. It exposes reliable bidirectional streams, unreliable datagrams, TLS 1.3 end-to-end encryption, connection statistics and roaming/rebind behavior.

Important current invariants include: relay nodes must not decrypt Fabric payloads; datagrams are best effort and initially capped at 1200 bytes; path migration requires challenge/response validation; closed connections are removed from driver connection tables; connect uses one handshake timeout budget across command dispatch and handshake completion; and `FabricConn` must not be confused with `nexus-session::Session`.

Transport is dependency-inverted through `UdpTransport`. Default std UDP remains available, while external transports such as TURN can implement the trait without Fabric depending back on them.

### 20.2 TURN

`nexus-turn` implements the RFC 5766 subset needed for relay fallback: Allocate, Refresh, CreatePermission, ChannelBind, ChannelData and Send indication with long-term authentication. `TurnSocket` implements Fabric's `UdpTransport`, so encrypted Fabric traffic can run over TURN. TURN is a relay mechanism, not the path selector.

Allocation lifetime is explicit; expired allocation produces an error rather than a silent black hole. The client has no hidden refresh thread: callers must explicitly refresh. The included minimal server is primarily an E4/self-test facility, not evidence of a production public TURN deployment.

### 20.3 NAT production wire-up

`nexus-nat-wireup` connects portable punching orchestration to the real Fabric driver. `FabricPunchChannel` carries signaling over an existing relay connection; `DriverPunchSocket` fans out direct QUIC connection attempts from the punch driver; `PunchManager` owns responder, deduplication, tie-break and direct-connection registration.

A `Migrated` result means a direct QUIC handshake actually completed, not merely that punch packets were sent. The relay is deliberately retained as warm backup after migration. Tie-break is deterministic from PeerId. Candidate adoption is nonce-bound to prevent accepting the wrong concurrent connection. The relay stream acceptor is single-owner: once wireup registers a relay, its responder loop owns `accept_bi`; non-punch streams are stashed in an unclaimed queue for the session layer. The contract explicitly notes that nexusd does not yet consume that unclaimed queue, which is a concrete remaining wiring gap.

### 20.4 NAT quality

`nexus-nat-quality` continuously measures candidate Fabric paths. It combines Fabric RTT with an active datagram ping/pong loss probe and feeds `PathStats` into `PathManager`. This exists specifically because direct-path success alone is not sufficient to conclude that direct is the best path.

The quality monitor has bounded thread ownership: one responder per measured connection plus one monitor thread, all stopped and joined by `QualityMonitor::shutdown`. Active and backup probe rates differ, and non-probe datagrams must not be silently consumed.

## 21. Platform implementation matrix

| Platform | Current evidence | Baseline status |
|---|---|---|
| Portable platform contract | Capability traits for packet interface, interception, projection, secure store, lifecycle/clock/random/attribution; ProjectedWorkspace; secure-store crypto core | Implemented contract/core |
| Linux | TUN/host adapter responsibility, transactional OS assembly contract, FUSE ProjectedWorkspace adapter, explicit rollback/dry-run/idempotence/SSH-protection semantics | Concrete implementation exists; individual capabilities still require scenario evidence |
| Windows | Wintun dynamic adapter, WinINET system proxy, scheduled-task autostart, explicit narrow unsafe FFI boundary and lifecycle order | Concrete implementation exists; capability-by-capability evidence required |
| macOS | MODULE contract states managed network/filesystem projection responsibility but currently exposes mostly generic skeleton language in the inspected contract | Contract/skeleton; do not claim parity |
| Android | MODULE contract defines VPN Service, underlay bypass, lifecycle/file bridge and recursion-avoidance invariant, but inspected contract remains skeleton-level | Contract/skeleton; do not claim parity |
| iOS | MODULE contract defines Packet Tunnel Extension, mobile lifecycle, projection/secure-store bridge and kill-tolerant correctness, but inspected contract remains skeleton-level | Contract/skeleton; do not claim parity |

The important current-state conclusion is asymmetric platform maturity. The repository is cross-platform in structure and contract, but the inspected evidence does not justify saying the five OS adapters are equally implemented.

## 22. Scenario surface and what it proves

The scenario tree is substantial and divided into product, platform, engineering and regression families. Product scenarios cover far more than the original architecture skeleton: N1 connectivity and roaming, Fabric/TURN/NAT, proxy protocols and groups, DNS, routing/failover/multipath, daemon real-host flows, workspace sync/conflict/cache/GC, N2 resource/session operations, N3 durable task behavior, crash recovery, QoS and observability. Platform scenarios cover OS assembly, virtual packet interface, Windows routing/process attribution/system proxy and workspace projection. Regression scenarios explicitly include crash recovery and exactly-once session outcome.

However, **scenario presence is not equivalent to a passing evidence level at this captured revision**. A scenario file proves that a behavior has a machine-readable verification target. Only a recorded run/evidence artifact can prove E-level closure. This baseline therefore records scenario coverage separately from verified status.

Notable scenario families visible in the current tree include:

- N1: `n1_wireup`, `n1_connectivity_roam`, `n1_connectivity_roam_realnet`, daemon real-host/relay/TUN/SOCKS flows;
- Fabric/NAT: basic/roam/rebind, TURN relay, hole punching, relay fallback, virtual subnet encrypted/holepunch/mesh;
- N2: grant/deny audit, plan preview, provider offline, resource list/publish/revoke/show, session close/list/watch, use loop;
- N3: submit, idempotency, authorization, crash reconcile/acceptance crash, cancellation races, client reattach, snapshot/input/artifact integrity, artifact resume/missing, timeout/nonzero exit/environment mismatch, GC roots and LocalAPI boundary;
- Workspace: authority v2, offline merge, cache eviction, GC, shallow/sparse, sync authorization/basic/conflict convergence/resume/path-race;
- Proxy: Clash subscription/config/rules, selector/urltest/loadbalance/relay groups, SOCKS/HTTP/TUN ingress, Shadowsocks/Trojan/VMess and real TCP/TLS checks;
- DNS: exit binding, rule/server selection, IP-CIDR and unified DNS;
- Recovery/engineering: config hot reload, graceful exit, crash recovery, harness verdict/evidence scenarios.

## 23. Capability status rules for the final baseline

From this point forward the document uses the following strict interpretation:

- **Contract**: a MODULE/schema/policy says the capability should exist.
- **Implemented**: executable source contains the behavior.
- **Wired**: a composition root reaches and owns the behavior in a product process.
- **Scenario-targeted**: a machine-readable scenario exists.
- **Verified**: evidence from an actual run at the captured revision proves the relevant level.
- **Production-closed**: implementation, product wiring, failure/recovery semantics and required evidence all agree.

These states are intentionally non-monotonic across different slices. For example, NAT wireup can be implemented while one consumer handoff remains unwired; a platform contract can exist while its adapter remains skeletal; an N3 scenario can exist while a control-api MODULE still marks an API set as pending.

## 24. Newly confirmed drift and incomplete wiring

1. `nexusd` introductory runtime comment is stale relative to executable assembly.
2. `nexus-nat-wireup` explicitly exposes an unclaimed non-punch stream handoff that nexusd does not yet consume.
3. N3 control API desired operations are documented in `nexus-control-api/MODULE.md` as pending, while N3 implementation/scenario work exists elsewhere; control-plane completion must be traced through daemon LocalAPI rather than assumed.
4. Platform maturity is asymmetric: Linux/Windows contracts describe concrete adapters and side effects, whereas inspected macOS/Android/iOS contracts remain largely skeleton-level.
5. TURN client refresh is caller-owned; existence of TURN support does not imply automatic allocation maintenance in every runtime.
6. DNS portable runtime does not itself implement real DNS wire transports.
7. Scenario abundance must not be reported as evidence abundance until current-revision run artifacts are mapped.

## 25. Current audit completeness

The baseline now contains source-level facts for the domain/planner/session core, control/registry/policy/auth/DNS, network/proxy model, daemon N2 ownership, storage/workspace/compute semantics, Fabric/TURN/NAT and platform maturity, plus the scenario surface.

Still not exhaustively enumerated at symbol level are every outbound protocol adapter, every CLI/LocalAPI route, every workspace and N3 persistence file, every path/discovery/routing algorithm, every harness verifier and every scenario's latest evidence artifact. Those are narrower implementation inventories rather than unknown architectural regions; they remain required before calling this document a complete repository certification.


## 26. Path, discovery, delivery and flow-session boundaries

### 26.1 Path manager

`nexus-path` answers one question: which currently available path should carry packets to a peer. Candidate kinds are Direct, Mesh, TURN and Proxy. It consumes quality facts and applies scoring/hysteresis; it does not construct sockets, run TURN, perform NAT punching, or make user proxy-rule decisions.

P0 is explicitly single-active-path. “Multipath” scenario names elsewhere must therefore be interpreted carefully: the frozen PathManager contract says concurrent multipath forwarding is not the P0 steady-state model. Connection-establishment racing can select a winner without changing that invariant. Switching preserves the Fabric connection identity and relies on Fabric migration rather than creating a new application session.

The contract also records an important future boundary: predictive trend/history layers and preemptive migration are not current core behavior and ML is explicitly not part of this layer.

### 26.2 Discovery

`nexus-discovery` is distinct from connectivity establishment. It handles bootstrap, peer discovery, endpoint/candidate exchange and presence. Dynamic `PresenceRegistry` entries carry TTL; expired peers are rejected rather than returning stale endpoints. Network discovery is abstracted through an injected request/response `DiscoveryTransport`; the discovery domain itself does not own the connection establishment.

The architectural consequence is important: bootstrap/discovery is not supposed to become a permanent dependency of an already-established data session.

### 26.3 Delivery and transport

`nexus-delivery` is a deliberately domain-neutral shared delivery abstraction and must not depend back on workspace/compute/service.

`nexus-transport` currently has a concrete frozen remote-P0 TCP frame stream: TCP connection plus u32 big-endian length-prefixed frames, with `FrameStream::send_frame`, `recv_frame` and `into_raw`. This is not the same abstraction as Fabric QUIC and should not be collapsed with it in the baseline.

### 26.4 Flow-session mapping

`nexus-flow-session` is the nexusd TUN “flow → resource Session” layer. Its key is the complete five-tuple. A new flow constructs `FlowContext(origin=PacketCapture)`, evaluates Policy, invokes Core Planner and creates a `nexus-session::SessionOwner`. Connectivity establishment runs off the packet-processing path; an allocating entry is later promoted through event/channel feedback. Established-flow fast path reuses the bound session and must not re-run the planner per packet.

The contract explicitly distinguishes local TCP termination state from the higher-level resource Session. One resource Session can own a terminated TCP flow or UDP five-tuple; the transport state is subordinate to the resource Session lifecycle.

## 27. Projection and unified TUN routing

`nexus-projection` is no longer merely a thin TUN-to-Fabric tunnel. The current module contract records a unified routing role: packets can resolve to MeshPeer, Egress or Drop; local UDP egress NAT exists; cross-node egress, hop-loop prevention, domain rules and real UDP egress are marked completed. TCP egress via local termination + Fabric byte stream + remote TcpStream is explicitly marked in progress.

This is another place where coarse labels are dangerous: “projection implemented” is true for L3 tunnel/routing and substantial UDP egress behavior, but does not mean the TCP egress track is complete.

## 28. Outbound protocol reality

The outbound crates share the `nexus-connectivity::OutboundAdapter` seam, but they have materially different completeness levels and protocol goals.

- **Shadowsocks**: AEAD adapter with deterministic offline cipher behavior; its contract additionally defines a real-TCP session track. The original adapter alone must not be described as full Shadowsocks networking.
- **VMess**: explicitly **not wire-compatible full VMess**; current adapter is an AEAD record-layer implementation and does not initiate real network connections. This is a major scope caveat.
- **Trojan**: substantially more protocol-realistic: rustls TLS, official-style request header, password validation, certificate pinning and loopback session primitives. It still excludes UDP, WS/gRPC disguise and multiplexing.
- **AnyTLS**: implements AnyTLS v2 session framing, authentication/settings negotiation, stream commands, UDP-over-TCP framing and TLS loopback primitives. Padding scheme negotiation exists, while padding write-path behavior and session pooling/heartbeat remain outside current responsibility.
- **VLESS**: implements request/response headers, UUID/addon encoding, TCP/UDP/Mux command framing, lazy response read and XTLS-Vision framing/state machines. Full Mux scheduling, transport chains such as WS/gRPC/REALITY and post-quantum VLESS-Encryption are explicitly not implemented.
- **Hysteria2**: has its own sans-I/O QUIC driver directly on quinn-proto because Fabric's identity/TLS/config model is incompatible with Hysteria2 requirements. It includes H3-style authentication, TCP/UDP framing, DATAGRAM, Salamander obfuscation and a test server. It should therefore be treated as a separate protocol transport stack, not as “Hysteria2 over Nexus Fabric”.

This diversity is architecturally significant: `OutboundAdapter` is a common handoff seam, not proof that every outbound shares the same transport/runtime or production maturity.

## 29. Explicit protocol limitations that must survive future documentation

The baseline must preserve negative capability facts, because deleting them would recreate the original documentation-drift problem:

- VMess is not a full wire-compatible VMess implementation.
- VLESS does not implement full Mux.Cool, REALITY/WS/gRPC transport chains or VLESS post-quantum encryption.
- AnyTLS does not currently own padding write policy, pooling or heartbeat runtime.
- Trojan does not implement UDP or disguise transports.
- Hysteria2 deliberately bypasses Fabric's Driver and uses quinn-proto directly.
- Projection TCP egress is in progress.
- PathManager steady-state P0 is single-active-path.
- Discovery is not connectivity establishment.
- Transport TCP FrameStream and Fabric QUIC are separate delivery mechanisms.

## 30. Architecture map after source audit

A more faithful current execution map is now:

`Ingress/TUN/CLI/LocalAPI`
→ flow/resource context
→ `Policy` (intent + hard constraints)
→ Registry/Discovery/Measurement/Connectivity facts
→ **single Core Planner**
→ immutable Plan/DecisionTrace snapshot
→ SessionOwner
→ domain runtime (Network/Service/Workspace/Compute)
→ connectivity/path establishment
→ one of several delivery mechanisms (Fabric/FrameStream/protocol outbound)
→ platform/projection/egress.

Supporting planes run alongside rather than inside the planner: DNS contributes resolution/exit-binding facts; Auth gates resource use; Registry carries advertisements; NAT wireup improves connectivity; PathManager chooses among available packet paths; Harness/Scenario/Evidence judges engineering/product behavior.

This map supersedes any interpretation that treats Proxy, NAT, DNS or a domain estimator as a second system-level planner.

## 31. Remaining evidence-focused work

After this pass, the largest unknown is no longer “what are the architectural components”; it is **which exact claims are verified at which evidence level on the captured revision**. A final certification pass should therefore prioritize evidence artifacts and runtime route tracing over adding more conceptual prose.

The still-needed high-value inventories are:

- exact CLI/LocalAPI route → daemon handler → owner/runtime mapping;
- N2/N3 persistence files, journal/reconcile paths and crash boundaries;
- current Evidence records for the large scenario catalog;
- Harness verifier/gate behavior and protected-path enforcement;
- exact real-vs-loopback-vs-simulation status for outbound/proxy/NAT scenarios;
- platform scenario PASS/SKIP conditions, especially host-dependent Linux/Windows checks.


## 32. nexusd composition-root drift and runtime authority

A deeper audit of `apps/nexusd` shows that its own `MODULE.md` is historically layered and cannot be read top-to-bottom as one internally consistent snapshot.

Two concrete examples:

1. the module still contains an “N3 装配契约增补（待实现）” section, while `apps/nexusd/src` now contains a large N3 implementation surface: acceptance store, runtime journal, requester store/outbox, snapshots, artifacts/catalog/download, capacity/recovery, executor/docker/log/result/recovery, task HTTP/service/provider/session and tests;
2. an earlier TCP-termination section labels Proxy transport wiring as `GAP-1`, while a later P1–P5 section specifies real ProxyEngine TCP/UDP forwarding. The later contract may supersede the earlier statement, but current-state truth must come from executable source + scenario evidence, not section order alone.

Therefore this baseline treats nexusd MODULE text as contract history unless corroborated by current source.

The current `src/` inventory itself is useful evidence of composition ownership. It includes `assembly`, `config`, `dataplane`, `nat_switch`, `proxy_fwd`, `recovery`, `snapshot_store`, `sync_transport`, `workspace` and a dedicated family of N3 task modules. This is materially beyond a thin CLI wrapper.

## 33. N3 provider persistence: executable facts

### 33.1 Acceptance authority

On Linux, `FileTaskAcceptanceStore` is a durable provider-side acceptance authority. It uses a private real directory, rejects symlink/permission violations, serializes access through a stable lock inode, persists a canonical acceptance image and initialization receipt, and synchronizes directories around publication boundaries.

A critical recovery rule is encoded directly in source: an existing directory with signs of prior N3 authority is not silently treated as a new provider if authority files disappear. Missing/corrupt initialized state becomes `StateCorrupt`/`PersistenceFailed`, preventing “recover by resetting history” behavior.

Non-Linux `open` returns `UnsupportedCapability` for durable N3 provider acceptance. This is a concrete platform limitation, not merely a future design note.

### 33.2 Runtime journal

`task_runtime_store.rs` persists `task-runtime-v1.json` plus an initialization receipt. The image contains versioned `RuntimeJournal` entries. Validation enforces:

- supported schema version;
- unique TaskId journals;
- every runtime journal must correspond to an accepted task;
- replay must succeed;
- execution handles cannot be reused across tasks.

The persisted envelope contains a SHA-256 digest of the canonical runtime payload. Load validates checksum, acceptance linkage and artifact runtime consistency before exposing state.

Acceptance and runtime journal operations deliberately share the acceptance lock. The source comments explicitly state that an invalid runtime authority blocks new work and GC. This is stronger than “write a JSON file”: runtime history is part of the provider authority boundary.

### 33.3 Requester mirror/outbox is separate authority

`FileTaskRequesterStore` is a distinct Linux requester-side cache/outbox. It is explicitly independent of provider acceptance authority. It has its own private root, stable lock, initialization receipt and durable image.

This separation matters semantically: requester state tracks intent/mirror/outbox and must not manufacture provider-authoritative terminal outcomes. Provider acceptance/runtime and requester delivery state are different consistency domains.

### 33.4 N3 persistence conclusion

The previous baseline wording “N3 persistence still needs implementation” is no longer accurate as a blanket statement. There is substantial executable durable-state machinery in nexusd. The remaining question is end-to-end production closure: exact LocalAPI/transport wiring, executor/capacity support, recovery ordering and current scenario evidence must be traced independently.

## 34. Harness implementation, not just methodology

`engineering/nexus-harness` is an executable verifier with no Nexus product-crate dependency. It invokes git/cargo/rustc and reads machine policies; it is forbidden from modifying business code, scenarios, policies, git index or HEAD, and is forbidden from network operations.

Machine JSON has a stable core: `schema_version`, `command`, `verdict`, `message`. Verdict vocabulary includes PASS, FAIL, STALE, UNKNOWN and BLOCKED. An unavailable or unimplemented check is required to surface UNKNOWN rather than silently becoming PASS.

### 34.1 Evidence binding

Current `evidence.rs` binds verification to:

- source revision;
- working-tree digest;
- dirty state;
- configuration digest;
- feature set;
- target triple;
- toolchain version;
- harness schema version;
- platform capability digest;
- contract hash.

A verify id hashes revision + configuration + contract and uses the first 12 hash characters. If `NEXUS_AGENT` is valid, evidence is namespaced per agent so one agent's verification does not stale another agent's evidence.

Each verify writes `summary.json`, `gates.json` and `metadata.json`, then updates `.evidence/latest.json`. Prior evidence in the same agent namespace whose bindings differ is rewritten to verdict STALE. This makes freshness an executable state transition rather than a prose convention.

Single-scenario evidence has a separate `scenario-...` namespace and additionally incorporates the scenario id into its identity seed.

### 34.2 Gate behavior

The harness does not trust arbitrary binaries from PATH for product scenario execution. Its gate code asks Cargo to build current workspace `nexus` and `nexusd` binaries, reads executable paths from Cargo artifact JSON, verifies those paths exist, then injects them into child tests via `NEXUS_N3_TEST_CLI_BIN` and `NEXUS_N3_TEST_DAEMON_BIN`.

The MODULE contract records real full-verification gates for workspace tests, product scenarios, regression, architecture policy, dependency governance, coverage summary, platform checks, feature matrix and portable-core checks; integration/fuzz/concurrency/performance are conditional and become UNKNOWN when prerequisites/content are absent. This is an important distinction from a “green CI = everything passed” model.

### 34.3 Final PASS authority

The engineering contract explicitly states that an Agent claim cannot produce final PASS. Harness/CI gate results and bound Evidence are the certification mechanism. Consequently this CURRENT_STATE document must never use “verified” merely because source, MODULE or a previous agent report says so.

## 35. Evidence interpretation rules tightened

For all remaining audits, use these rules:

1. `MODULE.md` = normative intent/history, not sufficient current-state proof.
2. source = implementation proof, but not necessarily product wiring proof.
3. composition-root ownership = wiring proof, but not runtime-success proof.
4. scenario = verification target, not run result.
5. `.evidence` bound to the captured revision/config/contract = verification proof.
6. host-dependent SKIP/UNKNOWN must remain SKIP/UNKNOWN; never normalize them to PASS.
7. stale evidence is evidence that a test once ran, not evidence for the current baseline.

This resolves the largest epistemic ambiguity in the repository: the same feature can legitimately be Contract + Implemented + Wired while still not be Verified for the captured revision.


## 36. CLI and LocalAPI routing: the control plane is not yet unified

Source tracing of `apps/nexus/src/main.rs` and `apps/nexusd/src/main.rs` shows that the current CLI is only partially a thin client. The top-level CLI comment is accurate only for a subset of commands.

### 36.1 Commands that use daemon LocalAPI

The generic observability path maps supported `ControlCommand` values through `localapi_client::route_for_dynamic` / `route_for` and issues authenticated HTTP GET requests. Daemon-side routes currently include status, dataplane stats, DNS status/cache, frozen session watch, N2 daemon session list/attach, plan explain, connectivity status, platform capabilities and Linux workspace mounts/commit.

N3 `task` and `artifact` command families take a separate thin-client path through `nexus::task_cli` into the authenticated/versioned daemon task HTTP service. `task_http::dispatch` gets first chance to consume the request before the legacy/general GET router.

LocalAPI is bearer-authenticated even on local transports. TCP service is loopback-oriented; Unix socket mode hardens the socket to 0600 and refuses an unsafe predictable temp-socket fallback. Per-connection read/write timeout is bounded at five seconds to prevent a client that never terminates headers from pinning the control plane.

### 36.2 Commands that still execute in the CLI process

The following important command families do **not** uniformly use daemon ownership:

- `plan`: local resolve/filter/score preview;
- `use`: local N2 resource-access path;
- `session`: local N2 session store/manager path;
- `resource`: local N2 resource directory;
- `grant`: local N2 grant management;
- `provider`: provider-side admission process;
- `run <resource>`: in-process SDK;
- `network up/status`: in-process composition;
- subnet, schedule, proxy, system-proxy, autostart, pair, node and config families: in-process/local operations.

Unsupported observability commands do not silently fall back to in-process behavior; they synthesize an explicit UNSUPPORTED result. That is good honesty, but it also exposes the incomplete migration surface.

### 36.3 Ownership contradiction that remains

The daemon now owns a global N2 `SessionManager`, and its `/localapi/v0/n2/session/list` and `/attach` routes read that owner. Yet the primary `nexus session ...` CLI family still executes through `nexus::session_cli` using the in-process N2 path. `nexus use` is likewise in-process.

Therefore “daemon is the sole runtime owner of all N2 sessions” is not yet a repository-wide truth. It is true for the daemon-integrated path, but the CLI still exposes parallel local N2 execution paths. This is a concrete control-plane convergence gap, not merely documentation drift.

There are also two session-watch semantics: `session_cli` owns current N2 CLI behavior, while daemon `/localapi/v0/session/watch` is retained as a frozen older observability route. They must not be conflated.

## 37. Daemon boot and shutdown ordering

The executable `run_daemon` path gives a more precise lifecycle than the older header comments.

Boot order is materially:

1. validate config directory and load configuration;
2. resolve potential orphan workspace mountpoints;
3. run generic `boot_reconcile` against durable Session/Connectivity state **before accepting new work**;
4. assemble/replay/reconcile the daemon N2 SessionManager and start the detached-session sweeper;
5. validate that at least one meaningful subsystem is configured;
6. build dataplane configuration;
7. assemble N1, with failure degraded rather than daemon-fatal;
8. optionally start the single-TUN dataplane thread;
9. start LocalAPI and wait up to five seconds for READY;
10. on Linux, start Workspace mounts after LocalAPI ownership is established;
11. start config watcher and enter the single-writer reload loop.

Shutdown is ordered: LocalAPI → N2 sweeper → Workspace unmount → dataplane → N1 → clear run marker. Individual joins are bounded rather than allowed to hang indefinitely.

This lifecycle is executable composition-root behavior and supersedes the introductory claim that mesh/proxy/DNS long-lived runtime assembly is simply “future work”.

## 38. Generic crash recovery and N3 execution recovery are separate layers

`apps/nexusd/src/recovery.rs` explicitly scopes the generic daemon recovery layer to Session + Connectivity durable markers. It persists `sessions.json`, `links.json` and `run.marker` under `<config>/state`. Writes use same-directory temp + fsync + rename atomic replacement. On restart, stale link markers are not treated as live sockets; unrecoverable/orphan session state is made explicit rather than silently discarded.

The comment saying Workspace/Compute recovery is “Phase 2/3” is only valid for this generic marker module. It must not be generalized to mean that N3 Task crash recovery does not exist.

N3 has a separate and substantially stronger recovery system across acceptance authority, runtime journal, executor proofs, artifact/result state and capacity reconciliation.

### 38.1 N3 executor cold reconciliation

`task_executor_recovery.rs` is conservative by construction:

- it reconciles the original execution identity and never creates/starts a replacement execution;
- recovery proofs are bound to TaskId and immutable contract digest;
- Docker container and exec IDs must match the persisted engine identity;
- command/cwd must match the accepted contract;
- durable exit/reap/stop-intent proofs are validated before synthesizing corresponding runtime events;
- missing Docker inspect data or ambiguous ownership is **not** proof of `ExecutionLost`;
- ambiguous state becomes pending/observation-lost rather than fabricated success/failure;
- cancellation recovery requires original stop intent plus agreement with the original stopped engine namespace;
- timeout budget is not reset or extended merely because the daemon restarted.

This is a strong exactly-once-oriented safety property: uncertainty is preserved as uncertainty instead of being converted into a convenient terminal outcome.

## 39. Current control-plane convergence assessment

The product currently has three execution styles coexisting:

1. daemon-owned LocalAPI/runtime paths;
2. CLI-local/in-process SDK paths;
3. dedicated long-lived or foreground composition roots such as provider/network/proxy operations.

This is not inherently invalid, but it means the architectural statement “CLI is a thin client and daemon is the sole owner” is aspirational rather than universally true.

The most important remaining convergence work is to decide which operations are intentionally local administration and which should migrate behind daemon ownership. In particular, N2 `use/session/resource/grant` semantics need an explicit ownership decision; otherwise daemon state and CLI-local state can continue to represent different operational worlds.

For the current-state baseline, the rule is simple: document the route that actually executes today, not the route implied by the top-level architecture comment.


## 40. Control-command routing matrix

The current command surface is broader than the daemon API. The following matrix records the actual execution owner rather than the intended unified architecture.

| Command family | Current execution path | Daemon-owned? | Current-state note |
|---|---|---:|---|
| status | LocalAPI `/localapi/v0/status` | Yes | observability snapshot |
| dns status/cache | LocalAPI | Yes | daemon route exists |
| dns resolve/providers | synthesized UNSUPPORTED in generic CLI path | No | no daemon route |
| connectivity status | LocalAPI | Yes | daemon route exists |
| connectivity candidates/probe/links | synthesized UNSUPPORTED | No | no daemon route |
| plan explain | LocalAPI dynamic query | Yes | older/frozen observability semantics |
| plan <resource> | `plan_cli` in process | No | local resolve/filter/score preview |
| session watch via ControlCommand | LocalAPI dynamic query | Yes | frozen observability route |
| session list/watch/close command family | `session_cli` in process | No | separate N2 operational path |
| daemon N2 session list/attach | dedicated LocalAPI routes | Yes | reads global daemon SessionManager |
| use | `use_cli` in process | No | N2 access path |
| resource | `resource_cli` in process | No | N2 directory/publish path |
| grant | `grant_cli` in process | No | N2 authorization administration |
| provider | `provider_cli` foreground process | No | provider admission root |
| workspace commit | LocalAPI dynamic path | Yes | Linux daemon WorkspaceManager |
| workspace heads/conflicts/cache | synthesized UNSUPPORTED | No | generic daemon route absent |
| task/artifact | `task_cli` → versioned task HTTP service | Yes | separate from generic ControlCommand router |
| task-provider grant | local operator path | No | explicitly rejects remote target |
| run <resource> | ControlServiceImpl in process | No | LocalAPI absent |
| run <resource> -- <cmd> | rejected as N3 semantic mismatch | No execution | honest UNSUPPORTED |
| network up/status | in-process N1 composition | No | foreground composition |
| subnet/schedule/proxy/system-proxy/autostart | in-process/local | No | specialized command roots |
| pair/node/config | local filesystem / foreground operations | No | administrative paths |

This table is evidence that `ControlCommand` is a shared vocabulary, not yet a guarantee of one transport or one runtime owner.

## 41. LocalAPI security and protocol boundary

The general LocalAPI and N3 task HTTP share a local listener but are dispatched in layers. `task_http::dispatch` can consume versioned Task requests first; unconsumed requests fall through to the GET-oriented legacy/general router.

Security properties visible in executable code include:

- bearer token authentication on both TCP and Unix local transports;
- 64-hex-character token persisted in a shared token file;
- owner-only token permissions on Unix;
- constant-time token comparison in the general router;
- Unix socket hardening to 0600;
- private runtime directory fallback rather than a predictable world-writable temp socket;
- bounded five-second client/server I/O timeout;
- fail-closed behavior when safe socket/token setup cannot be established.

The client does not retry and does not use TLS. Its trust model is local transport + bearer token, not remote-network confidentiality.

Windows named-pipe LocalAPI is not implemented in the inspected server path; the Windows socket branch reports UNSUPPORTED and TCP is the practical fallback.

## 42. Configuration load and hot-reload semantics

The daemon watches a fixed configuration set rather than arbitrary directory contents: `daemon.toml`, `network.toml`, `proxy.yaml`, `dns.toml` and `workspace.toml`.

Startup load validates syntax before assembly. Missing files disable the corresponding subsystem rather than being treated as malformed configuration. Important typed daemon settings include TUN enable/name/MTU and QoS settings; TUN MTU is constrained to 1280–9000 and QoS quantum to 64–65536.

The watcher polls every two seconds and is intentionally a reporter, not a shared-state mutator. It sends `ReloadEvent` to the daemon main thread, preserving a single-writer application model.

Three outcomes are explicit:

- `Applied`: valid hot-applicable change;
- `NeedsRestart`: valid change that requires process reconstruction;
- `Rejected`: invalid reload; old configuration remains active and daemon does not crash.

File add/remove and LocalAPI address changes require restart. Invalid content is rejected while retaining the old configuration. The watcher updates metadata after a bad edit to avoid repeatedly flooding the same error.

### 42.1 Important hot-reload caveat

A watcher `Applied` event does not by itself prove that every already-running subsystem object has been rebuilt with the new content. The main loop currently logs the applied event; actual mutable-runtime propagation must be checked subsystem by subsystem. Therefore this baseline distinguishes **configuration accepted as hot** from **runtime object demonstrably reconfigured**.

This distinction is especially important for network/proxy/DNS claims: configuration classification and runtime reassembly are separate facts.

## 43. Repository Evidence at the captured branch

The checked-in `.evidence` tree on `docs/current-state-baseline-20261008` is **not** a comprehensive current-revision certification database.

At the inspected branch, the repository-visible `.evidence` root contains only `red-n2-p0-0/`. That directory contains historical RED/transition artifacts such as `RED-EVIDENCE.md`, RED N2 scenario output, old/new run-honesty JSON and a helper script.

This has an important consequence:

> The repository contains a large scenario catalog and an executable Harness evidence mechanism, but the checked-in branch does not contain a complete bound PASS evidence set for all those scenarios at the current revision.

Accordingly, this document must not assign Verified/E4/E5 status merely from scenario filenames, tests in source, comments saying “green”, or historical evidence files.

The absence of committed current evidence also does not prove tests fail; it means the repository snapshot alone cannot certify their current result. Fresh Harness execution is required for that claim.

## 44. Scenario/Evidence gap classification

For current-state documentation, each capability should be classified along two independent axes:

**Implementation axis**
- Contract only
- Implemented
- Wired
- Production-reachable

**Verification axis**
- No scenario
- Scenario-targeted
- Historical evidence only
- Current bound evidence PASS
- Current bound evidence FAIL/UNKNOWN/BLOCKED/STALE

This two-axis model prevents a common false inference in the repository: “implemented + scenario exists = verified”. It also prevents the inverse mistake: “no committed current evidence = feature absent”.

For the captured branch, many major areas are at least Implemented/Scenario-targeted, but a repository-wide Current-bound-evidence-PASS claim is not supported by the checked-in evidence tree.

## 45. High-confidence current architecture findings after the extended audit

The source audit now supports several repository-wide conclusions with substantially higher confidence:

1. There is one intended system-level Core Planner; proxy rules, DNS, path quality, NAT and estimators are supporting decision inputs/mechanisms, not alternative planners.
2. Session terminal outcome ownership is deliberately centralized inside SessionOwner semantics, but operational ownership is not yet globally centralized in nexusd because CLI-local N2 paths remain.
3. Fabric connection identity is independent of network locator; path migration and NAT/TURN operate below application Session identity.
4. N3 durable execution is much more mature than old “pending” MODULE text suggests, particularly on Linux.
5. N3 recovery prefers unknown/pending verification over inventing a terminal outcome, preserving exactly-once safety.
6. Cross-platform repository structure exists, but implementation maturity is asymmetric and durable N3 provider authority is Linux-specific.
7. The daemon is a real composition root for TUN/dataplane/N1/LocalAPI/Workspace/N2 ownership, contradicting its stale introductory “configuration/status only” boundary.
8. The CLI is not yet a pure thin client; several operational domains still have independent in-process roots.
9. Configuration acceptance/hot classification is not equivalent to proof of live subsystem reconfiguration.
10. Scenario coverage is broad, but checked-in Evidence on the captured branch is sparse/historical and cannot certify the entire current tree.

## 46. Remaining work before calling CURRENT_STATE exhaustive

The remaining work is now narrower and measurable:

- enumerate the few workspace members not yet described at implementation-detail level, especially scheduler/measurement/ingress/proxy-config/proxy-transport and diagnostics;
- trace N1 bridge and dataplane packet classification end-to-end, including degraded counters and actual send/receive ownership;
- trace Workspace sync transport, FUSE projection, conflict/recovery and remote authority end-to-end;
- trace N3 task HTTP verbs/versions through service/provider/executor/artifact paths and record exact unsupported branches;
- run or inspect fresh Harness verification for this branch if a current Verified matrix is required;
- map host-dependent platform scenarios to required privileges/devices and SKIP/UNKNOWN behavior;
- verify whether watcher `Applied` changes are actually propagated into live network/proxy/DNS objects or only accepted/logged;
- reconcile stale top-of-file/module comments against executable behavior and mark/remove obsolete claims in a later documentation-cleanup pass.

At this point, the document is a detailed source-derived implementation baseline. It is not yet a current-revision test certification report; that distinction is intentional.

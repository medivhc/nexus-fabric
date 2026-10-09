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

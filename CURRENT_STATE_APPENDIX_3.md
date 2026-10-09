# Nexus Fabric Current State — Deep Audit Continuation III

> Continues `CURRENT_STATE_APPENDIX_2.md` after section 74.
> Source baseline: `48918863e70ef8589fbca6075c7ec11ca07e85a3` on `master`.
> This file remains staging material for the canonical `CURRENT_STATE.md`; findings here are source-derived current-state facts, not target-architecture decisions.

## 75. `nexus-projection` and `nexusd::Dataplane` are overlapping orchestrations, but they are not completely independent implementations

The previous audit correctly identified two dataplane-shaped layers, but a direct dependency/import trace refines that conclusion.

`apps/nexusd` has an explicit Cargo dependency on `nexus-projection`. More importantly, `apps/nexusd/src/dataplane.rs` imports and reuses concrete projection primitives:

- `nexus_projection::TunDevice`;
- `classifier::{Classification, PacketClassifier}`;
- `routing::Cidr`;
- `tcp::{TcpTerminator, TcpEvent, stream framing helpers}`.

The daemon's real TUN creation path also uses `nexus_projection::tun_rs_device::TunRsDevice`.

Therefore these are **not two wholly separate dataplanes built from unrelated implementations**. The more accurate current relationship is:

1. `nexus-projection` contains a substantial reusable dataplane toolkit **and** its own top-level Projection orchestration for TUN/Fabric/routing/egress;
2. `nexusd::Dataplane` reuses several of those lower-level components but owns a different higher-level orchestration centered on DNS interception, CAKE-like QoS, N1Sender, ProxyEngine and optional flow-session mapping.

This distinction matters for the eventual deletion test. The duplication is mostly at the **orchestration/ownership layer**, not at every low-level mechanism.

The target-state question is consequently sharper than “which dataplane implementation wins?” It is:

> Should the canonical product runtime be `nexus-projection`'s top-level Projection, `nexusd::Dataplane`, or a third composition that extracts their common primitives and leaves only one product-level packet owner?

Until that decision is made, both top-level orchestration shapes remain current source facts.

## 76. NAT switching is substantially implemented but explicitly not instantiated by the production daemon

`apps/nexusd/src/nat_switch.rs` is one of the clearest examples of the distinction between implementation completeness and composition completeness.

The module composes a meaningful production-shaped stack:

`PunchManager`
→ `PathManager`
→ `PathLink`
→ `QualityMonitor`
→ active `ConnShared` selection.

It registers relay connections, starts quality monitoring, optionally launches bounded background punching, registers successfully validated direct connections as competing candidates, updates Active/Backup probe roles after path events, and exposes `active_conn(peer)` as the connection production traffic should use.

However, its top-level source contains an explicit honest boundary: **`nexusd` does not instantiate this module in `main.rs` at this revision**. The stated reasons are not just missing glue:

- nexusd has no complete TURN client/configuration/credential-management path;
- STUN/srflx sampling is still a composition-root responsibility;
- `gather_host_candidates()` currently only exposes the Fabric driver's bound host address;
- the hook `on_relay_connected()` exists for a relay connector that has not yet been wired into daemon startup.

The module cites a real E4 path using TURN + NAT simulation, but that is evidence for the stack mechanism, not evidence that the normal daemon boot path enables it.

Current classification:

- portable punching state machine: **Implemented**;
- Fabric punch wire-up: **Implemented**;
- active quality monitor: **Implemented**;
- PathLink migration/adoption logic: **Implemented**;
- `NatSwitching` composition object: **Implemented**;
- normal nexusd boot activation: **Not wired**;
- daemon-owned TURN/STUN credential/discovery lifecycle: **Not closed**.

This is stronger evidence than the generic statement “NAT traversal is partial”: the missing boundary is now known precisely.

## 77. The daemon ProxyEngine supports a much narrower protocol set than proxy configuration and outbound crates suggest

The repository contains protocol crates for Shadowsocks, VMess, Trojan, AnyTLS, VLESS and Hysteria2, and `nexus-proxy-config::OutboundKind` can represent all of those plus Direct/Relay/SOCKS5.

The production `apps/nexusd/src/proxy_fwd.rs` path is narrower.

`ProxyEngine::new()` selects the first outbound that `dial_config_from_outbound()` can materialize. At this revision, daemon forwarding supports:

- Shadowsocks, **only** `chacha20-ietf-poly1305` in this production path;
- Trojan plaintext;
- Trojan TLS when the config triggers the TLS variant;
- SOCKS5.

The same function explicitly returns `None` for:

- Direct;
- Relay;
- VMess;
- AnyTLS;
- VLESS;
- Hysteria2.

Therefore a `proxy.yaml` can be syntactically valid and can name a protocol for which a crate exists, yet still yield **no usable daemon ProxyEngine outbound**. In that case daemon dataplane falls back to its observable degraded/no-proxy behavior.

This is a major current-state distinction:

> “Protocol adapter exists in the repository” != “nexusd unified TUN proxy forwarding can use that protocol.”

The production dataplane protocol matrix should consequently be documented separately from the repository-wide outbound implementation matrix.

### 77.1 Trojan has two production dial modes, and the default path is not automatically TLS

The daemon ProxyEngine chooses `TrojanTls` when the parsed outbound has `skip_cert_verify` or ALPN configuration; otherwise it chooses the plaintext `Trojan` dial variant.

That behavior should remain explicit in the baseline because the term “Trojan outbound” by itself can imply a TLS-protected wire protocol to a reader. The daemon implementation does not infer TLS simply from the protocol name.

Whether that default should survive in the target architecture is a separate design/security decision; the current-state fact is that both modes exist and plaintext is a reachable daemon selection.

## 78. N2 cross-machine admission authenticates both identities but does not provide a confidential channel

`apps/nexus/src/n2_admission.rs` is substantially more concrete than a “future N2 handshake” description suggests.

The provider-side admission service uses an independent TCP connection with u32-BE-length-prefixed JSON frames. The handshake establishes possession of ed25519 identities through challenge/response signatures:

- provider sends a random challenge;
- requester signs it with its persisted ed25519 key;
- provider derives Principal from the **verified** public key rather than requester-supplied identity text;
- provider evaluates its local grant table and records an audit event;
- the v2 path also has the provider sign a requester challenge;
- requester verifies the provider signature and evaluates the explicit TrustStore/TOFU policy.

This gives the admission path real mutual identity authentication at the application protocol level.

The same source explicitly states the P0 threat boundary: **there is no confidentiality and no forward secrecy**. The admission connection is not yet a mutually authenticated encrypted QUIC/TLS session. The current P0 threat model is described as a single-workspace/single-administrator environment, with authenticated QUIC reuse left as an evolution path.

This creates an important distinction between N2 and Fabric:

- N2 admission has an ed25519 mutual-signature handshake but plaintext application framing;
- Fabric has encrypted transport semantics but, as section 70 records, inbound server-side peer identity is not yet sufficient for the Workspace sync authorization property.

The repository therefore does not yet have one single authentication+confidentiality primitive reused consistently by every resource-control/data path.

### 78.1 Admission resource limits are explicit

The provider admission server bounds exposure rather than spawning without limit:

- maximum concurrent admissions: 64;
- per-connection read timeout: 10 seconds;
- repeated accept errors trigger backoff;
- excess connections are rejected instead of forming an unbounded queue.

These are real production-hardening facts and should not be lost when the handshake is eventually replaced or unified.

## 79. N2 identity durability is real, but cold initialization is only serialized inside one process

`apps/nexus/src/n2_identity.rs` persists the node's N2 authorization identity under `n2/auth-identity` as an ed25519 seed/public-key record.

Important existing safety properties include:

- key generation from 32 random bytes;
- public key recomputation from seed when loading;
- persisted public key/seed consistency validation;
- idempotent `ensure_auth_identity`;
- post-write Unix permission tightening to 0600 for the identity file;
- a process-local mutex protecting first creation.

The source also contains an explicit limitation: the mutex serializes **same-process** cold creation only; cross-process initialization of the same node directory still requires coordination by the node owner.

That caveat matters because current Nexus architecture still has daemon-owned and CLI-local execution paths that can touch the same node/config state. It is not proof that a real race occurs in the normal command sequence, but it is a known authority boundary: `ensure_auth_identity()` alone is not a cross-process single-writer protocol.

The target architecture should either preserve a single process owner for identity creation or strengthen this initialization with a cross-process lease/atomic-create authority comparable to the newer N3 state machinery.

## 80. N2Store is more durable than the generic recovery comments imply, but one semantic detail is intentionally lossy

`apps/nexus/src/n2_store.rs` is a substantial composition-level persistence layer over `FileKvStore`. It stores:

- N2 Session records;
- complete `PlanSnapshot` material associated with sessions;
- Grant records;
- authorization audit journal entries;
- provider advertisements and name tables;
- directory audit events;
- durable control-frame outbox entries such as AUTH_REVOKE delivery work.

The boot model is explicitly:

KV truth
+ journal replay/audit trail
+ session-record reconciliation
→ accept new work.

This is more precise and stronger than a generic “sessions.json marker” model.

### 80.1 Persisted `Failed` outcome is not a full typed-error round trip

There is one important fidelity boundary in current serialization. A `TerminalOutcome::Failed(NexusError)` is serialized using the formatted/debug reason text. On load, it is reconstructed as `NexusError::Internal { message: reason }` rather than reconstructing the original structured NexusError variant.

Therefore the persistence contract preserves the fact that the session failed and retains diagnostic text, but it does **not** preserve the exact typed failure variant across restart.

This should be documented as a current semantic limitation rather than hidden inside “durable SessionRecord” wording. A caller that relies on exact failure taxonomy after cold restart does not receive a byte-for-byte/type-for-type round trip today.

## 81. N3 requester-side Artifact download is one of the strongest crash-consistent client paths in the repository

The N3 implementation is not provider-only. `apps/nexus/src/artifact_download.rs` implements a Linux local receiver with resumable, integrity-checked publication semantics.

The current receiver has several strong properties:

- accepts only `Published` Artifact records within a fixed size bound;
- creates a private 0700 authority directory and 0600 partial data;
- uses a stable cross-process lease for one destination;
- persists an exact durable resume offset plus SHA-256 of the committed prefix;
- replay of already committed pages is accepted only when bytes match exactly;
- gaps and partial overlaps are rejected rather than silently repaired;
- final size + SHA-256 must equal the Artifact record before publication;
- output publication is no-replace: an unrelated existing file is never overwritten;
- symlink-containing output-parent paths are rejected;
- publication uses a hard-link/inode identity model and verifies that an existing destination is the receiver's own inode before treating it as resumable success;
- a crash after publication intent/link can be reconciled from persisted phase and inode identity.

This is materially stronger than ordinary “download to `.part` and rename” behavior.

Current maturity consequence: N3's requester-side local durability/integrity story is already advanced on Linux even though the overall distributed task transport and control ownership remain incompletely converged.

## 82. N3 provider grant administration deliberately bypasses the daemon and mutates local authority directly

`nexus task-provider grant ...` is another explicit example of current control-plane pluralism.

The command's own source states that it is **local operator access** to the existing scoped N2 Use-grant table and has:

- no daemon RPC;
- no identity provisioning;
- no name resolution;
- no Task ownership semantics.

It is Linux-only. The command binds itself to the `provider` + `workspace` scope in `task-api.toml`, validates the existing N2 identity, acquires a local file authority/lease, performs compare-before-write checks, records an audit intent, atomically publishes the grant mutation, and records the applied audit state.

The implementation also refuses to replace/revoke Manage or otherwise noncanonical permissions: the task-provider operator surface is restricted to the scoped Use-grant shape it owns.

This is good local authority hygiene, but architecturally it reinforces an earlier conclusion:

> Not every administrative mutation is intended to pass through `nexusd` LocalAPI at this revision.

Some operations are consciously local, file-authority operations. The future architecture should distinguish these from accidental CLI-local duplication instead of applying a blanket “everything must be daemon RPC” rule.

## 83. `nexusd/src/lib.rs` contains a fresh example of comment drift around N3 TaskStore

The library root currently documents `task_store` as:

> “N3-1 acceptance persistence, not yet connected to daemon product routes.”

That comment is stale relative to the current source tree audited earlier: `task_service`, `task_http`, provider service assembly and durable acceptance/runtime paths already consume the Task persistence machinery as part of the daemon's N3 LocalAPI/application service.

This is a useful drift example because it sits at a high-level module export, exactly where a reader is likely to infer maturity quickly.

Baseline treatment: keep the comment as historical evidence but treat the current Task HTTP/service call graph as authoritative.

## 84. The root architecture policy recognizes `nexus-workspace-intel` even though the literal root member list omits it

The previous appendix noted the physically present and product-consumed `nexus-workspace-intel` package. `policies/architecture.toml` confirms that this is not an accidental directory: the machine architecture policy contains an explicit `[[crate]]` entry for `nexus-workspace-intel`, assigns it the `domain-runtime` layer, and constrains its internal dependencies to domain/workspace/planner/registry/storage.

At the same time, the literal root `Cargo.toml` `members = [...]` array does not list the package, while `apps/nexus/Cargo.toml` has a direct path dependency on it.

Therefore there are three repository facts that must all be represented:

1. the explicit workspace member array has 50 entries;
2. `nexus-workspace-intel` is a real package depended on by the `nexus` application;
3. the machine architecture policy treats it as a first-class internal crate.

This strengthens the earlier recommendation to derive the actual Cargo package/workspace graph from `cargo metadata` when certification is required instead of treating the literal member array as the complete package inventory.

## 85. Updated runtime-integration matrix after this pass

| Capability | Mechanism exists | Product composition exists | Normal daemon startup enables it | Key limitation |
|---|---:|---:|---:|---|
| N1 mesh forwarding | yes | yes | yes when network/TUN configured | flow→Session layer still optional/unenabled |
| daemon proxy forwarding SS/Trojan/SOCKS5 | yes | yes | yes when a usable supported outbound exists | production protocol subset narrower than config/crates |
| VMess/AnyTLS/VLESS/Hysteria2 outbound crates | yes | elsewhere/partial | **not through current daemon ProxyEngine** | parsed/configurable does not imply daemon forwarding |
| NAT punch + quality + path switching | yes | `NatSwitching` exists | **no** | no daemon TURN/STUN/relay connector activation |
| Workspace FUSE/local commit | yes | yes | yes on Linux when configured/capable | commit-anchor crash window documented |
| Workspace Fabric sync transport | yes | adapter exists | passive/server binding still unproven | inbound peer identity not trustworthy enough for member auth |
| N2 admission | yes | CLI/provider composition | foreground provider service, not daemon-unified | authenticated but not confidential/forward-secret |
| N2 identity/store | yes | yes | used by CLI and daemon paths | cross-process identity creation not self-serialized |
| N3 Task provider | yes | yes | enabled by `task-api.toml` on Linux | platform-specific; distributed ownership still evolving |
| N3 Artifact local receiver | yes | yes | CLI-local receiver path | Linux-specific |

This matrix makes the repository's main maturity pattern more concrete: many difficult mechanisms already exist, while the largest remaining gaps are **composition ownership and unification**, not basic algorithm absence.

## 86. Highest-priority current-state corrections produced by this pass

The prior baseline should be read with the following refinements:

1. `nexus-projection` vs `nexusd::Dataplane` is **partial reuse plus competing top-level orchestration**, not two entirely separate stacks.
2. NAT switching is not merely “not proven”; its own composition source explicitly states that normal nexusd does not instantiate it.
3. Proxy production coverage must be reported separately from outbound-crate coverage; daemon ProxyEngine currently supports only a subset.
4. N2 cross-machine admission already has mutual ed25519 identity proof, but still lacks channel confidentiality and forward secrecy.
5. N2 identity has a process-local initialization lock only; cross-process single-writer authority is external.
6. N2 Session persistence preserves failure diagnosis but not the exact typed NexusError variant after restart.
7. N3 requester Artifact durability/integrity is already strong and should not be described as an unimplemented client concern.
8. Some CLI-local administration, such as task-provider grant management, is intentional local authority rather than obviously accidental daemon bypass.
9. High-level source comments continue to lag the N3 implementation, including the `task_store` export comment.

The aggregate architectural diagnosis remains the same but becomes more precise: the repository has accumulated many individually sophisticated mechanisms; the dominant uncertainty is now which runtime owns them, which paths are normal-product reachable, and which duplicated orchestration surfaces should survive.
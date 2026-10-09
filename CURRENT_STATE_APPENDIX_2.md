# Nexus Fabric Current State — Deep Audit Continuation II

> Continues `CURRENT_STATE_APPENDIX.md` after section 67.
> Source baseline: `48918863e70ef8589fbca6075c7ec11ca07e85a3` on `master`.
> This is another staging continuation; sections will be merged into the canonical `CURRENT_STATE.md` after the source sweep.

## 68. N1 currently contains two dataplane generations that must not be conflated

A deeper read of `crates/nexus-network/src/n1` shows that the current N1 implementation contains a complete portable connection-lifecycle subsystem in addition to the newer unified `nexusd` dataplane bridge.

The N1 portable boundary is deliberately dependency-inverted. `nexus-network::n1` does not directly depend on Fabric, Path, Discovery or Linux platform crates; instead it defines `N1Connection`, `N1Dialer`, `N1Listener`, `N1Discovery`, `N1EventSink` and keepalive I/O traits. The Composition Root adapts concrete Fabric/discovery/platform objects into these interfaces.

### 68.1 `N1SessionManager` owns transport connections, not resource Sessions

`N1SessionManager` explicitly says it is the owner of the actual per-peer transport instance and **not** the whitepaper/resource `Session` abstraction. It maintains a strict one-connection-per-peer invariant. `dial()` resolves locators through injected discovery, dials once, and installs the resulting connection; duplicate inbound connections are closed rather than creating a second active connection.

Each installed connection gets a `LinkStateWatcher`. Lifecycle is expressed as `Allocating → Active → Draining → Disposed`, but failed dialing does not leave an exposed `Allocating` record behind.

Shutdown ordering contains a concrete concurrency invariant: `remove()` must call `conn.close()` before `watcher.shutdown()`, because the watcher may be blocked in keepalive I/O and joining it first can deadlock. This is a real ownership property, not just a style guideline.

### 68.2 `N1MeshBridge` is the newer unified-dataplane glue

`N1MeshBridge` is intentionally thin: longest-prefix match selects a peer, `N1SessionManager::connection_for()` returns the existing transport, and the packet is sent as a datagram. The bridge therefore keeps N1 routing/connection knowledge inside `nexus-network` while letting `apps/nexusd::dataplane` remain generic through the `N1Sender` trait.

This is the production path already documented in sections 47–48.

### 68.3 `VpiPump` is a second, older/foreground packet-pump runtime

`n1/pump.rs` contains its own full VPI packet pump:

VPI receive
→ IPv4 parse
→ static longest-prefix routing
→ per-peer `send_datagram`,

with per-peer downlink workers reading datagrams and writing back to VPI.

It has substantial structured-concurrency machinery: uplink/downlink supervisors, worker restart counters, mutex-poison recovery and a process-level panic hook for `n1-pump*` threads.

However, the portable `VirtualPacketInterface::receive()` contract has no timeout/cancellation method. If the uplink worker blocks indefinitely inside `receive()`, shutdown cannot portably interrupt it. The supervisor waits up to two seconds and then detaches the worker; process exit is relied on for final OS cleanup.

This is an explicit bounded-shutdown compromise and should remain visible in the baseline.

### 68.4 Architectural implication

There are therefore at least two N1 packet-driving shapes in the tree:

1. `VpiPump`: N1-owned VPI ↔ per-peer connection pump;
2. unified `nexusd::Dataplane` + `N1MeshBridge`: daemon-owned TUN classification/Proxy/N1 pipeline.

The newer daemon path does not make the older pump source disappear. Future architecture cleanup should decide whether `VpiPump` remains an intentional standalone/foreground mode or is legacy duplication. Until then, documentation must not describe “the N1 dataplane” as one implementation.

## 69. PathManager's active-probe wording is ahead of its actual probe implementation

`nexus-path` has a substantial path-selection state machine: Direct/Mesh/TURN/Proxy candidates, EWMA scores, cost weighting, hysteresis, hold time, missed-probe failover, explicit switch/adopt events, single-active-path semantics and connection-setup racing.

But its background probe loop currently calls `send_heartbeat_stub()`, whose implementation sends no packets. The source says the scheduling/ownership framework is real while real ping/pong is a later phase; passive or externally supplied statistics drive current decisions.

This produces an important correction to earlier broad descriptions such as “PathManager probes candidates”: the **manager has probe scheduling infrastructure, but its own active heartbeat hook is currently a stub**.

That does not mean the repository has no active path quality probing. `nexus-nat-quality` separately implements active datagram ping/pong plus Fabric RTT measurement and can feed `PathStats` into the manager. The correct architecture is therefore:

- PathManager: scoring, hysteresis, failover, event production and probe scheduling framework;
- NAT quality monitor: one concrete real active-quality producer;
- PathManager's internal heartbeat sender: stub at this revision.

The distinction matters because dropping `nexus-nat-quality` or failing to wire another measurement producer can leave PathManager with no fresh active probe facts even though its own background thread is running.

The P0 steady-state rule remains one active path. Racing is a connection-establishment optimization, not concurrent multipath forwarding.

## 70. Workspace sync has a more serious production authorization limitation than previously recorded

`apps/nexusd/src/sync_transport.rs` is a real Fabric-backed implementation of `nexus_workspace::WorkspaceTransport`. It opens a bi-stream on an already active Fabric connection, uses stream type `0x03`, has a 64 KiB frame limit and a 30-second default receive deadline, and delegates workspace protocol semantics back to `nexus-workspace`.

The file also documents the intended passive routing:

- relay connection streams are handed out by `PunchManager::take_unclaimed()` and routed by stream type;
- direct connections are accepted and peeked for the workspace-sync stream type.

However, the same source contains a critical security caveat: Fabric P0 currently authenticates the server to the client but does not provide a trustworthy client PeerId on the server side. `ConnShared::peer` for the inbound/server side is described as zeroed. Consequently the passive sync server cannot currently treat that peer identity as an authenticated principal.

`SyncAuthorizer` and `serve_sync_authorized()` correctly implement a member allow-list mechanism and reject non-members before sending workspace objects, but the source explicitly states that production peer identity is not yet trustworthy and that the authorization mechanism becomes enforceable only after client authentication is completed.

Therefore the previous baseline wording “Fabric-backed workspace sync authorizes peer membership” is too strong unless qualified. The honest status is:

- Fabric workspace-sync framing/transport: **Implemented**;
- membership authorization algorithm: **Implemented**;
- trustworthy server-side remote principal for production sync: **Not yet established in Fabric P0**;
- production security property “only authenticated workspace members can read sync data”: **not proven/closed at this revision**.

This moves the Workspace integration issue from a simple startup/wiring question into a security-identity boundary as well.

A second integration gap remains: source comments describe how callers should route accepted/unclaimed streams to `serve_sync_authorized`, but the audit has not yet found a composition-root invocation proving that every production workspace mount starts this passive sync-serving loop.

## 71. Legacy Workspace/CAS identity uses a 64-bit non-cryptographic hash; N3 deliberately introduced a separate strong namespace

A deeper storage audit reveals an important generation boundary.

### 71.1 Legacy `ObjectId` is FNV-1a 64

`nexus-storage::object_id_of()` computes FNV-1a 64-bit and renders it as 16 hex characters. The portable `ContentStore`, in-memory store and `FsContentStore` use that identifier as the content address.

`FsContentStore` writes with temp-file + file fsync + atomic rename + directory fsync and is crash-consistent at the publication boundary. But if the target object path already exists, `atomic_write()` returns success without re-reading and byte-comparing the existing object; the implementation assumes equal identifier implies equal bytes.

That assumption is deterministic but is not cryptographically collision-resistant because the namespace is only 64 bits and uses FNV-1a.

### 71.2 This affects authoritative Workspace identity, not only an expendable cache

`nexus-workspace` derives `CommitId` through the same `object_id_of()` semantics; conflict identity also ultimately uses the legacy object-id hash. Workspace manifests and content objects live in that CAS, while the Commit DAG/HeadSet/Journal are correctness-authoritative.

Therefore the legacy hash choice is part of the authoritative Workspace identity model. It should not be described as equivalent to a cryptographic content digest.

The current-state issue is best framed as an **integrity/collision-resistance limitation**, not as proof of an observed corruption bug. Under benign workloads accidental collision probability may remain low, but the identity space and algorithm are materially weaker than SHA-256, especially if content may ever be influenced adversarially.

### 71.3 N3 explicitly avoids the legacy namespace

`nexus-storage::strong` makes this separation explicit in source: “N3 content addresses are independent of legacy FNV locators.” `StrongContentStore` takes a `Sha256Digest` plus expected length; every read/publication must verify digest and length, and the composition root supplies SHA-256.

This means the repository already recognizes two integrity generations:

- legacy Workspace/content namespace: FNV-1a 64 `ObjectId`;
- N3 frozen input/artifact namespace: SHA-256 + length verification.

The baseline should keep them distinct. It would be inaccurate to say “Nexus storage is SHA-256 content addressed” globally; it would equally be inaccurate to say N3 relies on the legacy FNV IDs.

### 71.4 KV durability is a third storage concern

`FileKvStore` explicitly does not use `ContentStore`/FNV. It is a crash-consistent small-state KV/journal substrate for identity, grants, audit and similar state. It uses temp+fsync+rename+directory-fsync for values and a bounded append journal with torn-tail detection. A torn journal is fail-closed until explicitly discarded.

So `nexus-storage` actually contains three different storage contracts: legacy CAS identity, strong N3 content verification seam, and crash-consistent small-state KV/journal.

## 72. The portable Platform contract is mature even where OS implementations are not

Although macOS/Android/iOS adapters are still root-level skeletons, `nexus-platform` itself has a concrete portable capability vocabulary. Current traits include `Clock`, `RandomSource`, `SecureStore`, `VirtualPacketInterface`, `PacketCarrier`, `TransparentIngressProvider`, projected-workspace contracts, system-proxy control and autostart registration.

`PacketCarrier` is deliberately separate from VPI: VPI handles IP packets; PacketCarrier handles encapsulated frames and locators; Connectivity composes authentication/encryption/establishment around them.

The most important failure semantic is `PlatformError::Unavailable { capability }`. The source comments explicitly prohibit silently changing product semantics when a host capability is absent. A missing platform feature must surface as an explicit unavailable capability.

This gives a useful distinction for cross-platform planning:

- portable capability **contract** can be mature;
- a platform adapter can still be absent/skeletal;
- callers should degrade through explicit capability-unavailable errors rather than pretending semantic parity.

This is the correct lens for macOS/Android/iOS today.

## 73. `nexus-projection` is another substantial dataplane implementation and increases the need to clarify runtime ownership

`nexus-projection` is far beyond a mock-only TUN adapter. Its root exports routing, classifier, DNS sniff/cache, egress NAT, real UDP egress, process attribution/QoS labels, path links, semantic ingress, TCP egress/relay, multipath helpers, Fabric datagram transport and a real `tun-rs` device adapter.

It defines packet intents for mesh, egress and TCP stream traffic, hop-count loop protection and structured routing/drop counters. The TCP path chunks byte-stream payload so it can preserve application bytes across the datagram MTU rather than applying the L3 “drop oversize packet” rule to stream bytes.

At the same time, `apps/nexusd` now owns a separate unified `Dataplane` with TUN classification, DNS interception, TCP termination, QoS, N1 and ProxyEngine forwarding.

This means the tree contains **two substantial dataplane-shaped implementations**:

1. `nexus-projection`'s TUN/Fabric/routing/egress engine;
2. `nexusd::Dataplane`'s unified TUN/N1/proxy engine.

This audit has not yet established that one is a strict library used internally by the other; code-search did not reveal a straightforward `nexus_projection` composition reference in the paths inspected. Therefore the baseline should treat their relationship as an unresolved ownership/convergence question rather than assuming one canonical dataplane.

This is potentially more important than an ordinary duplication issue because both layers contain routing, TUN and TCP/egress responsibilities. The target architecture should eventually answer which one is authoritative, which one is experimental/legacy, and what deletion test distinguishes them.

## 74. Updated highest-priority findings after the latest source sweep

The most consequential current-state issues are now:

1. **Runtime ownership is fragmented:** daemon-owned runtime, CLI-local N2 paths, N1 `VpiPump`, unified nexusd Dataplane and `nexus-projection` all represent overlapping execution shapes.
2. **Unified flow Session ownership is not production-enabled:** `enable_flow_sessions()` remains absent from inspected daemon composition.
3. **Workspace sync production authorization is incomplete:** membership checks exist, but inbound Fabric peer identity is not yet trustworthy without client authentication.
4. **Workspace integration is still not proven end-to-end:** Fabric sync transport exists, but automatic server/client startup and binding to every mounted workspace remains unverified.
5. **Legacy authoritative Workspace identity is only 64-bit FNV-1a:** N3 has moved to a separate SHA-256 namespace, exposing a clear integrity-generation split.
6. **Path quality ownership is distributed:** PathManager's own active-heartbeat sender is a stub; real active probing currently comes from other producers such as NAT quality when wired.
7. **Maturity varies dramatically behind symmetric crate names:** diagnostics/delivery/proto are near-skeletons, while connectivity/projection/N3/Linux contain substantial runtime machinery.
8. **Current-revision verification remains weakly evidenced:** broad scenario definitions still do not equal a bound PASS evidence set.
9. **Source comments themselves can be stale:** proxy transport and discovery now provide concrete examples where even comments inside executable crates contradict current symbols.

These findings reinforce the direction of the baseline: the next architecture pass should not begin by drawing cleaner boxes. It should first decide authoritative runtime owners and deletion tests for overlapping implementations, then define which existing mechanisms are retained, migrated or removed.

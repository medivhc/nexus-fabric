# Nexus Fabric Current State — Deep Audit Continuation IV

> Continues `CURRENT_STATE_APPENDIX_3.md` after section 86.
> Source baseline: `48918863e70ef8589fbca6075c7ec11ca07e85a3` on `master`.
> This file remains staging material for the canonical `CURRENT_STATE.md`; findings here are source-derived current-state facts, not target-architecture decisions.

## 87. `nexus-connectivity` contains at least three generations of implementation depth

The previous audit already classified `nexus-connectivity` as a mixed-maturity mega-crate. A deeper file-level read makes the internal generations more concrete.

The root module exports several categories at once:

1. foundational connectivity/evaluation and virtual-subnet machinery;
2. pure or mostly deterministic control/state-machine modules;
3. modules whose comments still call them “纯逻辑骨架”;
4. later “realized” or pipeline modules that attach some of those earlier models to concrete packet/handle behavior.

This means a single statement such as “Connectivity supports connection pooling, health checks, QoS, compression and fragmentation” is materially ambiguous.

### 87.1 Connection pooling is a good example of model → realized implementation evolution inside one file

`connection_pool.rs` begins by explicitly describing `ConnectionPool` as an in-memory synchronous skeleton. Its first implementation does not contain a socket: `PooledConnection` only has a logical key and `conn_id`; connection creation is simulated by incrementing an id, and the caller manually pairs `acquire`/`release`.

But the same source later contains a second generation, `RealizedPool<F: ConnectionFactory>`, which stores real opaque connection handles produced by an injected factory. Idle eviction drops those handles, so a concrete composition root may use it with actual sockets without making the connectivity crate itself perform I/O.

Therefore the current status is not simply “connection_pool = skeleton” and not simply “connection_pool = production connection pool”. It contains both:

- deterministic pool semantics and counters: **Implemented**;
- a generic realized-handle pool: **Implemented**;
- concrete product socket factory/composition: **caller-owned and must be traced independently**.

This model→realized pattern is likely to recur in other connectivity modules and should be recorded whenever both generations coexist in one source file.

### 87.2 Encryption is cryptographically substantive but explicitly zero-network

`encryption.rs` is not a crypto placeholder. It contains X25519 static + ephemeral keys, mixed-DH session-key derivation, HKDF-SHA256, ChaCha20-Poly1305 directional keys, authenticated frame headers, sequence-derived nonces and a replay window.

The module comments explicitly claim forward secrecy at the cryptographic handshake level by mixing static↔ephemeral and ephemeral↔ephemeral DH material. It also explicitly states that real online handshake transport, retransmission and key-rotation scheduling remain outside the module.

This yields a precise distinction:

- cryptographic protocol/state machine: **Implemented**;
- authenticated encryption/decryption and replay protection: **Implemented**;
- actual network handshake delivery/retransmit lifecycle: **not owned by this module**;
- product proof that all relevant transport paths use this encryption module: **must not be inferred from its existence**.

This is especially important because Nexus also has `nexus-fabric` TLS/QUIC encryption. The repository therefore contains more than one encryption mechanism serving different generations/paths; documentation should not collapse them into one global “Nexus encryption layer”.

### 87.3 The connectivity dataplane pipeline is a real wire-format feature, but it belongs to `VirtualSubnetTunnel`

`dataplane_pipeline.rs` attaches firewall, token-bucket QoS, compression and fragmentation to the `VirtualSubnetTunnel` packet path. When enabled, the wire format changes to a versioned `NXP1` envelope; empty configuration preserves legacy bytes exactly.

Its egress order is:

firewall → QoS → compression → fragmentation → carrier.

Its ingress order is:

reassembly → decompression → firewall → QoS → accounting → legacy inner-frame delivery.

Malformed/unknown pipeline input is not silently accepted; firewall-enabled ingress also fails closed when the inner tunnel header cannot be parsed.

This is significant implementation, but it should not be confused with the newer `nexusd::Dataplane` pipeline. The connectivity pipeline is tied to the older `VirtualSubnetTunnel` abstraction, while the daemon packet owner uses `nexus-projection` classifier/TCP primitives, CAKE scheduling, N1 and ProxyEngine.

Therefore the repository contains yet another dataplane generation boundary:

- `connectivity::VirtualSubnetTunnel + DataplanePipeline`;
- `projection` top-level routing/egress dataplane;
- `nexusd::Dataplane` product composition.

Some lower-level mechanisms are shared conceptually, but the top-level owners are not one continuous implementation.

## 88. `VirtualSubnetTunnel` is old in terminology but not merely dead skeleton code

`virtual_subnet.rs` still carries a visibly old P0 narrative in its header: static peers, direct point-to-point semantics, plaintext encapsulation and mock VPI/carrier. Parts of that header are also mojibake/encoding-corrupted, making it unreliable documentary evidence.

The executable body has clearly moved far beyond that header. It imports and uses:

- the real connectivity dataplane pipeline;
- X25519/ChaCha20-Poly1305 encryption state;
- identity management and secret storage;
- replay protection;
- hole-punch state;
- NAT-type-driven path decisions;
- peer locator update events;
- relay fallback events;
- routing/forwarding counters.

This is another strong same-file drift case: the top comment represents an older milestone while later code implements multiple subsequent phases.

The safest baseline description is:

> `VirtualSubnetTunnel` is a substantial older virtual-subnet runtime generation that accumulated encryption, identity, hole punching, relay fallback and the NXP1 dataplane pipeline. It should not be described from its P0 header alone, and it should not automatically be assumed to be the canonical product dataplane now that `nexus-projection` and `nexusd::Dataplane` also exist.

The encoding corruption in the file header is itself worth recording as documentation quality debt because it makes historical comments harder to audit mechanically and manually.

## 89. `apps/nexus` is both product CLI composition and an executable scenario laboratory

A source-level sweep of the very large `apps/nexus/src/lib.rs` explains why reading the app package as one product runtime is misleading.

The crate root labels itself a Composition Root, but it contains at least two qualitatively different classes of executable flow.

### 89.1 Deterministic in-process architecture slices

Functions such as `internet_access_flow` and `service_session_lifecycle` construct Registry records, deterministic measurements, planner snapshots and SessionOwner objects directly in process. They intentionally model architectural ordering and invariant behavior for E4-style machine evaluation.

The source is explicit that some lifecycle points are semantic markers rather than real transport. For example, one service lifecycle path says the connectivity-establishment step expresses ordering and does not fabricate a real network connection.

These functions are excellent executable architecture tests, but they are not evidence of production wiring.

### 89.2 Loopback-real E4 resource flows

The same crate later contains more realistic “remote” flows using real loopback TCP listeners, `FrameStream`, threads and injected probes. `remote_service_access_flow`, for example, starts a local provider listener and drives Discovery → Plan → Session → Connectivity → Service handshake over a real TCP socket.

That is stronger than a pure model test, but it is still an in-process/local-machine test composition rather than proof that `nexusd` production boot assembles the same route across independently managed nodes.

This suggests a four-level interpretation for executable application functions:

1. pure deterministic architecture slice;
2. loopback-real/in-process integration flow;
3. foreground product command root;
4. daemon-owned long-running production route.

The current `apps/nexus` package contains examples of at least the first three. Documentation should not promote all functions in this crate to level 4 simply because they use real sockets or appear in the formal CLI application crate.

## 90. `nexus network up` is a real foreground N1 runtime and preserves the `VpiPump` generation

`apps/nexus/src/network.rs` confirms that `VpiPump` is not merely orphan test code.

`nexus network up` is an actual Linux-only foreground command that:

1. parses N1 configuration;
2. creates/configures a real TUN through `nexus-platform-linux::TunVpi`;
3. builds AggregateDiscovery from static, LSA and mDNS sources;
4. constructs a Fabric-backed N1 dialer;
5. dials configured peers;
6. starts `VpiPump` with the configured IPv4 routes;
7. stays in the foreground until user shutdown.

This is an important correction to any temptation to classify `VpiPump` as “legacy source that production no longer uses”. It is still product-reachable through the foreground `nexus network up` command.

At the same time, nexusd has its separate unified dataplane + `N1MeshBridge` route. Therefore N1 currently has **two product-reachable execution modes**:

- foreground CLI N1 runtime using `VpiPump`;
- daemon mode using `nexusd::Dataplane` + `N1MeshBridge`.

The duplication is therefore architectural/product-level, not merely historical source residue.

### 90.1 Foreground N1 path also exposes another relay-gap fact

`FabricDialer::dial` constructs a `FallbackConfig` whose proxy and TURN fields are `None`, expands the chain, and only handles `PathKind::Direct`; all non-Direct candidates are skipped.

So even though path/fallback abstractions exist, the current foreground `network up` dialer is effectively Direct-only at this point.

This is distinct from the separate NAT/TURN implementations elsewhere in the repository. Again, mechanism existence does not imply command-path reachability.

## 91. The official Evidence root and the `.agents/evidence` archive are different things

The machine architecture policy declares `.evidence` as the authoritative evidence root. The earlier audit already found that the checked-in `.evidence` tree contains only sparse historical RED material at this revision.

The repository also contains `.agents/evidence/e4-plugin-obfs-echo.json`. That file records useful historical engineering evidence for the plugin work, including unit tests, a real loopback E4 run, review notes and a full-verify attempt.

However, the record itself is bound to a different historical revision (`d9691bff...`) and reports the full verify verdict as `FAIL`, despite many individual gates/scenarios passing.

Therefore:

- `.agents/evidence` is useful engineering history;
- it is **not** the configured Harness evidence root;
- its records must not be counted as current-revision PASS evidence;
- “there is an E4 JSON file in the repo” is not equivalent to “current master is E4-certified”.

This distinction should be preserved in the final Evidence chapter because two similarly named evidence locations otherwise invite accidental overclaiming.

## 92. Earlier baseline statement that Harness has no Nexus product-crate dependencies is incorrect

A direct read of `engineering/nexus-harness/Cargo.toml` corrects an earlier statement in the baseline.

The Harness binary has direct path dependencies on:

- `nexus-connectivity`;
- `nexus-dns`;
- `nexus-projection`.

The machine architecture policy explicitly allows those same dependencies for `nexus-harness`.

Therefore the correct current fact is:

> Production code must not depend on engineering code, but engineering/Harness code **is allowed to depend on selected product crates** for checks/verification.

This remains a valid one-way dependency architecture. What was wrong was the stronger claim that Harness had no Nexus product-crate dependencies at all.

The final canonical baseline must correct that text rather than carrying both statements forward.

The Harness's operational constraints still remain important: its command dispatcher records unimplemented replay as `UNKNOWN`, not PASS; FAIL exits 1 and BLOCKED exits 2. The dependency correction changes the architectural description, not the verdict semantics.

## 93. N2 now has three identity/encryption generations that must be kept separate

Several pieces of current source can look contradictory until their scope is separated.

### 93.1 N1/remote-P0 PSK authorization remains

`nexus-auth::verify_token` implements constant-time PSK comparison for the older remote-host/N1 path. Source explicitly says it must not be reused as N2 resource authorization.

### 93.2 N2 authorization identity is ed25519 and explicit TOFU

N2 `Principal` is derived from a verified ed25519 public key. Grants are provider-local, operation-scoped, optionally expiring and revocable. Unknown peer identity produces `UnknownFirstSeen` rather than silent learning.

The `apps/nexus` N2 identity file persists an ed25519 seed/public key under the N2 store and derives a stable principal from it. Its initialization lock protects same-process cold creation, while cross-process shared-directory initialization remains an external ownership concern.

### 93.3 N2 admission's mutual identity proof is not an encrypted channel

`n2_admission` uses signed challenges in both directions and verifies provider trust, but runs over its own framed TCP/JSON protocol. The module explicitly states no confidentiality and no forward secrecy for this admission channel.

This is independent from `nexus-connectivity::encryption`, which has a forward-secret X25519/AEAD handshake state machine, and independent again from `nexus-fabric`, which uses TLS/QUIC.

So a global sentence such as “Nexus uses mutual identity + forward-secret encryption” would be false without naming the path. Current security properties vary by subsystem and protocol generation.

## 94. Current runtime duplication is broader than daemon-vs-CLI; it is a repeated migration pattern

After this pass, overlapping runtime ownership appears in several independent areas:

| Concern | Older/alternate runtime | Newer/other runtime | Current product reachability |
|---|---|---|---|
| N1 packets | `VpiPump` | `nexusd::Dataplane + N1MeshBridge` | both reachable |
| virtual subnet dataplane | `VirtualSubnetTunnel + DataplanePipeline` | Projection / nexusd dataplane family | source mature; canonical owner unclear |
| projection/TUN orchestration | `nexus-projection` top-level engine | `nexusd::Dataplane` | daemon reuses projection primitives but owns orchestration |
| N2 operation | CLI-local use/session/resource/grant/provider | daemon global SessionManager + LocalAPI | both styles reachable |
| NAT/path switching | `NatSwitching` production-shaped stack | normal daemon startup | mechanism exists; daemon route not enabled |
| connectivity features | pure skeleton/state-machine modules | realized/pipeline variants | mixed; per-feature composition required |
| app E4 flows | in-process/loopback composition | daemon/foreground commands | tests and product roots coexist in same app package |

This is now the dominant architectural pattern of the repository: new generations are frequently added **next to** old generations before ownership is fully retired or unified.

That pattern explains much of the documentation drift. A design document that says “the subsystem now works like X” becomes stale as soon as X is introduced but the previous path remains product-reachable.

The future target-state work should therefore require a deletion/retirement answer for every major migration:

- Which runtime becomes authoritative?
- Which compatibility/foreground path intentionally remains?
- Which old path is deleted?
- What scenario proves the deleted path is no longer needed?
- What config/CLI/API surface, if any, preserves backwards compatibility?

Without explicit retirement criteria, another architecture rewrite alone will recreate the same overlap.

## 95. Corrections that must be applied when the staging appendices are merged

The canonical `CURRENT_STATE.md` must not merely concatenate the appendices. Several earlier statements now need replacement or qualification.

Required corrections include:

1. **Harness dependencies:** replace “Harness has no Nexus product-crate dependency” with the one-way dependency fact: production cannot depend on engineering; Harness directly depends on selected product crates.
2. **VpiPump status:** do not call it merely legacy/older source; `nexus network up` still uses it in a real Linux foreground product path.
3. **Connectivity skeletons:** avoid flat labels. Some files contain both deterministic skeleton and later realized-handle implementation.
4. **VirtualSubnetTunnel header:** do not use its P0/plaintext/static header as current truth; executable code contains encryption, identity, punching and the NXP1 pipeline.
5. **N1 fallback:** path abstractions and TURN support elsewhere do not make the foreground `network up` FabricDialer relay-capable; inspected dial logic currently only consumes Direct candidates.
6. **Evidence locations:** distinguish official `.evidence` from historical `.agents/evidence` records.
7. **Application functions:** separate deterministic E4 architecture slices, loopback-real integration flows, foreground product commands and daemon routes.
8. **Security wording:** identify protocol/path when claiming authentication, confidentiality or forward secrecy; different generations have different properties.

These are substantive current-state corrections, not editorial cleanup.

## 96. Updated priority list after the fourth continuation

The source sweep now points to a narrower set of remaining high-value questions:

1. **Connectivity hot-path reachability:** for each `nexus-connectivity` feature module, identify whether a real composition root constructs it, whether it is only scenario-tested, or whether it remains an isolated model.
2. **N1 discovery runtime:** `network up` constructs static + LSA + mDNS aggregate discovery; trace whether mDNS/LSA receive/update loops actually run continuously or are merely queryable state sources.
3. **Daemon PathManager inputs:** determine exactly where live candidate paths are inserted into the daemon dataplane manager and whether `boost_enabled` has meaningful production inputs.
4. **Workspace sync startup:** find an actual product invocation of the passive Fabric sync server/client or conclude that the transport remains unbound.
5. **Projection canonicality:** identify which `nexus-projection` top-level APIs are product-reachable beyond being reused as components by nexusd.
6. **Scenario realism:** classify remaining high-value scenarios as pure deterministic, loopback-real, namespace/network-real, or external-environment dependent.
7. **Current CI/Evidence:** inspect current revision GitHub workflow/check status and current Harness outputs if a certification claim is required.
8. **Final consolidation:** merge sections 55–96 into `CURRENT_STATE.md`, correcting earlier statements rather than blindly appending contradictions.

The central diagnosis is now strongly supported: Nexus Fabric is not missing mechanisms so much as it is carrying several generations of mechanisms simultaneously. The decisive architectural work is runtime ownership, production reachability, retirement criteria and evidence freshness.
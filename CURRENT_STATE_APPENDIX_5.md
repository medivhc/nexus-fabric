# Nexus Fabric Current State — Deep Audit Continuation V

> Continues `CURRENT_STATE_APPENDIX_4.md` after section 96.
> Source baseline: `48918863e70ef8589fbca6075c7ec11ca07e85a3` on `master`.
> This file remains staging material for the canonical `CURRENT_STATE.md`; findings here are source-derived current-state facts, not target-architecture decisions.

## 97. Foreground N1 constructs multi-source discovery, but the inspected runtime only proves a live Static source

`apps/nexus/src/network.rs` deserves a narrower reading than section 90 originally gave it.

`DiscoveryAdapter::new()` does construct an `AggregateDiscovery` containing three objects:

1. `StaticDiscovery`, populated from `network.toml` peers;
2. a newly created `Lsdb`;
3. an `MdnsDiscovery` instance.

However, object construction is not the same as a running discovery source.

The `nexus-discovery` mDNS implementation is deliberately zero-I/O. Its source requires the composition root to own the UDP/5353 socket, configure multicast, send queries/announcements, feed received datagrams through `handle_datagram`, prune the cache and drive the lifecycle. `AggregateDiscovery` itself merely merges already-populated source results with deterministic priority; it does not run any discovery I/O.

In the inspected foreground `network up` composition, no mDNS socket/pump/feed loop is attached to the constructed `MdnsDiscovery`, and the newly created `Lsdb` is not shown receiving LSAs before `N1Discovery::resolve()` reads from the aggregate. The code path simply calls `Discovery::resolve(&self.agg, peer)`.

Therefore the accurate current-state claim is:

- multi-source discovery **object graph**: Implemented/Wired into the foreground N1 adapter;
- configured Static peer source: **populated and product-reachable**;
- live mDNS network discovery in this foreground path: **not wired in the inspected composition**;
- live LSA feed into the fresh `Lsdb`: **not wired in the inspected composition**;
- effective foreground resolution at boot, absent another hidden feeder, is therefore dominated by the configured Static source.

This corrects the broader section-90 wording that `network up` “builds AggregateDiscovery from static, LSA and mDNS sources” if that phrase is read as all three being operationally live.

It is another instance of the repository-wide pattern:

> constructing a source object is weaker evidence than starting the source's producer/pump.

## 98. Workspace Fabric sync is implemented as a caller-driven adapter but is absent from the normal `WorkspaceManager` lifecycle

The Workspace sync gap can now be stated more strongly than “startup binding is unproven”.

`apps/nexusd/src/sync_transport.rs` is a real Fabric-backed `WorkspaceTransport`. It owns framing, stream type `0x03`, bounded frame size, receive deadline handling and an authorization wrapper. But the module explicitly leaves connection acquisition and passive routing to its caller:

- active side: the caller obtains an already-active connection, e.g. through `NatSwitching::active_conn(peer)`, then calls `FabricSyncTransport::open()`;
- relay passive side: the caller must consume `PunchManager::take_unclaimed()` and route stream type `0x03` into `serve_sync_authorized()`;
- direct passive side: the caller must accept bi-streams and classify the stream type before constructing the transport.

The normal Linux daemon Workspace owner, `apps/nexusd/src/workspace.rs`, does not perform any of those actions. Its lifecycle is local:

`workspace.toml`
→ open/create CAS-backed Workspace
→ FUSE mount
→ optional auto-commit
→ LocalAPI commit/status
→ shutdown/unmount.

That module does not own Fabric connections, NAT switching, sync accept loops, `SyncAuthorizer`, or stream routing. `apps/nexusd/src/lib.rs` merely exports `sync_transport` as a reusable module; export is not startup wiring.

Current classification is therefore:

- Workspace sync protocol in `nexus-workspace`: **Implemented**;
- Fabric sync transport adapter: **Implemented**;
- membership authorization algorithm: **Implemented**;
- trustworthy inbound Fabric principal: **not closed** because Fabric P0 server-side peer identity remains insufficient for this purpose;
- normal `WorkspaceManager` startup automatically serving/initiating remote sync: **not wired** at this revision.

This is a material distinction. Local Linux Workspace projection is product-wired; cross-node Workspace synchronization is currently a separate composition capability, not an automatic property of mounting a Workspace in nexusd.

## 99. Connectivity capability status needs at least four independent axes

The source sweep has now produced enough counterexamples that a one-column maturity label is no longer adequate.

For each capability, the baseline should independently answer:

1. **Mechanism Implemented?** — does executable code implement the state machine/algorithm/adapter?
2. **Scenario-targeted?** — is there a machine-readable scenario that executes or specifies it?
3. **Product Wired?** — does a real foreground/daemon composition root instantiate it in the relevant product path?
4. **Revision-bound Verified?** — is there current evidence bound to this source revision showing the intended verification result?

`Production-closed` remains a stronger fifth conclusion, requiring not only wiring but also authority/security/lifecycle/operational closure appropriate to that capability.

This model prevents several recurring category errors:

- a crate can be Implemented but not Wired;
- a scenario can be E4-labeled but current revision evidence can still be absent;
- an example can execute a module without making the daemon use it;
- a daemon can wire a mechanism while a security property around it remains unclosed.

These axes should replace statements such as “feature X is done” unless the intended axis is explicitly named.

## 100. Many Connectivity batch-2 through batch-6 features are executable scenario targets, but that does not make them daemon hot-path features

The product scenario pack gives substantial executable coverage to `nexus-connectivity` modules. Examples include:

- connection-pool;
- health-check;
- node-priority;
- auto-reconnect;
- config-hot-reload;
- graceful-exit;
- traffic-stats;
- bandwidth-policy;
- group-isolation;
- discovery-enhanced;
- failover;
- smart-retry;
- certificate-manager;
- log-level;
- node-tags;
- firewall-rules;
- bandwidth QoS;
- CAKE-like QoS;
- Mesh DNS;
- compression;
- fragmentation.

Most of these scenario files declare `evidence_strength = "E4"` and run either a dedicated `nexus` example or a harness-side scenario implementation. This is meaningful: they are not merely dead source modules; there are executable behavioral contracts around them.

But the scenario bodies also show why `Scenario-targeted` must remain distinct from `Product Wired`.

For example:

- `product.connection-pool` checks logical `conn_id`, reuse, exhaustion, idle eviction and counters; those expectations target the deterministic pool semantics rather than proving a daemon uses `RealizedPool` with real production sockets.
- `product.health-check`, `product.failover`, `product.smart-retry`, `product.group-isolation`, `product.bandwidth-policy`, `product.node-priority`, `product.log-level` and similar scenarios primarily exercise their state machines/models in isolated examples.
- `product.traffic-stats` exercises aggregation through an example rather than proving the daemon feeds every production packet/session into that statistics module.
- `product.config-hot-reload` tests the connectivity-level revision/validation model; it is not identical to the separate nexusd directory watcher and subsystem reassembly problem.
- `product.certificate-manager` verifies certificate validity classification/rotation semantics in an example; that does not prove the daemon's Fabric/TLS identity lifecycle is driven by this manager.

A stronger counterexample is CAKE: `nexus-connectivity::cake::CakeScheduler` is both scenario-targeted and actually imported by `nexusd::Dataplane`. Its scenario even validates daemon QoS config mapping. CAKE therefore has stronger production reachability than many neighboring batch modules despite appearing beside them in the same crate.

The correct baseline unit is consequently the individual capability and call path, not the source-directory batch label.

## 101. Compression has outgrown stale “identity skeleton” comments inside both source and scenario text

`nexus-connectivity/src/compression.rs` is a particularly clear same-file drift example.

The current executable implementation uses:

- `flate2` for real gzip compression/decompression;
- `lz4_flex` for real LZ4 compression/decompression;
- adaptive minimum-size gating;
- algorithm tags and original-length checking;
- statistics over actual encoded payload lengths.

`CompressionCodec::encode()` really invokes gzip/LZ4 when the algorithm and size threshold select compression, and `decode()` performs the corresponding real decompression.

Yet several lower-level comments in the same file still say things such as “Gzip/Lz4 identity passthrough, real implementation TODO”, “payload is a placeholder identity copy”, or imply compression level is only recorded. Those comments describe an earlier implementation generation and contradict the executable code below them.

The product scenario has a related stale phrase: it explains `ratio == 0` as “骨架身份透传”. The example source shows the actual reason is different: it deliberately generates high-entropy data so **real gzip does not shrink it**, and the ratio calculation clamps non-beneficial expansion to zero. The same example still verifies that the above-threshold block is marked compressed and successfully round-trips through the real codec.

Therefore current status is:

- gzip implementation: **Implemented**;
- LZ4 implementation: **Implemented**;
- adaptive compression model: **Implemented**;
- executable scenario: **Scenario-targeted**;
- integration into `VirtualSubnetTunnel`'s `DataplanePipeline`: **Wired for that runtime generation when configured**;
- integration into the separate `nexusd::Dataplane` packet owner: **not established by this mechanism alone**.

The stale identity/TODO comments should be treated as drift evidence, not current implementation truth.

## 102. NAT scenarios, NAT mechanisms and daemon NAT wiring represent three different evidence levels

NAT is another area where a single “E4 exists” statement would be misleading.

The scenario pack itself is unusually explicit about this distinction.

`product.nat-hole-punching` records a prior truthfulness correction: an older driver had fabricated a public mapping/NAT type/success result. The current frozen scenario instead verifies RFC5389/STUN codec behavior, optionally observes a real STUN mapping, fixes NAT type to `Unknown` under insufficient evidence, and explicitly marks true two-peer public-Internet hole punching as deferred.

Other scenarios are stronger in different but still bounded ways:

- `product.relay-fallback` executes a composition that models direct punch failure followed by relay data forwarding;
- `product.remote-nat-relay-fallback-flow` uses an in-process Node-R relay and real local TCP forwarding to exercise Direct-fail → Relay-fallback → Service access semantics.

Meanwhile the repository separately contains substantial NAT implementation machinery:

- NAT classification/prediction and punch state machine;
- Fabric punch wire-up;
- quality probing;
- `PathManager` integration;
- `nexusd::NatSwitching` production-shaped orchestration.

But section 76 already established that normal nexusd startup does not instantiate `NatSwitching`.

The honest current-state description is therefore:

- NAT algorithms/mechanisms: substantially **Implemented**;
- several NAT/relay behaviors: **Scenario-targeted** with different realism boundaries;
- a production-shaped daemon adapter: **Implemented**;
- normal daemon startup NAT-switching closure: **not Wired**;
- real cross-public-host punch success as represented by the `nat-hole-punching` scenario: explicitly **deferred**, not silently claimed PASS.

This is a good example of why each scenario's frozen semantics must be read rather than inferring capability strength from its filename or `E4` label.

## 103. Evidence-root correction: `.evidence` is gitignored/local; `.agents/evidence` is a separate tracked historical archive

Section 91 needs an explicit correction before final merge.

The root `.gitignore` contains:

- `/target`;
- `/.claude`;
- `/.evidence`.

Therefore the Harness-configured `.evidence` root is intentionally local/gitignored in the current repository configuration. A normal repository tree cannot be used to infer a checked-in current-revision PASS/FAIL set from `.evidence`.

The tracked `.agents/evidence` directory is a different engineering-history channel. The currently inspected `e4-plugin-obfs-echo.json` is useful provenance, but it is bound to historical revision `d9691bff...` and its own `full_verify.verdict` is `FAIL` despite many individual checks/scenarios passing.

Canonical merge correction:

- remove/replace any earlier claim that the repository has a checked-in authoritative `.evidence` RED set at the baseline revision unless a separately proven tracked path exists;
- describe `.evidence` as the official Harness evidence root but gitignored/local;
- describe `.agents/evidence` as tracked historical engineering evidence, not current certification;
- keep current-revision verification status `Unknown/insufficient` unless an actual bound Harness result is obtained from a runtime/artifact source.

This is a substantive evidence-model correction.

## 104. Four-axis capability snapshot after the fifth continuation

The following matrix is a better current-state representation than a flat “implemented/not implemented” table.

| Capability | Mechanism | Scenario-targeted | Product/daemon wiring | Current revision-bound verification |
|---|---|---|---|---|
| daemon CAKE QoS | Implemented | yes | **yes, nexusd Dataplane** | broad current bound PASS set not established |
| connectivity token-bucket QoS | Implemented | yes | VirtualSubnet pipeline path; separate from daemon CAKE path | not established globally |
| compression gzip/LZ4 | Implemented | yes | VirtualSubnet pipeline when configured | not established globally |
| fragmentation/reassembly | Implemented | yes | VirtualSubnet pipeline when configured | not established globally |
| firewall engine | Implemented | yes | VirtualSubnet pipeline; daemon has different packet composition | not established globally |
| logical connection pool | Implemented | yes | isolated/example use proven | not established globally |
| realized-handle connection pool | Implemented generic seam | scenario does not prove this variant | concrete product factory wiring not found | not established |
| health/failover/retry/group/bandwidth policy models | Implemented | yes | daemon hot-path consumers not established | not established globally |
| N1 Static discovery | Implemented | indirectly/product command | **yes in foreground/daemon N1 config path** | current full bound set absent |
| N1 mDNS object | Implemented parser/cache | source/scenario support exists elsewhere | **foreground live socket/pump not found** | not established |
| N1 LSA database | Implemented | routing/discovery scenarios exist | fresh foreground LSDB feed not found | not established |
| Workspace local FUSE/commit | Implemented | yes | **yes on Linux daemon** | current full bound set absent |
| Workspace Fabric sync adapter | Implemented | tests/mechanism present | **not in normal WorkspaceManager lifecycle** | not production-closed |
| NAT punch/quality/path switching | Implemented | yes, with bounded scenario semantics | NatSwitching exists; **normal daemon does not instantiate** | not production-closed |
| N3 Task provider/local artifacts | Implemented substantially | dedicated tests/scenarios/recorded implementation validation | **yes on Linux configured paths** | some historical/commit-level evidence; not a global current certification |

The main lesson is now measurable: much of the repository's remaining uncertainty is in the third and fourth columns — runtime ownership/wiring and revision-bound verification — rather than in lack of algorithms.

## 105. Required canonical merge work and remaining source sweep

The five staging continuations now contain enough cross-checks that consolidation should become an explicit audit phase rather than simple file concatenation.

During consolidation, the canonical `CURRENT_STATE.md` must apply at least these later corrections to earlier text:

1. mDNS/LSA in foreground N1 are constructed sources, not proven live discovery pumps;
2. Workspace Fabric sync is absent from the normal `WorkspaceManager` lifecycle, not merely “not yet traced”;
3. `.evidence` is gitignored/local; `.agents/evidence` is a separate historical archive;
4. compression is real gzip/LZ4 despite stale skeleton comments;
5. Harness/product scenario `E4` labels must not be promoted to current revision-bound verification;
6. connectivity capabilities need per-feature mechanism/scenario/wiring/verification status rather than batch-level maturity;
7. NAT scenario semantics must be separated from NAT implementation depth and daemon activation;
8. all previous corrections from sections 95 and earlier appendices must be applied, not left as contradictory parallel statements.

Remaining source audit should now prioritize untouched or only partially traced executable surfaces rather than repeatedly rereading already-classified scenarios. High-value remaining areas include:

- composition consumers for remaining connectivity modules;
- exact discovery producer lifecycle outside the inspected foreground N1 path;
- any alternative Workspace sync caller outside `WorkspaceManager`;
- less-audited proxy/outbound/platform code paths;
- final scenario → implementation → composition → evidence cross-index;
- current branch/worktree verification evidence if obtainable through an authoritative runtime/artifact channel.

At this point the current-state baseline is increasingly a problem of **classification and convergence of facts**, not discovery of the top-level architecture. The canonical merge should preserve contradictions as explicit drift where they are real, while replacing statements that later source evidence has actually disproved.
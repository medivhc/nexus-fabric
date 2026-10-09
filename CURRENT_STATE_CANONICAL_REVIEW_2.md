# CURRENT_STATE canonical draft — review round 2

> Reviewed draft: `CURRENT_STATE_CANONICAL_DRAFT.md` at blob `8f18af3baba9b332ec58ce1ec93be6574963d24d`.
>
> Source revision under review: `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573`.
>
> Purpose: adversarially review the canonical draft before replacing `CURRENT_STATE.md`.

## Result

**Not ready to promote yet.** The draft is structurally much cleaner than the old 150-section staging history, but it compresses several implementation areas too aggressively and violates the intended “major claims have code-line anchors” rule in a few sections.

No P0 factual contradiction was found in the sections already source-anchored, but the following P1 omissions would materially weaken the baseline if promoted as-is.

## P1-1 — N2 is under-specified

The draft currently summarizes N2 in one section, but the implementation has distinct identity, durable-store and cross-machine admission semantics that need to remain visible.

Required additions:

1. durable ed25519 identity in `n2/auth-identity`, idempotent cold creation, public-key consistency check and 0600 tightening;
2. explicit limitation: the initialization mutex is process-local; cross-process cold initialization of a shared node directory still requires external ownership coordination;
3. admission v2 is mutual challenge-response: requester proves requester key; provider signs requester challenge; requester validates provider through `TrustStore` / explicit TOFU policy;
4. no confidentiality / no forward secrecy at the N2 admission protocol layer;
5. admission has bounded frame size, 64 max concurrent connections and bounded I/O behavior;
6. N2Store persists sessions with full PlanSnapshot, grants, audit, directory advertisements/names/audit and control-frame outbox;
7. boot/recovery model is KV truth + journal replay + session reconciliation;
8. persisted `TerminalOutcome::Failed(NexusError)` is lossy: debug reason is persisted and reloaded as `NexusError::Internal`, so exact typed failure variant is not round-tripped.

Source anchors:

- [`apps/nexus/src/n2_identity.rs` L1-L16](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_identity.rs#L1-L16)
- [`apps/nexus/src/n2_identity.rs` L68-L132](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_identity.rs#L68-L132)
- [`apps/nexus/src/n2_admission.rs` L1-L31](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_admission.rs#L1-L31)
- [`apps/nexus/src/n2_admission.rs` L50-L82](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_admission.rs#L50-L82)
- [`apps/nexus/src/n2_store.rs` L1-L27](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_store.rs#L1-L27)
- [`apps/nexus/src/n2_store.rs` L102-L141](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/n2_store.rs#L102-L141)

## P1-2 — N3 durability/recovery is too compressed

The draft accurately says the Task/Artifact CLI is real, but it omits the provider/runtime crash-consistency model that was one of the strongest parts of the audit.

The promoted baseline should preserve these facts:

- durable acceptance is separate from runtime journal and requester mirror/outbox;
- accepted task identity / canonical request / receipt are durable authority;
- runtime recovery does not silently launch replacement execution when previous execution identity is ambiguous;
- StartIntent is persisted before executor start;
- Artifact publication requires natural-exit/proof/inventory/hash checks before Published;
- requester-side Artifact download is a separate strong no-replace receiver with cross-process lease, exact resume offset, prefix integrity and inode/publication checks on Linux.

The existing Task CLI line anchors already cover requester behavior, but provider-side anchors still need to be attached before final promotion.

## P1-3 — proxy protocol matrix needs direct line anchors for AnyTLS/VLESS/Hysteria2

The draft’s protocol matrix is correct relative to the prior sweep, but several foreground protocol claims rely on earlier audit prose rather than direct line anchors in the canonical file.

Required anchors:

- AnyTLS arm: [`apps/nexus/src/lib.rs` L5207-L5480](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/lib.rs#L5207-L5480)
- VLESS arm and Vision limitation: [`apps/nexus/src/lib.rs` L5520-L5755](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/lib.rs#L5520-L5755)
- Hysteria2 TCP-proxy arm and explicit UDP/port-hop/Brutal limits: [`apps/nexus/src/lib.rs` L5756-L5865](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/lib.rs#L5756-L5865)

Also preserve that foreground SOCKS5 outbound is explicitly deferred in this app path even though daemon ProxyEngine supports SOCKS5. That is another runtime-specific asymmetry.

## P1-4 — Workspace identity/durability distinction needs more detail

The draft covers the local commit/anchor crash window and sync auth boundary, but it omits the important storage-model split discovered earlier:

- legacy Workspace/CAS object identity is not the same strong content-identity scheme as N3 StrongContentStore/Artifact SHA-256 semantics;
- the canonical baseline must not imply that all Nexus storage uses the same collision/integrity contract.

This should be retained as a cross-domain integrity distinction, even if the canonical document avoids restating every old implementation detail.

## P1-5 — “small crates” section lacks line anchors

The sections for `nexus-service`, `nexus-delivery`, `nexus-diagnostics`, `nexus-proto`, ingress and Connectivity currently rely on prior sweep conclusions without direct source-line links. That violates the line-traceability gate.

Before promotion either:

- attach commit-pinned source ranges for each statement; or
- downgrade these to a compact inventory whose detail is explicitly delegated to `CURRENT_STATE_SOURCE_MAP*.md`.

The first option is preferred because the user requested the file itself to connect to code lines.

## P1-6 — LocalAPI/config/recovery lifecycle is under-represented

The old audit established meaningful daemon lifecycle facts that should not disappear merely because the canonical document is shorter:

- config directory ownership and hot reload;
- boot ordering: recovery/session reconcile before new work, dataplane/LocalAPI/workspace startup ordering;
- shutdown ordering;
- LocalAPI ordinary GET routing vs versioned N3 task HTTP split;
- Windows named-pipe absence / TCP fallback;
- no silent fallback on unsupported capability.

The canonical document can compress these, but should preserve the ownership and recovery boundaries because they affect architecture.

## P1-7 — `Verified` section should explicitly separate current code revision from commit-message claims

The draft already states the principle but should make the reviewed revision situation explicit:

- `master` commit message says tests/gates passed;
- that prose is useful historical context only;
- no checked-in revision-bound `.evidence` artifact is being used here to upgrade the product to `Verified`.

This prevents future readers from reading the current commit subject as equivalent to Harness Evidence.

## P1-8 — staging cleanup plan must be explicit

Promotion should not leave readers with several competing “canonical-looking” files.

Recommended final branch state:

- `CURRENT_STATE.md` — sole canonical baseline;
- `CURRENT_STATE_SOURCE_MAP.md` + `_2.md` — optional source-index companions;
- `CURRENT_STATE_MERGE_REVIEW.md` / `CURRENT_STATE_CANONICAL_REVIEW_2.md` — review history if desired;
- `CURRENT_STATE_APPENDIX*.md` and `CURRENT_STATE_CANONICAL_DRAFT.md` — remove after canonical promotion, or move under an obvious audit-history directory.

Leaving Appendix 1–10 beside a canonical file preserves contradictory current-state prose and defeats the convergence goal.

## Promotion gate

Before replacing `CURRENT_STATE.md`:

- [ ] expand N2 identity/admission/store/recovery semantics;
- [ ] restore N3 provider-side durability/recovery detail with code anchors;
- [ ] add direct foreground AnyTLS/VLESS/Hysteria2 line anchors;
- [ ] preserve Workspace legacy-vs-N3 integrity distinction;
- [ ] line-anchor ingress/connectivity/small-crate statements or reduce them;
- [ ] preserve daemon config/recovery/startup/shutdown boundaries;
- [ ] explicitly state commit-message test claims are not `Verified` evidence;
- [ ] run a contradiction pass for `50 members`, workspace-intel omission, “thin client”, N3 help text, proxy global support, NAT normal-daemon activation and `.evidence` checked-in claims;
- [ ] only then replace `CURRENT_STATE.md` and clean up staging appendices.

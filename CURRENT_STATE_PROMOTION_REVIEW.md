# CURRENT_STATE promotion review

> Candidate blob: `CURRENT_STATE_CANONICAL_DRAFT.md` = `1522640adf2d08af4742cbae1800f5909b0b2672`.
>
> Reviewed source revision: `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573`.

## Verdict

**PASS for canonical promotion.**

This review was performed after the adversarial round in `CURRENT_STATE_CANONICAL_REVIEW_2.md`; the candidate was rewritten to address every P1 promotion blocker identified there.

## Checks performed

- Workspace count is 51 and `nexus-workspace-intel` is explicitly a member; no current-state claim retains the old 50-member/omission conclusion.
- Generated `/.evidence` is described as gitignored; commit-message PASS claims are explicitly not treated as revision-bound Harness Evidence.
- `nexus` is not globally described as a thin client; CLI-owned and daemon-owned composition roots are both represented.
- Normal `nexusd::run_dataplane` is explicitly distinguished from optional `enable_flow_sessions()`; the candidate states normal activation is Not Wired.
- N1 foreground `VpiPump`/AutoMesh and daemon `Dataplane + N1Sender` are represented as separate runtime shapes.
- `NatSwitching` is represented as implemented but explicitly not instantiated by normal daemon composition.
- Foreground ProxyService, daemon TUN ProxyEngine and per-link Fabric-over-proxy transport are separate ownership planes.
- Foreground AnyTLS/VLESS/Hysteria2 claims now have direct immutable line anchors; runtime-specific SOCKS5/VMess/Relay limitations are retained.
- Workspace local FUSE/CAS lifecycle is separate from Fabric sync; server-side sync peer identity limitation is retained.
- Legacy Workspace FNV object identity is explicitly separated from N3 SHA-256 StrongContentStore semantics.
- N2 identity, mutual admission, no-confidentiality/no-PFS boundary, durable store/recovery and lossy typed-Failed round-trip are retained with source anchors.
- N3 LocalAPI transport is distinguished from provider-side public Submit closure. Public Submit is explicitly described as currently refused until capacity/Session/authenticated-input prerequisites are assembled.
- N3 acceptance authority and executor recovery semantics retain fail-closed/no-replacement behavior and StartIntent-before-start ordering.
- Scheduler remains a durable manually ticked registry with synthetic submit, not an autonomous executor.
- Connectivity/Ingress/Service/Delivery/Diagnostics/Proto maturity statements now have direct source anchors.
- Linux/Windows are substantive; macOS/Android/iOS skeleton status has direct source anchors.
- Major capability/ownership paragraphs use immutable `e6ccf8b8.../path#Lx-Ly` code links.

## Promotion action

Promote this exact candidate blob to `CURRENT_STATE.md`. After promotion, earlier `CURRENT_STATE_APPENDIX*.md` and the temporary canonical draft are staging history and must not be treated as parallel current truth. They should be deleted or moved out of the canonical root in the cleanup step.

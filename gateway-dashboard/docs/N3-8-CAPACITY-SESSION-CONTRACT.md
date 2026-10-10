# N3-8 Capacity and existing Session ownership contract

Task type: requirement-change (additive N3 foundation). Base: ccc7c0dc47e1d0c1d25c009632d630851d914275.

## Scope and owners

This slice supplies real durable capacity accounting and binds trusted provider-internal Tasks to existing N2 Sessions. LocalAPI/CLI Submit and complete artifact download remain UnsupportedCapability. The original 22 complete N3 E4 expectations and public DTOs remain protected. No new Planner, SessionManager, dependency edge, or protocol operation.

## Capacity authority

Explicit operator allocation covers CPU millicores, memory bytes, PID slots, writable runtime storage, retained backend disk, and concurrent tasks. Policy includes a nonzero fixed provider reserve and conservative per-task executor overhead; PID demand includes the current sandbox's 256 PIDs. Backend accounting includes bounded archive, two input copies, logs, materializations, publication temporaries and metadata overhead. Checked arithmetic is bounded by 2^53-1. These are configured admission allocations, not measured host free capacity or a universal OOM/ENOSPC guarantee.

Private checksummed acceptance envelope v2 atomically publishes public acceptance ledger plus policy, exact Task/contract/reservation links, readiness and capacity charges under acceptance.lock. Public AcceptanceLedger/AcceptedContract/schema remain unchanged. Only explicit fresh-empty provisioning can initialize or finish an interrupted upgrade; legacy accepted tasks cannot be silently enrolled. Capacity receipts prohibit v1 downgrade or empty rebuild after authority loss. Existing v1 query/library fixtures remain readable, but real new execution requires concrete capacity.

New acceptance and reservation are all-or-nothing with Task, scoped key and input pin. Same scoped-key replay retains its original Task/id/digest/TTL and allocates nothing, including when budget is exhausted or reconciliation is Pending. Conflict, exhaustion, corruption and publication errors acknowledge no new Task.

A live fixed-inode capacity-owner flock and fresh epoch are required in addition to durable Ready. Each process boot enters Pending before recovery; owner loss cannot authorize admission. Every new accept, Prepare/StartIntent and Snapshot GC checks live Ready under the same acceptance lock. Read/replay/reconciliation remain possible while Pending. Start verifies exact RuntimeHeld reservation internally, even if external authorization callback returns Ok.

Recovery validates all authority links, runtime sequence, Snapshot roots and original executor evidence before Ready. Missing/unknown execution state keeps reservation and blocks new admission/GC. Released owner lease, Engine 404, PID or Task terminal outcome alone do not prove reap. Runtime capacity release is proof-bound, idempotent and atomic against new starts; verified never-executed cancellation requires absence of execution authority. All retained backend disk charges remain held in this slice until future physical cleanup.

## Existing Session integration

Daemon config-folder is authoritative; NEXUS_CONFIG_DIR must not redirect that entry's N2 or Task ownership. TCP/socket compatibility entries derive one explicit root. Composition root creates one Arc/Mutex SessionManager once, injects it into TaskService, and retains existing sweep/shutdown ownership. Manager failure degrades explicitly.

Trusted Rust prepare_with_existing_session is the only new preparation entry (no wire operation). It checks authenticated principal/current Use, workspace/resource/provider, concrete capacity, actual Manager-owned Active/Unfinished Session and persisted canonical Plan/trace and N2 names. Session already attached to another Task is rejected. TaskOwner appends deduplicated SessionAttached events; accepted initial session_ids stays empty. GET and Submit never create Sessions.

Boot consumes existing bindings and durable cleanup intents. Confirmed Task cancellation closes attached Sessions through the original Manager, only after durable cleanup intent. Requested or unknown cancellation never closes early. Cleanup is completed only after same-root durable Disposed evidence. Failed saves retain intent and reload the original Manager's actual durable records before retry. Existing Session terminal outcomes remain unchanged; Session Failed/Disposed never invents Task failure. TaskOwner and SessionManager remain separate sole outcome writers.

## Verification mapping

product.n3-8-foundation-boundary (E4): real no-TUN config-folder daemon with deliberately different environment root; authenticated N2 list; explicit root owns N2, decoy untouched, one Manager, child reaped; real CLI Submit/artifact get refuse and leave acceptance/output untouched. No host interfaces or network privilege changes.

Capacity/Session authority tests (E2/E3): exact/exhausted dimensions, checked overflow, scoped replay/conflict, concurrent independent-process acceptance, corruption/receipt loss, interrupted provisioning, live-owner death, unknown execution, no-op callback rejection, idempotent proof-based release with retained disk; actual existing Session Plan validation, deduplication, cross-task refusal and durable cancellation cleanup/recovery. Genuine Engine fixture tests run only when available; missing capabilities remain UNKNOWN/BLOCKED.

Baseline Red executes new E4 expectations against actual CCC daemon/CLI artifacts before implementation. Contract/scenario hashes freeze after Red. Check -> affected -> Fast -> independent eight-dimension review -> Full; existing network failures and unavailable full N3/Windows evidence remain visible.

# Independent review — gateway file service, round 5 (evidence audit)

Reviewer host: Windows x64 (win32) + Git Bash. Toolchain actually invoked: **none**.
This crate cannot be compiled on this host (`ssh2 0.9.6`'s `userauth_pubkey_memory` is gated by
`cfg(any(unix, vendored-openssl, openssl-on-win32))`; no cl.exe/nasm). **Nothing was built or run here.**
Every claim below is decidable by reading plus integer arithmetic; no std-only probe was needed.
The implementer's measurements on xc-pc-linux (56 lib tests, clippy clean, 9/9 scenarios = 86 expectations,
`verify --fast` 9 gates, contract_hash `8f510129cd7d9bef054d2324a4517fc534ab9806`) are **not reproduced and not
used as evidence** for anything I could check by reading.
Reviewed content: working tree on top of `af953af8849c5549f78f77add4ef5441faba4267`, content tree `20362c24…`.

## Verdict: **CHANGES_REQUESTED**

The batch's *headline* evidence claims are mostly real this time (R4-W-2, R4-W-3, R4-W-4, R4-NEW-1 verified with
kill power; R4-W-6/W-7 declarations verified verbatim). But one claimed kill is inert, one newly-charged quantity
got no paired validation, and two r4 WARNs plus one claimed "documented" item are simply not in the tree.

---

## 1. R4-NEW-1 — **verified**

`FileLimits::validate()` (`src/file_service.rs:153-258`) now rejects zero `lockout_window` (:167-173),
zero `idle_timeout` (:174-178), zero `max_upload_bytes`/`max_rehash_bytes_per_stream` (:179-185).
Fixtures in `every_validate_rule_has_a_red_test` (:3525-3650) — I re-ran the rule order by hand for **all 12**:
each fixture's non-default fields violate only its named rule, because rules 1-4 are field-disjoint zero tests and
rules 5-11 compare different quantities. Specifically the four new ones:
`lockout_window: ZERO` reaches :167 (rule 1 does not name it) and no later rule reads the field ⇒ deleting :167
makes `validate()` return `Ok` ⇒ `expect_err` reddens. Same for `idle_timeout: ZERO`. `max_upload_bytes: 0` and
`max_rehash_bytes_per_stream: 0` share rule 1's *identical* message string, which weakens attribution but still
kills: delete :179 and those two fixtures return `Ok` ⇒ red.
Coverage is now complete over all 14 numeric fields (`max_inflight_bytes_per_session = 0` is caught by
`chunk_bytes ≤ …` at :198). Wiring verified: `Throttle::new(limits.max_throttle_buckets, limits.lockout_after,
limits.lockout_window)` at :1006-1010 matches the signature at :662 (no swapped args), and `record_failure`
calls `self.decay(now)` first (:705-706). **No hardcoded 60 s anywhere in the engine path.**

## 2. R4-W-1 — **partly verified** (headline real, second clause inert → R5-NEW-1)

`lockout_rearms_after_expiry_and_flood_arms_are_not_exempt` (:2715-2802), fixture cap=8/lockout_after=2/40 ms.
Flood is `0..(8+4)` on a table that already holds `repeat` ⇒ the table ends as {repeat, flood0..flood6} = 8,
so `assert_eq!(e.throttle_buckets(), 8)` (:2766) is true **and flood0 is genuinely in `buckets` with count 1, un-locked**.
Mutation: restore `&& !self.buckets.contains_key(&key)` in `is_locked` → `is_locked("flood0")` = false → token
matches → `authenticate` returns `Ok` → the `.map(|_| "ACCEPTED")` at :2772 yields `"ACCEPTED"` ≠ `code::THROTTLED`
⇒ **red**. The r4 complaint about the assertion subject is genuinely fixed.
The "one forged failure after expiry must not re-arm" clause (:2795-2799) does **not** fail under a no-decay
implementation: flood0 is *in* `buckets`, so `record_failure` takes the bucket branch and never touches `global`
in either variant; the assertion passes with `decay` gutted. See R5-NEW-1.

## 3. R4-W-2 — **verified**

`per_session_inflight_ceiling_is_enforced_by_the_engine` (:2897-2931). After the CAPACITY refusal and **before**
`settle_file` (:2927) there are now two assertions: `assert_eq!(e.budget().buffered(), 16)` (:2918) and
`assert!(e.inflight_matches_budget(s))` (:2919-2922). Numbers: ceiling=16, two accepted pages of 8 ⇒ 16/16.
Delete the `unpush_file` rollback in `charge_file` (:1144) → the refused 8 bytes stay reserved → `buffered()` = 24
(≠16) **and** `inflight_bytes`=16 vs `file_buffered_for`=24 ⇒ both assertions red. Claim matches the repo.

## 4. R4-W-3 — **verified**

`list_pages_are_charged_to_the_shared_budget` (:2804-2849). (a) Deleting `self.charge_file(session, ack_bytes)?`
(:1383) makes `budget().file_buffered()` 0 ⇒ :2824 red, and the 4th `list` returns `Ok` ⇒ `unwrap_err` at :2838
red. Two independent kills. (b) No self-validating arithmetic survived: the only equalities compare two *different*
stores (`inflight_bytes` vs `budget().file_buffered()`, then `inflight_matches_budget`) or engine output
(`entries.len()`, `truncated`); `settle_file(s, e.budget().file_buffered())` is a drain, not an assertion.
(c) My computation matches: envelope 72 + per entry (52+6)=58 ⇒ page1=130+58=**188**, page2=**188**, page3=**130**
(1 entry, `!truncated` correct since 1 < cap 2) ⇒ 188+188+130=**506 ≤ 512**; page4=188 ⇒ 506+188=694 > 512 ⇒
`push_file` refuses with QUEUE_FULL (:864-870). The three-pages-then-refuse claim is arithmetically right.
Probe side is unchanged (no `list`-charge field in `examples/gateway_file_contract.rs`) and the disposition does
**not** claim otherwise — honest.

## 5. R4-W-4 — **verified** (two wordings overstate: R5-N-8)

Success side now pinned by the `audited!` macro (row count `before+1`, action, code, principal non-empty,
:3097-3112) for `authenticate/OK` (:3121), `open_upload/OK` (:3167), `stat/OK` (:3222), `remove/OK` (:3224),
`commit/OK` (:3230), plus hand-written equivalents for the two unit-returning verbs: `abort_upload` (:3205-3214)
and `close_session` (:3263-3274) — both assert `+1` row, action, `"OK"` and principal, i.e. the same four
elements as the macro (`close_session` even strengthens it to `principal == "u"`). Deleting any one `record`
in the `Ok` arm reddens. The ring-flood loop now runs on a **live** session `s2` re-authenticated at :3277
(after `close_session(s)`), so its `NOT_FOUND` back-row is the real stat-refusal path, not "no such session"
(:1293-1296 gives the same code but a different message — the loop's row is attributable to a live principal).
MODULE G21 (:214-217) is true for existence of all 12 listed 落账出口; two wordings still overstate (R5-N-8).

## 6. R4-W-6 / R4-W-7 declarations — **verified verbatim**

MODULE.md:157-163 carries the caveat as an **open owner decision**, not a solved property: "`buckets` 自身不做时间
衰减…攻击者每窗口只需 `lockout_after`（默认 5）条伪造失败即可无限续期全局窗口，实测…约 94% 的时间被拒。要么给桶加
时间衰减…要么在 PRODUCT 里把'合法用户可被无限期拒服务'写成明示的可接受代价；本批**只把现象登记进契约与未证清单，
不静默改变语义**". (94% is the reviewer's number, not self-invented.) PRODUCT.md:3315-3318 repeats it and says
"这条留给仓库所有者裁决（MODULE G15 已登记）". PRODUCT.md:3320-3322 now reads "…都有配额表并在引擎里 enforced；
**全局 RSS 没有配额也没有计量**…本条不得再被读成'内存有上界'", which agrees with MODULE:189 ("OS 句柄层面
(`/proc/self/fd`) 与全局 RSS 上界仍未验") — no contradiction left.

## 7. Same-class hunt — new findings

**R5-NEW-1 (FAIL) — claimed kill is inert; `decay`'s global reset has zero coverage.**
`Throttle::decay` (:679-688) has two clauses; the second (`global_locked_until` lapse ⇒ `self.global = 0`, :681-685)
is *the* mitigation for "one flood stays armed forever" (r3 R3-W-2 / the r3 FAIL). Mutation test: replace :681-685 with
a no-op (global never resets, window still lapses) and walk all 56 tests: the only test that sleeps past a window
is :2786, and its post-expiry assertion subject `flood0` is in `buckets`, so `record_failure` never reaches the
`global += 1` branch (:708-715) — the assertion at :2796-2799 passes with the mutant. `!throttle_globally_locked()`
(:2787, :2796) is likewise satisfied by `globally_locked()`'s own `until > now` check (:745-748) regardless of decay.
So the whole `decay` function — both clauses — is now asserted zero times with kill power, while the disposition
says it was fixed and the green-evidence file (last section, item 3) says "另补『窗口过期后一条伪造失败不得立刻重新
武装』". Third recurrence of the r4-W-1/W-2 class, and the only thing standing between one flood and a permanently
armed window is untested. Fix ≤3 lines: after the expiry sleep, feed `lockout_after - 1` failures from **fresh**
principals and assert `!throttle_globally_locked()`, then one more and assert it *is* armed (kills both directions).

**R5-W-2 (WARN) — high ends unvalidated; unchecked `Instant + Duration`.**
This batch adds `MAX_TERMINALS_CEILING` precisely because "只检查 `== 0` 时…等于没有检查"
(`src/config.rs:15-19, 266-272`) — the file-side rule stops at the low end only. `lockout_window` is used in three
**unchecked additions**: `now + self.lockout` (:711, :721, :723); `Instant + Duration` panics on monotonic-clock
overflow, and this crate is `panic = "abort"`, panic-free-by-construction per MODULE G20 (:206-208) — a config with
`lockout_window = Duration::MAX` (or any value past the uptime margin) crashes the gateway on the *first failed
token*. `idle_timeout` large passes `validate()` and makes `sweep_idle`'s
`now.saturating_duration_since(last_activity) > timeout` (:1270) never true ⇒ sessions are never recycled while
G21 states they are; the `saturating_*` here only prevents the subtraction, not the inverted meaning. Add an upper
bound (e.g. ≤ 1 h) plus a fixture, or use `checked_add` and report CONFIG.

**R5-W-3 (WARN) — newly charged quantity, missing paired rule (exact R4-NEW-1 shape).**
`list` is now engine-charged with `ack_bytes` (:1383), which is bounded only by `max_ack_bytes`; `validate()`
cross-checks `chunk_bytes ≤ max_inflight_bytes_per_session` (:198) but has **no** `max_ack_bytes ≤
max_inflight_bytes_per_session`. So `max_buffered_amount=4096, max_inflight=128, max_ack=4096, chunk=8` passes
`validate()` while every list page with `ack_bytes > 128` hits the CAPACITY branch (:1142-1148), rolls back, and —
since `inflight` is 0 again — refuses identically forever: **a config that passes validation and makes every `list`
permanently refuse**, the "死配置" the batch itself rejects for zeros. Related half: the ack *floor* (:225-236) is
`envelope + ENTRY_ACK_OVERHEAD` = 124 and ignores `raw_name.len()`, which is what the truncation test at :1357 adds;
so at `max_ack_bytes` in [124, 124+len) a page truncates to **0 entries** and returns
`next_offset = offset + 0 = offset` (:1385) — the client spins on one offset, which is precisely the defect r2 W-4
was fixed for on `read`, and it breaks G17's "`next_offset` 必须单调". Two pieces of corroboration that this band is
real, not theoretical: the probe fixture comment (`examples/gateway_file_contract.rs:608-611`) says the value must
stay above the floor "否则 list 页永远截断成 0 条", yet its own `max_ack_bytes: 128` with 6-byte names gives
72+52+6 = 130 > 128 ⇒ 0 entries; and the reverse-boundary test asserts `max_ack_bytes = 124` **is valid**
(:3636-3649), i.e. the test blesses the permanently-unlistable config.

**R5-W-4 (WARN) — "有界" is row-bounded, not byte-bounded (contract overstates coverage).**
`record` (:2118-2147) caps rows at `AUDIT_CAPACITY = 8192` (:936) but stores `principal`/`root`/`rel` verbatim with
no length cap, and `authenticate` records the caller's `principal` **before** any token check (:1174-1176) and with
`session = 0`. Same for the throttle keys (:707, :753-755) — bounded to 1024 entries, each of unbounded length.
MODULE G21's sentence "审计环本身有界…无上限的审计日志就是一条用拒绝请求把节点内存打满的路径" and G15's
"表项有界（不得随伪造会话线性增长）" are therefore true of the count and false of the bytes; the ring-flood test
(:3278-3283) only measures `audit().len()`. Cheapest fix: cap recorded string length (truncate with a marker) or
add a byte budget and freeze it in a scenario. Ties directly into the declared RSS debt (PRODUCT:3320-3322).

**R5-W-5 (WARN) — debt list incomplete + one "documented" claim not in the tree.**
`still_open_after_this_batch` lists 7 items; two r4 WARNs are neither fixed nor listed, and both are still present:
R4-W-8's raw arithmetic `self.buffered() + bytes` at :840, :844, :864 (publicly reachable via `send_file_message`
:1112) still violates G20's "一律 `checked_*`" wording — only the other half of W-8 was taken, since the drain
reserve is now `bytes.saturating_sub(self.limit - self.buffered())` (:887); R4-W-5's empty `root` on refusal rows is
unchanged (`ack_staged` still records `""` at :1739, `stage_chunk` refusals likewise). And R4-N-4 is claimed
"documented（G21 侧记…闲置回收不清理节流状态）" — `grep forget` across `MODULE.md`/`PRODUCT.md`/`src` returns only
:752/:1260 plus probe uses: no such sentence exists, and `Throttle::forget`'s own comment ("Called on session
teardown: a recycled session must not leave state behind", :750-751) asserts the **opposite** of the code, since
`sweep_idle` (:1266-1285) does not call it.

**R5-N-6 (NOTE)** `FILE_MANIFEST.md:5` declares 194 and `awk '/^\| /{n++}'` = 195 ⇒ minus header = 194: **self-consistent**.
But the four registered rows (`:239-242`) point at `.evidence/review-gateway-file-r1|r2/*` which are **not tracked**
(`git ls-files .evidence` returns only `red-n2-p0-0` and `review-g11-ice-fix-qoder-r1`), and r3/r4 (now r5) dirs are
unregistered — so the landing commit changes the number again. Same item as R4-N-9, second round, not dispositioned.

**R5-N-7 (NOTE)** Probe fields `throttle_full_fail_closed` (`examples:537-543`) and
`product_engine_fails_closed_when_flooded` (`:591-592`) still test a **fresh**/out-of-table principal, so scenario
`gateway_file_auth_throttle` keeps two frozen expectations with no kill power against the exemption mutant (r4's
complaint ②, half unchanged; the unit test now carries the whole load). Not in the debt list.

**R5-N-8 (NOTE)** MODULE:213 "『漏记』在结构上不可发生" is still not literally true: `close_session` records inside
`if let Some(...)` (:1252-1262), so closing an unknown id leaves zero rows (r4 said this; unchanged). And G21's
"单测逐个动词断言恰好一行 + …" (:217) holds for 11 of the 12 listed exits — `idle_recycle`'s assertions
(:3080-3083) check action/code/principal but never the row count.

## 8. Residual honesty — spot-checked 3 of 7 "open" claims: all honest

`capability-negotiation` really has no product-side counterpart: `decide_channel` appears only at
`examples/gateway_file_contract.rs:902` (and its three probe call sites), `src/config.rs` has no `files` field
(grep: only `tls.files` prose), and the scenario has exactly 7 expectations as the probe header says
(`:10-14`). The `.part` pre-planted-symlink test really does bypass the engine:
`part_creation_refuses_a_preplanted_symlink` (:3673-3695) hand-builds `.f.bin.nexus-part-deadbeef` and calls
`std::fs::OpenOptions::create_new` directly, never `open_upload` — correctly declared open.
`files.enabled`/kill-switch wiring is genuinely absent and declared in both G12 (:99-102) and PRODUCT §18.4.
So the "open" claims I checked are trustworthy; the defect in that list is **incompleteness** (R5-W-5), not
over-claiming-of-openness.

## Merge decision

**Not mergeable in this state** — but the distance is short and the direction is right: 1 FAIL and 4 WARN, of which
one FAIL is a ≤3-line fixture change plus one WARN a ≤10-line `validate()` rule. R4-W-6 stays exactly where the
chain agreed it belongs (an open owner decision, declared in G15 + PRODUCT §18.2); it does **not** by itself block
this increment. Blocking items: R5-NEW-1 (the disposition's claimed kill must be made real, and `decay` covered),
R5-W-3 (paired `max_ack_bytes ≤ max_inflight_bytes_per_session` rule + explicit handling for a non-fitting entry
instead of a 0-entry page), R5-W-2 (upper bounds / `checked_add`), R5-W-5 (put W-5/W-8 back on the debt list or fix
them, and delete or correct the R4-N-4 "documented" claim and the `forget` comment at :750-751).
If those five land with the mutation-kills they claim, the increment is mergeable with W-6 declared-open.
Iteration count is now 5 against AGENTS.md:1585's default cap of 3 — the human-escalation flag from r4 still stands;
this round adds nothing to it beyond the W-6 decision already in front of the owner.

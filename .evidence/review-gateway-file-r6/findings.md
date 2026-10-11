# Independent review — gateway file service, round 6

**Host / toolchain (this review):** Windows 11 x64 (win32) + Git Bash, static reading only.
**NOT COMPILED:** `nexus-web-gateway` cannot be built here (`ssh2` 0.9.6 `userauth_pubkey_memory` is
cfg-gated to `unix | vendored-openssl | openssl-on-win32`; no cl.exe/nasm). No test/clippy/harness/scenario
was run by me; no std-only probe was needed (all arithmetic is byte counting doable on paper). The
implementer's measurements (57 lib tests, clippy clean, 9/9 = 86 expectations, `verify --fast` 9 gates,
contract_hash `8f510129…`) are not reproduced by me and are not used as proof of anything I can read.
Content tree `5dd8c66b…` on `xc-pc-linux`; branch tip `af953af`, working tree uncommitted.

**Verdict: COMMENTED.** 0 FAIL, 1 WARN, 4 NOTE. The round-5 FAIL is genuinely fixed with kill power.

## 1. R5-NEW-1 — off-table decay judgement: **VERIFIED**
`src/file_service.rs:2900-2915` with the fixture at `:2829-2836` (`max_throttle_buckets=8`,
`lockout_after=2`, `lockout_window=40ms`): after the two `repeat` rounds the map is
`{repeat, flood0..flood6}` = 8 (`:2872` asserts it), so `flood7..flood11` take the overflow branch
`:752-759`, leaving `global = 5` and the window armed. After the 60 ms sleep `off-a` is **not** in
`buckets`, so `record_failure` (`:748-750` → `decay` `:723-731`) again takes the overflow branch: correct
code resets `global=0` then `+1` ⇒ `throttle_overflow()==1` (`:2910`) and `!throttle_globally_locked()`
(`:2906`) both hold. **Mutation: delete `self.global = 0` at `:728`** ⇒ `global` 5→6 ≥ 2, `:754-757` re-arms,
so `:2906-2909` and `:2910` (6 ≠ 1) fail — two assertions, numbers 1 vs 6. `late-comer` (`:2897`) is a
*success* and `succeed` (`:776-779`) only removes a key, so it cannot perturb `global`; the fixture premise
is sound. `off-b` (`:2911-2915`) is the reverse guard (neutral to this mutation, correct as anti-"never
re-arm"). The round-5 subject error (an in-table principal) is gone.

## 2. R5-W-2 — 24 h bounds + `checked_add`: **VERIFIED**, one NOTE
(a) Rule order in `validate()`: zero-list `:155` → `lockout_window` 0 `:176` → `idle_timeout` 0 `:182` →
upload/rehash 0 `:188` → `lockout_window>24h` `:199` → `idle_timeout>24h` `:205` → `ack≤inflight` `:214` →
`browser≤sessions` `:220` → `chunk≤buffered` `:228` → `chunk≤inflight` `:234` → `ack≤buffered` `:242` →
`ack≥124` `:254` → `inflight≤buffered` `:268` → `handles≥sessions` `:277`. All 15 fixtures at `:3741-3867`
hand-computed: each violates only its own rule (the two 86401 s fixtures fire only `:199`/`:205` since
defaults pass `:214`); deleting any single `if` makes that fixture fall through to `Ok`, and the
message-keyword asserts `:3873-3877` catch "wrong rule fires first".
(b) `lock_until` `:703-706`: after `:199`, `checked_add` returns `None` only if `Instant::now()` is within
24 h of the clock max — unreachable for Linux's ns-since-boot monotonic clock (~584 y), so the fallback is
unreachable-after-validation. **NOTE-2:** the fallback body is itself an unguarded
`now + Duration::from_secs(3600)` (`:705`) and can panic in the very regime it handles (`now` within 1 h of
the max). `unwrap_or(now)` is not the fix (immediate expiry = fail-open, correctly rejected at `:701-702`).
(c) No other unguarded `Instant + Duration` (all `Instant` uses are assignments/comparisons: `:734, 749,
793, 1322, 1380, 1691-1694, 1746, 1777`); `sweep_idle` uses `saturating_duration_since` (`:1360`) and is now
bounded by `:205`. Residual raw arithmetic, all safe by invariant (`buffered ≤ limit`, monotone decreases):
`:863`, `:917` (post-check), `:949` (outer `saturating_sub`, inner raw), `:986`, plus `:1447`
`ack_bytes + 52 + len` (overflowable only if a byte limit is set near `usize::MAX`; byte limits keep only a
low edge — deliberate at `:197` / MODULE.md:33).

## 3. R5-W-3 — `ack ≤ inflight`, the implication, and PAGE_TOO_LARGE: **VERIFIED**
Honest: MODULE.md:103-123 says `ack ≤ buffered` is now "已被 `ack ≤ inflight ≤ buffered` 蕴含… 纵深防御",
and the test comment `:3804-3817` says the same and re-points that fixture at `inflight ≤ buffered`. Strictly
`:242` can still be the *first* failure (ack>buffered with inflight>buffered) but never the *sole* violated
rule, which is what the text claims. **NOTE-3:** the umbrella MODULE.md:103 "逐条都有单测把它跑红" is
literally false there — deleting `:242-247` reddens nothing (checked fixture by fixture) — and also for
MODULE.md:120 "root 非空且不重复": the rejection at `:1069-1080` has no test (every `FileEngine::new` in the
tests is `.unwrap()`, `:2392-3642`).
Refusal `:1473-1483` fires only on `truncated && entries.is_empty()`; `cap ≥ 1` (`:156`) means the cap branch
cannot yield an empty page, so it is exclusively the ack-byte case, it precedes `charge_file` (`:1487`) and
cannot leave a charge, and G17 monotonicity is restored. Exhausted listings are safe: offset past the end
breaks at `:1438` with `truncated = false` ⇒ `Ok`/empty/complete, asserted at `:2998-3002`. Deleting the
refusal makes `list()` return `Ok` ⇒ `:2990 unwrap_err()` panics ⇒
`list_refuses_to_stall_on_an_unrenderable_entry` reddens.
Fixture audit: 200 bytes < Linux NAME_MAX 255 (`:2976-2978`), and that name exists only in `tmp("list-stall")`
(per-test dirs, `:2379-2388`), listed by no other test. No fixture is broken by the new rule —
`:2794-2797` 128/128, `:2928-2933` 256/512, `:2979-2984` 188/128K, `:3055-3059` 128/128, `:3555-3559`
128/128, examples `:619-633` and `:810-813` 128/128; all others use defaults (32K ≤ 128K). The re-plan of
`per_session_inflight` (`:3052-3054`: inflight 128 + buffered 4096) is exactly the conflict the new rule
created, and it is registered in the evidence file.

## 4. R5-W-4 — byte bounding: **VERIFIED**; collision answered
Truncation is pre-insertion, so boundedness is storage not display: `bounded_key` (`:708-716`) feeds
`:735` (`locked.get`), `:751` → `buckets.entry(key.clone())` `:761` / `locked.insert` `:769`, `:777`, `:805`;
`record` truncates inside the `push_back` (`:2247-2253`). Char-boundary safe (`:1008-1011`). Output length is
`max + 3` (`…` is 3 bytes) `+ "[+NB]"`, so the constants `:999-1000` are the cut point, not the resulting cap;
the test bound `AUDIT_FIELD_MAX_BYTES + 16` (`:3467`, `:3472`) is the honest number (256+3+8 = 267 for the
4000-byte fixture) and MODULE.md:229-233 phrases it correctly. Kill power: deleting either `bounded_label`
call leaves 4000-4002-byte fields ⇒ `:3466`/`:3471` red, and `:3477-3484` reds; the row-count assertion was
rightly re-pointed at tail content because the ring is saturated (`:3462-3464`).
**Collision:** label = first 128 bytes (`IDENTITY_LABEL_MAX_BYTES` `:999`) + `…` + `[+{len−128}B]`, so two
identities collide iff they share the 128-byte prefix **and** the total byte length. It does **not** weaken
lockout — merging failures crosses `lockout_after` *earlier* (direction stays fail-closed; it only delays the
1024-distinct-key overflow path). It **does** let an attacker impose a lockout: 5 forged failures on a
prefix+length-matching identity lock the real one, and the test demonstrates it — the 20 principals at
`:3457-3459` (`"x"×4000`+`i`) collapse into two keys (`i<10` → `[+3873B]`, `i≥10` → `[+3874B]`), each arming
at `lockout_after = 5`. Versus pre-truncation this is not a new capability class: the keys were already fully
caller-supplied `(principal, source)` (`:1250-1255`), so an exact identity could already be locked; truncation
widens "exact string" to "prefix + length". **NOTE-4:** neither MODULE.md:155-161 nor PRODUCT §18 states the
collision class; the code comments only say "只影响归因精度，不影响判定方向" (`:710-711`, `:997-998`), which
understates cross-principal lockout. One sentence in G15 closes it.

## 5. R5-W-5 — `exceeds_limit` via `checked_add`: **VERIFIED**
`:873-878` returns `true` on `None`; sites `:902`, `:906` (push_terminal), `:926` (push_file) route `true`
into a refusal (`QUEUE_FULL` + `file_drops` `:927-931`; `CAPACITY` + `terminal_drops` `:911-915`), never into
acceptance; the accepting adds `:917`/`:933` are reached only after `buffered+bytes ≤ limit`. `charge_file`
uses `checked_add` with rollback on `None` (`:1217-1223`). No `self.buffered() + bytes` remains.
**NOTE-5:** R4-W-8's *second* half — `self.limit - self.buffered()` at `:949` — is still a raw subtract;
safe under the `buffered ≤ limit` invariant, but the r4 remedy asked for `saturating_sub` there, so the item
is "closed for adds".

## 6. R5-N-7 / N-8: **VERIFIED** (kill power confirmed)
Probe `examples/gateway_file_contract.rs:523-552` adds `in_table_correct` = `authenticate("p0", …, TOKEN)`
after the 8-bucket fill plus 3 overflow failures: `p0` is in `buckets` with count 1, so under the old
exemption predicate the call returns `Ok` → "ACCEPTED" → field false → the frozen
`throttle_full_fail_closed == true` (last two `[[expect]]` of `scenarios/product/gateway_file_auth_throttle.toml`)
reddens. Same at `:592-610` on the 1024-bucket product engine (`p0` is inserted by the flood loop `:581-584`
before the overflow failures). `close_session(unknown)` `:1346-1351` records `NOT_FOUND`, asserted by tail
content at `:3488-3495` (correct — ring saturated); without the `None` arm `back()` is the preceding `stat`
⇒ `:3490` red. `idle_recycle` `:3230-3236` asserts exactly-one-line on an **unsaturated** ring, so deleting
`:1372` reds both `:3232` and `:3249`.

## 7. Manifest and counts: **CONSISTENT**
`awk '/^\| /{n++}' FILE_MANIFEST.md` = **201**; the separator `|---|---|` (`:54`) is not matched, so
201 − 1 header = **200** = declared (`FILE_MANIFEST.md:5`), and the note at `:39` (194 + 6 rows for r3/r4/r5)
matches. `grep -c '[[expect]]'` over the 9 scenario files = 9+7+10+6+16+9+15+5+9 = **86**, matching both
recent evidence sections. HEAD totals **73** (7/7/10/6/8/9/12/5/9), so this increment adds exactly 13
(auth-throttle 7→9, quota 8→16, sftp-boundary 12→15); the intermediate "77" is an uncommitted state whose
own breakdown is arithmetically consistent (7+10+6+5+9+9+11+7+13 = 77), and the r3 section's correction of
"80/73" → "86/77" is self-consistent. **No genuine inconsistency.** Residual (already R5-N-6): `.gitignore:3`
ignores `/.evidence` and `git ls-files .evidence` still returns only `red-n2-p0-0` and
`review-g11-ice-fix-qoder-r1`, so the 6 newly registered rows point at unstaged files; the disposition
commits to carrying them with `git add -f` at landing.

## 8. Debt list: 3/3 spot-checks honest, **1 claimed-but-absent item (the WARN)**
- `capability-negotiation` has no product-side counterpart: `decide_channel` only at
  `examples/gateway_file_contract.rs:922` (used `:888/:901/:907`), nothing in `src/` ✓.
- `.part` preplanted-symlink test never calls the engine: `:3916-3941` is pure `OpenOptions::create_new` ✓.
- `release_session`'s `usize` (`:983-987`) is discarded at both teardown sites (`:1342`, `:1371`); only the
  unit-level `:2756` consumes it ✓.
- Also honest: no `files` block in `GatewayConfig` (`config.rs:19/:269` is the ssh-side ceiling), fuzz targets
  still only `policy_planner_no_panic.rs`, and `R3-N-4` is live (~30 emitted fields frozen by no scenario,
  e.g. `throttle_overflow_codes`, `read_page_overflow_code`, `peak_read_handles`).
- **WARN-1:** the R5-W-5 disposition row says "欠账清单补回漏掉的 R4-W-5 / R4-W-8", yet
  `still_open_after_this_batch` (9 items) has no entry for R4-W-5 and the code is unchanged — refusal lines
  still pass `root = ""` at `:1715` (`stage_chunk`), `:1843` (`ack_staged`), `:2009` (`abort_upload` unknown
  stream), while G21 promises "（主体、root、动作、目标相对路径、结果码）" (MODULE.md:226-228). R4-W-8
  legitimately needs no entry (fixed). Fourth occurrence in this chain of a disposition sentence with no
  counterpart in the repo; one-line list edit, no code risk. Nothing declared open turned out to be fixed.

## Merge decision
**Mergeable** (COMMENTED; no FAIL). Recommended to land in the same commit, all cheap: WARN-1 (add the
R4-W-5 empty-`root` item to the list, or fill the field), NOTE-2 (`checked_add`-safe 1 h fallback), NOTE-3
(qualify MODULE.md:103 and add a red test for duplicate/empty roots), NOTE-4 (one G15 sentence on the
prefix+length collision class), NOTE-5 (`saturating_sub` at `:949`). Declared-open items carried forward:
R4-W-6 (bucket decay vs long-run denial — owner decision, already in MODULE.md:86-91 / PRODUCT §18.2, **not**
counted here), files-block/kill-switch + capability-negotiation coupling (W-7/R3-W-6), W-12 `.part` nonce,
R3-N-4 unfrozen probe fields, `/proc/self/fd` + RSS accounting, fuzz target registration, error-code
vocabulary + N3-4/N3-9 cross-consistency, G1 hook binding (`689f63a`, unmerged), `release_session` byte count.
Iteration count is now 6 rounds against the default 3 in AGENTS.md:1585; owner escalation from r4 stands and
this round adds no new escalation item.

#!/usr/bin/env python3
"""Gateway file-service config-surface mutation harness (MC01-MC22).

Why this file is in the repo (review r14 W-2): the kill-power table's evidence used to
live only on the implementer's Linux box (`/work/mm10.log`), so a third party could not
recompute the coverage number from the repository alone. Run it, keep the raw output,
and commit that output to `.agents/mutation-log-gateway-file-config.txt`.

Usage (on xc-pc-linux, in an ISOLATED clone with an ISOLATED target - never the tree
you will later certify; a mutation that survives because the wrong binary was reused
is the exact failure this project has been asked to remove):

    git clone --no-hardlinks --branch <ref> /work/m0-origin.git /work/mm
    cd /work/mm && CARGO_TARGET_DIR=/work/mm-target python3 \
        crates/nexus-web-gateway/tools/mutation-gateway-file-config.py

Each recipe flips one guard into a never-matching form. A row with 0 red tests and
0 flipped expectations is a hole in the object set, not a pass - report it as such.
Kill evidence is the per-field JSON diff plus the red test names; the probe's exit
code and the harness' "PASS" word are deliberately not used (review r13 W-3).
"""
import json
import subprocess
import sys

CFG = "crates/nexus-web-gateway/src/config.rs"
FS = "crates/nexus-web-gateway/src/file_service.rs"
CASES = [
    ("config", "scenarios/product/gateway_file_config.toml"),
    ("auth-throttle", "scenarios/product/gateway_file_auth_throttle.toml"),
]

C = "        "


def sh(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.stdout + p.stderr


def frozen(path):
    out, key = [], None
    for line in open(path, encoding="utf-8"):
        s = line.strip()
        if s.startswith("field ="):
            key = s.split("=", 1)[1].strip().strip('"')
        elif s.startswith("equals") and key:
            out.append((key, s.split("=", 1)[1].strip()))
            key = None
    return out


EXPECT = {case: frozen(path) for case, path in CASES}

RECIPES = [
    ("MC01_window_floor_off", CFG,
     C + "if self.lockout_window_secs < MIN_FILE_LOCKOUT_WINDOW_SECS {",
     C + "if self.lockout_window_secs < MIN_FILE_LOCKOUT_WINDOW_SECS && false {"),
    ("MC02_window_ceiling_off", CFG,
     C + "if self.lockout_window_secs > MAX_FILE_WINDOW_SECS {",
     C + "if self.lockout_window_secs > MAX_FILE_WINDOW_SECS && false {"),
    ("MC03_engine_table_not_delegated", CFG,
     C + "if let Err(e) = limits.validate() {",
     C + "let _ = limits.validate();\n" + C + "if let Err(e) = Ok::<(), String>(()) {"),
    ("MC04_files_checked_only_when_on", CFG,
     C + "self.files.validate()?;",
     C + "if self.files.enabled {\n" + C + C + "self.files.validate()?;\n" + C + "}"),
    ("MC05_presence_not_gated", CFG,
     C + "if self.enabled {",
     C + "if true {"),
    ("MC06_kill_switch_inert", CFG,
     C + "if !self.files.enabled {",
     C + "if !self.files.enabled && false {"),
    ("MC07_launch_skips_validate", CFG,
     C + "self.validate()?;\n" + C + "if !self.files.enabled {",
     C + "if !self.files.enabled {"),
    ("MC08_dup_alias_off", CFG,
     C + C + "if !seen.insert(root.alias.as_str()) {",
     C + C + "if !seen.insert(root.alias.as_str()) && false {"),
    ("MC09_blank_alias_off", CFG,
     C + C + "if root.alias.trim().is_empty() {",
     C + C + "if root.alias.trim().is_empty() && false {"),
    ("MC10_mirror_drift", CFG,
     C + "lockout_window: Duration::from_secs(self.lockout_window_secs),",
     C + "lockout_window: Duration::from_secs(self.idle_timeout_secs),"),
    ("MC11_no_serde_default", CFG,
     "#[serde(default)]\n    pub files: FilesConfig,",
     "    pub files: FilesConfig,"),
    ("MC12_default_enables_files", CFG,
     "        Self {\n            enabled: false,\n            token: String::new(),",
     "        Self {\n            enabled: true,\n            token: String::new(),"),
    ("MC13_engine_window_ceiling_off", FS,
     C + "if self.lockout_window > Duration::from_secs(MAX_WINDOW_SECS) {",
     C + "if self.lockout_window > Duration::from_secs(MAX_WINDOW_SECS) && false {"),
    ("MC14_blank_token_off", CFG,
     C + "if self.token.trim().is_empty() {",
     C + "if self.token.trim().is_empty() && false {"),
    ("MC15_roots_nonempty_off", CFG,
     C + "if self.roots.is_empty() {",
     C + "if self.roots.is_empty() && false {"),
    ("MC16_seam_always_none", CFG,
     C + "Ok(Some(engine))",
     C + "let _ = engine;\n" + C + "Ok(None)"),
    ("MC17_skip_serializing_window", CFG,
     "    pub lockout_window_secs: u64,",
     "    #[serde(skip_serializing)]\n    pub lockout_window_secs: u64,"),
    ("MC18_open_errors_swallowed", CFG,
     "            roots.push(\n                SandboxRoot::open(r.alias.clone(), Path::new(&r.path), r.read_only)\n"
     "                    .map_err(|e| GatewayError::Config(format!(\"files.roots: {e}\")))?,\n            );",
     "            roots.extend(SandboxRoot::open(r.alias.clone(), Path::new(&r.path), r.read_only).ok());"),
    # MC19/MC20: 评审 r14 W-1 的 NEW20 一族——配置层那两条 idle 界先前没有带层标签的对象。
    ("MC19_idle_floor_off", CFG,
     C + "if self.idle_timeout_secs < 1 {",
     C + "if self.idle_timeout_secs < 1 && false {"),
    ("MC20_idle_ceiling_off", CFG,
     C + "if self.idle_timeout_secs > MAX_FILE_WINDOW_SECS {",
     C + "if self.idle_timeout_secs > MAX_FILE_WINDOW_SECS && false {"),
    # MC21/MC22 是评审 r15 的 R15B 一族：上界写成 `>=`（把边界值本身也误杀）。
    # "越界必须拒"那几格对这种改动是**盲的**（两层同集合，删一侧不改判定），
    # 所以对象必须是"边界值可用"本身——这就是 `*_ceiling_boundary_is_usable` 两格。
    ("MC21_window_ceiling_off_by_one", CFG,
     C + "if self.lockout_window_secs > MAX_FILE_WINDOW_SECS {",
     C + "if self.lockout_window_secs >= MAX_FILE_WINDOW_SECS {"),
    ("MC22_idle_ceiling_off_by_one", CFG,
     C + "if self.idle_timeout_secs > MAX_FILE_WINDOW_SECS {",
     C + "if self.idle_timeout_secs >= MAX_FILE_WINDOW_SECS {"),
    # MC23-MC25 是评审 r16 自己设计的三条，收编进这张表（其中两条暴露了我的空档：
    # 下界那一侧没有独立的"边界值可用"格；"两层同集合"这句话在整秒定义域外不成立）。
    ("MC23_window_floor_off_by_one", CFG,
     C + "if self.lockout_window_secs < MIN_FILE_LOCKOUT_WINDOW_SECS {",
     C + "if self.lockout_window_secs <= MIN_FILE_LOCKOUT_WINDOW_SECS {"),
    ("MC24_idle_floor_off_by_one", CFG,
     C + "if self.idle_timeout_secs < 1 {",
     C + "if self.idle_timeout_secs <= 1 {"),
    ("MC25_engine_floor_to_one_second", FS,
     C + "if self.lockout_window.is_zero() {",
     C + "if self.lockout_window < Duration::from_secs(1) {"),
]

PATHS = sorted({r[1] for r in RECIPES})
PRISTINE = {p: open(p, encoding="utf-8").read() for p in PATHS}

# 靶格声明（评审 r17 N-4）：一条配方常常翻好几格——有的是它专门打的，有的是共享夹具被
# 改严之后的级联。光看 FLIP 名单分不清这两种，于是"每条断言各有专属对象"这句话在日志里
# 不可机检。这里显式声明每条配方**专门**打哪几格，脚本末尾自己打 COVERAGE 段：
# 每格列出打它的配方，没有专属配方的格直接报 UNTARGETED。
# MC25 的靶在引擎侧（3 条时间夹具单测），不在本场景，故 targets 留空并注明。
TARGETS = {
    "MC01_window_floor_off": ["sub_second_window_rejected_by_config"],
    "MC02_window_ceiling_off": ["over_24h_window_rejected_by_config"],
    "MC03_engine_table_not_delegated": [
        "disabled_still_rejects_inconsistent_table", "disabled_still_rejects_zero_ceiling",
        "source_budget_below_pair_threshold_rejected", "source_budget_above_table_capacity_rejected",
        "invalid_table_yields_no_engine"],
    "MC04_files_checked_only_when_on": [
        "disabled_still_rejects_inconsistent_table", "disabled_still_rejects_zero_ceiling"],
    "MC05_presence_not_gated": ["absent_section_is_disabled", "disabled_yields_no_engine"],
    "MC06_kill_switch_inert": ["disabled_yields_no_engine"],
    "MC07_launch_skips_validate": [
        "invalid_table_yields_no_engine", "blank_token_yields_no_engine",
        "blank_alias_yields_no_engine"],
    "MC08_dup_alias_off": ["duplicate_root_alias_rejected"],
    "MC09_blank_alias_off": ["blank_root_alias_rejected", "blank_alias_yields_no_engine"],
    "MC10_mirror_drift": ["limits_round_trip_is_exact", "durations_map_to_engine_units"],
    "MC11_no_serde_default": ["absent_section_is_disabled"],
    "MC12_default_enables_files": ["absent_section_is_disabled"],
    "MC13_engine_window_ceiling_off": ["over_24h_window_rejected_by_config"],
    "MC14_blank_token_off": [
        "whitespace_only_token_rejected", "blank_token_yields_no_engine",
        "enabled_without_token_rejected"],
    "MC15_roots_nonempty_off": ["enabled_without_roots_rejected"],
    "MC16_seam_always_none": ["valid_config_launches_engine"],
    "MC17_skip_serializing_window": ["files_section_survives_json_round_trip"],
    "MC18_open_errors_swallowed": ["missing_root_path_rejected"],
    "MC19_idle_floor_off": ["idle_floor_rejected_by_config_layer"],
    "MC20_idle_ceiling_off": ["idle_ceiling_rejected_by_config_layer"],
    "MC21_window_ceiling_off_by_one": ["window_ceiling_boundary_is_usable"],
    "MC22_idle_ceiling_off_by_one": ["idle_ceiling_boundary_is_usable"],
    "MC23_window_floor_off_by_one": ["window_floor_boundary_is_usable"],
    "MC24_idle_floor_off_by_one": ["idle_floor_boundary_is_usable"],
    "MC25_engine_floor_to_one_second": [],
}


def coverage_report(flips_by_recipe, assertion_fields):
    """Machine-checkable coverage: which recipes target each assertion, and which
    assertions are only ever hit as collateral (or never at all)."""
    targeted = {}
    for recipe, cells in TARGETS.items():
        for c in cells:
            targeted.setdefault(c, []).append(recipe)
    print("=== COVERAGE 段（工具自打，不靠散文声明）===")
    for cell in assertion_fields:
        owns = sorted(targeted.get(cell, []))
        hits = sorted(r for r, fl in flips_by_recipe.items() if cell in fl)
        cascade = [r for r in hits if r not in owns]
        print("  %-46s targets=%s | flipped_by=%s%s" % (
            cell, ",".join(owns) or "NONE", ",".join(hits) or "-",
            (" | cascade_only_in=" + ",".join(cascade)) if cascade else ""))
    untargeted = [c for c in assertion_fields if not targeted.get(c)]
    print("  UNTARGETED（没有专属配方，只有级联或根本没翻）: %s"
          % (",".join(untargeted) or "none"))
    unknown = sorted({c for cells in TARGETS.values() for c in cells} - set(assertion_fields))
    print("  STALE_TARGETS（声明了但场景里没这格）: %s" % (",".join(unknown) or "none"))
    sys.stdout.flush()


def assertion_fields():
    return [f for f, want in EXPECT["config"] if want.strip('"').lower() not in ("pass",)
            and f != "case"]


def apply(path, orig, mut):
    body = PRISTINE[path]
    assert body.count(orig) == 1, "anchor %r count=%d" % (orig[:50], body.count(orig))
    open(path, "w", encoding="utf-8").write(body.replace(orig, mut, 1))


def restore_all():
    for p in PATHS:
        open(p, "w", encoding="utf-8").write(PRISTINE[p])
        assert open(p, encoding="utf-8").read() == PRISTINE[p], "restore mismatch %s" % p


def probe(case):
    raw = sh("cargo run -q -p nexus-web-gateway --example gateway_file_contract -- "
             "--case %s --json" % case)
    for ln in reversed(raw.splitlines()):
        try:
            return json.loads(ln), ""
        except json.JSONDecodeError:
            continue
    tail = [ln for ln in raw.splitlines() if ln.strip()][-2:]
    return None, " / ".join(t[:200] for t in tail)


def flips(data, exp):
    if not isinstance(data, dict):
        return None, len(exp)
    missing = [k for k, _ in exp if k not in data]
    out = []
    for field, want in exp:
        if field not in data:
            continue
        got = json.dumps(data[field])
        if got.strip('"') != want.strip('"') and str(data[field]).lower() != want.strip('"').lower():
            out.append((field, want, got))
    return out, len(missing)


def run(tag, mutated):
    out = sh("cargo test -p nexus-web-gateway --lib 2>&1")
    res = [ln for ln in out.splitlines() if ln.startswith("test result")]
    build = [ln for ln in out.splitlines() if ln.startswith("error")][:3]
    reds = sorted({ln.strip() for ln in out.splitlines()
                   if ln.startswith("    ") and "::tests::" in ln})
    print("=== %s  [%s] ===" % (tag, "MUTATED" if mutated else "baseline"))
    print("  lib:", res[-1].strip() if res else "NO RESULT")
    for b in build:
        print("  build:", b[:160])
    print("  red tests (%d):" % len(reds))
    # 不截断名单：r17 N-4 的一半问题是日志读不出全貌，`[:14]` 正是那种"看着全其实被切"
    # 的写法。配方最多红 6 条，全打不贵。
    for r in reds:
        print("   ", r)
    hits = []
    for case, _p in CASES:
        data, why = probe(case)
        exp = EXPECT[case]
        fl, missing = flips(data, exp)
        if fl is None:
            print("  probe %-13s: NO JSON (frozen=%d)  why: %s" % (case, len(exp), why[:200]))
            continue
        print("  probe %-13s: frozen=%d flips=%d missing=%d" % (case, len(exp), len(fl), missing))
        for field, want, got in fl:
            print("    FLIP %-44s want=%-6s got=%s" % (field, want, got[:36]))
        if case == "config":
            hits = [f for f, _w, _g in fl]
    sys.stdout.flush()
    return hits


bad = {n: PRISTINE[p].count(o) for n, p, o, _m in RECIPES if PRISTINE[p].count(o) != 1}
if bad:
    raise SystemExit("anchor precheck failed: %s" % bad)
print("anchor precheck ok: %d recipes" % len(RECIPES))

run("MC00_baseline", False)
FLIPS = {}
for name, path, orig, mut in RECIPES:
    apply(path, orig, mut)
    try:
        FLIPS[name] = run(name, True)
    finally:
        restore_all()
run("MC99_restored", False)
coverage_report(FLIPS, assertion_fields())

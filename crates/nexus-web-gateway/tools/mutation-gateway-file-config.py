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
    for r in reds[:14]:
        print("   ", r)
    for case, _p in CASES:
        data, why = probe(case)
        exp = EXPECT[case]
        fl, missing = flips(data, exp)
        if fl is None:
            print("  probe %-13s: NO JSON (frozen=%d)  why: %s" % (case, len(exp), why[:200]))
            continue
        print("  probe %-13s: frozen=%d flips=%d missing=%d" % (case, len(exp), len(fl), missing))
        for field, want, got in fl[:14]:
            print("    FLIP %-44s want=%-6s got=%s" % (field, want, got[:36]))
    sys.stdout.flush()


bad = {n: PRISTINE[p].count(o) for n, p, o, _m in RECIPES if PRISTINE[p].count(o) != 1}
if bad:
    raise SystemExit("anchor precheck failed: %s" % bad)
print("anchor precheck ok: %d recipes" % len(RECIPES))

run("MC00_baseline", False)
for name, path, orig, mut in RECIPES:
    apply(path, orig, mut)
    try:
        run(name, True)
    finally:
        restore_all()
run("MC99_restored", False)

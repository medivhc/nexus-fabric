#!/usr/bin/env python3
# ============================================================================
# guard-verify — 驱动执行 test-plan 中 selected 的测试，产出证据
# ----------------------------------------------------------------------------
# 流程位置：
#   env-check -> harness-select ->【guard-verify】-> evidence
#
# 为什么需要：
#   guard 此前只产出 test-plan.json（"本次能跑哪些"），但**不驱动执行**。
#   守卫的价值在于闭环：判定 -> 执行 -> 证据。guard-verify 补上执行这一段，
#   让 agent/CI 拿到的是「跑过的结果」而不是「计划」。
#
# 行为：
#   1. 产出/复用 test-plan.json（经 harness-select；BLOCKED 时透传 exit 2）
#   2. 对 selected 中每个测试 id：定位其 scenario toml，取 [when].command，
#      在**仓库根**执行（scenario 的 command 按仓库根相对路径编写）
#   3. skipped 项不执行，记为 SKIPPED（绝不计为 PASS）
#   4. 结果写入 .env-report/verify-results.json 并打印摘要 + STEP_SUMMARY 行
#
# 跨平台：脚本本身为纯 Python，无 bash 语法。scenario 命令中的 `python3`
#   会被规范化为当前解释器（Windows 常无 python3、只有 py 启动器）。
#
# 退出码：
#   0  无 FAIL（PASS + SKIPPED）
#   1  至少一个测试 FAIL
#   2  BLOCKED（harness-select 拒绝产出 test-plan）
#   3  参数或 IO 错误
# ============================================================================
import argparse, fnmatch, glob, json, os, subprocess, sys, time, datetime

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib

# 工具版本与产物 schema 版本（分离：工具迭代不一定改 schema）
VERSION = "1.0"
SCHEMA_VERSION = "1"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GUARD_ROOT = os.path.dirname(SCRIPT_DIR)
# 仓库根 = guard 目录的上一级（engineering/sandbox-env-guard -> <repo>）
REPO_ROOT = os.path.dirname(GUARD_ROOT)
HARNESS = os.path.join(SCRIPT_DIR, "harness-select")
ENV_CHECK = os.path.join(SCRIPT_DIR, "env-check")


def load_toml(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def scan_scenarios(dirpath):
    """扫描目录内所有 scenario toml，返回 [(id, path, command)]（递归，跳过 .git）。"""
    out = []
    if not dirpath or not os.path.isdir(dirpath):
        return out
    for p in sorted(glob.glob(os.path.join(dirpath, "**", "*.toml"), recursive=True)):
        if os.sep + ".git" + os.sep in p:
            continue
        try:
            doc = load_toml(p)
        except Exception as e:
            sys.stderr.write(f"[guard-verify] WARN cannot parse {p}: {e}\n")
            continue
        tid = doc.get("id")
        if not tid:
            continue
        cmd = (doc.get("when") or {}).get("command")
        out.append((tid, p, cmd))
    return out


def normalize_cmd(cmd):
    """把命令中的 `python3` / `python` 规范化为当前解释器。

    Windows 常无 `python3`（只有 `py` 启动器），而 scenario 的 command
    普遍写作 `python3 <相对仓库根的路径>`，直接执行会失败。
    """
    if not cmd:
        return None
    toks = cmd.split(None, 1)
    if toks and toks[0] in ("python3", "python"):
        exe = sys.executable
        if os.name == "nt":
            exe = subprocess.list2cmdline([exe])
        rest = toks[1] if len(toks) > 1 else ""
        return f"{exe} {rest}".strip()
    return cmd


def main():
    ap = argparse.ArgumentParser(
        prog="guard-verify",
        description="驱动执行 test-plan 中 selected 的测试，产出证据",
        epilog="退出码：0=无FAIL / 1=有FAIL / 2=BLOCKED / 3=参数或IO错误")
    ap.add_argument("--scenarios-dir", default=None,
                    help="scenario 目录（给 harness-select 用；与 --test-plan 二选一）")
    ap.add_argument("--test-plan", default=None,
                    help="复用已有 test-plan.json（跳过 harness-select）")
    ap.add_argument("--env-report", default=None,
                    help="env-report.json 路径（默认 <guard>/.env-report/env-report.json）")
    ap.add_argument("--map", default=None,
                    help="capability 映射表（默认 <guard>/test-capability-map.toml）")
    ap.add_argument("--out", default=None,
                    help="验证结果输出（默认 <guard>/.env-report/verify-results.json）")
    ap.add_argument("--filter", default=None,
                    help="只执行匹配该 fnmatch 表达式的测试 id")
    ap.add_argument("--limit", type=int, default=0,
                    help="最多执行 N 个测试（0=不限）")
    ap.add_argument("--dry-run", action="store_true",
                    help="只打印将要执行的测试清单，不实际运行")
    ap.add_argument("--timeout", type=int, default=300,
                    help="单个测试超时秒数（默认 300）")
    ap.add_argument("--refresh-env", action="store_true",
                    help="执行前先重跑 env-check 刷新能力矩阵")
    ap.add_argument("--version", action="version",
                    version=f"guard-verify {VERSION} (schema {SCHEMA_VERSION})")
    args = ap.parse_args()

    env_report = args.env_report or os.path.join(GUARD_ROOT, ".env-report", "env-report.json")
    cmap = args.map or os.path.join(GUARD_ROOT, "test-capability-map.toml")
    out_path = args.out or os.path.join(GUARD_ROOT, ".env-report", "verify-results.json")

    # ---- 1) 产出/复用 test-plan ----
    if args.test_plan:
        plan_path = args.test_plan
    elif args.scenarios_dir:
        if args.refresh_env or not os.path.isfile(env_report):
            r = subprocess.run([sys.executable, ENV_CHECK, "--out-dir",
                                os.path.dirname(env_report) or "."])
            if r.returncode != 0:
                sys.stderr.write("[guard-verify] ERROR env-check 失败\n")
                sys.exit(3)
        plan_path = os.path.join(tempfile_dir(), "guard-verify-plan.json")
        r = subprocess.run([sys.executable, HARNESS,
                            "--env-report", env_report, "--map", cmap,
                            "--scenarios-dir", args.scenarios_dir,
                            "--out", plan_path])
        if r.returncode == 2:
            # BLOCKED：守卫拒绝产出 test-plan，严格透传，绝不降级
            sys.stderr.write("[guard-verify] BLOCKED：harness-select 拒绝产出 test-plan\n")
            sys.exit(2)
        if r.returncode != 0:
            sys.stderr.write(f"[guard-verify] ERROR harness-select 失败 (exit {r.returncode})\n")
            sys.exit(3)
    else:
        sys.stderr.write("[guard-verify] ERROR: 需要 --scenarios-dir 或 --test-plan\n")
        sys.exit(3)

    with open(plan_path, encoding="utf-8") as f:
        plan = json.load(f)

    # 只在 scenarios 模式下执行：demo 模式的条目是 pattern 而非真实测试 id
    if plan.get("mode") != "scenarios":
        sys.stderr.write(
            f"[guard-verify] BLOCKED: test-plan mode={plan.get('mode')!r}，"
            "条目可能是 map pattern 而非真实测试 id，拒绝驱动执行\n"
        )
        sys.exit(2)

    # id -> (path, command)
    scen_dir = args.scenarios_dir
    index = {tid: (p, c) for tid, p, c in scan_scenarios(scen_dir)}

    selected = list(plan.get("selected", []))
    if args.filter:
        selected = [t for t in selected if fnmatch.fnmatch(t, args.filter)]
    if args.limit and args.limit > 0:
        selected = selected[: args.limit]

    # ---- dry-run：只列计划，不执行（CI 用它校验 test-plan 可执行性）----
    if args.dry_run:
        plan_report = {
            "schema_version": SCHEMA_VERSION,
            "generator": f"sandbox-env-guard/guard-verify {VERSION}",
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "mode": plan.get("mode"),
            "scenarios_dir": scen_dir,
            "env_report": env_report,
            "test_plan": plan_path,
            "dry_run": True,
            "results": [],
            "skipped": [
                {"id": s["id"], "required": s.get("required", []),
                 "blocked_by": s.get("blocked_by"), "verdict": "SKIPPED"}
                for s in plan.get("skipped", [])
            ],
            "summary": {
                "total": len(selected) + len(plan.get("skipped", [])),
                "selected": len(selected),
                "passed": 0,
                "failed": 0,
                "skipped": len(plan.get("skipped", [])),
                "no_command_or_scenario": 0,
            },
        }
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(plan_report, f, indent=2, ensure_ascii=False)
        print(f"[guard-verify] DRY-RUN: 将执行 {len(selected)} 个测试，"
              f"跳过 {len(plan.get('skipped', []))} 个")
        for tid in selected:
            entry = index.get(tid)
            cmd = entry[1] if entry else None
            print(f"  RUN  {tid}{'' if cmd else '  (无 command，执行时记 NO_COMMAND)'}")
        for s in plan.get("skipped", []):
            print(f"  SKIP {s['id']} <- {s['blocked_by']['capability']}")
        sys.exit(0)

    results = []
    for tid in selected:
        entry = index.get(tid)
        if entry is None:
            results.append({"id": tid, "path": None, "command": None,
                            "exit_code": None, "verdict": "NO_SCENARIO", "duration_ms": 0})
            continue
        path, raw_cmd = entry
        cmd = normalize_cmd(raw_cmd)
        if not cmd:
            results.append({"id": tid, "path": path, "command": raw_cmd,
                            "exit_code": None, "verdict": "NO_COMMAND", "duration_ms": 0})
            continue
        t0 = time.time()
        try:
            r = subprocess.run(cmd, cwd=REPO_ROOT, shell=True,
                               capture_output=True, text=True,
                               timeout=args.timeout)
            rc = r.returncode
            tail = (r.stdout + r.stderr).strip().splitlines()[-3:]
        except subprocess.TimeoutExpired:
            rc = None
            tail = [f"TIMEOUT after {args.timeout}s"]
        dur = int((time.time() - t0) * 1000)
        verdict = "PASS" if rc == 0 else "FAIL"
        results.append({"id": tid, "path": path, "command": cmd,
                        "exit_code": rc, "verdict": verdict,
                        "duration_ms": dur, "output_tail": tail})

    skipped = [{"id": s["id"], "required": s.get("required", []),
                "blocked_by": s.get("blocked_by"), "verdict": "SKIPPED"}
               for s in plan.get("skipped", [])]

    passed = sum(1 for r in results if r["verdict"] == "PASS")
    failed = sum(1 for r in results if r["verdict"] == "FAIL")
    nocmd = sum(1 for r in results if r["verdict"] in ("NO_COMMAND", "NO_SCENARIO"))

    summary = {
        "total": len(selected) + len(skipped),
        "selected": len(selected),
        "passed": passed,
        "failed": failed,
        "skipped": len(skipped),
        "no_command_or_scenario": nocmd,
    }

    report = {
        "schema_version": SCHEMA_VERSION,
        "generator": f"sandbox-env-guard/guard-verify {VERSION}",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "mode": plan.get("mode"),
        "scenarios_dir": scen_dir,
        "env_report": env_report,
        "test_plan": plan_path,
        "dry_run": False,
        "results": results,
        "skipped": skipped,
        "summary": summary,
    }

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"[guard-verify] total={summary['total']} passed={passed} "
          f"failed={failed} skipped={len(skipped)} no_command={nocmd}")
    for r in results:
        if r["verdict"] != "PASS":
            print(f"  ✗ {r['id']} -> {r['verdict']} (exit={r['exit_code']})")
            for ln in r.get("output_tail") or []:
                print(f"      | {ln}")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write("## guard-verify 摘要\n\n")
            f.write(f"- total={summary['total']} passed={passed} "
                    f"failed={failed} skipped={len(skipped)} no_command={nocmd}\n")
            for r in results:
                if r["verdict"] != "PASS":
                    f.write(f"- ✗ `{r['id']}` -> {r['verdict']} (exit={r['exit_code']})\n")

    sys.exit(1 if failed else 0)


def tempfile_dir():
    import tempfile
    return tempfile.gettempdir()


if __name__ == "__main__":
    main()

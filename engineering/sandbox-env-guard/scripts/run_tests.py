#!/usr/bin/env python3
# ============================================================================
# run_tests.py — sandbox-env-guard 自回归测试（darwin 工作流「实测表现」维度）
# ----------------------------------------------------------------------------
# 这是守卫自身的「测试 prompt 集」：用一组确定性能力矩阵 fixture（env-report）
# 真实驱动 harness-select，断言其 selected/skipped 判定是否符合 map 契约。
#
# 设计要点：
#   - 场景文件来自 quality/fixtures/scenarios/*.toml（同时验证递归扫描路径）
#   - 能力矩阵 fixture 内嵌于本文件（等价于 darwin 的 test-prompts.json）
#   - 期望结果随 fixture 写死，任何门控回归都会让测试变红
#   - 覆盖错误路径：路径不存在 -> exit 2；未指定 dir -> mode=demo
#
# 用法：python scripts/run_tests.py   （exit 0=全绿，非0=有失败）
# ============================================================================
import json, os, sys, subprocess, tempfile, importlib.util, importlib.machinery

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
SCENARIOS_DIR = os.path.join(PROJECT_ROOT, "quality", "fixtures", "scenarios")
MAP = os.path.join(PROJECT_ROOT, "test-capability-map.toml")
HARNESS = os.path.join(SCRIPT_DIR, "harness-select")
ENV_CHECK = os.path.join(SCRIPT_DIR, "env-check")


def load_env_check():
    """以模块方式加载 env-check（无 .py 后缀，用 SourceFileLoader 加载），供单元测试。
    env-check 的 main() 受 `if __name__ == "__main__"` 保护，import 不会触发运行。
    """
    loader = importlib.machinery.SourceFileLoader("env_check_mod", ENV_CHECK)
    spec = importlib.util.spec_from_loader("env_check_mod", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


# ----------------------------------------------------------------------------
# 能力矩阵 fixtures（name -> capabilities.status 字典）
# 仅列被门控关注的 capability；其余缺省视为 "ok"
# ----------------------------------------------------------------------------
def caps(**kw):
    # harness-select 按契约期望 capability 为对象 {"status": ...}（env-check 产物即此格式）
    base = {k: "ok" for k in (
        "linux_executor", "windows_executor", "openssh_e2e", "internet_egress",
        "tun_net_admin", "confidential_transport", "github_proxy", "crates_fetched")}
    base.update(kw)
    return {k: {"status": v} for k, v in base.items()}


FIXTURES = {
    "normal_linux": caps(
        windows_executor="unsupported",   # 真实 Linux 沙箱
        confidential_transport="unsupported",
    ),
    "no_openssh": caps(
        windows_executor="unsupported",
        confidential_transport="unsupported",
        openssh_e2e="missing",
    ),
    "no_egress": caps(
        windows_executor="unsupported",
        confidential_transport="unsupported",
        internet_egress="missing",
    ),
    "no_crates": caps(
        windows_executor="unsupported",
        confidential_transport="unsupported",
        crates_fetched="missing",
    ),
    "no_proxy": caps(
        windows_executor="unsupported",
        confidential_transport="unsupported",
        github_proxy="missing",
    ),
    "no_tun": caps(
        windows_executor="unsupported",
        confidential_transport="unsupported",
        tun_net_admin="missing",
    ),
    "windows_host": caps(
        # 在 Windows 上：linux 类场景 unsupported，其余 ok
        linux_executor="unsupported",
        windows_executor="ok",
    ),
    "full_missing": caps(
        linux_executor="unsupported",
        windows_executor="unsupported",
        openssh_e2e="missing",
        internet_egress="missing",
        tun_net_admin="missing",
        confidential_transport="unsupported",
        github_proxy="missing",
        crates_fetched="missing",
    ),
}

# 8 个 fixture 场景 id（与 quality/fixtures/scenarios/*.toml 一一对应）
S = {
    "n3": "product.n3-10-operator-grant",
    "web": "product.web-gateway-ssh",
    "win": "product.windows_linux_e5",
    "egress": "product.fabric-egress-remote",
    "cli": "product.cli-workspace-cache",
    "conf": "product.confidential-x",
    "fetch": "product.fetch-external-x",
    "net": "product.net-punch",
}

# 期望：(selected 集合, skipped 集合) —— 用 S 的键表示，跑前展开为完整 id
EXPECTED = {
    "normal_linux": ({"n3", "web", "egress", "cli", "fetch", "net"}, {"win", "conf"}),
    "no_openssh":   ({"n3", "egress", "cli", "fetch", "net"},        {"web", "win", "conf"}),
    "no_egress":    ({"n3", "web", "cli", "fetch", "net"},          {"egress", "win", "conf"}),
    "no_crates":    ({"n3", "web", "egress", "fetch", "net"},       {"cli", "win", "conf"}),
    "no_proxy":     ({"n3", "web", "egress", "cli", "net"},         {"fetch", "win", "conf"}),
    "no_tun":       ({"n3", "web", "egress", "cli", "fetch"},       {"net", "win", "conf"}),
    "windows_host": ({"web", "win", "egress", "conf", "fetch", "net"}, {"n3", "cli"}),
    "full_missing": (set(),                                      {"n3", "web", "win", "egress", "cli", "conf", "fetch", "net"}),
}


def run_harness(env_report_path, scenarios_dir):
    """真实驱动 harness-select，返回 (exit_code, parsed_json_or_None, stderr)。"""
    p = subprocess.run(
        [sys.executable, HARNESS,
         "--env-report", env_report_path,
         "--map", MAP,
         "--scenarios-dir", scenarios_dir,
         "--out", os.path.join(tempfile.gettempdir(), "tp_test.json")],
        capture_output=True, text=True)
    parsed = None
    try:
        parsed = json.loads(p.stdout)
    except Exception:
        pass
    return p.returncode, parsed, p.stderr


def main():
    failures = []

    # ---- 1) 正常门控矩阵 ----
    for name, capstatus in FIXTURES.items():
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump({"capabilities": capstatus}, tf)
            env_path = tf.name
        rc, plan, err = run_harness(env_path, SCENARIOS_DIR)
        os.unlink(env_path)
        exp_sel, exp_skip = EXPECTED[name]
        exp_sel_ids = {S[k] for k in exp_sel}
        exp_skip_ids = {S[k] for k in exp_skip}
        if rc != 0 or plan is None:
            failures.append(f"[{name}] harness-select 异常 exit={rc}\nstderr: {err[-300:]}")
            continue
        got_sel = set(plan["selected"])
        got_skip = {x["id"] for x in plan["skipped"]}
        if got_sel != exp_sel_ids:
            failures.append(
                f"[{name}] selected 不符\n  期望 {sorted(exp_sel_ids)}\n  实际 {sorted(got_sel)}")
        if got_skip != exp_skip_ids:
            failures.append(
                f"[{name}] skipped 不符\n  期望 {sorted(exp_skip_ids)}\n  实际 {sorted(got_skip)}")

    # ---- 2) 错误路径：路径不存在 -> exit 2 (BLOCKED，绝不静默降级) ----
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump({"capabilities": caps()}, tf)
        env_path = tf.name
    rc, _, err = run_harness(env_path, "/nonexistent-scenarios-dir")
    os.unlink(env_path)
    if rc != 2:
        failures.append(f"[bad_dir] 期望 exit=2 (BLOCKED)，实际 exit={rc}")

    # ---- 3) 错误路径：未指定 dir -> mode=demo ----
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump({"capabilities": caps()}, tf)
        env_path = tf.name
    p = subprocess.run(
        [sys.executable, HARNESS, "--env-report", env_path, "--map", MAP,
         "--out", os.path.join(tempfile.gettempdir(), "tp_demo.json")],
        capture_output=True, text=True)
    os.unlink(env_path)
    try:
        demo_plan = json.loads(p.stdout)
        demo_mode = demo_plan.get("mode")
    except Exception:
        demo_mode = None
    if demo_mode != "demo":
        failures.append(f"[demo] 期望 mode=demo，实际 {demo_mode}")

    # ---- 4) env-check：run_cmd 异常显式化（R2：不再静默吞）----
    ec = load_env_check()
    # 4a) 二进制不存在 → 返回 None（预期的「不存在」，不应触发 unknown）
    if ec.run_cmd("this_binary_does_not_exist_xyz") is not None:
        failures.append("[run_cmd] 不存在的二进制应返回 None，实际非 None")
    # 4b) 探测期操作失败（超时）→ 应抛 ProbeError，而非静默吞成 None/假绿
    try:
        ec.run_cmd("sleep", "5", timeout=1)
        failures.append("[run_cmd] 超时命令应抛 ProbeError，实际未抛（被静默吞了）")
    except ec.ProbeError:
        pass  # 期望：异常被显式抛出
    except Exception as e:
        failures.append(f"[run_cmd] 超时命令抛出的异常类型错误：{type(e).__name__}: {e}")

    # ---- 5) env-check 集成：TUN 三分支 + SKIP_NETWORK_PROBES（R2）----
    def run_env_check(extra_env):
        env = dict(os.environ, SKIP_NETWORK_PROBES="1")
        env.update(extra_env)
        p = subprocess.run([sys.executable, ENV_CHECK], capture_output=True, text=True,
                           env=env, timeout=60)
        try:
            return json.loads(p.stdout)
        except Exception:
            return None

    rep = run_env_check({})
    if rep is None:
        failures.append("[env-check] 正常跑未产出 JSON（stdout 异常）")
    else:
        # 本沙箱无 /dev/net/tun → missing（R2：无设备节点判 missing 而非 degraded）
        tun = rep["capabilities"]["tun_net_admin"]["status"]
        if tun != "missing":
            failures.append(f"[env-check] 无 /dev/net/tun 应判 missing，实际 {tun}")
        # SKIP_NETWORK_PROBES → 网络类能力记 unknown（「未探测」≠「缺失」）
        if rep["capabilities"]["github_proxy"]["status"] != "unknown":
            failures.append("[env-check] SKIP_NETWORK_PROBES 下 github_proxy 应 unknown")
        if rep["capabilities"]["internet_egress"]["status"] != "unknown":
            failures.append("[env-check] SKIP_NETWORK_PROBES 下 internet_egress 应 unknown")

    # 5b) TUN_DEVICE_PATH=/nonexistent → missing
    rep = run_env_check({"TUN_DEVICE_PATH": "/nonexistent"})
    if rep is None or rep["capabilities"]["tun_net_admin"]["status"] != "missing":
        got = rep["capabilities"]["tun_net_admin"]["status"] if rep else "N/A"
        failures.append(f"[env-check] TUN_DEVICE_PATH=/nonexistent 应 missing，实际 {got}")

    # 5c) TUN_DEVICE_PATH=普通文件 → 可 open 但 TUNSETIFF 失败 → degraded（避免假 ok）
    tmpf = tempfile.NamedTemporaryFile(delete=False).name
    rep = run_env_check({"TUN_DEVICE_PATH": tmpf})
    os.unlink(tmpf)
    if rep is None or rep["capabilities"]["tun_net_admin"]["status"] != "degraded":
        got = rep["capabilities"]["tun_net_admin"]["status"] if rep else "N/A"
        failures.append(f"[env-check] 普通文件应 degraded（非假 ok），实际 {got}")

    # ---- 6) 接口契约（R4）：--version / --help / 退出码 / guard-plan ----
    def run_tool(script, *args):
        return subprocess.run([sys.executable, os.path.join(SCRIPT_DIR, script), *args],
                              capture_output=True, text=True, timeout=60)

    # 6a) --version：应显式报错版本 + schema，exit 0
    for tool, name in (("env-check", "env-check"), ("harness-select", "harness-select")):
        p = run_tool(tool, "--version")
        if p.returncode != 0 or name not in p.stdout:
            failures.append(f"[{tool} --version] exit={p.returncode} stdout={p.stdout[:80]!r}")
        if "schema" not in p.stdout:
            failures.append(f"[{tool} --version] 输出未含 schema 版本：{p.stdout[:80]!r}")

    # 6b) --help：应列出关键参数，exit 0（env-check 此前无 argparse，根本没有 --help）
    for tool, expect in (("env-check", "--out-dir"), ("harness-select", "--scenarios-dir")):
        p = run_tool(tool, "--help")
        if p.returncode != 0 or expect not in p.stdout:
            failures.append(f"[{tool} --help] exit={p.returncode}，未列出 {expect}")

    # 6c) guard-plan 退出码显式翻译：坏路径 -> exit 2 且输出 BLOCKED（且不改 0）
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump({"capabilities": caps()}, tf)
        env_path = tf.name
    p = subprocess.run(
        [sys.executable, os.path.join(SCRIPT_DIR, "guard-plan"),
         "--env-report", env_path, "--map", MAP,
         "--out", os.path.join(tempfile.gettempdir(), "gp_bad.json"),
         "--scenarios-dir", "/nonexistent-scenarios-dir"],
        capture_output=True, text=True, timeout=60)
    if p.returncode != 2:
        failures.append(f"[guard-plan BLOCKED] 期望 exit=2（严格透传），实际 {p.returncode}")
    if "BLOCKED" not in p.stdout:
        failures.append(f"[guard-plan BLOCKED] 输出未显式标注 BLOCKED：{p.stdout[:120]!r}")

    # 6d) guard-plan 正常路径 -> exit 0 且输出 OK
    p = subprocess.run(
        [sys.executable, os.path.join(SCRIPT_DIR, "guard-plan"),
         "--env-report", env_path, "--map", MAP,
         "--out", os.path.join(tempfile.gettempdir(), "gp_ok.json"),
         "--scenarios-dir", SCENARIOS_DIR],
        capture_output=True, text=True, timeout=60)
    os.unlink(env_path)
    if p.returncode != 0 or "OK" not in p.stdout:
        failures.append(f"[guard-plan OK] exit={p.returncode} stdout={p.stdout[:120]!r}")

    # ---- 汇报 ----
    total = len(FIXTURES) + 2 + 1 + 3 + 6  # 门控矩阵 + bad_dir + demo + run_cmd + TUN三分支 + 接口契约
    passed = total - len(failures)
    print(f"[run_tests] 用例 {total}  通过 {passed}  失败 {len(failures)}")
    for f in failures:
        print("  ✗ " + f)
    if failures:
        print(f"[run_tests] FAILED ({len(failures)} 项)")
        sys.exit(1)
    print("[run_tests] ALL GREEN")
    sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""N2 P0-0 契约冻结 Red Evidence 运行器。

忠实复刻 engineering/nexus-harness/src/scenario.rs 的判定语义：
- [when].command 按空白切分执行，取 stdout（stderr 不参与判定）；
- stdout 解析为 JSON，失败即判 FAIL；
- [[expect]] 支持 equals / one_of / non_empty；
- 字段路径：先尝试完整 path 精确匹配（扁平键优先），再按 '.' 逐层下钻，
  数组支持数字下标（与 get_path 一致）。
输出 JSON 到 stdout；exit 0 恒为"运行器自身成功"，场景 verdict 见 JSON。
"""
import json
import subprocess
import sys
import tomllib
from pathlib import Path


def get_path(v, path):
    if isinstance(v, dict):
        if path in v:
            return v[path]
        if "." not in path:
            return None
        head, rest = path.split(".", 1)
        return get_path(v.get(head), rest)
    if isinstance(v, list):
        try:
            return v[int(path)]
        except (ValueError, IndexError):
            pass
        if "." not in path:
            return None
        head, rest = path.split(".", 1)
        try:
            return get_path(v[int(head)], rest)
        except (ValueError, IndexError):
            return None
    return None


def check_non_empty(v):
    if v is None:
        return False
    if isinstance(v, str):
        return len(v) > 0
    if isinstance(v, (list, dict)):
        return len(v) > 0
    if v is None:
        return False
    return True  # 与 harness 一致：其他标量视为 true


def run_one(toml_path, cwd, timeout=600):
    with open(toml_path, "rb") as f:
        d = tomllib.load(f)
    sid = d["id"]
    command = d["when"]["command"]
    expects = d.get("expect", [])
    try:
        p = subprocess.run(
            command.split(), cwd=cwd, capture_output=True, text=True,
            timeout=timeout,
        )
        stdout = p.stdout
    except Exception as e:
        return {"id": sid, "verdict": "FAIL",
                "detail": f"cannot run command: {e}", "expects": []}
    try:
        output = json.loads(stdout)
    except Exception:
        return {"id": sid, "verdict": "FAIL",
                "detail": "stdout is not JSON (command failed or unknown subcommand)",
                "stdout_head": stdout[:300], "expects": []}
    results = []
    failed = None
    for e in expects:
        field = e["field"]
        actual = get_path(output, field)
        if "equals" in e:
            ok = actual == e["equals"]
        elif "one_of" in e:
            ok = actual is not None and actual in e["one_of"]
        elif e.get("non_empty") is True:
            ok = check_non_empty(actual)
        else:
            ok, actual = False, "<unsupported expect kind>"
        results.append({"field": field, "ok": ok,
                        "actual": actual if ok else repr(actual)})
        if not ok and failed is None:
            failed = f"expect {sid}.{field} failed (actual: {actual!r})"
    return {"id": sid,
            "verdict": "PASS" if failed is None else "FAIL",
            "detail": failed or "all expects passed",
            "expects": results}


def main():
    if len(sys.argv) < 3:
        print("usage: run_red.py <worktree> <scenario.toml>...",
              file=sys.stderr)
        sys.exit(2)
    cwd, files = sys.argv[1], sys.argv[2:]
    out = [run_one(Path(f), cwd) for f in files]
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

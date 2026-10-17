import json, sys, re, pathlib, datetime, tomllib
list_path, root, run_id = sys.argv[1], sys.argv[2], sys.argv[3]
root = pathlib.Path(root)
data = json.loads(pathlib.Path(list_path).read_text(encoding="utf-8"))
scenarios = data.get("scenarios", [])
product = [s for s in scenarios if s.get("subdir") == "product"]
prod_text = (root / "PRODUCT.md").read_text(encoding="utf-8")
anchors = set(re.findall(r"\{#([a-z0-9-]+)\}", prod_text))
scenario_anchor = {}
for toml_path in sorted((root / "scenarios" / "product").glob("*.toml")):
    try:
        v = tomllib.loads(toml_path.read_text(encoding="utf-8"))
    except Exception:
        continue
    sid = v.get("id")
    req = v.get("requirement", "")
    m = re.search(r"#([a-z0-9-]+)", req)
    if sid and m:
        scenario_anchor[sid] = m.group(1)
anchor_to_scn = {a: [] for a in anchors}
unmapped = []
for s in product:
    a = scenario_anchor.get(s["name"])
    if a in anchor_to_scn:
        anchor_to_scn[a].append(s["name"])
    else:
        unmapped.append(s["name"])
out = root / "engineering" / "e2e" / "coverage_matrix.md"
lines = ["# E2E 覆盖矩阵（PRODUCT 锚点 × 场景）", ""]
lines.append("生成时间：" + datetime.datetime.now().isoformat(timespec="seconds") + "  run_id=" + run_id)
lines.append("场景总数：" + str(len(scenarios)) + "（product 子目录：" + str(len(product)) + "）  PRODUCT 锚点总数：" + str(len(anchors)))
lines.append("")
lines.append("| PRODUCT 锚点 | 覆盖场景数 | 场景 IDs |")
lines.append("|---|---:|---|")
for a in sorted(anchors):
    scns = anchor_to_scn.get(a, [])
    lines.append("| `" + a + "` | " + str(len(scns)) + " | " + (", ".join(scns) if scns else "— 无覆盖 —") + " |")
lines.append("")
lines.append("未映射到任何锚点的 product 场景数：" + str(len(unmapped)))
if unmapped:
    lines.append("")
    lines.append("未映射场景：" + ", ".join(unmapped[:40]) + (" …" if len(unmapped)>40 else ""))
out.write_text("\n".join(lines) + "\n", encoding="utf-8")
todo = root / "engineering" / "e2e" / "acceptance_todo.md"
todo_lines = ["# E2E 验收 Todo（无覆盖锚点）", ""]
todo_lines.append("生成时间：" + datetime.datetime.now().isoformat(timespec="seconds") + "  run_id=" + run_id)
todo_lines.append("")
zero = sorted(a for a in anchors if not anchor_to_scn.get(a))
todo_lines.append("无 E4 覆盖的锚点数：" + str(len(zero)) + " / " + str(len(anchors)))
todo_lines.append("")
for a in zero:
    todo_lines.append("- [ ] `" + a + "` — 需补充 E4 场景或 requirement-change 说明")
todo.write_text("\n".join(todo_lines) + "\n", encoding="utf-8")
snap = {"run_id": run_id, "scenario_count": len(scenarios), "product_count": len(product),
        "anchor_count": len(anchors), "covered_anchor_count": len(anchors)-len(zero),
        "zero_coverage_anchors": zero, "unmapped_scenario_count": len(unmapped)}
(root / ".evidence" / "e2e-acceptance" / (run_id + ".json")).write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
print("covered=" + str(len(anchors)-len(zero)) + "/" + str(len(anchors)) + "  unmapped=" + str(len(unmapped)))

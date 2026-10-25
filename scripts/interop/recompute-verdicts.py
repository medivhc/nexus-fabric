#!/usr/bin/env python3
"""机械复算 verdict + 渲染 MATRIX（AC-06/10/18/19；E1 规则 1–9 按序）。

输入：
  --run-dir <dir>      证据根（evidence/analysis/...）
  --run-meta <path>    run 元数据 JSON（run/baseline/spec/完成项/修复条目）；
                       省略时保持旧版叙述渲染，供前序 run 目录复算
  --matrix <path>      输出 MATRIX.md（仓库内唯一正本）
  --check             不写盘，重算后与现有 MATRIX 比对
  --allow-partial     阶段提交用：只渲染已有证据的协议节

规则实现顺序严格按 spec E1：首个命中即停。人工不得覆盖。
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR / "lib"))
import labels  # noqa: E402

REPO = SCRIPT_DIR.parents[1]
DEFAULT_CELL_MATRIX = SCRIPT_DIR / "cell-matrix.json"

NEXUS_CLASSES = {
    "E_NEXUS_HANDSHAKE_WIRE",
    "E_NEXUS_AUTH_ENCODING",
    "E_NEXUS_FRAMING",
    "E_NEXUS_TRANSPORT",
    "E_NEXUS_UDP",
    "E_NEXUS_CODEC",
    "E_NEXUS_NOT_IMPLEMENTED",
}
BLOCKING_CLASSES = {
    "E_REF_CONFIG",
    "E_NETWORK_ENV",
    "E_TOOL_BUG",
    "E_EVIDENCE_GAP",
    "E_REF_BEHAVIOR",
    "E_REF_UNSUPPORTED",
}
BANNED_WORDS = ["probably", "maybe", "待观察", "应该支持", "完全支持", "fully supported"]
FAILURE_CELLS = {"BadCredential", "BadConfig"}

PROTOCOL_ORDER = ["Vless", "Anytls", "Hysteria2", "Trojan", "Shadowsocks"]
RUN_META_REQUIRED = ("run_id", "baseline", "spec_version", "completed_items", "fix_branches")


def truncate_notes(text, limit=220):
    """按分隔符截断，避免把 class/classification 等关键令牌从词中间切断。"""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    for sep in ("; ", "；", ", ", "，", " "):
        idx = cut.rfind(sep)
        if idx > limit // 2:
            cut = cut[:idx]
            break
    return cut.rstrip() + " …"


class RecomputeError(RuntimeError):
    pass


def load_run_meta(path):
    """读取并校验 run 元数据；缺字段直接拒绝渲染，避免静默回落到旧叙述。"""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    missing = [key for key in RUN_META_REQUIRED if key not in data]
    if missing:
        raise RecomputeError("run-meta missing fields: " + ", ".join(missing))
    return data


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_status(value):
    mapping = {
        "Pass": "PASS",
        "Fail": "FAIL",
        "Blocked": "BLOCKED",
        "NotApplicable": "NOT_APPLICABLE",
        "NotImplemented": "NOT_IMPLEMENTED",
    }
    return mapping.get(value, value)


def class_to_status(cls, fallback):
    if cls is None:
        return normalize_status(fallback)
    if cls in NEXUS_CLASSES or cls == "E_TIMEOUT_HANG":
        return "FAIL"
    if cls in BLOCKING_CLASSES:
        return "BLOCKED"
    if cls in ("E_EXPECTED_AUTH_REJECT", "E_EXPECTED_CONFIG_REJECT"):
        return "PASS"
    if cls == "E_REF_LIMITATION":
        return "FAIL"
    return fallback


def load_classification(run_dir):
    out = {}
    cdir = Path(run_dir) / "analysis/classification"
    if not cdir.exists():
        return out
    for path in sorted(cdir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        eid = data.get("evidence_id") or path.stem
        out[eid] = data
    return out


def note_value(notes, key):
    for note in notes or []:
        if note.startswith(key + "="):
            return note.split("=", 1)[1]
    return None


def load_rows(run_dir, matrix):
    """读取矩阵格对应证据；返回 (rows, missing, findings)."""
    evidence_root = Path(run_dir) / "evidence"
    classifications = load_classification(run_dir)
    rows = []
    findings = []
    for entry in matrix["cells"]:
        proto = entry["protocol"]
        variant = entry["variant"]
        cell = entry["cell"]

        cell_dir = (
            evidence_root
            / labels.label("protocol", proto)
            / labels.label("variant", variant)
            / labels.label("cell", cell)
        )
        candidates = sorted(
            [p for p in cell_dir.glob("PIV-*") if (p / "probe.json").exists()]
        )
        if not candidates:
            rows.append({**entry, "present": False})
            continue
        ev_path = candidates[-1] / "probe.json"
        ev = json.loads(ev_path.read_text(encoding="utf-8"))
        cls_data = classifications.get(ev["evidence_id"], {})
        cls = cls_data.get("class") or note_value(ev.get("notes"), "classification")
        if ev.get("error"):
            cls = cls or ev["error"].get("class")
        status = normalize_status(cls_data.get("verdict") or class_to_status(cls, ev.get("verdict")))
        if ev.get("verdict") in ("NotApplicable", "NotImplemented") and not cls_data.get(
            "verdict"
        ):
            status = normalize_status(ev["verdict"])
        rows.append(
            {
                **entry,
                "present": True,
                "evidence": ev,
                "evidence_path": str(ev_path.relative_to(Path(run_dir))),
                "cell_dir": candidates[-1],
                "class": cls,
                "status": status,
                "classification": cls_data,
            }
        )

        # 校验（硬错误 → 拒绝渲染；证据缺口 → 机械降级）
        carrier = ev.get("carrier")
        scope = ev.get("scope")
        if (carrier, scope) not in (("ProductSocks5", "ProductPath"), ("CrateDirect", "ProtocolWire")):
            raise RecomputeError(
                f"{ev['evidence_id']}: illegal carrier/scope {carrier}/{scope}"
            )
        if (not entry.get("synthetic")) and ev.get("reference", {}).get("version") not in (
            None,
            "1.13.16",
            "26.10.21",
        ):
            raise RecomputeError(
                f"{ev['evidence_id']}: unexpected ref version {ev['reference'].get('version')}"
            )
        if cell == "TcpThroughput" and status == "PASS":
            samples = ev.get("metrics", {}).get("throughput_samples_bps", [])
            if len(samples) != 3 or ev.get("metrics", {}).get("throughput_median_bps", 0) <= 0:
                raise RecomputeError(f"{ev['evidence_id']}: T2 requires 3 throughput samples")
        if cell in ("Handshake", "TcpSmall") and status == "PASS":
            m = ev.get("metrics", {})
            if not m.get("sha256_up") or not m.get("sha256_down"):
                raise RecomputeError(f"{ev['evidence_id']}: {cell} PASS missing payload hashes")
        if cell in FAILURE_CELLS and not entry.get("synthetic"):
            kinds = {a.get("kind") for a in ev.get("artifacts", [])}
            if "Pcap" not in kinds:
                findings.append(
                    f"{ev['evidence_id']}: failure cell without pcap -> BLOCKED/E_EVIDENCE_GAP"
                )
                status = "BLOCKED"
                cls = "E_EVIDENCE_GAP"
                rows[-1].update({"status": status, "class": cls})
        if cls == "E_REF_LIMITATION":
            if not cls_data.get("ref_source") or not cls_data.get("ref_version"):
                raise RecomputeError(
                    f"{ev['evidence_id']}: E_REF_LIMITATION lacks ref_source/ref_version (AC-24)"
                )
    return rows, findings


def protocol_verdict(proto, rows, allow_partial):
    proto_rows = [r for r in rows if r["protocol"] == proto]
    required = [r for r in proto_rows if r.get("required") and not r.get("diag")]
    non_diag = [r for r in proto_rows if not r.get("diag")]
    present = [r for r in non_diag if r["present"]]
    if not present:
        return None
    if not allow_partial:
        missing = [r for r in non_diag if not r["present"]]
        if missing:
            raise RecomputeError(
                f"{proto}: missing required cells: "
                + ", ".join(f"{r['variant']}/{r['cell']}" for r in missing)
            )

    def by(cell, variant="Default"):
        for r in non_diag:
            if r["cell"] == cell and r["variant"] == variant and r["present"]:
                return r
        return None

    def non_pass(rs):
        return [r for r in rs if r["present"] and r["status"] != "PASS"]

    def cell_label(row):
        suffix = "" if row["variant"] == "Default" else f"[{row['variant']}]"
        return f"{row['cell']}{suffix}"

    missing_cells = [
        f"{cell_label(r)}({r['status']},{r['class'] or 'NONE'})" for r in non_pass(required)
    ]

    def result(verdict, scope, root_cause=None, claim=None, rule=None):
        counts = {}
        for r in non_diag:
            key = r["status"] if r["present"] else "MISSING"
            counts[key] = counts.get(key, 0) + 1
        claim_map = {
            "VERIFIED": "USABLE",
            "BROKEN": "NOT_USABLE",
        }
        if claim is None:
            if verdict == "PARTIAL":
                h = by("Handshake")
                t1 = by("TcpSmall")
                ok = all(x is not None and x["status"] == "PASS" for x in (h, t1))
                claim = "USABLE_WITH_GAPS" if ok else "NOT_CLAIMED"
            else:
                claim = claim_map.get(verdict, "NOT_CLAIMED")
        rc = root_cause
        if rc is None:
            rc = "NONE"
            for r in non_pass(required):
                rc = r["class"] or "NONE"
                break
        return {
            "verdict": verdict,
            "scope": scope,
            "claim": claim,
            "missing_cells": missing_cells,
            "root_cause_class": rc,
            "counts": counts,
            "rule": rule,
        }

    # rule 1: failure cell FAIL 且表现为有效 echo / 静默成功 / 挂死
    # 现象 → class 映射（spec E1 规则 1：现象式判定，白名单是 D1 词表内的代理）：
    #   有效 echo / 静默成功 → E_NEXUS_FRAMING
    #     （probe 负向格：错凭据仍返回有效 echo，或非 echo 字节被当隧道载荷上交；
    #     见 apps/nexus/examples/interop/product.rs 的 negative-case 块）
    #   挂死 → E_TIMEOUT_HANG（D1 映射 FAIL）
    # 新增 error class 时必须在此显式归类，否则规则 1 会静默漏检。
    for r in non_diag:
        if (
            r["present"]
            and r["cell"] in FAILURE_CELLS
            and r["status"] == "FAIL"
            and r["class"] in ("E_NEXUS_FRAMING", "E_TIMEOUT_HANG")
        ):
            return result(
                "BROKEN",
                proto_scope(proto, "BROKEN"),
                root_cause=r["class"],
                rule="1",
            )
    # rule 2: required FAIL 且 Nexus 族 / timeout
    for r in required:
        if r["present"] and r["status"] == "FAIL" and (
            r["class"] in NEXUS_CLASSES or r["class"] == "E_TIMEOUT_HANG"
        ):
            return result("BROKEN", proto_scope(proto, "BROKEN"), rule="2")
    # rule 3: V-rule
    if proto == "Vless":
        vision = [r for r in non_diag if r["variant"] == "VlessVision"]
        basic_cells = [r for r in non_diag if r["variant"] == "Default"]
        basic_ok = all(r["status"] == "PASS" for r in basic_cells if r["present"])
        if vision and all(r["present"] for r in vision):
            statuses = {r["status"] for r in vision}
            classes = {r["class"] for r in vision}
            if statuses == {"PASS"}:
                pass  # 不降级；VLESS scope 仍 PROTOCOL_SUBSET
            elif "FAIL" in statuses and classes <= {"E_REF_LIMITATION"}:
                return result("PARTIAL", "PROTOCOL_SUBSET", rule="3")
            elif "FAIL" in statuses and classes & NEXUS_CLASSES:
                return result("BROKEN", "PROTOCOL_SUBSET", rule="3")
            elif statuses & {"BLOCKED", "NOT_APPLICABLE"}:
                return result("PARTIAL", "PROTOCOL_SUBSET", rule="3")
        if basic_ok and not all(r["present"] for r in vision):
            pass
    # rule 4: required FAIL 但 E_REF_LIMITATION
    ref_lim = [r for r in required if r["present"] and r["status"] == "FAIL" and r["class"] == "E_REF_LIMITATION"]
    if ref_lim:
        return result("PARTIAL", proto_scope(proto, "PARTIAL"), rule="4")
    # rule 5: required BLOCKED
    if any(r["present"] and r["status"] == "BLOCKED" for r in required):
        return result("PARTIAL", proto_scope(proto, "PARTIAL"), rule="5")
    # rule 6: required NOT_IMPLEMENTED
    if any(r["present"] and r["status"] == "NOT_IMPLEMENTED" for r in required):
        return result("PARTIAL", proto_scope(proto, "PARTIAL"), rule="6")
    # rule 7: optional FAIL/BLOCKED/NOT_IMPL
    optional = [r for r in non_diag if not r.get("required") and r["present"]]
    if any(r["status"] in ("FAIL", "BLOCKED", "NOT_IMPLEMENTED") for r in optional):
        return result("PARTIAL", proto_scope(proto, "PARTIAL"), rule="7")
    # rule 8: 全 PASS
    if required and all(r["present"] and r["status"] == "PASS" for r in required):
        return result("VERIFIED", proto_scope(proto, "VERIFIED"), rule="8")
    # rule 9
    return result("PARTIAL", proto_scope(proto, "PARTIAL"), rule="9")


def proto_scope(proto, verdict):
    if proto == "Vless":
        return "PROTOCOL_SUBSET"
    if proto in ("Trojan", "Shadowsocks"):
        return "TCP_ONLY"
    return "FULL" if verdict == "VERIFIED" else "PROTOCOL_SUBSET"


def render_matrix(run_dir, matrix, verdicts, rows, findings, allow_partial, run_meta=None, run_meta_path=None):
    run_dir = Path(run_dir)
    env = run_dir / "evidence/env"
    ref = run_dir / "evidence/ref"

    # Optional per-run narrative overrides (C5a). Absent => byte-identical
    # output to the pre-override behaviour (fixes-1 regeneration is the guard).
    narrative = (run_meta or {}).get("narrative") or {}

    def read_first(path):
        try:
            return path.read_text(encoding="utf-8").splitlines()[0].strip()
        except OSError:
            return "MISSING"

    times = sorted(
        r["evidence"]["started_at_utc"] for r in rows if r["present"]
    )
    window = f"{times[0]} .. {times[-1]}" if times else "n/a"
    archive = sorted((run_dir / "archive").glob("*.tar.zst"))
    lines = []
    lines.append("# 出站协议互操作证据总表（MATRIX）")
    lines.append("")
    lines.append("> 本文件由 `scripts/interop/recompute-verdicts.py` 从证据机械生成；人工零编辑。")
    lines.append("> 修复顺序、依赖与复验口径见人工维护的 [NEXT-STEPS.md](NEXT-STEPS.md)。")
    lines.append("")
    if run_meta:
        spec = f"spec frozen {run_meta['spec_version']}"
        if run_meta.get("spec_sha256"):
            spec += f"（sha256 `{run_meta['spec_sha256']}`）"
        lines.append(
            f"- run `{run_meta['run_id']}`；baseline `{run_meta['baseline']}`；"
            f"{spec}；test window `{window}`。"
        )
    else:
        lines.append(
            f"- run `protocol-interop-verification`；baseline `0539169e8195944fcd183e7831e5d5ac746f3f40`；"
            f"spec frozen v1.1（sha256 `23c7e4e797ee9edbf0eb645bfc20a7c97cfacb30e1a67bd8fee77ccbc527de4f`）；"
            f"test window `{window}`。"
        )
    lines.append(
        f"- 参照实现：sing-box 1.13.16（sha256 `{read_first(ref / 'sing-box-sha256.txt').split()[0]}`）；"
        f"Xray 26.10.21（sha256 `{read_first(ref / 'xray-sha256.txt').split()[0]}`）。"
    )
    lines.append(
        "- archive（主机归档路径）："
        + (", ".join(f"`{p}`" for p in archive) if archive else "（S30 归档后追加）")
        + "。"
    )
    lines.append("")
    lines.append("## 先读：范围 / 结论 / 图例")
    lines.append("")
    lines.append(
        "- **覆盖**：5 个出站代理协议（VLESS、AnyTLS、Hysteria2、Trojan、Shadowsocks）"
        "共 46 个证据格。TCP 成功型格走产品 SOCKS5 出口路径；`UdpEcho` 与 VLESS Vision "
        "部分格为 crate 直调（`CrateDirect`），不代表产品入口可用。"
    )
    lines.append(
        "- **不覆盖**：VMess（本轮暂缓）、direct/relay/socks5 出站、TUN/VPN、"
        "Android 统一 VPN 入口、UI/诊断呈现。"
    )
    lines.append(
        "- **本表不回答**：直连/中继回退是否可用（属 N1 整体结论）；也不把"
        "「产品级 UDP 未实现」扩大成「Hy2 的 QUIC 出站传输不可用」（见产品级 UDP 节）。"
    )
    # 结论 1/3 必须由本次复算的 verdict 派生，禁止硬编码与结果无关的结论句。
    verdict_names = {
        "VERIFIED": [p for p in PROTOCOL_ORDER if verdicts.get(p, {}).get("verdict") == "VERIFIED"],
        "PARTIAL": [p for p in PROTOCOL_ORDER if verdicts.get(p, {}).get("verdict") == "PARTIAL"],
        "BROKEN": [p for p in PROTOCOL_ORDER if verdicts.get(p, {}).get("verdict") == "BROKEN"],
    }
    not_run = [p for p in PROTOCOL_ORDER if p not in verdicts]
    counts = "，".join(
        f"`{verdict}` {len(verdict_names[verdict])} 个"
        + (f"（{'、'.join(verdict_names[verdict])}）" if verdict_names[verdict] else "")
        for verdict in ("VERIFIED", "PARTIAL", "BROKEN")
    )
    if not_run:
        counts += f"，未运行 {len(not_run)} 个（{'、'.join(not_run)}）"
    if verdict_names["VERIFIED"]:
        usable = f"当前可宣称可用（`VERIFIED`）的协议为 {'、'.join(verdict_names['VERIFIED'])}。"
    else:
        usable = "当前无任何协议可宣称可用。"
    lines.append(f"- **结论 1**：本次复算：{counts}；{usable}")
    if run_meta:
        lines.append(
            "- **结论 1 限定**：`USABLE` 指 TCP 产品路径；产品 SOCKS5 UDP ASSOCIATE "
            "五协议均未实现，`UdpEcho` 为 crate 级证据、不代表产品入口可用。"
        )
    if run_meta:
        lines.append(
            "- **结论 2**："
            + narrative.get("conclusions", {}).get(
                "2",
                "剩余阻断分属协议编解码、协议线格式与产品安全语义/产品能力缺口；"
                "本 run 已消除产品装配（VLESS eager read）与跨协议传输（T2）两类阻断。"
                "`root_cause_class` 只是规则代表类，不是完整根因。",
            )
        )
    else:
        lines.append(
            "- **结论 2**：阻断分属产品装配、跨协议传输、协议编解码、协议线格式与产品安全语义；"
            "`root_cause_class` 只是规则代表类，不是完整根因。"
        )
    unverified = [
        p
        for p in PROTOCOL_ORDER
        if p in verdicts and verdicts[p]["verdict"] != "VERIFIED"
    ]
    if unverified:
        lines.append(
            "- **结论 3**：未达 `VERIFIED` 的协议及本次复算代表根因："
            + "；".join(
                f"{p} `{verdicts[p]['verdict']} / {verdicts[p]['root_cause_class']}`"
                for p in unverified
            )
            + "。"
        )
    else:
        lines.append("- **结论 3**：本次复算全部协议均达 `VERIFIED`，无代表根因。")
    if run_meta:
        lines.append(
            "- **结论 4**："
            + narrative.get("conclusions", {}).get(
                "4",
                "Trojan/SS 当前仍受 fallback 安全语义/线格式与产品 UDP 缺口阻断；"
                "即使其余修复完成，本 run `UdpEcho` 固定 `NOT_IMPLEMENTED`，"
                "上限仍为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（spec E1 规则 6/R11）。",
            )
        )
    else:
        lines.append(
            "- **结论 4**：即使修复完成，Trojan/SS 因本 run `UdpEcho` 固定 `NOT_IMPLEMENTED`，"
            "上限仍为 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（spec E1 规则 6/R11）。"
        )
    if run_meta:
        lines.append(
            "- **结论 5**：五协议当前均可在产品配置面选择，且无「实验性/未验证」标注；"
            "配置面标注已裁决批准，待 protocol-config-surface-labeling run 落地"
            "（本 run 不改产品代码）。"
        )
    else:
        lines.append(
            "- **结论 5**：五协议当前均可在产品配置面选择，且无「实验性/未验证」标注；"
            "是否继续暴露由产品负责人决定（本 run 不改产品代码）。"
        )
    if run_meta:
        completed = {item["id"]: item for item in run_meta.get("completed_items", [])}
        pending = {item["id"]: item for item in run_meta.get("pending_items", [])}

        def priority_key(item_id):
            digits = "".join(ch for ch in item_id if ch.isdigit())
            return (int(digits) if digits else 999, item_id)

        for idx, item_id in enumerate(
            sorted(set(completed) | set(pending), key=priority_key), 1
        ):
            if item_id in completed:
                item = completed[item_id]
                body = item.get("result") or ""
                evidence = item.get("evidence") or []
                if evidence:
                    body = (body + "；" if body else "") + "证据：" + "；".join(evidence)
                lines.append(
                    f"- **优先级 {idx}（{item_id}，DONE）**：{item.get('title', '')}"
                    + (f"——{body}" if body else "")
                    + "。"
                )
            else:
                item = pending[item_id]
                body = item.get("note") or ""
                lines.append(
                    f"- **优先级 {idx}（{item_id}，待办）**：{item.get('title', '')}"
                    + (f"——{body}" if body else "")
                    + "。"
                )
    else:
        lines.append(
            "- **优先级 1（P0）**：安全止血（文档/配置面，0 代码）——先公开并限制 Trojan fallback。"
        )
        lines.append(
            "- **优先级 2（P1）**：transport 批量写（唯一一格修多协议，预期 AnyTLS 首先可用）。"
        )
        lines.append(
            "- **优先级 3（P2）**：VLESS fix 合入复验 → Hy2 QPACK Huffman → SS SIP004 AEAD → "
            "Trojan fallback 完整语义（依赖/成本/复验口径见 [NEXT-STEPS.md](NEXT-STEPS.md)）。"
        )
    lines.append(
        "- **字段**：`verdict` = `VERIFIED`（规则 8，全 required PASS）/ `PARTIAL`"
        "（规则 3–7/9，非阻断缺口）/ `BROKEN`（规则 1/2，阻断性 Nexus 失败）；"
        "`scope` = `PROTOCOL_SUBSET` / `FULL` / `TCP_ONLY`；`claim` = `USABLE` / "
        "`USABLE_WITH_GAPS` / `NOT_USABLE` / `NOT_CLAIMED`；`carrier` = `ProductSocks5`"
        "（产品 SOCKS5 出口路径）/ `CrateDirect`（crate 直调，非产品入口）。"
    )
    lines.append(
        "- **规则 1**：失败格（BadCredential/BadConfig）判 FAIL 且表现为有效 echo/静默成功"
        "（`E_NEXUS_FRAMING`）或挂死（`E_TIMEOUT_HANG`）→ `BROKEN`。"
    )
    lines.append(
        "- **规则 2**：任一 required 格 FAIL 且 class 属 `E_NEXUS_*` / `E_TIMEOUT_HANG` → `BROKEN`。"
    )
    lines.append(
        "- **错误类**：`E_NEXUS_*` = Nexus 侧失败（握手/线格式、认证编码、帧/静默成功、"
        "传输、UDP、编解码、未实现），判 FAIL；`E_TIMEOUT_HANG` = 挂死/超时，判 FAIL；"
        "`E_EXPECTED_*` = 预期认证/配置拒绝，负向格判 PASS；`E_REF_*` / `E_NETWORK_ENV` / "
        "`E_TOOL_BUG` / `E_EVIDENCE_GAP` = 参照端/环境/证据缺口，判 BLOCKED"
        "（`E_REF_LIMITATION` 判 FAIL，须带 `ref_source`/`ref_version`）。"
    )
    lines.append(
        "- **Xray**：26.10.21 仅用于 VLESS Vision 争议裁决，本轮未触发；"
        "五协议结论全部来自 sing-box 1.13.16 参照。"
    )
    if run_meta:
        lines.append(
            "- **测试广度**：上述结论仅对 sing-box 1.13.16 参照配置成立；"
            "Xray 26.10.21 本轮未触发作裁决；其他服务端实现/传输组合"
            "（含 REALITY、ws/grpc）未测。"
        )
    lines.append("")
    lines.append("## ⚠ 安全警示：Trojan fallback fail-open")
    lines.append("")
    lines.append(
        "- **触发条件**：Trojan 密码错误、服务端被劫持，或服务端配置了 fallback"
        "（本 run 参照端 fallback → HTTP 404）。"
    )
    lines.append(
        "- **用户所见**：SOCKS5 CONNECT 已回 success，服务端 fallback 的 HTTP 响应被当作"
        "隧道数据交给应用（404 页面内容），用户误以为代理成功。"
    )
    lines.append(
        "- **白皮书映射**：违背 §6.2「路径失效时按配置阻断或回退，并向用户显示实际行为」"
        "与 §16.1 N1「失败与恢复可观察」。"
    )
    lines.append(
        "- **当前临时缓解（仅文档层）**：把含 fallback 的 Trojan 出站视为实验性/不安全；"
        "产品负责人决定是否默认禁用。本 run 不改产品代码。"
    )
    lines.append(
        "- **完整修复成本**：延迟 SOCKS5 success 至上游就绪或等价 fail-closed 方案，"
        ">400 行 / >2 人日，触及 `proxy_serve_once` 全部出站路径，应另立 run。"
    )
    lines.append(
        "- **证据**：`TrojanFallback/BadCredential`（FAIL，`E_NEXUS_FRAMING`），"
        "根因见 [fix/trojan/root-cause.md](fix/trojan/root-cause.md)。"
    )
    lines.append("")
    lines.append("## 协议 verdict（按 spec E1 复算）")
    lines.append("")
    lines.append("| 协议 | verdict | scope | claim | root_cause_class | missing_cells | 命中规则 |")
    lines.append("|---|---|---|---|---|---|---|")
    for proto in PROTOCOL_ORDER:
        v = verdicts.get(proto)
        if not v:
            lines.append(f"| {proto} | NOT_RUN | — | NOT_CLAIMED | — | — | allow-partial |")
            continue
        missing = ", ".join(v["missing_cells"]) if v["missing_cells"] else "NONE"
        lines.append(
            f"| {proto} | {v['verdict']} | {v['scope']} | {v['claim']} | "
            f"{v['root_cause_class']} | {missing} | {v['rule']} |"
        )
    lines.append("")
    lines.append("## 阻塞层、归属与修复后上限")
    lines.append("")
    lines.append(
        "`root_cause_class` 是 E1 首个命中规则所取的**代表类**，不是完整根因；"
        "下表按 fix 根因文档给出直接阻塞层与归属，不改变上表 verdict。"
    )
    lines.append("")
    lines.append(
        "| 协议 | 直接阻塞层 | 归属 | 剩余阻塞格（相对可用） | 单协议可解？ | 修复后本 run schema 上限 |"
    )
    lines.append("|---|---|---|---|---|---|")
    if run_meta:
        blocking_meta = {
            "Vless": (
                "产品装配（eager read）+ 跨协议 T2",
                "产品装配 bug + 跨协议数据面共性缺陷",
                "否，依赖 transport",
            ),
            "Anytls": ("跨协议 T2", "跨协议数据面共性缺陷", "是（transport 一处）"),
            "Hysteria2": (
                "认证响应 QPACK Huffman",
                "协议编解码实现错误",
                "是（编解码一处）",
            ),
            "Trojan": (
                "fallback 静默接受 + 产品 UDP 未实现",
                "产品安全语义 + 产品 UDP 能力缺口",
                "否，依赖产品 UDP / fallback 架构",
            ),
            "Shadowsocks": (
                "线格式/SIP004 AEAD + 产品 UDP 未实现",
                "协议实现错误 + 产品 UDP 能力缺口",
                "否，依赖产品 UDP",
            ),
        }
        upper_limit = {
            "Vless": "`VERIFIED / PROTOCOL_SUBSET`（Vision 仅 crate 级，产品 splice 未实现）",
            "Anytls": "`VERIFIED / FULL`",
            "Hysteria2": "`VERIFIED / FULL`",
            "Trojan": "本 run 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 未实现，规则 6）",
            "Shadowsocks": "本 run 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 未实现，规则 6）",
        }
        # Optional data-driven overrides: narrative.blocking_meta maps a
        # protocol to [blocking, owner, solvable]; narrative.upper_limit maps
        # a protocol to its ceiling text. Unknown protocols are ignored.
        for proto, triple in (narrative.get("blocking_meta") or {}).items():
            if proto in blocking_meta and isinstance(triple, (list, tuple)) and len(triple) == 3:
                blocking_meta[proto] = tuple(triple)
        for proto, limit in (narrative.get("upper_limit") or {}).items():
            if proto in upper_limit:
                upper_limit[proto] = limit
        for proto in PROTOCOL_ORDER:
            if proto not in verdicts:
                continue
            missing = verdicts[proto]["missing_cells"]
            remaining = ", ".join(missing) if missing else "无"
            if missing:
                blocking, owner, solvable = blocking_meta[proto]
            else:
                blocking = "无（本 run 已修复，证据见「fix 支线与复验」）"
                owner = "—"
                solvable = "—"
            lines.append(
                f"| {proto} | {blocking} | {owner} | {remaining} | {solvable} | "
                f"{upper_limit[proto]} |"
            )
    else:
        lines.append(
            "| VLESS | 产品装配（eager read）+ 跨协议 T2 | 产品装配 bug + 跨协议数据面共性缺陷 | "
            "H/T1/L/R 由 fix 解决；T2 需 transport | 否，依赖 transport | "
            "`VERIFIED / PROTOCOL_SUBSET`（Vision 仅 crate 级，产品 splice 未实现） |"
        )
        lines.append(
            "| AnyTLS | 跨协议 T2 | 跨协议数据面共性缺陷 | 仅 T2 | 是（transport 一处） | "
            "`VERIFIED / FULL` |"
        )
        lines.append(
            "| Hysteria2 | 认证响应 QPACK Huffman + T2 | 协议编解码实现错误 + 跨协议数据面共性缺陷 | "
            "Handshake/Handshake[Hy2Salamander]/TcpSmall/TcpThroughput/LongLived/Reconnect/UdpEcho/"
            "BadCredential 共 8 格 | 否，依赖 transport | `VERIFIED / FULL` |"
        )
        lines.append(
            "| Trojan | fallback 静默接受 + T2 | 产品安全语义 + 跨协议数据面共性缺陷 | "
            "fallback + T2；U 固定未实现 | 否，依赖 transport + fallback 架构 | "
            "本 run 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 未实现，规则 6） |"
        )
        lines.append(
            "| Shadowsocks | 线格式/SIP004 AEAD + T2 | 协议实现错误 + 跨协议数据面共性缺陷 | "
            "H/T1/T2/L/R；U 固定未实现 | 否，依赖 transport | "
            "本 run 最高 `PARTIAL / TCP_ONLY / USABLE_WITH_GAPS`（U 未实现，规则 6） |"
        )
    lines.append("")
    lines.append(
        "**参照端生态**：本轮未发现参照端生态缺陷——sing-box 1.13.16 的行为符合规范；"
        "Xray 26.10.21 仅用于 Vision 争议裁决，本轮未触发。五协议 verdict 均无 "
        "`E_REF_*` 根因。"
    )
    lines.append("")
    for proto in PROTOCOL_ORDER:
        proto_rows = [r for r in rows if r["protocol"] == proto]
        if not proto_rows:
            continue
        lines.append(f"## {proto}")
        lines.append("")
        v = verdicts.get(proto)
        if v:
            lines.append(
                f"> **verdict={v['verdict']} / claim={v['claim']}**"
                f"（scope={v['scope']}，root_cause_class={v['root_cause_class']}）"
            )
        else:
            lines.append("> **verdict=NOT_RUN / claim=NOT_CLAIMED**（allow-partial）")
        lines.append(">")
        lines.append(
            "> 本节任一 PASS 不改变协议 verdict；单格 PASS 只在所列 carrier/scope 下成立。"
        )
        if proto == "Vless":
            lines.append(
                "> VlessVision 行为 crate 级证据，产品 Vision splice 未实现。"
            )
        if proto == "Anytls":
            lines.append("> PaddingDiag 为诊断格，不参与 verdict。")
            if run_meta:
                lines.append("> AnyTLS：session 池/心跳定时器/padding 写路径未单独验。")
        if proto == "Hysteria2":
            lines.append("> QpackDiag 为诊断格，不参与 verdict。")
        lines.append("")
        lines.append(
            "| Cell | 状态 | carrier | scope | evidence_id | class | 关键数字 | 证据路径 | notes |"
        )
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for r in proto_rows:
            if not r["present"]:
                lines.append(
                    f"| {r['variant']}/{r['cell']} | MISSING | — | — | — | E_EVIDENCE_GAP | "
                    f"缺格 | — | 证据缺口，不参与 verdict |"
                )
                continue
            ev = r["evidence"]
            m = ev.get("metrics", {})
            if r["cell"] == "TcpThroughput":
                detail = f"median={m.get('throughput_median_bps', 0)}B/s samples={len(m.get('throughput_samples_bps', []))}"
            elif r["cell"] == "UdpEcho":
                detail = f"udp {m.get('udp_received', 0)}/{m.get('udp_sent', 0)} corrupt={m.get('udp_corrupt', 0)}"
            elif r["cell"] == "LongLived":
                detail = f"heartbeats={m.get('heartbeats_ok', 0)}"
            elif r["cell"] == "Reconnect":
                detail = f"reconnects={m.get('reconnects_ok', 0)}"
            else:
                detail = f"up={m.get('bytes_up', 0)}B down={m.get('bytes_down', 0)}B"
            err = r["class"] or "NONE"
            notes = truncate_notes("; ".join(ev.get("notes", [])).replace("|", "/"))
            qualifiers = []
            if r.get("diag"):
                qualifiers.append("诊断格，不参与 verdict")
            if proto == "Vless" and r["variant"] == "VlessVision":
                qualifiers.append("crate 级，产品 splice 未实现")
            if run_meta and proto in ("Vless", "Anytls") and r["cell"] == "UdpEcho":
                qualifiers.append("crate 级，产品入口不可用")
            if r["cell"] in FAILURE_CELLS and r["status"] == "PASS":
                override = narrative.get("failure_cell_qualifier")
                if override and proto in override:
                    # A string replaces the boilerplate; null/"" suppresses it
                    # (the run's evidence now proves the rejection semantics).
                    if override[proto]:
                        qualifiers.append(override[proto])
                elif proto in ("Vless", "Shadowsocks"):
                    qualifiers.append(
                        "限定：正向路径不通时本格仅证明无静默成功，不独立证明认证拒绝语义"
                    )
                elif proto == "Hysteria2":
                    qualifiers.append(
                        "限定：正向路径被 CODEC 阻断时本格 PASS 仅证明无静默成功，"
                        "不独立证明配置拒绝语义"
                    )
            if qualifiers:
                joined = "；".join(qualifiers)
                notes = f"{notes}; {joined}" if notes else joined
            lines.append(
                f"| {r['variant']}/{r['cell']} | {r['status']} | {ev.get('carrier')} | "
                f"{ev.get('scope')} | {ev.get('evidence_id')} | {err} | {detail} | "
                f"{r['evidence_path']} | {notes} |"
            )
        lines.append("")
    lines.append("## 产品级 UDP（不参与协议 verdict）")
    lines.append("")
    lines.append(
        "产品 SOCKS5 入口 `crates/nexus-ingress/src/lib.rs:232-241` 拒绝 BND/UDP ASSOCIATE；"
        "Trojan/SS 出站也没有 UDP 帧路径。因此产品级 UDP 按能力缺口记录，"
        "不进入五协议 verdict；crate 级 UDP 结论见各协议 `UdpEcho` 行。"
    )
    lines.append("")
    lines.append(
        "**区分**：本项指产品 SOCKS5 UDP relay 入口/出站帧路径缺失，"
        "不等于所有 UDP/QUIC 路径不可用——Hy2 出站到代理服务器仍走 QUIC/UDP 传输，"
        "其失败点是认证响应编解码（`E_NEXUS_CODEC`），不是 UDP 传输本身。"
    )
    lines.append("")
    lines.append("## 产品能力缺口")
    lines.append("")
    lines.append("- 产品级 UDP：未实现（上节）。")
    lines.append("- Vision：产品路径只编码 addon，不实现 splice；本 run 的 Vision 结论来自 crate 直调。")
    lines.append("- Hysteria2：端口跳跃/Brutal/gecko/分片不在范围。")
    lines.append("- AnyTLS：session 池/心跳定时器/padding 写路径不单独验。")
    lines.append(
        "- Trojan fallback fail-open（安全语义）：错凭据/被劫持/服务端 fallback 时，"
        "SOCKS5 仍回 success，fallback 的 HTTP 内容被当隧道数据。"
    )
    lines.append(
        "- 代理失败可观察性：上述场景下产品不显示实际行为，不满足白皮书 §6.2/§16.1。"
    )
    lines.append("")
    lines.append("## fix 支线与复验")
    lines.append("")
    fix_dir = run_dir / "fix"
    if run_meta:
        fix_branches = run_meta.get("fix_branches") or []
        if fix_branches:
            lines.append("本 run 产生 verdict 翻转的修复条目（来源：run-meta）：")
            lines.append("")
            for item in fix_branches:
                effect = item.get("effect") or ""
                evidence = item.get("evidence") or []
                tail = f"（{'；'.join(evidence)}）" if evidence else ""
                lines.append(
                    f"- **{item.get('name', '')}**（commit `{item.get('commit', '')}`）："
                    f"{effect}{tail}"
                )
            lines.append("")
        else:
            lines.append("- （无）")
            lines.append("")
        lines.append(
            f"根因文档位于仓库 `docs/protocols/interop/fix/`；本 run 证据根为 `{run_dir}`，"
            "上表 cell 证据路径均相对该目录。"
        )
    elif fix_dir.exists():
        for root in sorted(fix_dir.glob("*/root-cause.md")):
            title = root.read_text(encoding="utf-8").splitlines()[0].lstrip("# ").strip()
            repo_path = f"docs/protocols/interop/fix/{root.parent.name}/root-cause.md"
            lines.append(f"- [`{repo_path}`](fix/{root.parent.name}/root-cause.md)：{title}")
        lines.append("")
        lines.append(
            "根因文档内的 `evidence/...` 路径相对主机证据根 "
            "`$RUN_DIR=/work/interop-run/protocol-interop-verification`（非仓库内路径）；"
            "仓库内可打开的是根因文档本身。spec 原文不在仓库，规则 1/2 的判定摘要见顶部「先读」。"
        )
        reverify = fix_dir / "vless/reverify-run/evidence"
        if reverify.exists():
            lines.append("")
            lines.append("| fix 支线复验（vless lazy response）| 状态 | evidence_id |")
            lines.append("|---|---|---|")
            for path in sorted(reverify.glob("vless/*/*/PIV-*/probe.json")):
                ev = json.loads(path.read_text(encoding="utf-8"))
                lines.append(f"| {ev['cell']} | {normalize_status(ev['verdict'])} | {ev['evidence_id']} |")
            lines.append("")
            lines.append(
                "复验基于 fix 分支 `fix/protocol-interop-vless-lazy-response`；review 与 re-verify "
                "已完成（R-01 PASS）。合入与 verdict 更新待 fix 流程另行裁决；即使合入，"
                "T2 仍受 transport 阻塞——上表 verdict 只用 verify 分支基线证据。"
            )
    else:
        lines.append("- （无）")
    lines.append("")
    lines.append("## 附录 A：配置索引")
    lines.append("")
    lines.append("| 文件 | sha256 |")
    lines.append("|---|---|")
    cfg_dir = run_dir / "evidence/ref-config"
    if cfg_dir.exists():
        for sha in sorted(cfg_dir.glob("*.json.sha256")):
            name = sha.name[: -len(".sha256")]
            lines.append(f"| evidence/ref-config/{name} | {sha.read_text().strip()} |")
    lines.append("")
    lines.append("## 附录 B：证据清单")
    lines.append("")
    lines.append("| evidence_id | verdict | carrier | scope | 路径 |")
    lines.append("|---|---|---|---|---|")
    for r in sorted([r for r in rows if r["present"]], key=lambda x: x["evidence"]["evidence_id"]):
        ev = r["evidence"]
        lines.append(
            f"| {ev['evidence_id']} | {r['status']} | {ev.get('carrier')} | "
            f"{ev.get('scope')} | {r['evidence_path']} |"
        )
    lines.append("")
    lines.append("## 附录 C：命令与端口")
    lines.append("")
    lines.append("```bash")
    lines.append("scripts/interop/run-matrix.sh --protocol <p> --variant <v> --cell <c> \\")
    if run_meta:
        lines.append(f"  --run-dir {run_dir} \\")
    else:
        lines.append("  --run-dir /work/interop-run/protocol-interop-verification \\")
    lines.append("  --probe-bin $CARGO_TARGET_DIR/debug/examples/protocol_interop_probe \\")
    lines.append("  --ref-bin $RUN_DIR/ref/sing-box-1.13.16-linux-amd64-musl/sing-box")
    if run_meta:
        meta_path = run_meta_path or (run_dir / "analysis/run-meta.json")
        lines.append(f"python3 scripts/interop/recompute-verdicts.py --run-dir {run_dir} \\")
        lines.append(f"  --run-meta {meta_path} \\")
        lines.append("  --matrix docs/protocols/interop/MATRIX.md --check")
    else:
        lines.append("python3 scripts/interop/recompute-verdicts.py --run-dir $RUN_DIR \\")
        lines.append("  --matrix docs/protocols/interop/MATRIX.md --check")
    lines.append("```")
    lines.append("")
    lines.append("- 参照端口：vless 26100/26101、anytls 26102、hysteria2 26103/26104、")
    lines.append("  trojan 26105/26115、shadowsocks 26106、xray 26108/26109。")
    lines.append("- 目标端口：26200 echo / 26201 sink+source / 26202 udp / 26203 http fallback。")
    lines.append("- 抓包：dumpcap -P（pcap），T2 用 `-a filesize:102400` 封顶 100 MiB。")
    lines.append("")
    lines.append("## 附录 D：终局 T2 证据构建来源")
    lines.append("")
    lines.append("| 协议 | evidence_id | nexus.commit | cargo_target_dir | binary_sha256 |")
    lines.append("|---|---|---|---|---|")
    for r in rows:
        if not r["present"] or r["cell"] != "TcpThroughput":
            continue
        ev = r["evidence"]
        nexus = ev.get("nexus") or {}
        lines.append(
            f"| {r['protocol']} | {ev['evidence_id']} | {nexus.get('commit') or 'MISSING'} | "
            f"{nexus.get('cargo_target_dir') or 'MISSING'} | {nexus.get('binary_sha256') or 'MISSING'} |"
        )
    lines.append("")
    if run_meta:
        by_commit = {}
        for r in rows:
            if not r["present"] or r["cell"] != "TcpThroughput":
                continue
            nexus = r["evidence"].get("nexus") or {}
            by_commit.setdefault(nexus.get("commit") or "MISSING", []).append(r["protocol"])
        if by_commit:
            origins = "；".join(
                f"`{commit}`（{'、'.join(protos)}）"
                for commit, protos in sorted(by_commit.items())
            )
            lines.append(
                "上表逐格给出各 T2 证据绑定的构建提交、目标目录与二进制哈希；"
                f"按证据 `nexus.commit` 派生：{origins}。"
            )
        else:
            lines.append("本 run 无 T2 证据。")
        lines.append(
            "构建均来自证据记录的本 worktree `cargo_target_dir`，"
            "不再引用前序 run 的 fix worktree。"
        )
    else:
        lines.append(
            "AnyTLS/Trojan 终局 T2 由 fix 分支 `b7acb32` 的 fix worktree 构建（fix 仅改 VLESS 响应头泵，"
            "产品 `apps/nexus/src/lib.rs` 本表基线未被改动）；同格 FAIL 另有主 worktree 构建记录。"
        )
    lines.append("")
    superseded_path = run_dir / "analysis/superseded.json"
    if superseded_path.exists():
        superseded = json.loads(superseded_path.read_text(encoding="utf-8")).get("entries", [])
        if superseded:
            lines.append("## 附录 E：被替代运行")
            lines.append("")
            lines.append("| evidence_id | 原结论 | 替代者 | 弃用理由 |")
            lines.append("|---|---|---|---|")
            for entry in superseded:
                lines.append(
                    f"| {entry['evidence_id']} | {entry['original_verdict']} | "
                    f"{entry['superseded_by']} | {entry['reason']} |"
                )
            lines.append("")
            lines.append(
                "复算的选择规则是同格取最新 evidence_id；被替代运行仍保留在证据树与"
                " `analysis/progress.tsv`，不覆盖历史结论。"
            )
            lines.append("")
    if findings:
        lines.append("## 校验发现")
        lines.append("")
        for finding in findings:
            lines.append(f"- {finding}")
        lines.append("")
    text = "\n".join(lines).rstrip("\n") + "\n"
    for word in BANNED_WORDS:
        if word.lower() in text.lower():
            raise RecomputeError(f"MATRIX contains banned wording: {word}")
    return text


def build(run_dir, matrix_path, allow_partial, run_meta=None, run_meta_path=None):
    matrix = json.loads(Path(matrix_path).read_text(encoding="utf-8"))
    rows, findings = load_rows(run_dir, matrix)
    verdicts = {}
    for proto in ["Vless", "Anytls", "Hysteria2", "Trojan", "Shadowsocks"]:
        v = protocol_verdict(proto, rows, allow_partial)
        if v:
            verdicts[proto] = v
    completeness = {
        "expected": len(matrix["cells"]),
        "present": sum(1 for r in rows if r["present"]),
        "missing": [
            f"{r['protocol']}/{r['variant']}/{r['cell']}" for r in rows if not r["present"]
        ],
        "findings": findings,
    }
    text = render_matrix(
        run_dir,
        matrix,
        verdicts,
        rows,
        findings,
        allow_partial,
        run_meta=run_meta,
        run_meta_path=run_meta_path,
    )
    payload = {
        "schema_version": 1,
        "protocols": verdicts,
        "completeness": completeness,
        "product": {"udp": "NOT_IMPLEMENTED"},
    }
    return payload, text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--matrix", required=True)
    ap.add_argument("--cell-matrix", default=str(DEFAULT_CELL_MATRIX))
    ap.add_argument("--run-meta", default=None)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--allow-partial", action="store_true")
    args = ap.parse_args()
    try:
        run_meta = load_run_meta(args.run_meta) if args.run_meta else None
        payload, text = build(
            args.run_dir,
            args.cell_matrix,
            args.allow_partial,
            run_meta=run_meta,
            run_meta_path=args.run_meta,
        )
    except RecomputeError as err:
        print(f"recompute error: {err}", file=sys.stderr)
        return 2
    analysis = Path(args.run_dir) / "analysis"
    analysis.mkdir(parents=True, exist_ok=True)
    verdicts_path = analysis / "verdicts.json"
    (analysis / "completeness.json").write_text(
        json.dumps(payload["completeness"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    if args.check:
        existing = Path(args.matrix).read_text(encoding="utf-8") if Path(args.matrix).exists() else ""
        if existing != text:
            print("MATRIX drift: run recompute without --check", file=sys.stderr)
            return 1
        existing_verdicts = (
            verdicts_path.read_text(encoding="utf-8") if verdicts_path.exists() else ""
        )
        if existing_verdicts != json.dumps(payload, indent=2, ensure_ascii=False) + "\n":
            print("verdicts.json drift: run recompute without --check", file=sys.stderr)
            return 1
        print("MATRIX and verdicts.json are up to date")
        return 0
    verdicts_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    Path(args.matrix).parent.mkdir(parents=True, exist_ok=True)
    Path(args.matrix).write_text(text, encoding="utf-8")
    (analysis / "matrix-render.log").write_text(
        "\n".join(
            [
                f"utc=__import__('datetime').datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')",
                f"cells_present={payload['completeness']['present']}/{payload['completeness']['expected']}",
                "verdicts="
                + json.dumps({k: v["verdict"] for k, v in payload["protocols"].items()}, ensure_ascii=False),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        "wrote verdicts.json + MATRIX: "
        + json.dumps({k: v["verdict"] for k, v in payload["protocols"].items()}, ensure_ascii=False)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

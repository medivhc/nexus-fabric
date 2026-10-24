#!/usr/bin/env python3
"""机械复算 verdict + 渲染 MATRIX（AC-06/10/18/19；E1 规则 1–9 按序）。

输入：
  --run-dir <dir>      证据根（evidence/analysis/...）
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


class RecomputeError(RuntimeError):
    pass


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

        def kebab(value):
            out = []
            for ch in value:
                if ch.isupper():
                    out += ["-", ch.lower()]
                else:
                    out.append(ch)
            return "".join(out).lstrip("-")

        cell_dir = evidence_root / kebab(proto) / kebab(variant) / kebab(cell)
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
        if ev.get("reference", {}).get("version") not in (None, "1.13.16", "26.10.21"):
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

    missing_cells = [
        f"{r['cell']}({r['status']},{r['class'] or 'NONE'})" for r in non_pass(required)
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

    # rule 1: failure cell FAIL（有效 echo/静默成功/挂死）
    for r in non_diag:
        if r["present"] and r["cell"] in FAILURE_CELLS and r["status"] == "FAIL":
            return result(
                "BROKEN",
                proto_scope(proto, "BROKEN"),
                root_cause=r["class"] or "E_NEXUS_FRAMING",
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


def render_matrix(run_dir, matrix, verdicts, rows, findings, allow_partial):
    run_dir = Path(run_dir)
    env = run_dir / "evidence/env"
    ref = run_dir / "evidence/ref"

    def read_first(path):
        try:
            return path.read_text(encoding="utf-8").splitlines()[0].strip()
        except OSError:
            return "MISSING"

    def cell_matrix_name(proto, variant, cell):
        def kebab(value):
            out = []
            for ch in value:
                if ch.isupper():
                    out += ["-", ch.lower()]
                else:
                    out.append(ch)
            return "".join(out).lstrip("-")

        return f"{kebab(proto)}-{kebab(variant)}-{kebab(cell)}"

    times = sorted(
        r["evidence"]["started_at_utc"] for r in rows if r["present"]
    )
    window = f"{times[0]} .. {times[-1]}" if times else "n/a"
    archive = sorted((run_dir / "archive").glob("*.tar.zst"))
    lines = []
    lines.append("# 出站协议互操作证据总表（MATRIX）")
    lines.append("")
    lines.append("> 本文件由 `scripts/interop/recompute-verdicts.py` 从证据机械生成；人工零编辑。")
    lines.append("")
    lines.append("| 项 | 值 |")
    lines.append("|---|---|")
    lines.append(f"| run | protocol-interop-verification |")
    lines.append(f"| baseline | 0539169e8195944fcd183e7831e5d5ac746f3f40 |")
    lines.append("| spec | frozen v1.1（sha256 23c7e4e797ee9edbf0eb645bfc20a7c97cfacb30e1a67bd8fee77ccbc527de4f） |")
    lines.append(f"| sing-box | 1.13.16（{read_first(ref / 'sing-box-sha256.txt')}） |")
    lines.append(f"| Xray | 26.10.21（{read_first(ref / 'xray-sha256.txt')}） |")
    lines.append(f"| test window | {window} |")
    lines.append(
        "| archive | "
        + (", ".join(str(p) for p in archive) if archive else "（S30 归档后追加）")
        + " |"
    )
    lines.append("")
    lines.append("## 协议 verdict（按 spec E1 复算）")
    lines.append("")
    lines.append("| 协议 | verdict | scope | claim | root_cause_class | missing_cells | 命中规则 |")
    lines.append("|---|---|---|---|---|---|---|")
    order = ["Vless", "Anytls", "Hysteria2", "Trojan", "Shadowsocks"]
    for proto in order:
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
    for proto in order:
        proto_rows = [r for r in rows if r["protocol"] == proto]
        if not proto_rows:
            continue
        lines.append(f"## {proto}")
        lines.append("")
        lines.append("| Cell | 状态 | carrier | scope | evidence_id | 关键数字/错误 | 证据路径 | notes |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for r in proto_rows:
            if not r["present"]:
                lines.append(
                    f"| {r['variant']}/{r['cell']} | MISSING | — | — | — | 缺格 | — | E_EVIDENCE_GAP |"
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
            err = r["class"] or ""
            notes = "; ".join(ev.get("notes", []))[:220].replace("|", "/")
            lines.append(
                f"| {r['variant']}/{r['cell']} | {r['status']} | {ev.get('carrier')} | "
                f"{ev.get('scope')} | {ev.get('evidence_id')} | {detail} {err} | "
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
    lines.append("## 产品能力缺口")
    lines.append("")
    lines.append("- 产品级 UDP：未实现（上节）。")
    lines.append("- Vision：产品路径只编码 addon，不实现 splice；本 run 的 Vision 结论来自 crate 直调。")
    lines.append("- Hysteria2：端口跳跃/Brutal/gecko/分片不在范围。")
    lines.append("- AnyTLS：session 池/心跳定时器/padding 写路径不单独验。")
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
    lines.append("  --run-dir /work/interop-run/protocol-interop-verification \\")
    lines.append("  --probe-bin $CARGO_TARGET_DIR/debug/examples/protocol_interop_probe \\")
    lines.append("  --ref-bin $RUN_DIR/ref/sing-box-1.13.16-linux-amd64-musl/sing-box")
    lines.append("python3 scripts/interop/recompute-verdicts.py --run-dir $RUN_DIR \\")
    lines.append("  --matrix docs/protocols/interop/MATRIX.md --check")
    lines.append("```")
    lines.append("")
    lines.append("- 参照端口：vless 26100/26101、anytls 26102、hysteria2 26103/26104、")
    lines.append("  trojan 26105/26115、shadowsocks 26106、xray 26108/26109。")
    lines.append("- 目标端口：26200 echo / 26201 sink+source / 26202 udp / 26203 http fallback。")
    lines.append("- 抓包：dumpcap -P（pcap），T2 用 `-a filesize:102400` 封顶 100 MiB。")
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


def build(run_dir, matrix_path, allow_partial):
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
    text = render_matrix(run_dir, matrix, verdicts, rows, findings, allow_partial)
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
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--allow-partial", action="store_true")
    args = ap.parse_args()
    try:
        payload, text = build(args.run_dir, args.cell_matrix, args.allow_partial)
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

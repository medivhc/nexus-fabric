#!/usr/bin/env python3
"""证据收尾（B-8）：只追加 artifacts 与 notes，不改 verdict/error/metrics。

ProbeJson 自引用：probe.json 无法在自己的 artifacts 里记录自身的最终哈希（追加
Pcap/ClientLog 条目与 notes 后哈希必然变化）。因此 ProbeJson 不进入 artifacts；
probe.json 的最终 sha256/bytes 写入 finalize.log（`probe_json_final_*`），避免
自引用条目与最终文件长期不符。

唯一例外（计划 §8.1 规则 4 / AC-23）：失败格（bad-credential/bad-config）缺 pcap 或
pcap 无包 → 降为 BLOCKED + E_EVIDENCE_GAP。该降级显式写入 finalize.log。
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

FAILURE_CELLS = {"bad-credential", "bad-config"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe-json", required=True)
    ap.add_argument("--cell-dir", required=True)
    ap.add_argument("--evidence-root", required=True)
    ap.add_argument("--pcap", default="")
    ap.add_argument("--pcap-stats", default="")
    ap.add_argument("--cell", required=True)
    ap.add_argument("--cell-log", default="")
    ap.add_argument("--ref-log", default="")
    ap.add_argument("--synthetic", action="store_true")
    a = ap.parse_args()

    probe_path = Path(a.probe_json)
    evidence = json.loads(probe_path.read_text(encoding="utf-8"))
    root = Path(a.evidence_root).resolve()
    log = []

    def add(kind, path):
        p = Path(path)
        if not p.exists() or p.stat().st_size == 0:
            return
        rel = str(p.resolve().relative_to(root))
        evidence["artifacts"] = [
            x for x in evidence.get("artifacts", []) if not (x["kind"] == kind and x["path"] == rel)
        ]
        evidence["artifacts"].append(
            {"kind": kind, "path": rel, "sha256": sha256(p), "bytes": p.stat().st_size}
        )
        log.append(f"artifact kind={kind} path={rel} bytes={p.stat().st_size}")

    evidence["artifacts"] = [
        x for x in evidence.get("artifacts", []) if x.get("kind") != "ProbeJson"
    ]
    if a.pcap:
        add("Pcap", a.pcap)
    if a.cell_log:
        add("ClientLog", a.cell_log)
    if a.ref_log:
        add("RefLog", a.ref_log)

    if a.pcap_stats and Path(a.pcap_stats).exists():
        evidence.setdefault("notes", []).append(
            "pcap_stats=" + Path(a.pcap_stats).read_text(encoding="utf-8").replace("\n", ";")
        )

    pcap_packets = 0
    if a.pcap_stats and Path(a.pcap_stats).exists():
        for line in Path(a.pcap_stats).read_text(encoding="utf-8").splitlines():
            if line.startswith("packets="):
                try:
                    pcap_packets = int(line.split("=", 1)[1] or 0)
                except ValueError:
                    pcap_packets = 0
    pcap_ok = any(x["kind"] == "Pcap" for x in evidence.get("artifacts", []))
    if (not a.synthetic) and a.cell in FAILURE_CELLS and (not pcap_ok or pcap_packets == 0):
        old = evidence.get("verdict")
        evidence["verdict"] = "Blocked"
        evidence["error"] = {
            "class": "E_EVIDENCE_GAP",
            "message": f"failure cell lacks usable pcap (packets={pcap_packets})",
            "first_failure_artifact": "pcap.pcap",
        }
        evidence.setdefault("notes", []).append(
            f"verdict_downgraded {old}->Blocked per plan §8.1 rule 4 (missing pcap)"
        )
        log.append(f"DOWNGRADE {old}->Blocked reason=pcap_missing packets={pcap_packets}")

    probe_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    log.append(f"probe_json_final_sha256={sha256(probe_path)}")
    log.append(f"probe_json_final_bytes={probe_path.stat().st_size}")
    (Path(a.cell_dir) / "finalize.log").write_text(
        f"utc={__import__('datetime').datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        + "\n".join(log)
        + "\n",
        encoding="utf-8",
    )
    print(f"finalized {evidence['evidence_id']} verdict={evidence['verdict']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

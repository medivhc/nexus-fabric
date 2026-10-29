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
import subprocess
import sys
from pathlib import Path

FAILURE_CELLS = {"bad-credential", "bad-config"}

REPO_ROOT = Path(__file__).resolve().parents[3]


def ref_variant_for(protocol, variant, cell=""):
    """从 cell-matrix 找到 probe 格对应的参照端变体（找不到返回空串）。

    同一 probe 变体下不同 cell 可能指向不同的参照端配置（端口也不同），
    因此按 (protocol, variant, cell) 精确匹配；cell 用「忽略大小写与连字符」比较
    （finalize 拿到的是 kebab label，矩阵里是 CamelCase）。
    """
    try:
        matrix = json.loads(
            (REPO_ROOT / "scripts/interop/cell-matrix.json").read_text(encoding="utf-8")
        )
    except OSError:
        return ""

    def norm(value):
        return (value or "").replace("-", "").lower()

    fallback = ""
    for entry in matrix.get("cells", []):
        if entry.get("protocol") != protocol or entry.get("variant") != variant:
            continue
        if not fallback:
            fallback = entry.get("ref_variant") or ""
        if norm(entry.get("cell")) == norm(cell):
            return entry.get("ref_variant") or ""
    return fallback


def access_proof(pcap, node_port, fallback_port):
    """用 tshark 证明参照端侧访问（AC-12.2.3）。"""
    proof = {
        "checked": False,
        "node_access": False,
        "fallback_access": False,
        "node_port": node_port,
        "fallback_port": fallback_port,
        "error": "",
    }
    if not pcap or not Path(pcap).exists() or Path(pcap).stat().st_size == 0:
        proof["error"] = "pcap missing"
        return proof
    try:
        out = subprocess.run(
            [
                "tshark",
                "-r",
                str(pcap),
                "-Y",
                "tcp or udp",
                "-T",
                "fields",
                "-e",
                "tcp.srcport",
                "-e",
                "tcp.dstport",
                "-e",
                "udp.srcport",
                "-e",
                "udp.dstport",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        proof["error"] = f"tshark failed: {exc}"
        return proof
    proof["checked"] = True
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        ports = set()
        for raw in parts:
            raw = raw.strip()
            if not raw:
                continue
            try:
                ports.add(int(raw))
            except ValueError:
                continue
        if fallback_port and fallback_port in ports:
            proof["fallback_access"] = True
        if node_port and node_port in ports:
            proof["node_access"] = True
    return proof


def failure_cell_access_verdict(is_fallback_variant, proof):
    """失败格的「参照端访问可证」判定（纯函数，供负向测试）。

    返回 `(override_verdict, reason)`；`(None, "")` 表示证据充足、不降级。
    """
    if not proof.get("checked"):
        return ("Blocked", f"pcap unusable: {proof.get('error') or 'no pcap'}")
    if is_fallback_variant and not proof.get("fallback_access"):
        return ("Blocked", "no fallback-target flow in pcap")
    if not is_fallback_variant and not proof.get("node_access"):
        return ("Blocked", "no reference-node flow in pcap")
    return (None, "")


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
    # AC-12.2.3：失败格必须能证明「参照端侧确实被访问」。
    access = None
    if (not a.synthetic) and a.cell in FAILURE_CELLS:
        protocol = evidence.get("protocol", "")
        variant = evidence.get("variant", "")
        ref_variant = ref_variant_for(protocol, variant, a.cell)
        cfg_path = root / "ref-config" / f"{ref_variant}.json" if ref_variant else None
        node_port = None
        fallback_port = None
        if cfg_path is not None and cfg_path.exists():
            try:
                cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
                inbound = (cfg.get("inbounds") or [{}])[0]
                node_port = inbound.get("listen_port") or inbound.get("port")
                fallback_port = (inbound.get("fallback") or {}).get("server_port")
            except (OSError, ValueError, IndexError):
                node_port = fallback_port = None
        access = access_proof(a.pcap if pcap_ok else "", node_port, fallback_port)
        evidence.setdefault("notes", []).append(
            f"pcap_node_access={str(access['node_access']).lower()}"
        )
        evidence.setdefault("notes", []).append(
            f"pcap_fallback_access={str(access['fallback_access']).lower()}"
        )
        log.append(
            "access_proof node_port=%s fallback_port=%s node=%s fallback=%s error=%s"
            % (
                node_port,
                fallback_port,
                access["node_access"],
                access["fallback_access"],
                access["error"] or "-",
            )
        )
        override, reason = failure_cell_access_verdict(
            bool(fallback_port) and variant == "TrojanFallback", access
        )
        if override:
            old = evidence.get("verdict")
            evidence["verdict"] = override
            evidence["error"] = {
                "class": "E_EVIDENCE_GAP",
                "message": reason,
                "first_failure_artifact": "pcap.pcap",
            }
            evidence.setdefault("notes", []).append(
                f"verdict_downgraded {old}->{override} per AC-12.2.3 ({reason})"
            )
            log.append(f"DOWNGRADE_ACCESS {old}->{override} reason={reason}")

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

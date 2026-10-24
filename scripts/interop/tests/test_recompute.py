import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MOD_PATH = ROOT / "scripts/interop/recompute-verdicts.py"
MATRIX_PATH = ROOT / "scripts/interop/cell-matrix.json"
spec = importlib.util.spec_from_file_location("recompute", MOD_PATH)
recompute = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recompute)


def kebab(value):
    out = []
    for ch in value:
        if ch.isupper():
            out += ["-", ch.lower()]
        else:
            out.append(ch)
    return "".join(out).lstrip("-")


def entry_key(entry):
    return (entry["variant"], entry["cell"])


def write_cell(run_dir, entry, status, cls, payload_hashes=True, pcap=True,
               carrier=None, scope=None, notes=None, metrics=None, synthetic=False):
    proto = entry["protocol"]
    variant = entry["variant"]
    cell = entry["cell"]
    eid = f"PIV-{kebab(proto)}-{kebab(variant)}-{kebab(cell)}-20261025T000000Z-001"
    cell_dir = Path(run_dir) / "evidence" / kebab(proto) / kebab(variant) / kebab(cell) / eid
    cell_dir.mkdir(parents=True, exist_ok=True)
    ev = {
        "schema_version": 1,
        "evidence_id": eid,
        "run_id": "protocol-interop-verification",
        "protocol": proto,
        "variant": variant,
        "cell": cell,
        "carrier": carrier or entry["carrier"],
        "scope": scope or entry["scope"],
        "verdict": status.title().replace("_", ""),
        "started_at_utc": "2026-10-25T00:00:00Z",
        "duration_ms": 1,
        "nexus": {"commit": "x", "binary_sha256": "y", "cargo_target_dir": "z"},
        "reference": {
            "implementation": "sing-box",
            "version": "1.13.16",
            "binary_sha256": "b",
            "config_sha256": "c",
        },
        "effective_config_sha256": "d",
        "metrics": metrics if metrics is not None else {},
        "error": None,
        "notes": notes or [],
        "artifacts": [],
    }
    if cls:
        ev["error"] = {"class": cls, "message": "test", "first_failure_artifact": None}
    if cell == "TcpThroughput" and status == "PASS" and metrics is None:
        ev["metrics"] = {"throughput_samples_bps": [1, 2, 3], "throughput_median_bps": 2}
    if cell in ("Handshake", "TcpSmall") and status == "PASS" and payload_hashes:
        ev["metrics"].update({"sha256_up": "aa", "sha256_down": "bb"})
    if pcap:
        ev["artifacts"].append({"kind": "Pcap", "path": "pcap.pcap", "sha256": "x", "bytes": 1})
    (cell_dir / "probe.json").write_text(json.dumps(ev, indent=2), encoding="utf-8")
    return eid


def make_run(tmp, protocol, overrides, skip=(), only=None):
    """为某协议写入全部矩阵格；overrides: {(variant,cell): dict}。返回 {(variant,cell): eid}."""
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    written = {}
    for entry in matrix["cells"]:
        if entry["protocol"] != protocol:
            continue
        key = entry_key(entry)
        if key in skip:
            continue
        if only is not None and key not in only:
            continue
        spec_over = dict(overrides.get(key, {}))
        status = spec_over.pop("status", "PASS")
        cls = spec_over.pop("cls", None)
        written[key] = write_cell(tmp, entry, status, cls, **spec_over)
    return written


class RecomputeTests(unittest.TestCase):
    def build(self, tmp):
        return recompute.build(str(tmp), str(MATRIX_PATH), allow_partial=False)

    def test_trojan_all_pass_except_udp_is_partial_tcp_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            overrides = {
                ("Default", "UdpEcho"): {
                    "status": "NOT_IMPLEMENTED",
                    "cls": "E_NEXUS_NOT_IMPLEMENTED",
                }
            }
            make_run(Path(tmp), "Trojan", overrides)
            payload, _ = self.build(Path(tmp))
            v = payload["protocols"]["Trojan"]
            self.assertEqual(v["verdict"], "PARTIAL")
            self.assertEqual(v["scope"], "TCP_ONLY")
            self.assertEqual(v["claim"], "USABLE_WITH_GAPS")
            self.assertIn("UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED)", v["missing_cells"])

    def test_vless_vision_ref_limitation_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            written = make_run(
                tmp,
                "Vless",
                {("VlessVision", "Handshake"): {"status": "FAIL", "cls": "E_REF_LIMITATION"}},
            )
            eid = written[("VlessVision", "Handshake")]
            cls_dir = tmp / "analysis/classification"
            cls_dir.mkdir(parents=True)
            (cls_dir / f"{eid}.json").write_text(
                json.dumps(
                    {
                        "evidence_id": eid,
                        "class": "E_REF_LIMITATION",
                        "ref_source": "sing-box",
                        "ref_version": "1.13.16",
                    }
                ),
                encoding="utf-8",
            )
            payload, _ = self.build(tmp)
            v = payload["protocols"]["Vless"]
            self.assertEqual(v["verdict"], "PARTIAL")
            self.assertEqual(v["scope"], "PROTOCOL_SUBSET")

    def test_vless_vision_nexus_class_is_broken(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_run(
                Path(tmp),
                "Vless",
                {("VlessVision", "Handshake"): {"status": "FAIL", "cls": "E_NEXUS_CODEC"}},
            )
            payload, _ = self.build(Path(tmp))
            self.assertEqual(payload["protocols"]["Vless"]["verdict"], "BROKEN")

    def test_failure_cell_fail_is_broken(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_run(
                Path(tmp),
                "Vless",
                {("Default", "BadCredential"): {"status": "FAIL", "cls": "E_NEXUS_FRAMING"}},
            )
            payload, _ = self.build(Path(tmp))
            self.assertEqual(payload["protocols"]["Vless"]["verdict"], "BROKEN")

    def test_illegal_carrier_scope_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_run(
                Path(tmp),
                "Vless",
                {("Default", "Handshake"): {"carrier": "ProductSocks5", "scope": "ProtocolWire"}},
            )
            with self.assertRaises(recompute.RecomputeError):
                self.build(Path(tmp))

    def test_failure_cell_without_pcap_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_run(
                Path(tmp),
                "Vless",
                {("Default", "BadCredential"): {"pcap": False}},
            )
            payload, _ = self.build(Path(tmp))
            v = payload["protocols"]["Vless"]
            self.assertEqual(v["verdict"], "PARTIAL")
            self.assertIn("BadCredential(BLOCKED,E_EVIDENCE_GAP)", v["missing_cells"])

    def test_missing_cell_in_full_mode_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_run(Path(tmp), "Vless", {}, skip={("Default", "Reconnect")})
            with self.assertRaises(recompute.RecomputeError):
                self.build(Path(tmp))

    def test_allow_partial_renders_tested_protocol_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_run(Path(tmp), "Trojan", {("Default", "UdpEcho"): {"status": "NOT_IMPLEMENTED", "cls": "E_NEXUS_NOT_IMPLEMENTED"}})
            payload, text = recompute.build(str(tmp), str(MATRIX_PATH), allow_partial=True)
            self.assertIn("Trojan", payload["protocols"])
            self.assertNotIn("Vless", payload["protocols"])
            self.assertIn("NOT_RUN", text)

    def test_banned_wording_fails_render(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_run(
                Path(tmp),
                "Vless",
                {("Default", "Handshake"): {"notes": ["this probably works"]}},
            )
            with self.assertRaises(recompute.RecomputeError):
                self.build(Path(tmp))


if __name__ == "__main__":
    unittest.main()

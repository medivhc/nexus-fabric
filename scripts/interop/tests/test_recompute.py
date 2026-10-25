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


import sys as _sys
_sys.path.insert(0, str(ROOT / "scripts/interop/lib"))
import labels as _labels


def kebab(value):
    for kind, table in (("protocol", _labels.PROTOCOL), ("variant", _labels.VARIANT), ("cell", _labels.CELL)):
        if value in table:
            return table[value]
    raise KeyError(value)


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


def write_run_meta(tmp, **overrides):
    meta = {
        "run_id": "test-run",
        "baseline": "abc123",
        "spec_version": "v9.9",
        "spec_sha256": "deadbeef",
        "completed_items": [
            {
                "id": "P1",
                "title": "transport batch write",
                "result": "AnyTLS flipped",
                "evidence": ["commit `aaa`"],
            }
        ],
        "pending_items": [
            {"id": "P0", "title": "safety", "note": "docs done; config pending"}
        ],
        "fix_branches": [
            {
                "name": "transport batch write",
                "commit": "aaa",
                "effect": "flipped AnyTLS",
                "evidence": ["prediction-check step 2"],
            }
        ],
    }
    meta.update(overrides)
    path = Path(tmp) / "analysis/run-meta.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    return path, meta


def blocking_row(text, proto):
    section = text.split("## 阻塞层、归属与修复后上限", 1)[1].split("**参照端生态**", 1)[0]
    for line in section.splitlines():
        if line.startswith(f"| {proto} |"):
            return line
    raise AssertionError(f"no blocking row for {proto}")



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

    def test_rule1_covers_all_three_failure_phenomena(self):
        # S-01：spec E1 规则 1 的三种现象各固定一个算例，防止新增 error class
        # 或 probe 负向格分支变化时静默漏检。
        phenomena = {
            "valid echo silently accepted": {
                "status": "FAIL",
                "cls": "E_NEXUS_FRAMING",
                "notes": ["negative case silently accepted: valid echo returned"],
            },
            "non-echo data surfaced": {
                "status": "FAIL",
                "cls": "E_NEXUS_FRAMING",
                "notes": [
                    "negative case returned non-echo bytes; silently surfaced as tunnel payload"
                ],
            },
            "hang": {
                "status": "FAIL",
                "cls": "E_TIMEOUT_HANG",
                "notes": ["negative case hung without echo"],
            },
        }
        for name, override in phenomena.items():
            with self.subTest(phenomenon=name), tempfile.TemporaryDirectory() as tmp:
                make_run(
                    Path(tmp),
                    "Vless",
                    {("Default", "BadCredential"): override},
                )
                payload, _ = self.build(Path(tmp))
                verdict = payload["protocols"]["Vless"]
                self.assertEqual(verdict["verdict"], "BROKEN")
                self.assertEqual(verdict["rule"], "1")
                self.assertEqual(verdict["missing_cells"][0], f"BadCredential(FAIL,{override['cls']})")

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

    def test_notes_injection_replaces_hardcoded_security_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            make_run(tmp, "Vless", {})
            notes = tmp / "notes.md"
            notes.write_text("# Trojan 注记\n\n- 承诺边界：success 前零字节。\n", encoding="utf-8")
            payload, text = recompute.build(
                str(tmp), str(MATRIX_PATH), allow_partial=True, notes=notes.read_text(encoding="utf-8"),
                notes_path=str(notes),
            )
            sha = __import__("hashlib").sha256(notes.read_bytes()).hexdigest()
            self.assertIn("## Trojan 注记（机器注入自", text)
            self.assertIn(f"notes_sha256={sha}", text)
            self.assertIn("承诺边界：success 前零字节。", text)
            # 硬编码安全警示段（含过期规模句）不得再出现在注记注入产物里（R-7）。
            self.assertNotIn(">400 行 / >2 人日", text)
            self.assertNotIn("## ⚠ 安全警示：Trojan fallback fail-open", text)

    def test_without_notes_keeps_legacy_security_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            make_run(tmp, "Vless", {})
            _, text_a = recompute.build(str(tmp), str(MATRIX_PATH), allow_partial=True)
            _, text_b = recompute.build(str(tmp), str(MATRIX_PATH), allow_partial=True)
            self.assertEqual(text_a, text_b, "无 --notes 时输出必须稳定")
            self.assertIn("## ⚠ 安全警示：Trojan fallback fail-open", text_a)

    def test_notes_drift_is_detected_by_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            make_run(tmp, "Vless", {})
            notes = tmp / "notes.md"
            notes.write_text("- v1\n", encoding="utf-8")
            matrix = tmp / "MATRIX.md"
            recompute.build(
                str(tmp), str(MATRIX_PATH), allow_partial=True, notes=notes.read_text(encoding="utf-8"),
                notes_path=str(notes),
            )
            _, text_v1 = recompute.build(
                str(tmp), str(MATRIX_PATH), allow_partial=True, notes=notes.read_text(encoding="utf-8"),
                notes_path=str(notes),
            )
            matrix.write_text(text_v1, encoding="utf-8")
            notes.write_text("- v2\n", encoding="utf-8")
            _, text_v2 = recompute.build(
                str(tmp), str(MATRIX_PATH), allow_partial=True, notes=notes.read_text(encoding="utf-8"),
                notes_path=str(notes),
            )
            self.assertNotEqual(text_v1, text_v2, "注记变化必须反映在生成产物上（--check 由此判 drift）")

    def test_banned_wording_fails_render(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_run(
                Path(tmp),
                "Vless",
                {("Default", "Handshake"): {"notes": ["this probably works"]}},
            )
            with self.assertRaises(recompute.RecomputeError):
                self.build(Path(tmp))

    def test_run_meta_header_and_priority_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            meta_path, meta = write_run_meta(tmp)
            make_run(tmp, "Vless", {})
            payload, text = recompute.build(
                str(tmp), str(MATRIX_PATH), allow_partial=True,
                run_meta=meta, run_meta_path=str(meta_path),
            )
            self.assertIn("run `test-run`", text)
            self.assertIn("baseline `abc123`", text)
            self.assertIn("spec frozen v9.9", text)
            self.assertIn("deadbeef", text)
            self.assertNotIn("protocol-interop-verification", text)
            self.assertIn("（P1，DONE）", text)
            self.assertIn("commit `aaa`", text)
            self.assertIn("（P0，待办）", text)
            self.assertIn("config pending", text)

    def test_blocking_table_derives_missing_cells_from_verdicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            meta_path, meta = write_run_meta(tmp)
            make_run(tmp, "Vless", {})
            _, text = recompute.build(
                str(tmp), str(MATRIX_PATH), allow_partial=True,
                run_meta=meta, run_meta_path=str(meta_path),
            )
            row = blocking_row(text, "Vless")
            self.assertIn("| 无（本 run 已修复", row)
            self.assertIn("| 无 |", row)

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            meta_path, meta = write_run_meta(tmp)
            make_run(
                tmp,
                "Trojan",
                {("Default", "UdpEcho"): {"status": "NOT_IMPLEMENTED", "cls": "E_NEXUS_NOT_IMPLEMENTED"}},
            )
            _, text = recompute.build(
                str(tmp), str(MATRIX_PATH), allow_partial=True,
                run_meta=meta, run_meta_path=str(meta_path),
            )
            row = blocking_row(text, "Trojan")
            self.assertIn("UdpEcho(NOT_IMPLEMENTED,E_NEXUS_NOT_IMPLEMENTED)", row)

    def test_p3_qualifiers_are_rendered_near_claims_and_cells(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            meta_path, meta = write_run_meta(tmp)
            make_run(tmp, "Vless", {})
            _, text = recompute.build(
                str(tmp), str(MATRIX_PATH), allow_partial=True,
                run_meta=meta, run_meta_path=str(meta_path),
            )
            self.assertIn("**结论 1 限定**", text)
            self.assertIn("`USABLE` 指 TCP 产品路径", text)
            self.assertIn("**测试广度**", text)
            self.assertIn("REALITY、ws/grpc", text)
            udp_line = next(
                line for line in text.splitlines()
                if line.startswith("| Default/UdpEcho |") and "MISSING" not in line
            )
            self.assertIn("crate 级，产品入口不可用", udp_line)

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            meta_path, meta = write_run_meta(tmp)
            make_run(tmp, "Anytls", {})
            _, text = recompute.build(
                str(tmp), str(MATRIX_PATH), allow_partial=True,
                run_meta=meta, run_meta_path=str(meta_path),
            )
            self.assertIn("> AnyTLS：session 池/心跳定时器/padding 写路径未单独验。", text)
            udp_line = next(
                line for line in text.splitlines()
                if line.startswith("| Default/UdpEcho |") and "MISSING" not in line
            )
            self.assertIn("crate 级，产品入口不可用", udp_line)

    def test_fix_section_and_appendix_use_run_meta_and_actual_run_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            meta_path, meta = write_run_meta(tmp)
            make_run(tmp, "Vless", {})
            _, text = recompute.build(
                str(tmp), str(MATRIX_PATH), allow_partial=True,
                run_meta=meta, run_meta_path=str(meta_path),
            )
            self.assertIn("本 run 产生 verdict 翻转的修复条目", text)
            self.assertIn("**transport batch write**（commit `aaa`）", text)
            self.assertIn("flipped AnyTLS", text)
            self.assertIn(f"--run-dir {tmp}", text)
            self.assertIn(f"--run-meta {meta_path}", text)
            self.assertNotIn("b7acb32", text)
            self.assertIn("按证据 `nexus.commit` 派生：`x`（Vless）", text)

    def test_run_meta_missing_fields_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run-meta.json"
            path.write_text(json.dumps({"run_id": "x"}), encoding="utf-8")
            with self.assertRaises(recompute.RecomputeError):
                recompute.load_run_meta(str(path))

    def test_without_run_meta_keeps_legacy_narrative(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            make_run(tmp, "Vless", {})
            _, text = recompute.build(str(tmp), str(MATRIX_PATH), allow_partial=True)
            self.assertIn("run `protocol-interop-verification`", text)
            self.assertIn("b7acb32", text)
            self.assertNotIn("**结论 1 限定**", text)

    # ---- C5a: optional narrative overrides ---------------------------------

    def _ss_run_with_meta(self, tmp, narrative=None):
        make_run(
            Path(tmp),
            "Shadowsocks",
            {("Default", "UdpEcho"): {"status": "NOT_IMPLEMENTED", "cls": "E_NEXUS_NOT_IMPLEMENTED"}},
        )
        path, meta = write_run_meta(tmp)
        if narrative is not None:
            meta["narrative"] = narrative
            path.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
        _, text = recompute.build(
            str(tmp), str(MATRIX_PATH), allow_partial=False, run_meta=meta
        )
        return text

    def test_narrative_absent_keeps_default_narrative(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = self._ss_run_with_meta(tmp)
            self.assertIn(
                "剩余阻断分属协议编解码、协议线格式与产品安全语义/产品能力缺口", text
            )
            self.assertIn(
                "Trojan/SS 当前仍受 fallback 安全语义/线格式与产品 UDP 缺口阻断", text
            )
            self.assertIn("线格式/SIP004 AEAD + 产品 UDP 未实现", blocking_row(text, "Shadowsocks"))
            self.assertIn(
                "限定：正向路径不通时本格仅证明无静默成功", text
            )

    def test_narrative_overrides_conclusions_blocking_and_upper_limit(self):
        narrative = {
            "conclusions": {"2": "FIXES2-CONCLUSION-2", "4": "FIXES2-CONCLUSION-4"},
            "blocking_meta": {"Shadowsocks": ["仅剩产品 UDP", "产品 UDP 能力缺口", "否"]},
            "upper_limit": {"Shadowsocks": "FIXES2-UPPER"},
            "failure_cell_qualifier": {"Shadowsocks": "FIXES2-QUALIFIER"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            text = self._ss_run_with_meta(tmp, narrative)
            self.assertIn("**结论 2**：FIXES2-CONCLUSION-2", text)
            self.assertIn("**结论 4**：FIXES2-CONCLUSION-4", text)
            row = blocking_row(text, "Shadowsocks")
            self.assertIn("仅剩产品 UDP", row)
            self.assertIn("产品 UDP 能力缺口", row)
            self.assertIn("FIXES2-UPPER", row)
            self.assertNotIn("线格式/SIP004 AEAD + 产品 UDP 未实现", row)
            self.assertIn("FIXES2-QUALIFIER", text)
            self.assertNotIn("限定：正向路径不通时本格仅证明无静默成功", text)

    def test_narrative_null_qualifier_suppresses_boilerplate(self):
        narrative = {"failure_cell_qualifier": {"Shadowsocks": None}}
        with tempfile.TemporaryDirectory() as tmp:
            text = self._ss_run_with_meta(tmp, narrative)
            self.assertNotIn("限定：正向路径不通时本格仅证明无静默成功", text)
            # Verdict narrative stays default when only the qualifier is overridden.
            self.assertIn("Trojan/SS 当前仍受 fallback 安全语义/线格式与产品 UDP 缺口阻断", text)


if __name__ == "__main__":
    unittest.main()

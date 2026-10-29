#!/usr/bin/env python3
"""finalize.py 的失败格访问证明（AC-12.2.3）负向测试。

覆盖（对应 spec AC-12.3 的 meta 负向测试 (c)）：
- pcap 缺失 → Blocked；
- pcap 存在但没有任何参照端侧访问流 → Blocked（不得 PASS）；
- 只有无关端口的流量 → Blocked；
- 命中参照端节点端口 / fallback 端口 → 不降级。
"""

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import finalize  # noqa: E402


def _pcap_bytes(dst_port: int, src_port: int = 40000, proto: str = "tcp") -> bytes:
    """最小 pcap：一条到 dst_port 的 TCP SYN 或 UDP 报文（零校验和，tshark 仍可解析端口）。"""
    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    eth = b"\x00" * 12 + struct.pack(">H", 0x0800)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        40,
        0,
        0,
        64,
        6,
        0,
        b"\x7f\x00\x00\x01",
        b"\x7f\x00\x00\x01",
    )
    if proto == "udp":
        # IPv4 协议号 17 = UDP；UDP 头 8 字节。
        ip = struct.pack(
            ">BBHHHBBH4s4s",
            0x45,
            0,
            28,
            0,
            0,
            64,
            17,
            0,
            b"\x7f\x00\x00\x01",
            b"\x7f\x00\x00\x01",
        )
        transport = struct.pack(">HHHH", src_port, dst_port, 8, 0)
    else:
        transport = struct.pack(">HHIIBBHHH", src_port, dst_port, 0, 0, 0x50, 0x02, 8192, 0, 0)
    packet = eth + ip + transport
    record = struct.pack("<IIII", 0, 0, len(packet), len(packet))
    return global_header + record + packet


class AccessProofTest(unittest.TestCase):
    def _write(self, data: bytes) -> str:
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        f.write(data)
        f.close()
        return f.name

    def test_node_flow_is_proved(self):
        pcap = self._write(_pcap_bytes(26115))
        proof = finalize.access_proof(pcap, node_port=26115, fallback_port=26203)
        self.assertTrue(proof["checked"])
        self.assertTrue(proof["node_access"])
        self.assertFalse(proof["fallback_access"])
        override, reason = finalize.failure_cell_access_verdict(False, proof)
        self.assertIsNone(override, reason)

    def test_fallback_flow_is_proved(self):
        pcap = self._write(_pcap_bytes(26203))
        proof = finalize.access_proof(pcap, node_port=26115, fallback_port=26203)
        self.assertTrue(proof["fallback_access"])
        override, reason = finalize.failure_cell_access_verdict(True, proof)
        self.assertIsNone(override, reason)

    def test_unrelated_flow_is_blocked(self):
        # meta 负向测试 (c)：pcap 里没有参照端访问流 => 证据不足，不得 PASS。
        pcap = self._write(_pcap_bytes(9999))
        proof = finalize.access_proof(pcap, node_port=26115, fallback_port=26203)
        self.assertTrue(proof["checked"])
        self.assertFalse(proof["node_access"])
        self.assertFalse(proof["fallback_access"])
        override, reason = finalize.failure_cell_access_verdict(True, proof)
        self.assertEqual(override, "Blocked")
        self.assertIn("fallback", reason)
        override, reason = finalize.failure_cell_access_verdict(False, proof)
        self.assertEqual(override, "Blocked")
        self.assertIn("node", reason)

    def test_fallback_variant_with_only_node_flow_is_blocked(self):
        # TrojanFallback 格必须证明 fallback 目标被访问；只有节点流不足。
        pcap = self._write(_pcap_bytes(26115))
        proof = finalize.access_proof(pcap, node_port=26115, fallback_port=26203)
        override, _ = finalize.failure_cell_access_verdict(True, proof)
        self.assertEqual(override, "Blocked")

    def test_udp_flow_is_proved(self):
        # Hysteria2 等 QUIC/UDP 载体：失败格的参照端访问以 UDP 端口匹配。
        pcap = self._write(_pcap_bytes(26103, proto="udp"))
        proof = finalize.access_proof(pcap, node_port=26103, fallback_port=None)
        self.assertTrue(proof["node_access"])
        override, reason = finalize.failure_cell_access_verdict(False, proof)
        self.assertIsNone(override, reason)

    def test_missing_pcap_is_blocked(self):
        proof = finalize.access_proof("", node_port=26115, fallback_port=26203)
        self.assertFalse(proof["checked"])
        override, reason = finalize.failure_cell_access_verdict(True, proof)
        self.assertEqual(override, "Blocked")
        self.assertIn("pcap", reason)

    def test_missing_file_is_blocked(self):
        proof = finalize.access_proof("/nonexistent/x.pcap", 26115, 26203)
        self.assertFalse(proof["checked"])
        override, _ = finalize.failure_cell_access_verdict(False, proof)
        self.assertEqual(override, "Blocked")


if __name__ == "__main__":
    unittest.main()

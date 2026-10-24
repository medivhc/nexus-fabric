#!/usr/bin/env python3
"""由 cell-matrix.json 生成 46 份 token 化 probe 模板（S17）。

令牌只允许凭据/运行期值；端口与协议字段全部具体化，便于评审。
`--check` 幂等：生成到内存后与磁盘逐字节比较，不写盘。
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
import labels  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
MATRIX = REPO / "scripts/interop/cell-matrix.json"
OUT_DIR = REPO / "docs/protocols/interop/probe-config"

REF_PORTS = {
    "vless-basic": 26100,
    "vless-vision": 26101,
    "vless-basic-flow-mismatch": 26101,
    "anytls": 26102,
    "anytls-custom-padding": 26102,
    "hysteria2-plain": 26103,
    "hysteria2-salamander": 26104,
    "trojan": 26105,
    "trojan-fallback": 26115,
    "shadowsocks": 26106,
    "shadowsocks-aes256gcm": 26106,
}

WRONG = {
    "Vless": {"uuid": "00000000-0000-4000-8000-000000000000", "flow": "None"},
    "Anytls": {"password": "wrong-anytls-password", "padding_md5_hex": "${ANYTLS_PADDING_MD5}"},
    "Hysteria2": {"password": "wrong-hysteria2-password", "obfs": "None"},
    "Trojan": {"password": "wrong-trojan-password", "header_format": "Standard"},
    "Shadowsocks": {"password": "wrong-shadowsocks-password", "method": "Chacha20IetfPoly1305"},
}


def credentials(protocol, variant, cell):
    wrong = cell in ("BadCredential",)
    if protocol == "Vless":
        if wrong:
            return {"Vless": dict(WRONG["Vless"])}
        flow = "Vision" if variant == "VlessVision" else "None"
        return {"Vless": {"uuid": "${VLESS_UUID}", "flow": flow}}
    if protocol == "Anytls":
        if wrong:
            return {"Anytls": dict(WRONG["Anytls"])}
        return {
            "Anytls": {
                "password": "${ANYTLS_PASSWORD}",
                "padding_md5_hex": "${ANYTLS_PADDING_MD5}",
            }
        }
    if protocol == "Hysteria2":
        if wrong:
            return {"Hysteria2": dict(WRONG["Hysteria2"])}
        obfs = (
            {"Salamander": {"password": "${HY2_OBFS_PASSWORD}"}}
            if variant == "Hy2Salamander"
            else "None"
        )
        return {"Hysteria2": {"password": "${HY2_PASSWORD}", "obfs": obfs}}
    if protocol == "Trojan":
        if wrong:
            return {"Trojan": dict(WRONG["Trojan"])}
        return {"Trojan": {"password": "${TROJAN_PASSWORD}", "header_format": "Standard"}}
    if protocol == "Shadowsocks":
        if wrong:
            return {"Shadowsocks": dict(WRONG["Shadowsocks"])}
        return {
            "Shadowsocks": {
                "password": "${SS_PASSWORD}",
                "method": "Chacha20IetfPoly1305",
            }
        }
    raise SystemExit(f"unknown protocol {protocol}")


def timeouts(cell, t2):
    cell_ms = 60000
    if cell == "LongLived":
        cell_ms = 120000
    if cell == "UdpEcho":
        cell_ms = 20000
    return {
        "handshake_ms": 10000,
        "cell_ms": cell_ms,
        "failure_ms": 10000,
        "long_lived_ms": 120000,
        "heartbeat_ms": 10000,
        "reconnect_wait_ms": 2000,
    }


def workload(t2):
    return {
        "small_bytes": 65536,
        "throughput_bytes": 33554432 if t2 else 33554432,
        "throughput_repeats": 3,
        "warmup_bytes": 1048576,
        "udp_datagrams": 1000,
        "udp_payload_bytes": 512,
        "udp_interval_ms": 1,
        "long_lived_heartbeats": 12,
        "reconnect_cycles": 3,
    }


def build(entry):
    ref_variant = entry["ref_variant"]
    port = REF_PORTS.get(ref_variant, 26100) if ref_variant else 26100
    cfg = {
        "schema_version": 1,
        "run_id": "protocol-interop-verification",
        "protocol": entry["protocol"],
        "variant": entry["variant"],
        "cell": entry["cell"],
        "reference": {
            "host": "127.0.0.1",
            "port": port,
            "server_name": "localhost",
            "alpn": [],
        },
        "target": {
            "kind": entry["target_kind"],
            "host": "127.0.0.1",
            "port": entry["target_port"],
        },
        "credentials": credentials(entry["protocol"], entry["variant"], entry["cell"]),
        "tls": {"skip_cert_verify": True, "sni": "localhost"},
        "transport": {"fast_open": True, "udp": True, "vision_direct": False},
        "timeouts": timeouts(entry["cell"], entry["t2"]),
        "workload": workload(entry["t2"]),
    }
    return cfg


def file_name(entry):
    return (
        f"{labels.label('protocol', entry['protocol'])}-"
        f"{labels.label('variant', entry['variant'])}-"
        f"{labels.label('cell', entry['cell'])}.json"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rendered = {}
    for entry in matrix["cells"]:
        name = file_name(entry)
        rendered[name] = json.dumps(build(entry), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        problems = []
        for name, text in rendered.items():
            path = OUT_DIR / name
            if not path.exists():
                problems.append(f"missing {name}")
            elif path.read_text(encoding="utf-8") != text:
                problems.append(f"drift {name}")
        extra = {p.name for p in OUT_DIR.glob("*.json")} - set(rendered)
        problems.extend(f"unexpected {name}" for name in sorted(extra))
        if problems:
            for p in problems:
                print(p)
            return 1
        print(f"probe templates up to date ({len(rendered)} files)")
        return 0
    for name, text in rendered.items():
        (OUT_DIR / name).write_text(text, encoding="utf-8")
    for stale in {p.name for p in OUT_DIR.glob("*.json")} - set(rendered):
        (OUT_DIR / stale).unlink()
    print(f"wrote {len(rendered)} probe templates to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

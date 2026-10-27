#!/usr/bin/env python3
"""Trojan CONNECT 应答时序 / 线缆字节对照探针（develop 步骤 1 的位移等价判据）。

只做测量，不进入产品依赖：

1. 起一个本地 TLS Trojan 节点（Python `ssl` + 运行时自签证书）：读 56B 密码 hash
   校验通过后进入 echo 模式；
2. 用给定二进制起 `nexus proxy --addr 127.0.0.1:<p> --config <proxy.yaml>`；
3. 原始 SOCKS5 客户端逐样本记录：
   - `t_connect_sent -> t_success_read`（CONNECT 应答到达耗时，ms）；
   - 客户端可见的 success 应答字节 + echo 载荷字节（用于逐字节对照）。
4. 可选 `--pcap`：dumpcap 抓 `lo` 上到节点的 TCP，收尾后用 tshark 导出 TLS
   record 的 content_type / length 序列（线缆面记录条数与长度对照）。

同一脚本对 baseline / candidate 两个二进制各跑一遍（节点与客户端代码完全相同），
输出一份 JSON 供证据归档：

```
python3 scripts/interop/trojan_reply_probe.py \
  --baseline /work/wt-fixes5-baseline/target/debug/nexus \
  --candidate target/debug/nexus --samples 20 \
  --out /work/interop-run/fixes5/analysis/step1-reply-timing.json
```
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time

PASSWORD = "probe-pass"
PAYLOAD = b"ping-via-trojan-tunnel"
PROBE_TIMEOUT_S = 5.0


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


PROXY_PORT = 1080


def port_is_free(port: int) -> bool:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def make_cert(tmpdir: str) -> tuple[str, str]:
    cert = os.path.join(tmpdir, "cert.pem")
    key = os.path.join(tmpdir, "key.pem")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key,
            "-out",
            cert,
            "-days",
            "2",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def trojan_header(host: str, port: int) -> bytes:
    pw_hash = hashlib.sha224(PASSWORD.encode()).hexdigest().encode()
    header = pw_hash + b"\r\n" + b"\x01" + b"\x01" + socket.inet_aton(host)
    header += port.to_bytes(2, "big") + b"\r\n"
    return header


class TrojanNode(threading.Thread):
    """本地 TLS Trojan 节点：校验密码 hash，随后 echo。"""

    def __init__(self, cert: str, key: str):
        super().__init__(daemon=True)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.connections = 0
        self.errors: list[str] = []
        self.lock = threading.Lock()

    def run(self) -> None:
        self.sock.settimeout(0.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()
        try:
            self.sock.close()
        except OSError:
            pass

    def _serve(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(PROBE_TIMEOUT_S)
            tls = self.ctx.wrap_socket(conn, server_side=True)
        except OSError as e:  # TLS 失败不致命：记下原因继续服务
            with self.lock:
                self.errors.append(f"tls: {e}")
            try:
                conn.close()
            except OSError:
                pass
            return
        try:
            buf = b""
            while buf.count(b"\r\n") < 2:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                buf += chunk
            first_end = buf.find(b"\r\n")
            second_end = buf.find(b"\r\n", first_end + 2)
            first = buf[:first_end]
            expected = hashlib.sha224(PASSWORD.encode()).hexdigest().encode()
            if first.strip().lower() != expected:
                with self.lock:
                    self.errors.append("auth denied")
                return
            payload = buf[second_end + 2 :]
            while True:
                if payload:
                    tls.sendall(payload)
                    payload = b""
                chunk = tls.recv(4096)
                if not chunk:
                    return
                tls.sendall(chunk)
        except OSError as e:
            with self.lock:
                self.errors.append(f"io: {e}")
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def shutdown(self) -> None:
        self.stop.set()
        self.join(timeout=3)


def start_proxy(binary: str, config_path: str) -> subprocess.Popen:
    # 注意：`nexus proxy --addr` 会被全局 `extract_remote_target` 当作 thin-client
    # 目标吃掉（既有 CLI 行为，与本 run 无关），因此这里使用进程内代理的默认监听地址
    # 127.0.0.1:1080；调用方负责保证该端口空闲（busy 直接失败，不静默改用别的端口）。
    proc = subprocess.Popen(
        [binary, "proxy", "--config", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                raise RuntimeError(f"proxy exited early: {proc.stderr.read()}")
            continue
        if '"READY"' in line:
            return proc
    proc.kill()
    raise RuntimeError("proxy did not report READY within 10s")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            break
        out += chunk
    return out


def one_sample(proxy_port: int, dest_port: int) -> dict:
    client = socket.create_connection(("127.0.0.1", proxy_port), timeout=PROBE_TIMEOUT_S)
    client.settimeout(PROBE_TIMEOUT_S)
    record: dict = {}
    try:
        client.sendall(b"\x05\x01\x00")
        greeting = recv_exact(client, 2)
        record["greeting_reply_hex"] = greeting.hex()
        req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + dest_port.to_bytes(2, "big")
        t0 = time.monotonic()
        client.sendall(req)
        reply = recv_exact(client, 10)
        t1 = time.monotonic()
        record["success_ms"] = (t1 - t0) * 1000.0
        record["success_bytes_sha256"] = sha256_bytes(reply)
        record["success_reply_hex"] = reply.hex()
        if len(reply) != 10 or reply[1] != 0:
            record["ok"] = False
            record["error"] = f"connect reply {reply.hex()}"
            return record
        client.sendall(PAYLOAD)
        echo = recv_exact(client, len(PAYLOAD))
        record["echo_bytes_sha256"] = sha256_bytes(echo)
        record["echo_hex"] = echo.hex()
        record["ok"] = echo == PAYLOAD
    finally:
        try:
            client.close()
        except OSError:
            pass
    return record


def pcap_records(pcap_path: str) -> dict:
    """用 tshark 导出 TLS record 的 content_type/length 序列（线缆记录面）。"""
    if not shutil.which("tshark") or not os.path.exists(pcap_path):
        return {"available": False}
    out = subprocess.run(
        [
            "tshark",
            "-r",
            pcap_path,
            "-Y",
            "tls.record.content_type",
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "tcp.srcport",
            "-e",
            "tls.record.content_type",
            "-e",
            "tls.record.length",
        ],
        capture_output=True,
        text=True,
    )
    rows = []
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        rows.append(
            {
                "frame": parts[0],
                "src": parts[1],
                "srcport": parts[2],
                "content_type": parts[3],
                "length": parts[4],
            }
        )
    return {"available": True, "records": rows, "count": len(rows)}


def run_arm(binary: str, samples: int, pcap: str | None) -> dict:
    tmpdir = tempfile.mkdtemp(prefix="trojan-reply-probe-")
    cert, key = make_cert(tmpdir)
    node = TrojanNode(cert, key)
    node.start()
    port = PROXY_PORT
    config_path = os.path.join(tmpdir, "proxy.yaml")
    with open(config_path, "w", encoding="utf-8") as f:
        f.write(
            "schema_version: 1\n"
            "inbounds:\n"
            "  - tag: socks5-in\n"
            "    kind: socks5\n"
            "    listen: 127.0.0.1:0\n"
            "rules:\n"
            "  - tag: rule-match\n"
            "    kind: match\n"
            '    match: ""\n'
            "    action:\n"
            "      - kind: select_outbound\n"
            "        tag: trojan-node\n"
            "outbounds:\n"
            "  - tag: trojan-node\n"
            "    kind: trojan\n"
            f'    locator: "127.0.0.1:{node.port}"\n'
            f"    password: {PASSWORD}\n"
            "    skip_cert_verify: true\n"
            "    header_format: standard\n"
        )
    dumpcap = None
    if pcap:
        bpf = f"tcp port {node.port}"
        dumpcap = subprocess.Popen(
            ["dumpcap", "-i", "lo", "-w", pcap, "-f", bpf],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.6)
    if not port_is_free(port):
        raise RuntimeError(f"proxy listen port {port} is busy; refusing to run")
    proxy = start_proxy(binary, config_path)
    rows = []
    try:
        for _ in range(samples):
            rows.append(one_sample(port, node.port))
            time.sleep(0.01)
    finally:
        proxy.kill()
        proxy.wait(timeout=5)
        if dumpcap is not None:
            dumpcap.terminate()
            try:
                dumpcap.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dumpcap.kill()
        node.shutdown()
    times = [r["success_ms"] for r in rows if r.get("ok")]
    report = {
        "binary": binary,
        "binary_sha256": sha256_file(binary),
        "samples": len(rows),
        "ok_samples": len(times),
        "median_ms": statistics.median(times) if times else None,
        "p50_ms": statistics.median(times) if times else None,
        "p95_ms": (
            sorted(times)[max(0, int(round(0.95 * (len(times) - 1))))] if times else None
        ),
        "success_bytes_sha256": sorted({r["success_bytes_sha256"] for r in rows}),
        "echo_bytes_sha256": sorted({r["echo_bytes_sha256"] for r in rows if r.get("echo_bytes_sha256")}),
        "success_reply_hex": sorted({r.get("success_reply_hex") for r in rows}),
        "node_connections": node.connections,
        "node_errors": node.errors,
        "rows": rows,
    }
    if pcap:
        report["pcap"] = {"path": pcap, **pcap_records(pcap)}
    shutil.rmtree(tmpdir, ignore_errors=True)
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", help="baseline nexus 二进制（a30147a 同机重建）")
    ap.add_argument("--candidate", required=True, help="candidate nexus 二进制")
    ap.add_argument("--samples", type=int, default=20)
    ap.add_argument("--out", help="输出 JSON 路径")
    ap.add_argument("--pcap", help="dumpcap 抓包输出路径（可选，仅对 candidate）")
    ap.add_argument("--baseline-pcap", help="dumpcap 抓包输出路径（可选，仅对 baseline）")
    args = ap.parse_args()

    if args.samples < 1:
        print("--samples must be >= 1", file=sys.stderr)
        return 2

    result = {
        "tool": "trojan_reply_probe.py",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "payload_sha256": sha256_bytes(PAYLOAD),
        "loopback": True,
        "samples_per_arm": args.samples,
    }
    if args.baseline:
        result["baseline"] = run_arm(args.baseline, args.samples, args.baseline_pcap)
    result["candidate"] = run_arm(args.candidate, args.samples, args.pcap)

    b = result.get("baseline")
    c = result["candidate"]
    if b and b["median_ms"] is not None and c["median_ms"] is not None:
        result["median_delta_ms"] = c["median_ms"] - b["median_ms"]
        result["median_delta_within_50ms"] = abs(result["median_delta_ms"]) <= 50.0
    if b:
        result["client_bytes_identical"] = (
            b["success_bytes_sha256"] == c["success_bytes_sha256"]
            and b["echo_bytes_sha256"] == c["echo_bytes_sha256"]
        )

    text = json.dumps(result, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(text)
    ok = all(r.get("ok") for r in c["rows"])
    if b:
        ok = ok and all(r.get("ok") for r in b["rows"])
        ok = ok and result.get("median_delta_within_50ms", False)
        ok = ok and result.get("client_bytes_identical", False)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

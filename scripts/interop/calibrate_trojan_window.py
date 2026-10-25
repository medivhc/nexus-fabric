#!/usr/bin/env python3
"""AC-9 窗口校准：用 sing-box 1.13.16 的 trojan-fallback 参照端 + 错密码产品会话，
在 loopback 上抓包测量「Trojan 头首字节 → fallback 首字节」的分布，并核对
`W >= 3×p99 + 20ms`（spec §9 / AC-9.4）。

识别方法（spec 冻结）：
- 「Trojan 头 flush 首字节」= TLS 握手完成后首个 client→node TLS ApplicationData
  记录的首字节时刻；
- 「fallback 首字节」= 首个 node→client TLS ApplicationData 记录的首字节时刻；
- 每个 TCP 流一组，取 ≥100 个样本的 p99。

不满足 `W >= 3×p99 + 20ms` 时脚本以非零退出并给出需要抬高到的下限（**不得降低判据**）。

用法：
```
python3 scripts/interop/calibrate_trojan_window.py \
  --run-dir /work/interop-run/fixes5 --samples 100 \
  --proxy-bin target/debug/nexus \
  --out /work/interop-run/fixes5/analysis/ac9-calibration.json
```
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time

REF_PORT_FALLBACK = 26203
PRODUCT_PASSWORD = "deliberately-wrong-password"
WINDOW_MIN_MS = 50
WINDOW_MAX_MS = 600


def sha256_file(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            break
        out += chunk
    return out


def start_fallback_target(port: int):
    """极简 HTTP 404 目标（sing-box fallback 指向它）。"""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    srv.settimeout(0.2)

    import threading

    stop = threading.Event()
    hits = {"count": 0}

    def serve():
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            hits["count"] += 1
            try:
                c.settimeout(0.5)
                c.recv(1024)
                body = b"interop-404-body"
                c.sendall(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + body
                )
            except OSError:
                pass
            finally:
                try:
                    c.close()
                except OSError:
                    pass
        try:
            srv.close()
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return stop, hits, t


def sample_once(product_port: int) -> dict:
    c = socket.create_connection(("127.0.0.1", product_port), timeout=5)
    c.settimeout(5)
    try:
        c.sendall(b"\x05\x01\x00")
        recv_exact(c, 2)
        req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + (26200).to_bytes(2, "big")
        t0 = time.monotonic()
        c.sendall(req)
        reply = recv_exact(c, 10)
        elapsed = (time.monotonic() - t0) * 1000.0
        return {"rep": reply[1] if len(reply) > 1 else None, "ms": elapsed}
    finally:
        try:
            c.close()
        except OSError:
            pass


def tshark_streams(pcap: str, ref_port: int) -> dict:
    """按 TCP 流收集 TLS ApplicationData 记录（content_type=23）。

    识别方法（spec §9 冻结口径的落地）：
    - TLS 1.3 下 client Finished 也是 content_type=23，所以「Trojan 头首字节」取
      **该流最后一条 client→node ApplicationData 记录**（产品在窗口内不再发任何字节）；
    - 「fallback 首字节」取该流**第一条晚于头记录**的 node→client ApplicationData 记录。
    """
    out = subprocess.run(
        [
            "tshark",
            "-r",
            pcap,
            "-Y",
            "tcp.port == %d && tls && !tls.record.content_type && tcp.len > 0" % ref_port,
            "-T",
            "fields",
            "-e",
            "tcp.stream",
            "-e",
            "frame.time_epoch",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.len",
        ],
        capture_output=True,
        text=True,
    )
    streams: dict[str, dict] = {}
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 4 or not parts[0]:
            continue
        stream, ts, srcport, length = parts[0], parts[1], parts[2], parts[3]
        row = streams.setdefault(stream, {"client": [], "server": []})
        try:
            record = (float(ts), int(length))
        except ValueError:
            continue
        if srcport != str(ref_port):
            row["client"].append(record)
        else:
            row["server"].append(record)
    return streams


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--samples", type=int, default=100)
    ap.add_argument("--proxy-bin", required=True)
    ap.add_argument("--ref-bin")
    ap.add_argument("--ref-config")
    ap.add_argument("--pcap")
    ap.add_argument("--out")
    args = ap.parse_args()

    run_dir = os.path.abspath(args.run_dir)
    ref_bin = args.ref_bin or os.path.join(
        run_dir, "ref/sing-box-1.13.16-linux-amd64-musl/sing-box"
    )
    ref_config = args.ref_config or os.path.join(
        run_dir, "evidence/ref-config/trojan-fallback.json"
    )
    pcap = args.pcap or os.path.join(run_dir, "analysis/ac9.pcap")
    os.makedirs(os.path.dirname(pcap), exist_ok=True)

    for path in (ref_bin, ref_config, args.proxy_bin):
        if not os.path.exists(path):
            print(f"missing {path}", file=sys.stderr)
            return 2
    if not shutil.which("tshark") or not shutil.which("dumpcap"):
        print("tshark/dumpcap unavailable", file=sys.stderr)
        return 2

    cfg = json.load(open(ref_config, encoding="utf-8"))
    ref_port = cfg["inbounds"][0].get("listen_port") or cfg["inbounds"][0].get("port")
    fallback_port = int(
        (cfg["inbounds"][0].get("fallback") or {}).get("server_port", REF_PORT_FALLBACK)
    )

    # 端口门禁（不静默改端口）。
    for p in (ref_port, fallback_port):
        s = socket.socket()
        # SO_REUSEADDR：只看「是否有活跃监听者」，不把 TIME_WAIT 误判为占用。
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", p))
        except OSError:
            print(f"port {p} busy; refusing to run", file=sys.stderr)
            return 2
        finally:
            s.close()

    fb_stop, fb_hits, fb_thread = start_fallback_target(fallback_port)
    dumpcap_log = os.path.join(run_dir, "analysis/ac9-dumpcap.log")
    dumpcap = subprocess.Popen(
        ["dumpcap", "-i", "lo", "-w", pcap, "-f", f"tcp port {ref_port} or tcp port {fallback_port}"],
        stdout=subprocess.DEVNULL,
        stderr=open(dumpcap_log, "w"),
    )
    time.sleep(0.6)
    ref = subprocess.Popen(
        [ref_bin, "run", "-c", ref_config],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    time.sleep(0.6)
    # 参照端就绪检查（避免「端口被旧进程占用 → 参照端退出 → 抓到 0 包」被误读成校准结果）。
    ref_ready = False
    for _ in range(50):
        if ref.poll() is not None:
            break
        probe = socket.socket()
        probe.settimeout(0.2)
        try:
            probe.connect(("127.0.0.1", ref_port))
            ref_ready = True
        except OSError:
            pass
        finally:
            probe.close()
        if ref_ready:
            break
        time.sleep(0.1)
    if not ref_ready:
        print(
            f"ref not ready on {ref_port}: poll={ref.poll()} (port busy or config invalid)",
            file=sys.stderr,
        )
        try:
            print(ref.stderr.read(), file=sys.stderr)
        except Exception:
            pass
        dumpcap.terminate()
        fb_stop.set()
        return 2

    product_port = free_port()
    proxy_cfg = os.path.join(run_dir, "analysis/ac9-proxy.yaml")
    with open(proxy_cfg, "w", encoding="utf-8") as f:
        f.write(
            "schema_version: 1\n"
            "rules:\n"
            "  - tag: rule-match\n"
            "    kind: match\n"
            '    match: ""\n'
            "    action:\n"
            "      - kind: select_outbound\n"
            "        tag: trojan-fallback\n"
            "outbounds:\n"
            "  - tag: trojan-fallback\n"
            "    kind: trojan\n"
            f'    locator: "127.0.0.1:{ref_port}"\n'
            f"    password: {PRODUCT_PASSWORD}\n"
            "    skip_cert_verify: true\n"
        )
    product = subprocess.Popen(
        [args.proxy_bin, "proxy", "--addr", f"127.0.0.1:{product_port}", "--config", proxy_cfg],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # `nexus proxy` 的 --addr 会被全局 remote-target 解析吃掉（既有 CLI 行为），
    # 实际监听 127.0.0.1:1080；这里读取 READY 行确认实际地址。
    readies = []
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        line = product.stdout.readline()
        if not line:
            if product.poll() is not None:
                break
            continue
        readies.append(line.strip())
        if '"READY"' in line:
            break
    if not any('"READY"' in r for r in readies):
        print(f"product proxy not ready: {readies} {product.stderr.read()}", file=sys.stderr)
        for p in (product, ref, dumpcap):
            p.kill()
        fb_stop.set()
        return 2
    actual = json.loads([r for r in readies if '"READY"' in r][0])["daemon"]["addr"]
    product_port = int(actual.rsplit(":", 1)[1])

    rows = []
    try:
        for _ in range(args.samples):
            rows.append(sample_once(product_port))
            time.sleep(0.005)
    finally:
        product.kill()
        product.wait(timeout=5)
        dumpcap.terminate()
        try:
            dumpcap.wait(timeout=5)
        except subprocess.TimeoutExpired:
            dumpcap.kill()
        ref.terminate()
        try:
            ref.wait(timeout=5)
        except subprocess.TimeoutExpired:
            ref.kill()
        fb_stop.set()
        fb_thread.join(timeout=2)

    streams = tshark_streams(pcap, ref_port)
    deltas = []
    complete = 0
    for _sid, row in streams.items():
        if not row["client"] or not row["server"]:
            continue
        header_ts, header_len = max(row["client"])
        later = [ts for ts, _ in row["server"] if ts > header_ts]
        if not later:
            continue
        delta_ms = (min(later) - header_ts) * 1000.0
        complete += 1
        deltas.append(delta_ms)

    if not deltas:
        print("no complete streams in pcap", file=sys.stderr)
        print(f"streams={len(streams)} client_replies={rows}", file=sys.stderr)
        return 2
    deltas.sort()
    p99 = deltas[max(0, int(round(0.99 * (len(deltas) - 1))))]
    required = 3 * p99 + 20.0
    effective_w = WINDOW_MIN_MS  # loopback: t_connect ≈ 0 => adaptive W = 50ms
    ok = effective_w >= required

    report = {
        "tool": "calibrate_trojan_window.py",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "samples_requested": args.samples,
        "samples_with_complete_streams": complete,
        "pcap": pcap,
        "measure": {
            "method": (
                "per TCP stream: 头首字节 = 该流最后一条 client->node TLS ApplicationData 记录的时间戳"
                "（TLS1.3 下 client Finished 同为 content_type=23，故取最后一条；产品在窗口内不再发字节）；"
                "fallback 首字节 = 该流第一条晚于头记录的 node->client TLS ApplicationData 记录时间戳"
            ),
            "delta_ms_median": deltas[len(deltas) // 2],
            "delta_ms_p99": p99,
            "delta_ms_max": deltas[-1],
        },
        "window": {
            "adaptive_min_ms": WINDOW_MIN_MS,
            "adaptive_max_ms": WINDOW_MAX_MS,
            "effective_w_ms_loopback": effective_w,
            "required_min_ms": required,
            "rule": "W >= 3*p99 + 20ms",
            "ok": ok,
            "raise_to_ms": None if ok else int(required) + 1,
        },
        "ref": {
            "bin": ref_bin,
            "bin_sha256": sha256_file(ref_bin),
            "config": ref_config,
            "config_sha256": sha256_file(ref_config),
            "port": ref_port,
            "fallback_port": fallback_port,
        },
        "product_bin": {"path": os.path.abspath(args.proxy_bin), "sha256": sha256_file(args.proxy_bin)},
        "fallback_target_hits": fb_hits["count"],
        "client_replies": {
            "samples": len(rows),
            "rep_nonzero": sum(1 for r in rows if r["rep"] not in (0, None)),
            "median_fail_ms": sorted(r["ms"] for r in rows)[len(rows) // 2] if rows else None,
        },
    }
    text = json.dumps(report, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        open(args.out, "w", encoding="utf-8").write(text + "\n")
    print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

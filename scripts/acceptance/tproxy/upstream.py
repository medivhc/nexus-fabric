#!/usr/bin/env python3
"""E5 netns 验收用的上游站点（DNS / HTTP echo / UDP echo / SOCKS5）。

只监听本 netns 内的地址，不接触宿主网络。所有服务都写出可读日志，
供 harness 断言"流量真的到达上游"以及"回包源地址"。
"""

from __future__ import annotations

import argparse
import signal
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_LOG_LOCK = threading.Lock()
_LOG_PATH: str | None = None
_SOCKS5_LOG: str | None = None


def log(message: str) -> None:
    line = f"{time.strftime('%H:%M:%S')} {message}"
    with _LOG_LOCK:
        print(line, flush=True)
        if _LOG_PATH:
            with open(_LOG_PATH, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")


def socks5_log(message: str) -> None:
    line = f"{time.strftime('%H:%M:%S')} {message}"
    with _LOG_LOCK:
        print(f"[socks5] {line}", flush=True)
        if _SOCKS5_LOG:
            with open(_SOCKS5_LOG, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")


def parse_qname(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated qname")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if offset + length > len(packet):
            raise ValueError("truncated label")
        labels.append(packet[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), offset


def dns_response(query: bytes, answer_ip: str) -> bytes:
    if len(query) < 12:
        raise ValueError("short dns query")
    ident, flags, qdcount = struct.unpack("!HHH", query[:6])
    if qdcount != 1:
        raise ValueError(f"unsupported qdcount {qdcount}")
    qname, offset = parse_qname(query, 12)
    if offset + 4 > len(query):
        raise ValueError("truncated qtype")
    qtype, qclass = struct.unpack("!HH", query[offset : offset + 4])
    question = query[12 : offset + 4]
    answer = b""
    ancount = 0
    if qtype == 1 and qclass == 1:
        answer = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + socket.inet_aton(answer_ip)
        )
        ancount = 1
    header = struct.pack(
        "!HHHHHH",
        ident,
        0x8180,
        1,
        ancount,
        0,
        0,
    )
    log(f"[dns] qname={qname} qtype={qtype} answer={answer_ip if ancount else '-'}")
    return header + question + answer


def serve_dns(bind: str, answer_ip: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, 53))
    log(f"[dns] listening {bind}:53 answer={answer_ip}")
    while True:
        data, peer = sock.recvfrom(4096)
        try:
            reply = dns_response(data, answer_ip)
        except Exception as error:  # noqa: BLE001 - log and keep serving
            log(f"[dns] malformed query from {peer}: {error}")
            continue
        sock.sendto(reply, peer)
        log(f"[dns] replied to {peer[0]}:{peer[1]}")


class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self.path.startswith("/slow"):
            time.sleep(2.0)
        body = f"hello-nexus path={self.path} host={self.headers.get('Host', '-')}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        log(f"[http] {self.server.server_address[0]}:8080 {self.command} {self.path}")

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        log(f"[http] {self.server.server_address[0]}:8080 " + (fmt % args))


def serve_http(bind: str) -> None:
    server = ThreadingHTTPServer((bind, 8080), EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log(f"[http] listening {bind}:8080")


def serve_udp_echo(bind: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, 9000))
    log(f"[udp] listening {bind}:9000")
    while True:
        data, peer = sock.recvfrom(65535)
        sock.sendto(data, peer)
        log(f"[udp] echoed {len(data)} bytes to {peer[0]}:{peer[1]}")


def read_exact(sock: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            raise ConnectionError("peer closed")
        chunks.extend(chunk)
    return bytes(chunks)


def relay(left: socket.socket, right: socket.socket) -> None:
    try:
        while True:
            data = left.recv(65536)
            if not data:
                break
            right.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (left, right):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle_socks5(client: socket.socket, peer: tuple[str, int]) -> None:
    try:
        version, nmethods = read_exact(client, 2)
        if version != 5:
            raise ValueError(f"bad version {version}")
        methods = read_exact(client, nmethods)
        if 0 not in methods:
            client.sendall(b"\x05\xff")
            return
        client.sendall(b"\x05\x00")
        version, command, _reserved, atyp = read_exact(client, 4)
        if version != 5 or command != 1:
            client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        if atyp == 1:
            target_host = socket.inet_ntoa(read_exact(client, 4))
        elif atyp == 3:
            (length,) = struct.unpack("!B", read_exact(client, 1))
            target_host = read_exact(client, length).decode("ascii", "replace")
        elif atyp == 4:
            target_host = socket.inet_ntop(socket.AF_INET6, read_exact(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        (target_port,) = struct.unpack("!H", read_exact(client, 2))
        socks5_log(f"connect from={peer[0]}:{peer[1]} target={target_host}:{target_port}")
        try:
            upstream = socket.create_connection((target_host, target_port), timeout=5)
        except OSError as error:
            socks5_log(f"connect_failed target={target_host}:{target_port} err={error}")
            client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        upstream.settimeout(None)
        first = threading.Thread(target=relay, args=(client, upstream), daemon=True)
        first.start()
        relay(upstream, client)
        first.join(timeout=2)
    except (OSError, ValueError) as error:
        socks5_log(f"error from={peer[0]}:{peer[1]} err={error}")
    finally:
        try:
            client.close()
        except OSError:
            pass


def serve_socks5(bind: str) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((bind, 1080))
    listener.listen(64)
    log(f"[socks5] listening {bind}:1080")
    while True:
        client, peer = listener.accept()
        threading.Thread(
            target=handle_socks5, args=(client, peer), daemon=True
        ).start()


def main() -> int:
    global _LOG_PATH, _SOCKS5_LOG
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="10.200.2.2")
    parser.add_argument("--site", default="10.200.2.9")
    parser.add_argument("--dns-answer", default="10.200.2.9")
    parser.add_argument("--log", default=None)
    parser.add_argument("--socks5-log", default=None)
    parser.add_argument("--no-socks5", action="store_true")
    args = parser.parse_args()

    _LOG_PATH = args.log
    _SOCKS5_LOG = args.socks5_log

    def shutdown(*_args: object) -> None:
        log("shutdown signal")
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    threads = [
        threading.Thread(target=serve_dns, args=(args.bind, args.dns_answer), daemon=True),
        threading.Thread(target=serve_http, args=(args.bind,), daemon=True),
        threading.Thread(target=serve_http, args=(args.site,), daemon=True),
        threading.Thread(target=serve_udp_echo, args=(args.bind,), daemon=True),
    ]
    if not args.no_socks5:
        threads.append(
            threading.Thread(target=serve_socks5, args=(args.bind,), daemon=True)
        )
    for thread in threads:
        thread.start()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    raise SystemExit(main())

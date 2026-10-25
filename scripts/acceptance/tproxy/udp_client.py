#!/usr/bin/env python3
"""E5 S2 客户端 UDP 探针：打印 recvfrom() 的真实回包源地址。"""

from __future__ import annotations

import argparse
import socket
import struct
import sys


def build_query(name: str, ident: int = 0x4E58) -> bytes:
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    question = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".") if label
    ) + b"\x00"
    question += struct.pack("!HH", 1, 1)
    return header + question


def parse_a(packet: bytes) -> str:
    if len(packet) < 12:
        return "-"
    qdcount, ancount = struct.unpack("!HH", packet[4:8])
    offset = 12
    for _ in range(qdcount):
        while offset < len(packet) and packet[offset] != 0:
            if packet[offset] & 0xC0 == 0xC0:
                offset += 2
                break
            offset += 1 + packet[offset]
        else:
            offset += 1
        offset += 4
    for _ in range(ancount):
        if offset + 12 > len(packet):
            return "-"
        if packet[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(packet) and packet[offset] != 0:
                offset += 1 + packet[offset]
            offset += 1
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", packet[offset : offset + 10])
        offset += 10
        rdata = packet[offset : offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            return socket.inet_ntoa(rdata)
    return "-"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dns", default="10.200.2.2")
    parser.add_argument("--echo", default="10.200.2.2:9000")
    parser.add_argument("--name", default="example.nexus")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    failures = 0

    dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns.settimeout(args.timeout)
    query = build_query(args.name)
    try:
        dns.sendto(query, (args.dns, 53))
        reply, peer = dns.recvfrom(4096)
        print(f"dns_src={peer[0]}:{peer[1]} dns_answer={parse_a(reply)}", flush=True)
    except OSError as error:
        print(f"dns_error={error}", flush=True)
        failures += 1
    finally:
        dns.close()

    echo_host, echo_port = args.echo.rsplit(":", 1)
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.settimeout(args.timeout)
    payload = b"hello-udp-nexus"
    try:
        echo.sendto(payload, (echo_host, int(echo_port)))
        reply, peer = echo.recvfrom(65535)
        print(
            f"echo_src={peer[0]}:{peer[1]} echo_payload={reply.decode(errors='replace')}",
            flush=True,
        )
    except OSError as error:
        print(f"echo_error={error}", flush=True)
        failures += 1
    finally:
        echo.close()

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

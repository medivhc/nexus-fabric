#!/usr/bin/env python3
"""E5 S2 回包失败路径辅助：hold / echo / probe 三种角色。

- hold ADDR PORT：在 router netns 以 IP_TRANSPARENT、无 SO_REUSEADDR 独占
  bind ADDR:PORT，使 nexusd 的回包 socket bind 失败。
- echo ADDR PORT：在 upstream netns 回显收到的数据报（证明上游确实回了包）。
- probe ADDR PORT：在 client netns 发一个数据报，打印 recvfrom() 的回包源或
  no_reply。

每个角色最多运行 --secs 秒后自行退出（root 进程不依赖外层包装回收）。
"""

from __future__ import annotations

import argparse
import socket
import time

IP_TRANSPARENT = getattr(socket, "IP_TRANSPARENT", 19)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["hold", "echo", "probe"])
    parser.add_argument("addr")
    parser.add_argument("port", type=int)
    parser.add_argument("--secs", type=float, default=15.0)
    parser.add_argument("--tag", default="")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end = time.monotonic() + args.secs
    if args.role == "hold":
        sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        sock.bind((args.addr, args.port))
        print("held", flush=True)
        time.sleep(max(0.0, end - time.monotonic()))
    elif args.role == "echo":
        sock.bind((args.addr, args.port))
        print("ready", flush=True)
        while time.monotonic() < end:
            sock.settimeout(max(0.1, end - time.monotonic()))
            try:
                data, peer = sock.recvfrom(2048)
            except socket.timeout:
                break
            sock.sendto(data, peer)
            print(f"echoed {len(data)} to {peer[0]}:{peer[1]}", flush=True)
    else:
        sock.settimeout(min(args.secs, 3.0))
        sock.sendto(b"held-probe", (args.addr, args.port))
        try:
            _, source = sock.recvfrom(2048)
            print(f"reply_from={source[0]}:{source[1]}", flush=True)
        except socket.timeout:
            print("no_reply", flush=True)


if __name__ == "__main__":
    main()

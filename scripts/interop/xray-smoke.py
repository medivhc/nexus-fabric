#!/usr/bin/env python3
"""Xray VLESS basic 冒烟（O-02a）。

自带 127.0.0.1:<target-port> TCP echo，起一份 Xray VLESS inbound 配置（TLS），
用 stdlib ssl 建 TLS、发 VLESS basic 请求头（TCP + 1 字节载荷），校验响应头与 echo。
只证明参照端配置可用；不产出协议 verdict。
"""
import argparse, hashlib, json, socket, ssl, subprocess, sys, threading, time, uuid

def is_free(port):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port)); return True
    except OSError:
        return False
    finally:
        s.close()

class Echo(threading.Thread):
    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", port)); self.srv.listen(1)
        self.received = None
        self.error = None
    def run(self):
        try:
            conn, _ = self.srv.accept()
            with conn:
                conn.settimeout(10)
                data = conn.recv(4096)
                self.received = data
                conn.sendall(data)
        except Exception as e:  # noqa: BLE001 - 冒烟脚本记录原始异常
            self.error = repr(e)
    def close(self):
        try: self.srv.close()
        except OSError: pass

def parse_uuid(text):
    return uuid.UUID(text).bytes

def vless_header(uuid_hex, port, payload):
    h = bytearray([0x00])
    h += parse_uuid(uuid_hex)
    h += bytes([0x00])           # addon_len = 0（flow=""）
    h += bytes([0x01])           # command = TCP
    h += port.to_bytes(2, "big")
    h += bytes([0x01, 127, 0, 0, 1])  # addr_type=Ipv4 + 目标
    h += payload
    return bytes(h)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xray-bin", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--uuid", required=True)
    ap.add_argument("--port", type=int, default=26108)
    ap.add_argument("--target-port", type=int, default=26200)
    ap.add_argument("--out", required=True)
    ap.add_argument("--wait-seconds", type=float, default=10.0)
    a = ap.parse_args()

    started = time.time()
    result = {"script": "xray-smoke.py", "ref_implementation": "xray",
              "config": a.config, "port": a.port, "target_port": a.target_port,
              "checks": {}, "ok": False}
    result["config_sha256"] = hashlib.sha256(open(a.config, "rb").read()).hexdigest()
    for p in (a.port, a.target_port):
        if not is_free(p):
            result["error"] = "port %d already in use" % p
            json.dump(result, open(a.out, "w"), indent=2); print(json.dumps(result)); return 2

    echo = Echo(a.target_port); echo.start()
    proc = subprocess.Popen([a.xray_bin, "run", "-c", a.config],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.time() + a.wait_seconds
        up = False
        while time.time() < deadline and proc.poll() is None:
            if not is_free(a.port):
                up = True; break
            time.sleep(0.05)
        result["checks"]["xray_listening"] = up
        if not up:
            result["error"] = "xray did not listen"
            return 2
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", a.port), timeout=10)
        tls = ctx.wrap_socket(raw, server_hostname="localhost")
        tls.settimeout(10)
        payload = b"X"
        tls.sendall(vless_header(a.uuid, a.target_port, payload))
        head = b""
        while len(head) < 2:
            chunk = tls.recv(2 - len(head))
            if not chunk: break
            head += chunk
        result["checks"]["response_header"] = list(head)
        addon_len = head[1] if len(head) == 2 else -1
        addon = b""
        while addon_len > 0 and len(addon) < addon_len:
            chunk = tls.recv(addon_len - len(addon))
            if not chunk: break
            addon += chunk
        echoed = b""
        while len(echoed) < len(payload):
            chunk = tls.recv(len(payload) - len(echoed))
            if not chunk: break
            echoed += chunk
        result["checks"]["echo"] = echoed.decode("latin1")
        result["checks"]["version_ok"] = len(head) == 2 and head[0] == 0x00
        result["checks"]["echo_ok"] = echoed == payload
        echo_join_deadline = time.time() + 5
        while echo.received is None and echo.error is None and time.time() < echo_join_deadline:
            time.sleep(0.02)
        result["checks"]["target_received"] = (echo.received == payload)
        result["ok"] = all(bool(result["checks"].get(k)) for k in
                           ("xray_listening", "version_ok", "echo_ok", "target_received"))
    except Exception as e:  # noqa: BLE001 - 冒烟脚本必须留原始失败
        result["error"] = repr(e)
    finally:
        try: tls.close()
        except Exception: pass
        proc.terminate()
        try: proc.wait(timeout=5)
        except subprocess.TimeoutExpired: proc.kill()
        echo.close()
        result["xray_log_tail"] = (proc.stdout.read() if proc.stdout else "")[-2000:]
        result["duration_ms"] = int((time.time() - started) * 1000)
        json.dump(result, open(a.out, "w"), indent=2)
        print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1

if __name__ == "__main__":
    sys.exit(main())

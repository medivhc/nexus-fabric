#!/usr/bin/env bash
# E4: 真实 TUN + sing-box 1.13.16 参照端的 VLESS / AnyTLS / Shadowsocks 出站真流量验证。
#
# 用法: tun_outbound_ref_flow.sh <vless|anytls|shadowsocks>
# 输出: 单行 JSON（stdout；诊断全部走 stderr）。
#
# 拓扑（单个新网络命名空间内）:
#   client netns 10.200.0.2 --veth--> 10.200.0.1 (root) --route--> tun (10.66.0.1/24)
#   tun 由被测进程 (`nexusd --example tun_outbound_flow`) 创建并驱动 dataplane；
#   出站 proxy.yaml 指向 127.0.0.1:<ref-port> 上的 sing-box 参照端；
#   参照端 direct 出站连接 10.99.0.2:18080，经 OUTPUT DNAT 落到本机 echo 服务
#   （目标侧只看到参照端出口，不直连）。
#
# 权限: 创建 TUN 需要 CAP_NET_ADMIN。非 root 时用特权容器 chroot 到宿主根
# （不需要 root 密码），这是本仓库既有的真机/沙箱 TUN 能力路径。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KIND="${1:-}"
case "$KIND" in
  vless|anytls|shadowsocks) ;;
  *)
    echo "usage: $0 <vless|anytls|shadowsocks>" >&2
    exit 2
    ;;
esac

SINGBOX_BIN="${SINGBOX_BIN:-/work/interop-run/protocol-interop-verification/ref/sing-box-1.13.16-linux-amd64-musl/sing-box}"
export SINGBOX_BIN

json_fail() {
  printf '{"verdict":"FAIL","error":"%s"}\n' "$1"
  exit 1
}

# ---------------------------------------------------------------- 非 root：升权重放
if [ "$(id -u)" -ne 0 ]; then
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
  cargo build -q -p nexusd --example tun_outbound_flow >&2 || json_fail "build tun_outbound_flow"
  E4_BIN="$CARGO_TARGET_DIR/debug/examples/tun_outbound_flow"
  [ -x "$E4_BIN" ] || json_fail "missing example binary"
  [ -x "$SINGBOX_BIN" ] || json_fail "missing sing-box 1.13.16 reference binary"
  command -v docker >/dev/null 2>&1 || json_fail "no TUN capability and no docker fallback"
  IMAGE="${E4_CONTAINER_IMAGE:-postgres:16-alpine}"
  docker image inspect "$IMAGE" >/dev/null 2>&1 || json_fail "container image $IMAGE unavailable"
  exec docker run --rm --privileged --network none \
    -e E4_BIN="$E4_BIN" -e SINGBOX_BIN="$SINGBOX_BIN" -e E4_KEEP="${E4_KEEP:-0}" \
    -e E4_DEBUG="${E4_DEBUG:-0}" \
    -v /:/host "$IMAGE" \
    chroot /host /bin/bash "$ROOT/scripts/e4/tun_outbound_ref_flow.sh" "$KIND"
fi

# ---------------------------------------------------------------- root：真实执行
BIN="${E4_BIN:-}"
[ -x "$BIN" ] || json_fail "missing E4_BIN (example binary)"
[ -x "$SINGBOX_BIN" ] || json_fail "missing sing-box reference binary"
SINGBOX_SHA="$(sha256sum "$SINGBOX_BIN" | cut -d' ' -f1)"
SINGBOX_SHA_EXPECTED="8da901e7b6eb0d2f6f6e701f19d5f78af235d038ae078b37a70739db5895d262"
[ "$SINGBOX_SHA" = "$SINGBOX_SHA_EXPECTED" ] || \
  json_fail "sing-box sha256 mismatch (spec §10.2)"
SINGBOX_VERSION="$("$SINGBOX_BIN" version | head -n1 | awk '{print $3}')"

WORK="$(mktemp -d "/tmp/nexus-e4-${KIND}.XXXXXX")"
NETNS="e4${KIND}x"        # <= 15 chars
VETH="e4v${KIND:0:6}"
TUN_ADDR="10.66.0.1"
CLIENT_ADDR="10.200.0.2"
ROOT_ADDR="10.200.0.1"
TARGET_ADDR="10.99.0.2"
TARGET_PORT=18080
case "$KIND" in
  vless) REF_PORT=18443 ;;
  anytls) REF_PORT=18444 ;;
  shadowsocks) REF_PORT=18445 ;;
esac

PIDS=()
cleanup() {
  rc=$?
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -INT "$pid" 2>/dev/null || true
  done
  sleep 0.3
  iptables -t nat -D OUTPUT -p tcp -d "$TARGET_ADDR" --dport "$TARGET_PORT" \
    -j DNAT --to-destination "127.0.0.1:${TARGET_PORT}" 2>/dev/null || true
  ip netns del "$NETNS" 2>/dev/null || true
  ip link del "$VETH" 2>/dev/null || true
  [ "${E4_KEEP:-0}" = 1 ] || rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

ip link set lo up

if [ "${E4_DEBUG:-0}" = 1 ]; then
  tcpdump -l -n -i lo >"$WORK/tcpdump-lo.log" 2>&1 &
  PIDS+=($!)
fi

# 目标回显服务（目标侧；只被参照端出口访问）
cat > "$WORK/echo_server.py" <<'PY'
import http.server, socketserver, sys

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        sys.stderr.write("[e4-target] " + (args[0] % args[1:]) + "\n")

with socketserver.ThreadingTCPServer(("127.0.0.1", 18080), Handler) as server:
    server.daemon_threads = True
    server.serve_forever()
PY

# 客户端（client netns）：固定 POST body，比较请求/响应 sha256。
cat > "$WORK/client.py" <<'PY'
import hashlib, json, socket, sys

body = bytes((i * 31 + 7) % 251 for i in range(4096))
request = (
    "POST /echo HTTP/1.1\r\n"
    "Host: 10.99.0.2\r\n"
    "Content-Type: application/octet-stream\r\n"
    f"Content-Length: {len(body)}\r\n"
    "Connection: close\r\n\r\n"
).encode() + body

sock = socket.create_connection(("10.99.0.2", 18080), timeout=20)
sock.sendall(request)
chunks = []
while True:
    chunk = sock.recv(65536)
    if not chunk:
        break
    chunks.append(chunk)
sock.close()
response = b"".join(chunks)
head, _, payload = response.partition(b"\r\n\r\n")
status = 0
if head.startswith(b"HTTP/1."):
    status = int(head.split(b" ")[1])
json.dump(
    {
        "client.status": status,
        "client.request_sha256": hashlib.sha256(body).hexdigest(),
        "client.response_sha256": hashlib.sha256(payload).hexdigest(),
        "client.request_length": len(body),
        "client.response_length": len(payload),
        "client.sha_match": hashlib.sha256(body).hexdigest()
        == hashlib.sha256(payload).hexdigest(),
    },
    sys.stdout,
)
PY

python3 "$WORK/echo_server.py" >"$WORK/target.log" 2>&1 &
PIDS+=($!)

# sing-box 参照端（TLS 自签，仅本机回环）。
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
  -days 2 -nodes -subj "/CN=127.0.0.1" >/dev/null 2>&1

case "$KIND" in
  vless)
    INBOUND=$(cat <<JSON
{"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":${REF_PORT},
 "users":[{"uuid":"11111111-1111-1111-1111-111111111111"}],
 "tls":{"enabled":true,"server_name":"127.0.0.1",
        "certificate_path":"$WORK/cert.pem","key_path":"$WORK/key.pem"}}
JSON
)
    ;;
  anytls)
    INBOUND=$(cat <<JSON
{"type":"anytls","tag":"anytls-in","listen":"127.0.0.1","listen_port":${REF_PORT},
 "users":[{"password":"e4-password"}],
 "tls":{"enabled":true,"server_name":"127.0.0.1",
        "certificate_path":"$WORK/cert.pem","key_path":"$WORK/key.pem"}}
JSON
)
    ;;
  shadowsocks)
    # SIP004 AEAD（chacha20-ietf-poly1305）；无 TLS 外壳。
    INBOUND=$(cat <<JSON
{"type":"shadowsocks","tag":"ss-in","listen":"127.0.0.1","listen_port":${REF_PORT},
 "method":"chacha20-ietf-poly1305","password":"e4-password"}
JSON
)
    ;;
esac
cat > "$WORK/sing-box.json" <<JSON
{"log":{"level":"info","timestamp":true},
 "inbounds":[${INBOUND}],
 "outbounds":[{"type":"direct","tag":"direct"}]}
JSON

"$SINGBOX_BIN" run -c "$WORK/sing-box.json" >"$WORK/sing-box.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 100); do
  if (echo >/dev/tcp/127.0.0.1/"$REF_PORT") 2>/dev/null; then break; fi
  sleep 0.1
done
(echo >/dev/tcp/127.0.0.1/"$REF_PORT") 2>/dev/null || json_fail "sing-box reference did not listen"

# 参照端出口 → 本机目标服务（只影响本命名空间内自发的出站连接）。
iptables -t nat -A OUTPUT -p tcp -d "$TARGET_ADDR" --dport "$TARGET_PORT" \
  -j DNAT --to-destination "127.0.0.1:${TARGET_PORT}"

# 客户端命名空间 + veth。
ip netns add "$NETNS"
ip link add "$VETH" type veth peer name "${VETH}c"
ip link set "${VETH}c" netns "$NETNS"
ip addr add "${ROOT_ADDR}/24" dev "$VETH"
ip link set "$VETH" up
ip netns exec "$NETNS" ip addr add "${CLIENT_ADDR}/24" dev "${VETH}c"
ip netns exec "$NETNS" ip link set "${VETH}c" up
ip netns exec "$NETNS" ip link set lo up
ip netns exec "$NETNS" ip route add default via "$ROOT_ADDR"
sysctl -qw net.ipv4.ip_forward=1

# proxy.yaml（生产配置面）。
case "$KIND" in
  vless)
    cat > "$WORK/proxy.yaml" <<YAML
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: proxy
outbounds:
  - tag: proxy
    kind: vless
    locator: 127.0.0.1:${REF_PORT}
    uuid: 11111111-1111-1111-1111-111111111111
    tls: true
    skip_cert_verify: true
YAML
    ;;
  anytls)
    cat > "$WORK/proxy.yaml" <<YAML
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: proxy
outbounds:
  - tag: proxy
    kind: anytls
    locator: 127.0.0.1:${REF_PORT}
    password: e4-password
    skip_cert_verify: true
YAML
    ;;
  shadowsocks)
    cat > "$WORK/proxy.yaml" <<YAML
schema_version: 1
rules:
  - tag: r1
    kind: match
    action:
      - kind: select_outbound
        tag: proxy
outbounds:
  - tag: proxy
    kind: shadowsocks
    locator: 127.0.0.1:${REF_PORT}
    method: chacha20-ietf-poly1305
    password: e4-password
YAML
    ;;
esac

"$BIN" --kind "$KIND" --proxy-yaml "$WORK/proxy.yaml" \
  --tun-name "nx${KIND:0:4}" --status-file "$WORK/status.json" \
  --done-file "$WORK/done" --timeout-secs 60 --json \
  >"$WORK/example.json" 2>"$WORK/example.err" &
EXAMPLE_PID=$!
PIDS+=("$EXAMPLE_PID")

for _ in $(seq 1 100); do
  [ -s "$WORK/status.json" ] && break
  sleep 0.1
done
[ -s "$WORK/status.json" ] || {
  echo "--- example stderr ---" >&2
  tail -n 20 "$WORK/example.err" >&2 || true
  json_fail "TUN not created (see example stderr)"
}
TUN_NAME="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["tun"])' "$WORK/status.json")"

ip addr add "${TUN_ADDR}/24" dev "$TUN_NAME"
ip link set "$TUN_NAME" up
ip route add "${TARGET_ADDR}/32" dev "$TUN_NAME"
[ -n "$(ip route show "${TARGET_ADDR}/32")" ] || json_fail "route via TUN missing"

if [ "${E4_DEBUG:-0}" = 1 ]; then
  tcpdump -l -n -i "$TUN_NAME" >"$WORK/tcpdump-tun.log" 2>&1 &
  PIDS+=($!)
  tcpdump -l -n -i "$VETH" >"$WORK/tcpdump-veth.log" 2>&1 &
  PIDS+=($!)
fi

# 真实客户端流量（client netns → TUN → nexusd → sing-box 参照端 → 目标）。
if ! ip netns exec "$NETNS" python3 "$WORK/client.py" >"$WORK/client.json" 2>"$WORK/client.err"; then
  touch "$WORK/done"
  wait "$EXAMPLE_PID" 2>/dev/null || true
  json_fail "client request failed: $(tail -n 3 "$WORK/client.err" 2>/dev/null | tr '\n' ' ')"
fi
touch "$WORK/done"
wait "$EXAMPLE_PID" 2>/dev/null || true

if [ "${E4_DEBUG:-0}" = 1 ]; then
  {
    echo "=== ip -s link ==="
    ip -s link show
    echo "=== ip route ==="
    ip route show table all
    echo "=== netstat drops ==="
    nstat -az 2>/dev/null | grep -Ei 'drop|filter|overflow|error' || true
    echo "=== client netns ==="
    ip netns exec "$NETNS" ip -s link show
  } >"$WORK/ip-debug.log" 2>&1
fi

[ -s "$WORK/example.json" ] || json_fail "example produced no JSON"
REF_SEEN=false
if grep -q "${TARGET_ADDR}:${TARGET_PORT}" "$WORK/sing-box.log"; then
  REF_SEEN=true
fi

# AC-3 字面证据：生产选路日志中的 `kind=shadowsocks source=crate`
# （`adapter::legacy::ShadowsocksCrateDialer::new` 输出到 stderr）。
SOURCE_CRATE=false
if grep -q "kind=shadowsocks source=crate" "$WORK/example.err"; then
  SOURCE_CRATE=true
fi

python3 - "$WORK/example.json" "$WORK/client.json" "$KIND" "$REF_SEEN" \
  "$SINGBOX_SHA" "$SINGBOX_VERSION" "$SOURCE_CRATE" <<'PY'
import json, sys

example = json.load(open(sys.argv[1]))
client = json.load(open(sys.argv[2]))
kind = sys.argv[3]
ref_seen = sys.argv[4] == "true"
ref_sha = sys.argv[5]
ref_version = sys.argv[6]
source_crate = sys.argv[7] == "true"

out = dict(example)
out.update(client)
out["ref.target_seen"] = ref_seen
out["ref.sha256"] = ref_sha
out["ref.version"] = ref_version
out["no_direct"] = (
    example.get("stats.direct_forwarded") == 0 and ref_seen
)
out["tcp_dials_ok.positive"] = example.get("stats.proxy_forwarded", 0) > 0
out["log.source_crate"] = source_crate
ok = (
    example.get("verdict") == "PASS"
    and example.get("outbound.kind") == kind
    and example.get("outbound.tag") == "proxy"
    and example.get("stats.proxy_forwarded", 0) > 0
    and example.get("stats.proxy_tcp_bytes", 0) > 0
    and example.get("tun.created") is True
    and client.get("client.status") == 200
    and client.get("client.sha_match") is True
    and client.get("client.response_length", 0) > 0
    and ref_version == "1.13.16"
    and out["no_direct"] is True
    and (kind != "shadowsocks" or source_crate)
)
out["verdict"] = "PASS" if ok else "FAIL"
print(json.dumps(out))
PY

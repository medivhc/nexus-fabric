#!/usr/bin/env bash
# 参照端起停（S06 / O-01 / O-02 / O-03）：sing-box 与 Xray 串行，flock 互斥。
# 用法：ref.sh start_ref <variant> [--impl sing-box|xray] ; ref.sh stop_ref [variant]
set -euo pipefail

_REF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ports.sh
. "$_REF_DIR/ports.sh"

: "${RUN_DIR:?RUN_DIR required}"
REF_ROOT="${RUN_DIR}/ref"
SINGBOX_BIN="${SINGBOX_BIN:-$REF_ROOT/sing-box-1.13.16-linux-amd64-musl/sing-box}"
XRAY_BIN="${XRAY_BIN:-$REF_ROOT/xray}"
REF_LOCK="${RUN_DIR}/locks/ref.lock"
STATE_DIR="${RUN_DIR}/evidence/ref"

_ref_bin_for() {
  case "$1" in
    sing-box) echo "$SINGBOX_BIN" ;;
    xray) echo "$XRAY_BIN" ;;
    *) echo "unknown impl $1" >&2; return 1 ;;
  esac
}

_ref_config_port() {
  python3 - "$1" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
if "inbounds" in c:
    ib=c["inbounds"][0]
    port=ib.get("listen_port") or ib.get("port")
else:
    port=c.get("listen_port") or c.get("port")
if not port:
    raise SystemExit("no port in config")
print(port)
PY
}

_ref_pgrep_clean() {
  pgrep -af 'sing-box|xray' || true
}

start_ref() {
  local variant="${1:?variant required}"; shift || true
  local impl="sing-box"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --impl) impl="${2:?}"; shift 2 ;;
      *) echo "unknown arg $1" >&2; return 2 ;;
    esac
  done
  local cfg="$RUN_DIR/evidence/ref-config/$variant.json"
  [[ -f "$cfg" ]] || { echo "missing config $cfg" >&2; return 1; }
  local bin; bin="$(_ref_bin_for "$impl")"
  [[ -x "$bin" ]] || { echo "missing binary $bin" >&2; return 1; }
  local port; port="$(_ref_config_port "$cfg")"
  local state="$STATE_DIR/$variant"
  mkdir -p "$state"

  ports_snapshot "pre-start-$variant" >/dev/null
  ports_assert_free "$port" || {
    echo "port $port busy; refusing to start $variant" >&2
    return 1
  }
  if [[ -f "$state/pid" ]] && kill -0 "$(cat "$state/pid")" 2>/dev/null; then
    echo "ref $variant already running pid=$(cat "$state/pid")" >&2
    return 1
  fi

  case "$impl" in
    sing-box)
      "$bin" check -c "$cfg" > "$state/check.txt" 2>&1 || { echo "sing-box check failed" >&2; return 1; }
      ;;
    xray)
      "$bin" run -test -c "$cfg" > "$state/check.txt" 2>&1 || { echo "xray run -test failed" >&2; return 1; }
      ;;
  esac

  {
    echo "impl=$impl"
    echo "variant=$variant"
    echo "config=$cfg"
    echo "config_sha256=$(sha256sum "$cfg" | awk '{print $1}')"
    echo "binary=$bin"
    echo "binary_sha256=$(sha256sum "$bin" | awk '{print $1}')"
    echo "port=$port"
    echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$state/start.txt"

  # setsid + flock：参照进程与锁同生共死；pid 即进程组组长。
  setsid flock -n "$REF_LOCK" "$bin" run -c "$cfg" > "$state/stdout.log" 2>>"$state/stderr.log" &
  local pid=$!
  echo "$pid" > "$state/pid"
  local deadline=$((SECONDS + 5))
  while (( SECONDS < deadline )); do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "ref $variant exited early" >&2
      tail -20 "$state/stdout.log" "$state/stderr.log" 2>/dev/null | sed 's/^/  /' >&2 || true
      rm -f "$state/pid"
      return 1
    fi
    if ports_in_use "$port"; then break; fi
    sleep 0.1
  done
  ss -ltnup 2>/dev/null | grep -E ":$port\b" > "$state/listen.txt" || true
  if ! ports_in_use "$port"; then
    echo "ref $variant did not listen on $port within 5s" >&2
    tail -20 "$state/stdout.log" 2>/dev/null | sed 's/^/  /' >&2 || true
    stop_ref "$variant" >/dev/null 2>&1 || true
    return 1
  fi
  echo "started $variant impl=$impl pid=$pid port=$port"
}

stop_ref() {
  local variant="${1:-}"
  local state="${STATE_DIR}/${variant:-}"
  if [[ -z "$variant" || ! -f "$state/pid" ]]; then
    # 无指定：清理所有登记的 ref pid
    local f
    for f in "$STATE_DIR"/*/pid; do
      [[ -f "$f" ]] || continue
      local v; v="$(basename "$(dirname "$f")")"
      stop_ref "$v" || true
    done
    return 0
  fi
  local pid; pid="$(cat "$state/pid")"
  local port=""; [[ -f "$state/start.txt" ]] && port="$(sed -n 's/^port=//p' "$state/start.txt")"
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    local i
    for i in $(seq 1 50); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
      sleep 0.2
    fi
  fi
  {
    echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "pid=$pid"
    echo "alive_after=$(kill -0 "$pid" 2>/dev/null && echo yes || echo no)"
    if [[ -n "$port" ]]; then ports_in_use "$port" && echo "port_in_use=yes" || echo "port_in_use=no"; fi
    echo "pgrep=$(pgrep -af 'sing-box|xray' | tr '\n' ';' || true)"
  } > "$state/stop.txt"
  rm -f "$state/pid"
  echo "stopped $variant"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  cmd="${1:-}"; shift || true
  case "$cmd" in
    start_ref) start_ref "$@" ;;
    stop_ref) stop_ref "$@" ;;
    *) echo "usage: $0 {start_ref|stop_ref} ..." >&2; exit 2 ;;
  esac
fi

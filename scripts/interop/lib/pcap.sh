#!/usr/bin/env bash
# dumpcap 启停与校验（D-5/D-16）：pcap 格式固定 -P；T2 用 filesize 封顶。
set -euo pipefail

pcap_start() {
  local iface="$1" bpf="$2" out="$3" max_kb="${4:-0}"
  mkdir -p "$(dirname "$out")"
  local args=(-q -i "$iface" -P -f "$bpf" -w "$out")
  if [[ "$max_kb" -gt 0 ]]; then
    args+=(-a "filesize:${max_kb}")
  fi
  setsid dumpcap "${args[@]}" > "${out}.dumpcap.log" 2>&1 &
  echo $! > "${out}.pid"
  local i
  for i in $(seq 1 30); do
    [[ -s "$out" ]] && break
    kill -0 "$(cat "${out}.pid")" 2>/dev/null || {
      echo "dumpcap exited early" >&2
      tail -5 "${out}.dumpcap.log" >&2 || true
      return 1
    }
    sleep 0.1
  done
  echo "dumpcap pid=$(cat "${out}.pid") out=$out"
}

pcap_stop() {
  local out="$1" stats="$2"
  local pidfile="${out}.pid"
  if [[ -f "$pidfile" ]]; then
    local pid; pid="$(cat "$pidfile")"
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      local i
      for i in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  fi
  {
    echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [[ -s "$out" ]]; then
      echo "packets=$(capinfos -c -M "$out" 2>/dev/null | awk -F': *' '/Number of packets/{print $2}')"
      echo "size_bytes=$(stat -c %s "$out")"
      echo "capinfos_ok=$(capinfos "$out" >/dev/null 2>&1 && echo yes || echo no)"
      echo "first_packet=$(tshark -r "$out" -c 1 -T fields -e frame.number 2>/dev/null | head -1)"
      echo "sha256=$(sha256sum "$out" | awk '{print $1}')"
    else
      echo "packets=0"
      echo "size_bytes=0"
      echo "capinfos_ok=no"
      echo "sha256="
    fi
    echo "dumpcap_log_tail:"
    tail -3 "${out}.dumpcap.log" 2>/dev/null || true
  } > "$stats"
  echo "pcap stats -> $stats"
}

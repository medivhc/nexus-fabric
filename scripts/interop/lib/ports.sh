#!/usr/bin/env bash
# 端口登记与快照（O-03 / F3）。所有函数要求 RUN_DIR 已设置。
set -euo pipefail

PIV_PORT_MIN="${PIV_PORT_MIN:-26100}"
PIV_PORT_MAX="${PIV_PORT_MAX:-26299}"

ports_snapshot() {
  local tag="${1:?tag required}"
  local dir="${RUN_DIR:?RUN_DIR required}/evidence/ports"
  mkdir -p "$dir"
  local stamp; stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local out="$dir/${stamp}-${tag}.txt"
  {
    echo "# ports snapshot tag=$tag utc=$stamp"
    echo "## listeners 26100-26299"
    ss -ltnup 2>/dev/null | grep -E ":26[12][0-9]{2}\b" || echo "(none)"
    echo "## listeners all (tcp+udp)"
    ss -ltnup 2>/dev/null || true
  } > "$out"
  echo "$out"
}

ports_in_use() {
  local port="$1"
  ss -ltnu 2>/dev/null | awk -v p=":$port" '{for(i=1;i<=NF;i++) if($i ~ p"$") found=1} END {exit found?0:1}'
}

ports_assert_free() {
  local port="${1:?port required}"
  if ports_in_use "$port"; then
    echo "port $port is already in use" >&2
    return 1
  fi
  return 0
}

ports_registry_update() {
  local original="$1" replacement="$2" reason="$3"
  local dir="${RUN_DIR:?RUN_DIR required}/evidence/ports"
  mkdir -p "$dir"
  local reg="$dir/registry.md"
  [[ -f "$reg" ]] || {
    printf '# port registry (run: protocol-interop-verification)\n\n| utc | original | replacement | reason |\n|---|---|---|---|\n' > "$reg"
  }
  printf '| %s | %s | %s | %s |\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$original" "$replacement" "$reason" >> "$reg"
}

ports_choose_free() {
  local preferred="${1:?preferred required}"
  local lo="${2:-$PIV_PORT_MIN}" hi="${3:-$PIV_PORT_MAX}"
  local p
  if ports_assert_free "$preferred" 2>/dev/null; then echo "$preferred"; return 0; fi
  for p in $(seq "$lo" "$hi"); do
    if ports_assert_free "$p" 2>/dev/null; then
      echo "$p" >&2
      ports_registry_update "$preferred" "$p" "preferred port busy at runtime"
      echo "$p"; return 0
    fi
  done
  echo "no free port in $lo-$hi" >&2
  return 1
}

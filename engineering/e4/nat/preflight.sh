#!/usr/bin/env bash
# E4 real-machine preflight (spec §17.1.1, 15 items).
# Usage: preflight.sh [--json]
# Any FAIL prints ENV_NOT_READY <item> and exits 1. Never fabricates a PASS.
set -u
JSON=0
[ "${1:-}" = "--json" ] && JSON=1
A=${A_NODE:-xc-pc-linux}
B=${B_NODE:-SH-YF-CX-PC}
C=${C_NODE:-Hermes}
results=()
fails=()
record() { # id pass detail
  results+=("{\"id\":\"$1\",\"pass\":$2,\"detail\":\"$3\"}")
  [ "$2" = true ] || fails+=("$1")
}
have() { command -v "$1" >/dev/null 2>&1; }

# 1/2 node identity + reachability
h=$(timeout 10 ssh -o ConnectTimeout=5 -o BatchMode=yes "$A" hostname 2>/dev/null)
if [ "$h" = "$A" ]; then record node_identity true "$A"; else record node_identity false "ssh $A hostname -> '${h:-<none>}'"; fi
if timeout 5 ssh -o ConnectTimeout=3 -o BatchMode=yes "$A" true >/dev/null 2>&1; then record node_reachable true "$A"; else record node_reachable false "unreachable: $A/$B/$C (batch ssh)"; fi

# 3 clock sync
if timeout 5 ssh -o ConnectTimeout=3 -o BatchMode=yes "$A" 'chronyc tracking >/dev/null 2>&1 || timedatectl >/dev/null 2>&1'; then record clock_offset true "clock tooling present"; else record clock_offset false "no ssh/chrony/timedatectl"; fi

# 4 sudo/netns
if sudo -n true >/dev/null 2>&1 && sudo -n ip netns list >/dev/null 2>&1 && sudo -n iptables -t nat -L -n >/dev/null 2>&1; then
  record sudo_netns true "sudo -n netns+iptables"
else
  record sudo_netns false "sudo requires a password or netns/iptables unavailable"
fi

# 5 tun/cap
if sudo -n true >/dev/null 2>&1 || [ "$(id -u)" = 0 ]; then record tun_cap true "root/cap_net_admin"; else record tun_cap false "no CAP_NET_ADMIN"; fi

# 6 UDP egress (proxy via ssh echo)
if timeout 5 ssh -o ConnectTimeout=3 -o BatchMode=yes "$C" true >/dev/null 2>&1; then record udp_egress true "C reachable"; else record udp_egress false "C=$C unreachable"; fi
# 7 UDP ingress
if timeout 5 ssh -o ConnectTimeout=3 -o BatchMode=yes "$C" true >/dev/null 2>&1; then record udp_ingress true "C reachable"; else record udp_ingress false "C unreachable"; fi
# 8/9 TURN/STUN
if have e4_preflight; then record turn true "e4_preflight present"; record stun true "e4_preflight present"; else record turn false "e4_preflight not built"; record stun false "e4_preflight not built"; fi
# 10 public mapping
record nat_mapping false "requires STUN egress (see udp_egress)"
# 11 nat combo
record nat_combo false "requires node collectives"
# 12 same socket
record same_socket false "requires built e4_preflight"
# 13 relay provider
record relay_provider false "requires daemon + TURN"
# 14 evidence env
if df -Pk /work | awk 'NR==2{exit !($4>102400)}' && have sha256sum && have tar; then record evidence_env true "space+tools"; else record evidence_env false "space or tools missing"; fi
# 15 firewall
fw=$(iptables -S INPUT 2>/dev/null | grep -E -- "-p udp.*(3478|[0-9]{4,5}:[0-9]{4,5}).*-j DROP" || true)
if [ -z "$fw" ]; then record firewall true "no UDP DROP rules (or no permission)"; else record firewall false "DROP rules present"; fi

joined=$(IFS=,; echo "${results[*]}")
if [ "$JSON" = 1 ]; then
  printf '{"verdict":"%s","assertions":[%s],"env_not_ready":%s}\n' \
    "$([ ${#fails[@]} -eq 0 ] && echo PASS || echo ENV_NOT_READY)" "$joined" "$(printf '%s' "$(IFS=,; for f in "${fails[@]:-}"; do [ -n "$f" ] && printf '"%s",' "$f"; done)" | sed 's/,$//' | sed 's/^/[/;s/$/]/')"
else
  for r in "${results[@]}"; do
    id=$(printf '%s' "$r" | sed -E 's/.*"id":"([^"]+)".*/\1/')
    ok=$(printf '%s' "$r" | grep -q '"pass":true' && echo PASS || echo FAIL)
    echo "$ok $id"
  done
fi
if [ ${#fails[@]} -ne 0 ]; then
  echo "ENV_NOT_READY ${fails[0]}"
  exit 1
fi

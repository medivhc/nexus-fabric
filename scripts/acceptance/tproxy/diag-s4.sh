#!/usr/bin/env bash
# E5 S4 (S62) 补充旁证：TUN 前端 Direct/Proxy 两流的 client-netns tcpdump。
#
# 断言：
#   1. 两流 SYN-ACK 源地址 == orig_dst（Direct 10.200.2.2:8080，Proxy 10.200.2.9:8080）；
#   2. 两流都出现完整 GET 与站点 200 响应（P7/请求方向）；
#   3. 记录 GET 到 200 的间隔，作为 P8（静默期回程送达）的旁证。
#
# 用法：
#   bash scripts/acceptance/tproxy/diag-s4.sh --run-id <id> --evidence <abs-dir>
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=netns-lib.sh
source "${HERE}/netns-lib.sh"

RUN_ID=""
EVIDENCE_ARG=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --run-id) RUN_ID="${2:-}"; shift 2 ;;
        --evidence) EVIDENCE_ARG="${2:-}"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "${RUN_ID}" ] || { echo "--run-id required" >&2; exit 2; }
[ -n "${EVIDENCE_ARG}" ] || { echo "--evidence required" >&2; exit 2; }

rm -rf "${EVIDENCE_ARG}"
mkdir -p "${EVIDENCE_ARG}"
init_step 44 "${RUN_ID}" "${EVIDENCE_ARG}"
trap on_exit EXIT INT TERM

wait_os_state() {
    local want="$1" tries="${2:-100}" i state poll="${EVIDENCE_DIR}/status.os.json"
    for i in $(seq 1 "${tries}"); do
        stats_json "${poll}" >/dev/null 2>&1 || true
        state="$(stats_value "${poll}" '.dataplane.os_assemble.state')"
        [ "${state}" = "${want}" ] && return 0
        sleep 0.1
    done
    return 1
}

# client netns 内起 tcpdump（覆盖 Direct + Proxy 两流；不按 host 收窄）。
DIAG_TCPDUMP_PID=""
start_client_tcpdump() {
    local out="$1"
    : >"${out}"
    timeout 40 sudo -n "${IP}" netns exec "${NS_C}" \
        tcpdump -i any -nn -l 'tcp port 8080' >"${out}" 2>&1 &
    DIAG_TCPDUMP_PID=$!
    sleep 0.5
}

stop_client_tcpdump() {
    local pid="${DIAG_TCPDUMP_PID}" i
    [ -n "${pid}" ] || return 0
    if ps -p "${pid}" >/dev/null 2>&1; then
        timeout 10 sudo -n "${IP}" netns exec "${NS_C}" kill -TERM "${pid}" >/dev/null 2>&1 || true
        for i in $(seq 1 30); do
            ps -p "${pid}" >/dev/null 2>&1 || break
            sleep 0.1
        done
        ps -p "${pid}" >/dev/null 2>&1 && \
            timeout 10 sudo -n "${IP}" netns exec "${NS_C}" kill -KILL "${pid}" >/dev/null 2>&1 || true
        wait "${pid}" 2>/dev/null || true
    fi
    DIAG_TCPDUMP_PID=""
}

finalize_diag() {
    stop_client_tcpdump
    stop_nexusd
    stop_upstream
    cleanup_netns
    snapshot_host "${EVIDENCE_DIR}/after-host.txt"
    cleanup_host_alias
    ORDERLY_DONE=1
    if diff -u "${EVIDENCE_DIR}/before-host.txt" "${EVIDENCE_DIR}/after-host.txt" \
        >"${EVIDENCE_DIR}/host-diff.txt" 2>&1; then
        record "PASS host_diff_empty"
    else
        record "FAIL host_diff_nonempty see host-diff.txt"
        STEP_FAILED=1
    fi
    assert_no_run_netns
}

if ! setup_host_alias; then
    STEP_FAILED=1
    exit 1
fi
snapshot_host "${EVIDENCE_DIR}/before-host.txt"
if ! setup_topology; then
    STEP_FAILED=1
    finalize_diag
    exit 1
fi
: >"${EVIDENCE_DIR}/socks5.log"
: >"${EVIDENCE_DIR}/upstream.log"

cfg="${EVIDENCE_DIR}/config"
mkdir -p "$cfg"
write_daemon_toml "$cfg" true auto false
write_tun_yaml "$cfg" iptables

if ! start_upstream; then finalize_diag; exit 1; fi
if ! start_nexusd "$cfg" "${EVIDENCE_DIR}/nexusd.log" \
    PATH="/usr/local/sbin:/usr/local/bin:/usr/bin:/sbin:/bin"; then
    finalize_diag
    exit 1
fi
if ! wait_os_state applied 100; then
    record "FAIL os_assemble_applied timeout"
    stats_json "${EVIDENCE_DIR}/status.json" >/dev/null 2>&1 || true
    finalize_diag
    exit 1
fi
record "PASS os_assemble_applied"

stats_json "${EVIDENCE_DIR}/status.json" >/dev/null 2>&1 || true
ifname="$(stats_value "${EVIDENCE_DIR}/status.json" '.dataplane.os_assemble.ifname')"
record "diag_ifname=${ifname}"

ns_exec "${NS_R}" ip rule add from "${CLIENT_ADDR}" lookup 200 priority 100 >/dev/null 2>&1 || true
ns_exec "${NS_R}" ip route replace 10.200.2.0/24 dev "${ifname}" table 200 >/dev/null 2>&1 || true
record "diag_steer=from ${CLIENT_ADDR} lookup 200; table200=$(ns_exec "${NS_R}" ip route show table 200 2>&1 | tr '\n' ' ')"

start_client_tcpdump "${EVIDENCE_DIR}/client.txt"

# DIAG_ONLY=both|direct|proxy|none：归因实验用（默认 both，产品判据只认 both）。
DIAG_ONLY="${DIAG_ONLY:-both}"
case "${DIAG_ONLY}" in
    both) WANT_DIRECT=1; WANT_PROXY=1 ;;
    direct) WANT_DIRECT=1; WANT_PROXY=0 ;;
    proxy) WANT_DIRECT=0; WANT_PROXY=1 ;;
    none) WANT_DIRECT=0; WANT_PROXY=0 ;;
    *) echo "DIAG_ONLY must be both|direct|proxy|none" >&2; exit 2 ;;
esac
record "diag_only=${DIAG_ONLY} direct=${WANT_DIRECT} proxy=${WANT_PROXY}"

if [ "${WANT_DIRECT}" = "1" ]; then
    body="$(client_curl "http://${UPSTREAM_ADDR}:8080/" 10 2>"${EVIDENCE_DIR}/curl-direct.err")"
    rc=$?
    printf '%s\n' "$body" >"${EVIDENCE_DIR}/curl-direct.txt"
    assert_eq diag_direct_curl_exit "$rc" 0
    assert_contains diag_direct_curl_body "$body" "hello-nexus"
    sleep 0.5
    stats_json "${EVIDENCE_DIR}/status-direct.json" >/dev/null 2>&1 || true
fi

if [ "${WANT_PROXY}" = "1" ]; then
    body="$(client_curl "http://${SITE_ADDR}:8080/" 10 2>"${EVIDENCE_DIR}/curl-proxy.err")"
    rc=$?
    printf '%s\n' "$body" >"${EVIDENCE_DIR}/curl-proxy.txt"
    assert_eq diag_proxy_curl_exit "$rc" 0
    assert_contains diag_proxy_curl_body "$body" "hello-nexus"
fi

sleep 1
stats_json "${EVIDENCE_DIR}/status.json" >/dev/null 2>&1 || true
stop_client_tcpdump

cap="$(cat "${EVIDENCE_DIR}/client.txt" 2>/dev/null || true)"
# 每条流的第一个 SYN-ACK（源 IP:port > 10.200.1.2:port, Flags [S.]）。
direct_synack="$(printf '%s\n' "$cap" | grep -E '10\.200\.2\.2\.8080 > 10\.200\.1\.2\.[0-9]+: Flags \[S\.\]' | head -1 || true)"
proxy_synack="$(printf '%s\n' "$cap" | grep -E '10\.200\.2\.9\.8080 > 10\.200\.1\.2\.[0-9]+: Flags \[S\.\]' | head -1 || true)"
record "direct_synack_line=${direct_synack:-missing}"
record "proxy_synack_line=${proxy_synack:-missing}"
if [ "${WANT_DIRECT}" = "1" ]; then
    if [ -n "$direct_synack" ]; then
        record "PASS diag_direct_synack_src_is_orig_dst src=${UPSTREAM_ADDR}:8080"
    else
        record "FAIL diag_direct_synack_src_is_orig_dst missing"
        STEP_FAILED=1
    fi
fi
if [ "${WANT_PROXY}" = "1" ]; then
    if [ -n "$proxy_synack" ]; then
        record "PASS diag_proxy_synack_src_is_orig_dst src=${SITE_ADDR}:8080"
    else
        record "FAIL diag_proxy_synack_src_is_orig_dst missing"
        STEP_FAILED=1
    fi
fi

direct_req="$(printf '%s\n' "$cap" | grep -E '10\.200\.1\.2\.[0-9]+ > 10\.200\.2\.2\.8080:.*GET / HTTP' | head -1 || true)"
proxy_req="$(printf '%s\n' "$cap" | grep -E '10\.200\.1\.2\.[0-9]+ > 10\.200\.2\.9\.8080:.*GET / HTTP' | head -1 || true)"
direct_resp="$(printf '%s\n' "$cap" | grep -E '10\.200\.2\.2\.8080 > 10\.200\.1\.2\.[0-9]+:.*HTTP/1\.1 200 OK' | head -1 || true)"
proxy_resp="$(printf '%s\n' "$cap" | grep -E '10\.200\.2\.9\.8080 > 10\.200\.1\.2\.[0-9]+:.*HTTP/1\.1 200 OK' | head -1 || true)"
record "direct_request_packet=${direct_req:-missing}"
record "direct_response_packet=${direct_resp:-missing}"
record "proxy_request_packet=${proxy_req:-missing}"
record "proxy_response_packet=${proxy_resp:-missing}"
if [ "${WANT_DIRECT}" = "1" ]; then
    if [ -n "$direct_req" ] && [ -n "$direct_resp" ]; then
        record "PASS diag_direct_get_and_200_present"
    else
        record "FAIL diag_direct_get_and_200_present"
        STEP_FAILED=1
    fi
fi
if [ "${WANT_PROXY}" = "1" ]; then
    if [ -n "$proxy_req" ] && [ -n "$proxy_resp" ]; then
        record "PASS diag_proxy_get_and_200_present"
    else
        record "FAIL diag_proxy_get_and_200_present"
        STEP_FAILED=1
    fi
fi

# GET 与 200 的时差（秒，tcpdump 行首 HH:MM:SS.nnnnnn）。
ts() { printf '%s' "$1" | awk '{print $1}' | awk -F: '{printf "%.6f", $1*3600+$2*60+$3}'; }
if [ -n "$direct_req" ] && [ -n "$direct_resp" ]; then
    record "diag_direct_get_to_200_s=$(awk -v a="$(ts "$direct_req")" -v b="$(ts "$direct_resp")" 'BEGIN{printf "%.3f", b-a}')"
fi
if [ -n "$proxy_req" ] && [ -n "$proxy_resp" ]; then
    record "diag_proxy_get_to_200_s=$(awk -v a="$(ts "$proxy_req")" -v b="$(ts "$proxy_resp")" 'BEGIN{printf "%.3f", b-a}')"
fi

# 计数（每 flow 一条记录）。
record "diag_counters: direct_tcp_dial_ok=$(stats_value "${EVIDENCE_DIR}/status.json" '.dataplane.direct_tcp_dial_ok') direct_forwarded=$(stats_value "${EVIDENCE_DIR}/status.json" '.dataplane.direct_forwarded') proxy_forwarded=$(stats_value "${EVIDENCE_DIR}/status.json" '.dataplane.proxy_forwarded') proxy_tcp_streams=$(stats_value "${EVIDENCE_DIR}/status.json" '.dataplane.proxy_tcp_streams') dropped=$(stats_value "${EVIDENCE_DIR}/status.json" '.dataplane.dropped') proxy_dropped_no_proxy=$(stats_value "${EVIDENCE_DIR}/status.json" '.dataplane.proxy_dropped_no_proxy') upstream_failed=$(stats_value "${EVIDENCE_DIR}/status.json" '.dataplane.upstream_failed') proxy_dial_buffer_dropped_bytes=$(stats_value "${EVIDENCE_DIR}/status.json" '.dataplane.proxy_dial_buffer_dropped_bytes') proxy_dial_buffer_overflow_resets=$(stats_value "${EVIDENCE_DIR}/status.json" '.dataplane.proxy_dial_buffer_overflow_resets')"
record "upstream_site_log:"
while IFS= read -r line; do record "  upstream: $line"; done < <(grep -E '\[http\].*GET / HTTP/1\.1' "${EVIDENCE_DIR}/upstream.log" 2>/dev/null || true)

record "diag_done"
finalize_diag
if [ "${STEP_FAILED}" -eq 0 ]; then
    record "verdict=PASS step=S4-diag"
else
    record "verdict=FAIL step=S4-diag"
fi
exit "${STEP_FAILED}"

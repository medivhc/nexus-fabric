#!/usr/bin/env bash
# E5 netns 验收驱动（plan §8.2 S59–S68 / E5 S1–S10）。
#
# 用法：
#   bash scripts/acceptance/tproxy/run.sh s1 --run-id <id> --evidence <abs-dir>
#
# 每个子命令自成一个独立的三角色 netns 场景；宿主 before/after 快照必须一致。

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=netns-lib.sh
source "${HERE}/netns-lib.sh"

SUBCOMMAND=""
RUN_ID=""
EVIDENCE_ARG=""

usage() {
    cat <<'EOF'
usage: run.sh <s1|s2|...|s10> --run-id <id> --evidence <abs-dir>
EOF
}

parse_args() {
    [ "$#" -ge 1 ] || { usage; exit 2; }
    SUBCOMMAND="$1"
    shift
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --run-id) RUN_ID="${2:-}"; shift 2 ;;
            --evidence) EVIDENCE_ARG="${2:-}"; shift 2 ;;
            *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
        esac
    done
    [ -n "${RUN_ID}" ] || { echo "--run-id required" >&2; exit 2; }
    [ -n "${EVIDENCE_ARG}" ] || { echo "--evidence required" >&2; exit 2; }
    case "${SUBCOMMAND}" in
        s1|s2|s3|s4|s5|s6|s7|s8|s9|s10) ;;
        *) echo "unknown subcommand: ${SUBCOMMAND}" >&2; exit 2 ;;
    esac
}

prepare_step() {
    local step="$1"
    if [ -e "${EVIDENCE_ARG}" ]; then
        if ! rm -rf "${EVIDENCE_ARG}" 2>/dev/null; then
            mv "${EVIDENCE_ARG}" "${EVIDENCE_ARG}.prev-$(date +%s)" 2>/dev/null || true
        fi
    fi
    mkdir -p "${EVIDENCE_ARG}"
    init_step "${step}" "${RUN_ID}" "${EVIDENCE_ARG}"
    trap on_exit EXIT INT TERM
    if ! setup_host_alias; then
        STEP_FAILED=1
        return 1
    fi
    snapshot_host "${EVIDENCE_DIR}/before-host.txt"
    if ! setup_topology; then
        STEP_FAILED=1
        return 1
    fi
    : >"${EVIDENCE_DIR}/socks5.log"
    : >"${EVIDENCE_DIR}/upstream.log"
    return 0
}

finalize_step() {
    local cleanup_failed=0
    stop_tcpdump
    stop_nexusd
    stop_upstream
    cleanup_netns
    snapshot_host "${EVIDENCE_DIR}/after-host.txt"
    cleanup_host_alias
    ORDERLY_DONE=1

    if [ -f "${EVIDENCE_DIR}/nexusd.log" ]; then
        if grep -q 'state=cleanup_failed\|event=rules_failed step=cleanup' "${EVIDENCE_DIR}/nexusd.log"; then
            record "FAIL cleanup_failed_log present"
            cleanup_failed=1
        else
            record "PASS cleanup_failed_log absent"
        fi
    fi

    if diff -u "${EVIDENCE_DIR}/before-host.txt" "${EVIDENCE_DIR}/after-host.txt" \
        >"${EVIDENCE_DIR}/host-diff.txt"; then
        record "PASS host_diff_empty"
    else
        record "FAIL host_diff_nonempty (see host-diff.txt)"
        cleanup_failed=1
        STEP_FAILED=1
    fi
    assert_no_run_netns

    if [ "${cleanup_failed}" -eq 0 ]; then
        record "cleanup_ok=true"
    else
        record "cleanup_ok=false"
    fi
    if [ "${STEP_FAILED}" -eq 0 ]; then
        record "verdict=PASS step=S${STEP_N}"
    else
        record "verdict=FAIL step=S${STEP_N}"
    fi
    record "finished_at=$(date -Is)"
}

step_exit_code() {
    [ "${STEP_FAILED}" -eq 0 ] && return 0
    return 1
}

# ---------------------------------------------------------------------------
# S1: TPROXY-TCP 原始目的地 + 直连
# ---------------------------------------------------------------------------
step_s1() {
    prepare_step 1 || { finalize_step; return 1; }
    local ev="$EVIDENCE_DIR" cfg="$EVIDENCE_DIR/config"
    mkdir -p "$cfg"
    write_daemon_toml "$cfg" false auto false
    write_tproxy_yaml_direct "$cfg" iptables

    start_upstream || { finalize_step; return 1; }
    start_nexusd "$cfg" "$ev/nexusd.log" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        || { stats_json "$ev/status.json" >/dev/null 2>&1 || true; finalize_step; return 1; }
    if ! wait_tproxy_state active 100; then
        stats_json "$ev/status.json" >/dev/null 2>&1 || true
        local st rsn enf priv rules_line
        st="$(stats_value "$ev/status.json" '.tproxy.state')"
        rsn="$(stats_value "$ev/status.json" '.tproxy.reason')"
        enf="$(stats_value "$ev/status.json" '.tproxy.enforcement')"
        priv="$(stats_value "$ev/status.json" '.tproxy.privilege')"
        record "FAIL tproxy_state_active actual=${st:-missing} reason=${rsn:--} enforcement=${enf:--} privilege=${priv:--}"
        rules_line="$(grep -o '\[nexusd.tproxy\] level=error event=rules_failed.*' "$ev/nexusd.log" 2>/dev/null | head -1 || true)"
        record "MEASURED rules_failed='${rules_line:-missing}'"
        record "BLOCKED curl_exit actual=not_run reason=tproxy_state_${st:-missing}"
        record "BLOCKED ss_accepted_local actual=not_run reason=tproxy_state_${st:-missing}"
        record "BLOCKED tcp_accepted actual=$(stats_value "$ev/status.json" '.tproxy.counters.tcp_accepted') reason=no_traffic"
        record "BLOCKED orig_dst_missing actual=$(stats_value "$ev/status.json" '.tproxy.counters.orig_dst_missing') reason=no_traffic"
        record "BLOCKED nexusd_flow_decision_log actual=not_run reason=tproxy_state_${st:-missing}"
        printf 'NOT_RUN: tproxy.state=%s reason=%s; S1 aborted before ss capture\n' "${st:-missing}" "${rsn:--}" >"$ev/ss.txt"
        printf 'NOT_RUN: tproxy.state=%s reason=%s; S1 aborted before curl\n' "${st:-missing}" "${rsn:--}" >"$ev/curl.txt"
        finalize_step
        return 1
    fi
    record "PASS tproxy_state_active"

    local body rc
    body="$(client_curl "http://${UPSTREAM_ADDR}:8080/" 10 2>"$ev/curl.err")"
    rc=$?
    printf '%s\n' "$body" >"$ev/curl.txt"
    assert_eq curl_exit "$rc" 0
    assert_contains curl_body "$body" "hello-nexus"

    client_curl "http://${UPSTREAM_ADDR}:8080/slow" 10 >"$ev/curl-slow.txt" 2>&1 &
    local slow_pid=$!
    sleep 0.6
    router_ss "$ev/ss.txt"
    wait "$slow_pid" 2>/dev/null || true

    local ss_local
    ss_local="$(awk '$1=="ESTAB" && $4=="'"${UPSTREAM_ADDR}"':8080" {print $4; exit}' "$ev/ss.txt")"
    assert_eq ss_accepted_local "$ss_local" "${UPSTREAM_ADDR}:8080"

    stats_json "$ev/status.json" >/dev/null 2>&1 || true
    local tcp missing upstream state ipv6
    tcp="$(stats_value "$ev/status.json" '.tproxy.counters.tcp_accepted')"
    missing="$(stats_value "$ev/status.json" '.tproxy.counters.orig_dst_missing')"
    upstream="$(stats_value "$ev/status.json" '.tproxy.counters.upstream_failed')"
    state="$(stats_value "$ev/status.json" '.tproxy.state')"
    ipv6="$(stats_value "$ev/status.json" '.tproxy.ipv6_enabled')"
    assert_ge tcp_accepted "$tcp" 1
    assert_eq orig_dst_missing "$missing" 0
    assert_eq upstream_failed "$upstream" 0
    assert_eq tproxy_state "$state" active
    assert_eq tproxy_ipv6_enabled "$ipv6" false

    local logtext decision
    local expected="matched_rule=rule-match egress_hint=- outbound=self"
    logtext="$(cat "$ev/nexusd.log" 2>/dev/null || true)"
    decision="$(printf '%s\n' "$logtext" | grep -oF "${expected}" | head -1 || true)"
    if [ -n "$decision" ]; then
        record "PASS nexusd_flow_decision_log value='${decision}'"
    else
        record "FAIL nexusd_flow_decision_log missing expected='${expected}'"
        STEP_FAILED=1
    fi
    assert_not_contains nexusd_upstream_failed "$logtext" "event=upstream_failed"

    finalize_step
    step_exit_code
}

# ---------------------------------------------------------------------------
# S2: TPROXY-UDP + DNS，回包源地址断言
# ---------------------------------------------------------------------------
step_s2() {
    prepare_step 2 || { finalize_step; return 1; }
    local ev="$EVIDENCE_DIR" cfg="$EVIDENCE_DIR/config"
    mkdir -p "$cfg"
    write_daemon_toml "$cfg" false auto false
    write_tproxy_yaml_direct "$cfg" iptables

    start_upstream || { finalize_step; return 1; }
    start_nexusd "$cfg" "$ev/nexusd.log" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        || { stats_json "$ev/status.json" >/dev/null 2>&1 || true; finalize_step; return 1; }
    if ! wait_tproxy_state active 100; then
        record "FAIL tproxy_state_active timeout"
        stats_json "$ev/status.json" >/dev/null 2>&1 || true
        finalize_step
        return 1
    fi
    record "PASS tproxy_state_active"

    start_tcpdump "src host ${UPSTREAM_ADDR} and udp src port 53" "$ev/tcpdump.txt" 1 15

    local dig_out dig_rc
    dig_out="$(client_dig example.nexus 2>&1)"
    dig_rc=$?
    printf '%s\n' "$dig_out" >"$ev/dig.txt"
    assert_eq dig_exit "$dig_rc" 0
    assert_contains dig_answer "$dig_out" "${SITE_ADDR}"

    local udp_out udp_rc
    timeout 10 sudo -n "${IP}" netns exec "${NS_C}" python3 "${TPROXY_DIR}/udp_client.py" \
        --dns "${UPSTREAM_ADDR}" --echo "${UPSTREAM_ADDR}:9000" --name example.nexus \
        >"$ev/udp-client.txt" 2>&1
    udp_rc=$?
    local udp_text
    udp_text="$(cat "$ev/udp-client.txt")"
    assert_eq udp_client_exit "$udp_rc" 0
    assert_contains udp_dns_src "$udp_text" "dns_src=${UPSTREAM_ADDR}:53"
    assert_contains udp_dns_answer "$udp_text" "dns_answer=${SITE_ADDR}"
    assert_contains udp_echo_src "$udp_text" "echo_src=${UPSTREAM_ADDR}:9000"
    assert_contains udp_echo_payload "$udp_text" "echo_payload=hello-udp-nexus"

    sleep 0.5
    stop_tcpdump
    if [ -s "$ev/tcpdump.txt" ] && grep -q "${UPSTREAM_ADDR}.53" "$ev/tcpdump.txt"; then
        record "PASS tcpdump_dns_reply captured"
    else
        record "FAIL tcpdump_dns_reply missing"
        STEP_FAILED=1
    fi

    stats_json "$ev/status.json" >/dev/null 2>&1 || true
    local datagrams reply_failed missing state ipv6
    datagrams="$(stats_value "$ev/status.json" '.tproxy.counters.udp_datagrams')"
    reply_failed="$(stats_value "$ev/status.json" '.tproxy.counters.udp_reply_failed')"
    missing="$(stats_value "$ev/status.json" '.tproxy.counters.orig_dst_missing')"
    state="$(stats_value "$ev/status.json" '.tproxy.state')"
    ipv6="$(stats_value "$ev/status.json" '.tproxy.ipv6_enabled')"
    assert_ge udp_datagrams "$datagrams" 2
    assert_eq udp_reply_failed "$reply_failed" 0
    assert_eq orig_dst_missing "$missing" 0
    assert_eq tproxy_state "$state" active
    assert_eq tproxy_ipv6_enabled "$ipv6" false

    finalize_step
    step_exit_code
}

# ---------------------------------------------------------------------------
# S3: TPROXY 规则分流（Proxy，egress_hint=p1）
# ---------------------------------------------------------------------------
step_s3() {
    prepare_step 3 || { finalize_step; return 1; }
    local ev="$EVIDENCE_DIR" cfg="$EVIDENCE_DIR/config"
    mkdir -p "$cfg"
    write_daemon_toml "$cfg" false auto false
    write_tproxy_yaml_proxy "$cfg" iptables block

    start_upstream || { finalize_step; return 1; }
    start_nexusd "$cfg" "$ev/nexusd.log" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        || { stats_json "$ev/status.json" >/dev/null 2>&1 || true; finalize_step; return 1; }
    if ! wait_tproxy_state active 100; then
        record "FAIL tproxy_state_active timeout"
        stats_json "$ev/status.json" >/dev/null 2>&1 || true
        finalize_step
        return 1
    fi
    record "PASS tproxy_state_active"

    local body rc
    body="$(client_curl "http://${SITE_ADDR}:8080/" 10 2>"$ev/curl.err")"
    rc=$?
    printf '%s\n' "$body" >"$ev/curl.txt"
    assert_eq curl_exit "$rc" 0
    assert_contains curl_body "$body" "hello-nexus"

    sleep 0.5
    # P5-d 之后 stop_nexusd 会真正等 nexusd 退出，LocalAPI 随之关闭；因此
    # dataplane 统计必须在停机之前抓取，否则读到 connection refused。
    stats_json "$ev/status.json" >/dev/null 2>&1 || true
    local providers fstate
    providers="$(stats_value "$ev/status.json" '.dataplane.flow_sessions.providers')"
    fstate="$(stats_value "$ev/status.json" '.dataplane.flow_sessions.state')"
    assert_eq providers "$providers" 1
    assert_eq flow_sessions_state "$fstate" enabled

    stop_nexusd
    local socks
    socks="$(cat "$ev/socks5.log" 2>/dev/null || true)"
    assert_contains socks5_connect "$socks" "connect from="
    assert_contains socks5_target "$socks" "target=${SITE_ADDR}:8080"

    local logtext
    logtext="$(cat "$ev/nexusd.log" 2>/dev/null || true)"
    if printf '%s\n' "$logtext" | grep -Fq 'egress_hint=p1 outbound=p1'; then
        record "PASS nexusd_egress_hint_log egress_hint=p1 outbound=p1"
    else
        record "FAIL nexusd_egress_hint_log missing expected='egress_hint=p1 outbound=p1'"
        STEP_FAILED=1
    fi
    if printf '%s\n' "$logtext" | grep -Fq 'matched_rule=ip-cidr-p1'; then
        record "PASS matched_rule_ip_cidr"
    else
        record "FAIL matched_rule_ip_cidr missing expected='matched_rule=ip-cidr-p1'"
        STEP_FAILED=1
    fi
    record "NOTE proxy_forwarded UNOBSERVABLE in tproxy counters (spec exposes only dataplane TUN counter)"
    record "NOTE Planned.provider indirect evidence: providers=1 + socks5 connect target=${SITE_ADDR}:8080"

    finalize_step
    step_exit_code
}

# ---------------------------------------------------------------------------
# S4: TUN 对照（一致性 + OS 装配断言）
# ---------------------------------------------------------------------------
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

run_tun_pass() {
    local tag="$1" default_route="$2"
    local ev="$EVIDENCE_DIR" cfg="$EVIDENCE_DIR/config-${tag}"
    mkdir -p "$cfg"
    write_daemon_toml "$cfg" true auto "$default_route"
    write_tun_yaml "$cfg" iptables

    start_nexusd "$cfg" "$ev/nexusd-${tag}.log" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        || { stop_nexusd; return 1; }
    if ! wait_os_state applied 100; then
        record "FAIL os_assemble_applied timeout tag=${tag}"
        stats_json "${ev}/status-${tag}.json" >/dev/null 2>&1 || true
        # P5-d：超时后必须先终止本 pass 的 nexusd 本体，否则下一 pass
        # 会因 LocalAPI 18080 被占而级联失败（挂起/孤儿也不能留给 finalize）。
        stop_nexusd
        return 1
    fi
    local status="${ev}/status-${tag}.json"
    stats_json "$status" >/dev/null 2>&1 || true
    local ifname os_state os_default excludes
    ifname="$(stats_value "$status" '.dataplane.os_assemble.ifname')"
    os_state="$(stats_value "$status" '.dataplane.os_assemble.state')"
    os_default="$(stats_value "$status" '.dataplane.os_assemble.default_route')"
    excludes="$(stats_value "$status" '.dataplane.os_assemble.excludes')"
    record "tun_pass=${tag} ifname=${ifname}"
    assert_eq "os_assemble_state_${tag}" "$os_state" applied
    assert_eq "os_assemble_default_route_${tag}" "$os_default" "$default_route"
    assert_ge "os_assemble_excludes_${tag}" "$excludes" 1

    ns_exec "${NS_R}" ip addr show "${ifname}" >"${ev}/ip-addr-${tag}.txt" 2>&1 || true
    ns_exec "${NS_R}" ip route show table all >"${ev}/ip-route-${tag}.txt" 2>&1 || true
    assert_contains "tun_addr_${tag}" "$(cat "${ev}/ip-addr-${tag}.txt" 2>/dev/null || true)" "10.99.0.1/24"
    assert_contains "tun_subnet_route_${tag}" "$(cat "${ev}/ip-route-${tag}.txt" 2>/dev/null || true)" "10.99.0.0/24"

    if [ "$default_route" = "true" ]; then
        local defaults
        defaults="$(ns_exec "${NS_R}" ip route show default 2>&1 || true)"
        assert_contains "default_route_via_tun_${tag}" "$defaults" "${ifname}"
    fi

    ns_exec "${NS_R}" ip route add 10.200.2.0/24 dev "${ifname}" >/dev/null 2>&1 || true

    local body rc
    body="$(client_curl "http://${UPSTREAM_ADDR}:8080/" 10 2>"${ev}/curl-direct-${tag}.err")"
    rc=$?
    printf '%s\n' "$body" >"${ev}/curl-direct-${tag}.txt"
    assert_eq "tun_direct_curl_exit_${tag}" "$rc" 0
    assert_contains "tun_direct_curl_body_${tag}" "$body" "hello-nexus"

    body="$(client_curl "http://${SITE_ADDR}:8080/" 10 2>"${ev}/curl-proxy-${tag}.err")"
    rc=$?
    printf '%s\n' "$body" >"${ev}/curl-proxy-${tag}.txt"
    assert_eq "tun_proxy_curl_exit_${tag}" "$rc" 0
    assert_contains "tun_proxy_curl_body_${tag}" "$body" "hello-nexus"

    stats_json "$status" >/dev/null 2>&1 || true
    local direct_ok proxy_fwd
    direct_ok="$(stats_value "$status" '.dataplane.direct_tcp_dial_ok')"
    proxy_fwd="$(stats_value "$status" '.dataplane.proxy_forwarded')"
    assert_ge "tun_direct_tcp_dial_ok_${tag}" "$direct_ok" 1
    assert_ge "tun_proxy_forwarded_${tag}" "$proxy_fwd" 1

    local route_get
    route_get="$(ns_exec "${NS_R}" ip route get "${UPSTREAM_ADDR}" 2>&1 || true)"
    assert_not_contains "tun_exclude_proxy_server_${tag}" "$route_get" "dev ${ifname}"

    stop_nexusd
    sleep 0.3
    if ns_exec "${NS_R}" ip link show "${ifname}" >/dev/null 2>&1; then
        record "FAIL tun_iface_cleanup_${tag} ifname=${ifname} still present"
        STEP_FAILED=1
    else
        record "PASS tun_iface_cleanup_${tag}"
    fi
    return 0
}

step_s4() {
    prepare_step 4 || { finalize_step; return 1; }
    local ev="$EVIDENCE_DIR"
    start_upstream || { finalize_step; return 1; }

    run_tun_pass "dr_false" false || true
    run_tun_pass "dr_true" true || true

    stats_json "$ev/status.json" >/dev/null 2>&1 || true
    local logtext
    logtext="$(cat "$ev/nexusd-dr_false.log" 2>/dev/null || true)"
    if printf '%s\n' "$logtext" | grep -Fq 'matched_rule='; then
        record "PASS tun_matched_rule_log"
    else
        record "FAIL tun_matched_rule_log missing"
        STEP_FAILED=1
    fi
    record "NOTE selected_outbound/egress_hint UNOBSERVABLE in LocalAPI status (E5 daemon does not emit flow_decision)"

    finalize_step
    step_exit_code
}

# ---------------------------------------------------------------------------
# S5: 失败阻断（路径失效）
# ---------------------------------------------------------------------------
step_s5() {
    prepare_step 5 || { finalize_step; return 1; }
    local ev="$EVIDENCE_DIR" cfg="$EVIDENCE_DIR/config"
    mkdir -p "$cfg"
    write_daemon_toml "$cfg" false auto false
    write_tproxy_yaml_proxy "$cfg" iptables block

    start_upstream --no-socks5 || { finalize_step; return 1; }
    start_nexusd "$cfg" "$ev/nexusd.log" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        || { stats_json "$ev/status.json" >/dev/null 2>&1 || true; finalize_step; return 1; }
    if ! wait_tproxy_state active 100; then
        record "FAIL tproxy_state_active timeout"
        stats_json "$ev/status.json" >/dev/null 2>&1 || true
        finalize_step
        return 1
    fi
    record "PASS tproxy_state_active"

    start_tcpdump "src host ${ROUTER_UP_ADDR} and dst host ${SITE_ADDR} and tcp" \
        "$ev/tcpdump.txt" 1 12

    local start_ms end_ms elapsed rc
    start_ms="$(date +%s%3N)"
    client_curl "http://${SITE_ADDR}:8080/" 10 >"$ev/curl.txt" 2>&1
    rc=$?
    end_ms="$(date +%s%3N)"
    elapsed=$((end_ms - start_ms))
    printf 'exit=%s elapsed_ms=%s\n' "$rc" "$elapsed" >>"$ev/curl.txt"
    assert_ne curl_exit "$rc" 0
    if [ "$elapsed" -lt 10000 ]; then
        record "PASS curl_failed_within_10s elapsed_ms=${elapsed}"
    else
        record "FAIL curl_failed_within_10s elapsed_ms=${elapsed}"
        STEP_FAILED=1
    fi

    sleep 0.5
    stop_tcpdump
    if [ -s "$ev/tcpdump.txt" ]; then
        record "FAIL no_direct_bypass tcpdump_captured_router_originated_direct_packet"
        STEP_FAILED=1
    else
        record "PASS no_direct_bypass no router-originated packet to ${SITE_ADDR}"
    fi

    stats_json "$ev/status.json" >/dev/null 2>&1 || true
    local upstream last_reason
    upstream="$(stats_value "$ev/status.json" '.tproxy.counters.upstream_failed')"
    last_reason="$(stats_value "$ev/status.json" '.tproxy.last_failure_reason')"
    assert_ge upstream_failed "$upstream" 1
    if printf '%s' "$last_reason" | grep -Fq 'upstream_failed'; then
        record "PASS last_failure_reason value='${last_reason}'"
    else
        record "FAIL last_failure_reason actual='${last_reason}' expected_contains='upstream_failed'"
        STEP_FAILED=1
    fi

    finalize_step
    step_exit_code
}

# ---------------------------------------------------------------------------
# S6: 捕获失败（不静默漏流量）
# ---------------------------------------------------------------------------

start_port_occupier() {
    local port="$1"
    timeout 300 sudo -n "${IP}" netns exec "${NS_R}" python3 -c "
import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', ${port}))
s.listen(16)
time.sleep(280)
" >"${EVIDENCE_DIR}/occupier.log" 2>&1 &
OCCUPIER_PID=$!
sleep 0.5
}

stop_port_occupier() {
    if [ -n "${OCCUPIER_PID:-}" ] && ps -p "${OCCUPIER_PID}" >/dev/null 2>&1; then
        timeout 10 sudo -n "${IP}" netns exec "${NS_R}" kill -TERM "${OCCUPIER_PID}" >/dev/null 2>&1 || true
        wait "${OCCUPIER_PID}" 2>/dev/null || true
    fi
    OCCUPIER_PID=""
}

step_s6() {
    prepare_step 6 || { finalize_step; return 1; }
    local ev="$EVIDENCE_DIR" cfg="$EVIDENCE_DIR/config"
    mkdir -p "$cfg"
    write_daemon_toml "$cfg" false auto false
    write_tproxy_yaml_direct "$cfg" iptables

    start_upstream || { finalize_step; return 1; }
    start_port_occupier 7895
    start_nexusd "$cfg" "$ev/nexusd.log" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        || { stats_json "$ev/status.json" >/dev/null 2>&1 || true; stop_port_occupier; finalize_step; return 1; }
    wait_tproxy_state degraded 100 || true
    stats_json "$ev/status.json" >/dev/null 2>&1 || true

    local state reason enforcement
    state="$(stats_value "$ev/status.json" '.tproxy.state')"
    reason="$(stats_value "$ev/status.json" '.tproxy.reason')"
    enforcement="$(stats_value "$ev/status.json" '.tproxy.enforcement')"
    assert_eq tproxy_state_degraded "$state" degraded
    assert_eq tproxy_reason_bind_failed "$reason" bind_failed
    if [ "$enforcement" = "block" ] || [ "$enforcement" = "impossible" ]; then
        record "PASS tproxy_enforcement value=${enforcement}"
    else
        record "FAIL tproxy_enforcement actual=${enforcement} expected=block|impossible"
        STEP_FAILED=1
    fi

    local body rc
    body="$(client_curl "http://${UPSTREAM_ADDR}:8080/" 8 2>&1)"
    rc=$?
    printf 'exit=%s body=%s\n' "$rc" "$body" >"$ev/curl.txt"
    if [ "$enforcement" = "block" ]; then
        assert_ne curl_exit_block "$rc" 0
    else
        if printf '%s\n' "$(cat "$ev/nexusd.log")" | grep -Fq 'event=capture_failed'; then
            record "PASS enforcement_impossible_error_log present"
        else
            record "FAIL enforcement_impossible_error_log missing"
            STEP_FAILED=1
        fi
    fi
    if [ "$rc" -eq 0 ]; then
        record "FAIL silent_bypass request succeeded while capture failed"
        STEP_FAILED=1
    else
        record "PASS no_silent_bypass request failed"
    fi

    stop_port_occupier
    finalize_step
    step_exit_code
}

# ---------------------------------------------------------------------------
# S7: 清理与宿主安全
# ---------------------------------------------------------------------------
step_s7() {
    prepare_step 7 || { finalize_step; return 1; }
    local ev="$EVIDENCE_DIR" cfg="$EVIDENCE_DIR/config"
    mkdir -p "$cfg"
    write_daemon_toml "$cfg" false auto false
    write_tproxy_yaml_direct "$cfg" iptables

    start_upstream || { finalize_step; return 1; }
    start_nexusd "$cfg" "$ev/nexusd.log" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        || { stats_json "$ev/status.json" >/dev/null 2>&1 || true; finalize_step; return 1; }
    if ! wait_tproxy_state active 100; then
        record "FAIL tproxy_state_active timeout"
        stats_json "$ev/status.json" >/dev/null 2>&1 || true
        finalize_step
        return 1
    fi
    record "PASS tproxy_state_active"

    local body rc
    body="$(client_curl "http://${UPSTREAM_ADDR}:8080/" 10 2>"$ev/curl.err")"
    rc=$?
    assert_eq curl_exit "$rc" 0

    ns_exec "${NS_R}" iptables -t mangle -S >"$ev/iptables-before.txt" 2>&1 || true
    stop_nexusd
    sleep 0.4
    # 删除 setup_topology 添加的客户端子网拓扑路由，table 100 只剩产品清理结果。
    ns_exec "${NS_R}" ip route del "${CLIENT_SUBNET}" dev "${VR}" table 100 >/dev/null 2>&1 || true
    ns_exec "${NS_R}" iptables -t mangle -S >"$ev/iptables.txt" 2>&1 || true
    ns_exec "${NS_R}" ip rule show >"$ev/ip-rule.txt" 2>&1 || true
    ns_exec "${NS_R}" ip route show table 100 >"$ev/ip-route.txt" 2>&1 || true

    local ipt iprule iproute
    ipt="$(cat "$ev/iptables.txt" 2>/dev/null || true)"
    iprule="$(cat "$ev/ip-rule.txt" 2>/dev/null || true)"
    iproute="$(cat "$ev/ip-route.txt" 2>/dev/null || true)"
    assert_not_contains iptables_no_chain "$ipt" "NEXUS_TPROXY"
    assert_not_contains ip_rule_no_mark "$iprule" "fwmark 0x1f3/0x1f3"
    assert_eq table100_empty "$(printf '%s' "$iproute" | tr -d '[:space:]')" ""

    {
        echo "=== stop_nexusd SIGTERM ==="
        echo "iptables:"; cat "$ev/iptables.txt" 2>/dev/null || true
        echo "ip rule:"; cat "$ev/ip-rule.txt" 2>/dev/null || true
        echo "table 100:"; cat "$ev/ip-route.txt" 2>/dev/null || true
    } >"$ev/cleanup.log"

    finalize_step
    step_exit_code
}

# ---------------------------------------------------------------------------
# S8: nftables backend
# ---------------------------------------------------------------------------
step_s8() {
    prepare_step 8 || { finalize_step; return 1; }
    local ev="$EVIDENCE_DIR" cfg="$EVIDENCE_DIR/config"
    mkdir -p "$cfg"
    write_daemon_toml "$cfg" false auto false
    write_tproxy_yaml_direct "$cfg" nftables

    start_upstream || { finalize_step; return 1; }
    start_nexusd "$cfg" "$ev/nexusd.log" \
        PATH="${NFT_PATH}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        LD_LIBRARY_PATH="${NFT_LIB}" \
        || { stats_json "$ev/status.json" >/dev/null 2>&1 || true; finalize_step; return 1; }
    if ! wait_tproxy_state active 100; then
        record "FAIL tproxy_state_active timeout (nftables)"
        stats_json "$ev/status.json" >/dev/null 2>&1 || true
        finalize_step
        return 1
    fi
    record "PASS tproxy_state_active"

    ns_exec_nft "${NS_R}" nft list table inet nexus_tproxy >"$ev/nft.txt" 2>&1 || true
    ns_exec_nft "${NS_R}" nft list chain inet nexus_tproxy NEXUS_TPROXY >>"$ev/nft.txt" 2>&1 || true
    assert_contains nft_table_visible "$(cat "$ev/nft.txt" 2>/dev/null || true)" "NEXUS_TPROXY"

    local body rc dig_out
    body="$(client_curl "http://${UPSTREAM_ADDR}:8080/" 10 2>"$ev/curl.err")"
    rc=$?
    assert_eq curl_exit "$rc" 0
    assert_contains curl_body "$body" "hello-nexus"
    dig_out="$(client_dig example.nexus 2>&1)"
    assert_contains dig_answer "$dig_out" "${SITE_ADDR}"

    stats_json "$ev/status.json" >/dev/null 2>&1 || true
    local backend tcp datagrams
    backend="$(stats_value "$ev/status.json" '.tproxy.backend')"
    tcp="$(stats_value "$ev/status.json" '.tproxy.counters.tcp_accepted')"
    datagrams="$(stats_value "$ev/status.json" '.tproxy.counters.udp_datagrams')"
    assert_eq tproxy_backend "$backend" nftables
    assert_ge tcp_accepted "$tcp" 1
    assert_ge udp_datagrams "$datagrams" 1

    stop_nexusd
    sleep 0.4
    if ns_exec_nft "${NS_R}" nft list table inet nexus_tproxy >"$ev/nft-after.txt" 2>&1; then
        record "FAIL nft_table_cleanup table still present"
        STEP_FAILED=1
    else
        record "PASS nft_table_cleanup table removed"
    fi

    finalize_step
    step_exit_code
}

# ---------------------------------------------------------------------------
# S9: 权限与 external backend
# ---------------------------------------------------------------------------
install_external_rules() {
    ns_exec "${NS_R}" iptables -t mangle -N NEXUS_TPROXY >/dev/null 2>&1 || true
    ns_exec "${NS_R}" iptables -t mangle -A NEXUS_TPROXY -m addrtype --dst-type LOCAL -j RETURN >/dev/null 2>&1 || true
    ns_exec "${NS_R}" iptables -t mangle -A NEXUS_TPROXY -p tcp -j TPROXY --on-port 7895 --tproxy-mark 0x1f3/0x1f3 >/dev/null 2>&1 || true
    ns_exec "${NS_R}" iptables -t mangle -A NEXUS_TPROXY -p udp -j TPROXY --on-port 7895 --tproxy-mark 0x1f3/0x1f3 >/dev/null 2>&1 || true
    ns_exec "${NS_R}" iptables -t mangle -A PREROUTING -j NEXUS_TPROXY >/dev/null 2>&1 || true
    ns_exec "${NS_R}" ip rule add fwmark 0x1f3/0x1f3 lookup 100 >/dev/null 2>&1 || true
    ns_exec "${NS_R}" ip route add local 0.0.0.0/0 dev lo table 100 >/dev/null 2>&1 || true
}

remove_external_rules() {
    ns_exec "${NS_R}" iptables -t mangle -D PREROUTING -j NEXUS_TPROXY >/dev/null 2>&1 || true
    ns_exec "${NS_R}" iptables -t mangle -F NEXUS_TPROXY >/dev/null 2>&1 || true
    ns_exec "${NS_R}" iptables -t mangle -X NEXUS_TPROXY >/dev/null 2>&1 || true
    ns_exec "${NS_R}" ip route del local 0.0.0.0/0 dev lo table 100 >/dev/null 2>&1 || true
    ns_exec "${NS_R}" ip rule del fwmark 0x1f3/0x1f3 lookup 100 >/dev/null 2>&1 || true
}

step_s9() {
    prepare_step 9 || { finalize_step; return 1; }
    local ev="$EVIDENCE_DIR" cfg="$EVIDENCE_DIR/config"
    mkdir -p "$cfg"
    write_daemon_toml "$cfg" false auto false
    write_tproxy_yaml_external "$cfg" block

    start_upstream || { finalize_step; return 1; }

    # A. external + rules present
    install_external_rules
    ns_exec "${NS_R}" iptables -t mangle -S NEXUS_TPROXY >"$ev/external-rules-before.txt" 2>&1 || true
    start_nexusd "$cfg" "$ev/nexusd-root.log" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        || { stats_json "$ev/status-root.json" >/dev/null 2>&1 || true; finalize_step; return 1; }
    wait_tproxy_state active 100 || true
    stats_json "$ev/status-root.json" >/dev/null 2>&1 || true
    local state enforcement privilege
    state="$(stats_value "$ev/status-root.json" '.tproxy.state')"
    enforcement="$(stats_value "$ev/status-root.json" '.tproxy.enforcement')"
    privilege="$(stats_value "$ev/status-root.json" '.tproxy.privilege')"
    assert_eq external_state_active "$state" active
    assert_eq external_enforcement_active "$enforcement" active
    assert_eq external_privilege_root "$privilege" root
    local body rc
    body="$(client_curl "http://${UPSTREAM_ADDR}:8080/" 10 2>"$ev/curl.err")"
    rc=$?
    assert_eq external_curl_exit "$rc" 0
    assert_contains external_curl_body "$body" "hello-nexus"
    stop_nexusd

    ns_exec "${NS_R}" iptables -t mangle -S NEXUS_TPROXY >"$ev/external-rules-after.txt" 2>&1 || true
    if diff -u "$ev/external-rules-before.txt" "$ev/external-rules-after.txt" \
        >"$ev/external-rules.diff"; then
        record "PASS external_cleanup_kept_rules"
    else
        record "FAIL external_cleanup_deleted_or_changed_rules"
        STEP_FAILED=1
    fi
    remove_external_rules

    # B. external + rules missing
    start_nexusd "$cfg" "$ev/nexusd-missing.log" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        || { stats_json "$ev/status-missing.json" >/dev/null 2>&1 || true; finalize_step; return 1; }
    wait_tproxy_state degraded 100 || true
    stats_json "$ev/status-missing.json" >/dev/null 2>&1 || true
    state="$(stats_value "$ev/status-missing.json" '.tproxy.state')"
    local reason
    reason="$(stats_value "$ev/status-missing.json" '.tproxy.reason')"
    enforcement="$(stats_value "$ev/status-missing.json" '.tproxy.enforcement')"
    assert_eq external_missing_state "$state" degraded
    assert_eq external_missing_reason "$reason" rule_apply_failed
    assert_eq external_missing_enforcement "$enforcement" impossible
    stop_nexusd

    # C. non-root without capabilities
    start_nexusd_nonroot "$cfg" "$ev/nexusd-nonroot.log" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        || { stats_json "$ev/status-nonroot.json" >/dev/null 2>&1 || true; finalize_step; return 1; }
    wait_tproxy_state degraded 100 || true
    stats_json "$ev/status-nonroot.json" >/dev/null 2>&1 || true
    state="$(stats_value "$ev/status-nonroot.json" '.tproxy.state')"
    reason="$(stats_value "$ev/status-nonroot.json" '.tproxy.reason')"
    privilege="$(stats_value "$ev/status-nonroot.json" '.tproxy.privilege')"
    enforcement="$(stats_value "$ev/status-nonroot.json" '.tproxy.enforcement')"
    assert_eq nonroot_state "$state" degraded
    assert_eq nonroot_reason "$reason" permission_denied
    assert_eq nonroot_privilege "$privilege" insufficient
    if [ "$enforcement" = "impossible" ] || [ "$enforcement" = "none" ]; then
        record "PASS nonroot_enforcement value=${enforcement}"
    else
        record "FAIL nonroot_enforcement actual=${enforcement} expected=impossible|none"
        STEP_FAILED=1
    fi

    finalize_step
    step_exit_code
}

# ---------------------------------------------------------------------------
# S10: 无 provider 源（auto）
# ---------------------------------------------------------------------------
step_s10() {
    prepare_step 10 || { finalize_step; return 1; }
    local ev="$EVIDENCE_DIR" cfg="$EVIDENCE_DIR/config"
    mkdir -p "$cfg"
    write_daemon_toml "$cfg" false auto false
    write_tproxy_yaml_direct "$cfg" iptables

    start_upstream || { finalize_step; return 1; }
    start_nexusd "$cfg" "$ev/nexusd.log" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        || { stats_json "$ev/status.json" >/dev/null 2>&1 || true; finalize_step; return 1; }
    if ! wait_tproxy_state active 100; then
        record "FAIL tproxy_state_active timeout"
        stats_json "$ev/status.json" >/dev/null 2>&1 || true
        finalize_step
        return 1
    fi
    record "PASS tproxy_state_active"

    local body rc
    body="$(client_curl "http://${UPSTREAM_ADDR}:8080/" 10 2>"$ev/curl.err")"
    rc=$?
    printf '%s\n' "$body" >"$ev/curl.txt"
    assert_eq curl_exit "$rc" 0
    assert_contains curl_body "$body" "hello-nexus"

    stats_json "$ev/status.json" >/dev/null 2>&1 || true
    local fstate freason providers
    fstate="$(stats_value "$ev/status.json" '.dataplane.flow_sessions.state')"
    freason="$(stats_value "$ev/status.json" '.dataplane.flow_sessions.reason')"
    providers="$(stats_value "$ev/status.json" '.dataplane.flow_sessions.providers')"
    assert_eq flow_sessions_state "$fstate" disabled
    assert_eq flow_sessions_reason "$freason" no_providers
    assert_eq providers "$providers" 0
    assert_not_contains plan_failed "$(cat "$ev/nexusd.log" 2>/dev/null || true)" "plan_failed"

    finalize_step
    step_exit_code
}

main() {
    parse_args "$@"
    case "${SUBCOMMAND}" in
        s1) step_s1 ;;
        s2) step_s2 ;;
        s3) step_s3 ;;
        s4) step_s4 ;;
        s5) step_s5 ;;
        s6) step_s6 ;;
        s7) step_s7 ;;
        s8) step_s8 ;;
        s9) step_s9 ;;
        s10) step_s10 ;;
    esac
}

main "$@"

#!/usr/bin/env bash
# E5 netns 验收共享库（spec/plan §8.2）。
#
# 只操作本 run 的 nxtp-* netns 与 NEXUS_TPROXY 链/table 100；绝不全局清空
# iptables，也不修改宿主网络。所有特权调用只经由 `sudo -n /usr/bin/ip`
# （netns 创建/进入）与 `sudo -n /usr/sbin/setcap`（S9 能力测试）。

set -u
set -o pipefail

TPROXY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TPROXY_DIR}/../../.." && pwd)"
IP="/usr/bin/ip"
NEXUSD="${NEXUSD:-${REPO_ROOT}/target/debug/nexusd}"
UPSTREAM_PY="${TPROXY_DIR}/upstream.py"
NFT_ROOT="${NFT_ROOT:-${HOME}/opt/nft-root}"
NFT_PATH="${NFT_ROOT}/usr/sbin"
NFT_LIB="${NFT_ROOT}/usr/lib/x86_64-linux-gnu"

CLIENT_ADDR="10.200.1.2"
CLIENT_SUBNET="10.200.1.0/24"
ROUTER_CLIENT_ADDR="10.200.1.1"
ROUTER_UP_ADDR="10.200.2.1"
UPSTREAM_ADDR="10.200.2.2"
SITE_ADDR="10.200.2.9"
LOCALAPI="http://127.0.0.1:18080/localapi/v0/dataplane/stats"

NS_C=""
NS_R=""
NS_U=""
NS_HOST=""
VC=""
VR=""
VU=""
VN=""

EVIDENCE_DIR=""
ASSERT_LOG=""
RUN_ID=""
STEP_N=""
STEP_FAILED=0
NEXUSD_PID=""
UPSTREAM_PID=""
TCPDUMP_PID=""
OCCUPIER_PID=""
CURRENT_CFG=""
ORDERLY_DONE=0

log() {
    printf '%s\n' "$*"
}

record() {
    local line="$*"
    printf '%s\n' "$line"
    if [ -n "${ASSERT_LOG}" ]; then
        printf '%s\n' "$line" >>"${ASSERT_LOG}"
    fi
}

init_step() {
    STEP_N="$1"
    RUN_ID="$2"
    EVIDENCE_DIR="$3"
    local sfx="$$s${STEP_N}"
    NS_C="nxtp-c-${RUN_ID}-s${STEP_N}"
    NS_R="nxtp-r-${RUN_ID}-s${STEP_N}"
    NS_U="nxtp-u-${RUN_ID}-s${STEP_N}"
    NS_HOST="nxtp-h-${RUN_ID}-s${STEP_N}"
    VC="vc${sfx}"
    VR="vr${sfx}"
    VU="vu${sfx}"
    VN="vn${sfx}"
    mkdir -p "${EVIDENCE_DIR}"
    ASSERT_LOG="${EVIDENCE_DIR}/assertions.log"
    : >"${ASSERT_LOG}"
    record "run_id=${RUN_ID} step=S${STEP_N} started_at=$(date -Is)"
    record "netns: ${NS_C} ${NS_R} ${NS_U}; veth: ${VC}/${VR} ${VU}/${VN}"
}

# ---------- 特权执行 ----------

ns_exec() {
    local ns="$1"
    shift
    timeout 10 sudo -n "${IP}" netns exec "${ns}" "$@"
}

ns_exec_long() {
    local ns="$1"
    shift
    timeout 20 sudo -n "${IP}" netns exec "${ns}" "$@"
}

ns_exec_nft() {
    local ns="$1"
    shift
    timeout 10 sudo -n "${IP}" netns exec "${ns}" \
        env PATH="${NFT_PATH}:${PATH}" LD_LIBRARY_PATH="${NFT_LIB}" "$@"
}

# ---------- 断言 ----------

assert_eq() {
    local label="$1" actual="$2" expected="$3"
    if [ "${actual}" = "${expected}" ]; then
        record "PASS ${label} actual=${actual} expected=${expected}"
    else
        record "FAIL ${label} actual=${actual} expected=${expected}"
        STEP_FAILED=1
    fi
}

assert_ne() {
    local label="$1" actual="$2" unexpected="$3"
    if [ "${actual}" != "${unexpected}" ]; then
        record "PASS ${label} actual=${actual} unexpected=${unexpected}"
    else
        record "FAIL ${label} actual=${actual} unexpected=${unexpected}"
        STEP_FAILED=1
    fi
}

assert_ge() {
    local label="$1" actual="$2" minimum="$3"
    if [ "${actual}" -ge "${minimum}" ] 2>/dev/null; then
        record "PASS ${label} actual=${actual} minimum=${minimum}"
    else
        record "FAIL ${label} actual=${actual} minimum=${minimum}"
        STEP_FAILED=1
    fi
}

assert_contains() {
    local label="$1" haystack="$2" needle="$3"
    if printf '%s' "${haystack}" | grep -Fq -- "${needle}"; then
        record "PASS ${label} contains='${needle}'"
    else
        record "FAIL ${label} contains='${needle}' actual='${haystack}'"
        STEP_FAILED=1
    fi
}

assert_not_contains() {
    local label="$1" haystack="$2" needle="$3"
    if printf '%s' "${haystack}" | grep -Fq -- "${needle}"; then
        record "FAIL ${label} unexpectedly_contains='${needle}'"
        STEP_FAILED=1
    else
        record "PASS ${label} not_contains='${needle}'"
    fi
}

assert_file_empty() {
    local label="$1" path="$2"
    if [ -s "${path}" ]; then
        record "FAIL ${label} file_nonempty=${path}"
        STEP_FAILED=1
    else
        record "PASS ${label} file_empty=${path}"
    fi
}

# ---------- 宿主快照 ----------

setup_host_alias() {
    timeout 10 sudo -n "${IP}" netns delete "${NS_HOST}" >/dev/null 2>&1 || true
    timeout 10 sudo -n "${IP}" netns attach "${NS_HOST}" 1 >/dev/null 2>&1 || {
        record "FAIL host_alias_attach ns=${NS_HOST}"
        return 1
    }
    record "host_alias=${NS_HOST} (pid 1 netns)"
}

cleanup_host_alias() {
    timeout 10 sudo -n "${IP}" netns delete "${NS_HOST}" >/dev/null 2>&1 || true
}

snapshot_host() {
    local out="$1"
    {
        echo "## ip rule"
        timeout 10 ip rule show | sort
        echo "## ip route show table all"
        timeout 10 ip route show table all | sort
        echo "## iptables -t mangle -S"
        timeout 10 sudo -n "${IP}" netns exec "${NS_HOST}" iptables -t mangle -S 2>&1
        echo "## ip6tables -t mangle -S"
        timeout 10 sudo -n "${IP}" netns exec "${NS_HOST}" ip6tables -t mangle -S 2>&1
    } >"${out}"
}

# ---------- 拓扑 ----------

setup_topology() {
    cleanup_netns
    local ns
    for ns in "${NS_C}" "${NS_R}" "${NS_U}"; do
        timeout 10 sudo -n "${IP}" netns add "${ns}" || {
            record "FAIL netns_add ns=${ns}"
            return 1
        }
    done

    timeout 10 sudo -n "${IP}" link add "${VC}" type veth peer name "${VR}" || return 1
    timeout 10 sudo -n "${IP}" link set "${VC}" netns "${NS_C}" || return 1
    timeout 10 sudo -n "${IP}" link set "${VR}" netns "${NS_R}" || return 1

    timeout 10 sudo -n "${IP}" link add "${VU}" type veth peer name "${VN}" || return 1
    timeout 10 sudo -n "${IP}" link set "${VU}" netns "${NS_R}" || return 1
    timeout 10 sudo -n "${IP}" link set "${VN}" netns "${NS_U}" || return 1

    # client
    ns_exec "${NS_C}" ip link set lo up
    ns_exec "${NS_C}" ip link set "${VC}" up
    ns_exec "${NS_C}" ip addr add "${CLIENT_ADDR}/24" dev "${VC}"
    ns_exec "${NS_C}" ip route add default via "${ROUTER_CLIENT_ADDR}"

    # router
    ns_exec "${NS_R}" ip link set lo up
    ns_exec "${NS_R}" ip link set "${VR}" up
    ns_exec "${NS_R}" ip link set "${VU}" up
    ns_exec "${NS_R}" ip addr add "${ROUTER_CLIENT_ADDR}/24" dev "${VR}"
    ns_exec "${NS_R}" ip addr add "${ROUTER_UP_ADDR}/24" dev "${VU}"
    ns_exec "${NS_R}" sysctl -qw net.ipv4.ip_forward=1
    ns_exec "${NS_R}" sysctl -qw net.ipv4.conf.all.rp_filter=0
    ns_exec "${NS_R}" sysctl -qw net.ipv4.conf.default.rp_filter=0

    # 本机 fib_validate_source 对带 fwmark 的入包按 table 100 做反向源校验；
    # table 100 若只有 `local default`（RTN_LOCAL），校验失败会把 TPROXY 包丢掉。
    # 补一条客户端子网的 unicast 反向路由（拓扑属性；S7 断言前删除）。
    ns_exec "${NS_R}" ip route add "${CLIENT_SUBNET}" dev "${VR}" table 100
    record "topology_route table=100 dst=${CLIENT_SUBNET} dev=${VR}"

    # upstream
    ns_exec "${NS_U}" ip link set lo up
    ns_exec "${NS_U}" ip link set "${VN}" up
    ns_exec "${NS_U}" ip addr add "${UPSTREAM_ADDR}/24" dev "${VN}"
    ns_exec "${NS_U}" ip addr add "${SITE_ADDR}/32" dev lo
    ns_exec "${NS_U}" ip route add default via "${ROUTER_UP_ADDR}"

    if [ "${PRESEED_TABLE100:-0}" = "1" ]; then
        ns_exec "${NS_R}" ip route add local 0.0.0.0/0 dev lo table 100
        record "DIAGNOSTIC preseed_table_100=true"
    fi
    record "topology_ready client=${CLIENT_ADDR} router=${ROUTER_CLIENT_ADDR}/${ROUTER_UP_ADDR} upstream=${UPSTREAM_ADDR} site=${SITE_ADDR}"
}

cleanup_netns() {
    local ns v
    for ns in "${NS_C}" "${NS_R}" "${NS_U}"; do
        [ -n "${ns}" ] && timeout 10 sudo -n "${IP}" netns delete "${ns}" >/dev/null 2>&1 || true
    done
    for v in "${VC}" "${VR}" "${VU}" "${VN}"; do
        [ -n "${v}" ] && timeout 5 sudo -n "${IP}" link delete "${v}" >/dev/null 2>&1 || true
    done
}

assert_no_run_netns() {
    local listed
    listed="$(timeout 10 sudo -n "${IP}" netns list 2>/dev/null || true)"
    if printf '%s\n' "${listed}" | grep -Eq "(^| )nxtp-[cruh]-${RUN_ID}-s${STEP_N}( |$)"; then
        record "FAIL run_netns_cleanup remaining='$(printf '%s' "${listed}" | grep "nxtp-.*-${RUN_ID}-s${STEP_N}" | tr '\n' ' ')'"
        STEP_FAILED=1
    else
        record "PASS run_netns_cleanup no nxtp-*-${RUN_ID}-s${STEP_N}"
    fi
}

# ---------- upstream ----------

start_upstream() {
    local extra=("$@")
    : >"${EVIDENCE_DIR}/upstream.log"
    timeout 1800 sudo -n "${IP}" netns exec "${NS_U}" python3 "${UPSTREAM_PY}" \
        --bind "${UPSTREAM_ADDR}" --site "${SITE_ADDR}" --dns-answer "${SITE_ADDR}" \
        --log "${EVIDENCE_DIR}/upstream.log" \
        --socks5-log "${EVIDENCE_DIR}/socks5.log" "${extra[@]}" \
        >>"${EVIDENCE_DIR}/upstream.log" 2>&1 &
    UPSTREAM_PID=$!
    sleep 0.6
    if ! ps -p "${UPSTREAM_PID}" >/dev/null 2>&1; then
        record "FAIL upstream_start exited pid=${UPSTREAM_PID}"
        tail -n 20 "${EVIDENCE_DIR}/upstream.log" >&2 || true
        return 1
    fi
    record "upstream_started pid=${UPSTREAM_PID}"
}

stop_upstream() {
    # `UPSTREAM_PID` 是本地 `timeout … sudo …` 包装：只 TERM 包装会留下
    # root 的 sudo/python 子进程（r7 遗留 8 对孤儿即此因）。先按本步
    # upstream.log 唯一匹配 netns 内的 python 本体，再回收包装。
    if [ -n "${NS_U}" ] && [ -n "${EVIDENCE_DIR}" ]; then
        local up_pids pid i
        up_pids="$(timeout 10 sudo -n "${IP}" netns exec "${NS_U}" \
            pgrep -f "upstream\\.py.*--log ${EVIDENCE_DIR}/upstream\\.log" 2>/dev/null || true)"
        for pid in ${up_pids}; do
            timeout 10 sudo -n "${IP}" netns exec "${NS_U}" kill -TERM "${pid}" >/dev/null 2>&1 || true
        done
        for i in $(seq 1 30); do
            [ -z "$(timeout 10 sudo -n "${IP}" netns exec "${NS_U}" \
                pgrep -f "upstream\\.py.*--log ${EVIDENCE_DIR}/upstream\\.log" 2>/dev/null || true)" ] && break
            sleep 0.1
        done
        up_pids="$(timeout 10 sudo -n "${IP}" netns exec "${NS_U}" \
            pgrep -f "upstream\\.py.*--log ${EVIDENCE_DIR}/upstream\\.log" 2>/dev/null || true)"
        for pid in ${up_pids}; do
            timeout 10 sudo -n "${IP}" netns exec "${NS_U}" kill -KILL "${pid}" >/dev/null 2>&1 || true
        done
    fi
    if [ -n "${UPSTREAM_PID}" ] && ps -p "${UPSTREAM_PID}" >/dev/null 2>&1; then
        timeout 10 sudo -n "${IP}" netns exec "${NS_U}" kill -TERM "${UPSTREAM_PID}" >/dev/null 2>&1 || true
        local i
        for i in $(seq 1 30); do
            ps -p "${UPSTREAM_PID}" >/dev/null 2>&1 || break
            sleep 0.1
        done
        if ps -p "${UPSTREAM_PID}" >/dev/null 2>&1; then
            timeout 10 sudo -n "${IP}" netns exec "${NS_U}" kill -KILL "${UPSTREAM_PID}" >/dev/null 2>&1 || true
        fi
        wait "${UPSTREAM_PID}" 2>/dev/null || true
    fi
    UPSTREAM_PID=""
}

# ---------- nexusd ----------

start_nexusd() {
    local cfg="$1" logfile="$2"
    shift 2
    : >"${logfile}"
    CURRENT_CFG="${cfg}"
    timeout 1800 sudo -n "${IP}" netns exec "${NS_R}" env "$@" "${NEXUSD}" "${cfg}" \
        >"${logfile}" 2>&1 &
    NEXUSD_PID=$!
    local i
    for i in $(seq 1 100); do
        if grep -q '"verdict":"READY"' "${logfile}" 2>/dev/null; then
            record "nexusd_ready pid=${NEXUSD_PID}"
            return 0
        fi
        if ! ps -p "${NEXUSD_PID}" >/dev/null 2>&1; then
            record "FAIL nexusd_exited_before_ready pid=${NEXUSD_PID}"
            STEP_FAILED=1
            return 1
        fi
        sleep 0.1
    done
    record "FAIL nexusd_ready_timeout pid=${NEXUSD_PID}"
    STEP_FAILED=1
    return 1
}

start_nexusd_nonroot() {
    local cfg="$1" logfile="$2"
    shift 2
    : >"${logfile}"
    CURRENT_CFG="${cfg}"
    timeout 600 sudo -n "${IP}" netns exec "${NS_R}" setpriv \
        --reuid="$(id -u)" --regid="$(id -g)" --clear-groups \
        env "$@" "${NEXUSD}" "${cfg}" >"${logfile}" 2>&1 &
    NEXUSD_PID=$!
    local i
    for i in $(seq 1 100); do
        if grep -q '"verdict":"READY"' "${logfile}" 2>/dev/null; then
            record "nexusd_nonroot_ready pid=${NEXUSD_PID}"
            return 0
        fi
        if ! ps -p "${NEXUSD_PID}" >/dev/null 2>&1; then
            record "FAIL nexusd_nonroot_exited_before_ready pid=${NEXUSD_PID}"
            STEP_FAILED=1
            return 1
        fi
        sleep 0.1
    done
    record "FAIL nexusd_nonroot_ready_timeout pid=${NEXUSD_PID}"
    STEP_FAILED=1
    return 1
}

# P5-d：按唯一 config 路径定位 nexusd **本体** PID（不含 timeout/sudo 包装）。
#
# netns 只切换网络命名空间、共享 PID 命名空间，因此宿主 PID 可直接 kill。
# nexusd 的 argv 为 `<NEXUSD> <cfg>`；`pgrep -f` 用锚定前缀匹配，
# 不会命中 `timeout/sudo/ip netns exec` 包装（它们 argv 不以 NEXUSD 开头）。
nexusd_pids_for_cfg() {
    local cfg="$1"
    [ -n "${cfg}" ] && [ -n "${NS_R}" ] || return 0
    timeout 10 sudo -n "${IP}" netns exec "${NS_R}" \
        pgrep -f "^${NEXUSD} ${cfg}( |$)" 2>/dev/null || true
}

stop_nexusd() {
    local cfg="${CURRENT_CFG}" pids pid i
    # 1) 先杀 netns 内的 nexusd 本体：向 `timeout 1800 sudo …` 包装发 TERM
    #    不会被 sudo 转发给 nexusd，会留下 root 孤儿并占用 LocalAPI 18080。
    if [ -n "${cfg}" ]; then
        pids="$(nexusd_pids_for_cfg "${cfg}")"
        if [ -n "${pids}" ]; then
            record "nexusd_stop target=$(printf '%s' "${pids}" | tr '\n' ',')"
            for pid in ${pids}; do
                timeout 10 sudo -n "${IP}" netns exec "${NS_R}" kill -TERM "${pid}" >/dev/null 2>&1 || true
            done
            for i in $(seq 1 100); do
                [ -z "$(nexusd_pids_for_cfg "${cfg}")" ] && break
                sleep 0.1
            done
            pids="$(nexusd_pids_for_cfg "${cfg}")"
            for pid in ${pids}; do
                timeout 10 sudo -n "${IP}" netns exec "${NS_R}" kill -KILL "${pid}" >/dev/null 2>&1 || true
            done
        fi
    fi
    # 2) 回收本地包装进程（timeout/sudo 是当前 shell 的子进程）。
    if [ -n "${NEXUSD_PID}" ] && ps -p "${NEXUSD_PID}" >/dev/null 2>&1; then
        kill -TERM "${NEXUSD_PID}" 2>/dev/null || true
        for i in $(seq 1 100); do
            ps -p "${NEXUSD_PID}" >/dev/null 2>&1 || break
            sleep 0.1
        done
        if ps -p "${NEXUSD_PID}" >/dev/null 2>&1; then
            kill -KILL "${NEXUSD_PID}" 2>/dev/null || true
        fi
        wait "${NEXUSD_PID}" 2>/dev/null || true
    fi
    NEXUSD_PID=""
}

# ---------- LocalAPI / 客户端 ----------

stats_json() {
    local out="$1" token=""
    if [ -n "${CURRENT_CFG}" ]; then
        token="$(timeout 10 sudo -n "${IP}" netns exec "${NS_R}" \
            cat "${CURRENT_CFG}/localapi.token" 2>/dev/null || true)"
    fi
    if [ -n "${token}" ]; then
        timeout 10 sudo -n "${IP}" netns exec "${NS_R}" \
            curl -sS --max-time 8 -H "Authorization: Bearer ${token}" \
            "${LOCALAPI}" >"${out}" 2>"${out}.err"
    else
        timeout 10 sudo -n "${IP}" netns exec "${NS_R}" \
            curl -sS --max-time 8 "${LOCALAPI}" >"${out}" 2>"${out}.err"
    fi
}

stats_value() {
    local path="$1" expr="$2"
    jq -r "${expr} | select(. != null)" "${path}" 2>/dev/null || true
}

# `stats_value` 自检：null 输出空，false 必须原样输出 `false`，缺失键输出空。
stats_value_selftest() {
    local fixture status=0 actual
    fixture="$(mktemp)"
    printf '%s\n' '{"flag":false,"nil":null,"num":0}' >"${fixture}"
    actual="$(stats_value "${fixture}" '.flag')"
    if [ "${actual}" != "false" ]; then
        printf 'stats_value selftest FAIL: false key -> %q (want false)\n' "${actual}" >&2
        status=1
    fi
    actual="$(stats_value "${fixture}" '.missing')"
    if [ -n "${actual}" ]; then
        printf 'stats_value selftest FAIL: missing key -> %q (want empty)\n' "${actual}" >&2
        status=1
    fi
    actual="$(stats_value "${fixture}" '.nil')"
    if [ -n "${actual}" ]; then
        printf 'stats_value selftest FAIL: null key -> %q (want empty)\n' "${actual}" >&2
        status=1
    fi
    rm -f "${fixture}"
    if [ "${status}" -eq 0 ]; then
        printf 'stats_value selftest PASS\n'
    fi
    return "${status}"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    stats_value_selftest
fi

wait_tproxy_state() {
    local want="$1" tries="${2:-100}" i state poll="${EVIDENCE_DIR}/status.poll.json"
    for i in $(seq 1 "${tries}"); do
        stats_json "${poll}" >/dev/null 2>&1 || true
        state="$(stats_value "${poll}" '.tproxy.state')"
        [ "${state}" = "${want}" ] && return 0
        sleep 0.1
    done
    STEP_FAILED=1
    return 1
}

client_curl() {
    local url="$1" max_time="${2:-10}"
    timeout $((max_time + 2)) sudo -n "${IP}" netns exec "${NS_C}" \
        curl -sS --max-time "${max_time}" --retry 2 --retry-delay 1 "${url}"
}

client_dig() {
    local name="${1:-example.nexus}"
    timeout 3 sudo -n "${IP}" netns exec "${NS_C}" \
        dig +time=2 +tries=1 @${UPSTREAM_ADDR} "${name}" A +short
}

router_ss() {
    local out="$1"
    timeout 10 sudo -n "${IP}" netns exec "${NS_R}" ss -tnp >"${out}" 2>&1 || true
}

start_tcpdump() {
    local filter="$1" out="$2" count="${3:-1}" secs="${4:-20}"
    : >"${out}"
    timeout "${secs}" sudo -n "${IP}" netns exec "${NS_R}" \
        tcpdump -i any -nn -l -c "${count}" "${filter}" >"${out}" 2>&1 &
    TCPDUMP_PID=$!
    sleep 0.4
}

stop_tcpdump() {
    if [ -n "${TCPDUMP_PID}" ] && ps -p "${TCPDUMP_PID}" >/dev/null 2>&1; then
        timeout 10 sudo -n "${IP}" netns exec "${NS_R}" kill -TERM "${TCPDUMP_PID}" >/dev/null 2>&1 || true
        local i
        for i in $(seq 1 30); do
            ps -p "${TCPDUMP_PID}" >/dev/null 2>&1 || break
            sleep 0.1
        done
        ps -p "${TCPDUMP_PID}" >/dev/null 2>&1 && \
            timeout 10 sudo -n "${IP}" netns exec "${NS_R}" kill -KILL "${TCPDUMP_PID}" >/dev/null 2>&1 || true
        wait "${TCPDUMP_PID}" 2>/dev/null || true
    fi
    TCPDUMP_PID=""
}

# ---------- 配置 ----------

write_daemon_toml() {
    local dir="$1" tun_enabled="$2" flow_enabled="${3:-auto}" default_route="${4:-false}"
    mkdir -p "${dir}/state" "${dir}/n2"
    chmod 777 "${dir}/state" "${dir}/n2" 2>/dev/null || true
    cat >"${dir}/daemon.toml" <<EOF
[localapi]
addr = "127.0.0.1:18080"

[tun]
enabled = ${tun_enabled}
default_route = ${default_route}
exclude_server_routes = true

[flow_sessions]
enabled = "${flow_enabled}"
EOF
}

write_tproxy_yaml_direct() {
    local dir="$1" backend="${2:-iptables}"
    cat >"${dir}/proxy.yaml" <<EOF
schema_version: 1
inbounds:
  - tag: tp-in
    kind: tproxy
    listen: 0.0.0.0:7895
    backend: ${backend}
rules:
  - tag: rule-match
    kind: match
    match: ""
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: direct
    kind: direct
    locator: ""
EOF
}

write_tproxy_yaml_proxy() {
    local dir="$1" backend="${2:-iptables}" on_path_failure="${3:-block}"
    cat >"${dir}/proxy.yaml" <<EOF
schema_version: 1
inbounds:
  - tag: tp-in
    kind: tproxy
    listen: 0.0.0.0:7895
    backend: ${backend}
    on_path_failure: ${on_path_failure}
rules:
  - tag: ip-cidr-p1
    kind: ip_cidr
    match: ${SITE_ADDR}/32
    action:
      - kind: select_outbound
        tag: p1
  - tag: rule-match
    kind: match
    match: ""
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: p1
    kind: socks5
    locator: ${UPSTREAM_ADDR}:1080
  - tag: direct
    kind: direct
    locator: ""
EOF
}

write_tproxy_yaml_external() {
    local dir="$1" on_capture_failure="${2:-block}"
    cat >"${dir}/proxy.yaml" <<EOF
schema_version: 1
inbounds:
  - tag: tp-in
    kind: tproxy
    listen: 0.0.0.0:7895
    backend: external
    on_capture_failure: ${on_capture_failure}
rules:
  - tag: rule-match
    kind: match
    match: ""
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: direct
    kind: direct
    locator: ""
EOF
}

write_tun_yaml() {
    local dir="$1" backend="${2:-iptables}"
    cat >"${dir}/proxy.yaml" <<EOF
schema_version: 1
inbounds:
  - tag: tun-in
    kind: tun
    name: nexustun0
    mtu: 1500
    address: 10.99.0.1/24
    default_route: false
    sessions: auto
rules:
  - tag: ip-cidr-p1
    kind: ip_cidr
    match: ${SITE_ADDR}/32
    action:
      - kind: select_outbound
        tag: p1
  - tag: rule-match
    kind: match
    match: ""
    action:
      - kind: select_outbound
        tag: direct
outbounds:
  - tag: p1
    kind: socks5
    locator: ${UPSTREAM_ADDR}:1080
  - tag: direct
    kind: direct
    locator: ""
EOF
}

# ---------- 清理 ----------

finish_step() {
    stop_tcpdump
    stop_nexusd
    stop_upstream
    cleanup_netns
    if [ "${ORDERLY_DONE}" -eq 0 ]; then
        cleanup_host_alias
    fi
}

on_exit() {
    set +e
    finish_step
}

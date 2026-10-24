#!/usr/bin/env bash
# 单 cell 编排（D2.5）：端口门禁 → 参照端 → dumpcap → probe → finalize。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=lib/ports.sh
. "$SCRIPT_DIR/lib/ports.sh"
# shellcheck source=lib/pcap.sh
. "$SCRIPT_DIR/lib/pcap.sh"
MATRIX="$SCRIPT_DIR/cell-matrix.json"

PROTOCOL="" VARIANT="" CELL="" RUN_DIR="" PROBE_BIN="" REF_BIN=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --protocol) PROTOCOL="$2"; shift 2 ;;
    --variant) VARIANT="$2"; shift 2 ;;
    --cell) CELL="$2"; shift 2 ;;
    --run-dir) RUN_DIR="$2"; shift 2 ;;
    --probe-bin) PROBE_BIN="$2"; shift 2 ;;
    --ref-bin) REF_BIN="$2"; shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done
export RUN_DIR PROBE_BIN REF_BIN
: "${RUN_DIR:?--run-dir required}"
: "${PROBE_BIN:?--probe-bin required}"
: "${REF_BIN:?--ref-bin required}"
: "${PROTOCOL:?--protocol required}"
: "${VARIANT:?--variant required}"
: "${CELL:?--cell required}"

ENTRY="$(python3 - "$MATRIX" "$PROTOCOL" "$VARIANT" "$CELL" "$SCRIPT_DIR/lib" <<'PYEOF'
import json,sys
matrix,proto,variant,cell,libdir=sys.argv[1:6]
sys.path.insert(0, libdir)
import labels
data=json.load(open(matrix))
for e in data["cells"]:
    if (labels.label("protocol", e["protocol"])==proto
            and labels.label("variant", e["variant"])==variant
            and labels.label("cell", e["cell"])==cell):
        print(json.dumps(e)); sys.exit(0)
print(f"no matrix entry for {proto}/{variant}/{cell}", file=sys.stderr); sys.exit(2)
PYEOF
)"
REF_VARIANT="$(jq -r '.ref_variant // empty' <<<"$ENTRY")"
IMPL="$(jq -r '.impl // empty' <<<"$ENTRY")"
T2="$(jq -r '.t2' <<<"$ENTRY")"
SYNTHETIC="$(jq -r '.synthetic' <<<"$ENTRY")"
DIAG="$(jq -r '.diag' <<<"$ENTRY")"
TARGET_PORT="$(jq -r '.target_port' <<<"$ENTRY")"

TEMPLATE="$REPO_ROOT/docs/protocols/interop/probe-config/${PROTOCOL}-${VARIANT}-${CELL}.json"
[[ -f "$TEMPLATE" ]] || { echo "missing template $TEMPLATE" >&2; exit 2; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BASE="${PROTOCOL}-${VARIANT}-${CELL}-${STAMP}-$$"
EVID="$RUN_DIR/evidence"
STAGE="$EVID/staging"
mkdir -p "$STAGE" "$EVID/probe-config" "$RUN_DIR/logs"
CONFIG="$EVID/probe-config/$BASE.json"
export CONFIG
OUT_STAGE="$STAGE/$BASE.probe.json"
STDOUT_STAGE="$STAGE/$BASE.stdout.jsonl"
STDERR_STAGE="$STAGE/$BASE.stderr.log"
PCAP_STAGE="$STAGE/$BASE.pcap"
PCAP_STATS="$STAGE/$BASE.pcap.stats.txt"
PROGRESS="$RUN_DIR/analysis/progress.tsv"
mkdir -p "$RUN_DIR/analysis"
[[ -f "$PROGRESS" ]] || printf 'utc\tprotocol\tvariant\tcell\tevidence_id\tverdict\terror\tpcap_packets\n' > "$PROGRESS"

REF_STARTED=0
PCAP_STARTED=0
cleanup() {
  local rc=$?
  set +e
  if [[ "$PCAP_STARTED" == "1" ]]; then pcap_stop "$PCAP_STAGE" "$PCAP_STATS" >/dev/null 2>&1; fi
  if [[ "$REF_STARTED" == "1" ]]; then
    "$SCRIPT_DIR/lib/ref.sh" stop_ref "$REF_VARIANT" >/dev/null 2>&1 || true
  fi
  exit $rc
}
trap cleanup EXIT INT TERM

ports_snapshot "pre-cell-$BASE" >/dev/null

env_block() {
  local reason="$1"
  local id="PIV-${PROTOCOL}-${VARIANT}-${CELL}-${STAMP}-001"
  local dir="$EVID/${PROTOCOL}/${VARIANT}/${CELL}/$id"
  mkdir -p "$dir"
  python3 - "$dir/probe.json" "$id" "$PROTOCOL" "$VARIANT" "$CELL" "$reason" "$ENTRY" <<'PY'
import json,sys,datetime,os
out,evid,proto,variant,cell,reason,entry=sys.argv[1:8]
e=json.loads(entry)
cfg_path=os.environ.get("CONFIG_PATH","")
now=datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
ev={"schema_version":1,"evidence_id":evid,"run_id":"protocol-interop-verification",
 "protocol":e["protocol"],"variant":e["variant"],"cell":e["cell"],
 "carrier":e["carrier"],"scope":e["scope"],"verdict":"Blocked",
 "started_at_utc":now,"duration_ms":0,
 "nexus":{"commit":os.environ.get("NEXUS_COMMIT",""),"binary_sha256":"","cargo_target_dir":""},
 "reference":{"implementation":"sing-box","version":"1.13.16","binary_sha256":"","config_sha256":""},
 "effective_config_sha256":"","metrics":{},
 "error":{"class":"E_NETWORK_ENV","message":reason,"first_failure_artifact":None},
 "notes":["environment gate failed"],"artifacts":[]}
open(out,"w").write(json.dumps(ev,indent=2)+"\n")
PY
  printf '%s\t%s\t%s\t%s\t%s\tBlocked\tE_NETWORK_ENV\t0\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PROTOCOL" "$VARIANT" "$CELL" "$id" >> "$PROGRESS"
  echo "ENV BLOCKED: $reason (evidence=$dir)" >&2
  exit 2
}

# 端口门禁：目标端 26200-26203 + 参照端口
for p in 26200 26201 26202 26203; do
  ports_assert_free "$p" || env_block "target port $p busy"
done
if [[ -n "$REF_VARIANT" ]]; then
  REF_PORT="$(python3 - "$EVID/ref-config/$REF_VARIANT.json" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
ib=c["inbounds"][0]
print(ib.get("listen_port") or ib.get("port"))
PY
)"
  ports_assert_free "$REF_PORT" || env_block "reference port $REF_PORT busy"
fi

python3 "$SCRIPT_DIR/lib/render_probe_config.py" --template "$TEMPLATE" --out "$CONFIG" --run-dir "$RUN_DIR" >/dev/null

if [[ -n "$REF_VARIANT" ]]; then
  BPF="port $REF_PORT"
  if [[ "$REF_VARIANT" == "trojan-fallback" ]]; then BPF="$BPF or port 26203"; fi
  MAX_KB=0; [[ "$T2" == "true" ]] && MAX_KB=102400
  pcap_start lo "$BPF" "$PCAP_STAGE" "$MAX_KB" >/dev/null
  PCAP_STARTED=1
  # dumpcap 打开文件到真正进入捕获有短窗口；先起抓包再起参照端，并留 settle 时间，
  # 避免秒级 F 格抓到 0 包（否则会被误降 E_EVIDENCE_GAP）。
  sleep 0.6
  "$SCRIPT_DIR/lib/ref.sh" start_ref "$REF_VARIANT" --impl "${IMPL:-sing-box}" > "$STAGE/$BASE.ref-start.txt" 2>&1
  REF_STARTED=1
  REF_PORT="$(sed -n 's/^port=//p' "$RUN_DIR/evidence/ref/$REF_VARIANT/start.txt")"
fi

TIMEOUT_S=200
CELL_MS="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["timeouts"]["cell_ms"])' "$CONFIG")"
TIMEOUT_S="$(( CELL_MS / 1000 + 20 ))"

export PIV_NEXUS_COMMIT="${PIV_NEXUS_COMMIT:-$(cd "$REPO_ROOT" && git rev-parse HEAD)}"
export PIV_NEXUS_TARGET_DIR="${CARGO_TARGET_DIR:-}"
if [[ -n "$REF_VARIANT" ]]; then
  export PIV_REF_IMPLEMENTATION="${IMPL:-sing-box}"
  export PIV_REF_CONFIG_SHA256="$(cat "$EVID/ref-config/$REF_VARIANT.json.sha256")"
  if [[ "${IMPL:-sing-box}" == "xray" ]]; then
    export PIV_REF_VERSION="$(awk '{print $2}' "$EVID/ref/xray-version.txt" | head -1)"
    export PIV_REF_BIN_SHA256="$(sha256sum "$RUN_DIR/ref/xray" | awk '{print $1}')"
  else
    export PIV_REF_VERSION="$(awk '{print $3}' "$EVID/ref/sing-box-version.txt" | head -1)"
    export PIV_REF_BIN_SHA256="$(sha256sum "$REF_BIN" | awk '{print $1}')"
  fi
else
  export PIV_REF_IMPLEMENTATION="none"
  export PIV_REF_VERSION="none"
  export PIV_REF_BIN_SHA256="none"
  export PIV_REF_CONFIG_SHA256="none"
fi

set +e
timeout -k 5 "${TIMEOUT_S}s" "$PROBE_BIN" --config "$CONFIG" --out "$OUT_STAGE" \
  --evidence-root "$EVID" > "$STDOUT_STAGE" 2> "$STDERR_STAGE"
PROBE_RC=$?
set -e

if [[ "$PCAP_STARTED" == "1" ]]; then
  pcap_stop "$PCAP_STAGE" "$PCAP_STATS" >/dev/null
  PCAP_STARTED=0
fi

if [[ ! -f "$OUT_STAGE" ]]; then
  # probe 未产出证据（超时/崩溃）：按判定式落 E_TIMEOUT_HANG / E_TOOL_BUG
  ID="PIV-${PROTOCOL}-${VARIANT}-${CELL}-${STAMP}-001"
  DIR="$EVID/${PROTOCOL}/${VARIANT}/${CELL}/$ID"
  mkdir -p "$DIR"
  if [[ "$PROBE_RC" == "124" || "$PROBE_RC" == "137" ]]; then CLASS="E_TIMEOUT_HANG"; VERDICT="Fail"; else CLASS="E_TOOL_BUG"; VERDICT="Blocked"; fi
  python3 - "$DIR/probe.json" "$ID" "$ENTRY" "$CLASS" "$VERDICT" "$PROBE_RC" "$STDOUT_STAGE" "$STDERR_STAGE" <<'PY'
import json,sys,datetime,shutil,os
out,evid,entry,cls,verdict,rc,so,se=sys.argv[1:9]
e=json.loads(entry)
cfg=json.load(open(os.environ["CONFIG"]))
now=datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"
ev={"schema_version":1,"evidence_id":evid,"run_id":cfg["run_id"],
 "protocol":e["protocol"],"variant":e["variant"],"cell":e["cell"],
 "carrier":e["carrier"],"scope":e["scope"],"verdict":verdict,
 "started_at_utc":now,"duration_ms":0,
 "nexus":{"commit":os.environ.get("PIV_NEXUS_COMMIT",""),"binary_sha256":"","cargo_target_dir":os.environ.get("PIV_NEXUS_TARGET_DIR","")},
 "reference":{"implementation":os.environ.get("PIV_REF_IMPLEMENTATION","none"),
   "version":os.environ.get("PIV_REF_VERSION","none"),
   "binary_sha256":os.environ.get("PIV_REF_BIN_SHA256","none"),
   "config_sha256":os.environ.get("PIV_REF_CONFIG_SHA256","none")},
 "effective_config_sha256":"","metrics":{},"error":{"class":cls,"message":f"probe exit {rc} without evidence","first_failure_artifact":"probe.stdout.jsonl"},
 "notes":[],"artifacts":[]}
open(out,"w").write(json.dumps(ev,indent=2)+"\n")
if os.path.exists(so): shutil.move(so, os.path.join(os.path.dirname(out),"probe.stdout.jsonl"))
if os.path.exists(se): shutil.move(se, os.path.join(os.path.dirname(out),"probe.stderr.log"))
PY
  if [[ "$PCAP_STARTED" == "0" && -s "$PCAP_STAGE" ]]; then cp "$PCAP_STAGE" "$DIR/pcap.pcap"; fi
  [[ -s "$PCAP_STATS" ]] && cp "$PCAP_STATS" "$DIR/pcap.stats.txt"
  echo "probe produced no evidence rc=$PROBE_RC -> $VERDICT/$CLASS" >&2
  exit "$PROBE_RC"
fi

EVIDENCE_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["evidence_id"])' "$OUT_STAGE")"
CELL_DIR="$EVID/${PROTOCOL}/${VARIANT}/${CELL}/$EVIDENCE_ID"
mkdir -p "$CELL_DIR"
mv "$OUT_STAGE" "$CELL_DIR/probe.json"
[[ -f "$STDOUT_STAGE" ]] && mv "$STDOUT_STAGE" "$CELL_DIR/probe.stdout.jsonl"
[[ -f "$STDERR_STAGE" ]] && mv "$STDERR_STAGE" "$CELL_DIR/probe.stderr.log"
if [[ -s "$PCAP_STAGE" ]]; then mv "$PCAP_STAGE" "$CELL_DIR/pcap.pcap"; fi
[[ -s "$PCAP_STATS" ]] && mv "$PCAP_STATS" "$CELL_DIR/pcap.stats.txt"
{
  echo "protocol=$PROTOCOL variant=$VARIANT cell=$CELL"
  echo "evidence_id=$EVIDENCE_ID"
  echo "probe_rc=$PROBE_RC"
  echo "ref_variant=${REF_VARIANT:-none}"
  echo "config=$CONFIG"
  echo "config_sha256=$(sha256sum "$CONFIG" | awk '{print $1}')"
  echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$CELL_DIR/cell.log"

REF_LOG=""
if [[ -n "$REF_VARIANT" && -f "$EVID/ref/$REF_VARIANT/stdout.log" ]]; then
  REF_LOG="$EVID/ref/$REF_VARIANT/stdout.log"
fi
set +e
FINAL_ARGS=(--probe-json "$CELL_DIR/probe.json" --cell-dir "$CELL_DIR" --evidence-root "$EVID"
  --pcap "$CELL_DIR/pcap.pcap" --pcap-stats "$CELL_DIR/pcap.stats.txt"
  --cell "$CELL" --cell-log "$CELL_DIR/probe.stdout.jsonl" --ref-log "$REF_LOG")
if [[ "$SYNTHETIC" == "true" ]]; then FINAL_ARGS+=(--synthetic); fi
python3 "$SCRIPT_DIR/lib/finalize.py" "${FINAL_ARGS[@]}" >/dev/null 2>&1
FINAL_RC=$?
set -e
if [[ "$FINAL_RC" != "0" ]]; then echo "finalize failed" >&2; exit 3; fi

VERDICT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["verdict"])' "$CELL_DIR/probe.json")"
ERR="$(python3 -c 'import json,sys;e=json.load(open(sys.argv[1]));print((e.get("error") or {}).get("class",""))' "$CELL_DIR/probe.json")"
PACKETS="$(sed -n 's/^packets=//p' "$CELL_DIR/pcap.stats.txt" 2>/dev/null | head -1)"
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PROTOCOL" "$VARIANT" "$CELL" "$EVIDENCE_ID" "$VERDICT" "$ERR" "${PACKETS:-0}" >> "$PROGRESS"
echo "cell $PROTOCOL/$VARIANT/$CELL -> $VERDICT ${ERR:-} (evidence $EVIDENCE_ID)"
exit "$PROBE_RC"

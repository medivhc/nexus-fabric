#!/usr/bin/env bash
# E4 real-machine window: register, run, release (spec §17.1 / V9–V11).
# `--dry-run` only prints the plan and touches nothing.
set -u
RUN=${RUN:-/home/appen/pipeline-runs/nat-traversal-implementation}
ID=${WINDOW_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
MODE=${1:-}
if [ "$MODE" = "--dry-run" ]; then
  cat <<PLAN
window dry-run:
  id: $ID
  nodes: xc-pc-linux, SH-YF-CX-PC, Hermes
  purpose: AC-13 relay-first -> direct -> 10 MiB chunked SHA-256 + AC-8 fallback drill
  steps: preflight -> register node_windows -> start A/B nexusd -> relay 1MiB -> direct wait
         -> 10 MiB (64 KiB chunks, re-read active_conn) -> DROP direct -> 4s fallback -> 1 MiB
  evidence: $RUN/evidence/e4-real/$ID/
  max: 90min (retry <=60min, <=2 windows)
PLAN
  exit 0
fi
mkdir -p "$RUN/evidence/e4-real/$ID"
bash "$(dirname "$0")/preflight.sh" --json > "$RUN/evidence/e4-real/$ID/preflight.json" 2>&1
rc=$?
echo "WINDOW_START $ID nodes=xc-pc-linux,SH-YF-CX-PC,Hermes"
echo "{\"nodes\":[\"xc-pc-linux\",\"SH-YF-CX-PC\",\"Hermes\"],\"start\":\"$(date -u +%FT%TZ)\",\"planned_end\":null,\"run\":\"nat-traversal-implementation\",\"purpose\":\"AC-13 + AC-8 fallback drill\",\"holder\":\"nat-traversal\",\"status\":\"started\",\"id\":\"$ID\"}" >> "$RUN/node-windows.json"
if [ $rc -ne 0 ]; then
  echo "WINDOW_END $ID ENV_NOT_READY"
  exit $rc
fi
# Placeholder: real execution requires the daemon/turn/transfer harness on all nodes.
echo "WINDOW_END $ID BLOCKED_NOT_IMPLEMENTED"
exit 2

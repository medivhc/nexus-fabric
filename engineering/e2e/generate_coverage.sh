#!/usr/bin/env bash
# generate_coverage.sh — E2E acceptance coverage matrix generator (feature 004)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
EVI_DIR=".evidence/e2e-acceptance"
mkdir -p "$EVI_DIR"
LIST_JSON="$EVI_DIR/${RUN_ID}-scenario-list.json"
cargo run --quiet -p nexus-harness -- scenario list --json > "$LIST_JSON" 2>/dev/null
python3 "$REPO_ROOT/engineering/e2e/_render_coverage.py" "$LIST_JSON" "$REPO_ROOT" "$RUN_ID"

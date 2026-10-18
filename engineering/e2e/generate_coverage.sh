#!/usr/bin/env bash
# generate_coverage.sh — E2E acceptance coverage matrix generator (feature 004)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
EVI_DIR=".evidence/e2e-acceptance"
mkdir -p "$EVI_DIR"
LIST_JSON="$EVI_DIR/${RUN_ID}-scenario-list.json"
# 不要把 stderr 丢进 /dev/null：曾因并发 cargo 占用 target/debug/nexus-harness.exe
# 报 "拒绝访问 (os error 5)"，被 2>/dev/null 吞掉后看起来像成功，
# 产出的是一份空/陈旧矩阵（2026-10-18 审计发现）。fail-fast，宁可不生成。
if ! cargo run --quiet -p nexus-harness -- scenario list --json > "$LIST_JSON"; then
    echo "generate_coverage: scenario list 失败（cargo 编译/运行错误），未生成矩阵" >&2
    echo "  中间产物保留在 $LIST_JSON 供排查" >&2
    exit 1
fi
# cargo 失败时 stdout 可能为空或含编译噪声，导致 JSON 解析静默出错——先验一下。
if ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$LIST_JSON" 2>/dev/null; then
    echo "generate_coverage: $LIST_JSON 不是合法 JSON，未生成矩阵" >&2
    exit 1
fi
python3 "$REPO_ROOT/engineering/e2e/_render_coverage.py" "$LIST_JSON" "$REPO_ROOT" "$RUN_ID"

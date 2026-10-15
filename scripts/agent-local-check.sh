#!/usr/bin/env bash
# agent-local-check.sh — Agent 推送前的分级本地预检
#
# 目的：
#   云端 agent 在任意沙箱写代码后、推送前，先做轻量本地预检，
#   避免把编译错误直接推到 CI 浪费 5-15 分钟反馈周期。
#
# 分级：
#   L1 cargo check     — 语法/import/类型/借用检查（快，30s-2min）
#   L2 cargo clippy    — 潜在 bug + lint（-D warnings）
#   L3 cargo build     — 链接错误（FFI/平台代码；--full 模式才跑）
#   fmt --check        — 格式检查
#
# 用法：
#   ./scripts/agent-local-check.sh <crate>           # L1 + L2 + fmt
#   ./scripts/agent-local-check.sh <crate> --full    # 追加 L3 build
#   ./scripts/agent-local-check.sh                   # 自动检测 diff 中的 crate
#
# 退出码：
#   0  = 全部通过，可推送
#   非0 = 预检失败，修复后重试

set -euo pipefail

# 彩色输出（非 TTY 自动降级）
if [ -t 1 ]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; NC=''
fi

ok()   { printf "${GREEN}[PASS]${NC} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${NC} %s\n" "$*"; }
info() { printf "${YELLOW}[..]${NC} %s\n" "$*"; }

# --- 参数解析 ---
CRATE="${1:-}"
MODE="${2:-fast}"

if [ -z "$CRATE" ]; then
  info "未指定 crate，自动检测 git diff 中改动的 crate..."
  CRATE=$(git diff --name-only HEAD~1 2>/dev/null \
    | sed -n 's|^crates/\([^/]*\)/.*|\1|p' \
    | sort -u | head -1)
  if [ -z "$CRATE" ]; then
    fail "无法自动检测 crate，请显式指定: $0 <crate>"
    exit 2
  fi
  info "检测到 crate: ${CRATE}"
fi

OVERALL=0

# --- L1: cargo check ---
info "L1: cargo check -p ${CRATE} --all-targets"
set +e
cargo check -p "${CRATE}" --all-targets 2>&1 | tee /tmp/agent-check-l1.log
L1_RC=${PIPESTATUS[0]}
set -e
if [ "${L1_RC}" -eq 0 ]; then
  ok "cargo check 通过"
else
  fail "cargo check 失败（exit ${L1_RC}），见 /tmp/agent-check-l1.log"
  OVERALL=$((OVERALL + 1))
fi

# --- L2: cargo clippy ---
info "L2: cargo clippy -p ${CRATE} --all-targets -- -D warnings"
set +e
cargo clippy -p "${CRATE}" --all-targets -- -D warnings 2>&1 | tee /tmp/agent-check-l2.log
L2_RC=${PIPESTATUS[0]}
set -e
if [ "${L2_RC}" -eq 0 ]; then
  ok "clippy 通过（-D warnings）"
else
  fail "clippy 失败（exit ${L2_RC}），见 /tmp/agent-check-l2.log"
  OVERALL=$((OVERALL + 1))
fi

# --- fmt --check ---
info "fmt: cargo fmt -p ${CRATE} -- --check"
set +e
cargo fmt -p "${CRATE}" -- --check 2>&1 | tee /tmp/agent-check-fmt.log
FMT_RC=${PIPESTATUS[0]}
set -e
if [ "${FMT_RC}" -eq 0 ]; then
  ok "fmt --check 通过"
else
  fail "fmt --check 失败（exit ${FMT_RC}），见 /tmp/agent-check-fmt.log"
  OVERALL=$((OVERALL + 1))
fi

# --- L3: cargo build（--full 模式）---
if [ "$MODE" = "--full" ]; then
  info "L3: cargo build -p ${CRATE} --all-targets"
  set +e
  cargo build -p "${CRATE}" --all-targets 2>&1 | tee /tmp/agent-check-l3.log
  L3_RC=${PIPESTATUS[0]}
  set -e
  if [ "${L3_RC}" -eq 0 ]; then
    ok "cargo build 通过"
  else
    fail "cargo build 失败（exit ${L3_RC}），见 /tmp/agent-check-l3.log"
    OVERALL=$((OVERALL + 1))
  fi
else
  info "跳过 L3 build（涉及 FFI/平台代码时请加 --full）"
fi

echo ""
if [ "$OVERALL" -eq 0 ]; then
  ok "本地预检通过，可以推送: ./nexus-sync.sh --push"
else
  fail "本地预检未通过，请修复后重新运行本脚本"
fi
exit "$OVERALL"

# Agent 推送前的分级本地预检
#
# 目的：
#   云端 agent 在任意沙箱写代码后、推送前，先做轻量本地预检，
#   避免把编译错误直接推到 CI 浪费 5-15 分钟反馈周期。
#
# 分级：
#   L1 cargo check     — 语法/import/类型/借用检查（快，30s-2min）
#   L2 cargo clippy    — 潜在 bug + lint（-D warnings）
#   L3 cargo build     — 链接错误（FFI/平台代码；--full 模式才跑）
#   fmt --check        — 格式检查
#
# 用法：
#   ./scripts/agent-local-check.sh <crate>           # L1 + L2 + fmt
#   ./scripts/agent-local-check.sh <crate> --full    # 追加 L3 build
#   ./scripts/agent-local-check.sh                   # 自动检测 diff 中的 crate
#
# 退出码：
#   0  = 全部通过，可推送
#   非0 = 预检失败，修复后重试

set -eu

# 彩色输出（非 TTY 自动降级）
if [ -t 1 ]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; NC=''
fi

ok()   { printf "${GREEN}[PASS]${NC} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${NC} %s\n" "$*"; }
info() { printf "${YELLOW}[..]${NC} %s\n" "$*"; }

# --- 参数解析 ---
CRATE="${1:-}"
MODE="${2:-fast}"

if [ -z "$CRATE" ]; then
  info "未指定 crate，自动检测 git diff 中改动的 crate..."
  CRATE=$(git diff --name-only HEAD~1 2>/dev/null \
    | sed -n 's|^crates/\([^/]*\)/.*|\1|p' \
    | sort -u | head -1)
  if [ -z "$CRATE" ]; then
    fail "无法自动检测 crate，请显式指定: $0 <crate>"
    exit 2
  fi
  info "检测到 crate: ${CRATE}"
fi

OVERALL=0

# --- L1: cargo check ---
info "L1: cargo check -p ${CRATE} --all-targets"
if cargo check -p "${CRATE}" --all-targets 2>&1 | tee /tmp/agent-check-l1.log; then
  ok "cargo check 通过"
else
  fail "cargo check 失败，见 /tmp/agent-check-l1.log"
  OVERALL=1
fi

# --- L2: cargo clippy ---
info "L2: cargo clippy -p ${CRATE} --all-targets -- -D warnings"
if cargo clippy -p "${CRATE}" --all-targets -- -D warnings 2>&1 | tee /tmp/agent-check-l2.log; then
  ok "clippy 通过（-D warnings）"
else
  fail "clippy 失败，见 /tmp/agent-check-l2.log"
  OVERALL=1
fi

# --- fmt --check ---
info "fmt: cargo fmt -p ${CRATE} -- --check"
if cargo fmt -p "${CRATE}" -- --check 2>&1 | tee /tmp/agent-check-fmt.log; then
  ok "fmt --check 通过"
else
  fail "fmt --check 失败，见 /tmp/agent-check-fmt.log"
  OVERALL=1
fi

# --- L3: cargo build（--full 模式）---
if [ "$MODE" = "--full" ]; then
  info "L3: cargo build -p ${CRATE} --all-targets"
  if cargo build -p "${CRATE}" --all-targets 2>&1 | tee /tmp/agent-check-l3.log; then
    ok "cargo build 通过"
  else
    fail "cargo build 失败，见 /tmp/agent-check-l3.log"
    OVERALL=1
  fi
else
  info "跳过 L3 build（涉及 FFI/平台代码时请加 --full）"
fi

echo ""
if [ "$OVERALL" -eq 0 ]; then
  ok "本地预检通过，可以推送: ./nexus-sync.sh --push"
else
  fail "本地预检未通过，请修复后重新运行本脚本"
fi
exit "$OVERALL"
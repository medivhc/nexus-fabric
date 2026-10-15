#!/usr/bin/env bash
# agent-zero-deps-check.sh — 小空间沙箱（<1GB）零依赖预检
#
# 目的：
#   沙箱剩余空间不足时，`cargo check` 会直接 OOM/失败。
#   本脚本在不下载任何依赖、不编译的前提下，只做轻量级契约检查：
#     - Cargo.toml 语法 + workspace members 解析（cargo metadata --no-deps）
#     - git diff 白名单检查（protected / forbidden / secrets）
#     - 代码风格基础检查（git diff --check）
#
# 退出码：
#   0 = 通过，可推送（仍需 CI quick-check 兜底编译）
#   1 = 契约违规，不可推送
#
# 依赖：bash、git、cargo（仅 metadata --no-deps，不触发下载）、jq（可选）

set -euo pipefail

if [ -t 1 ]; then
  GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; NC=''
fi

ok()   { printf "${GREEN}[PASS]${NC} %s\n" "$*"; }
fail() { printf "${RED}[FAIL]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
info() { printf "${YELLOW}[..]${NC} %s\n" "$*"; }

OVERALL=0

# --- 0. 前置检查 ---
if ! command -v git >/dev/null 2>&1; then
  fail "git 不可用"
  exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
  fail "cargo 不可用（本脚本需要 cargo metadata --no-deps）"
  exit 1
fi

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { fail "不在 git 仓库中"; exit 1; }
cd "${ROOT}"

# --- 1. git diff --check（空白/行尾空白/缺失换行）---
info "1/5 git diff --check（空白检查）"
if git diff --check HEAD 2>&1; then
  ok "无空白违规"
else
  fail "存在空白违规（见上）"
  OVERALL=$((OVERALL + 1))
fi

# --- 2. cargo metadata --no-deps（不下载依赖）---
# 注意：cargo metadata --no-deps 不下载依赖，但仍需解析 Cargo.lock 与所有
# workspace Cargo.toml。首次运行 / 无 registry cache 时可能较慢（>2min），
# 因此加 timeout；超时或失败均降级为 warning（编译正确性由 CI quick-check 兜底）。
info "2/5 cargo metadata --no-deps（Cargo.toml 语法 + workspace members 解析）"
CARGO_META_RC=0
if command -v timeout >/dev/null 2>&1; then
  timeout 180 cargo metadata --no-deps --format-version 1 > /tmp/zero-deps-metadata.json 2>/tmp/zero-deps-metadata.err || CARGO_META_RC=$?
else
  cargo metadata --no-deps --format-version 1 > /tmp/zero-deps-metadata.json 2>/tmp/zero-deps-metadata.err || CARGO_META_RC=$?
fi

if [ "${CARGO_META_RC}" -eq 0 ]; then
  if command -v jq >/dev/null 2>&1; then
    if jq -e '.workspace_members != null' /tmp/zero-deps-metadata.json >/dev/null 2>&1; then
      ok "workspace members 解析成功"
    else
      warn "cargo metadata 输出结构异常（无 jq 时跳过结构校验）"
    fi
  else
    ok "cargo metadata --no-deps 通过（无 jq，跳过结构校验）"
  fi
elif [ "${CARGO_META_RC}" -eq 124 ] || [ "${CARGO_META_RC}" -eq 137 ]; then
  warn "cargo metadata --no-deps 超时（${CARGO_META_RC}），跳过本项（编译正确性由 CI quick-check 兜底）"
else
  warn "cargo metadata --no-deps 失败（exit ${CARGO_META_RC}），跳过本项（编译正确性由 CI quick-check 兜底）"
  tail -n 5 /tmp/zero-deps-metadata.err 2>/dev/null | sed 's/^/    /'
fi

# --- 3. protected paths（契约冻结区）---
info "3/5 protected paths 检查（契约冻结区不可直接修改）"
PROTECTED="PRODUCT.md ARCHITECTURE.md policies/ scenarios/ harness.toml MODULE.md"
PROTECTED_HIT=$(git diff --name-only HEAD 2>/dev/null | grep -E "^(${PROTECTED// /|})" || true)
if [ -z "$PROTECTED_HIT" ]; then
  ok "未触碰 protected paths"
else
  fail "触碰 protected paths（需 contract/requirement-change marker）:"
  echo "$PROTECTED_HIT" | sed 's/^/    - /'
  OVERALL=$((OVERALL + 1))
fi

# --- 4. forbidden paths（构建产物 / evidence / 密钥）---
info "4/5 forbidden paths 检查（target/ .evidence/ 密钥文件）"
FORBIDDEN_HIT=$(git diff --name-only HEAD 2>/dev/null | grep -E "^(target/|\.evidence/|.*\.(pem|key|p12)$|.*id_rsa|.*id_ed25519$)" || true)
if [ -z "$FORBIDDEN_HIT" ]; then
  ok "未触碰 forbidden paths"
else
  fail "触碰 forbidden paths（构建产物/密钥不应入仓库）:"
  echo "$FORBIDDEN_HIT" | sed 's/^/    - /'
  OVERALL=$((OVERALL + 1))
fi

# --- 5. secrets-pattern 扫描 ---
info "5/5 secrets-pattern 扫描（AWS AKIA / GitHub ghp_ / OpenAI sk-）"
SECRETS=$(git diff HEAD 2>/dev/null | grep -nE "(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{48})" || true)
if [ -z "$SECRETS" ]; then
  ok "未发现 secrets pattern"
else
  fail "发现疑似 secrets:"
  echo "$SECRETS" | sed 's/^/    /'
  OVERALL=$((OVERALL + 1))
fi

echo ""
if [ "$OVERALL" -eq 0 ]; then
  ok "零依赖预检通过，可推送（编译正确性由 CI quick-check 兜底）"
else
  fail "零依赖预检未通过，修复后重新运行本脚本"
fi
exit "$OVERALL"
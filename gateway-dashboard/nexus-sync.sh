#!/bin/sh
# Nexus 多 Agent 同步+推送包装（AGENTS.md §29.3）：
#   fetch → rebase origin/master → verify --fast → push
#
# 用法：
#   ./nexus-sync.sh                # 同步+验证，不推送（安全检查）
#   ./nexus-sync.sh --push         # 同步+验证+推送
#   ./nexus-sync.sh --branch <ref> # 对指定上游操作（默认 origin/master）
#
# 环境变量：
#   NEXUS_AGENT    证据命名空间（verify-<agent>-<hash>，AGENTS.md §29.2）
#   GIT_PUSH_URL   覆盖 push 远端 URL（CI/临时凭据用；不落盘 remote 配置）
#
# 冲突处理：rebase 中断时提示显式解决（§17 FF/3-way/显式冲突），
# 脚本不会自动丢弃任何已提交工作；只有 `--abort` 显式重置。
set -eu

ROOT="$(git rev-parse --show-toplevel)" || { echo "not inside a git repository" >&2; exit 1; }
cd "$ROOT"

PUSH=0
BRANCH="origin/master"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --push) PUSH=1 ;;
    --branch) BRANCH="${2:?--branch needs a ref}"; shift ;;
    *) echo "usage: $0 [--push] [--branch <ref>]" >&2; exit 2 ;;
  esac
  shift
done

step() { printf '[nexus-sync] %s\n' "$*"; }

step "1/4 fetch"
git fetch origin || { echo "fetch failed (check network/credentials)" >&2; exit 1; }

step "2/4 rebase onto $BRANCH"
if ! git rebase "$BRANCH"; then
  echo "[nexus-sync] rebase conflicts - resolve explicitly (AGENTS.md §17), then:"
  echo "  git add <resolved> && git rebase --continue"
  echo "  (never discard committed work silently; --abort only to reset)"
  exit 1
fi

step "3/4 verify --fast"
if command -v nexus-harness >/dev/null 2>&1; then
  nexus-harness verify --fast
elif command -v cargo >/dev/null 2>&1; then
  cargo run -q -p nexus-harness -- verify --fast
else
  echo "[nexus-sync] WARN: nexus-harness/cargo not found; verify skipped (no evidence produced)" >&2
fi

if [ "$PUSH" -eq 1 ]; then
  step "4/4 push"
  if [ -n "${GIT_PUSH_URL:-}" ]; then
    git push "$GIT_PUSH_URL" "$(git branch --show-current)" 2>/dev/null \
      || git push "$GIT_PUSH_URL" HEAD:master
  else
    git push origin "$(git branch --show-current)"
  fi
else
  echo "[nexus-sync] done (dry run; add --push to push)"
fi

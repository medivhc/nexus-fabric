#!/usr/bin/env bash
# remote-dev-setup.sh — 云端 Agent 远程开发环境一键配置
#
# 目的：
#   云端 agent（Trae / Copilot / opencode 等）不在本地沙箱工作，
#   而是 SSH 到统一远程开发机（xc-pc-linux），确保环境一致性。
#
# 解决：
#   - 各沙箱环境不一致（工具链/系统库/性能）
#   - 无 Docker 权限
#   - Evidence 不可比
#
# 用法：
#   ./scripts/remote-dev-setup.sh --agent-name trae-18
#   ./scripts/remote-dev-setup.sh --agent-name trae-18 --crate nexus-auth
#   ./scripts/remote-dev-setup.sh --agent-name trae-18 --branch agent/remote/trae-18
#
# 前置条件：
#   - SSH 到 xc-pc-linux 已配置（见 DEV-ENV.md）
#   - 远程机上已有 /work/nexus-dev/nexus 克隆
#
# 产出：
#   - 远程机上的独立 worktree: /work/nexus-dev/worktrees/<agent-name>
#   - 独立分支: agent/remote/<agent-name>
#   - 已安装 git hooks
#   - 环境变量: NEXUS_AGENT, CARGO_TARGET_DIR
#
# 依赖：bash ≥ 4（用 ${2:?} 与 set -euo pipefail）；POSIX sh 不兼容。

set -euo pipefail

# 默认值
AGENT_NAME=""
CRATE=""
BRANCH=""
REMOTE_HOST="xc-pc-linux"
REMOTE_BASE="/work/nexus-dev"
REMOTE_REPO="${REMOTE_BASE}/nexus"

# usage [exit_code]
#   默认 exit 0（--help 正常路径）；缺参数时传 2 以区分"用法错误"与"正常帮助"。
usage() {
  local exit_code="${1:-0}"
  cat <<EOF
Usage: $(basename "$0") --agent-name <name> [--crate <crate>] [--branch <ref>]

Options:
  --agent-name <name>   Agent 唯一标识（用于 NEXUS_AGENT 和分支名）
  --crate <crate>       目标 crate（可选，用于上下文获取）
  --branch <ref>        自定义分支名（默认: agent/remote/<agent-name>)
  -h, --help            显示此帮助

Examples:
  $(basename "$0") --agent-name trae-18
  $(basename "$0") --agent-name copilot-22 --crate nexus-auth
  $(basename "$0") --agent-name opencode-31 --branch agent/custom-branch
EOF
  exit "${exit_code}"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --agent-name) AGENT_NAME="${2:?--agent-name needs a value}"; shift 2 ;;
    --crate)      CRATE="${2:?--crate needs a value}"; shift 2 ;;
    --branch)     BRANCH="${2:?--branch needs a value}"; shift 2 ;;
    -h|--help)    usage 0 ;;
    *)            echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$AGENT_NAME" ]; then
  echo "error: --agent-name is required" >&2
  usage 2
fi

# 分支名默认值
if [ -z "$BRANCH" ]; then
  BRANCH="agent/remote/${AGENT_NAME}"
fi

WORKTREE_DIR="${REMOTE_BASE}/worktrees/${AGENT_NAME}"

echo "[remote-dev] Agent:    ${AGENT_NAME}"
echo "[remote-dev] Remote:   ${REMOTE_HOST}"
echo "[remote-dev] Worktree: ${WORKTREE_DIR}"
echo "[remote-dev] Branch:   ${BRANCH}"
echo ""

# 1. 在远程机上创建 worktree
echo "[remote-dev] 1/4 Creating worktree on ${REMOTE_HOST}..."
# 远程脚本用 heredoc 传递；任何中途失败（fetch / worktree add / install hooks）
# 都必须清理掉已创建的 worktree，否则下次运行会因残留目录而再次失败。
ssh "${REMOTE_HOST}" bash -s <<REMOTE
set -euo pipefail

# 中途失败时清理 worktree，避免残留 broken worktree。
# 优先 git worktree remove（同步清理 git 元数据），再 rm -rf 兜底。
trap 'git -C "${REMOTE_REPO}" worktree remove --force "${WORKTREE_DIR}" 2>/dev/null || true; rm -rf "${WORKTREE_DIR}" 2>/dev/null || true' EXIT

cd "${REMOTE_REPO}"

# 确保 origin 最新
git fetch origin

# 如果分支已存在，先删除（幂等）
if git show-ref --verify --quiet "refs/heads/${BRANCH}"; then
  echo "[remote-dev] Branch ${BRANCH} exists, deleting..."
  git branch -D "${BRANCH}"
fi

# 如果 worktree 已存在，先清理
if [ -d "${WORKTREE_DIR}" ]; then
  echo "[remote-dev] Worktree ${WORKTREE_DIR} exists, removing..."
  git worktree remove --force "${WORKTREE_DIR}" 2>/dev/null || true
  rm -rf "${WORKTREE_DIR}"
fi

# 创建新 worktree
git worktree add -b "${BRANCH}" "${WORKTREE_DIR}" origin/master
cd "${WORKTREE_DIR}"

# 安装 git hooks（worktree 会丢 +x）
./.githooks/install.sh

echo "[remote-dev] Worktree created: ${WORKTREE_DIR}"
# 成功路径显式清除 trap，避免误删已建好的 worktree
trap - EXIT
REMOTE

# 2. 设置环境变量并验证
echo ""
echo "[remote-dev] 2/4 Verifying environment..."
ssh "${REMOTE_HOST}" "cd ${WORKTREE_DIR} && \
  export NEXUS_AGENT=${AGENT_NAME} && \
  export CARGO_TARGET_DIR=${WORKTREE_DIR}/target && \
  export RUSTUP_HOME=/work/nexus-dev/.rustup && \
  export CARGO_HOME=/work/nexus-dev/.cargo && \
  export PATH=\${CARGO_HOME}/bin:\${PATH} && \
  echo 'Toolchain:' && rustc --version && cargo --version && \
  echo 'Harness:' && nexus-harness --version 2>/dev/null || cargo run -q -p nexus-harness -- --version 2>/dev/null || echo '(harness will be built on first run)'"

# 3. 获取上下文
echo ""
echo "[remote-dev] 3/4 Fetching context..."
ssh "${REMOTE_HOST}" "cd ${WORKTREE_DIR} && \
  export NEXUS_AGENT=${AGENT_NAME} && \
  export CARGO_TARGET_DIR=${WORKTREE_DIR}/target && \
  export RUSTUP_HOME=/work/nexus-dev/.rustup && \
  export CARGO_HOME=/work/nexus-dev/.cargo && \
  export PATH=\${CARGO_HOME}/bin:\${PATH} && \
  nexus-harness status --json 2>/dev/null || cargo run -q -p nexus-harness -- status --json"

if [ -n "$CRATE" ]; then
  echo ""
  echo "[remote-dev] Target crate: ${CRATE}"
  ssh "${REMOTE_HOST}" "cd ${WORKTREE_DIR} && \
    export NEXUS_AGENT=${AGENT_NAME} && \
    export CARGO_TARGET_DIR=${WORKTREE_DIR}/target && \
    export RUSTUP_HOME=/work/nexus-dev/.rustup && \
    export CARGO_HOME=/work/nexus-dev/.cargo && \
    export PATH=\${CARGO_HOME}/bin:\${PATH} && \
    nexus-harness context ${CRATE} --json 2>/dev/null || echo '(context available after first build)'"
fi

# 4. 输出使用指南
echo ""
echo "[remote-dev] 4/4 Done. Usage:"
echo ""
echo "  # 在远程机上执行所有开发操作:"
echo "  ssh ${REMOTE_HOST} 'cd ${WORKTREE_DIR} && \\"
echo "    export NEXUS_AGENT=${AGENT_NAME} && \\"
echo "    export CARGO_TARGET_DIR=${WORKTREE_DIR}/target && \\"
echo "    export RUSTUP_HOME=/work/nexus-dev/.rustup && \\"
echo "    export CARGO_HOME=/work/nexus-dev/.cargo && \\"
echo "    export PATH=\${CARGO_HOME}/bin:\${PATH} && \\"
echo "    <your command>'"
echo ""
echo "  # 常用命令:"
echo "  ssh ${REMOTE_HOST} 'cd ${WORKTREE_DIR} && export NEXUS_AGENT=${AGENT_NAME} && export CARGO_TARGET_DIR=${WORKTREE_DIR}/target && export RUSTUP_HOME=/work/nexus-dev/.rustup && export CARGO_HOME=/work/nexus-dev/.cargo && export PATH=\${CARGO_HOME}/bin:\${PATH} && nexus-harness verify --fast'"
echo ""
echo "  # 清理（任务完成后）:"
echo "  ssh ${REMOTE_HOST} 'cd ${REMOTE_REPO} && git worktree remove ${WORKTREE_DIR} && git branch -D ${BRANCH}'"
echo ""

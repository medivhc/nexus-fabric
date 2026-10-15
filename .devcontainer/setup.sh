#!/usr/bin/env bash
# .devcontainer/setup.sh — Dev Container 的 Post Create Command。
#
# 目的：
#   - 在 Codespaces / devcontainer 中复现与远程开发机（xc-pc-linux）一致的
#     Rust 工具链（由 rust-toolchain.toml 单一来源锁定，当前 1.98.1）。
#   - 安装系统依赖（与 DEV-ENV.md / ci-verify.yml 对齐）。
#
# 幂等：可重复执行。所有外部下载失败均降级为 warning，不阻断容器启动。

set -euo pipefail

echo "[devcontainer-setup] Rust 工具链与系统依赖安装中..."

# --- 1. Rust 工具链（rustup，版本由 rust-toolchain.toml 单一来源）---
# rust-toolchain.toml 是版本唯一真值（见 AGENTS.md §31.1），
# 这里显式读取 channel，避免硬编码漂移。
if command -v rustc >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1; then
  echo "[devcontainer-setup] Rust 已安装：$(rustc --version 2>/dev/null || echo '?') / $(cargo --version 2>/dev/null || echo '?')"
else
  echo "[devcontainer-setup] 安装 rustup + stable 工具链..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
  sh /tmp/rustup-init.sh -y --default-toolchain none --profile minimal
  rm -f /tmp/rustup-init.sh
fi

# rustup 由 rust-toolchain.toml 自动按需安装 1.98.1（含 rustfmt/clippy/llvm-tools-preview）
export RUSTUP_HOME="${RUSTUP_HOME:-/work/nexus-dev/.rustup}"
export CARGO_HOME="${CARGO_HOME:-/work/nexus-dev/.cargo}"
export PATH="${CARGO_HOME}/bin:${PATH}"

# 确保 rust-toolchain.toml 指定的组件齐全（devcontainer 首次启动时可能缺）
if [ -f rust-toolchain.toml ]; then
  rustup component add rustfmt clippy llvm-tools-preview 2>/dev/null \
    || echo "[devcontainer-setup] warning: rustup component 安装失败（已忽略，不影响编译）" >&2
fi

echo "[devcontainer-setup] 工具链: $(rustc --version 2>/dev/null || echo 'pending')"

# --- 2. 系统依赖（与 ci-verify.yml 的 Install system dependencies 对齐）---
# apt 安装失败不阻断容器（CI runner 上由 workflow 单独保证）。
if command -v apt-get >/dev/null 2>&1; then
  echo "[devcontainer-setup] 安装系统依赖..."
  sudo apt-get update -qq 2>/dev/null \
    || echo "[devcontainer-setup] warning: apt-get update 失败" >&2
  sudo apt-get install -y -qq \
    libssl-dev \
    pkg-config \
    clang \
    llvm \
    libdbus-1-dev \
    libxcb1-dev \
    2>/dev/null \
    || echo "[devcontainer-setup] warning: 部分系统依赖安装失败（不影响 cargo check，仅影响 FFI/平台代码）" >&2
fi

# --- 3. git hooks（与 remote-dev-setup.sh 保持一致）---
if [ -d .githooks ] && [ -f .githooks/install.sh ]; then
  echo "[devcontainer-setup] 安装 git hooks..."
  ./.githooks/install.sh \
    || echo "[devcontainer-setup] warning: git hooks 安装失败" >&2
fi

echo "[devcontainer-setup] 完成。"
echo "[devcontainer-setup] 提示：进入容器后运行"
echo "    nexus-harness verify --fast"
echo "  或"
echo "    ./scripts/agent-local-check.sh <crate>"
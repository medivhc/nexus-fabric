#!/bin/sh
# Installs the Nexus git hooks by setting core.hooksPath to .githooks.
# Usage: ./.githooks/install.sh   (POSIX shells; Windows users can use install.ps1)
set -eu

root="$(git rev-parse --show-toplevel)" || { echo "Not inside a git repository; run 'git init' first." >&2; exit 1; }

# Worktree config is opt-in and shares its enable flag. Do not move unusual
# shared core.worktree/core.bare settings automatically.
if [ "$(git config --local --get extensions.worktreeConfig || true)" != "true" ]; then
  if git config --local --get core.worktree >/dev/null 2>&1 \
     || [ "$(git config --local --get core.bare || true)" = "true" ]; then
    echo "[nexus-hook] migrate shared core.worktree/core.bare before enabling worktreeConfig (git help worktree)" >&2
    exit 1
  fi
  git config --local extensions.worktreeConfig true
fi
git config --worktree core.hooksPath .githooks
chmod +x "$root/.githooks/pre-commit" "$root/.githooks/commit-msg" "$root/.githooks/pre-push"

echo "[nexus-hook] installed for this worktree: core.hooksPath = .githooks"
echo "[nexus-hook] active gates: pre-commit, commit-msg, pre-push (see .githooks/README.md)"

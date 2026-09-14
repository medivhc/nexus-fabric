#!/bin/sh
# Installs the Nexus git hooks by setting core.hooksPath to .githooks.
# Usage: ./.githooks/install.sh   (POSIX shells; Windows users can use install.ps1)
set -eu

root="$(git rev-parse --show-toplevel)" || { echo "Not inside a git repository; run 'git init' first." >&2; exit 1; }

git config core.hooksPath .githooks
chmod +x "$root/.githooks/pre-commit" "$root/.githooks/commit-msg" "$root/.githooks/pre-push"

echo "[nexus-hook] installed: core.hooksPath = .githooks"
echo "[nexus-hook] active gates: pre-commit, commit-msg, pre-push (see .githooks/README.md)"

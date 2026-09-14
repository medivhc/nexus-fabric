#!/bin/sh
# Nexus git hooks —— shared helpers.
# Loaded by each hook via: . "$(git rev-parse --show-toplevel)/.githooks/hook-common.sh"
# Gate configuration is declared in harness.toml ([hooks] section); scripts keep
# the same semantics so Local Harness and CI share one gate definition.

# --- colored output (disable when not a TTY) ---------------------------------
if [ -t 1 ]; then
  C_RED="\033[31m"
  C_YEL="\033[33m"
  C_GRN="\033[32m"
  C_RST="\033[0m"
else
  C_RED=""
  C_YEL=""
  C_GRN=""
  C_RST=""
fi

log_info()  { printf '[nexus-hook] %b%s%b\n' "$C_GRN" "$*" "$C_RST"; }
log_warn()  { printf '[nexus-hook] %bWARN%b  %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
log_error() { printf '[nexus-hook] %bERROR%b %s\n' "$C_RED" "$C_RST" "$*" >&2; }

# --- task taxonomy (AGENTS.md §4) --------------------------------------------
NEXUS_TASK_TYPES="feature|bugfix|refactor|test|docs|performance|dependency|requirement-change"

# --- protected contract paths (AGENTS.md §7 + harness.toml [hooks.protected]) -
PROTECTED_PATTERN='^(PRODUCT\.md|ARCHITECTURE\.md|policies/|scenarios/|harness\.toml|.*/MODULE\.md)$'

# Contract marker required in commit body when protected paths change.
CONTRACT_MARKER_PATTERN='^(contract|requirement-change):[[:space:]]*[A-Za-z0-9]{8,64}'

# Staged paths touching protected contract paths (one per line, "" if none).
protected_paths_touched() {
  git diff --cached --name-only --diff-filter=ACMRD | grep -E "$PROTECTED_PATTERN" || true
}

# All changed paths in a given revision range touching protected paths.
protected_paths_in_range() {
  git diff --name-only "$1" 2>/dev/null | grep -E "$PROTECTED_PATTERN" || true
}

is_valid_task_type() {
  case "$1" in
    feature|bugfix|refactor|test|docs|performance|dependency|requirement-change) return 0 ;;
    *) return 1 ;;
  esac
}

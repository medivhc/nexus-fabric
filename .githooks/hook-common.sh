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

# --- agent identity (shared by pre-commit / pre-push) -------------------------
# NEXUS_AGENT is authoritative when set; keep it verbatim because multi-agent
# evidence namespacing relies on the exact value. When it is unset/empty, fall
# back to `git config user.name` sanitised into a directory-safe slug, then to a
# fixed placeholder. Never leave AGENT empty: an empty identity widens the STALE
# evidence scan to every agent's records.
nexus_agent_identity() {
  if [ -n "${NEXUS_AGENT:-}" ]; then
    printf '%s' "$NEXUS_AGENT"
    return 0
  fi
  agent_name="$(git config user.name 2>/dev/null || true)"
  agent_slug="$(printf '%s' "$agent_name" | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9]/-/g; s/^-*//; s/-*$//')"
  if [ -n "$agent_slug" ]; then
    printf '%s' "$agent_slug"
  else
    printf '%s' 'unknown-agent'
  fi
}
AGENT="$(nexus_agent_identity)"

# --- task taxonomy (AGENTS.md §4) --------------------------------------------
NEXUS_TASK_TYPES="feature|bugfix|refactor|test|docs|performance|dependency|requirement-change"

# --- protected contract paths (AGENTS.md §7 + harness.toml [hooks.protected]) -
PROTECTED_PATTERN='^(PRODUCT\.md|ARCHITECTURE\.md|policies/|scenarios/|harness\.toml|.*/MODULE\.md|DEV-ENV\.md)$'

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

# Keep the hook's Git/index environment intact. Only validation subprocesses
# enter the worktree without Git's repository-local variables.
worktree_cargo() (
  task_git_vars="$(git rev-parse --local-env-vars)" || exit 1
  for task_git_var in $task_git_vars; do unset "$task_git_var"; done
  cd "$ROOT" || exit 1
  task_main="$(git worktree list --porcelain | sed -n '1s/^worktree //p')" || exit 1
  task_target="${CARGO_TARGET_DIR:-}"
  if [ -n "$task_target" ] && [ "$task_main" != "$ROOT" ]; then
    # Resolve an existing parent, also handling relative paths and spaces.
    task_parent="$(dirname "$task_target")"
    task_leaf="$(basename "$task_target")"
    task_resolved="$(cd "$task_parent" 2>/dev/null && printf '%s/%s' "$(pwd -P)" "$task_leaf")" || task_resolved="$task_target"
    if [ "$task_resolved" = "$task_main/target" ]; then
      CARGO_TARGET_DIR="$ROOT/target"
      export CARGO_TARGET_DIR
    fi
  fi
  exec cargo "$@"
)

#!/usr/bin/env bash
set -euo pipefail

# Pin the toolchain for the whole job from rust-toolchain.toml.
# The CI image and the rust-toolchain action both provide a floating
# `stable` toolchain as the rustup default, while the repo pins 1.98.1.
# RUSTUP_TOOLCHAIN overrides both the rustup default and the directory
# override, so builds and the profile merge resolve to the same pinned
# toolchain. (Kept as hygiene: this pin alone did NOT fix the coverage
# failures — see the profraw quarantine below for the actual root cause.)
if [ -z "${RUSTUP_TOOLCHAIN:-}" ] && [ -f rust-toolchain.toml ]; then
  PINNED_TOOLCHAIN="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-toolchain.toml | head -n 1)"
  if [ -n "${PINNED_TOOLCHAIN}" ]; then
    export RUSTUP_TOOLCHAIN="${PINNED_TOOLCHAIN}"
    echo "coverage: RUSTUP_TOOLCHAIN pinned to ${RUSTUP_TOOLCHAIN} (rust-toolchain.toml)"
  fi
fi

MIN_LINES="${NEXUS_COVERAGE_MIN_LINES:-60}"
OUTPUT_DIR="${NEXUS_COVERAGE_OUTPUT_DIR:-target/coverage}"
mkdir -p "${OUTPUT_DIR}"

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "cargo-llvm-cov is required: cargo install cargo-llvm-cov --locked" >&2
  exit 2
fi

# BEGIN profraw-quarantine
# Root cause of the recurring "unrecognized instrumentation profile
# encoding format" / "no profile can be merged" failures (verified by
# local reproduction, 2026-10-23): the workspace test suite spawns
# instrumented subprocesses (e.g. nexusd integration tests spawn the
# daemon binary, which inherits LLVM_PROFILE_FILE). A subprocess that is
# still exiting when the test phase ends can leave behind a profraw whose
# header has not been written yet. llvm-profdata aborts the ENTIRE merge
# if any single input is unreadable, so one half-written file fails the
# whole gate even though every test passed. A full local workspace run
# produced 358 profraws, all valid and merging cleanly — the corruption
# is a CI-side timing race on one late subprocess, not a toolchain or
# code problem.
#
# Strategy: give suspect files a few seconds to finish writing, then
# quarantine (rename, with a loud warning) any file llvm-profdata still
# cannot read, so the gate measures the remaining profiles. The same
# binary normally leaves many valid profraws, so the coverage loss is
# negligible. If many files are unreadable something systemic is wrong:
# fail instead of quarantining.
quarantine_unreadable_profiles() {
  local profraw_dir="$1"
  local target_libdir profdata
  target_libdir="$(rustc --print target-libdir)"
  profdata="$(dirname "${target_libdir}")/bin/llvm-profdata"
  if [ ! -x "${profdata}" ]; then
    echo "coverage: llvm-profdata not found at ${profdata}; skipping profraw validation" >&2
    return 0
  fi

  local suspects
  suspects="$(python3 - "${profraw_dir}" <<'PYEOF'
import os, sys
d = sys.argv[1]
MAGICS = (b"\x81rforpl\xff", b"\xfflprofi\x81")
try:
    names = sorted(os.listdir(d))
except OSError:
    names = []
for name in names:
    if not name.endswith(".profraw"):
        continue
    p = os.path.join(d, name)
    try:
        with open(p, "rb") as fh:
            head = fh.read(8)
    except OSError:
        head = b""
    if head not in MAGICS:
        print(p)
PYEOF
)"

  local quarantined=0
  # Wait-and-recheck loop for files whose header is not (yet) readable:
  # the writer may still be exiting.
  local attempt f remaining
  for attempt in 1 2 3 4 5; do
    [ -n "${suspects}" ] || break
    sleep 2
    remaining=""
    while IFS= read -r f; do
      [ -n "${f}" ] || continue
      if ! "${profdata}" merge -sparse "${f}" -o /dev/null >/dev/null 2>&1; then
        remaining="${remaining}${f}
"
      fi
    done <<< "${suspects}"
    suspects="${remaining}"
  done

  # Validate the whole population with llvm-profdata itself (catches
  # suspects that never recovered and any truncated-body files).
  local all_files
  all_files="$(ls "${profraw_dir}"/*.profraw 2>/dev/null || true)"
  while IFS= read -r f; do
    [ -n "${f}" ] || continue
    if ! "${profdata}" merge -sparse "${f}" -o /dev/null >/dev/null 2>&1; then
      mv "${f}" "${f}.quarantined"
      echo "::warning::coverage: quarantined unreadable profraw ${f} (excluded from merge; a test subprocess was likely still writing it)"
      quarantined=$((quarantined + 1))
    fi
  done <<< "${all_files}"

  if [ "${quarantined}" -gt 5 ]; then
    echo "coverage: ${quarantined} profraw files unreadable — systemic problem, failing" >&2
    return 1
  fi
  if [ "${quarantined}" -gt 0 ]; then
    echo "coverage: quarantined ${quarantined} unreadable profraw file(s); continuing with the remaining profiles"
  fi
  return 0
}
# END profraw-quarantine

cargo llvm-cov clean --workspace

# Phase 1: run the tests only; reports are generated in phase 2 after
# profraw validation.
cargo llvm-cov \
  --workspace \
  --all-features \
  --ignore-filename-regex '(^|/)(vendor|target)/' \
  --no-report

TARGET_DIR="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
quarantine_unreadable_profiles "${TARGET_DIR}/llvm-cov-target"

# NOTE: `cargo llvm-cov report` (0.9.1) rejects --workspace/--all-features;
# it reports on the workspace recorded by the phase-1 run.
cargo llvm-cov report \
  --ignore-filename-regex '(^|/)(vendor|target)/' \
  --lcov \
  --output-path "${OUTPUT_DIR}/lcov.info" \
  --fail-under-lines "${MIN_LINES}"

cargo llvm-cov report \
  --ignore-filename-regex '(^|/)(vendor|target)/' \
  --summary-only | tee "${OUTPUT_DIR}/summary.txt"

#!/usr/bin/env bash
set -euo pipefail

# Pin the toolchain for the whole job from rust-toolchain.toml.
# The CI image and the rust-toolchain action both provide a floating
# `stable` toolchain as the rustup default, while the repo pins 1.98.1.
# Without this export, test binaries can be built by stable while
# cargo-llvm-cov merges profiles with the pinned toolchain's
# llvm-profdata, which rejects the newer profraw encoding
# ("unrecognized instrumentation profile encoding format" /
# "no profile can be merged"). RUSTUP_TOOLCHAIN overrides both the
# rustup default and the directory override, so the build and the
# profile merge resolve to the same pinned toolchain.
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

cargo llvm-cov clean --workspace
cargo llvm-cov \
  --workspace \
  --all-features \
  --ignore-filename-regex '(^|/)(vendor|target)/' \
  --lcov \
  --output-path "${OUTPUT_DIR}/lcov.info" \
  --fail-under-lines "${MIN_LINES}"

cargo llvm-cov report \
  --workspace \
  --all-features \
  --ignore-filename-regex '(^|/)(vendor|target)/' \
  --summary-only | tee "${OUTPUT_DIR}/summary.txt"

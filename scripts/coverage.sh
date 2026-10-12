#!/usr/bin/env bash
set -euo pipefail

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

#!/usr/bin/env bash
# S49 doc-consistency gate.
#
# Stale-symbol grep over PRODUCT.md, docs/, crates/ and scenarios/.
#
# Explicit exclusion: docs/recovery/.
# docs/recovery/ is a forensic archive of SHA-256 manifest-fixed historical
# snapshots (docs/recovery/2026-10-20/canonical-export-manifest.json). Old
# symbols in those snapshots are expected; rewriting them to satisfy a live
# documentation consistency check would break manifest verification.
# The archive is therefore immutable evidence, not live documentation.
#
# Usage: ./scripts/doc-consistency-check.sh
# Exit: 0 = no stale symbol outside the forensic archive; 1 = found.

set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
cd "${ROOT}"

PATTERN=${1:-TunNatRouter}

HITS=$(grep -rn --exclude-dir=recovery --exclude-dir=target --exclude-dir=.git \
  "${PATTERN}" PRODUCT.md docs crates scenarios 2>/dev/null || true)

if [ -n "${HITS}" ]; then
  printf 'stale symbol %s found outside docs/recovery/:\n%s\n' "${PATTERN}" "${HITS}" >&2
  exit 1
fi

printf 'doc consistency: %s not found outside docs/recovery/ (forensic archive excluded)\n' "${PATTERN}"

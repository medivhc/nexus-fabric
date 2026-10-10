#!/usr/bin/env python3
"""Validate crates/nexus-web-gateway/requirements.toml against SPEC §5.1.

Usage:
    python3 validate-requirements.py [path/to/requirements.toml]

Exit codes:
    0 - valid (or file missing: warning, not fail, for bootstrap)
    1 - invalid (missing fields, bad enum, duplicate ID, bad format)

Only Python standard library (tomllib, re, sys).
"""
import re
import sys
from pathlib import Path

REQUIRED_FIELDS = {"id", "title", "status", "priority", "acceptance", "created"}
VALID_STATUS = {"todo", "doing", "done"}
VALID_PRIORITY = {"P0", "P1", "P2"}
ID_PATTERN = re.compile(r"^REQ-\d{3}$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def validate(path: Path) -> list[str]:
    """Return list of error strings; empty means valid."""
    errors: list[str] = []
    if not path.exists():
        # Bootstrap: missing file is warning, not fail (SPEC §9)
        print(f"WARNING: {path} not found (bootstrap mode)", file=sys.stderr)
        return errors

    try:
        import tomllib
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        return [f"parse error: {e}"]

    reqs = data.get("req", [])
    if not isinstance(reqs, list):
        return ["'req' must be a list of tables"]

    seen_ids: set[str] = set()
    for i, req in enumerate(reqs):
        prefix = f"req[{i}]"
        if not isinstance(req, dict):
            errors.append(f"{prefix}: must be a table")
            continue
        # Field completeness
        missing = REQUIRED_FIELDS - set(req.keys())
        if missing:
            errors.append(f"{prefix}: missing fields {sorted(missing)}")
        # ID format and uniqueness
        rid = req.get("id", "")
        if not ID_PATTERN.match(str(rid)):
            errors.append(f"{prefix}: id '{rid}' must match ^REQ-\\d{{3}}$")
        elif rid in seen_ids:
            errors.append(f"{prefix}: duplicate id '{rid}'")
        else:
            seen_ids.add(rid)
        # Enums
        if req.get("status") not in VALID_STATUS:
            errors.append(
                f"{prefix}: status '{req.get('status')}' must be one of {sorted(VALID_STATUS)}"
            )
        if req.get("priority") not in VALID_PRIORITY:
            errors.append(
                f"{prefix}: priority '{req.get('priority')}' must be one of {sorted(VALID_PRIORITY)}"
            )
        # Date format
        if not DATE_PATTERN.match(str(req.get("created", ""))):
            errors.append(
                f"{prefix}: created '{req.get('created')}' must match YYYY-MM-DD"
            )
    return errors


def main() -> int:
    default = Path(__file__).resolve().parent.parent / "requirements.toml"
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    errors = validate(path)
    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)
    if errors:
        print(f"FAILED: {len(errors)} error(s)", file=sys.stderr)
        return 1
    print("OK: requirements.toml valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# Contributing to Nexus

## Commit Messages

We use the task taxonomy from AGENTS.md §4.

### Format

```
<type>(<scope>): <summary>
```

- **type**: `feature` | `bugfix` | `refactor` | `test` | `docs` | `performance` | `dependency` | `requirement-change`
- **scope**: module name (e.g., `web-gateway`, `dashboard`, `ci`, `harness`)
- **summary**: imperative mood, max 100 chars

### Examples

```
feature(web-gateway): add REQ-003 access authentication
bugfix(ci): handle grep exit code in bash -e mode
docs(gateway): update API documentation
```

### Enforcement

- Local: `.githooks/commit-msg` (already in repo, enforces format + contract hash)
- CI: `.github/workflows/commitlint.yml` (runs on PR)

## Author Identity

Use a single consistent identity per project:

```bash
# For Xiang (project owner)
git config user.name "Xiang Cui"
git config user.email "medivhc@gmail.com"

# For Muse (AI assistant)
git config user.name "Muse"
git config user.email "muse@htch-runtime"
```

#requires -Version 5.1
<#
.SYNOPSIS
Installs the Nexus git hooks by setting core.hooksPath to .githooks.

.DESCRIPTION
Run from anywhere inside the repository (or from the repository root).
Equivalent command: git config core.hooksPath .githooks
On Windows, Git for Windows runs the POSIX-shell hooks via its bundled sh,
so no chmod is required.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .githooks/install.ps1
#>
$ErrorActionPreference = "Stop"

& git rev-parse --git-dir *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Not inside a git repository. Run 'git init' (or clone) first, then re-run this installer."
}

& git config core.hooksPath .githooks
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to set core.hooksPath = .githooks"
}

Write-Host "[nexus-hook] installed: core.hooksPath = .githooks"
Write-Host "[nexus-hook] active gates: pre-commit, commit-msg, pre-push (see .githooks/README.md)"

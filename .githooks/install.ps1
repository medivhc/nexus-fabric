#requires -Version 5.1
<#
.SYNOPSIS
Installs the Nexus git hooks by setting core.hooksPath to .githooks.

.DESCRIPTION
Run from anywhere inside the repository (or from the repository root).
Uses extensions.worktreeConfig and git config --worktree core.hooksPath .githooks.
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

$enabled = & git config --local --get extensions.worktreeConfig
if ($enabled -ne "true") {
    $sharedWorktree = & git config --local --get core.worktree
    $hasSharedWorktree = $LASTEXITCODE -eq 0
    $sharedBare = & git config --local --get core.bare
    if ($hasSharedWorktree -or $sharedBare -eq "true") {
        throw "Migrate shared core.worktree/core.bare before enabling worktreeConfig (git help worktree)"
    }
    & git config --local extensions.worktreeConfig true
    if ($LASTEXITCODE -ne 0) { throw "Failed to enable worktreeConfig" }
}
& git config --worktree core.hooksPath .githooks
if ($LASTEXITCODE -ne 0) { throw "Failed to set worktree core.hooksPath" }
Write-Host "[nexus-hook] installed for this worktree: core.hooksPath = .githooks"
Write-Host "[nexus-hook] active gates: pre-commit, commit-msg, pre-push (see .githooks/README.md)"

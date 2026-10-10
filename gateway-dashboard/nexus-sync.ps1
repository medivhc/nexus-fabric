# nexus-sync.ps1 - Nexus 多 Agent 同步+推送包装（AGENTS.md §29.3）
#   fetch -> rebase origin/master -> verify --fast -> push
#
# 用法：
#   pwsh -File ./nexus-sync.ps1                # 同步+验证，不推送（安全检查）
#   pwsh -File ./nexus-sync.ps1 -Push          # 同步+验证+推送
#   pwsh -File ./nexus-sync.ps1 -Branch <ref>  # 对指定上游操作（默认 origin/master）
#
# 环境变量：
#   NEXUS_AGENT   证据命名空间（verify-<agent>-<hash>，AGENTS.md §29.2）
#   GIT_PUSH_URL  覆盖 push 远端 URL（CI/临时凭据用；不落盘 remote 配置）
#
# 冲突处理：rebase 中断时提示显式解决（§17），不自动丢弃已提交工作。
[CmdletBinding()]
param(
    [switch]$Push,
    [string]$Branch = 'origin/master'
)

$ErrorActionPreference = 'Stop'
$root = git rev-parse --show-toplevel
if (-not $root) { Write-Error 'not inside a git repository'; exit 1 }
Set-Location $root

function Step([string]$m) { Write-Host "[nexus-sync] $m" }

Step '1/4 fetch'
git fetch origin
if ($LASTEXITCODE -ne 0) { Write-Error 'fetch failed (check network/credentials)'; exit 1 }

Step "2/4 rebase onto $Branch"
git rebase $Branch
if ($LASTEXITCODE -ne 0) {
    Write-Host "[nexus-sync] rebase conflicts - resolve explicitly (AGENTS.md §17), then:" -ForegroundColor Yellow
    Write-Host "  git add <resolved> && git rebase --continue"
    Write-Host "  (never discard committed work silently; --abort only to reset)"
    exit 1
}

Step '3/4 verify --fast'
$harness = Get-Command nexus-harness -ErrorAction SilentlyContinue
if ($harness) {
    nexus-harness verify --fast
}
elseif (Get-Command cargo -ErrorAction SilentlyContinue) {
    cargo run -q -p nexus-harness -- verify --fast
}
else {
    Write-Warning 'nexus-harness/cargo not found; verify skipped (no evidence produced)'
}

if ($Push) {
    Step '4/4 push'
    $branch = git branch --show-current
    if ($env:GIT_PUSH_URL) {
        git push $env:GIT_PUSH_URL $branch 2>$null; if ($LASTEXITCODE -ne 0) { git push $env:GIT_PUSH_URL HEAD:master }
    }
    else {
        git push origin $branch
    }
}
else {
    Write-Host '[nexus-sync] done (dry run; add -Push to push)'
}

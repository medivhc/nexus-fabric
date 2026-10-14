# ============================================================================
# guard.ps1 — Windows 便捷入口（**不需要 bash / Git Bash / WSL**）
# ----------------------------------------------------------------------------
# 用法（PowerShell）：
#   .\scripts\guard.ps1
#   .\scripts\guard.ps1 -ScenariosDir <仓库 scenarios 目录>
#
# 等价于 Linux/macOS 下的 `mise run guard`。
# 它直接调用 Python 脚本，命令里不含任何 bash 语法（`&&`、管道、重定向等），
# 因此 Windows 原生 PowerShell 即可运行；mise 的 shell 钩子在 Windows 上
# 依赖 `mise activate powershell`，若未启用 hook，用本脚本手动跑即可。
# ============================================================================
param(
    [string]$ScenariosDir = "samples/scenarios",
    [string]$ReportDir = ".env-report"
)

$ErrorActionPreference = "Stop"

# 定位项目根（scripts/ 的上级目录），保证相对路径一致
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# 候选顺序：先试 Unix 常见名（python3 / python），最后试 Windows 启动器（py -3 / py）。
# Windows 上通常没有 python，只有 py 启动器；py 默认可能指向 py2，故显式用 `py -3` 强制 Python 3。
# 用显式 exe + args 数组，避免 PowerShell「1..0 范围」陷阱（单段候选会拼出 $null 参数）。
$candidates = @(
    @{ exe = "python3"; args = @() },
    @{ exe = "python";  args = @() },
    @{ exe = "py";      args = @("-3") },
    @{ exe = "py";      args = @() }
)

function Find-Python {
    foreach ($c in $candidates) {
        try {
            $out = & $c.exe @($c.args) "--version" 2>&1
        } catch {
            continue
        }
        if ($out -match "Python (\d+)\.(\d+)") {
            $maj, $min = [int]$Matches[1], [int]$Matches[2]
            if ($maj -ge 3 -and ($maj -gt 3 -or $min -ge 11)) {
                # 返回可复用的调用形式：exe 与 args 分开存
                return @{ exe = $c.exe; args = $c.args }
            }
        }
    }
    throw "未找到 Python 3.11+ 解释器（已尝试 python3 / python / py -3 / py）。`n" +
          "Windows 请安装 Python 3.11+，或用 `py -3 --version` 确认启动器可用；Linux/macOS 请 `python3 --version`。"
}

function Invoke-Py {
    param([string[]]$ScriptArgs)
    & $py.exe @($py.args) @ScriptArgs
    return $LASTEXITCODE
}

$py = Find-Python
Write-Host "[guard] 解释器: $($py.exe) $($py.args -join ' ')" -ForegroundColor Cyan

# env-check 通过环境变量确定产物目录
$env:ENV_REPORT_DIR = $ReportDir

Write-Host "[guard] 1/2 env-check ..." -ForegroundColor Cyan
Invoke-Py "scripts/env-check"
if ($LASTEXITCODE -ne 0) { throw "env-check 失败 (exit $LASTEXITCODE)" }

Write-Host "[guard] 2/2 harness-select ..." -ForegroundColor Cyan
Invoke-Py @("scripts/harness-select",
    "--env-report", (Join-Path $ReportDir "env-report.json"),
    "--map", "test-capability-map.toml",
    "--scenarios-dir", $ScenariosDir,
    "--out", (Join-Path $ReportDir "test-plan.json"))
if ($LASTEXITCODE -ne 0) { throw "harness-select 失败 (exit $LASTEXITCODE)" }

Write-Host "[guard] 完成 -> $(Join-Path $ReportDir 'env-report.json') / $(Join-Path $ReportDir 'test-plan.json')" -ForegroundColor Green
Write-Host "[guard] 下一步：只运行 test-plan.json 里的 selected；skipped 记为 SKIPPED，不得记为 PASS。" -ForegroundColor Yellow

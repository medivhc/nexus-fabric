# ============================================================================
# run_tests.ps1 — sandbox-env-guard 自回归测试的 Windows 入口
# ----------------------------------------------------------------------------
# 为什么需要这一层：
#   run_tests.py 是守卫门控契约的**唯一真源**（能力矩阵 fixtures + 错误路径 +
#   env-check 组件 + 接口契约）。Windows 上常见情况是：
#     - 没有 `python`，只有 `py` 启动器；
#     - 没有 bash（`&&` / `$?` 等写法不可用）。
#   直接 `python scripts/run_tests.py` 会失败。本脚本只负责**找到可用的
#   Python 3.11+ 解释器**（tomllib 依赖），断言仍由 run_tests.py 执行，
#   从而保证 Windows 与 Linux/macOS 跑的是**同一套断言**——单一真源，
#   避免维护两份门控逻辑导致漂移。
#
# 等价关系：
#   Linux/macOS : mise run test           -> python scripts/run_tests.py
#   Windows     : .\scripts\run_tests.ps1 -> <py -3|python|python3> scripts/run_tests.py
#
# 用法（PowerShell，无需 bash / 无需 mise）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/run_tests.ps1
#
# 退出码：透传 run_tests.py（0=全绿 / 1=有用例失败）；找不到解释器时为 1。
# ============================================================================
$ErrorActionPreference = "Stop"

# 项目根（scripts/ 的上一级）
$Root = Split-Path -Parent $PSScriptRoot

function Find-Python {
    <#
    定位可用的 Python 3.11+ 解释器。
    候选按 (Exe, Args) 显式组织——不要写 `@($parts[1..0])` 这类范围 splat，
    单段候选在 PowerShell 会产生 1..0 的倒序范围并混入 $null 参数。
    顺序：py -3（Windows 启动器，显式强制 Python 3） -> python -> python3
    #>
    $candidates = @(
        @{ Exe = "py";      Args = @("-3") },
        @{ Exe = "python";  Args = @() },
        @{ Exe = "python3"; Args = @() }
    )
    foreach ($c in $candidates) {
        $cmd = Get-Command $c.Exe -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        try {
            $out = (& $c.Exe @($c.Args) "--version" 2>&1 | Out-String)
        } catch {
            continue
        }
        if ($out -match "Python (\d+)\.(\d+)") {
            $maj = [int]$Matches[1]
            $min = [int]$Matches[2]
            if ($maj -ge 3 -and ($maj -gt 3 -or $min -ge 11)) {
                return $c
            }
        }
    }
    throw "未找到 Python 3.11+（已尝试 py -3 / python / python3）。`n" +
          "守卫依赖标准库 tomllib（Python 3.11+）。请先安装 Python 3.11+，或用 `py -3 --version` 确认启动器可用。"
}

try {
    Set-Location $Root

    $py = Find-Python
    $exe = $py.Exe
    $pyArgs = @($py.Args)
    Write-Host "[run_tests.ps1] 项目根 : $Root"
    Write-Host "[run_tests.ps1] 解释器 : $exe $($pyArgs -join ' ')" -ForegroundColor Cyan

    Write-Host "[run_tests.ps1] 运行守卫自回归套件 ..." -ForegroundColor Cyan
    & $exe @pyArgs "scripts/run_tests.py"
    $code = $LASTEXITCODE

    if ($code -eq 0) {
        Write-Host "[run_tests.ps1] ALL GREEN" -ForegroundColor Green
    } elseif ($code -eq 2) {
        # 与 harness-select 对齐：2 = BLOCKED（守卫显式拒绝，非崩溃）
        Write-Host "[run_tests.ps1] BLOCKED：守卫拒绝产出（exit 2）" -ForegroundColor Yellow
    } else {
        Write-Host "[run_tests.ps1] FAILED (exit $code)" -ForegroundColor Red
    }
    exit $code
}
catch {
    Write-Host "[run_tests.ps1] ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

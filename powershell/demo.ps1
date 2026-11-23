# powershell/demo.ps1 - Complete end-to-end presentation demo script with -WhatIf dry run support.
[CmdletBinding()]
param(
    [int]$Port = 8000,
    [string]$WslDir,
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "            SecureFileGuard Path-Containment Testbench          " -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan

if ($WhatIf) {
    Write-Host "[WhatIf - Dry Run Mode Enabled: Showing actions without executing]`n" -ForegroundColor Yellow
    Write-Host "1. [setup.ps1] Would verify WSL status and install requirements (build-essential, python3, rsync)."
    Write-Host "2. [setup.ps1] Would sync project files to native WSL ext4 filesystem (target: $WslDir)."
    Write-Host "3. [build.ps1] Would build C++17 guard engine and test runner using 'make all'."
    Write-Host "4. [test.ps1]  Would generate fixtures, run 36 path containment tests, and save results to .\results\results.csv."
    Write-Host "5. [race.ps1]  Would execute TOCTOU race demo with 20,000 iterations x 2 runs comparing V2, V3, and V4."
    Write-Host "6. [web.ps1]   Would launch Python HTTP server on port $Port and open http://localhost:$Port in browser."
    Write-Host "`n[WhatIf] Dry run completed. No commands were executed." -ForegroundColor Green
    exit 0
}

# 1. Environment Setup
Write-Host "`n[1/5] Setting up WSL environment..." -ForegroundColor Yellow
$setupArgs = @("-NonInteractive")
if ($WslDir) { $setupArgs += @("-WslDir", $WslDir) }
& "$PSScriptRoot\setup.ps1" @setupArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 2. Build
Write-Host "`n[2/5] Building C++17 checkers and testbench..." -ForegroundColor Yellow
$buildArgs = @()
if ($WslDir) { $buildArgs += @("-WslDir", $WslDir) }
& "$PSScriptRoot\build.ps1" @buildArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 3. Test Suite
Write-Host "`n[3/5] Executing full test suite and generating metrics..." -ForegroundColor Yellow
$testArgs = @()
if ($WslDir) { $testArgs += @("-WslDir", $WslDir) }
& "$PSScriptRoot\test.ps1" @testArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 4. TOCTOU Race Demo
Write-Host "`n[4/5] Executing live TOCTOU symlink race demo (20,000 iterations x 2 runs)..." -ForegroundColor Yellow
$raceArgs = @("-Iterations", "20000", "-Runs", "2")
if ($WslDir) { $raceArgs += @("-WslDir", $WslDir) }
& "$PSScriptRoot\race.ps1" @raceArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# 5. Web Interface
Write-Host "`n[5/5] Launching interactive web interface on port $Port..." -ForegroundColor Yellow
$webArgs = @("-Port", $Port)
if ($WslDir) { $webArgs += @("-WslDir", $WslDir) }
& "$PSScriptRoot\web.ps1" @webArgs

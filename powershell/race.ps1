# powershell/race.ps1 - Runs TOCTOU race condition benchmark inside WSL.
[CmdletBinding()]
param(
    [int]$Iterations = 100000,
    [int]$Runs = 3,
    [string]$WslDir
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\common.ps1"

$targetDir = Get-WslRepoPath -SyncChanges -WslDir $WslDir

Write-Host "==> Ensuring toctou_race binary is built..." -ForegroundColor Cyan
Invoke-Wsl -Dir $targetDir -Command "test -f build/toctou_race || make build/toctou_race"

Write-Host "==> Starting TOCTOU race demo ($Iterations iterations, $Runs runs)..." -ForegroundColor Cyan
$rawOutput = Invoke-Wsl -Dir $targetDir -Command "./build/toctou_race $Iterations $Runs" -ReturnOutput

# Print colored output
$inJson = $false
foreach ($line in ($rawOutput -split "`r?`n")) {
    if ($line -match '^JSON_OUTPUT_START') { $inJson = $true; continue }
    if ($line -match '^JSON_OUTPUT_END') { $inJson = $false; continue }
    if ($inJson) { continue }

    if ($line -match '^(V\d\s+.*?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$') {
        # Multi-run table row
        $name = $matches[1]
        $attempts = $matches[2]
        $allowed = $matches[3]
        $opened = $matches[4]
        $min = $matches[5]
        $max = $matches[6]
        $total = [int]$matches[7]
        $runsBreakdown = $matches[8]

        Write-Host ("{0,-20} {1,10} {2,10} {3,10} {4,6} {5,6} " -f $name, $attempts, $allowed, $opened, $min, $max) -NoNewline
        if ($total -gt 0) {
            Write-Host ("{0,6}  " -f $total) -ForegroundColor Red -NoNewline
            Write-Host $runsBreakdown -ForegroundColor Red
        } else {
            Write-Host ("{0,6}  " -f $total) -ForegroundColor Green -NoNewline
            Write-Host $runsBreakdown -ForegroundColor Green
        }
    }
    elseif ($line -match '^(V\d\s+.*?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$') {
        # Single-run table row
        $name = $matches[1]
        $attempts = $matches[2]
        $allowed = $matches[3]
        $opened = $matches[4]
        $escapes = [int]$matches[5]

        Write-Host ("{0,-20} {1,10} {2,10} {3,10} " -f $name, $attempts, $allowed, $opened) -NoNewline
        if ($escapes -gt 0) {
            Write-Host ("{0,10}" -f $escapes) -ForegroundColor Red
        } else {
            Write-Host ("{0,10}" -f $escapes) -ForegroundColor Green
        }
    }
    elseif ($line -match 'Environment:') {
        Write-Host $line -ForegroundColor Cyan
    }
    elseif ($line -match 'PROBABILISTIC') {
        Write-Host $line -ForegroundColor Yellow
    }
    else {
        Write-Host $line
    }
}

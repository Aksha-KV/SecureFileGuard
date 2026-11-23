# powershell/test.ps1 - Runs C++ path guard test suite inside WSL and displays colorized metrics.
[CmdletBinding()]
param(
    [string]$OutDir = ".\results",
    [string]$WslDir
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\common.ps1"

$targetDir = Get-WslRepoPath -SyncChanges -WslDir $WslDir

Write-Host "==> Creating fixtures in WSL ($targetDir)..." -ForegroundColor Cyan
Invoke-Wsl -Dir $targetDir -Command "bash tools/make_fixtures.sh runtime/fixtures"

Write-Host "==> Running path containment test suite..." -ForegroundColor Cyan
$rawOutput = Invoke-Wsl -Dir $targetDir -Command "./build/run_tests runtime/fixtures results/results.csv" -ReturnOutput

# Parse and colorize output lines
foreach ($line in ($rawOutput -split "`r?`n")) {
    if ($line -match '^(\d+)\s+(\w+)\s+(.*?)\s+(ALLOW|DENY)\s+(.*)$') {
        # Table row: colorize decisions
        $id = $matches[1]
        $cat = $matches[2]
        $path = $matches[3]
        $expect = $matches[4]
        $decisions = $matches[5]

        Write-Host ("{0,-3} {1,-10} {2,-38} {3,-6}" -f $id, $cat, $path, $expect) -NoNewline

        # Print each variant cell with color
        $cells = -split $decisions
        foreach ($c in $cells) {
            if ($c -match '\*') {
                if ($cat -in @("traversal", "symlink", "prefix", "absolute") -and $expect -eq "DENY") {
                    Write-Host (" {0,-7}" -f $c) -ForegroundColor Red -NoNewline
                } else {
                    Write-Host (" {0,-7}" -f $c) -ForegroundColor Yellow -NoNewline
                }
            } else {
                Write-Host (" {0,-7}" -f $c) -ForegroundColor Green -NoNewline
            }
        }
        Write-Host ""
    }
    elseif ($line -match '^(V\d)\s+(.*?)\s+(\d+\.\d+%.*?\))\s+(\d+\.\d+%.*?\))\s+(\d+\.\d+%.*?\))\s+(\d+\.\d+%.*?\))\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$') {
        # Metrics row with 4 percentages: Containment-safe, Type-policy, Missing-name, Allow-rate
        $vid = $matches[1]
        $name = $matches[2]
        $containSafe = $matches[3]
        $typeMatch = $matches[4]
        $missingMatch = $matches[5]
        $allowRate = $matches[6]
        $cf = [int]$matches[7]
        $tm = [int]$matches[8]
        $pm = [int]$matches[9]
        $fb = [int]$matches[10]

        Write-Host ("{0,-4} {1,-17} {2,13} {3,13} {4,13} {5,13}" -f $vid, $name, $containSafe, $typeMatch, $missingMatch, $allowRate) -NoNewline
        if ($cf -gt 0) {
            Write-Host (" {0,15}" -f $cf) -ForegroundColor Red -NoNewline
        } else {
            Write-Host (" {0,15}" -f $cf) -ForegroundColor Green -NoNewline
        }
        if ($tm -gt 0) {
            Write-Host (" {0,12}" -f $tm) -ForegroundColor Yellow -NoNewline
        } else {
            Write-Host (" {0,12}" -f $tm) -ForegroundColor Green -NoNewline
        }
        if ($pm -gt 0) {
            Write-Host (" {0,14}" -f $pm) -ForegroundColor Yellow -NoNewline
        } else {
            Write-Host (" {0,14}" -f $pm) -ForegroundColor Green -NoNewline
        }
        if ($fb -gt 0) {
            Write-Host (" {0,11}" -f $fb) -ForegroundColor Cyan -NoNewline
        } else {
            Write-Host (" {0,11}" -f $fb) -ForegroundColor Green -NoNewline
        }
        Write-Host ""
    }
    elseif ($line -match '^(V\d)\s+(.*?)\s+(\d+\.\d+%.*?\))\s+(\d+\.\d+%.*?\))\s+(\d+\.\d+%.*?\))\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$') {
        # Fallback 3-percentage row
        $vid = $matches[1]
        $name = $matches[2]
        $p1 = $matches[3]
        $p2 = $matches[4]
        $p3 = $matches[5]
        $cf = [int]$matches[6]
        $tm = [int]$matches[7]
        $pm = [int]$matches[8]
        $fb = [int]$matches[9]

        Write-Host ("{0,-4} {1,-17} {2,13} {3,13} {4,13}" -f $vid, $name, $p1, $p2, $p3) -NoNewline
        Write-Host (" {0,15}" -f $cf) -ForegroundColor (if ($cf -gt 0) { "Red" } else { "Green" }) -NoNewline
        Write-Host (" {0,12}" -f $tm) -ForegroundColor (if ($tm -gt 0) { "Yellow" } else { "Green" }) -NoNewline
        Write-Host (" {0,14}" -f $pm) -ForegroundColor (if ($pm -gt 0) { "Yellow" } else { "Green" }) -NoNewline
        Write-Host (" {0,11}" -f $fb) -ForegroundColor (if ($fb -gt 0) { "Cyan" } else { "Green" })
    }
    else {
        if ($line -match 'Root:|Policy:|Oracle:') {
            Write-Host $line -ForegroundColor Cyan
        } elseif ($line -match 'Evaluation breakdown:') {
            Write-Host $line -ForegroundColor White
        } elseif ($line -match 'ContainmentFail') {
            Write-Host $line -ForegroundColor Red
        } elseif ($line -match 'TypeMismatch|PolicyMismatch') {
            Write-Host $line -ForegroundColor Yellow
        } else {
            Write-Host $line
        }
    }
}

# Copy results.csv to Windows OutDir
$winOutDir = [System.IO.Path]::GetFullPath($OutDir)
if (-not (Test-Path $winOutDir)) {
    $null = New-Item -ItemType Directory -Force -Path $winOutDir
}

$csvContent = Invoke-Wsl -Dir $targetDir -Command "cat results/results.csv" -ReturnOutput
if ($csvContent) {
    $targetFile = Join-Path $winOutDir "results.csv"
    Set-Content -Path $targetFile -Value $csvContent -Encoding UTF8
    Write-Host "`n==> Copied results to: $targetFile" -ForegroundColor Green
}

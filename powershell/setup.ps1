# powershell/setup.ps1 - Environment check and setup for SecureFileGuard inside WSL.
[CmdletBinding()]
param(
    [string]$WslDir,
    [switch]$NonInteractive
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\common.ps1"

Write-Host "==> Checking WSL status..." -ForegroundColor Cyan
Assert-WslInstalled

$winProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$wslWinPath = Get-WinToWslPath -WindowsPath $winProjectRoot

Write-Host "Windows project path: $winProjectRoot" -ForegroundColor Gray
Write-Host "WSL mount path:       $wslWinPath" -ForegroundColor Gray

# Determine WSL target directory
$targetDir = Get-WslTargetDir -OverrideDir $WslDir
Write-Host "WSL target directory: $targetDir" -ForegroundColor Gray

$isDrvFs = ($wslWinPath -match '^/mnt/[a-z]')
if ($isDrvFs) {
    Write-Warning "Detected that project is located on a Windows filesystem mount (/mnt/*)."
    Write-Warning "Linux symlinks, mkfifo, and socket features fail on DrvFS (/mnt/c)."
}

# Check if target directory exists in WSL
$escapedTarget = if ($targetDir.StartsWith("~")) {
    '`$HOME' + (Protect-BashString ($targetDir.Substring(1)))
} else {
    Protect-BashString $targetDir
}

$hasTarget = (& wsl.exe -e bash -lc "test -d $escapedTarget && echo yes" 2>$null)
$hasTargetStr = if ($hasTarget) { $hasTarget.ToString().Trim() } else { "" }

if ($hasTargetStr -ne "yes") {
    $doCopy = $true
    if (-not $NonInteractive -and $isDrvFs) {
        $resp = Read-Host "Copy project to native WSL ext4 filesystem ($targetDir)? (Y/n)"
        if ($resp -and $resp.Trim().ToLower() -eq 'n') {
            $doCopy = $false
        }
    }
    if ($doCopy) {
        Write-Host "==> Copying project to WSL filesystem ($targetDir)..." -ForegroundColor Cyan
        Sync-ProjectToWsl -WslTargetDir $targetDir
        Write-Host "Successfully copied to $targetDir." -ForegroundColor Green
    }
} else {
    Write-Host "==> Existing WSL copy found at $targetDir. Syncing latest files..." -ForegroundColor Cyan
    Sync-ProjectToWsl -WslTargetDir $targetDir
    Write-Host "Synced with $targetDir." -ForegroundColor Green
}

# Check for required tools inside WSL
Write-Host "==> Checking build tools inside WSL..." -ForegroundColor Cyan
$checkTools = (& wsl.exe -e bash -lc "which g++ make python3 >/dev/null 2>&1 || echo missing" 2>$null)
$missingTools = if ($checkTools) { $checkTools.ToString().Trim() } else { "" }

if ($missingTools -eq "missing") {
    Write-Warning "One or more required tools (g++, make, python3) are missing in WSL."
    $install = $false
    if (-not $NonInteractive) {
        $resp = Read-Host "Install build-essential and python3 inside WSL with sudo apt-get? (Y/n)"
        if (-not $resp -or $resp.Trim().ToLower() -eq 'y') {
            $install = $true
        }
    } else {
        $install = $true
    }

    if ($install) {
        Write-Host "Running: sudo apt-get update && sudo apt-get install -y build-essential python3" -ForegroundColor Yellow
        & wsl.exe -e bash -lc "sudo apt-get update && sudo apt-get install -y build-essential python3"
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to install required tools inside WSL (exit code $LASTEXITCODE)."
            exit $LASTEXITCODE
        }
    } else {
        Write-Error "Cannot proceed without g++, make, and python3 inside WSL."
        exit 1
    }
} else {
    Write-Host "All required tools (g++, make, python3) are present in WSL." -ForegroundColor Green
}

Write-Host "==> Setup complete!" -ForegroundColor Green

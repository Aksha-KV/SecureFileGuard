# powershell/build.ps1 - Runs make inside WSL.
[CmdletBinding()]
param(
    [string]$WslDir
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\common.ps1"

$targetDir = Get-WslRepoPath -SyncChanges -WslDir $WslDir

Write-Host "==> Building SecureFileGuard in WSL ($targetDir)..." -ForegroundColor Cyan
Invoke-Wsl -Dir $targetDir -Command "make all"

Write-Host "==> Build succeeded!" -ForegroundColor Green

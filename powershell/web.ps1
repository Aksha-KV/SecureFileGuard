# powershell/web.ps1 - Starts the SecureFileGuard server in WSL and opens the browser.
[CmdletBinding()]
param(
    [int]$Port = 8000,
    [switch]$NoRateLimit,
    [string]$WslDir
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\common.ps1"

# Check if port is in use
$portBusy = $false
try {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    $listener.Start()
    $listener.Stop()
}
catch {
    $portBusy = $true
}

if ($portBusy) {
    Write-Error "Port $Port is already in use on localhost. Please specify a different port with -Port <number> (e.g. .\powershell\web.ps1 -Port 8080)."
    exit 1
}

$targetDir = Get-WslRepoPath -SyncChanges -WslDir $WslDir

Write-Host "==> Ensuring binaries and fixtures are prepared..." -ForegroundColor Cyan
Invoke-Wsl -Dir $targetDir -Command "make all && bash tools/make_fixtures.sh runtime/fixtures"

$rateLimitFlag = ""
if ($NoRateLimit) {
    $rateLimitFlag = "--no-rate-limit"
}

$url = "http://localhost:$Port"
Write-Host "==> Starting web server on $url..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop the server." -ForegroundColor Yellow

# Start browser in background job after short delay
$browseJob = Start-Job -ScriptBlock {
    param($targetUrl)
    Start-Sleep -Seconds 2
    try { Start-Process $targetUrl -ErrorAction SilentlyContinue } catch {}
} -ArgumentList $url

try {
    # Run server in foreground so console displays live logs and captures Ctrl+C
    Invoke-Wsl -Dir $targetDir -Command "exec python3 server/app.py --port $Port $rateLimitFlag"
}
finally {
    # Ensure any lingering server instance on that port is cleanly terminated
    $null = Invoke-Wsl -Dir $targetDir -Command "fuser -k $Port/tcp >/dev/null 2>&1 || true"
    Remove-Job -Job $browseJob -Force -ErrorAction SilentlyContinue 2>$null
    Write-Host "`n==> Web server stopped." -ForegroundColor Cyan
}

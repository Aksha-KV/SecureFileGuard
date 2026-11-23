# powershell/check.ps1 - Tests a single path string against all five guard variants.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Path,
    [string]$WslDir
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\common.ps1"

$targetDir = Get-WslRepoPath -SyncChanges -WslDir $WslDir

# Ensure guard_cli is built and fixtures exist
Invoke-Wsl -Dir $targetDir -Command "test -f build/guard_cli || make build/guard_cli"
Invoke-Wsl -Dir $targetDir -Command "test -d runtime/fixtures || bash tools/make_fixtures.sh runtime/fixtures"

# Pass path safely via Invoke-Wsl StdinInput (base64-piped to guard_cli)
$jsonOut = Invoke-Wsl -Dir $targetDir -Command './build/guard_cli "$(realpath runtime/fixtures/secure_files)"' -StdinInput $Path -ReturnOutput

if ([string]::IsNullOrWhiteSpace($jsonOut)) {
    Write-Error "guard_cli returned empty output."
    exit 1
}

try {
    $res = $jsonOut | ConvertFrom-Json
}
catch {
    Write-Host $jsonOut
    exit 1
}

Write-Host "================ Single Path Containment Check ================" -ForegroundColor Cyan
Write-Host "Input Path:    " -NoNewline
Write-Host ($Path.Replace("`0", "\0")) -ForegroundColor White
Write-Host "Ground Truth:  " -NoNewline
if ($res.expected -eq "ALLOW") {
    Write-Host "ALLOW" -ForegroundColor Green -NoNewline
} else {
    Write-Host "DENY" -ForegroundColor Red -NoNewline
}
Write-Host " — $($res.reason)" -ForegroundColor Gray

if ($res.oracle_method) {
    Write-Host "Oracle Method: $($res.oracle_method)" -ForegroundColor Gray
}
if ($res.resolved) {
    Write-Host "Resolves To:   $($res.resolved) ($($res.kind))" -ForegroundColor Gray
}

Write-Host ""
Write-Host ("{0,-6} {1,-20} {2,-10} {3}" -f "Var", "Technique", "Decision", "Verdict")
Write-Host ("{0,-6} {1,-20} {2,-10} {3}" -f "---", "---------", "--------", "-------")

foreach ($v in $res.variants) {
    Write-Host ("{0,-6} {1,-20} " -f $v.id, $v.name) -NoNewline
    if ($v.decision -eq "ALLOW") {
        Write-Host ("{0,-10} " -f $v.decision) -ForegroundColor Green -NoNewline
    } else {
        Write-Host ("{0,-10} " -f $v.decision) -ForegroundColor Red -NoNewline
    }

    if ($v.verdict -eq "correct") {
        Write-Host $v.verdict -ForegroundColor Green
    } elseif ($v.verdict -match "containment_failure|false_allow") {
        Write-Host "$($v.verdict) (CRITICAL)" -ForegroundColor Red
    } elseif ($v.verdict -match "type_mismatch|policy_mismatch") {
        Write-Host $v.verdict -ForegroundColor Yellow
    } else {
        Write-Host $v.verdict -ForegroundColor Cyan
    }
}
Write-Host "================================================================" -ForegroundColor Cyan

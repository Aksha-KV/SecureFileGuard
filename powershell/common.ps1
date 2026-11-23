# powershell/common.ps1 - Robust WSL orchestration and quoting helpers for SecureFileGuard.

function Assert-WslInstalled {
    try {
        $null = & wsl.exe --status 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "WSL is not available or encountered an error (exit code $LASTEXITCODE). Run 'wsl --status' to inspect."
            exit 1
        }
    }
    catch {
        Write-Error "wsl.exe was not found. Please install Windows Subsystem for Linux (WSL2)."
        exit 1
    }
}

function Protect-BashString {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$InputString
    )
    # Safely wrap input in single quotes, escaping any inner single quotes as '\''.
    # In POSIX bash: 'foo'\''bar' represents foo'bar.
    return "'" + $InputString.Replace("'", "'\''") + "'"
}

function Get-WinToWslPath {
    param([Parameter(Mandatory=$true)][string]$WindowsPath)
    $fullPath = [System.IO.Path]::GetFullPath($WindowsPath).Replace('\', '/')
    $wslPath = (& wsl.exe wslpath -a -u "$fullPath" 2>$null)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($wslPath)) {
        Write-Error "wslpath failed to convert path: $WindowsPath"
        exit 1
    }
    return $wslPath.Trim()
}

function Get-WslConfigFile {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    return (Join-Path $scriptDir ".wsl_dir")
}

function Get-WslTargetDir {
    param([string]$OverrideDir)

    $configFile = Get-WslConfigFile
    if (-not [string]::IsNullOrWhiteSpace($OverrideDir)) {
        Set-Content -Path $configFile -Value $OverrideDir.Trim() -Encoding UTF8
        return $OverrideDir.Trim()
    }

    if (Test-Path $configFile) {
        $saved = (Get-Content -Path $configFile -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($saved)) {
            return $saved
        }
    }

    # Derive default target directory name from current project folder name
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $folderName = Split-Path -Leaf (Get-Item "$scriptDir\..").FullName
    $defaultDir = "~/$folderName"
    Set-Content -Path $configFile -Value $defaultDir -Encoding UTF8
    return $defaultDir
}

function Sync-ProjectToWsl {
    param(
        [Parameter(Mandatory=$true)][string]$WslTargetDir
    )
    Assert-WslInstalled

    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $winProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptDir ".."))
    $wslWinSource = Get-WinToWslPath -WindowsPath $winProjectRoot

    # Target path in bash
    $wslTargetEscaped = if ($WslTargetDir.StartsWith("~")) {
        '"$HOME"' + (Protect-BashString ($WslTargetDir.Substring(1)))
    } else {
        Protect-BashString $WslTargetDir
    }

    $wslSourceEscaped = Protect-BashString $wslWinSource

    # Check if rsync is available in WSL
    $checkRsync = (& wsl.exe -e bash -lc "command -v rsync >/dev/null 2>&1 && echo yes" 2>$null)
    $hasRsync = ($checkRsync -and $checkRsync.ToString().Trim() -eq "yes")

    if ($hasRsync) {
        $syncCmd = "mkdir -p $wslTargetEscaped && rsync -au --exclude='.git' --exclude='runtime' --exclude='build' --exclude='__pycache__' $wslSourceEscaped/ $wslTargetEscaped/"
        & wsl.exe -e bash -lc $syncCmd
    } else {
        Write-Warning "rsync is not installed in WSL. Falling back to tar-based synchronization."
        Write-Warning "To install rsync in WSL: sudo apt-get update && sudo apt-get install -y rsync"
        $syncCmd = "mkdir -p $wslTargetEscaped && tar -C $wslSourceEscaped --exclude='.git' --exclude='runtime' --exclude='build' --exclude='__pycache__' -cf - . | tar -C $wslTargetEscaped -xf -"
        & wsl.exe -e bash -lc $syncCmd
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to synchronize project files to WSL ($WslTargetDir) with exit code $LASTEXITCODE."
        exit $LASTEXITCODE
    }
}

function Invoke-Wsl {
    param(
        [string]$Dir,
        [Parameter(Mandatory=$true)][string]$Command,
        [string]$StdinInput,
        [switch]$ReturnOutput
    )
    Assert-WslInstalled

    $cdClause = ""
    if (-not [string]::IsNullOrWhiteSpace($Dir)) {
        if ($Dir.StartsWith("~")) {
            $bashDir = '"$HOME"' + (Protect-BashString ($Dir.Substring(1)))
            $cdClause = "cd $bashDir && "
        } else {
            $cdClause = "cd " + (Protect-BashString $Dir) + " && "
        }
    }

    $fullBash = $cdClause + $Command

    if ($StdinInput -ne $null) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($StdinInput)
        $b64 = [Convert]::ToBase64String($bytes)
        $pipedBash = "echo '$b64' | base64 -d | ($fullBash)"
        if ($ReturnOutput) {
            $out = & wsl.exe -e bash -lc $pipedBash
            $ec = $LASTEXITCODE
            if ($ec -ne 0) {
                Write-Error "WSL command failed with exit code ${ec}: $fullBash"
                exit $ec
            }
            return $out
        } else {
            & wsl.exe -e bash -lc $pipedBash
            $ec = $LASTEXITCODE
            if ($ec -ne 0) {
                Write-Error "WSL command failed with exit code ${ec}: $fullBash"
                exit $ec
            }
        }
    } else {
        if ($ReturnOutput) {
            $out = & wsl.exe -e bash -lc $fullBash
            $ec = $LASTEXITCODE
            if ($ec -ne 0) {
                Write-Error "WSL command failed with exit code ${ec}: $fullBash"
                exit $ec
            }
            return $out
        } else {
            & wsl.exe -e bash -lc $fullBash
            $ec = $LASTEXITCODE
            if ($ec -ne 0) {
                Write-Error "WSL command failed with exit code ${ec}: $fullBash"
                exit $ec
            }
        }
    }
}

function Get-WslRepoPath {
    param(
        [switch]$SyncChanges = $true,
        [string]$WslDir
    )
    $targetDir = Get-WslTargetDir -OverrideDir $WslDir

    if ($SyncChanges) {
        Sync-ProjectToWsl -WslTargetDir $targetDir
    }

    return $targetDir
}

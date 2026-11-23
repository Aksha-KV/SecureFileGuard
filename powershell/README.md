# SecureFileGuard - Windows PowerShell Guide

This folder contains Windows PowerShell automation scripts to build, test, benchmark, and run SecureFileGuard while transparently executing the underlying Linux C++ engine inside WSL2.

---

## Quick Start (Copy-Paste)

### 1. Allow Script Execution in Current Session
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 2. Run Presentation Demo (End-to-End)
```powershell
.\powershell\demo.ps1
```

### 3. Dry Run (WhatIf Mode)
```powershell
.\powershell\demo.ps1 -WhatIf
```

---

## Available Scripts

| Script | Purpose | Example |
| :--- | :--- | :--- |
| `setup.ps1` | Checks WSL, detects `/mnt/c` mounts, copies to ext4, verifies build tools | `.\powershell\setup.ps1` |
| `build.ps1` | Compiles `guard_cli`, `toctou_race`, and `run_tests` inside WSL | `.\powershell\build.ps1` |
| `test.ps1` | Runs 36 test cases, prints colored metrics, exports `results.csv` | `.\powershell\test.ps1 -OutDir .\results` |
| `check.ps1` | Tests a single path string safely (supports spaces, unicode, quotes) | `.\powershell\check.ps1 -Path "../outside_secret.txt"` |
| `race.ps1` | Runs TOCTOU race demo with custom iterations and repeated runs | `.\powershell\race.ps1 -Iterations 50000 -Runs 3` |
| `web.ps1` | Starts web server in WSL, handles port conflicts, opens browser | `.\powershell\web.ps1 -Port 8000` |
| `demo.ps1` | Complete presentation workflow (setup, build, test, race, web) | `.\powershell\demo.ps1 -Port 8000` |

---

## Quoting & Safety Architecture

All scripts use `Invoke-Wsl` and `Protect-BashString` from `powershell/common.ps1`:
- Arguments and paths are strictly single-quoted (`'...'`) with internal single-quote escaping (`'\''`).
- Paths with spaces, apostrophes, double quotes, dollar signs (`$`), backticks, and Unicode characters are passed without shell injection risks.
- Input paths are piped via base64 decoding on stdin to prevent shell expansion.
- Every WSL invocation checks `$LASTEXITCODE` and stops immediately on failure.
- Target WSL directory is stored in `powershell/.wsl_dir` (default: derived from project folder name, or configured with `-WslDir`).

---

## Troubleshooting Table

| Error / Symptom | Root Cause | Solution |
| :--- | :--- | :--- |
| `File ... cannot be loaded because running scripts is disabled` | PowerShell ExecutionPolicy is set to `Restricted` | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in your PowerShell window. |
| `wsl.exe was not found` | WSL is not installed or enabled on Windows | Run `wsl --install` from an elevated PowerShell prompt and restart Windows. |
| `Operation not supported` on `mkfifo` / symlink issues | Project run on Windows DrvFS mount (`/mnt/c`) | Run `.\powershell\setup.ps1` to automatically sync files to the native WSL ext4 filesystem (`~/<project-name>`). |
| `Port 8000 is already in use` | Another service is using port 8000 | Specify a different port with `-Port <number>` (e.g., `.\powershell\web.ps1 -Port 8080`) or stop the conflicting service. |
| `rsync is not installed in WSL` | Ubuntu minimal installation lacks `rsync` | `common.ps1` automatically falls back to `tar`. To install rsync: `wsl -e bash -lc "sudo apt-get update && sudo apt-get install -y rsync"`. |

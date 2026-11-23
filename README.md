# SecureFileGuard Lab

An interactive research testbench comparing five C++ path-containment strategies (V0 to V4) against path traversal, symlink escapes, and TOCTOU race conditions, evaluated against an independent POSIX `realpath(3)` ground truth.

```
       Input Path  ──>  [ V0 Naive Prefix               ]  ──>  ALLOW / DENY
                        [ V1 Lexically Normal           ]  ──>  ALLOW / DENY
                        [ V2 Weakly Canonical           ]  ──>  ALLOW / DENY
                        [ V3 Canonical Path             ]  ──>  ALLOW / DENY
                        [ V4 openat2(RESOLVE_BENEATH)   ]  ──>  ALLOW / DENY
                                  vs.
                        [ Independent realpath(3) Oracle]  ──>  Ground Truth
```

---

## What This Project Proves

1. **Text manipulation is not path security**: Naive prefix checks (`V0`) fail on `..` traversal and sibling folders (e.g., `secure_files_backup`). Lexical normalization (`V1`) stops simple traversal but cannot inspect symlinks on disk.
2. **"Check-then-open" designs are vulnerable to TOCTOU races**: Canonical checks (`V2`, `V3`) properly detect symlink escapes at check time, but opening the file by name creates a Time-of-Check to Time-of-Use window where concurrent attackers swap targets.
3. **Kernel-enforced containment solves both**: `openat2` with `RESOLVE_BENEATH` (`V4`) resolves and opens the target in a single kernel call, refusing to cross directory boundaries or follow symlinks escaping the jail, eliminating race windows.
4. **Fair evaluation matters**: Non-regular files (`.` directory, FIFO) and non-existent files are policy mismatches, not security traversal attacks. Evaluating **Containment Failures**, **File-Type Policy**, and **Missing-File Policy** separately gives an honest, defensible comparison.

---

## Requirements

- **Operating System**: Linux or Windows Subsystem for Linux (WSL2 with Ubuntu 20.04/22.04/24.04).
- **Kernel**: Linux kernel >= 5.6 (required for `openat2` syscall and `RESOLVE_BENEATH`).
- **Compiler**: `g++` with C++17 support (`-std=c++17`).
- **Build System**: `make` (canonical build) or `cmake` >= 3.10.
- **Runtime**: Python 3.8+ (**standard library only**, zero third-party packages).
- **Filesystem**: Native Linux filesystem (`ext4`, e.g. `~/SecureFileGuard-Web`). **Do not run fixtures directly on `/mnt/c`** as DrvFS does not support FIFOs (`mkfifo`) or native Linux symlink semantics.

---

## Two Ways to Run

### Method 1: Windows PowerShell (Engine in WSL)

The project includes first-class Windows PowerShell scripts that orchestrate WSL under the hood, syncing changes and colorizing output.

#### Script Execution Policy
To allow PowerShell scripts in your current terminal session:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

#### One-Command Presentation Demo
Run the complete presentation flow (environment setup, build, test suite with metrics, race demo, and web browser launch):
```powershell
.\powershell\demo.ps1
```

#### Individual PowerShell Commands
- **Environment Setup**: Checks WSL and tools, syncs project to native WSL ext4 filesystem:
  ```powershell
  .\powershell\setup.ps1
  ```
- **Build**: Compiles binaries inside WSL using header dependency tracking:
  ```powershell
  .\powershell\build.ps1
  ```
- **Test Suite**: Runs all 30 tests, prints colorized Expected vs. Actual and metrics table, copies `results/results.csv` to Windows:
  ```powershell
  .\powershell\test.ps1 -OutDir .\results
  ```
- **Check Single Path**: Evaluates one user-supplied path string:
  ```powershell
  .\powershell\check.ps1 -Path "../outside_secret.txt"
  .\powershell\check.ps1 -Path "notes.txt"
  ```
- **TOCTOU Race Demo**: Runs repeated concurrent symlink swapping race runs:
  ```powershell
  .\powershell\race.ps1 -Iterations 100000 -Runs 3
  ```
- **Start Web Server**: Launches the Python server inside WSL and opens the browser on localhost:
  ```powershell
  .\powershell\web.ps1 -Port 8000
  ```

---

### Method 2: Native Linux / WSL Bash

Run directly from inside WSL (e.g. `~/SecureFileGuard-Web`):

```bash
# Build all targets (guard_cli, toctou_race, run_tests)
make

# Run C++ tests and Python security unit tests
make test

# Start the web server and open http://127.0.0.1:8000
./scripts/run.sh
# or customize host and port:
./scripts/run.sh --port 8080 --host 127.0.0.1
```

---

## Deployment

SecureFileGuard-Web can be hosted either as a full containerized C++17 + Python engine or as a static frontend demo.

### 1. Render (Docker Web Service)
1. In the [Render Dashboard](https://dashboard.render.com/), select **New + > Web Service** and connect your GitHub repository (`Aksha-KV/SecureFileGuard`).
2. Select **Docker** as the runtime (Render will automatically detect the root `Dockerfile`).
3. In the service settings, configure the environment variables:
   - `HOST`: `0.0.0.0`
   - `PORT`: `10000` (Render will automatically pass its assigned port via `$PORT`)
   - `ALLOWED_HOSTS`: `*.onrender.com,your-service-name.onrender.com`
   - `TRUST_PROXY`: `true`
4. Click **Deploy**. Render builds the C++ binaries, generates fixtures on native ext4, and serves the lab.

### 2. Fly.io (Linux MicroVM with Docker)
Fly.io runs native Linux microVMs with modern kernels ($\ge 5.15$), fully supporting `V4` (`openat2` + `RESOLVE_BENEATH`).
1. Install `flyctl` and log in:
   ```bash
   fly auth login
   ```
2. Launch using the included `fly.toml`:
   ```bash
   fly launch --copy-config
   ```
3. Set your deployment secrets/variables:
   ```bash
   fly secrets set ALLOWED_HOSTS="*.fly.dev,your-app.fly.dev" TRUST_PROXY="true"
   ```
4. Deploy:
   ```bash
   fly deploy
   ```

### 3. Hugging Face Spaces (Docker)
1. Create a new Space on [Hugging Face](https://huggingface.co/spaces) and select the **Docker** SDK (Blank).
2. Connect or push your repository.
3. Hugging Face Spaces automatically builds the `Dockerfile` and expects port `7860`. Set the Space variables:
   - `PORT`: `7860`
   - `ALLOWED_HOSTS`: `*.hf.space`
   - `TRUST_PROXY`: `true`

### 4. Vercel (Static Frontend Demo Only)
If deploying only the web presentation and static interface (without live C++ backend execution):
1. Import the repository into [Vercel](https://vercel.com/).
2. Vercel automatically detects [vercel.json](file:///c:/Users/dell/OneDrive/Desktop/SecureFileGuard-Web-updated/vercel.json), serving `server/static` with clean URLs for `/`, `/research`, and `/results`.
3. Deploy with zero build configuration needed.

> [!IMPORTANT]
> **Kernel & Filesystem Requirements for Full Engine:**
> - **Linux Kernel >= 5.6 Required**: Variant `V4` (`openat2` with `RESOLVE_BENEATH`) requires Linux kernel $\ge 5.6$. On older kernels or non-Linux hosts, `server/app.py` prints an explicit error on startup.
> - **Native Ext4 / OverlayFS Filesystem Required**: Do not mount fixtures on Windows DrvFS (`/mnt/c`), as Windows mounts do not support `mkfifo` (FIFOs) or Linux symlink properties. Docker containers on Linux, Render, Fly.io, and Hugging Face Spaces satisfy this natively.

---

## Project Structure

```
.
├── Makefile                # Canonical build system (header dependency tracking -MMD -MP)
├── CMakeLists.txt          # Alternative CMake build (supports all targets)
├── README.md               # Documentation and guides
├── cli/
│   └── guard_cli.cpp       # CLI runner: stdin path -> JSON (independent oracle, zero leak)
├── demo/
│   └── toctou_race.cpp     # Multi-threaded TOCTOU symlink race benchmark (min/max/total)
├── powershell/             # Windows host scripts (executes engine in WSL)
│   ├── common.ps1          # Shared WSL path translation and environment checks
│   ├── setup.ps1           # WSL setup, /mnt/c warning, package installer
│   ├── build.ps1           # Runs make inside WSL
│   ├── test.ps1            # Runs test suite, colorized metrics, exports CSV
│   ├── check.ps1           # Single path containment checker
│   ├── race.ps1            # Multi-run TOCTOU benchmark runner
│   ├── web.ps1             # Web server launcher with browser auto-open
│   └── demo.ps1            # Full end-to-end presentation demo
├── results/
│   └── results.csv         # Generated benchmark evaluation matrix
├── scripts/
│   └── run.sh              # Bash build, fixture regeneration, and server start
├── server/
│   ├── app.py              # Hardened stdlib HTTP server (rate limiting, host/origin checks)
│   └── static/             # Self-contained UI (HTML/CSS/JS, zero CDN/external dependencies)
├── src/                    # C++17 guard implementations (V0 to V4)
│   ├── guard.hpp           # Common guard interfaces and variant registry
│   ├── common.hpp          # String and path component utilities
│   ├── guard_v0.cpp        # V0: Naive prefix check
│   ├── guard_v1.cpp        # V1: std::filesystem::path::lexically_normal
│   ├── guard_v2.cpp        # V2: std::filesystem::weakly_canonical
│   ├── guard_v3.cpp        # V3: std::filesystem::canonical
│   └── guard_v4.cpp        # V4: openat2(2) with RESOLVE_BENEATH
├── tests/
│   ├── run_tests.cpp       # CLI test suite runner with Fair Evaluation metrics
│   ├── test_cases.hpp      # Test case definitions (Attack vs Legit vs Type vs Missing)
│   ├── test_cases.cpp      # 30 comprehensive test cases
│   └── test_server.py      # Python unittest suite for server security controls
└── tools/
    └── make_fixtures.sh    # Test fixture generator (symlinks, fifos, folders)
```

---

## Verified On (Reference Test Environment)

Generated from live `/api/info` system diagnostics:

| Component | Verified Specification | Notes |
| :--- | :--- | :--- |
| **Operating System** | WSL2 Ubuntu 24.04 LTS (Windows 11 host) | ext4 Linux filesystem (~/SecureFileGuard-Web) |
| **Linux Kernel** | `6.18.58.1-microsoft-standard-WSL2` (x86_64) | >= 5.6 required for `openat2` syscall |
| **C++ Compiler** | `g++ 13.3.0` (`-std=c++17 -O2 -Wall -Wextra`) | Standard C++17 filesystem & POSIX APIs |
| **Python Runtime** | `Python 3.12.3` | **Standard library only** (0 external dependencies) |
| **PowerShell & Pester** | Windows PowerShell 5.1 / Pester 3.4.0+ / pwsh | Safe single-quoted base64 IPC |
| **Oracle Implementation** | `realpath(3)` + `stat(2)` | Independent from `std::filesystem::canonical` |

---

## What Each Result Means for a Security Reviewer

When reviewing path-validation mechanisms in code reviews or penetration testing, results fall into four critical categories:

1. **Containment Failures (Critical Vulnerability - Arbitrary File Read / Escape)**
   - *Definition*: The guard returned `ALLOW` for an input whose fully resolved path leaves the jail root.
   - *Security Impact*: High/Critical. An attacker can read sensitive files outside the jail (e.g. `../../etc/passwd`, symlink to `/var/log` or sibling directories).
   - *Observations*: `V0` (naive prefix) completely fails on `..` traversals. `V1` (`lexically_normal`) completely fails on disk symlinks because it never touches the filesystem.

2. **File-Type Policy Mismatches (Non-Security Policy Divergence)**
   - *Definition*: The guard returned `ALLOW` for an entity inside the jail that is not a regular file (e.g. `.` directory, `reports/` folder, `fifo` named pipe).
   - *Security Impact*: Low/Operational. Reading a directory can fail or cause listing disclosures; opening a FIFO can block indefinitely (DoS). Not an escape.
   - *Observations*: `V0` through `V3` allow directories because they only check path names, not file descriptors. `V4` inspects `fstat` on the opened descriptor and enforces regular files only.

3. **Missing-Name Policy Mismatches (Policy Divergence)**
   - *Definition*: The guard returned `ALLOW` for a file name that does not exist or has invalid syntax (e.g. `missing.txt`, `notes.txt...` trailing dots, backslashes, percent-encoding).
   - *Security Impact*: Low (under strict missing=deny policy). In applications that check existence before opening, missing names should be rejected.
   - *Observations*: `V0` and `V1` allow missing names because they only inspect strings. `V3` and `V4` require the file to exist.

4. **False Blocks (Availability / Usability Trade-off)**
   - *Definition*: The guard returned `DENY` for a legitimate regular file located inside the jail folder.
   - *Security Impact*: Functional regression.
   - *Observations*: `V4` intentionally denies absolute symlinks even when they point inside the jail. This is a documented, deliberate trade-off of `RESOLVE_BENEATH` to eliminate root-breakout bypasses.

5. **TOCTOU Concurrency Escapes (Race Condition)**
   - *Definition*: An attacker thread continuously replaces an allowed file with an outside symlink while a victim thread checks and then opens the file.
   - *Security Impact*: Critical. `V2` (weakly_canonical) and `V3` (canonical) pass check-time validation, but the target is swapped before `open()` executes, leaking secret data.
   - *Observations*: `V4` (`openat2 RESOLVE_BENEATH`) achieves **0 escapes** across all iterations and runs because the kernel resolves and opens atomically.

---

## Fair Evaluation Metrics

Traditional path-traversal benchmarks label any disagreement with a strict policy as a "false allow", misleadingly inflating failure rates for directory inputs or non-existent files. SecureFileGuard separates these into three clear dimensions:

1. **Containment Failures** (*Critical Security Flaw*): The variant returns `ALLOW` for an input whose fully resolved path escapes the jail (e.g. `../../etc/passwd`, symlink pointing outside).
2. **File-Type Policy Mismatches**: The variant returns `ALLOW` for an entity that stays inside the jail but is not a regular file (e.g. `.` directory, `fifo`).
3. **Missing-File Policy Mismatches**: The variant returns `ALLOW` for non-existent names (e.g. `missing.txt`, `notes.txt/`, literal backslash names).
4. **False Blocks**: The variant returns `DENY` for a legitimate regular file inside the jail.

All metric tables and web views display the exact counts next to every percentage (e.g., `BlockRate = 12/12 attacks (100%)`).

---

## Security Hardening & Safeguards

Because this testbench explores path traversal, the server itself is strictly hardened:
- **Zero Information Leak**: For queries resolving outside the jail, `guard_cli` returns `"resolved": null` and `"kind": null`. It never leaks whether outside files (e.g. `/etc/shadow`) exist or what file type they have.
- **DNS Rebinding & Host Validation**: POST endpoints reject requests unless the `Host` header matches `127.0.0.1:<port>` or `localhost:<port>`.
- **Cross-Site Request Protection**: Origin headers, when present, must strictly match the permitted localhost origin.
- **Content-Type Enforcement**: POST requests must specify `Content-Type: application/json`.
- **Slowloris Mitigation**: Per-connection socket timeout (`timeout = 10` seconds) on the HTTP handler.
- **In-Memory Rate Limiting**: Sliding window per-IP rate limiting (60 requests/min general, 10/min for race demo). Can be toggled with `--no-rate-limit`.
- **Subprocess Safety**: Fixed jail root (users cannot set roots), static file whitelist (no filesystem traversal), request body capped at 20 KB, argument lists without shell invocation, subprocess timeouts, and single-flight race demo concurrency lock.
- **Zero External Assets**: All styles, icons, fonts, and charts are local and self-contained; strict Content Security Policy (`default-src 'self'`).

---

## Ground Truth ("Oracle")

The ground truth oracle in `cli/guard_cli.cpp` is implemented using standard POSIX **`realpath(3)`** and `stat(2)`. It is completely independent of `std::filesystem::canonical` (which variant V3 uses), ensuring an unbiased evaluation.

---

## Troubleshooting

| Problem | Cause | Solution |
| :--- | :--- | :--- |
| **`g++` or `make` not found** | Required build tools missing in WSL | Run `sudo apt-get update && sudo apt-get install -y build-essential python3`, or run `.\powershell\setup.ps1`. |
| **`Operation not supported` on `mkfifo`** | Running fixtures under Windows `/mnt/c` | Windows DrvFS does not support Linux FIFOs or native symlink properties. Copy to native WSL ext4 filesystem (e.g. `~/SecureFileGuard-Web`). `powershell\setup.ps1` handles this automatically. |
| **V4 denies everything or kernel startup error** | Linux kernel < 5.6 or openat2 returns `ENOSYS` | Check kernel with `uname -r`. Linux kernel >= 5.6 is required for `openat2` and `RESOLVE_BENEATH`. Server prints clear error and exits if unsupported. |
| **HTTP 403 `forbidden host: invalid Host header`** | Host header mismatch (DNS rebinding safeguard) | By default only `localhost` and `127.0.0.1` are permitted. For custom domains or hosted IPs, launch with `--allowed-host mydomain.com:8000`. |
| **HTTP 429 `rate limit exceeded`** | Too many requests from single IP | Sliding-window limiter bounds memory (60 req/min general, 10 req/min race). Disable for local testing with `--no-rate-limit`. |
| **`rsync` missing in WSL** | Minimal WSL distribution installed | `powershell/setup.ps1` automatically detects missing `rsync` and falls back cleanly to `tar`, or install with `sudo apt install -y rsync`. |
| **Custom project folder name** | Renaming project root directory | Scripts never hardcode paths; target WSL path is automatically derived from your folder name and persisted in `powershell/.wsl_dir` (override with `-WslDir`). |
| **Port in use (`Port 8000 is already in use`)** | Another process is bound to port 8000 | Specify a different port: `./scripts/run.sh --port 8080` or `.\powershell\web.ps1 -Port 8080`, or terminate the previous instance with `fuser -k 8000/tcp`. |
| **PowerShell script execution disabled** | Windows PowerShell restricted execution policy | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in your PowerShell session. |

---

## Limitations

1. **Single-Machine Evaluation**: TOCTOU race measurements depend on host CPU core count, thread scheduling, and hardware timing.
2. **Probabilistic Race Results**: A race demo result of 0 escapes in a single run is probabilistic and does **not** prove safety; running repeated runs exposes intermittent race windows.
3. **Linux-Only V4**: `openat2(2)` with `RESOLVE_BENEATH` is a Linux-specific kernel feature. macOS and Windows require different containment APIs (e.g., sandbox profiles or directory capabilities).
4. **Oracle Scope**: The ground truth oracle relies on `realpath(3)` at test time.

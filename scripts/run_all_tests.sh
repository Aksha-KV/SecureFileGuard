#!/usr/bin/env bash
# scripts/run_all_tests.sh - Unified test runner for C++, Python, and PowerShell/Pester tests.
set -u

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE"

PASSED=0
FAILED=0
CPP_STATUS="FAIL"
PY_STATUS="FAIL"
PWSH_STATUS="SKIPPED"

echo "================================================================"
echo "          SecureFileGuard Comprehensive Test Runner             "
echo "================================================================"

# 1. Regenerate fixtures
echo -e "\n[1/3] Generating fixtures..."
if bash tools/make_fixtures.sh runtime/fixtures; then
    echo "Fixtures generated successfully."
else
    echo "ERROR: Fixture generation failed!"
    exit 1
fi

# 2. C++ Test Suite
echo -e "\n[2/3] Running C++ Containment Engine Tests..."
if [ -x ./build/run_tests ]; then
    if ./build/run_tests runtime/fixtures results/results.csv; then
        CPP_STATUS="PASS"
        PASSED=$((PASSED + 1))
    else
        CPP_STATUS="FAIL"
        FAILED=$((FAILED + 1))
    fi
else
    echo "ERROR: build/run_tests binary not found! Run make all first."
    CPP_STATUS="FAIL"
    FAILED=$((FAILED + 1))
fi

# 3. Python Integration & Hardening Tests
echo -e "\n[3/3] Running Python Server Integration & Security Tests..."
if python3 -m unittest discover -s tests -p "test_*.py"; then
    PY_STATUS="PASS"
    PASSED=$((PASSED + 1))
else
    PY_STATUS="FAIL"
    FAILED=$((FAILED + 1))
fi

# 4. PowerShell / Pester Tests (if pwsh is installed)
if command -v pwsh >/dev/null 2>&1; then
    echo -e "\n[4/4] Running PowerShell / Pester Quoting Tests (pwsh detected)..."
    if pwsh -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Pester -Script powershell/tests/Quoting.Tests.ps1 -EnableExit"; then
        PWSH_STATUS="PASS"
        PASSED=$((PASSED + 1))
    else
        PWSH_STATUS="FAIL"
        FAILED=$((FAILED + 1))
    fi
else
    PWSH_STATUS="SKIPPED (pwsh not in PATH)"
fi

echo -e "\n================================================================"
echo "                      TEST EXECUTION SUMMARY                    "
echo "================================================================"
printf "  %-32s : %s\n" "C++ Containment Engine Tests" "$CPP_STATUS"
printf "  %-32s : %s\n" "Python Server Security Tests" "$PY_STATUS"
printf "  %-32s : %s\n" "PowerShell / Pester Tests" "$PWSH_STATUS"
echo "----------------------------------------------------------------"

if [ "$FAILED" -eq 0 ] && [ "$CPP_STATUS" = "PASS" ] && [ "$PY_STATUS" = "PASS" ]; then
    echo "  OVERALL RESULT: ALL REQUIRED TEST SUITES PASSED [PASS]"
    echo "================================================================"
    exit 0
else
    echo "  OVERALL RESULT: ONE OR MORE TEST SUITES FAILED [FAIL]"
    echo "================================================================"
    exit 1
fi

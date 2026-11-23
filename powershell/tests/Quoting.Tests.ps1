# powershell/tests/Quoting.Tests.ps1 - Pester tests for PowerShell quoting helpers.
# Runs locally in Windows PowerShell without requiring WSL.
$ProgressPreference = 'SilentlyContinue'

$commonPath = if ($PSScriptRoot) {
    Join-Path $PSScriptRoot "..\common.ps1"
} else {
    Join-Path (Get-Location) "powershell\common.ps1"
}
. ([System.IO.Path]::GetFullPath($commonPath))

Describe "Protect-BashString Helper" {
    It "wraps standard strings in single quotes" {
        Protect-BashString "simple_path" | Should Be "'simple_path'"
    }

    It "preserves and quotes strings with spaces" {
        Protect-BashString "path with spaces" | Should Be "'path with spaces'"
    }

    It "properly escapes apostrophes/single quotes" {
        Protect-BashString "user's_folder" | Should Be "'user'\''s_folder'"
    }

    It "handles strings with multiple apostrophes" {
        Protect-BashString "it's john's file" | Should Be "'it'\''s john'\''s file'"
    }

    It "preserves dollar signs without variable interpolation in bash" {
        $actual = Protect-BashString '$HOME/$VAR/test'
        $expected = "'`$HOME/`$VAR/test'"
        $actual | Should Be $expected
    }

    It "preserves backticks without command substitution in bash" {
        $actual = Protect-BashString '`whoami`_test'
        $expected = "'``whoami``_test'"
        $actual | Should Be $expected
    }

    It "preserves double quotes inside single quotes" {
        $actual = Protect-BashString 'path with "double quotes"'
        $expected = "'path with `"double quotes`"'"
        $actual | Should Be $expected
    }

    It "handles Unicode and emoji characters without corruption" {
        Protect-BashString "café_naïve_📁_résumé" | Should Be "'café_naïve_📁_résumé'"
    }

    It "handles combination of spaces, apostrophes, dollars, and unicode" {
        $inputStr = "user's folder `$100 / café_éàç"
        $expected = "'user'\''s folder `$100 / café_éàç'"
        Protect-BashString $inputStr | Should Be $expected
    }

    It "handles empty string" {
        Protect-BashString "" | Should Be "''"
    }
}

Describe "Get-WslTargetDir Configuration" {
    It "returns configured directory when overridden" {
        $cfg = Get-WslConfigFile
        $backup = if (Test-Path $cfg) { Get-Content -Path $cfg -Raw } else { $null }
        try {
            $testDir = "~/custom_test_dir"
            $res = Get-WslTargetDir -OverrideDir $testDir
            $res | Should Be $testDir
        } finally {
            if ($backup -ne $null) {
                Set-Content -Path $cfg -Value $backup -Encoding UTF8
            } else {
                if (Test-Path $cfg) { Remove-Item $cfg -Force }
            }
        }
    }
}

<#
.RUTILUS SHA-256 manifest generator (PowerShell) — release pipeline (§5.4:
生成 SHA-256, 1.0.0 release condition 17). Windows-side twin of
scripts/checksums.sh; emits the same standard sha256sum format
"<lowercase-hex>  <basename>" for cross-platform verification with
`sha256sum -c`.
Writes LF line endings: POSIX `sha256sum -c` treats CRLF as part of the
filename token and fails every line (H4 audit MINOR 2; verified 2026-08-12,
5/5 FAILED with the previous CRLF output).

Usage:
  powershell -ExecutionPolicy Bypass -File scripts/checksums.ps1 <file> [<file> ...]
  powershell -ExecutionPolicy Bypass -File scripts/checksums.ps1 -Output release\SHA256SUMS release\*.exe

Parameters:
  -Output   Manifest path (default: SHA256SUMS in the working dir).
  -Files    Files to hash (positional arguments are also accepted).

Writes atomically (tmp file + move), so a failed run never leaves a
truncated manifest.

Exit codes: 0 = manifest written; 1 = missing input file.
#>
[CmdletBinding()]
param(
    [string]$Output = 'SHA256SUMS',
    [Parameter(Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Files
)

$lines = [System.Collections.Generic.List[string]]::new()
foreach ($file in $Files) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        Write-Host "checksums.ps1: ERROR: file not found: $file" -ForegroundColor Red
        exit 1
    }
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
    $name = Split-Path -Leaf -Path $file
    $lines.Add("$hash  $name")
}

$tmp = "$Output.tmp.$PID"
# LF line endings (see header): WriteAllLines would emit Environment.NewLine
# (CRLF on Windows) and break `sha256sum -c`; join with "`n" explicitly.
# UTF-8 no BOM and the atomic tmp+move write are unchanged.
[System.IO.File]::WriteAllText($tmp, ($lines -join "`n") + "`n", (New-Object System.Text.UTF8Encoding($false)))
Move-Item -Force -LiteralPath $tmp -Destination $Output
Write-Host "checksums.ps1: wrote $Output ($($lines.Count) files)"

<#
.RUTILUS Windows Authenticode signing script — release pipeline (§5.4 of
redfish-management-product-final-design.md, 1.0.0 release condition 17).

Signs one or more PE executables with SHA-256 Authenticode plus an RFC 3161
timestamp (DigiCert), using signtool from the Windows SDK. Each file is
verified afterwards with `signtool verify /pa /tw`.

Usage:
  powershell -ExecutionPolicy Bypass -File scripts/sign-windows.ps1 <exe> [<exe> ...]
  powershell -ExecutionPolicy Bypass -File scripts/sign-windows.ps1 -Files a.exe, b.exe -SigntoolPath C:\sdk\signtool.exe -SkipVerify

Parameters:
  -Files          PE files to sign (positional arguments are also accepted).
  -SigntoolPath   Explicit path to signtool.exe. When omitted, signtool is
                  resolved from PATH first, then from the Windows Kits SDK
                  (`C:\Program Files (x86)\Windows Kits\10\bin\<ver>\x64\
                  signtool.exe`, newest version wins) — the path the
                  windows-latest GitHub runner ships with.
  -SkipVerify     Skip the post-sign `signtool verify /pa /tw` step.

Environment (certificate material is passed ONLY through these variables;
the script never echoes the password or the certificate itself):
  RUTILUS_WINDOWS_CERT_PATH        Path to the signing PFX. Required unless
                                   RUTILUS_WINDOWS_CERT_THUMBPRINT is set.
  RUTILUS_WINDOWS_CERT_PASSWORD    PFX password. Required when CERT_PATH is
                                   set (set any non-empty placeholder value
                                   for an unprotected PFX).
  RUTILUS_WINDOWS_CERT_THUMBPRINT  SHA-1 or SHA-256 thumbprint of a signing
                                   certificate already installed in the
                                   current user's "My" certificate store.
                                   Alternative to CERT_PATH; takes
                                   precedence when both are set (keeps the
                                   key material entirely out of CI args).

The PFX password is passed to signtool's `/p` option (its standard interface;
it appears in no log line this script emits). For a fully env-only flow,
import the PFX once on the signing host and use
RUTILUS_WINDOWS_CERT_THUMBPRINT instead.

Exit codes: 0 = every file signed and verified; 1 = no certificate env
configured, a file or signtool is missing, or a sign/verify failure.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Files,
    [string]$SigntoolPath,
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Stop'
$TimestampUrl = 'http://timestamp.digicert.com'

# --- certificate material ----------------------------------------------------
$thumbprint = $env:RUTILUS_WINDOWS_CERT_THUMBPRINT
$pfx = $env:RUTILUS_WINDOWS_CERT_PATH
$pfxPassword = $env:RUTILUS_WINDOWS_CERT_PASSWORD

$missing = @()
if ([string]::IsNullOrWhiteSpace($thumbprint) -and [string]::IsNullOrWhiteSpace($pfx)) {
    $missing += 'RUTILUS_WINDOWS_CERT_THUMBPRINT (installed certificate) or RUTILUS_WINDOWS_CERT_PATH (PFX)'
}
if (-not [string]::IsNullOrWhiteSpace($pfx) -and [string]::IsNullOrWhiteSpace($pfxPassword)) {
    $missing += 'RUTILUS_WINDOWS_CERT_PASSWORD (required when RUTILUS_WINDOWS_CERT_PATH is set)'
}
if ($missing.Count -gt 0) {
    Write-Host "sign-windows.ps1: ERROR: no signing certificate configured; set:" -ForegroundColor Red
    foreach ($m in $missing) { Write-Host "  - $m" -ForegroundColor Red }
    Write-Host "sign-windows.ps1: signing skipped, nothing signed (exit 1)." -ForegroundColor Red
    exit 1
}

# --- locate signtool ---------------------------------------------------------
$signtool = $null
if (-not [string]::IsNullOrWhiteSpace($SigntoolPath)) {
    if (-not (Test-Path -LiteralPath $SigntoolPath -PathType Leaf)) {
        Write-Host "sign-windows.ps1: ERROR: -SigntoolPath does not exist: $SigntoolPath" -ForegroundColor Red
        exit 1
    }
    $signtool = $SigntoolPath
}
if (-not $signtool) {
    $cmd = Get-Command signtool -ErrorAction SilentlyContinue
    if ($cmd) { $signtool = $cmd.Source }
}
if (-not $signtool) {
    # windows-latest ships the Windows SDK; resolve the newest x64 signtool
    # across the versioned bin directories.
    $kits = 'C:\Program Files (x86)\Windows Kits\10\bin'
    if (Test-Path -LiteralPath $kits) {
        $found = Get-ChildItem -LiteralPath $kits -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
            ForEach-Object {
                $cand = Join-Path $_.FullName 'x64\signtool.exe'
                if (Test-Path -LiteralPath $cand) {
                    try { [pscustomobject]@{ Version = [version]$_.Name; Path = $cand } } catch {}
                }
            } |
            Sort-Object Version | Select-Object -Last 1
        if ($found) { $signtool = $found.Path }
    }
}
if (-not $signtool) {
    Write-Host "sign-windows.ps1: ERROR: signtool.exe not found; pass -SigntoolPath or install the Windows SDK." -ForegroundColor Red
    exit 1
}
Write-Host "sign-windows.ps1: using signtool: $signtool"

# --- sign --------------------------------------------------------------------
$commonArgs = @('/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256')
if (-not [string]::IsNullOrWhiteSpace($thumbprint)) {
    # /sha1 accepts SHA-1 or SHA-256 thumbprints (SDK >= 10.0.15063).
    $signArgs = $commonArgs + @('/sha1', $thumbprint)
    $modeDesc = "thumbprint $thumbprint (installed store)"
} else {
    $signArgs = $commonArgs + @('/f', $pfx, '/p', $pfxPassword)
    $modeDesc = "PFX $pfx"
}
Write-Host "sign-windows.ps1: certificate: $modeDesc"

$failed = $false
foreach ($file in $Files) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        Write-Host "sign-windows.ps1: ERROR: file not found: $file" -ForegroundColor Red
        $failed = $true
        continue
    }
    Write-Host "sign-windows.ps1: signing: $file"
    & $signtool sign @signArgs $file
    if ($LASTEXITCODE -ne 0) {
        Write-Host "sign-windows.ps1: ERROR: signtool sign failed for $file (exit $LASTEXITCODE)" -ForegroundColor Red
        $failed = $true
        continue
    }
    if (-not $SkipVerify) {
        & $signtool verify /pa /tw $file
        if ($LASTEXITCODE -ne 0) {
            Write-Host "sign-windows.ps1: ERROR: signtool verify failed for $file (exit $LASTEXITCODE)" -ForegroundColor Red
            $failed = $true
            continue
        }
    }
    Write-Host "sign-windows.ps1: OK: $file signed"
}

if ($failed) { exit 1 }
Write-Host "sign-windows.ps1: all files signed"
exit 0

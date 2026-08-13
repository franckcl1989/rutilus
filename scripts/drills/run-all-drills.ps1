# run-all-drills.ps1 - one-command re-run entry for the standalone drill suite
# (the live-run entry for the design section 19.3 remaining items, plus the
# S20.1/S20.2 backup/restore cycle; each drill file's own header carries its
# exact design clause references).
#
# Runs the 5 independently runnable drills in a fixed order, each inside its
# own powershell.exe (Windows PowerShell 5.1) child process so a failure or
# hang in one drill can never take the suite down, then prints and records a
# per-drill summary (PASS / FAIL / SKIP, duration, drill log path). Every
# drill runs to completion regardless of earlier failures; the wrapper exit
# code is 0 when every RUN drill passed and 1 when any drill FAILed.
#
# Drills (fixed order; the drill files are executed as-is, never modified):
#   1. backup-restore-cycle        S20.1 backup / S20.2 restore
#   2. sqlite-write-interruption   S19.3 SQLite write interruption
#   3. bmc-restart-during-task     S19.3 / S13.6 restart-recovery contract
#   4. large-file-interruption     S19.3 large-file upload / S0.4.0 resume
#   5. kill-mid-operation          S19.3 / S13.5 / S15.4 idempotency
# (drill-delay-proxy.ps1 is a SHARED relay component, not a standalone drill:
# drill-lib.ps1 Start-DelayRelay launches it in its own process for
# drill-kill-mid-operation. It is intentionally not part of this run list.)
#
# Prerequisites:
#   * A real interactive console session (Windows Terminal or a PowerShell
#     window). The drills drive the interactive CLI through ConPTY
#     (drill-lib.ps1); in execution contexts that cannot spawn pseudo
#     consoles (observed: non-interactive tool-hosted sessions), every drill
#     FAILs within seconds - that fast FAIL is the EXPECTED behavior after
#     the hang-protection fix (the drill reports the 0xC0000142 / outputLen=0
#     diagnostic facts and exits 1 instead of hanging). This script reports
#     each drill honestly and keeps going.
#   * The debug binaries built from the current HEAD:
#         cargo build --locked --workspace
#     The workspace default-members set only builds the app crate, so the
#     --workspace flag is required for the test-support mock-bmc bin
#     (target/debug/rutilus.exe and target/debug/mock-bmc.exe).
#   * If the execution policy blocks scripts, launch via:
#         powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\run-all-drills.ps1
#
# Usage:
#   .\run-all-drills.ps1                        # all 5 drills, fixed order
#   .\run-all-drills.ps1 -KeepWorkDir           # keep each drill's tmp work dir
#   .\run-all-drills.ps1 -Drill kill-mid-operation   # single drill only
#   .\run-all-drills.ps1 -DrillTimeoutMinutes 15     # tighten the watchdog
#   (-Drill accepts 'kill-mid-operation', 'drill-kill-mid-operation' or
#   'drill-kill-mid-operation.ps1', case-insensitive; drills not selected by
#   -Drill are recorded SKIP in the summary.)
#
# Output:
#   * Console: per-drill result rows and a suite verdict (colored), plus each
#     drill's own console record as it finishes.
#   * scripts/drills/logs/run-all-<stamp>.summary.txt   (run digest, ASCII)
#   * scripts/drills/logs/run-all-<stamp>.<drill>.out.txt / .err.txt
#     (per-drill child captures; the drill's own structured log is the path
#     the drill prints as '[INFO] drill log: <path>' and is reported here).
#   Only scripts/drills/logs/ is written. tmp/ work dirs are owned by the
#   drills themselves (and cleaned by them unless -KeepWorkDir is given).
#
# Known limitations:
#   * Per-drill watchdog: a drill still running after -DrillTimeoutMinutes
#     (default 30) is force-killed together with its process tree
#     (taskkill /T /F) and recorded FAIL (timeout). The drill's own finally
#     cleanup does not run on that path; helper processes it spawned are
#     killed with the tree.
#   * SKIP here means "not selected by -Drill". A drill that runs always
#     records PASS or FAIL; a ConPTY-less context makes drills FAIL fast by
#     design (see Prerequisites) rather than SKIP.
#   * This script is a self-contained orchestrator and deliberately does NOT
#     dot-source drill-lib.ps1: it only launches child processes and must not
#     depend on the lib's Add-Type types or script globals.
#   * Pure ASCII source (PS 5.1 parses BOM-less files as the ANSI codepage;
#     non-ASCII would mojibake). Wrapper-generated text is ASCII; drill text
#     echoed into the summary is reduced to ASCII (console echo is raw).
#   * PowerShell 5.1 compatible (Windows PowerShell). No product code is
#     touched.
#
# Result classification: a drill PASSes iff its child process exits 0 (the
# drill sets exit code 0 only on its 'DRILL PASSED' path); anything else -
# non-zero exit, launch failure, or watchdog timeout - is FAIL.

param(
    [switch]$KeepWorkDir,
    [string]$Drill = '',
    [int]$DrillTimeoutMinutes = 30
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Locate the repo, the binaries, and the drill scripts
# ---------------------------------------------------------------------------
$script:RunAllDir = $PSScriptRoot
$script:RunAllLogsDir = Join-Path $PSScriptRoot 'logs'
$script:RunAllRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:RunAllBinDir = Join-Path $script:RunAllRepoRoot 'target\debug'
$script:RunAllRutilusExe = Join-Path $script:RunAllBinDir 'rutilus.exe'
$script:RunAllMockBmcExe = Join-Path $script:RunAllBinDir 'mock-bmc.exe'
# Children always run under Windows PowerShell 5.1 (the suite target), not
# under whatever host launched this script.
$script:RunAllPowerShellExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path $script:RunAllPowerShellExe)) { $script:RunAllPowerShellExe = 'powershell.exe' }

# The 5 standalone drills in the fixed run order.
$script:DrillDefs = @(
    @{ Name = 'backup-restore-cycle';        File = 'drill-backup-restore-cycle.ps1' },
    @{ Name = 'sqlite-write-interruption';   File = 'drill-sqlite-write-interruption.ps1' },
    @{ Name = 'bmc-restart-during-task';     File = 'drill-bmc-restart-during-task.ps1' },
    @{ Name = 'large-file-interruption';     File = 'drill-large-file-interruption.ps1' },
    @{ Name = 'kill-mid-operation';          File = 'drill-kill-mid-operation.ps1' }
)

# ---------------------------------------------------------------------------
# Console logging (same style and colors as drill-lib's Write-Drill).
# ---------------------------------------------------------------------------
function Write-RunAll {
    param(
        [Parameter(Mandatory = $true)][string]$Level,   # STEP / PASS / FAIL / WARN / INFO / DONE
        [Parameter(Mandatory = $true)][string]$Message
    )
    $line = '[{0}] {1}' -f $Level, $Message
    if ($Level -eq 'PASS') { Write-Host $line -ForegroundColor Green }
    elseif ($Level -eq 'FAIL') { Write-Host $line -ForegroundColor Red }
    elseif ($Level -eq 'WARN') { Write-Host $line -ForegroundColor Yellow }
    elseif ($Level -eq 'STEP') { Write-Host $line -ForegroundColor Cyan }
    elseif ($Level -eq 'DONE') { Write-Host $line -ForegroundColor Magenta }
    else { Write-Host $line }
}

# Reduces arbitrary drill-captured text to one ASCII line for the summary
# file. Console display is NOT filtered.
function ConvertTo-AsciiLine {
    param([Parameter(Mandatory = $true)][string]$Value)
    return (($Value -replace '[^\x20-\x7E]', '?') -replace '\s+', ' ').Trim()
}

function Format-Duration {
    param([Parameter(Mandatory = $true)][TimeSpan]$TimeSpan)
    $total = [int]$TimeSpan.TotalSeconds
    if ($total -ge 60) { return '{0}m {1:00}s' -f ([int]($total / 60)), ($total % 60) }
    return '{0}s' -f $total
}

# Normalizes a -Drill argument: 'drill-kill-mid-operation.ps1',
# 'drill-kill-mid-operation' and 'kill-mid-operation' all match.
function ConvertTo-DrillName {
    param([Parameter(Mandatory = $true)][string]$Value)
    $n = $Value.ToLowerInvariant().Trim()
    if ($n.EndsWith('.ps1')) { $n = $n.Substring(0, $n.Length - 4) }
    if ($n.StartsWith('drill-')) { $n = $n.Substring(6) }
    return $n
}

function Get-BinaryStamp {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path $Path) { return (Get-Item $Path).LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }
    return 'MISSING'
}

# ---------------------------------------------------------------------------
# Per-drill runner: one powershell.exe child, redirected capture files, a
# bounded watchdog (taskkill /T on timeout), result classification.
# ---------------------------------------------------------------------------
function Invoke-OneDrill {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ScriptFile,
        [Parameter(Mandatory = $true)][string]$RunStamp
    )
    $scriptPath = Join-Path $script:RunAllDir $ScriptFile
    $outCap = Join-Path $script:RunAllLogsDir ('run-all-{0}.{1}.out.txt' -f $RunStamp, $Name)
    $errCap = Join-Path $script:RunAllLogsDir ('run-all-{0}.{1}.err.txt' -f $RunStamp, $Name)

    $argsList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $scriptPath + '"'))
    if ($KeepWorkDir) { $argsList += '-KeepWorkDir' }

    $proc = $null
    $launchError = $null
    $timedOut = $false
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $proc = Start-Process -FilePath $script:RunAllPowerShellExe -ArgumentList $argsList `
            -WorkingDirectory $script:RunAllDir -RedirectStandardOutput $outCap `
            -RedirectStandardError $errCap -PassThru -WindowStyle Hidden
        $deadline = (Get-Date).AddMinutes($DrillTimeoutMinutes)
        $exited = $false
        while (-not $exited) {
            try { $proc.Refresh() } catch { }
            $exited = $proc.HasExited
            if ($exited) { break }
            if ((Get-Date) -ge $deadline) { break }
            Start-Sleep -Milliseconds 1000
        }
        if (-not $exited) {
            $timedOut = $true
            $null = & taskkill /PID $proc.Id /T /F 2>$null
            $proc.WaitForExit(15000) | Out-Null
            $proc.Refresh()
        }
    }
    catch {
        $launchError = $_.Exception.Message
    }
    $sw.Stop()

    $exitCode = -1
    if ($null -ne $proc) {
        try { $exitCode = $proc.ExitCode } catch { }
    }
    $stdoutText = ''
    if (Test-Path $outCap) { $stdoutText = Get-Content -Path $outCap -Raw }
    $stderrText = ''
    if (Test-Path $errCap) { $stderrText = Get-Content -Path $errCap -Raw }

    # The drill prints its own structured log path as '[INFO] drill log: <p>'.
    $logFile = '(none)'
    $m = [regex]::Match($stdoutText, '\[INFO\] drill log:\s*(\S+)')
    if ($m.Success) { $logFile = $m.Groups[1].Value }

    # The drill's own verdict line ('DRILL PASSED: ...' / 'DRILL FAILED: ...'),
    # captured for the summary (informational; the exit code is authoritative).
    $verdictLine = ''
    $mv = [regex]::Match($stdoutText, 'DRILL (?:PASSED|FAILED)[^\r\n]*')
    if ($mv.Success) { $verdictLine = $mv.Value }

    $result = 'FAIL'
    $reason = ''
    if ($null -ne $launchError) {
        $reason = 'launch failed: ' + $launchError
    }
    elseif ($timedOut) {
        $reason = "timeout after $DrillTimeoutMinutes min (process tree force-killed)"
    }
    elseif ($exitCode -eq 0) {
        $result = 'PASS'
    }
    elseif ($stdoutText -match '0xC0000142|ConPTY launch failed') {
        $reason = "exit code $exitCode; ConPTY launch failure (0xC0000142) - expected in contexts that cannot spawn pseudo consoles; run from a real interactive console"
    }
    else {
        $reason = 'exit code ' + $exitCode
    }

    # Show the drill's console record after it finishes (the drill's own log
    # file carries the timestamped copy; this keeps the wrapper session a
    # faithful transcript).
    if ($stdoutText) { Write-Host $stdoutText.TrimEnd() }
    if ($stderrText) { Write-Host $stderrText.TrimEnd() }

    return [pscustomobject]@{
        Name = $Name
        Result = $result
        Reason = $reason
        Duration = $sw.Elapsed
        ExitCode = $exitCode
        LogFile = $logFile
        Verdict = $verdictLine
        OutCap = $outCap
        ErrCap = $errCap
    }
}

# ---------------------------------------------------------------------------
# Summary-file writer: assembles the run digest from structured state, so
# every path (including pre-flight aborts) lands a self-contained ASCII file.
# ---------------------------------------------------------------------------
$script:SuiteStart = Get-Date
$script:GitHead = 'unknown'
$script:ProductVersionLine = 'unknown'
$script:Notices = New-Object System.Collections.Generic.List[string]
$script:ResultsByName = @{}
$script:ResultsComplete = $false   # set to $true once the digest is built

function Write-SummaryFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('run-all-drills summary')
    $lines.Add('start     : ' + $script:SuiteStart.ToString('yyyy-MM-ddTHH:mm:ss'))
    $lines.Add('end       : ' + (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss'))
    $lines.Add('powershell: ' + $PSVersionTable.PSVersion.ToString())
    $lines.Add('os        : ' + [System.Environment]::OSVersion.VersionString)
    $lines.Add('git head  : ' + $script:GitHead)
    $lines.Add('rutilus   : ' + $script:RunAllRutilusExe + ' (built ' + (Get-BinaryStamp -Path $script:RunAllRutilusExe) + ')')
    $lines.Add('version   : ' + $script:ProductVersionLine)
    $lines.Add('mock-bmc  : ' + $script:RunAllMockBmcExe + ' (built ' + (Get-BinaryStamp -Path $script:RunAllMockBmcExe) + ')')
    $lines.Add('mode      : ' + $script:ModeText)
    $lines.Add('keep-work : ' + [bool]$KeepWorkDir)
    $lines.Add('timeout   : ' + $DrillTimeoutMinutes + ' min per drill (watchdog)')
    $lines.Add('')
    foreach ($n in $script:Notices) { $lines.Add('notice    : ' + $n) }
    if ($script:ResultsComplete) {
        $lines.Add('')
        foreach ($r in $script:FinalResults) {
            $line = 'results : [{0}] {1} ({2})' -f $r.Result, $r.Name, (Format-Duration -TimeSpan $r.Duration)
            if ($r.Reason) { $line += '  ' + $r.Reason }
            $lines.Add($line)
            $lines.Add('          log: ' + $r.LogFile)
            if ($r.Verdict) { $lines.Add('          verdict: ' + (ConvertTo-AsciiLine -Value $r.Verdict)) }
            if ($r.OutCap) { $lines.Add('          captures: ' + $r.OutCap + ' / ' + $r.ErrCap) }
        }
        $lines.Add('')
        $lines.Add('totals    : PASS ' + $script:PassCount + ' / FAIL ' + $script:FailCount + ' / SKIP ' + $script:SkipCount)
        $lines.Add('verdict   : ' + $script:SuiteVerdict)
    }
    $lines.Add('summary   : ' + $Path)
    Set-Content -Path $Path -Value ($lines.ToArray()) -Encoding UTF8
    Write-Host "[INFO] summary: $Path"
}

# ---------------------------------------------------------------------------
# Banner, selection, pre-flight
# ---------------------------------------------------------------------------
$suiteSw = [System.Diagnostics.Stopwatch]::StartNew()
$runStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$summaryPath = Join-Path $script:RunAllLogsDir ('run-all-{0}.summary.txt' -f $runStamp)
$script:ModeText = 'all ' + $script:DrillDefs.Count + ' drills'
New-Item -ItemType Directory -Force -Path $script:RunAllLogsDir | Out-Null

Write-RunAll -Level INFO -Message "run-all-drills: $($script:DrillDefs.Count) standalone drills, stamp $runStamp"
Write-RunAll -Level INFO -Message "rutilus.exe : $script:RunAllRutilusExe"
Write-RunAll -Level INFO -Message "mock-bmc.exe: $script:RunAllMockBmcExe"
if (-not [Environment]::UserInteractive) {
    Write-RunAll -Level WARN -Message 'non-interactive session detected; the drills need a real interactive console (ConPTY) and will FAIL fast otherwise - expected, reported honestly'
}

# Best-effort environment facts for the summary (never fatal; runs before
# selection so abort summaries carry them too).
try {
    $head = & git -C $script:RunAllRepoRoot rev-parse --short HEAD 2>$null
    if ($head) { $script:GitHead = ([string]$head).Trim() }
} catch { }
try {
    $v = & $script:RunAllRutilusExe version 2>$null
    if ($v -is [string]) { $script:ProductVersionLine = $v.Trim() }
    elseif ($v) { $script:ProductVersionLine = ([string]$v[0]).Trim() }
} catch { }

# -Drill selection (validated before anything runs).
$selected = $script:DrillDefs
$singleMode = $false
if ($Drill -ne '') {
    $want = ConvertTo-DrillName -Value $Drill
    $hit = @($script:DrillDefs | Where-Object { $_.Name -eq $want })
    if ($hit.Count -ne 1) {
        $names = @($script:DrillDefs | ForEach-Object { $_.Name }) -join ', '
        $msg = "unknown drill '$Drill' (normalized '$want'); valid drills: $names"
        Write-RunAll -Level FAIL -Message $msg
        $script:Notices.Add($msg)
        Write-SummaryFile -Path $summaryPath
        exit 1
    }
    $selected = $hit
    $singleMode = $true
    $script:ModeText = 'single drill: ' + $selected[0].Name
    Write-RunAll -Level INFO -Message "single-drill mode: $($selected[0].Name)"
}

# Pre-flight: binaries and drill scripts must exist; fail fast with the
# build hint instead of producing a wall of identical drill failures.
$preflightError = $null
if (-not (Test-Path $script:RunAllRutilusExe)) {
    $preflightError = "debug binary not found: $script:RunAllRutilusExe (build it with: cargo build --locked --workspace)"
}
elseif (-not (Test-Path $script:RunAllMockBmcExe)) {
    $preflightError = "debug binary not found: $script:RunAllMockBmcExe (build it with: cargo build --locked --workspace)"
}
foreach ($d in $script:DrillDefs) {
    if ($null -eq $preflightError -and -not (Test-Path (Join-Path $script:RunAllDir $d.File))) {
        $preflightError = "drill script missing: $(Join-Path $script:RunAllDir $d.File)"
    }
}
if ($null -ne $preflightError) {
    Write-RunAll -Level FAIL -Message $preflightError
    $script:Notices.Add($preflightError)
    Write-SummaryFile -Path $summaryPath
    exit 1
}

# ---------------------------------------------------------------------------
# Run the drills (one subprocess each; failures never interrupt the suite)
# ---------------------------------------------------------------------------
$runOrdinal = 0
foreach ($d in $selected) {
    $runOrdinal++
    Write-RunAll -Level STEP -Message "drill $runOrdinal/$($selected.Count): $($d.Name) (subprocess $script:RunAllPowerShellExe, watchdog $DrillTimeoutMinutes min)"
    $r = Invoke-OneDrill -Name $d.Name -ScriptFile $d.File -RunStamp $runStamp
    $script:ResultsByName[$d.Name] = $r
}
$suiteSw.Stop()

# ---------------------------------------------------------------------------
# Results digest: registry order (selected drills with their result, the
# rest SKIP), totals, verdict, console rows, and the summary file.
# ---------------------------------------------------------------------------
$script:FinalResults = @()
foreach ($d in $script:DrillDefs) {
    $r = $script:ResultsByName[$d.Name]
    if ($null -eq $r) {
        $r = [pscustomobject]@{
            Name = $d.Name; Result = 'SKIP'; Reason = "not selected (mode: $($selected[0].Name))"
            Duration = [TimeSpan]::Zero; ExitCode = -1; LogFile = '(none)'; Verdict = ''
            OutCap = ''; ErrCap = ''
        }
    }
    $script:FinalResults += $r
}

$script:PassCount = @($script:FinalResults | Where-Object { $_.Result -eq 'PASS' }).Count
$script:FailCount = @($script:FinalResults | Where-Object { $_.Result -eq 'FAIL' }).Count
$script:SkipCount = @($script:FinalResults | Where-Object { $_.Result -eq 'SKIP' }).Count
$script:SuiteVerdict = 'PASS'
if ($script:FailCount -gt 0) { $script:SuiteVerdict = 'FAIL' }
$script:ResultsComplete = $true

foreach ($r in $script:FinalResults) {
    $durText = Format-Duration -TimeSpan $r.Duration
    if ($r.Result -eq 'PASS') {
        Write-RunAll -Level PASS -Message "drill $($r.Name): PASS ($durText) log=$($r.LogFile)"
    }
    elseif ($r.Result -eq 'FAIL') {
        Write-RunAll -Level FAIL -Message "drill $($r.Name): FAIL ($durText) $($r.Reason) log=$($r.LogFile)"
    }
    else {
        Write-RunAll -Level INFO -Message "drill $($r.Name): SKIP ($($r.Reason))"
    }
}
Write-RunAll -Level DONE -Message ('DRILL SUITE: {0} - PASS {1} / FAIL {2} / SKIP {3} (wall {4})' -f $script:SuiteVerdict, $script:PassCount, $script:FailCount, $script:SkipCount, (Format-Duration -TimeSpan $suiteSw.Elapsed))

Write-SummaryFile -Path $summaryPath

if ($script:FailCount -gt 0) { exit 1 }
exit 0

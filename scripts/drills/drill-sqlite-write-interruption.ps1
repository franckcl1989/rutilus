# drill-sqlite-write-interruption.ps1 — design §19.3 "SQLite 写入中断"
# (best-effort on Windows).
#
# The scenario simulates a storage-level write interruption: the database
# file is held with an exclusive share mode (FileShare.None) by the drill,
# so the product cannot open the store. The drill verifies the product
# fails CLEANLY (a controlled error and a non-zero exit, no hang, no
# corruption) and that releasing the lock restores full operation — the
# same database passes `rutilus doctor` and serves the console again.
#
# Note on Windows file semantics (verified in RESULTS.md): once the product
# holds the SQLite file, a second FileShare.None open is refused by the OS
# (sharing violation) — so the "interruption while running" form cannot be
# induced from outside; the closest cross-process simulation is the
# unavailable-at-startup form exercised here, plus a Phase B that proves the
# product owns the file exclusively while running.

param([switch]$KeepWorkDir)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
. .\drill-lib.ps1

$drillName = 'drill-sqlite-write-interruption'
$logFile = Start-DrillLog $drillName
$workDir = $null
$run = $null
$api = $null
$exitCode = 1

try {
    Write-Drill -Level STEP -Message 'Preparing work directory (fresh portable instance)'
    $workDir = New-DrillWorkDir $drillName

    Write-Drill -Level STEP -Message 'rutilus init --portable'
    $init = Invoke-RutilusInit -WorkDir $workDir -Passphrase $script:DrillPassphrase
    Write-Drill -Level PASS -Message 'init completed; bootstrap code captured'

    $bin = Join-Path $workDir 'bin'
    $exe = Join-Path $bin 'rutilus.exe'
    $dbPath = Join-Path $bin 'rutilus-data\rutilus.db'
    if (-not (Test-Path $dbPath)) { throw "database missing after init: $dbPath" }

    Write-Drill -Level STEP -Message 'Phase A: holding the database with FileShare.None, then starting the instance'
    $lockStream = [System.IO.File]::Open($dbPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    try {
        Write-Drill -Level INFO -Message 'exclusive lock acquired on rutilus.db (write path unavailable)'
        $session = Start-ConPtyProcess -ExePath $exe -Arguments 'run --portable --no-open' -WorkingDirectory $bin
        try {
            if (-not (Wait-ConPtyOutput $session 'Local unlock passphrase:' 60)) {
                throw "run did not prompt; output: $($session.Output)"
            }
            $session.SendLine($script:DrillPassphrase)
            # The store open must fail cleanly: the process exits non-zero
            # with a controlled error instead of hanging or panicking.
            $exited = $session.WaitExit(60000)
            $code = $session.ExitCode()
            Write-Drill -Level INFO -Message "run-with-locked-db exited=$exited code=$code"
            $tail = $session.Output.Substring([Math]::Max(0, $session.Output.Length - 600))
            Write-Drill -Level INFO -Message "console output tail: $tail"
            if (-not $exited) {
                throw 'product hung against the locked database instead of failing cleanly'
            }
            if ($code -eq 0) {
                throw 'product exited 0 despite the locked database — the interruption was not surfaced'
            }
            if ($tail -notmatch 'failed to open SQLite database') {
                throw "non-zero exit but no controlled store-open error in the output tail; tail: $tail"
            }
        }
        finally {
            Stop-ConPtySession $session -Force $true
        }
        Write-Drill -Level PASS -Message 'clean failure: the product refused to start against the locked database (non-zero exit, no hang, no corruption)'
    }
    finally {
        $lockStream.Dispose()
    }

    Write-Drill -Level STEP -Message 'Phase A recovery: releasing the lock and starting normally'
    $run = Start-RutilusRun -WorkDir $workDir -Passphrase $script:DrillPassphrase
    $api = New-ApiSession -BaseUrl $run.Url
    Invoke-RutilusBootstrap -Session $api -BootstrapCode $init.BootstrapCode -AdminPassword $script:DrillAdminPassword
    $health = Invoke-Api -Session $api -Method GET -Path '/api/v1/health' -Expect @(200)
    Write-Drill -Level PASS -Message "instance fully operational after the interruption (health: $($health.Body))"

    Write-Drill -Level STEP -Message 'Phase B: while the instance runs, a second exclusive open must be refused by the OS'
    $refused = $false
    try {
        $attempt = [System.IO.File]::Open($dbPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $attempt.Dispose()
    } catch {
        $refused = $true
    }
    if (-not $refused) {
        throw 'the running product does not hold the database file — the write-interruption guard is not in place'
    }
    Write-Drill -Level PASS -Message 'the running product holds the database exclusively (second exclusive open refused with a sharing violation)'

    # Verify the instance is still healthy after the refused open.
    $health2 = Invoke-Api -Session $api -Method GET -Path '/api/v1/health' -Expect @(200)
    Write-Drill -Level PASS -Message "console still healthy: $($health2.Body)"

    Write-Drill -Level STEP -Message 'Stopping the instance and running rutilus doctor --portable'
    Stop-RutilusRunGraceful -Run $run -GraceSeconds 25
    $run = $null
    $docSession = Start-ConPtyProcess -ExePath $exe -Arguments 'doctor --portable' -WorkingDirectory $bin
    try {
        $exited = $docSession.WaitExit(60000)
        $code = $docSession.ExitCode()
        if (-not $exited -or $code -ne 0) {
            throw "doctor did not pass after the interruption (exited=$exited code=$code): $($docSession.Output)"
        }
        if ($docSession.Output -match '\[FAIL\]') {
            throw "doctor reported a failing check: $($docSession.Output)"
        }
    }
    finally {
        Stop-ConPtySession $docSession -Force $true
    }
    $doctorText = $docSession.Output -replace '\s+', ' '
    Write-Drill -Level PASS -Message "rutilus doctor --portable exited 0 (all checks OK): $doctorText"

    Write-Drill -Level DONE -Message 'DRILL PASSED: sqlite-write-interruption — clean failure, no corruption, full recovery after the interruption'
    $exitCode = 0
}
catch {
    Write-Drill -Level FAIL -Message "DRILL FAILED: $($_.Exception.Message)"
    if ($_.ScriptStackTrace) { Write-Drill -Level INFO -Message $_.ScriptStackTrace }
    $exitCode = 1
}
finally {
    Write-Drill -Level STEP -Message 'Cleanup'
    if ($run) { Stop-RutilusRunForce -Run $run }
    if (-not $KeepWorkDir -and $workDir -and (Test-Path $workDir)) {
        Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
    }
    Write-Drill -Level INFO -Message "log: $logFile"
}

exit $exitCode

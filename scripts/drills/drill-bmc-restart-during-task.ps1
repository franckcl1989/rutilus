# drill-bmc-restart-during-task.ps1 — design §19.3 "BMC 更新中重启" and the
# §13.6 restart-recovery contract: after a restart the product must scan
# WaitingRemote operations, re-establish the BMC session, and resume Task
# polling.
#
# Scenario: an update operation is accepted asynchronously by the BMC
# (202 Accepted + Task), the BMC process is then force-killed mid-Task and
# restarted on the same port, and finally the rutilus process is also
# restarted. The drill verifies:
#   1. the operation is tracked in WaitingRemote (never corrupted);
#   2. polls against the killed BMC fail without disturbing the operation;
#   3. after the BMC returns, the Task monitor resumes polling (observed at
#      the TCP level — the mock keeps no external request log);
#   4. after the product's own restart, the §13.6 scan re-lists the
#      WaitingRemote row and polling resumes again.
#
# The mock BMC serves a static "Running" Task fixture and never advances it,
# so the operation legitimately stays WaitingRemote — a documented mock
# limitation (see RESULTS.md): the product's tracking and recovery are what
# this drill proves; a deterministic Task terminal state needs a scriptable
# Task fixture, which the current mock-bmc binary does not provide.

param([switch]$KeepWorkDir)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
. .\drill-lib.ps1

$drillName = 'drill-bmc-restart-during-task'
$logFile = Start-DrillLog $drillName
$workDir = $null
$mock = $null
$run = $null
$api = $null
$exitCode = 1

try {
    Write-Drill -Level STEP -Message 'Preparing work directory (fresh portable instance)'
    $workDir = New-DrillWorkDir $drillName

    Write-Drill -Level STEP -Message 'rutilus init --portable'
    $init = Invoke-RutilusInit -WorkDir $workDir -Passphrase $script:DrillPassphrase
    Write-Drill -Level PASS -Message 'init completed; bootstrap code captured'

    Write-Drill -Level STEP -Message 'Starting the mock BMC (nvidia profile, fixed port)'
    $mockPort = Get-FreeTcpPort
    $mock = Start-MockBmc -WorkDir $workDir -Name 'mock' -Port $mockPort -Profile 'nvidia'
    Write-Drill -Level PASS -Message "mock BMC up at $($mock.Url) (pid $($mock.Pid))"

    Write-Drill -Level STEP -Message 'rutilus run --portable --no-open'
    $run = Start-RutilusRun -WorkDir $workDir -Passphrase $script:DrillPassphrase
    $api = New-ApiSession -BaseUrl $run.Url
    Invoke-RutilusBootstrap -Session $api -BootstrapCode $init.BootstrapCode -AdminPassword $script:DrillAdminPassword
    Write-Drill -Level PASS -Message 'bootstrap claim completed'

    Write-Drill -Level STEP -Message 'Enrolling the NVIDIA-profile endpoint'
    $endpoint = Add-TestEndpoint -Session $api -DisplayName 'nvidia-mock' -Address $mock.Url -Fingerprint $mock.Fingerprint
    Write-Drill -Level PASS -Message "endpoint enrolled: $($endpoint.EndpointId)"

    Write-Drill -Level STEP -Message 'Submitting the asynchronous profile Update (BMC accepts with 202 + Task)'
    $command = @{
        oem = @{ SystemConfigProfile = @{ Update = @{ profile_file = '{"id":"drill-profile","name":"drill"}' } } }
    }
    $operationId = Submit-Operation -Session $api -TargetEndpointId $endpoint.EndpointId -CommandObject $command
    $waiting = Wait-For -TimeoutSeconds 40 -IntervalMs 400 -What 'operation WaitingRemote' -Condition {
        (Get-OperationState -Session $api -OperationId $operationId) -eq 'waiting_remote'
    }
    if (-not $waiting) {
        $detail = (Get-OperationDetail -Session $api -OperationId $operationId).Body
        throw "operation did not reach WaitingRemote (async Task acceptance expected): $detail"
    }
    Write-Drill -Level PASS -Message "operation $operationId is WaitingRemote — the product is polling the BMC Task"

    Write-Drill -Level STEP -Message 'Force-killing the BMC while the Task is in progress'
    $mockPid = $mock.Pid
    Stop-MockBmc -Mock $mock
    $mock = $null
    Write-Drill -Level PASS -Message "mock BMC (pid $mockPid) killed mid-Task"

    # Let a few polls fail against the dead BMC; the operation must survive.
    Start-Sleep -Seconds 8
    $stateDuring = Get-OperationState -Session $api -OperationId $operationId
    if ($stateDuring -ne 'waiting_remote') {
        throw "operation corrupted by the BMC outage (state=$stateDuring); expected waiting_remote"
    }
    Write-Drill -Level PASS -Message "operation still WaitingRemote after the BMC outage (state=$stateDuring) — transient poll failures are deferred, never terminal"

    Write-Drill -Level STEP -Message 'Restarting the BMC on the same port'
    $mock = Start-MockBmc -WorkDir $workDir -Name 'mock' -Port $mockPort -Profile 'nvidia'
    Write-Drill -Level PASS -Message "mock BMC restarted at $($mock.Url) (pid $($mock.Pid))"

    Write-Drill -Level STEP -Message 'Observing resumed Task polling at the TCP level (25 s window, 50 ms sampling)'
    $conns = Measure-ConnectionsToPort -Port $mockPort -WindowSeconds 25 -IntervalMs 50
    Write-Drill -Level INFO -Message "observed $conns sampling windows with live connections to the mock port"
    if ($conns -lt 1) { throw "no resumed polling traffic observed against the restarted BMC (sampled $conns)" }
    Write-Drill -Level PASS -Message "Task monitor resumed polling the restarted BMC ($conns observation windows)"

    $stateMid = Get-OperationState -Session $api -OperationId $operationId
    if ($stateMid -ne 'waiting_remote') { throw "operation left waiting_remote after BMC restart (state=$stateMid)" }
    Write-Drill -Level PASS -Message "operation still tracked WaitingRemote after the BMC restart (state=$stateMid)"

    Write-Drill -Level STEP -Message 'Restarting the rutilus process too (§13.6 scan-after-restart)'
    Stop-RutilusRunGraceful -Run $run -GraceSeconds 25
    $run = $null
    $run = Start-RutilusRun -WorkDir $workDir -Passphrase $script:DrillPassphrase
    $api = New-ApiSession -BaseUrl $run.Url
    Invoke-RutilusLogin -Session $api -Password $script:DrillAdminPassword

    $stateAfter = Get-OperationState -Session $api -OperationId $operationId
    if ($stateAfter -ne 'waiting_remote') {
        throw "operation not re-tracked after product restart (state=$stateAfter); expected waiting_remote"
    }
    Write-Drill -Level PASS -Message "after the product restart the operation is re-listed WaitingRemote (state=$stateAfter) — the §13.6 scan picked it up"

    Write-Drill -Level STEP -Message 'Observing resumed Task polling after the product restart (25 s window, 50 ms sampling)'
    $conns2 = Measure-ConnectionsToPort -Port $mockPort -WindowSeconds 25 -IntervalMs 50
    Write-Drill -Level INFO -Message "observed $conns2 sampling windows with live connections after the product restart"
    if ($conns2 -lt 1) { throw "no resumed polling traffic observed after the product restart (sampled $conns2)" }
    Write-Drill -Level PASS -Message "Task polling resumed after the full restart cycle ($conns2 observation windows)"

    Write-Drill -Level STEP -Message 'Console health check'
    $health = Invoke-Api -Session $api -Method GET -Path '/api/v1/health' -Expect @(200)
    Write-Drill -Level PASS -Message "health: $($health.Body)"

    Write-Drill -Level DONE -Message 'DRILL PASSED: bmc-restart-during-task — tracking and §13.6 recovery verified (see RESULTS.md for the static-Task caveat)'
    $exitCode = 0
}
catch {
    Write-Drill -Level FAIL -Message "DRILL FAILED: $($_.Exception.Message)"
    if ($_.ScriptStackTrace) { Write-Drill -Level INFO -Message $_.ScriptStackTrace }
    $exitCode = 1
}
finally {
    Write-Drill -Level STEP -Message 'Cleanup'
    if ($mock) { Stop-MockBmc -Mock $mock }
    if ($run) { Stop-RutilusRunForce -Run $run }
    if (-not $KeepWorkDir -and $workDir -and (Test-Path $workDir)) {
        Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
    }
    Write-Drill -Level INFO -Message "log: $logFile"
}

exit $exitCode

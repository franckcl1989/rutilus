# drill-kill-mid-operation.ps1 — design §19.3 "产品进程在任务中被终止".
#
# Scenario: an operation is executing (Running / Verifying) when the rutilus
# process is force-killed. After restart, the operation must reach a
# deterministic terminal state through the §13.5 recovery path (re-read and
# decide — never a blind re-dispatch), leave no dirty state, and not execute
# the write twice (§15.4 idempotency).
#
# To guarantee the kill lands mid-execution, the BMC address is a transparent
# delay relay in front of the real mock-bmc: the relay delays every
# mock->product chunk (including each TLS handshake record) by 6 s, so the
# synchronous create-account flow stays in flight for tens of seconds — a
# wide, deterministic kill window. The drill waits up to 60 s to observe
# Running / Verifying before force-killing.
#
# Terminal-state expectation: the dispatch POST reaches the mock well before
# the kill (the relay only delays the response), so the account row exists;
# the recovery re-read proves the effect and the operation is recorded
# Succeeded with a Confirmed verification. Idempotency is asserted on the
# mock side: exactly ONE created account row.

param([switch]$KeepWorkDir)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
. .\drill-lib.ps1

$drillName = 'drill-kill-mid-operation'
$logFile = Start-DrillLog $drillName
$workDir = $null
$mock = $null
$relay = $null
$run = $null
$api = $null
$delayFile = $null
$exitCode = 1

try {
    Write-Drill -Level STEP -Message 'Preparing work directory (fresh portable instance)'
    $workDir = New-DrillWorkDir $drillName
    $delayFile = Join-Path $workDir 'relay-delay.txt'
    Set-RelayDelay -DelayFile $delayFile -Milliseconds 0

    Write-Drill -Level STEP -Message 'rutilus init --portable'
    $init = Invoke-RutilusInit -WorkDir $workDir -Passphrase $script:DrillPassphrase
    if (-not $init.BootstrapCode) { throw 'no bootstrap code captured' }
    Write-Drill -Level PASS -Message 'init completed and printed the one-time bootstrap code'

    Write-Drill -Level STEP -Message 'Starting the mock BMC and the delay relay'
    $mock = Start-MockBmc -WorkDir $workDir -Name 'mock' -Profile 'rutilus'
    $relayPort = Get-FreeTcpPort
    $relay = Start-DelayRelay -ListenPort $relayPort -TargetPort $mock.Port -DelayFile $delayFile
    $relayAddress = "https://127.0.0.1:$relayPort/"
    Write-Drill -Level PASS -Message "delay relay up at $relayAddress -> mock :$($mock.Port)"

    Write-Drill -Level STEP -Message 'rutilus run --portable --no-open'
    $run = Start-RutilusRun -WorkDir $workDir -Passphrase $script:DrillPassphrase
    $api = New-ApiSession -BaseUrl $run.Url
    Invoke-RutilusBootstrap -Session $api -BootstrapCode $init.BootstrapCode -AdminPassword $script:DrillAdminPassword
    Write-Drill -Level PASS -Message 'bootstrap claim completed; session + CSRF armed'

    Write-Drill -Level STEP -Message 'Enrolling the endpoint through the relay (delay 0)'
    $endpoint = Add-TestEndpoint -Session $api -DisplayName 'mock-through-relay' -Address $relayAddress -Fingerprint $mock.Fingerprint
    Write-Drill -Level PASS -Message "endpoint enrolled: $($endpoint.EndpointId)"

    Write-Drill -Level STEP -Message 'Arming the 6 s response delay (every BMC response is now held in flight)'
    Set-RelayDelay -DelayFile $delayFile -Milliseconds 6000
    Start-Sleep -Milliseconds 300

    Write-Drill -Level STEP -Message 'Submitting a create-account operation (synchronous write, effect-asserting verification)'
    $command = @{
        account = @{ CreateAccount = @{
            user_name = 'drill-user'
            password = 'drill-password-2026'
            role_id = 'Operator'
        } }
    }
    $operationId = Submit-Operation -Session $api -TargetEndpointId $endpoint.EndpointId -CommandObject $command
    Write-Drill -Level INFO -Message "operation $operationId submitted"

    # Wait until the operation is observably mid-execution, then force-kill.
    # Budget 60 s: the relay delays every mock->product chunk (TLS handshake
    # records included) by 6 s, so Running/Verifying may only appear after
    # several handshake round trips.
    $inFlight = Wait-For -TimeoutSeconds 60 -IntervalMs 200 -What 'operation Running or Verifying' -Condition {
        $state = Get-OperationState -Session $api -OperationId $operationId
        $state -in @('running', 'verifying')
    }
    $stateBefore = Get-OperationState -Session $api -OperationId $operationId
    if (-not $inFlight) {
        throw "operation never reached Running/Verifying before kill (state=$stateBefore)"
    }
    Write-Drill -Level PASS -Message "operation is $stateBefore — killing the rutilus process now (Stop-Process -Force)"
    $killedPid = $run.Session.ProcessId
    Stop-RutilusRunForce -Run $run
    $run = $null
    Write-Drill -Level PASS -Message "rutilus (pid $killedPid) force-killed mid-operation"

    Write-Drill -Level STEP -Message 'Restarting rutilus on the same data directory'
    $run = Start-RutilusRun -WorkDir $workDir -Passphrase $script:DrillPassphrase
    $api = New-ApiSession -BaseUrl $run.Url
    Invoke-RutilusLogin -Session $api -Password $script:DrillAdminPassword
    Write-Drill -Level PASS -Message 'console back up; signed in'

    Write-Drill -Level STEP -Message 'Waiting for the §13.5 recovery judgement to reach a terminal state'
    # Budget 120 s: the recovery re-read goes through the still-delayed relay
    # (fresh connection per request, ~30-60 s of per-chunk delays per round).
    $terminal = Wait-For -TimeoutSeconds 120 -IntervalMs 500 -What 'terminal operation state' -Condition {
        (Get-OperationState -Session $api -OperationId $operationId) -in @('succeeded', 'failed', 'unknown', 'cancelled')
    }
    $stateAfter = Get-OperationState -Session $api -OperationId $operationId
    if (-not $terminal) { throw "operation did not reach a terminal state after restart (state=$stateAfter)" }
    Write-Drill -Level PASS -Message "operation reached deterministic terminal state: $stateAfter"
    if ($stateAfter -ne 'succeeded') {
        Write-Drill -Level WARN -Message "state is $stateAfter (not succeeded) — see operation detail: $((Get-OperationDetail -Session $api -OperationId $operationId).Body)"
    }

    # Recovery went through the re-read-and-decide path: with the dispatch
    # response lost, the re-read proves the account was created exactly once.
    # Query the mock DIRECTLY (pinned by its fingerprint) and count rows.
    Write-Drill -Level STEP -Message 'Idempotency check on the mock ledger (exactly one created account)'
    $accounts = Invoke-MockHttps -Url "https://127.0.0.1:$($mock.Port)/redfish/v1/AccountService/Accounts" -ExpectedFingerprint $mock.Fingerprint
    $created = @($accounts.Json.Members | Where-Object { $_.'@odata.id' -match 'user-' }).Count
    Write-Drill -Level INFO -Message "mock accounts collection holds $created drill-created account(s)"
    if ($created -ne 1) {
        throw "idempotency violated: expected exactly 1 created account, found $created"
    }
    Write-Drill -Level PASS -Message 'idempotency holds: the operation executed exactly once (no re-dispatch after recovery)'

    Write-Drill -Level STEP -Message 'Dirty-state check: endpoint inventory intact, console healthy'
    $inventory = Invoke-Api -Session $api -Method GET -Path '/api/v1/endpoints' -Expect @(200)
    if (@($inventory.Json.endpoints).Count -ne 1) {
        throw "expected 1 endpoint after restart, found $(@($inventory.Json.endpoints).Count)"
    }
    $health = Invoke-Api -Session $api -Method GET -Path '/api/v1/health' -Expect @(200)
    Write-Drill -Level PASS -Message "endpoint inventory intact ($(@($inventory.Json.endpoints).Count) endpoint); health: $($health.Body)"

    Write-Drill -Level DONE -Message 'DRILL PASSED: kill-mid-operation — deterministic terminal state, no dirty data, no duplicate execution'
    $exitCode = 0
}
catch {
    Write-Drill -Level FAIL -Message "DRILL FAILED: $($_.Exception.Message)"
    if ($_.ScriptStackTrace) { Write-Drill -Level INFO -Message $_.ScriptStackTrace }
    $exitCode = 1
}
finally {
    Write-Drill -Level STEP -Message 'Cleanup'
    if ($relay) { Stop-Process -Id $relay.Id -Force -ErrorAction SilentlyContinue }
    if ($mock) { Stop-MockBmc -Mock $mock }
    if ($run) { Stop-RutilusRunForce -Run $run }
    if (-not $KeepWorkDir -and $workDir -and (Test-Path $workDir)) {
        Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
    }
    Write-Drill -Level INFO -Message "log: $logFile"
}

exit $exitCode

# drill-large-file-interruption.ps1 — design §19.3 "大文件上传中断" in its
# cross-process form: the artifact upload is interrupted by a force-kill of
# the rutilus process mid-transfer, and after restart the upload must be
# resumable from the persisted progress (断点续传, §0.4.0 acceptance) with no
# corrupted residue — completing the remaining chunks and finalizing must
# verify the declared SHA-256 and reach Ready.
#
# Chunk contract (application/src/artifact_store.rs): each chunk carries
# base64 text of at most ARTIFACT_CHUNK_BASE64_MAX_BYTES (4 MiB) characters;
# the drill sends 3 MiB raw per chunk (exactly 4 MiB base64). Progress is
# acknowledged per chunk, so after a kill the persisted uploaded_bytes equals
# the acked prefix and the upload resumes from there.

param([switch]$KeepWorkDir)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
. .\drill-lib.ps1

$drillName = 'drill-large-file-interruption'
$logFile = Start-DrillLog $drillName
$workDir = $null
$run = $null
$api = $null
$exitCode = 1
$filePath = $null
$artifact = $null

try {
    Write-Drill -Level STEP -Message 'Preparing work directory (fresh portable instance)'
    $workDir = New-DrillWorkDir $drillName

    Write-Drill -Level STEP -Message 'rutilus init --portable'
    $init = Invoke-RutilusInit -WorkDir $workDir -Passphrase $script:DrillPassphrase
    Write-Drill -Level PASS -Message 'init completed; bootstrap code captured'

    Write-Drill -Level STEP -Message 'rutilus run --portable --no-open'
    $run = Start-RutilusRun -WorkDir $workDir -Passphrase $script:DrillPassphrase
    $api = New-ApiSession -BaseUrl $run.Url
    Invoke-RutilusBootstrap -Session $api -BootstrapCode $init.BootstrapCode -AdminPassword $script:DrillAdminPassword
    Write-Drill -Level PASS -Message 'bootstrap claim completed'

    Write-Drill -Level STEP -Message 'Constructing a 64 MiB fixture file with a real SHA-256'
    $filePath = Join-Path $workDir 'firmware-64m.bin'
    $chunkBytes = 3 * 1024 * 1024   # raw bytes per chunk (4 MiB base64 text, at the limit)
    $sizeBytes = 64 * 1024 * 1024  # 64 MiB exactly
    $fs = [System.IO.File]::Create($filePath)
    try {
        $random = New-Object System.Random(20260812)
        $buffer = New-Object byte[] $chunkBytes
        $remaining = $sizeBytes
        while ($remaining -gt 0) {
            $take = [Math]::Min($chunkBytes, $remaining)
            $random.NextBytes($buffer)
            $fs.Write($buffer, 0, $take)
            $remaining -= $take
        }
    }
    finally {
        $fs.Dispose()
    }
    $hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $actualSize = (Get-Item $filePath).Length
    Write-Drill -Level PASS -Message "fixture file: $actualSize bytes, sha256=$hash"

    Write-Drill -Level STEP -Message 'Declaring the artifact (POST /api/v1/artifacts)'
    $createBody = @{ name = 'firmware-64m.bin'; size_bytes = $actualSize; sha256 = $hash } | ConvertTo-Json -Compress
    $created = Invoke-Api -Session $api -Method POST -Path '/api/v1/artifacts' -Body $createBody -Expect @(201) -Mutation $true
    $artifact = $created.Json
    if ($artifact.state -ne 'uploading') { throw "artifact started in unexpected state: $($artifact.state)" }
    Write-Drill -Level PASS -Message "artifact $($artifact.artifact_id) declared (state $($artifact.state))"

    # Upload helper: one base64 chunk at a given offset.
    function Send-Chunk {
        param($Session, $ArtifactId, [long]$Offset, [byte[]]$Bytes)
        $data = [Convert]::ToBase64String($Bytes)
        $body = @{ offset = $Offset; data = $data } | ConvertTo-Json -Compress
        $resp = Invoke-Api -Session $Session -Method POST -Path "/api/v1/artifacts/$ArtifactId/chunks" -Body $body -Expect @(200) -Mutation $true
        return [long]$resp.Json.uploaded_bytes
    }

    Write-Drill -Level STEP -Message 'Uploading the first 5 chunks (acked), then killing rutilus mid-upload'
    $fs = [System.IO.File]::OpenRead($filePath)
    try {
        $acked = 0
        for ($i = 0; $i -lt 5; $i++) {
            $buf = New-Object byte[] $chunkBytes
            [void]$fs.Read($buf, 0, $chunkBytes)
            $acked = Send-Chunk -Session $api -ArtifactId $artifact.artifact_id -Offset $acked -Bytes $buf
        }
        Write-Drill -Level INFO -Message "5 chunks acknowledged; progress $acked / $actualSize"
        # Chunk 6 in flight: start it in a background job and kill the
        # product while the request is being processed. The job runs in its
        # own process, so the session cookie must be injected explicitly —
        # without it the guarded API rejects the chunk with 401 and no
        # upload is ever in flight at kill time.
        $cookieList = @()
        foreach ($ck in $api.Handler.CookieContainer.GetCookies([uri]$api.BaseUrl)) {
            $cookieList += [pscustomobject]@{ Name = $ck.Name; Value = $ck.Value }
        }
        $buf6 = New-Object byte[] $chunkBytes
        [void]$fs.Read($buf6, 0, $chunkBytes)
        $data6 = [Convert]::ToBase64String($buf6)
        $body6 = @{ offset = $acked; data = $data6 } | ConvertTo-Json -Compress
        $job = Start-Job -ScriptBlock {
            param($u, $aid, $b, $csrf, $cookies)
            $h = New-Object System.Net.Http.HttpClientHandler
            $h.CookieContainer = New-Object System.Net.CookieContainer
            $base = [uri]$u
            foreach ($item in $cookies) {
                $ck = New-Object System.Net.Cookie($item.Name, $item.Value)
                $ck.Domain = $base.Host
                $ck.Path = '/'
                $h.CookieContainer.Add($base, $ck)
            }
            $c = New-Object System.Net.Http.HttpClient($h)
            $c.Timeout = [TimeSpan]::FromSeconds(180)
            try {
                $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Post, "$u/api/v1/artifacts/$aid/chunks")
                $req.Content = New-Object System.Net.Http.StringContent($b, [System.Text.Encoding]::UTF8, 'application/json')
                [void]$req.Headers.TryAddWithoutValidation('X-CSRF-Token', $csrf)
                $r = $c.SendAsync($req).GetAwaiter().GetResult()
                $txt = $r.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                $r.Dispose(); $req.Dispose()
                return $txt
            } catch { return "ERR: $($_.Exception.Message)" }
            finally { $c.Dispose() }
        } -ArgumentList $api.BaseUrl, $artifact.artifact_id, $body6, $api.Csrf, $cookieList
        Start-Sleep -Milliseconds 400
        Write-Drill -Level INFO -Message 'chunk 6 request in flight — force-killing rutilus'
        Stop-RutilusRunForce -Run $run
        $run = $null
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
    finally {
        $fs.Dispose()
    }
    Write-Drill -Level PASS -Message 'rutilus force-killed mid-upload'

    Write-Drill -Level STEP -Message 'Restarting rutilus and checking the artifact state'
    $run = Start-RutilusRun -WorkDir $workDir -Passphrase $script:DrillPassphrase
    $api = New-ApiSession -BaseUrl $run.Url
    Invoke-RutilusLogin -Session $api -Password $script:DrillAdminPassword
    $detail = Invoke-Api -Session $api -Method GET -Path "/api/v1/artifacts/$($artifact.artifact_id)" -Expect @(200)
    $progressAfter = [long]$detail.Json.uploaded_bytes
    Write-Drill -Level INFO -Message "after restart: state=$($detail.Json.state), uploaded_bytes=$progressAfter"
    if ($detail.Json.state -ne 'uploading') {
        throw "artifact not resumable after interruption (state=$($detail.Json.state)); expected uploading"
    }
    if ($progressAfter -ne 15728640) {
        throw "persisted progress unexpected: $progressAfter (expected 15728640 = 5 acked chunks)"
    }
    Write-Drill -Level PASS -Message "artifact resumable: state uploading, progress $progressAfter persisted across the kill (exactly the acked prefix)"

    Write-Drill -Level STEP -Message 'Resuming the upload from the persisted offset'
    $fs = [System.IO.File]::OpenRead($filePath)
    try {
        $offset = $progressAfter
        $remaining = $actualSize - $offset
        while ($remaining -gt 0) {
            $take = [Math]::Min($chunkBytes, $remaining)
            $buf = New-Object byte[] $take
            [void]$fs.Read($buf, 0, $take)
            $offset = Send-Chunk -Session $api -ArtifactId $artifact.artifact_id -Offset $offset -Bytes $buf
            $remaining = $actualSize - $offset
        }
        Write-Drill -Level INFO -Message "all bytes uploaded (progress $offset / $actualSize)"
    }
    finally {
        $fs.Dispose()
    }

    Write-Drill -Level STEP -Message 'Finalizing (the server re-reads the file and verifies the SHA-256)'
    $finalized = Invoke-Api -Session $api -Method POST -Path "/api/v1/artifacts/$($artifact.artifact_id)/finalize" -Body '{}' -Expect @(200) -Mutation $true
    $stateFinal = $finalized.Json.state
    Write-Drill -Level INFO -Message "final state: $stateFinal"
    if ($stateFinal -ne 'ready') { throw "finalize did not reach ready (state=$stateFinal)" }
    Write-Drill -Level PASS -Message 'artifact Ready — the resumed upload verified the declared SHA-256 end-to-end'

    Write-Drill -Level DONE -Message 'DRILL PASSED: large-file-interruption — resumable upload across a process kill, no corrupted residue'
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

# drill-lib.ps1 - shared library for the process-level drill suite (W-A).
#
# Provides:
#   * ConPTY-driven CLI interaction (rutilus init / run / backup all prompt
#     for the unlock passphrase on an interactive terminal; the pseudo
#     console supplies one).
#   * mock-bmc process management (start, stop, output parsing).
#   * The delay relay (transparent TCP proxy with a configurable delay) used
#     by drill-kill-mid-operation to hold a BMC response in flight.
#   * REST helpers against the rutilus console API (session cookie + CSRF).
#   * Process cleanup helpers (try/finally discipline), polling waits, and
#     structured PASS/FAIL logging into scripts/drills/logs/.
#
# PowerShell 5.1 compatible (Windows PowerShell). No product code is touched.
#
# The only fixture credentials used: the mock BMC's well-known
# admin/password pair (test-support fixture) and the drill's own local
# unlock passphrase (a drill fixture, not a secret).
# Fixture credentials are drill-local test stand-ins. The secret_leak_gate
# mechanical scan scope only covers `*/src/**/*.rs` and `*/tests/**/*.rs`;
# .ps1 files are outside that scope (documented boundary).

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Locate the repo and the binaries
# ---------------------------------------------------------------------------
$script:DrillRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$script:DrillBinDir = Join-Path $script:DrillRepoRoot 'target\debug'
$script:DrillRutilusExe = Join-Path $script:DrillBinDir 'rutilus.exe'
$script:DrillMockBmcExe = Join-Path $script:DrillBinDir 'mock-bmc.exe'
$script:DrillTmpRoot = Join-Path $PSScriptRoot 'tmp'
$script:DrillLogRoot = Join-Path $PSScriptRoot 'logs'

# The drill-local unlock passphrase (fixture; min length is 12 chars).
$script:DrillPassphrase = 'drill-local-unlock-2026'
# The console administrator password set at bootstrap claim (fixture).
$script:DrillAdminPassword = 'drill-admin-password-2026'

# ---------------------------------------------------------------------------
# Structured logging: every line goes to the console AND the drill log.
# ---------------------------------------------------------------------------
$script:DrillLogFile = $null

function Write-Drill {
    param(
        [Parameter(Mandatory = $true)][string]$Level,   # STEP / PASS / FAIL / INFO / WARN / SKIP / DONE
        [Parameter(Mandatory = $true)][string]$Message
    )
    $line = "[{0}] {1}" -f $Level, $Message
    if ($Level -eq 'PASS') { Write-Host $line -ForegroundColor Green }
    elseif ($Level -eq 'FAIL') { Write-Host $line -ForegroundColor Red }
    elseif ($Level -eq 'WARN') { Write-Host $line -ForegroundColor Yellow }
    elseif ($Level -eq 'STEP') { Write-Host $line -ForegroundColor Cyan }
    elseif ($Level -eq 'DONE') { Write-Host $line -ForegroundColor Magenta }
    else { Write-Host $line }
    if ($script:DrillLogFile) {
        Add-Content -Path $script:DrillLogFile -Value ('{0:O} {1}' -f (Get-Date), $line) -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

function Start-DrillLog {
    param([Parameter(Mandatory = $true)][string]$DrillName)
    New-Item -ItemType Directory -Force -Path $script:DrillLogRoot | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:DrillLogFile = Join-Path $script:DrillLogRoot ('{0}-{1}.log' -f $DrillName, $stamp)
    Write-Host "[INFO] drill log: $script:DrillLogFile"
    return $script:DrillLogFile
}

# ---------------------------------------------------------------------------
# Polling wait: run $Condition until it returns $true or the timeout expires.
# ---------------------------------------------------------------------------
function Wait-For {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Condition,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [int]$IntervalMs = 250,
        [string]$What = 'condition'
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds $IntervalMs
    }
    return $false
}

# ---------------------------------------------------------------------------
# Free-port picker (bind port 0, read the assigned port, release).
# ---------------------------------------------------------------------------
function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()
    return $port
}

# ---------------------------------------------------------------------------
# ConPTY driver: spawns a child process attached to a pseudo console so the
# interactive CLI prompts can be driven (and the console output captured).
#
# Hang protection (learned from the 2026-08-12 first run, where a degraded
# ConPTY context hung the suite >20 min instead of FAILing): Start-ConPtyProcess
# probes for instant-launch failure, Wait-ConPtyOutput times out and cleans
# the session up on failure, and Dispose runs its teardown under a watchdog
# so ClosePseudoConsole can never block the drill forever.
# ---------------------------------------------------------------------------
if (-not ('ConPtySession' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class ConPtyNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct COORD { public short X; public short Y; }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX; public int dwY; public int dwXSize; public int dwYSize;
        public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute;
        public uint dwFlags; public short wShowWindow; public short cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO si;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess; public IntPtr hThread;
        public int dwProcessId; public int dwThreadId;
    }

    public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    public const uint STARTF_USESTDHANDLES = 0x00000100;
    public const uint PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int CreatePseudoConsole(COORD size, IntPtr hInput, IntPtr hOutput, uint dwFlags, out IntPtr phPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int ClosePseudoConsole(IntPtr hPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, IntPtr lpPipeAttributes, int nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToWrite, out int lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead, out int lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CancelIoEx(IntPtr hFile, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessW(string lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
}

public sealed class ConPtySession
{
    private IntPtr _pc;
    private IntPtr _inWrite;
    private IntPtr _outRead;
    private IntPtr _procHandle;
    private IntPtr _attrList;
    private Thread _reader;
    private readonly StringBuilder _output = new StringBuilder();
    private readonly object _lock = new object();
    private volatile bool _reading = true;

    public Process Process { get; private set; }
    public int ProcessId { get { return Process.Id; } }
    public string Output { get { lock (_lock) { return _output.ToString(); } } }

    public static ConPtySession Start(string exePath, string arguments, string workingDirectory)
    {
        ConPtyNative.COORD size = new ConPtyNative.COORD();
        size.X = 160; size.Y = 50;

        IntPtr inRead, inWrite, outRead, outWrite;
        if (!ConPtyNative.CreatePipe(out inRead, out inWrite, IntPtr.Zero, 0)) throw new InvalidOperationException("CreatePipe(input) failed: " + Marshal.GetLastWin32Error());
        if (!ConPtyNative.CreatePipe(out outRead, out outWrite, IntPtr.Zero, 0)) throw new InvalidOperationException("CreatePipe(output) failed: " + Marshal.GetLastWin32Error());

        IntPtr pc;
        int hr = ConPtyNative.CreatePseudoConsole(size, inRead, outWrite, 0, out pc);
        if (hr != 0) throw new InvalidOperationException("CreatePseudoConsole failed: " + hr);

        IntPtr attrSize = IntPtr.Zero;
        ConPtyNative.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attrSize);
        IntPtr attrList = Marshal.AllocHGlobal(attrSize);
        if (!ConPtyNative.InitializeProcThreadAttributeList(attrList, 1, 0, ref attrSize)) throw new InvalidOperationException("InitializeProcThreadAttributeList failed: " + Marshal.GetLastWin32Error());
        IntPtr pcPtr = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(pcPtr, pc);
        if (!ConPtyNative.UpdateProcThreadAttribute(attrList, 0, (IntPtr)ConPtyNative.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, pcPtr, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero)) throw new InvalidOperationException("UpdateProcThreadAttribute failed: " + Marshal.GetLastWin32Error());

        ConPtyNative.STARTUPINFOEX si = new ConPtyNative.STARTUPINFOEX();
        si.si.cb = Marshal.SizeOf(typeof(ConPtyNative.STARTUPINFOEX));
        si.si.dwFlags = ConPtyNative.STARTF_USESTDHANDLES;
        si.si.hStdInput = inRead;
        si.si.hStdOutput = outWrite;
        si.si.hStdError = outWrite;
        si.lpAttributeList = attrList;

        StringBuilder cmd = new StringBuilder();
        cmd.Append('"').Append(exePath).Append('"');
        if (!string.IsNullOrEmpty(arguments)) cmd.Append(' ').Append(arguments);

        ConPtyNative.PROCESS_INFORMATION pi;
        bool ok = ConPtyNative.CreateProcessW(null, cmd, IntPtr.Zero, IntPtr.Zero, false,
            ConPtyNative.EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero,
            string.IsNullOrEmpty(workingDirectory) ? null : workingDirectory, ref si, out pi);
        if (!ok) throw new InvalidOperationException("CreateProcessW failed: " + Marshal.GetLastWin32Error());

        // Parent copies of the console-facing pipe ends are no longer needed.
        ConPtyNative.CloseHandle(inRead);
        ConPtyNative.CloseHandle(outWrite);
        Marshal.FreeHGlobal(pcPtr);

        ConPtySession session = new ConPtySession();
        session._pc = pc;
        session._inWrite = inWrite;
        session._outRead = outRead;
        session._procHandle = pi.hProcess;
        session._attrList = attrList;
        session.Process = Process.GetProcessById(pi.dwProcessId);
        ConPtyNative.CloseHandle(pi.hThread);
        session._reader = new Thread(session.ReadLoop);
        session._reader.IsBackground = true;
        session._reader.Start();
        return session;
    }

    private void ReadLoop()
    {
        byte[] buffer = new byte[8192];
        while (_reading)
        {
            int read;
            if (!ConPtyNative.ReadFile(_outRead, buffer, buffer.Length, out read, IntPtr.Zero))
                break;
            if (read == 0) break;
            lock (_lock) { _output.Append(Encoding.UTF8.GetString(buffer, 0, read)); }
        }
    }

    public void SendInput(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        int written;
        if (!ConPtyNative.WriteFile(_inWrite, bytes, bytes.Length, out written, IntPtr.Zero))
            throw new InvalidOperationException("WriteFile(input) failed: " + Marshal.GetLastWin32Error());
    }

    public void SendLine(string text) { SendInput(text + "\r"); }

    public bool WaitExit(int timeoutMilliseconds)
    {
        uint result = ConPtyNative.WaitForSingleObject(_procHandle, (uint)timeoutMilliseconds);
        return result == 0;
    }

    public int ExitCode()
    {
        uint code;
        if (!ConPtyNative.GetExitCodeProcess(_procHandle, out code)) return -1;
        return (int)code;
    }

    public void Kill()
    {
        try { Process.Kill(); } catch { }
    }

    public void Dispose()
    {
        _reading = false;
        // Best-effort unblock of a reader stuck on the output pipe; a no-op
        // where the console plumbing works (the watchdog below is the actual
        // guarantee, so failures here are ignored).
        try { ConPtyNative.CancelIoEx(_outRead, IntPtr.Zero); } catch { }
        // Closing _outRead while the reader is stuck in ReadFile, and
        // ClosePseudoConsole itself, can both block indefinitely when the
        // pseudo console is degraded - the observed drill-hang mechanism
        // (drill cleanup hung >20 min, ClosePseudoConsole never returned).
        // All teardown therefore runs on a background watchdog thread and
        // Dispose returns after a fixed budget; anything left over leaks
        // background state that the OS reclaims when the process exits.
        Thread cleanup = new Thread(() =>
        {
            // Snapshot the handles into locals and zero the fields before
            // closing: a second Dispose (the timeout path stops the session,
            // then the caller's catch/finally stops it again) then finds
            // IntPtr.Zero everywhere and is a no-op - no repeated CloseHandle
            // on an already-closed handle (bounded but not handle-level
            // idempotent: a closed handle value could in theory be reused),
            // and no NULL attribute-list delete. The snapshot also keeps a
            // still-running watchdog immune to a concurrent Dispose.
            IntPtr pc = _pc, inWrite = _inWrite, outRead = _outRead,
                   procHandle = _procHandle, attrList = _attrList;
            _pc = IntPtr.Zero; _inWrite = IntPtr.Zero; _outRead = IntPtr.Zero;
            _procHandle = IntPtr.Zero; _attrList = IntPtr.Zero;
            try { if (outRead != IntPtr.Zero) ConPtyNative.CloseHandle(outRead); } catch { }
            try { if (inWrite != IntPtr.Zero) ConPtyNative.CloseHandle(inWrite); } catch { }
            try { if (pc != IntPtr.Zero) ConPtyNative.ClosePseudoConsole(pc); } catch { }
            try { if (attrList != IntPtr.Zero) ConPtyNative.DeleteProcThreadAttributeList(attrList); } catch { }
            try { if (attrList != IntPtr.Zero) Marshal.FreeHGlobal(attrList); } catch { }
            try { if (procHandle != IntPtr.Zero) ConPtyNative.CloseHandle(procHandle); } catch { }
        });
        cleanup.IsBackground = true;
        cleanup.Start();
        cleanup.Join(4000);
    }
}
'@ -ReferencedAssemblies System.dll
}

# Starts one interactive CLI command under a pseudo console.
# Returns a ConPtySession; the caller must call Stop-ConPtySession on it.
function Start-ConPtyProcess {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [string]$Arguments = '',
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [int]$StartupProbeSeconds = 5
    )
    if (-not (Test-Path $ExePath)) { throw "binary not found: $ExePath" }
    $session = [ConPtySession]::Start($ExePath, $Arguments, $WorkingDirectory)
    # Startup probe: in a degraded environment the pseudo-console child dies
    # within a couple of seconds with zero output (observed: 0xC0000142
    # STATUS_DLL_INIT_FAILED) and the console pipe yields nothing. Detect
    # that fast so the drill FAILs in seconds instead of spending the full
    # wait budget on a console that will never answer. Any captured output,
    # or the child staying alive for the whole window, means the console
    # plumbing works and normal waiting takes over - the probe exits early
    # as soon as output appears, so healthy runs pay only one poll interval.
    $probeExited = $false
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $StartupProbeSeconds) {
        if ($session.Output.Length -gt 0) { break }
        if ($session.WaitExit(0)) { $probeExited = $true; break }
        Start-Sleep -Milliseconds 200
    }
    if ($probeExited -and $session.Output.Length -eq 0) {
        $code = -1
        try { $code = $session.ExitCode() } catch { }
        Write-Drill -Level WARN -Message ("ConPTY startup probe: {0} {1} exited within {2}s before producing console output (exitCode={3}, outputLen=0) - pseudo-console launch failure in this context" -f $ExePath, $Arguments, $StartupProbeSeconds, $code)
        try { $null = Stop-ConPtySession $session -Force $true } catch { }
        throw "ConPTY launch failed: $ExePath exited with code $code before producing console output (outputLen=0); pseudo-console children cannot start in this execution context"
    }
    return $session
}

function Wait-ConPtyOutput {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [int]$TimeoutSeconds = 60
    )
    $matched = Wait-For -TimeoutSeconds $TimeoutSeconds -IntervalMs 150 -What "console output matching '$Pattern'" -Condition {
        ($Session.Output -match $Pattern)
    }
    if (-not $matched) {
        # Interactive-output timeout: the session will not produce the
        # awaited output. Fail the drill rather than hang - record the key
        # facts, then clean the session up through the normal bounded path
        # so the caller's finally has nothing left to block on. (The caller
        # checks the $false and throws with the captured output; the cleanup
        # is idempotent if it stops the session again.)
        $exited = $false
        try { $exited = $Session.WaitExit(0) } catch { }
        $code = -1
        if ($exited) { try { $code = $Session.ExitCode() } catch { } }
        Write-Drill -Level WARN -Message ("console output timed out after {0}s waiting for '{1}' (processExited={2} exitCode={3} outputLen={4}); cleaning up session" -f $TimeoutSeconds, $Pattern, $exited, $code, $Session.Output.Length)
        try { $null = Stop-ConPtySession $Session -Force $true } catch {
            Write-Drill -Level WARN -Message "cleanup after output timeout failed: $($_.Exception.Message)"
        }
    }
    return $matched
}

# Graceful stop: sends Ctrl-C (\x03) through the pseudo console, waits for
# the process to exit; force-kills as a fallback. Returns $true if the
# process exited (either way) within the budget.
#
# Every step is bounded so cleanup can never hang the drill: Ctrl-C is only
# sent while the child is still alive (a dead child cannot consume console
# input, and SendInput could stall on a degraded console), WaitExit has a
# hard timeout, and Dispose is watchdog-bounded in the C# type
# (ClosePseudoConsole can block forever when the pseudo console is broken -
# the observed drill-hang mechanism, >20 min stuck in cleanup).
function Stop-ConPtySession {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [int]$GraceSeconds = 20,
        [bool]$Force = $false
    )
    if ($null -eq $Session) { return }
    if (-not $Force -and -not $Session.WaitExit(0)) {
        try { $Session.SendInput([char]3) } catch { }
        if ($Session.WaitExit($GraceSeconds * 1000)) {
            $Session.Dispose()
            return $true
        }
    }
    try { $Session.Kill() } catch { }
    $Session.WaitExit(10000) | Out-Null
    $Session.Dispose()
    return $true
}

# ---------------------------------------------------------------------------
# mock-bmc process management
# ---------------------------------------------------------------------------
function Start-MockBmc {
    param(
        [Parameter(Mandatory = $true)][string]$WorkDir,
        [int]$Port = 0,
        [string]$Profile = 'rutilus',
        [Parameter(Mandatory = $true)][string]$Name = 'mock'
    )
    # The port is always passed explicitly: the default 0 tells mock-bmc to
    # bind a free port (TcpListener::bind on port 0) and report it in the
    # 'listening at' URL below, from which $portActual is parsed - so
    # $mock.Port is the real bound port whether -Port was given or not. (An
    # empty ArgumentList would also fail Start-Process' parameter
    # validation.)
    $argsList = @()
    $argsList += [string]$Port
    if ($Profile -ne 'rutilus') { $argsList += $Profile }
    $outLog = Join-Path $WorkDir "$Name.stdout.log"
    $errLog = Join-Path $WorkDir "$Name.stderr.log"
    $proc = Start-Process -FilePath $script:DrillMockBmcExe `
        -ArgumentList $argsList -WorkingDirectory $WorkDir `
        -RedirectStandardOutput $outLog -RedirectStandardError $errLog `
        -PassThru -WindowStyle Hidden
    $ready = Wait-For -TimeoutSeconds 30 -IntervalMs 200 -What "mock-bmc '$Name' listening" -Condition {
        (Test-Path $outLog) -and ((Get-Content $outLog -Raw -ErrorAction SilentlyContinue) -match 'listening at')
    }
    if (-not $ready) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        throw "mock-bmc '$Name' did not become ready; stderr: $(Get-Content $errLog -Raw -ErrorAction SilentlyContinue)"
    }
    $outText = Get-Content $outLog -Raw
    $urlMatch = [regex]::Match($outText, 'listening at\s+(\S+)')
    $fpMatch = [regex]::Match($outText, 'SHA-256 fingerprint:\s*(\S+)')
    if (-not $urlMatch.Success) { throw "mock-bmc '$Name' output missing URL: $outText" }
    if (-not $fpMatch.Success) { throw "mock-bmc '$Name' output missing fingerprint: $outText" }
    $portActual = ([uri]$urlMatch.Groups[1].Value).Port
    Write-Drill -Level INFO -Message "$Name listening at $($urlMatch.Groups[1].Value) (pid $($proc.Id), fingerprint $($fpMatch.Groups[1].Value))"
    return [pscustomobject]@{
        Process = $proc
        Pid = $proc.Id
        Url = $urlMatch.Groups[1].Value
        Port = $portActual
        Fingerprint = $fpMatch.Groups[1].Value
        OutLog = $outLog
        ErrLog = $errLog
    }
}

function Stop-MockBmc {
    param([Parameter(Mandatory = $true)]$Mock)
    if ($null -eq $Mock) { return }
    Stop-Process -Id $Mock.Pid -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# Delay relay: a transparent TCP proxy whose mock->product direction is
# delayed by a value re-read from a control file per chunk. The TLS
# handshake and every response pass through the delay, which is how a BMC
# response can be held in flight for drill-kill-mid-operation. The relay
# counts connections for its own debugging only: the counter lives in the
# relay's SEPARATE process ([DelayRelayWorker] in drill-delay-proxy.ps1),
# which the drill's process cannot read. Drills observe actual traffic
# through Measure-ConnectionsToPort (Get-NetTCPConnection), not the counter.
# ---------------------------------------------------------------------------
if (-not ('DelayRelay' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

public static class DelayRelay
{
    private static volatile int _delayMs;
    private static string _delayFile;
    private static long _connections;

    public static void Start(int listenPort, string targetHost, int targetPort, string delayFile)
    {
        _delayFile = delayFile;
        _delayMs = ReadDelay();
        TcpListener listener = new TcpListener(IPAddress.Loopback, listenPort);
        listener.Start();
        Thread accept = new Thread(() => AcceptLoop(listener, targetHost, targetPort));
        accept.IsBackground = true;
        accept.Start();
    }

    public static long Connections { get { return Interlocked.Read(ref _connections); } }

    private static int ReadDelay()
    {
        try { return int.Parse(File.ReadAllText(_delayFile).Trim()); }
        catch { return 0; }
    }

    private static void AcceptLoop(TcpListener listener, string targetHost, int targetPort)
    {
        while (true)
        {
            TcpClient client;
            try { client = listener.AcceptTcpClient(); }
            catch { return; }
            Interlocked.Increment(ref _connections);
            Thread t = new Thread(() => HandleClient(client, targetHost, targetPort));
            t.IsBackground = true;
            t.Start();
        }
    }

    private static void HandleClient(TcpClient client, string targetHost, int targetPort)
    {
        TcpClient target = null;
        try
        {
            target = new TcpClient();
            target.Connect(targetHost, targetPort);
            NetworkStream toBmc = target.GetStream();
            NetworkStream fromBmc = client.GetStream();

            Thread productToBmc = new Thread(() => Pump(client.GetStream(), toBmc, 0));
            productToBmc.IsBackground = true;
            productToBmc.Start();

            Pump(toBmc, fromBmc, 1);
            productToBmc.Join(1000);
        }
        catch { }
        finally
        {
            try { client.Close(); } catch { }
            try { if (target != null) target.Close(); } catch { }
        }
    }

    private static void Pump(Stream readFrom, Stream writeTo, int direction)
    {
        byte[] buffer = new byte[16384];
        try
        {
            while (true)
            {
                int read = readFrom.Read(buffer, 0, buffer.Length);
                if (read <= 0) return;
                if (direction == 1)
                {
                    int d = _delayMs;
                    if (d > 0) Thread.Sleep(d);
                }
                writeTo.Write(buffer, 0, read);
                writeTo.Flush();
            }
        }
        catch { }
    }
}
'@ -ReferencedAssemblies System.dll
}

# Starts the delay relay as a background PowerShell process (its own
# process so a drill kill cannot wedge the drill itself).
function Start-DelayRelay {
    param(
        [Parameter(Mandatory = $true)][int]$ListenPort,
        [Parameter(Mandatory = $true)][int]$TargetPort,
        [Parameter(Mandatory = $true)][string]$DelayFile
    )
    $proxyScript = Join-Path $PSScriptRoot 'drill-delay-proxy.ps1'
    $proc = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $proxyScript + '"'), $ListenPort, $TargetPort, ('"' + $DelayFile + '"')) `
        -WorkingDirectory (Split-Path $proxyScript) -WindowStyle Hidden -PassThru
    # Wait for the proxy to listen.
    $ready = Wait-For -TimeoutSeconds 15 -IntervalMs 200 -What 'delay relay listening' -Condition {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect('127.0.0.1', $ListenPort)
            $c.Close()
            $true
        } catch { $false }
    }
    if (-not $ready) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        throw "delay relay did not become ready on port $ListenPort"
    }
    return $proc
}

# Sets the per-response delay of a running relay (ms).
function Set-RelayDelay {
    param([Parameter(Mandatory = $true)][string]$DelayFile, [int]$Milliseconds = 0)
    Set-Content -Path $DelayFile -Value ([string]$Milliseconds) -Encoding ASCII
}

# ---------------------------------------------------------------------------
# rutilus CLI interaction (init / run / backup / restore) via the pty.
# ---------------------------------------------------------------------------
# Fresh work directory per drill: the portable data dir lives BESIDE the
# executable, so each drill gets its own exe copy + rutilus-data/.
function New-DrillWorkDir {
    param([Parameter(Mandatory = $true)][string]$DrillName)
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $dir = Join-Path $script:DrillTmpRoot ("{0}-{1}" -f $DrillName, $stamp)
    $bin = Join-Path $dir 'bin'
    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    Copy-Item -Path $script:DrillRutilusExe -Destination $bin -Force
    return $dir
}

# Runs `rutilus init --portable` interactively; returns the bootstrap code
# and the raw console output.
function Invoke-RutilusInit {
    param(
        [Parameter(Mandatory = $true)][string]$WorkDir,
        [Parameter(Mandatory = $true)][string]$Passphrase
    )
    $bin = Join-Path $WorkDir 'bin'
    $exe = Join-Path $bin 'rutilus.exe'
    $session = Start-ConPtyProcess -ExePath $exe -Arguments 'init --portable' -WorkingDirectory $bin
    try {
        if (-not (Wait-ConPtyOutput $session 'Local unlock passphrase:' 60)) {
            throw "init did not prompt for the passphrase; output: $($session.Output)"
        }
        $session.SendLine($Passphrase)
        if (-not (Wait-ConPtyOutput $session 'Confirm local unlock passphrase:' 30)) {
            throw "init did not prompt for confirmation; output: $($session.Output)"
        }
        $session.SendLine($Passphrase)
        if (-not (Wait-ConPtyOutput $session 'Rutilus bootstrap code:' 120)) {
            throw "init did not print the bootstrap code; output: $($session.Output)"
        }
        $codeMatch = [regex]::Match($session.Output, 'Rutilus bootstrap code:\s*(\S+)')
        if (-not $codeMatch.Success) { throw "bootstrap code not parseable: $($session.Output)" }
        $exited = $session.WaitExit(120000)
        $exitCode = $session.ExitCode()
        if (-not $exited -or $exitCode -ne 0) {
            throw "init did not exit cleanly (exited=$exited code=$exitCode); output: $($session.Output)"
        }
        Write-Drill -Level INFO -Message 'rutilus init --portable completed; bootstrap code captured'
        return [pscustomobject]@{ BootstrapCode = $codeMatch.Groups[1].Value; Output = $session.Output }
    }
    finally {
        $null = Stop-ConPtySession $session -Force $true
    }
}

# Runs `rutilus run --portable --no-open` interactively; waits for the
# listening line and returns the console URL. The session stays ALIVE; the
# caller must stop it via Stop-ConPtySession.
function Start-RutilusRun {
    param(
        [Parameter(Mandatory = $true)][string]$WorkDir,
        [Parameter(Mandatory = $true)][string]$Passphrase
    )
    $bin = Join-Path $WorkDir 'bin'
    $exe = Join-Path $bin 'rutilus.exe'
    $session = Start-ConPtyProcess -ExePath $exe -Arguments 'run --portable --no-open' -WorkingDirectory $bin
    try {
        if (-not (Wait-ConPtyOutput $session 'Local unlock passphrase:' 60)) {
            throw "run did not prompt for the passphrase; output: $($session.Output)"
        }
        $session.SendLine($Passphrase)
        if (-not (Wait-ConPtyOutput $session 'Rutilus Standalone is listening at' 90)) {
            throw "run did not report the listening address; output: $($session.Output)"
        }
        $urlMatch = [regex]::Match($session.Output, 'listening at\s+(\S+)')
        if (-not $urlMatch.Success) { throw "listening URL not parseable: $($session.Output)" }
        Write-Drill -Level INFO -Message "rutilus console listening at $($urlMatch.Groups[1].Value)"
        return [pscustomobject]@{ Session = $session; Url = $urlMatch.Groups[1].Value }
    }
    catch {
        $null = Stop-ConPtySession $session -Force $true
        throw
    }
}

# Force-kills the rutilus run session (drill-a/drill-b kill semantics).
function Stop-RutilusRunForce {
    param([Parameter(Mandatory = $true)]$Run)
    if ($null -eq $Run) { return }
    $pid = $Run.Session.ProcessId
    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    $Run.Session.WaitExit(15000) | Out-Null
    $Run.Session.Dispose()
}

# Gracefully stops the rutilus run session (Ctrl-C via the pty), with a
# force-kill fallback.
function Stop-RutilusRunGraceful {
    param([Parameter(Mandatory = $true)]$Run, [int]$GraceSeconds = 25)
    if ($null -eq $Run) { return }
    Stop-ConPtySession $Run.Session -GraceSeconds $GraceSeconds
}

# ---------------------------------------------------------------------------
# Console API helpers (session cookie + CSRF token discipline).
# ---------------------------------------------------------------------------
function New-ApiSession {
    param([Parameter(Mandatory = $true)][string]$BaseUrl)
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.CookieContainer = New-Object System.Net.CookieContainer
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(180)
    return [pscustomobject]@{
        Client = $client
        Handler = $handler
        BaseUrl = $BaseUrl.TrimEnd('/')
        Csrf = $null
    }
}

function Invoke-Api {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [string]$Method = 'GET',
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Body = $null,
        [int[]]$Expect = @(200, 201),
        [bool]$Mutation = $false,
        [string]$ContentType = 'application/json'
    )
    $url = $Session.BaseUrl + $Path
    $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::$Method, $url)
    try {
        if ($null -ne $Body) {
            $request.Content = New-Object System.Net.Http.StringContent($Body, [System.Text.Encoding]::UTF8, $ContentType)
        }
        if ($Mutation -and $Session.Csrf) {
            [void]$request.Headers.TryAddWithoutValidation('X-CSRF-Token', $Session.Csrf)
        }
        $response = $Session.Client.SendAsync($request).GetAwaiter().GetResult()
        $status = [int]$response.StatusCode
        $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $response.Dispose()
        if ($Expect -notcontains $status) {
            throw "API $Method $Path returned $status (expected $($Expect -join '/')): $text"
        }
        $json = $null
        if ($text) { try { $json = $text | ConvertFrom-Json } catch { $json = $null } }
        return [pscustomobject]@{ Status = $status; Body = $text; Json = $json }
    }
    finally {
        $request.Dispose()
    }
}

# First-run claim: POST /api/v1/auth/bootstrap with the printed code.
function Invoke-RutilusBootstrap {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$BootstrapCode,
        [Parameter(Mandatory = $true)][string]$AdminPassword
    )
    $body = @{ code = $BootstrapCode; password = $AdminPassword } | ConvertTo-Json -Compress
    $response = Invoke-Api -Session $Session -Method POST -Path '/api/v1/auth/bootstrap' -Body $body -Expect @(200)
    if (-not $response.Json.csrf_token) { throw 'bootstrap response carried no CSRF token' }
    $Session.Csrf = $response.Json.csrf_token
    Write-Drill -Level INFO -Message 'bootstrap claim completed; console is now guarded'
    return $response
}

# Sign-in: POST /api/v1/auth/login.
function Invoke-RutilusLogin {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [string]$Username = 'admin',
        [Parameter(Mandatory = $true)][string]$Password
    )
    $body = @{ username = $Username; password = $Password } | ConvertTo-Json -Compress
    $response = Invoke-Api -Session $Session -Method POST -Path '/api/v1/auth/login' -Body $body -Expect @(200)
    if (-not $response.Json.csrf_token) { throw 'login response carried no CSRF token' }
    $Session.Csrf = $response.Json.csrf_token
    return $response
}

# ---------------------------------------------------------------------------
# Mock-HTTPS pinning helper (C#). Two PowerShell 5.1 realities force this:
#   * the TLS validation callback runs on a worker thread that has NO
#     PowerShell runspace, so a scriptblock callback cannot be invoked there
#     (PSInvalidOperationException -> the handshake always fails);
#   * $certificate.GetCertHashString() returns SHA-1 on .NET Framework, which
#     can never match the SHA-256 fingerprint mock-bmc advertises.
# The C# delegate computes SHA-256 over the served certificate DER (the exact
# value mock-bmc's fingerprint_text() prints) and compares it, ordinal,
# against the expected fingerprint normalized to lowercase hex without
# separators.
# ---------------------------------------------------------------------------
if (-not ('MockHttpsPinner' -as [type])) {
Add-Type -AssemblyName System.Net.Http
Add-Type -TypeDefinition @'
using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public static class MockHttpsPinner
{
    public static HttpClientHandler Apply(HttpClientHandler handler, string expectedFingerprint)
    {
        handler.ServerCertificateCustomValidationCallback =
            new Func<HttpRequestMessage, X509Certificate2, X509Chain, System.Net.Security.SslPolicyErrors, bool>(
                (sender, certificate, chain, sslPolicyErrors) =>
                {
                    if (certificate == null) { return false; }
                    using (SHA256 sha = SHA256.Create())
                    {
                        string actual = BitConverter.ToString(sha.ComputeHash(certificate.GetRawCertData()))
                            .Replace("-", string.Empty)
                            .ToLowerInvariant();
                        return string.Equals(actual, expectedFingerprint, StringComparison.Ordinal);
                    }
                });
        return handler;
    }
}
'@ -ReferencedAssemblies System.Net.Http
}

# HTTPS helper for talking to the mock BMC directly (drills verify the mock
# ledger): pinned by the SHA-256 certificate fingerprint printed by mock-bmc.
function Invoke-MockHttps {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$ExpectedFingerprint,
        [string]$Method = 'GET',
        [string]$Body = $null
    )
    $handler = New-Object System.Net.Http.HttpClientHandler
    $expected = $ExpectedFingerprint -replace ':', ''
    $expected = $expected.ToLowerInvariant()
    $handler = [MockHttpsPinner]::Apply($handler, $expected)
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(60)
    try {
        $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::$Method, $Url)
        # NOTE: a [string] parameter default of $null binds as '' (PS coercion),
        # so the body must be tested for emptiness, not nullness: attaching an
        # empty StringContent to a GET makes .NET Framework throw
        # ProtocolViolationException ("cannot send a content body with this
        # verb type") before the request is ever sent.
        if (-not [string]::IsNullOrEmpty($Body)) {
            $request.Content = New-Object System.Net.Http.StringContent($Body, [System.Text.Encoding]::UTF8, 'application/json')
        }
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $status = [int]$response.StatusCode
        $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $response.Dispose()
        $request.Dispose()
        $json = $null
        if ($text) { try { $json = $text | ConvertFrom-Json } catch { $json = $null } }
        return [pscustomobject]@{ Status = $status; Body = $text; Json = $json }
    }
    finally {
        $client.Dispose()
    }
}

# ---------------------------------------------------------------------------
# Enrollment helper: create a credential, then enroll a pinned endpoint.
# Returns the endpoint id.
# ---------------------------------------------------------------------------
function Add-TestEndpoint {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][string]$Fingerprint,
        [string]$CredentialName = 'mock-admin',
        [string]$CredentialUser = 'admin',
        [string]$CredentialPassword = 'password'
    )
    $credBody = @{ name = $CredentialName; username = $CredentialUser; password = $CredentialPassword } | ConvertTo-Json -Compress
    $cred = Invoke-Api -Session $Session -Method POST -Path '/api/v1/credentials' -Body $credBody -Expect @(201) -Mutation $true
    $credentialId = $cred.Json.credential_id
    if (-not $credentialId) { throw "credential create returned no id: $($cred.Body)" }
    $enrollBody = @{
        display_name = $DisplayName
        address = $Address
        trust = @{ mode = 'pinned_certificate'; fingerprint_sha256 = $Fingerprint }
        credential_id = $credentialId
    } | ConvertTo-Json -Compress -Depth 6
    $enrolled = Invoke-Api -Session $Session -Method POST -Path '/api/v1/endpoints' -Body $enrollBody -Expect @(201) -Mutation $true
    if (-not $enrolled.Json.endpoint_id) { throw "enrollment returned no endpoint id: $($enrolled.Body)" }
    Write-Drill -Level INFO -Message "enrolled endpoint '$DisplayName' -> $Address (id $($enrolled.Json.endpoint_id))"
    return [pscustomobject]@{ EndpointId = $enrolled.Json.endpoint_id; CredentialId = $credentialId }
}

# Submits one typed operation; returns the operation id.
function Submit-Operation {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$TargetEndpointId,
        [Parameter(Mandatory = $true)]$CommandObject
    )
    $body = @{ targets = @($TargetEndpointId); command = $CommandObject } | ConvertTo-Json -Compress -Depth 10
    $response = Invoke-Api -Session $Session -Method POST -Path '/api/v1/operations' -Body $body -Expect @(201) -Mutation $true
    if (-not $response.Json.operation_id) { throw "operation submission returned no id: $($response.Body)" }
    return $response.Json.operation_id
}

function Get-OperationState {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$OperationId
    )
    $response = Invoke-Api -Session $Session -Method GET -Path "/api/v1/operations/$OperationId" -Expect @(200)
    if ($null -eq $response.Json.state) { throw "operation detail carried no state: $($response.Body)" }
    return $response.Json.state
}

function Get-OperationDetail {
    param(
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)][string]$OperationId
    )
    return Invoke-Api -Session $Session -Method GET -Path "/api/v1/operations/$OperationId" -Expect @(200)
}

# ---------------------------------------------------------------------------
# TCP observation: counts sampling windows in which a live connection to a
# loopback port was seen. Used by drill-bmc-restart-during-task to prove the
# Task monitor resumed polling the restarted mock (the mock keeps no external
# request log).
#
# Timing rationale: the product's HTTP client opens a fresh short-lived
# connection per poll (pool_max_idle_per_host(0)) and the Task monitor polls
# roughly every 2 s, so live connections only occupy a small fraction of each
# cycle. Get-NetTCPConnection itself takes ~100-300 ms per round, so with the
# default 50 ms sleep the effective sampling period is ~150-350 ms. Drills
# must combine a 20-30 s window (many poll cycles) with a `-ge 1` threshold;
# a short window with a high threshold fails randomly on healthy products.
# ---------------------------------------------------------------------------
function Measure-ConnectionsToPort {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$WindowSeconds,
        [int]$IntervalMs = 50
    )
    $observations = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $WindowSeconds) {
        $conns = Get-NetTCPConnection -RemotePort $Port -ErrorAction SilentlyContinue |
            Where-Object { $_.State -in @('Established', 'SynSent', 'SynReceived') }
        if ($conns) { $observations += 1 }
        Start-Sleep -Milliseconds $IntervalMs
    }
    return $observations
}

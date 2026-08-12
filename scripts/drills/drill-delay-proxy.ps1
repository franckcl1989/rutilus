# drill-delay-proxy.ps1 — transparent loopback TCP relay with a configurable
# delay on the mock->product direction. Started by drill-lib.ps1
# (Start-DelayRelay) as its own process so it survives drill script restarts
# and is killed independently in cleanup.
#
# Usage: powershell -NoProfile -File drill-delay-proxy.ps1 <listen-port> <target-port> <delay-file>
#
# The delay file holds the number of milliseconds to delay each relayed
# mock->product chunk; the value is re-read per chunk, so a drill can flip
# the delay at any moment. The relay counts connections (its own control
# surface is the connection itself: every accepted connection increments
# the counter exposed nowhere externally — connection counting for
# assertions is done by the drill through Get-NetTCPConnection).

param(
    [Parameter(Mandatory = $true)][int]$ListenPort,
    [Parameter(Mandatory = $true)][int]$TargetPort,
    [Parameter(Mandatory = $true)][string]$DelayFile
)

$ErrorActionPreference = 'Stop'
$relayType = @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

public static class DelayRelayWorker
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
'@

Add-Type -TypeDefinition $relayType -ReferencedAssemblies System.dll
[DelayRelayWorker]::Start($ListenPort, '127.0.0.1', $TargetPort, $DelayFile)

# Keep the proxy process alive; the drill kills it in cleanup.
while ($true) {
    Start-Sleep -Seconds 1
}

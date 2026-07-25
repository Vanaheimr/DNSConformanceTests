using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace DNSConformance.Core.Scripted;

/// <summary>
/// A loopback UDP responder driven entirely by the test: for every received
/// datagram the responder delegate decides which datagrams (zero or more,
/// e.g. spoofed + genuine) are sent back. Records all requests.
/// </summary>
public sealed class ScriptedUdpServer : IAsyncDisposable
{

    private readonly Func<Byte[], Int32, IEnumerable<Byte[]>>  responder;
    private readonly UdpClient                                 udp;
    private readonly CancellationTokenSource                   cts       = new();
    private readonly Task                                      loop;
    private          Int32                                     requestCounter;

    public ConcurrentQueue<Byte[]>  Requests   { get; } = new();

    public Int32                    Port       { get; }

    public IPEndPoint               EndPoint   => new(IPAddress.Loopback, Port);


    /// <summary>Responder receives (request bytes, zero-based request index) and yields response datagrams in send order.</summary>
    /// <param name="Responder">The scripted response logic.</param>
    /// <param name="FixedPort">Bind this specific port instead of an ephemeral one (e.g. to pair with a TCP listener for RFC 7766 fallback tests).</param>
    public ScriptedUdpServer(Func<Byte[], Int32, IEnumerable<Byte[]>>  Responder,
                             Int32                                     FixedPort   = 0)
    {

        responder  = Responder;
        udp        = new UdpClient(new IPEndPoint(IPAddress.Loopback, FixedPort));
        Port       = ((IPEndPoint) udp.Client.LocalEndPoint!).Port;
        loop       = Task.Run(ReceiveLoop);

    }

    /// <summary>Simple form: one response (or null for silence) per request.</summary>
    public ScriptedUdpServer(Func<Byte[], Byte[]?>  Responder,
                             Int32                  FixedPort   = 0)

        : this((request, _) => Responder(request) is { } response ? [response] : Array.Empty<Byte[]>(),
               FixedPort)

    { }

    /// <summary>Always answer with the same canned bytes.</summary>
    public static ScriptedUdpServer Static(Byte[] Response)
        => new((_, _) => [Response]);

    /// <summary>Never answer (timeout behavior).</summary>
    public static ScriptedUdpServer Silent()
        => new((_, _) => Array.Empty<Byte[]>());


    private async Task ReceiveLoop()
    {

        try
        {
            while (!cts.IsCancellationRequested)
            {

                var datagram = await udp.ReceiveAsync(cts.Token);
                Requests.Enqueue(datagram.Buffer);

                var index = Interlocked.Increment(ref requestCounter) - 1;

                foreach (var response in responder(datagram.Buffer, index))
                    await udp.SendAsync(response, datagram.RemoteEndPoint, cts.Token);

            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException)    { }
        catch (SocketException)            { }

    }


    public async ValueTask DisposeAsync()
    {

        await cts.CancelAsync();
        udp.Dispose();

        try
        {
            await loop.WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch { /* loop is stuck in native receive — process teardown will collect it */ }

        cts.Dispose();

    }

}

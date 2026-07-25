using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace DNSConformance.Core.Scripted;

public sealed class ScriptedTcpOptions
{

    /// <summary>Write responses in chunks of this many bytes with flushes in between (0 = single write). Exercises RFC 7766 §8 stream reassembly.</summary>
    public Int32     WriteChunkSize    { get; init; } = 0;

    /// <summary>Delay between chunked writes.</summary>
    public TimeSpan  WriteChunkDelay   { get; init; } = TimeSpan.FromMilliseconds(5);

    /// <summary>Close the connection right after the first response.</summary>
    public Boolean   CloseAfterFirst   { get; init; } = false;

    /// <summary>Send the 2-byte length prefix and the payload in separate writes.</summary>
    public Boolean   SplitLengthPrefix { get; init; } = false;

}


/// <summary>
/// A loopback TCP DNS responder implementing RFC 1035 §4.2.2 / RFC 7766
/// two-byte length framing. The responder delegate works on unframed
/// messages; framing (including deliberately hostile write patterns)
/// is handled here.
/// </summary>
public sealed class ScriptedTcpServer : IAsyncDisposable
{

    private readonly Func<Byte[], IEnumerable<Byte[]>>  responder;
    private readonly TcpListener                        listener;
    private readonly CancellationTokenSource            cts        = new();
    private readonly Task                               acceptLoop;
    private readonly ScriptedTcpOptions                 options;

    public ConcurrentQueue<Byte[]>  Requests         { get; } = new();

    public Int32                    Port             { get; }

    public Int32                    ConnectionCount  => connectionCount;
    private Int32                   connectionCount;


    public ScriptedTcpServer(Func<Byte[], IEnumerable<Byte[]>>  Responder,
                             ScriptedTcpOptions?                Options   = null)
    {

        responder   = Responder;
        options     = Options ?? new ScriptedTcpOptions();
        listener    = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port        = ((IPEndPoint) listener.LocalEndpoint).Port;
        acceptLoop  = Task.Run(AcceptLoop);

    }

    public ScriptedTcpServer(Func<Byte[], Byte[]?>  Responder,
                             ScriptedTcpOptions?    Options   = null)

        : this(request => Responder(request) is { } response ? [response] : Array.Empty<Byte[]>(),
               Options)

    { }


    private async Task AcceptLoop()
    {

        try
        {
            while (!cts.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(cts.Token);
                Interlocked.Increment(ref connectionCount);
                _ = Task.Run(() => HandleConnection(client));
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException)    { }
        catch (SocketException)            { }

    }


    private async Task HandleConnection(TcpClient client)
    {

        try
        {

            using var _      = client;
            var       stream = client.GetStream();

            while (!cts.IsCancellationRequested)
            {

                var lengthBytes = new Byte[2];

                if (!await ReadExactly(stream, lengthBytes))
                    return;                                     // peer closed

                var length  = (lengthBytes[0] << 8) | lengthBytes[1];
                var message = new Byte[length];

                if (!await ReadExactly(stream, message))
                    return;

                Requests.Enqueue(message);

                foreach (var response in responder(message))
                {

                    var framed = new Byte[response.Length + 2];
                    framed[0] = (Byte) (response.Length >> 8);
                    framed[1] = (Byte) (response.Length & 0xFF);
                    response.CopyTo(framed, 2);

                    if (options.SplitLengthPrefix)
                    {
                        await stream.WriteAsync(framed.AsMemory(0, 1), cts.Token);
                        await stream.FlushAsync(cts.Token);
                        await Task.Delay(options.WriteChunkDelay, cts.Token);
                        await stream.WriteAsync(framed.AsMemory(1, 1), cts.Token);
                        await stream.FlushAsync(cts.Token);
                        await Task.Delay(options.WriteChunkDelay, cts.Token);
                        await WriteChunked(stream, framed.AsMemory(2));
                    }
                    else if (options.WriteChunkSize > 0)
                        await WriteChunked(stream, framed);
                    else
                        await stream.WriteAsync(framed, cts.Token);

                    await stream.FlushAsync(cts.Token);

                    if (options.CloseAfterFirst)
                        return;

                }

            }

        }
        catch (OperationCanceledException) { }
        catch (IOException)                { }
        catch (ObjectDisposedException)    { }

    }


    private async Task WriteChunked(NetworkStream stream, ReadOnlyMemory<Byte> data)
    {

        var chunkSize = Math.Max(1, options.WriteChunkSize);

        for (var offset = 0; offset < data.Length; offset += chunkSize)
        {
            var chunk = data.Slice(offset, Math.Min(chunkSize, data.Length - offset));
            await stream.WriteAsync(chunk, cts.Token);
            await stream.FlushAsync(cts.Token);
            await Task.Delay(options.WriteChunkDelay, cts.Token);
        }

    }


    private async Task<Boolean> ReadExactly(NetworkStream stream, Byte[] buffer)
    {

        var read = 0;

        while (read < buffer.Length)
        {

            var n = await stream.ReadAsync(buffer.AsMemory(read), cts.Token);

            if (n == 0)
                return false;

            read += n;

        }

        return true;

    }


    public async ValueTask DisposeAsync()
    {

        await cts.CancelAsync();
        listener.Stop();

        try
        {
            await acceptLoop.WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch { }

        cts.Dispose();

    }

}

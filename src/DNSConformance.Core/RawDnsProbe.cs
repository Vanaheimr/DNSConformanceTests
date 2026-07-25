using System.Net;
using System.Net.Sockets;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Core;

/// <summary>
/// A raw-socket DNS client used to interrogate a DNS *server* without going
/// through any Hermod client code — so server conformance is judged
/// independently.
/// </summary>
public static class RawDnsProbe
{

    /// <summary>Send raw bytes over UDP and return the raw response bytes (null on timeout).</summary>
    public static async Task<Byte[]?> UdpAsync(Int32      port,
                                               Byte[]     request,
                                               TimeSpan?  timeout   = null,
                                               String     host      = "127.0.0.1")
    {

        using var udp = new UdpClient();
        udp.Connect(IPAddress.Parse(host), port);

        await udp.SendAsync(request);

        using var cts = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(3));

        try
        {
            var result = await udp.ReceiveAsync(cts.Token);
            return result.Buffer;
        }
        catch (OperationCanceledException)
        {
            return null;
        }

    }


    /// <summary>Send a message over TCP with RFC 7766 framing and return the unframed response.</summary>
    public static async Task<Byte[]?> TcpAsync(Int32      port,
                                               Byte[]     request,
                                               TimeSpan?  timeout   = null,
                                               String     host      = "127.0.0.1")
    {

        using var cts    = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(5));
        using var client = new TcpClient();

        await client.ConnectAsync(IPAddress.Parse(host), port, cts.Token);

        var stream = client.GetStream();

        return await ExchangeFramedAsync(stream, request, cts.Token);

    }


    /// <summary>Send several messages over ONE TCP connection (RFC 7766 §6.2.1 reuse).</summary>
    public static async Task<List<Byte[]?>> TcpPipelineAsync(Int32                 port,
                                                             IEnumerable<Byte[]>   requests,
                                                             TimeSpan?             timeout   = null,
                                                             String                host      = "127.0.0.1")
    {

        using var cts    = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(10));
        using var client = new TcpClient();

        await client.ConnectAsync(IPAddress.Parse(host), port, cts.Token);

        var stream    = client.GetStream();
        var responses = new List<Byte[]?>();

        foreach (var request in requests)
            responses.Add(await ExchangeFramedAsync(stream, request, cts.Token));

        return responses;

    }


    /// <summary>Send raw (unframed!) bytes over TCP — for framing-violation tests.</summary>
    public static async Task<Byte[]?> TcpRawAsync(Int32      port,
                                                  Byte[]     rawBytes,
                                                  TimeSpan?  timeout   = null,
                                                  String     host      = "127.0.0.1")
    {

        using var cts    = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(3));
        using var client = new TcpClient();

        await client.ConnectAsync(IPAddress.Parse(host), port, cts.Token);

        var stream = client.GetStream();

        await stream.WriteAsync(rawBytes, cts.Token);
        await stream.FlushAsync(cts.Token);

        var buffer = new Byte[4096];

        try
        {
            var read = await stream.ReadAsync(buffer, cts.Token);
            return read == 0 ? null : buffer[..read];
        }
        catch (OperationCanceledException)
        {
            return null;
        }

    }


    private static async Task<Byte[]?> ExchangeFramedAsync(Stream             stream,
                                                           Byte[]             request,
                                                           CancellationToken  cancellationToken)
    {

        var framed = new Byte[request.Length + 2];
        framed[0]  = (Byte) (request.Length >> 8);
        framed[1]  = (Byte) (request.Length & 0xFF);
        request.CopyTo(framed, 2);

        await stream.WriteAsync(framed, cancellationToken);
        await stream.FlushAsync(cancellationToken);

        try
        {

            var lengthBytes = new Byte[2];

            if (!await ReadExactlyAsync(stream, lengthBytes, cancellationToken))
                return null;

            var response = new Byte[(lengthBytes[0] << 8) | lengthBytes[1]];

            return await ReadExactlyAsync(stream, response, cancellationToken)
                       ? response
                       : null;

        }
        catch (OperationCanceledException)
        {
            return null;
        }

    }


    private static async Task<Boolean> ReadExactlyAsync(Stream             stream,
                                                        Byte[]             buffer,
                                                        CancellationToken  cancellationToken)
    {

        var read = 0;

        while (read < buffer.Length)
        {

            var n = await stream.ReadAsync(buffer.AsMemory(read), cancellationToken);

            if (n == 0)
                return false;

            read += n;

        }

        return true;

    }

}

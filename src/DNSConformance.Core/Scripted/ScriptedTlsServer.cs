using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Core.Scripted;

/// <summary>
/// A loopback DNS-over-TLS responder (RFC 7858): TLS 1.2/1.3 with a
/// self-signed test certificate, then RFC 7766 two-byte framing.
/// </summary>
public sealed class ScriptedTlsServer : IAsyncDisposable
{

    private readonly Func<Byte[], IEnumerable<Byte[]>>  responder;
    private readonly TcpListener                        listener;
    private readonly CancellationTokenSource            cts        = new();
    private readonly Task                               acceptLoop;

    public X509Certificate2         Certificate      { get; }

    public ConcurrentQueue<Byte[]>  Requests         { get; } = new();

    public Int32                    Port             { get; }

    public Int32                    HandshakeCount   => handshakeCount;
    private Int32                   handshakeCount;


    public ScriptedTlsServer(Func<Byte[], IEnumerable<Byte[]>>  Responder,
                             X509Certificate2?                  Certificate   = null)
    {

        responder         = Responder;
        this.Certificate  = Certificate ?? TestCertificate.CreateServerCertificate();
        listener          = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port              = ((IPEndPoint) listener.LocalEndpoint).Port;
        acceptLoop        = Task.Run(AcceptLoop);

    }

    public ScriptedTlsServer(Func<Byte[], Byte[]?>  Responder,
                             X509Certificate2?      Certificate   = null)

        : this(request => Responder(request) is { } response ? [response] : Array.Empty<Byte[]>(),
               Certificate)

    { }


    private async Task AcceptLoop()
    {

        try
        {
            while (!cts.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(cts.Token);
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

            using var _         = client;
            await using var tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);

            await tls.AuthenticateAsServerAsync(
                      new SslServerAuthenticationOptions {
                          ServerCertificate          = Certificate,
                          EnabledSslProtocols        = SslProtocols.Tls12 | SslProtocols.Tls13,
                          ClientCertificateRequired  = false
                      },
                      cts.Token
                  );

            Interlocked.Increment(ref handshakeCount);

            while (!cts.IsCancellationRequested)
            {

                var lengthBytes = new Byte[2];

                if (!await ReadExactly(tls, lengthBytes))
                    return;

                var length  = (lengthBytes[0] << 8) | lengthBytes[1];
                var message = new Byte[length];

                if (!await ReadExactly(tls, message))
                    return;

                Requests.Enqueue(message);

                foreach (var response in responder(message))
                {

                    var framed = new Byte[response.Length + 2];
                    framed[0] = (Byte) (response.Length >> 8);
                    framed[1] = (Byte) (response.Length & 0xFF);
                    response.CopyTo(framed, 2);

                    await tls.WriteAsync(framed, cts.Token);
                    await tls.FlushAsync(cts.Token);

                }

            }

        }
        catch (OperationCanceledException)  { }
        catch (IOException)                 { }
        catch (AuthenticationException)     { }
        catch (ObjectDisposedException)     { }

    }


    private async Task<Boolean> ReadExactly(Stream stream, Byte[] buffer)
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

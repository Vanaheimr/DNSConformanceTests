using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace DNSConformance.Core;

/// <summary>
/// A raw DNS-over-TLS client (RFC 7858) built straight on SslStream, used to
/// judge a DoT *server* without involving Hermod's own DoT client.
/// Certificate validation is intentionally disabled: the test certificates are
/// self-signed, and the TLS trust decision is not what these tests measure.
/// </summary>
public static class RawTlsProbe
{

    public static async Task<Byte[]?> QueryAsync(Int32      port,
                                                 Byte[]     request,
                                                 TimeSpan?  timeout   = null,
                                                 String     host      = "127.0.0.1")
    {

        var responses = await QueryManyAsync(port, [request], timeout, host);

        return responses.FirstOrDefault();

    }


    /// <summary>
    /// Send several queries over ONE TLS session.
    /// </summary>
    public static async Task<List<Byte[]?>> QueryManyAsync(Int32                port,
                                                           IEnumerable<Byte[]>  requests,
                                                           TimeSpan?            timeout   = null,
                                                           String               host      = "127.0.0.1")
    {

        using var cts    = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(10));
        using var client = new TcpClient();

        await client.ConnectAsync(IPAddress.Parse(host), port, cts.Token);

        await using var tls = new SslStream(
                                  client.GetStream(),
                                  leaveInnerStreamOpen: false,
                                  userCertificateValidationCallback: (_, _, _, _) => true
                              );

        await tls.AuthenticateAsClientAsync(
                  new SslClientAuthenticationOptions {
                      TargetHost           = "localhost",
                      EnabledSslProtocols  = SslProtocols.Tls12 | SslProtocols.Tls13
                  },
                  cts.Token
              );

        var responses = new List<Byte[]?>();

        foreach (var request in requests)
        {

            var framed = new Byte[request.Length + 2];
            framed[0]  = (Byte) (request.Length >> 8);
            framed[1]  = (Byte) (request.Length & 0xFF);
            request.CopyTo(framed, 2);

            await tls.WriteAsync(framed, cts.Token);
            await tls.FlushAsync(cts.Token);

            try
            {

                var lengthBytes = new Byte[2];

                if (!await ReadExactlyAsync(tls, lengthBytes, cts.Token))
                {
                    responses.Add(null);
                    break;
                }

                var response = new Byte[(lengthBytes[0] << 8) | lengthBytes[1]];

                responses.Add(await ReadExactlyAsync(tls, response, cts.Token) ? response : null);

            }
            catch (OperationCanceledException)
            {
                responses.Add(null);
                break;
            }

        }

        return responses;

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

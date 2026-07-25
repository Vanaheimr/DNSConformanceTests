using System.Collections.Concurrent;
using System.Net;

namespace DNSConformance.Core.Scripted;

/// <summary>One recorded DoH exchange, capturing everything RFC 8484 cares about.</summary>
public sealed record DoHExchange(
    String   Method,
    String   Path,
    String?  RawDnsParameter,   // the ?dns= value EXACTLY as sent (base64url padding checks!)
    String?  ContentType,
    String?  Accept,
    Byte[]   DnsMessage
);


/// <summary>
/// A minimal RFC 8484 DoH endpoint on plain HTTP (loopback), backed by
/// HttpListener. Decodes GET ?dns= (base64url) and POST bodies, hands the raw
/// DNS message to the responder, returns application/dns-message.
/// Plain HTTP is intentional: Hermod's DNSHTTPSClient offers HTTP_* test modes,
/// and TLS would only obscure the RFC 8484 layer under test here.
/// </summary>
public sealed class ScriptedDoHServer : IAsyncDisposable
{

    private readonly Func<Byte[], Byte[]?>    responder;
    private readonly HttpListener             http;
    private readonly CancellationTokenSource  cts   = new();
    private readonly Task                     loop;

    public ConcurrentQueue<DoHExchange>  Exchanges              { get; } = new();

    public Int32                         Port                   { get; }

    /// <summary>Reject POSTs whose Content-Type is not application/dns-message with 415 (RFC 8484 §4.1).</summary>
    public Boolean                       StrictContentType      { get; init; } = true;

    /// <summary>The RFC 8484 template URL of this server (path /dns-query).</summary>
    public String                        Url                    => $"http://127.0.0.1:{Port}/dns-query";


    public ScriptedDoHServer(Func<Byte[], Byte[]?> Responder)
    {

        responder = Responder;

        // HttpListener cannot bind port 0 — probe for a free one.
        var random     = new Random();
        HttpListener?  candidate = null;
        var            port      = 0;

        for (var attempt = 0; attempt < 20; attempt++)
        {

            port      = random.Next(20000, 60000);
            candidate = new HttpListener();
            candidate.Prefixes.Add($"http://127.0.0.1:{port}/");

            try
            {
                candidate.Start();
                break;
            }
            catch (HttpListenerException)
            {
                candidate.Close();
                candidate = null;
            }

        }

        http  = candidate ?? throw new InvalidOperationException("Could not find a free port for the DoH test server!");
        Port  = port;
        loop  = Task.Run(HandleLoop);

    }


    private async Task HandleLoop()
    {

        try
        {
            while (!cts.IsCancellationRequested)
            {
                var context = await http.GetContextAsync().WaitAsync(cts.Token);
                _ = Task.Run(() => HandleRequest(context));
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException)    { }
        catch (HttpListenerException)      { }

    }


    private async Task HandleRequest(HttpListenerContext context)
    {

        var request   = context.Request;
        var response  = context.Response;

        try
        {

            Byte[]?  dnsMessage    = null;
            String?  rawDnsParam   = null;

            if (request.HttpMethod == "GET")
            {

                // Extract the raw ?dns= value ourselves — QueryString would already
                // have URL-decoded it and we need to inspect the *literal* encoding.
                var query = request.Url?.Query ?? "";

                foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (pair.StartsWith("dns=", StringComparison.Ordinal))
                        rawDnsParam = pair[4..];
                }

                if (rawDnsParam is null)
                {
                    response.StatusCode = 400;
                    response.Close();
                    return;
                }

                // RFC 4648 §5 base64url; RFC 8484 §6 forbids padding, but decode
                // tolerantly and let tests assert on RawDnsParameter.
                var padded = rawDnsParam.Replace('-', '+').Replace('_', '/');

                if (padded.Length % 4 != 0)
                    padded += new String('=', 4 - padded.Length % 4);

                dnsMessage = Convert.FromBase64String(padded);

            }
            else if (request.HttpMethod == "POST")
            {

                using var ms = new MemoryStream();
                await request.InputStream.CopyToAsync(ms, cts.Token);
                dnsMessage = ms.ToArray();

            }
            else
            {
                response.StatusCode = 405;
                response.Close();
                return;
            }

            // Record BEFORE any rejection, so tests can assert on what the
            // client actually sent even when the request is refused.
            Exchanges.Enqueue(new DoHExchange(
                request.HttpMethod,
                request.Url?.AbsolutePath ?? "",
                rawDnsParam,
                request.ContentType,
                request.Headers["Accept"],
                dnsMessage
            ));

            if (StrictContentType &&
                request.HttpMethod == "POST" &&
                !(request.ContentType?.StartsWith("application/dns-message", StringComparison.OrdinalIgnoreCase) ?? false))
            {
                response.StatusCode = 415;   // RFC 8484 §4.1
                response.Close();
                return;
            }

            var answer = responder(dnsMessage);

            if (answer is null)
            {
                response.StatusCode = 500;
                response.Close();
                return;
            }

            response.StatusCode       = 200;
            response.ContentType      = "application/dns-message";
            response.ContentLength64  = answer.Length;
            await response.OutputStream.WriteAsync(answer, cts.Token);
            response.Close();

        }
        catch
        {
            try
            {
                response.StatusCode = 500;
                response.Close();
            }
            catch { }
        }

    }


    public async ValueTask DisposeAsync()
    {

        await cts.CancelAsync();

        try
        {
            http.Stop();
            http.Close();
        }
        catch { }

        try
        {
            await loop.WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch { }

        cts.Dispose();

    }

}

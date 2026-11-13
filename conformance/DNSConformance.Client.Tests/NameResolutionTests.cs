using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

using IPAddress = System.Net.IPAddress;

namespace DNSConformance.Client.Tests;

/// <summary>
/// <c>NameResolution</c>, the one place Hermod turns a host into the addresses
/// to connect to: an address is itself, "localhost" the loopback addresses, and
/// a host name what the DNS client it is given finds for it.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="SpecialUseNameTests"/> asks it about the names RFC 6761 and RFC
/// 7686 reserve. This fixture asks about everything else it reads: the literal
/// addresses, which need no DNS client, the query a host name becomes, and the
/// <c>SocketsHttpHandler</c> it builds for Hermod's HTTP clients, whose
/// connections go where it resolved them and nowhere else.
/// </para>
/// <para>
/// Its callers are TLSWarden, the HTTP/2 and HTTP/3 clients, the SSH and MTA-STS
/// clients and a handful of others, none of which this suite runs. So nothing
/// here goes through them: each test hands <c>NameResolution</c> the host as
/// they would.
/// </para>
/// </remarks>
[TestFixture]
public class NameResolutionTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    private static readonly Byte[] OK = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"u8.ToArray();


    /// <summary>
    /// What NameResolution resolves the host to, or null when it refuses it
    /// with the exception it documents.
    /// </summary>
    private static async Task<IReadOnlyList<IPAddress>?> ResolvedOrNull(String       Host,
                                                                        IDNSClient?  Client)
    {
        try
        {
            return await NameResolution.ResolveAsync(Host, Client);
        }
        catch (NameResolutionException)
        {
            return null;
        }
    }


    /// <summary>
    /// A server that answers A for every name with 192.0.2.61 and every other
    /// type with an empty NOERROR - or, for a name beginning "empty.", every
    /// type with an empty NOERROR.
    /// </summary>
    private static ScriptedUdpServer AnswerA()

        => new (request => {

               var questions = RawDnsReader.Parse(request).Questions;

               if (questions.Count != 1)
                   return null;

               var name = $"{questions[0].Name.Canonical}.";

               return questions[0].Type == RawDnsType.A && !name.StartsWith("empty.", StringComparison.Ordinal)
                          ? RawDnsResponder.Answer(request, (name, RawDnsType.A, 300, [192, 0, 2, 61]))
                          : RawDnsResponder.Answer(request);

           });


    private static DNSClient ClientOf(ScriptedUdpServer Server)

        => new (IPv4Address.Localhost,
                IPPort.Parse((UInt16) Server.Port),
                QueryTimeout:   Timeout,
                UseQueryCache:  false);


    /// <summary>
    /// Read an HTTP/1.1 request head, up to and including the empty line.
    /// </summary>
    private static async Task<String> ReadHead(NetworkStream Stream)
    {

        var head    = new StringBuilder();
        var buffer  = new Byte[1];

        while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {

            if (await Stream.ReadAsync(buffer).AsTask().WaitAsync(Timeout) == 0)
                break;

            head.Append((Char) buffer[0]);

        }

        return head.ToString();

    }


    private static TcpListener Listening()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return listener;
    }

    /// <summary>
    /// The zone of an IPv6 address, and 0 for an IPv4 address, which has none.
    /// </summary>
    private static Int64 ZoneOf(IPAddress Address)
        => Address.AddressFamily == AddressFamily.InterNetworkV6 ? Address.ScopeId : 0;

    private static Int32 PortOf(TcpListener Listener)
        => ((IPEndPoint) Listener.LocalEndpoint).Port;

    #endregion


    #region An address is itself, and needs no DNS client

    [Test]
    [Property("RFC", "3986 §3.2.2, 4007 §11, 6874 §2")]
    [TestCase("192.0.2.1",       "192.0.2.1",   TestName = "{m}: 192.0.2.1")]
    [TestCase("[2001:db8::1]",   "2001:db8::1", TestName = "{m}: [2001:db8::1], as a URL has it")]
    [TestCase("[fe80::1%2514]",  "fe80::1%14",  TestName = "{m}: [fe80::1%2514], a URL's zone, percent-encoded")]
    [TestCase("fe80::1%14",      "fe80::1%14",  TestName = "{m}: fe80::1%14, a zone written by hand")]
    public async Task An_Address_Is_Itself_Without_A_DNS_Client(String Host,
                                                                String Expected)
    {

        // An address names no host to look up, so the DNS client NameResolution
        // documents as optional for it is not given. The zones are the two forms
        // its own comments name. RFC 6874 §2 writes a zone inside a URL's
        // brackets after "%25", the percent-encoded "%": "[fe80::1%2514]" is
        // interface 14, and not 2514. RFC 4007 §11 writes it by hand after a
        // bare "%", which §4 of RFC 6874 asks URI parsers to accept as well
        // when no two hexadecimal digits follow it.
        var expected = IPAddress.Parse(Expected);
        var resolved = await ResolvedOrNull(Host, null);

        Assert.That(resolved, Is.Not.Null, $"'{Host}' is an address, which needs no DNS client");

        Assert.Multiple(() => {
            Assert.That(resolved, Is.EqualTo(new[] { expected }), $"'{Host}' is {expected}");
            Assert.That(resolved!.Select(ZoneOf), Is.EqualTo(new[] { ZoneOf(expected) }),
                        $"'{Host}' is on interface {ZoneOf(expected)}");
        });

    }


    [Test]
    [Property("RFC", "3986 §3.2.2")]
    public async Task An_Unclosed_Bracket_Is_No_Address()
    {

        // RFC 3986 §3.2.2: an IPv6 address in a host is distinguished "by
        // enclosing the IP literal within square brackets", and its grammar
        // closes what it opens: IP-literal = "[" ( IPv6address / IPvFuture ) "]".
        // "[::1" is not one, and nothing in it is a host name either.
        // Taken apart by its first and last characters it would be "::", the
        // unspecified address - which is no reading of it at all.
        await using var server  = AnswerA();
        using       var client  = ClientOf(server);

        var resolved  = await ResolvedOrNull("[::1", client);
        var sent      = server.Requests.Count;

        Assert.Multiple(() => {
            Assert.That(resolved, Is.Null, "'[::1' is neither an address nor a host name, and is refused");
            Assert.That(sent,     Is.Zero, "and nobody is asked about it");
        });

        // The control: the same client, the same server, a host name.
        Assert.That(await ResolvedOrNull("control.example", client),
                    Is.EqualTo(new[] { IPAddress.Parse("192.0.2.61") }),
                    "control: a host name is looked up through the same client");

    }

    #endregion


    #region "localhost" is the loopback addresses, and needs no DNS client

    [Test]
    [Property("RFC", "6761 §6.3")]
    [TestCase("localhost",       TestName = "{m}: localhost")]
    [TestCase("LocalHost",       TestName = "{m}: LocalHost, in another case")]
    [TestCase("localhost.",      TestName = "{m}: localhost., with the root's dot")]
    [TestCase("www.localhost",   TestName = "{m}: www.localhost, below it")]
    public async Task Localhost_Is_The_Loopback_Addresses_Without_A_DNS_Client(String Host)
    {

        // RFC 6761 §6.3 item 3: name resolution APIs "SHOULD always return the
        // IP loopback address for address queries". NameResolution documents
        // that "an IP address and localhost need none" - no DNS client. Given a
        // client, it would be asked, and the client answers localhost itself;
        // without one, the name is NameResolution's to know.
        var resolved = await ResolvedOrNull(Host, null);

        Assert.That(resolved, Is.Not.Null, $"'{Host}' needs no DNS client");
        Assert.That(resolved, Is.EquivalentTo(new[] { IPAddress.Loopback, IPAddress.IPv6Loopback }),
                    $"'{Host}' is the two loopback addresses");

    }


    [Test]
    [TestCase("localhost6",  TestName = "{m}: localhost6")]
    [TestCase("LocalHost6",  TestName = "{m}: LocalHost6, in another case")]
    public async Task Localhost6_Is_The_IPv6_Loopback_Address_Without_A_DNS_Client(String Host)
    {

        // No RFC: "localhost6" is what a hosts file calls ::1 on many systems,
        // and NameResolution knows it as that. It is no name below
        // "localhost.", so RFC 6761 does not make it the loopback address, and
        // without this branch it would be a host name that needs a DNS client.
        var resolved = await ResolvedOrNull(Host, null);

        Assert.That(resolved, Is.Not.Null, $"'{Host}' needs no DNS client");
        Assert.That(resolved, Is.EqualTo(new[] { IPAddress.IPv6Loopback }),
                    $"'{Host}' is the IPv6 loopback address alone");

    }

    #endregion


    #region A host name is asked of the DNS client, with recursion desired

    [Test]
    [Property("RFC", "1034 §4.3.1, §5.3.1")]
    public async Task A_Host_Name_Is_Asked_With_Recursion_Desired()
    {

        // NameResolution is a stub resolver in the sense of RFC 1034 §5.3.1:
        // all it needs "is a list of name server addresses that will perform
        // the recursive requests". §4.3.1: "the name server should never
        // perform recursive service unless asked via RD". A query without it
        // asks the server only for what it holds itself.
        await using var server  = AnswerA();
        using       var client  = ClientOf(server);

        var resolved  = await ResolvedOrNull("host.example", client);
        var queries   = server.Requests.Select(request => RawDnsReader.Parse(request)).ToArray();

        Assert.Multiple(() => {

            Assert.That(resolved, Is.EqualTo(new[] { IPAddress.Parse("192.0.2.61") }),
                        "the address the server named is the host's");

            Assert.That(queries, Is.Not.Empty,
                        "and the server was asked");

            Assert.That(queries.Select(query => query.RD), Is.All.True,
                        "§4.3.1: every query asks for recursion");

        });

    }


    [Test]
    [Property("RFC", "1034 §4.3.1")]
    public async Task A_Host_Name_Without_An_Address_Is_Refused()
    {

        // NameResolution documents its exception for "one it found no address
        // for": an empty list would be a host with nowhere to connect to,
        // handed to a caller that assumes there is somewhere.
        await using var server  = AnswerA();
        using       var client  = ClientOf(server);

        var resolved  = await ResolvedOrNull("empty.example", client);
        var sent      = server.Requests.Count;

        Assert.Multiple(() => {

            Assert.That(resolved, Is.Null,
                        "a name its server named no address for is refused");

            Assert.That(sent, Is.Positive,
                        "after the server was asked");

        });

    }

    #endregion


    #region The HTTP handler connects where NameResolution resolved, and nowhere else

    [Test]
    public async Task The_Handler_Connects_To_An_Allowed_Address_And_Not_To_Another()
    {

        // AllowAddress decides which of the resolved addresses may be connected
        // to. Where it allows none, the request fails before a connection is
        // made; where it allows one, the connection is made to it.
        using var target = Listening();

        try
        {

            using (var refused = new HttpClient(NameResolution.HTTPHandler(null, _ => false)))
            {
                Assert.That(async () => await refused.GetStringAsync($"http://127.0.0.1:{PortOf(target)}/"),
                            Throws.InstanceOf<HttpRequestException>(),
                            "no address allowed: no connection, and the request fails");
            }

            Assert.That(target.Pending(), Is.False, "and nothing reached the host");

            using var allowed  = new HttpClient(NameResolution.HTTPHandler(null, address => IPAddress.IsLoopback(address)));
            var       get      = allowed.GetStringAsync($"http://127.0.0.1:{PortOf(target)}/");

            using var peer     = await target.AcceptTcpClientAsync().WaitAsync(Timeout);
            var       stream   = peer.GetStream();

            await ReadHead(stream);
            await stream.WriteAsync(OK);

            Assert.That(await get.WaitAsync(Timeout), Is.EqualTo("ok"),
                        "the address allowed is connected to, and the answer read");

        }
        finally
        {
            target.Stop();
        }

    }


    [Test]
    public async Task Disposing_The_Handler_Closes_Its_Connections()
    {

        // The handler's connections are sockets NameResolution opened, so they
        // are its to close: disposing the client that owns the handler closes
        // the idle connection, and the host reads the end of it. A stream that
        // did not own its socket would leave it open until a finalizer ran.
        using var target = Listening();

        try
        {

            var       http     = new HttpClient(NameResolution.HTTPHandler(null));
            var       get      = http.GetStringAsync($"http://127.0.0.1:{PortOf(target)}/");

            using var peer     = await target.AcceptTcpClientAsync().WaitAsync(Timeout);
            var       stream   = peer.GetStream();

            await ReadHead(stream);
            await stream.WriteAsync(OK);

            Assert.That(await get.WaitAsync(Timeout), Is.EqualTo("ok"), "the request was answered");

            http.Dispose();

            var read      = stream.ReadAsync(new Byte[1]).AsTask();
            var finished  = await Task.WhenAny(read, Task.Delay(Timeout));

            Assert.That(finished, Is.SameAs(read),
                        "disposing the client closes the connection");

            Assert.That(await read, Is.Zero,
                        "and the host reads its end");

        }
        finally
        {
            target.Stop();
        }

    }


    [Test]
    [NonParallelizable]
    public async Task The_Handler_Goes_Through_No_Proxy()
    {

        // NameResolution's handler "goes through no proxy - which one, and how
        // its own name would be looked up, would be the system's to say". A
        // proxy is set as the process's default here, where any handler that
        // uses one would find it, and the control proves that one does.
        using var target  = Listening();
        using var proxy   = Listening();

        var saved = HttpClient.DefaultProxy;

        try
        {

            HttpClient.DefaultProxy = new WebProxy($"http://127.0.0.1:{PortOf(proxy)}/");

            // The control: a handler that uses the default proxy sends its
            // request there, in the absolute form a proxy is sent.
            using (var viaProxy = new HttpClient(new SocketsHttpHandler { UseProxy = true }))
            {

                var       get     = viaProxy.GetStringAsync($"http://127.0.0.1:{PortOf(target)}/control");
                using var peer    = await proxy.AcceptTcpClientAsync().WaitAsync(Timeout);
                var       stream  = peer.GetStream();
                var       head    = await ReadHead(stream);

                Assert.That(head, Does.StartWith($"GET http://127.0.0.1:{PortOf(target)}/control "),
                            "control: a handler that uses the default proxy sends its request to it");

                await stream.WriteAsync(OK);
                await get.WaitAsync(Timeout);

            }

            using var http          = new HttpClient(NameResolution.HTTPHandler(null));
            var       request       = http.GetStringAsync($"http://127.0.0.1:{PortOf(target)}/");
            var       toTarget      = target.AcceptTcpClientAsync();
            var       toProxy       = proxy. AcceptTcpClientAsync();
            var       first         = await Task.WhenAny(toTarget, toProxy, Task.Delay(Timeout));

            Assert.That(first, Is.SameAs(toTarget),
                        "NameResolution's handler connects to the host, and not to the proxy");

            using var peerOfTarget  = await toTarget;
            var       targetStream  = peerOfTarget.GetStream();

            await ReadHead(targetStream);
            await targetStream.WriteAsync(OK);

            Assert.That(await request.WaitAsync(Timeout), Is.EqualTo("ok"));

        }
        finally
        {
            HttpClient.DefaultProxy = saved;
            target.Stop();
            proxy. Stop();
        }

    }

    #endregion

}

using System.Net;
using System.Net.Sockets;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

using IPAddress = System.Net.IPAddress;

namespace DNSConformance.Client.Tests;

/// <summary>
/// The connection behind every stream transport: which of a resolver's
/// addresses a client dials, and what it does when the first one does not
/// answer (RFC 8305 §4, §5, "Happy Eyeballs Version 2").
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ResolutionDelayTests"/> covers the first of RFC 8305's phases,
/// the lookup of the addresses. This file covers the two after it. §4: "the
/// client MUST sort the addresses received up to this point using Destination
/// Address Selection ([RFC6724], Section 6)", and then "SHOULD modify the
/// ordered list to interleave address families". §5: "one connection attempt
/// to a single address is started first, followed by the others in the list,
/// one at a time."
/// </para>
/// <para>
/// A client that dials one address and gives up when it fails has a resolver
/// with addresses of both families only as reachable as the family it picked.
/// The nightly's public resolver tests showed what that costs: dns.google and
/// cloudflare-dns.com have both, the GitHub runners have no IPv6 route, and
/// every DoH query there failed in a few milliseconds as SERVFAIL.
/// </para>
/// <para>
/// One host has two loopbacks, 127.0.0.1 and ::1, and a port can be open on
/// one of them and closed on the other. A closed port refuses a connect at
/// once, which is how "Network is unreachable" fails on a host without an IPv6
/// route: the attempt is over before any delay runs out. Whether a client
/// starts the next attempt after a delay, without waiting for the first to
/// fail, needs an attempt that hangs, and a loopback has none to offer; that
/// part of §5 is not tested here.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "8305 §4, §5")]
public class ConnectionAttemptTests
{

    #region Data

    private static readonly TimeSpan        Timeout  = TimeSpan.FromSeconds(8);

    private static readonly DNSServiceName  Asked    = DNSServiceName.Parse("attempt.example.");

    /// <summary>A name the scripted resolver gives one address of each family: both loopbacks.</summary>
    private const           String          Dual     = "dual.attempts.test";

    private static readonly Byte[]          Answer   = [ 192, 0, 2, 13 ];


    private static Byte[] OneAddress(Byte[] Request)
        => RawDnsResponder.Answer(Request, ($"{RawDnsReader.Parse(Request).Questions[0].Name.Canonical}.", RawDnsType.A, 60, Answer));


    /// <summary>
    /// A resolver for <see cref="Dual"/>: A 127.0.0.1 and AAAA ::1, the
    /// type that was asked for, as a dual-stack DoH or DoT server publishes them.
    /// </summary>
    private static ScriptedUdpServer DualStackResolver()

        => new (request => {

               var question = RawDnsReader.Parse(request).Questions[0];
               var name     = $"{question.Name.Canonical}.";

               return question.Type switch {
                   RawDnsType.A     => RawDnsResponder.Answer(request, (name, RawDnsType.A,    60, [ 127, 0, 0, 1 ])),
                   RawDnsType.AAAA  => RawDnsResponder.Answer(request, (name, RawDnsType.AAAA, 60, [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 ])),
                   _                => RawDnsResponder.Answer(request)
               };

           });


    private static DNSClient ClientOf(ScriptedUdpServer Resolver)
        => new (IPv4Address.Localhost,
                IPPort.Parse((UInt16) Resolver.Port),
                QueryTimeout: Timeout);


    /// <summary>
    /// A port that is free on both loopbacks, so that a peer can take it on one
    /// of them and the other one refuses it.
    /// </summary>
    private static Int32 PortFreeOnBothLoopbacks()
    {

        for (var attempt = 0; attempt < 50; attempt++)
        {

            var ipv4 = new TcpListener(IPAddress.Loopback, 0);
            ipv4.Start();
            var port = ((IPEndPoint) ipv4.LocalEndpoint).Port;

            try
            {
                var ipv6 = new TcpListener(IPAddress.IPv6Loopback, port);
                ipv6.Start();
                ipv6.Stop();
                return port;
            }
            catch (SocketException)
            { }
            finally
            {
                ipv4.Stop();
            }

        }

        throw new InvalidOperationException("No port was free on both loopbacks.");

    }


    /// <summary>
    /// Whether a connect to the address and port is refused. The positive
    /// control of every test here: the address the client must get past is
    /// one it cannot get through.
    /// </summary>
    private static async Task<Boolean> Refuses(IPAddress Address, Int32 Port)
    {

        using var socket = new Socket(Address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

        try
        {
            await socket.ConnectAsync(new IPEndPoint(Address, Port)).WaitAsync(Timeout);
            return false;
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return true;
        }

    }


    /// <summary>
    /// A peer on one loopback address alone, answering every connection with
    /// the handler it is given, and counting the connections that reached it.
    /// </summary>
    private sealed class LoopbackPeer : IAsyncDisposable
    {

        private readonly TcpListener              listener;
        private readonly CancellationTokenSource  cts = new();
        private readonly Task                     loop;
        private          Int32                    connections;

        public  Int32  Port         { get; }
        public  Int32  Connections  => Volatile.Read(ref connections);

        public LoopbackPeer(IPAddress Address, Int32 Port, Func<NetworkStream, CancellationToken, Task> Handler)
        {

            listener  = new TcpListener(Address, Port);
            listener.Start();

            this.Port = ((IPEndPoint) listener.LocalEndpoint).Port;

            loop      = Task.Run(async () => {
                            while (!cts.IsCancellationRequested)
                            {
                                TcpClient client;
                                try
                                {
                                    client = await listener.AcceptTcpClientAsync(cts.Token);
                                }
                                catch
                                {
                                    return;
                                }
                                Interlocked.Increment(ref connections);
                                _ = Task.Run(async () => {
                                        using (client)
                                        {
                                            try
                                            {
                                                await Handler(client.GetStream(), cts.Token);
                                            }
                                            catch
                                            { }
                                        }
                                    });
                            }
                        });

        }

        public async ValueTask DisposeAsync()
        {
            cts.Cancel();
            listener.Stop();
            try { await loop; } catch { }
            cts.Dispose();
        }

    }


    /// <summary>DNS over TCP (RFC 1035 §4.2.2): every framed query is answered with one A record.</summary>
    private static async Task DnsOverTcp(NetworkStream Stream, CancellationToken Token)
    {

        var length = new Byte[2];

        while (await Stream.ReadAtLeastAsync(length, 2, throwOnEndOfStream: false, Token) == 2)
        {

            var query    = new Byte[(length[0] << 8) | length[1]];
            await Stream.ReadExactlyAsync(query, Token);

            var response = OneAddress(query);
            await Stream.WriteAsync(new Byte[] { (Byte) (response.Length >> 8), (Byte) response.Length }, Token);
            await Stream.WriteAsync(response, Token);

        }

    }


    /// <summary>
    /// DNS over HTTP/1.1 (RFC 8484 §4.1), POST alone: the body is the query,
    /// and the answer goes back as application/dns-message on a connection
    /// that is closed after it.
    /// </summary>
    private static async Task DohPost(NetworkStream Stream, CancellationToken Token)
    {

        var head   = new List<Byte>();
        var one    = new Byte[1];

        while (!(head.Count >= 4 && head[^4] == '\r' && head[^3] == '\n' && head[^2] == '\r' && head[^1] == '\n'))
        {
            if (await Stream.ReadAsync(one, Token) == 0)
                return;
            head.Add(one[0]);
        }

        var contentLength = Encoding.ASCII.GetString(head.ToArray()).
                                Split("\r\n").
                                Where (line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)).
                                Select(line => Int32.Parse(line["Content-Length:".Length..].Trim())).
                                FirstOrDefault();

        var query    = new Byte[contentLength];
        await Stream.ReadExactlyAsync(query, Token);

        var response = OneAddress(query);

        await Stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\n" +
                                                        $"Content-Type: application/dns-message\r\n" +
                                                        $"Content-Length: {response.Length}\r\n" +
                                                        $"Connection: close\r\n\r\n"), Token);
        await Stream.WriteAsync(response, Token);

    }


    private static Boolean Answered(DNSInfo Info)
        => Info.Answers.OfType<A>().Any(record => record.IPv4Address.Equals(IPv4Address.Parse("192.0.2.13")));

    #endregion


    #region By address: this machine, both loopbacks

    // IPvXAddress.Localhost - what the port-only constructors connect to - is
    // both loopback addresses to Hermod's connect, as a host name with an A and
    // an AAAA record is. The preference picks the first to dial; the other one
    // is the address to go on to.

    [Test]
    public async Task A_Client_Preferring_IPv6_Goes_On_To_IPv4_When_IPv6_Is_Refused()
    {

        var port = PortFreeOnBothLoopbacks();

        await using var peer   = new LoopbackPeer(IPAddress.Loopback, port, DnsOverTcp);
        await using var client = new DNSTCPClient(IPvXAddress.Localhost,
                                                  IPPort.Parse((UInt16) port),
                                                  QueryTimeout:    Timeout,
                                                  PreferIPv4:      IPVersionPreference.PreferIPv6,
                                                  ConnectTimeout:  Timeout);

        Assert.That(await Refuses(IPAddress.IPv6Loopback, port), Is.True, "[::1] refuses the port the peer listens on at 127.0.0.1");

        var info = await client.Query(Asked, [ DNSResourceRecordTypes.A ], Timeout);

        Assert.Multiple(() => {
            Assert.That(peer.Connections, Is.GreaterThanOrEqualTo(1), "after [::1] refused, the client went on to 127.0.0.1");
            Assert.That(Answered(info),   Is.True,                    "and the question was answered there");
        });

    }


    [Test]
    public async Task A_Client_Preferring_IPv4_Goes_On_To_IPv6_When_IPv4_Is_Refused()
    {

        var port = PortFreeOnBothLoopbacks();

        await using var peer   = new LoopbackPeer(IPAddress.IPv6Loopback, port, DnsOverTcp);
        await using var client = new DNSTCPClient(IPvXAddress.Localhost,
                                                  IPPort.Parse((UInt16) port),
                                                  QueryTimeout:    Timeout,
                                                  PreferIPv4:      IPVersionPreference.PreferIPv4,
                                                  ConnectTimeout:  Timeout);

        Assert.That(await Refuses(IPAddress.Loopback, port), Is.True, "127.0.0.1 refuses the port the peer listens on at [::1]");

        var info = await client.Query(Asked, [ DNSResourceRecordTypes.A ], Timeout);

        Assert.Multiple(() => {
            Assert.That(peer.Connections, Is.GreaterThanOrEqualTo(1), "after 127.0.0.1 refused, the client went on to [::1]");
            Assert.That(Answered(info),   Is.True,                    "and the question was answered there");
        });

    }


    [Test]
    public async Task A_Client_Naming_No_Preference_Goes_On_To_IPv4_When_IPv6_Is_Refused()
    {

        // The default, which every caller gets who says nothing: PreferIPv6,
        // as RFC 8305 §2 assumes. EncryptedClientConstructionTests sets
        // PreferIPv4 on its port-only DoH client for exactly this reason - "the
        // constructor dials [::1] unless told otherwise".
        var port = PortFreeOnBothLoopbacks();

        await using var peer   = new LoopbackPeer(IPAddress.Loopback, port, DnsOverTcp);
        await using var client = new DNSTCPClient(IPvXAddress.Localhost,
                                                  IPPort.Parse((UInt16) port),
                                                  QueryTimeout:    Timeout,
                                                  ConnectTimeout:  Timeout);

        Assert.That(await Refuses(IPAddress.IPv6Loopback, port), Is.True, "[::1] refuses the port the peer listens on at 127.0.0.1");

        var info = await client.Query(Asked, [ DNSResourceRecordTypes.A ], Timeout);

        Assert.Multiple(() => {
            Assert.That(peer.Connections, Is.GreaterThanOrEqualTo(1), "after [::1] refused, the client went on to 127.0.0.1");
            Assert.That(Answered(info),   Is.True,                    "and the question was answered there");
        });

    }

    #endregion

    #region By name: a resolver published with an A and an AAAA record

    [Test]
    public async Task A_Doh_Client_Reaches_A_Dual_Stack_Resolver_Over_IPv4_When_IPv6_Is_Refused()
    {

        // The nightly's case offline: a DoH resolver with an address of each
        // family, and a host on which IPv6 does not get through.
        var port = PortFreeOnBothLoopbacks();

        await using var resolver = DualStackResolver();
        using       var dns      = ClientOf(resolver);
        await using var peer     = new LoopbackPeer(IPAddress.Loopback, port, DohPost);
        await using var client   = new DNSHTTPSClient(URL.Parse($"http://{Dual}:{port}/dns-query"),
                                                      Mode:            DNSHTTPSMode.POST,
                                                      QueryTimeout:    Timeout,
                                                      ConnectTimeout:  Timeout,
                                                      DNSClient:       dns);

        Assert.That(await Refuses(IPAddress.IPv6Loopback, port), Is.True, "[::1] refuses the port the peer listens on at 127.0.0.1");

        var info = await client.Query(Asked, [ DNSResourceRecordTypes.A ], Timeout);

        Assert.Multiple(() => {
            Assert.That(peer.Connections, Is.GreaterThanOrEqualTo(1), $"after [::1] refused, the client went on to 127.0.0.1, the A record of {Dual}");
            Assert.That(Answered(info),   Is.True,                    "and the question was answered there");
        });

    }


    [Test]
    public async Task A_Dot_Client_Reaches_A_Dual_Stack_Resolver_Over_IPv4_When_IPv6_Is_Refused()
    {

        // The same over TLS. ScriptedTlsServer listens on 127.0.0.1 alone.
        await using var resolver = DualStackResolver();
        using       var dns      = ClientOf(resolver);
        await using var server   = new ScriptedTlsServer(OneAddress);
        await using var client   = new DNSTLSClient(URL.Parse($"tls://{Dual}:{server.Port}"),
                                                    QueryTimeout:                Timeout,
                                                    RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success(),
                                                    ConnectTimeout:              Timeout,
                                                    DNSClient:                   dns);

        Assert.That(await Refuses(IPAddress.IPv6Loopback, server.Port), Is.True, "[::1] refuses the port the server listens on at 127.0.0.1");

        var info = await client.Query(Asked, [ DNSResourceRecordTypes.A ], Timeout);

        Assert.Multiple(() => {
            Assert.That(server.HandshakeCount, Is.GreaterThanOrEqualTo(1), $"after [::1] refused, the client went on to 127.0.0.1, the A record of {Dual}");
            Assert.That(Answered(info),        Is.True,                    "and the question was answered there");
        });

    }

    #endregion

    #region Guards: the preferred family first, one attempt at a time, and "only" means only

    [TestCase(IPVersionPreference.PreferIPv6, true,  TestName = "With both loopbacks open, a client preferring IPv6 dials IPv6 alone")]
    [TestCase(IPVersionPreference.PreferIPv4, false, TestName = "With both loopbacks open, a client preferring IPv4 dials IPv4 alone")]
    public async Task The_Preferred_Family_Is_Dialled_And_Nothing_Beside_It(IPVersionPreference Preference, Boolean IPv6First)
    {

        // RFC 8305 §5: "connection attempts SHOULD NOT be made simultaneously",
        // and once one succeeds, "Any address that was not yet attempted as a
        // connection SHOULD be ignored". A fix that raced both families at once,
        // or tried them in the wrong order, would reach both peers or the wrong
        // one. Passes as it is, and must go on passing.
        var port = PortFreeOnBothLoopbacks();

        await using var ipv4   = new LoopbackPeer(IPAddress.Loopback,     port, DnsOverTcp);
        await using var ipv6   = new LoopbackPeer(IPAddress.IPv6Loopback, port, DnsOverTcp);
        await using var client = new DNSTCPClient(IPvXAddress.Localhost,
                                                  IPPort.Parse((UInt16) port),
                                                  QueryTimeout:    Timeout,
                                                  PreferIPv4:      Preference,
                                                  ConnectTimeout:  Timeout);

        var info = await client.Query(Asked, [ DNSResourceRecordTypes.A ], Timeout);

        // The peer that was not dialled is given a moment, in case an attempt
        // to it is under way.
        await Task.Delay(TimeSpan.FromMilliseconds(500));

        Assert.Multiple(() => {
            Assert.That(Answered(info),                                  Is.True,             "the question was answered");
            Assert.That((IPv6First ? ipv6 : ipv4).Connections,           Is.GreaterThanOrEqualTo(1), "by the preferred family");
            Assert.That((IPv6First ? ipv4 : ipv6).Connections,           Is.EqualTo(0),       "and the other family was never dialled");
        });

    }


    [TestCase(IPVersionPreference.IPv4Only, TestName = "A client told IPv4 only never dials IPv6, even when IPv4 is refused")]
    [TestCase(IPVersionPreference.IPv6Only, TestName = "A client told IPv6 only never dials IPv4, even when IPv6 is refused")]
    public async Task Only_Means_Only(IPVersionPreference Only)
    {

        // The other side of going on: a family the caller ruled out is no
        // address to go on to. Passes as it is, and must go on passing.
        var port         = PortFreeOnBothLoopbacks();
        var ruledOut     = Only == IPVersionPreference.IPv4Only ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        var allowed      = Only == IPVersionPreference.IPv4Only ? IPAddress.Loopback     : IPAddress.IPv6Loopback;
        var otherOnly    = Only == IPVersionPreference.IPv4Only ? IPVersionPreference.IPv6Only : IPVersionPreference.IPv4Only;

        await using var peer = new LoopbackPeer(ruledOut, port, DnsOverTcp);

        Assert.That(await Refuses(allowed, port), Is.True, $"{allowed} refuses the port the peer listens on at {ruledOut}");

        await using (var client = new DNSTCPClient(IPvXAddress.Localhost,
                                                   IPPort.Parse((UInt16) port),
                                                   QueryTimeout:    TimeSpan.FromSeconds(3),
                                                   PreferIPv4:      Only,
                                                   ConnectTimeout:  TimeSpan.FromSeconds(3)))
        {

            var info = await client.Query(Asked, [ DNSResourceRecordTypes.A ], TimeSpan.FromSeconds(3));

            Assert.Multiple(() => {
                Assert.That(peer.Connections, Is.EqualTo(0), $"{ruledOut} was never dialled");
                Assert.That(Answered(info),   Is.False,      "so there was no answer");
            });

        }

        // The positive control: the peer can be reached, by a client that may.
        await using (var control = new DNSTCPClient(IPvXAddress.Localhost,
                                                    IPPort.Parse((UInt16) port),
                                                    QueryTimeout:    Timeout,
                                                    PreferIPv4:      otherOnly,
                                                    ConnectTimeout:  Timeout))
        {

            var info = await control.Query(Asked, [ DNSResourceRecordTypes.A ], Timeout);

            Assert.That(Answered(info), Is.True, $"a client told {otherOnly} reaches the peer at {ruledOut}");

        }

    }

    #endregion

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Server.Tests;

/// <summary>
/// A server told to listen on the wildcard has to be reachable over both address
/// families, and each request has to keep the family it arrived on.
/// </summary>
/// <remarks>
/// <para>
/// No RFC requires this — it is what "any" means to the person configuring it.
/// The default bind address is the wildcard and resolves to <c>[::]</c>, and a
/// socket bound there does not answer on 127.0.0.1: measured as a full query
/// timeout, not a refusal. So a server started with default options was
/// reachable over IPv6 only, and nothing noticed, because every fixture in this
/// suite binds IPv4 explicitly and never uses the default.
/// </para>
/// <para>
/// The one-line alternative was a dual-mode socket, and it is rejected here for
/// a reason worth keeping: a dual-mode socket hands every IPv4 client to the
/// application as <c>::ffff:a.b.c.d</c>, and RFC 7873 §5.2.1 derives the server
/// cookie from the client's IP address. Changing what that address looks like
/// would invalidate every cookie an IPv4 client holds, inside a mechanism whose
/// entire job is to be hard to forge.
/// </para>
/// </remarks>
[TestFixture]
public class DualStackListenerTests
{

    #region Data

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromSeconds(3);

    private static async Task<DNSServer> StartOn(IIPAddress BindAddress)
    {

        var server = new DNSServer(
                         new AuthoritativeDNSRequestHandler(ZoneFixtures.CreateStandardZone()),
                         new DNSServerOptions {
                             EnableUDPUnicast    = true,
                             UDPUnicastSocket    = new IPSocket(BindAddress, IPPort.Zero),
                             EnableUDPMulticast  = false,
                             EnableTCPUnicast    = false,
                             EnableTLSUnicast    = false
                         }
                     );

        await server.Start();

        return server;

    }

    /// <summary>
    /// Whether the server answered at all. REFUSED is an answer — the fixture
    /// zone is not authoritative for this name, and RFC 1035 §4.1.1 with
    /// RFC 8020 makes refusing the right reply. Silence is what a listener that
    /// is not there produces, and it costs the whole timeout.
    /// </summary>
    private static async Task<Boolean> Answers(IIPAddress Address, UInt16 Port)
    {

        await using var client = new DNSUDPClient(
                                     Address,
                                     IPPort.Parse(Port),
                                     QueryTimeout: ShortTimeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("a.example.org."), ShortTimeout);

        return response.IsValid;

    }

    #endregion

    #region The_Wildcard_Answers_On_Both_Families()

    [Test]
    public async Task The_Wildcard_Answers_On_Both_Families()
    {

        var server = await StartOn(IPvXAddress.Any);

        try
        {

            var port = server.ActiveUDPUnicastSocket?.Port.ToUInt16() ?? 0;

            Assert.That(port, Is.Not.Zero, "the listener has to have come up at all");

            // Not Assert.Multiple with an async lambda: that compiles to async
            // void, so the assertions escape the scope and nothing waits for
            // them. Awaited first, asserted second.
            var overIPv4 = await Answers(IPv4Address.Localhost,    port);
            var overIPv6 = await Answers(IPv6Address.Parse("::1"), port);

            Assert.Multiple(() => {

                Assert.That(overIPv4, Is.True, "a server on the wildcard must answer on 127.0.0.1");
                Assert.That(overIPv6, Is.True, "and on ::1");

            });

        }
        finally
        {
            await server.Stop();
        }

    }

    #endregion

    #region Both_Families_Answer_On_The_Same_Port()

    [Test]
    public async Task Both_Families_Answer_On_The_Same_Port()
    {

        // Not a detail. A client that truncates over UDP retries over TCP at the
        // same endpoint (RFC 7766 §5), and a resolver that found the server on
        // one port over IPv4 has no reason to look for another over IPv6. Two
        // listeners on two ephemeral ports would be two servers.
        var server = await StartOn(IPvXAddress.Any);

        try
        {

            var port = server.ActiveUDPUnicastSocket?.Port.ToUInt16() ?? 0;

            Assert.That(await Answers(IPv4Address.Localhost,   port), Is.True);
            Assert.That(await Answers(IPv6Address.Parse("::1"), port), Is.True);

        }
        finally
        {
            await server.Stop();
        }

    }

    #endregion

    #region An_Explicit_Address_Is_Not_Split()

    [Test]
    [TestCase("ipv4")]
    [TestCase("ipv6")]
    public async Task An_Explicit_Address_Is_Not_Split(String Family)
    {

        // The other half of the rule, and the one that keeps the fix from being
        // "always bind everything": an operator who names 127.0.0.1 has said
        // something, and binding ::1 as well would be answering on an address
        // they did not ask for.
        IIPAddress bind  = Family == "ipv4" ? IPv4Address.Localhost : IPv6Address.Parse("::1");
        IIPAddress other = Family == "ipv4" ? IPv6Address.Parse("::1") : IPv4Address.Localhost;

        var server = await StartOn(bind);

        try
        {

            var port = server.ActiveUDPUnicastSocket?.Port.ToUInt16() ?? 0;

            var onTheNamedOne = await Answers(bind,  port);
            var onTheOtherOne = await Answers(other, port);

            Assert.Multiple(() => {

                Assert.That(onTheNamedOne, Is.True,  "the address that was asked for answers");
                Assert.That(onTheOtherOne, Is.False, "and the one that was not, does not");

            });

        }
        finally
        {
            await server.Stop();
        }

    }

    #endregion

    #region Tcp_Answers_On_Both_Families_Too()

    [Test]
    public async Task Tcp_Answers_On_Both_Families_Too()
    {

        // A server answering UDP on both families and TCP on one is worse than
        // answering on one everywhere: RFC 7766 §5 sends a client whose answer
        // was truncated to TCP *at the same endpoint*, so the fallback would
        // vanish for exactly half the clients, and only for the answers too big
        // to fit in a datagram.
        var server = new DNSServer(
                         new AuthoritativeDNSRequestHandler(ZoneFixtures.CreateStandardZone()),
                         new DNSServerOptions {
                             EnableUDPUnicast    = false,
                             EnableUDPMulticast  = false,
                             EnableTCPUnicast    = true,
                             TCPUnicastSocket    = new IPSocket(IPvXAddress.Any, IPPort.Zero),
                             EnableTLSUnicast    = false
                         }
                     );

        await server.Start();

        try
        {

            var port = server.ActiveTCPUnicastSocket?.Port.ToUInt16() ?? 0;

            Assert.That(port, Is.Not.Zero);

            var overIPv4 = await AnswersOverTcp(IPv4Address.Localhost,    port);
            var overIPv6 = await AnswersOverTcp(IPv6Address.Parse("::1"), port);

            Assert.Multiple(() => {
                Assert.That(overIPv4, Is.True, "TCP on 127.0.0.1");
                Assert.That(overIPv6, Is.True, "and TCP on ::1");
            });

        }
        finally
        {
            await server.Stop();
        }

    }

    private static async Task<Boolean> AnswersOverTcp(IIPAddress Address, UInt16 Port)
    {

        await using var client = new DNSTCPClient(
                                     Address,
                                     IPPort.Parse(Port),
                                     QueryTimeout: ShortTimeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("a.example.org."), ShortTimeout);

        return response.IsValid;

    }

    #endregion

    #region A_Taken_Port_In_One_Family_Is_Not_Served_As_Half()

    [Test]
    public async Task A_Taken_Port_In_One_Family_Is_Not_Served_As_Half()
    {

        // The failure mode this whole change exists to remove, in its second
        // shape: the wildcard was asked for, one family cannot be bound, and the
        // tempting thing to write is a warning and a shrug. That produces a
        // server which answers half its clients and looks healthy doing it —
        // which is exactly the state the default bind address used to be in.
        //
        // A system-chosen port is retried with another number instead; a fixed
        // one has nowhere to move to, so it has to be loud.
        using var occupier = new System.Net.Sockets.UdpClient(System.Net.Sockets.AddressFamily.InterNetwork);

        occupier.Client.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Any, 0));

        var takenPort = ((System.Net.IPEndPoint) occupier.Client.LocalEndPoint!).Port;

        var server = new DNSServer(
                         new AuthoritativeDNSRequestHandler(ZoneFixtures.CreateStandardZone()),
                         new DNSServerOptions {
                             EnableUDPUnicast    = true,
                             UDPUnicastSocket    = new IPSocket(IPvXAddress.Any, IPPort.Parse((UInt16) takenPort)),
                             EnableUDPMulticast  = false,
                             EnableTCPUnicast    = false,
                             EnableTLSUnicast    = false
                         }
                     );

        try
        {

            await server.Start();

            // Start() does not wait for the listener task, so the failure
            // surfaces as a listener that never came up rather than as a throw
            // out of Start itself. Either way, what must not happen is a server
            // reporting a healthy IPv6-only listener on a port whose IPv4 half
            // belongs to somebody else.
            await Task.Delay(TimeSpan.FromMilliseconds(500));

            Assert.That(await Answers(IPv6Address.Parse("::1"), (UInt16) takenPort),
                        Is.False,
                        "half a listener is not a listener: the server must not be serving IPv6 " +
                        "on a port it could not take for IPv4");

        }
        finally
        {
            try { await server.Stop(); } catch { }
        }

    }

    #endregion

    #region The_Client_Address_Keeps_Its_Family()

    [Test]
    [Property("RFC", "7873 §5.2.1")]
    public async Task The_Client_Address_Keeps_Its_Family()
    {

        // The whole reason this is two listeners rather than one dual-mode
        // socket — and the assertion that was missing when it was first written.
        // A mutation that turned DualMode back on *survived*: both families
        // still answered, because a second IPv4 listener binds happily beside a
        // dual-mode IPv6 one. Reachability was never what DualMode=false was
        // protecting. What it protects is the address the server sees: a
        // dual-mode socket reports an IPv4 client as ::ffff:127.0.0.1, and
        // RFC 7873 §5.2.1 derives the server cookie from that address.
        //
        // So the address has to be observed, not inferred from a working query.
        var server = new DNSServer(
                         new AuthoritativeDNSRequestHandler(ZoneFixtures.CreateStandardZone()),
                         new DNSServerOptions {
                             EnableUDPUnicast    = true,
                             UDPUnicastSocket    = new IPSocket(IPvXAddress.Any, IPPort.Zero),
                             EnableUDPMulticast  = false,
                             EnableTCPUnicast    = false,
                             EnableTLSUnicast    = false
                         }
                     );

        var seen = new List<IPSocket>();

        server.OnDNSRequestReceived += (timestamp, sender, transport, request, token) => {
            lock (seen)
                seen.Add(request.RemoteSocket);
            return Task.CompletedTask;
        };

        await server.Start();

        try
        {

            var port = server.ActiveUDPUnicastSocket?.Port.ToUInt16() ?? 0;

            Assert.That(await Answers(IPv4Address.Localhost,    port), Is.True);
            Assert.That(await Answers(IPv6Address.Parse("::1"), port), Is.True);

            IPSocket[] observed;
            lock (seen)
                observed = [.. seen];

            Assert.That(observed, Has.Length.EqualTo(2), "both queries have to have been seen");

            var addresses = observed.Select(socket => socket.IPAddress.ToString()).ToArray();

            Assert.Multiple(() => {

                Assert.That(addresses.Any(address => address.Contains("127.0.0.1")), Is.True,
                            $"the IPv4 client must arrive as an IPv4 address: {String.Join(", ", addresses)}");

                Assert.That(addresses.Any(address => address.Contains("ffff:127", StringComparison.OrdinalIgnoreCase) ||
                                                     address.Contains("::ffff:")),
                            Is.False,
                            $"and never as an IPv4-mapped IPv6 one, which is what a dual-mode socket would " +
                            $"report and what would change every cookie it derives: {String.Join(", ", addresses)}");

            });

        }
        finally
        {
            await server.Stop();
        }

    }

    #endregion

}

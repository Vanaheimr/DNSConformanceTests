using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

using IPAddress = System.Net.IPAddress;

namespace DNSConformance.Multicast.Tests;

/// <summary>
/// Multicast DNS over the host's own sockets: Hermod's <see cref="UDPMulticastDNSTransport"/>
/// held to what RFC 6762 asks of the packets a host sends and receives, its §3, §6.7, §11,
/// §14, §15 and §20.
/// </summary>
/// <remarks>
/// <para>
/// Every other multicast test runs over <see cref="InMemoryMulticastDNSNetwork"/>, which
/// hands the responder and the client a datagram together with the verdicts a socket
/// would have produced: the interface, the destination, and whether the source is on the
/// link. Here the socket produces them. The tests need an interface that is up and can
/// multicast, so they are in the <c>Multicast</c> category, and each one says what it
/// lacks when a host does not have it.
/// </para>
/// <para>
/// Each test picks a port of its own, never 5353, so that the host's own Multicast DNS
/// responder neither hears these packets nor answers them. The sender is a plain socket
/// wherever it can be, so that what is sent does not depend on the code under test. The
/// interfaces a test expects are worked out here, from the host's own list of them, and
/// not read back from the transport.
/// </para>
/// <para>
/// What these tests cannot show is a source that is not on the link. Every source a
/// single host can send from is one of its own addresses, on the interface that address
/// belongs to: Windows sends a packet only from the interface its source address is
/// configured on, whatever interface the socket names. So §11's negative half, a
/// response from off the link, needs a second host.
/// </para>
/// </remarks>
[TestFixture]
[Category(TestCategories.Multicast)]
[NonParallelizable]
public sealed class MulticastSocketConformanceTests
{

    #region Harness

    /// <summary>
    /// How long a test waits for a datagram it expects.
    /// </summary>
    private static readonly TimeSpan Patience  = TimeSpan.FromSeconds(2);

    /// <summary>
    /// How long a test waits before it concludes that a datagram it does not expect is
    /// not coming. Every datagram here travels inside one host.
    /// </summary>
    private static readonly TimeSpan Settle    = TimeSpan.FromMilliseconds(300);

    private static readonly IPAddress IPv4Group  = IPAddress.Parse("224.0.0.251");

    private static readonly IPAddress IPv6Group  = IPAddress.Parse("ff02::fb");


    /// <summary>
    /// A port of the test's own, away from 5353 and from the range Hermod's own tests use.
    /// </summary>
    private static IPPort PrivatePort()
        => IPPort.Parse((UInt16) (5600 + Random.Shared.Next(0, 300)));


    /// <summary>
    /// An interface the host reports as up and able to multicast, other than the loopback
    /// interface, with its first IPv4 address and its IPv6 link-local address, where it has them.
    /// </summary>
    private sealed record Link(Int32       Index,
                               String      Name,
                               IPAddress?  IPv4,
                               IPAddress?  IPv6LinkLocal)
    {

        public IPAddress? Address(AddressFamily Family)
            => Family == AddressFamily.InterNetwork ? IPv4 : IPv6LinkLocal;

    }


    private static Link[] Links()
    {

        var links = new List<Link>();

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {

            if (nic.OperationalStatus    != OperationalStatus.Up ||
               !nic.SupportsMulticast                            ||
                nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            var properties  = nic.GetIPProperties();
            var addresses   = properties.UnicastAddresses.Select(unicast => unicast.Address).ToArray();
            var ipv4        = addresses.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork);
            var ipv6        = addresses.FirstOrDefault(address => address.IsIPv6LinkLocal);
            var index       = IndexOf(() => properties.GetIPv4Properties().Index, ipv4) ??
                              IndexOf(() => properties.GetIPv6Properties().Index, ipv6);

            if (index.HasValue)
                links.Add(new Link(index.Value, nic.Name, ipv4, ipv6));

        }

        return [.. links];

    }

    private static Int32? IndexOf(Func<Int32> Index, IPAddress? Address)
    {

        if (Address is null)
            return null;

        try
        {
            return Index();
        }
        catch (Exception)
        {
            return null;
        }

    }


    private static Link[] RequireLinks(AddressFamily  Family,
                                       Int32          AtLeast = 1)
    {

        var links = Links().Where(link => link.Address(Family) is not null).ToArray();

        if (links.Length < AtLeast)
            Assert.Ignore($"This host has {links.Length} interface(s) that are up, can multicast and carry an " +
                          $"{(Family == AddressFamily.InterNetwork ? "IPv4 address" : "IPv6 link-local address")}; " +
                          $"the test needs {AtLeast}.");

        return links;

    }


    /// <summary>
    /// The loopback interface, where the host lets it multicast. Windows does; Linux does not.
    /// </summary>
    private static void RequireMulticastLoopback()
    {

        var loopback = NetworkInterface.GetAllNetworkInterfaces().
                           FirstOrDefault(nic => nic.NetworkInterfaceType == NetworkInterfaceType.Loopback);

        if (loopback is null || loopback.OperationalStatus != OperationalStatus.Up || !loopback.SupportsMulticast)
            Assert.Ignore("The loopback interface of this host does not multicast, so no Multicast DNS transport takes it.");

    }


    private static async Task<UDPMulticastDNSTransport> Started(UDPMulticastDNSTransportOptions Options)
    {
        var transport = new UDPMulticastDNSTransport(Options);
        await transport.StartAsync();
        return transport;
    }


    /// <summary>
    /// A payload no other test sends: a query for a name of its own.
    /// </summary>
    private static Byte[] Marker()
        => RawDnsWriter.Query(0, $"m{Guid.NewGuid():N}.local.", RawDnsType.A, recursionDesired: false);


    private static Boolean IsIPv6(IIPAddress Address)
        => Address.GetBytes().Length == 16;


    /// <summary>
    /// Everything a transport hears.
    /// </summary>
    private sealed class Ear
    {

        private readonly ConcurrentQueue<MulticastDNSDatagram> datagrams = new();

        public Ear(IMulticastDNSTransport Transport)
            => Transport.OnDatagramReceived += (_, _, datagram, _) => {
                   datagrams.Enqueue(datagram);
                   return Task.CompletedTask;
               };

        public MulticastDNSDatagram[] Matching(Func<MulticastDNSDatagram, Boolean> Match)
            => [.. datagrams.Where(Match)];

        public MulticastDNSDatagram[] Carrying(Byte[] Payload)
            => Matching(datagram => datagram.Payload.Span.SequenceEqual(Payload));

        public async Task<MulticastDNSDatagram[]> Await(Func<MulticastDNSDatagram, Boolean>  Match,
                                                       Int32                                Count = 1)
        {

            var deadline = DateTimeOffset.UtcNow + Patience;

            while (true)
            {

                var found = Matching(Match);

                if (found.Length >= Count || DateTimeOffset.UtcNow > deadline)
                    return found;

                await Task.Delay(20);

            }

        }

        public void Clear()
            => datagrams.Clear();

    }


    /// <summary>
    /// Multicast the payload from a plain socket, from the given interface's address of the
    /// given family, to the Multicast DNS group of that family on the given port.
    /// </summary>
    private static async Task MulticastFrom(Link           Link,
                                            AddressFamily  Family,
                                            IPPort         Port,
                                            Byte[]         Payload)
    {

        var source = Link.Address(Family)!;

        using var socket = new Socket(Family, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(source, 0));

        IPAddress group;

        if (Family == AddressFamily.InterNetwork)
        {
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, source.GetAddressBytes());
            group = IPv4Group;
        }
        else
        {
            socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, Link.Index);
            group = new IPAddress(IPv6Group.GetAddressBytes(), Link.Index);
        }

        await socket.SendToAsync(Payload, SocketFlags.None, new IPEndPoint(group, Port.ToInt32()));

    }


    private static async Task UnicastFrom(IPAddress  Source,
                                          IPAddress  Destination,
                                          IPPort     Port,
                                          Byte[]     Payload)
    {

        using var socket = new Socket(Source.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(Source, 0));

        await socket.SendToAsync(Payload, SocketFlags.None, new IPEndPoint(Destination, Port.ToInt32()));

    }


    /// <summary>
    /// A responder with every delay of its own removed, the rate limit of §6 included: these
    /// tests are about where its packets go, not when.
    /// </summary>
    private static MulticastDNSResponderOptions Quick()

        => new () {
               ProbeInterval               = TimeSpan.FromMilliseconds(5),
               MaxInitialProbeDelay        = TimeSpan.Zero,
               AnnouncementInterval        = TimeSpan.FromMilliseconds(5),
               MinSharedResponseDelay      = TimeSpan.Zero,
               MaxSharedResponseDelay      = TimeSpan.Zero,
               MinRecordMulticastInterval  = TimeSpan.Zero
           };


    private static String HostName()
        => $"socket-{Guid.NewGuid():N}"[..19] + ".local.";


    private static RawDnsMessage? Read(ReadOnlyMemory<Byte> Payload)
    {
        try
        {
            return RawDnsReader.Parse(Payload.ToArray());
        }
        catch (Exception)
        {
            return null;
        }
    }


    private static Boolean AnswersFor(MulticastDNSDatagram Datagram, String Host)
        => Read(Datagram.Payload) is { QR: true } message &&
           message.Answers.Any(record => record.Type == RawDnsType.A &&
                                         record.Name.Canonical == Host.TrimEnd('.').ToLowerInvariant());

    #endregion


    #region Hearing the groups (RFC 6762 §3, §11)

    [TestCase(AddressFamily.InterNetwork,   TestName = "A multicast to 224.0.0.251 is heard on every interface that is up")]
    [TestCase(AddressFamily.InterNetworkV6, TestName = "A multicast to FF02::FB is heard on every interface that is up")]
    [Property("RFC", "6762 §3, §11")]
    public async Task A_Multicast_To_The_Group_Is_Heard_On_Every_Interface_That_Is_Up(AddressFamily Family)
    {

        // §3: "Any DNS query for a name ending with ".local." MUST be sent to the mDNS IPv4
        // link-local multicast address 224.0.0.251 (or its IPv6 equivalent FF02::FB)." A
        // transport left at its defaults is there to hear them, on every link the host is on.
        var links      = RequireLinks(Family);
        var port       = PrivatePort();

        await using var transport = await Started(new () { Port = port });
        var ear        = new Ear(transport);

        foreach (var link in links)
        {

            var payload   = Marker();
            await MulticastFrom(link, Family, port, payload);

            var heard     = (await ear.Await(datagram => datagram.Payload.Span.SequenceEqual(payload))).FirstOrDefault();

            Assert.That(heard, Is.Not.Null,
                        $"the multicast sent on {link.Name} from {link.Address(Family)} was not heard");

            Assert.Multiple(() => {

                Assert.That(heard!.InterfaceIndex, Is.EqualTo(link.Index),
                            $"the multicast sent on {link.Name} was reported as received on another interface");

                Assert.That(heard.DestinationAddress?.GetBytes(),
                            Is.EqualTo((Family == AddressFamily.InterNetwork ? IPv4Group : IPv6Group).GetAddressBytes()),
                            "the destination of the IP header is the group");

                Assert.That(heard.SourceIsOnLocalLink, Is.True,
                            "§11: responses to the group \"are necessarily deemed to have originated on the " +
                            "local link, regardless of source IP address\"");

            });

        }

    }

    #endregion

    #region More than one Multicast DNS socket on a host (RFC 6762 §15, §20)

    [TestCase(AddressFamily.InterNetwork,   TestName = "Two transports on one port each hear what the other multicasts, over IPv4")]
    [TestCase(AddressFamily.InterNetworkV6, TestName = "Two transports on one port each hear what the other multicasts, over IPv6")]
    [Property("RFC", "6762 §15, §15.1")]
    public async Task Two_Transports_On_One_Port_Each_Hear_What_The_Other_Multicasts(AddressFamily Family)
    {

        // §15.1: "all Multicast DNS implementations SHOULD use the SO_REUSEPORT and/or
        // SO_REUSEADDR options (or equivalent as appropriate for the operating system in
        // question) so they will all be able to bind to UDP port 5353 and receive incoming
        // multicast packets addressed to that port." And §15: more than one responder or
        // querier may "coexist on the same machine", so what one multicasts is heard by
        // the other although it never leaves the host.
        var links       = RequireLinks(Family);
        var port        = PrivatePort();

        await using var first   = await Started(new () { Port = port });
        await using var second  = await Started(new () { Port = port });

        var firstEar    = new Ear(first);
        var secondEar   = new Ear(second);

        var fromFirst   = Marker();
        var fromSecond  = Marker();

        await first. SendAsync(fromFirst);
        await second.SendAsync(fromSecond);

        Boolean OfTheFamily(MulticastDNSDatagram datagram)
            => IsIPv6(datagram.RemoteSocket.IPAddress) == (Family == AddressFamily.InterNetworkV6);

        var heardBySecond  = await secondEar.Await(datagram => OfTheFamily(datagram) && datagram.Payload.Span.SequenceEqual(fromFirst),  links.Length);
        var heardByFirst   = await firstEar. Await(datagram => OfTheFamily(datagram) && datagram.Payload.Span.SequenceEqual(fromSecond), links.Length);

        Assert.Multiple(() => {

            Assert.That(heardBySecond.Select(datagram => datagram.InterfaceIndex).Distinct(),
                        Is.SupersetOf(links.Select(link => (Int32?) link.Index)),
                        "the second transport did not hear the first one's multicast on every interface");

            Assert.That(heardByFirst.Select(datagram => datagram.InterfaceIndex).Distinct(),
                        Is.SupersetOf(links.Select(link => (Int32?) link.Index)),
                        "the first transport did not hear the second one's multicast on every interface");

        });

    }


    [TestCase(AddressFamily.InterNetwork,   TestName = "A transport of IPv4 alone starts, and its multicast is heard over IPv4 alone")]
    [TestCase(AddressFamily.InterNetworkV6, TestName = "A transport of IPv6 alone starts, and its multicast is heard over IPv6 alone")]
    [Property("RFC", "6762 §20")]
    public async Task A_Transport_Of_One_Address_Family_Is_Heard_Over_That_Family_Alone(AddressFamily Family)
    {

        // §20: "An IPv4-only host and an IPv6-only host behave as "ships that pass in the
        // night"." Either is a Multicast DNS host, on the family it has.
        var links      = RequireLinks(Family);
        var port       = PrivatePort();

        await using var listener  = await Started(new () { Port = port });
        var ear        = new Ear(listener);

        await using var single    = await Started(new () {
                                                      Port        = port,
                                                      EnableIPv4  = Family == AddressFamily.InterNetwork,
                                                      EnableIPv6  = Family == AddressFamily.InterNetworkV6
                                                  });

        var payload    = Marker();
        await single.SendAsync(payload);

        await ear.Await(datagram => datagram.Payload.Span.SequenceEqual(payload), links.Length);
        await Task.Delay(Settle);

        var heard      = ear.Carrying(payload);

        Assert.Multiple(() => {

            Assert.That(heard.Select(datagram => datagram.InterfaceIndex).Distinct(),
                        Is.SupersetOf(links.Select(link => (Int32?) link.Index)),
                        "the multicast was not heard on every interface");

            Assert.That(heard.Where(datagram => IsIPv6(datagram.RemoteSocket.IPAddress) != (Family == AddressFamily.InterNetworkV6)),
                        Is.Empty,
                        "a transport of one family multicast over the other");

        });

    }

    #endregion

    #region Unicast from the link (RFC 6762 §11)

    public enum UnicastSource
    {
        InterfaceIPv4,
        InterfaceIPv6LinkLocal,
        Loopback,
        LoopbackElsewhereInItsSubnet,
        LoopbackIPv6
    }


    [TestCase(UnicastSource.InterfaceIPv4,                 TestName = "A unicast from an interface's own IPv4 address is on the local link")]
    [TestCase(UnicastSource.InterfaceIPv6LinkLocal,        TestName = "A unicast from an interface's own IPv6 link-local address is on the local link")]
    [TestCase(UnicastSource.Loopback,                      TestName = "A unicast from 127.0.0.1 to 127.0.0.1 is on the local link of the loopback interface")]
    [TestCase(UnicastSource.LoopbackElsewhereInItsSubnet,  TestName = "A unicast from 127.1.0.1 to 127.0.0.1 is on the local link, inside 127.0.0.0/8")]
    [TestCase(UnicastSource.LoopbackIPv6,                  TestName = "A unicast from ::1 to ::1 is on the local link, a prefix of all 128 bits")]
    [Property("RFC", "6762 §11")]
    public async Task A_Unicast_From_The_Receiving_Interfaces_Subnet_Is_On_The_Local_Link(UnicastSource Source)
    {

        // §11: "For responses received with a unicast destination address in the IP header,
        // the source IP address in the packet is checked to see if it is an address on a
        // local subnet. An IPv4 source address is determined to be on a local subnet if,
        // for (one of) the address(es) configured on the interface receiving the packet,
        // (I & M) == (P & M) [...]. An IPv6 source address is determined to be on the local
        // link if, for any of the on-link IPv6 prefixes on the interface receiving the
        // packet [...], the first 'n' bits of the IPv6 source address match the first 'n'
        // bits of the prefix address."
        //
        // A unicast reaches only one of the sockets bound to a port (§15.1), so each case
        // has a port, and a transport, to itself.
        IPAddress from, to;
        var options = new UDPMulticastDNSTransportOptions { Port = PrivatePort() };

        switch (Source)
        {

            case UnicastSource.InterfaceIPv4:
                from = to = RequireLinks(AddressFamily.InterNetwork)[0].IPv4!;
                break;

            case UnicastSource.InterfaceIPv6LinkLocal:
                from = to = RequireLinks(AddressFamily.InterNetworkV6)[0].IPv6LinkLocal!;
                break;

            default:
                RequireMulticastLoopback();
                options = new UDPMulticastDNSTransportOptions { Port = options.Port, IncludeLoopbackInterface = true };
                (from, to) = Source switch {
                                 UnicastSource.Loopback                      => (IPAddress.Loopback,          IPAddress.Loopback),
                                 UnicastSource.LoopbackElsewhereInItsSubnet  => (IPAddress.Parse("127.1.0.1"), IPAddress.Loopback),
                                 _                                           => (IPAddress.IPv6Loopback,      IPAddress.IPv6Loopback)
                             };
                break;

        }

        await using var transport = await Started(options);
        var ear      = new Ear(transport);

        var payload  = Marker();
        await UnicastFrom(from, to, options.Port, payload);

        var heard    = (await ear.Await(datagram => datagram.Payload.Span.SequenceEqual(payload))).FirstOrDefault();

        Assert.That(heard, Is.Not.Null,
                    $"the unicast from {from} to {to} was not heard");

        Assert.Multiple(() => {

            Assert.That(heard!.RemoteSocket.IPAddress.GetBytes(), Is.EqualTo(from.GetAddressBytes()),
                        "the source is the one the packet was sent from");

            Assert.That(heard.DestinationAddress?.GetBytes(), Is.EqualTo(to.GetAddressBytes()),
                        "the destination of the IP header is the unicast address");

            Assert.That(heard.SourceIsOnLocalLink, Is.True,
                        $"§11: {from} is on a subnet of the interface that received the packet");

        });

    }

    #endregion

    #region Choosing the interface (RFC 6762 §6.2, §14)

    [Test]
    [Property("RFC", "6762 §6.2, §14")]
    public async Task A_Response_Goes_Out_On_The_Interface_The_Query_Came_In_On_Alone()
    {

        // §14: "addresses in IPv4 or IPv6 address records in Multicast DNS responses MUST be
        // valid for use on the interface on which the response is being sent." §6.2: a
        // responder "MUST NOT include addresses that are not valid on that interface (such
        // as addresses that may be configured on the host's other interfaces)." The record
        // here holds the address of the interface the query arrives on, which is valid on
        // that interface alone, so the answer goes out there and nowhere else.
        var links      = RequireLinks(AddressFamily.InterNetwork, AtLeast: 2);
        var asked      = links[0];
        var port       = PrivatePort();
        var host       = HostName();

        await using var responderTransport  = await Started(new () { Port = port });
        await using var listener            = await Started(new () { Port = port });
        var ear        = new Ear(listener);

        await using var responder = new MulticastDNSResponder(responderTransport, Quick());
        await responder.StartAsync();

        await responder.PublishAsync([
            new A(DomainName.Parse(host), DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv4Address.Parse(asked.IPv4!.ToString()))
        ], Probe: false);

        // The announcements go out on every interface; they are not what this is about.
        await Task.Delay(Settle);
        ear.Clear();

        // A query of a full Multicast DNS querier: from the Multicast DNS port, so that it is
        // answered by multicast (§6.7 would send a legacy query's answer back by unicast).
        using (var querier = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            querier.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            querier.Bind(new IPEndPoint(asked.IPv4!, port.ToInt32()));
            querier.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, asked.IPv4!.GetAddressBytes());
            await querier.SendToAsync(RawDnsWriter.Query(0, host, RawDnsType.A, recursionDesired: false),
                                      SocketFlags.None,
                                      new IPEndPoint(IPv4Group, port.ToInt32()));
        }

        await ear.Await(datagram => AnswersFor(datagram, host));
        await Task.Delay(Settle);

        var answers    = ear.Matching(datagram => AnswersFor(datagram, host));

        Assert.That(answers, Is.Not.Empty,
                    $"the query on {asked.Name} was not answered");

        Assert.That(answers.Select(datagram => datagram.InterfaceIndex).Distinct(),
                    Is.EqualTo(new Int32?[] { asked.Index }),
                    $"the answer holds the address of {asked.Name}, and went out on other interfaces as well");

    }


    [Test]
    [Property("RFC", "6762 §14")]
    public async Task A_Transport_Named_To_One_Interface_Multicasts_There_Alone()
    {

        // §14: a host that wants to support the same name on two links "needs network
        // programming APIs that allow applications to specify on what interface to perform
        // a link-local Multicast DNS query". The transport takes a list of interface names.
        var links      = RequireLinks(AddressFamily.InterNetwork);
        var chosen     = links[0];
        var port       = PrivatePort();

        await using var listener  = await Started(new () { Port = port });
        var ear        = new Ear(listener);

        await using var named     = await Started(new () { Port = port, InterfaceNames = [ chosen.Name ] });

        var payload    = Marker();
        await named.SendAsync(payload);

        await ear.Await(datagram => datagram.Payload.Span.SequenceEqual(payload));
        await Task.Delay(Settle);

        Assert.Multiple(() => {

            Assert.That(named.InterfaceIndexes, Is.EqualTo(new[] { chosen.Index }),
                        $"the transport named to {chosen.Name} took other interfaces, or not that one");

            Assert.That(ear.Carrying(payload).Select(datagram => datagram.InterfaceIndex).Distinct(),
                        Is.EqualTo(new Int32?[] { chosen.Index }),
                        $"the transport named to {chosen.Name} multicast elsewhere, or not there");

        });

    }

    #endregion

    #region Legacy unicast over the socket (RFC 6762 §6.7)

    [Test]
    [Property("RFC", "6762 §6.7")]
    public async Task A_Legacy_Query_Is_Answered_By_Unicast_To_Its_Source()
    {

        // §6.7: "If the source UDP port in a received Multicast DNS query is not port 5353
        // [...] the Multicast DNS responder MUST send a UDP response directly back to the
        // querier, via unicast, to the query packet's source IP address and port. [...] it
        // MUST repeat the query ID and the question given in the query message."
        var link       = RequireLinks(AddressFamily.InterNetwork)[0];
        var port       = PrivatePort();
        var host       = HostName();

        await using var transport = await Started(new () { Port = port });
        await using var responder = new MulticastDNSResponder(transport, Quick());
        await responder.StartAsync();

        await responder.PublishAsync([
            new A(DomainName.Parse(host), DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv4Address.Parse(link.IPv4!.ToString()))
        ], Probe: false);

        using var querier = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        querier.Bind(new IPEndPoint(link.IPv4!, 0));
        querier.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, link.IPv4!.GetAddressBytes());

        await querier.SendToAsync(RawDnsWriter.Query(0x5A5A, host, RawDnsType.A, recursionDesired: false),
                                  SocketFlags.None,
                                  new IPEndPoint(IPv4Group, port.ToInt32()));

        var buffer     = new Byte[9000];
        var receiving  = querier.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0));

        Assert.That(await Task.WhenAny(receiving, Task.Delay(Patience)), Is.SameAs(receiving),
                    "no unicast response came back to the legacy querier's port");

        var received   = await receiving;
        var response   = RawDnsReader.Parse(buffer[..received.ReceivedBytes]);

        Assert.Multiple(() => {

            Assert.That(((IPEndPoint) received.RemoteEndPoint).Port, Is.EqualTo(port.ToInt32()),
                        "the response comes from the Multicast DNS port");

            Assert.That(response.QR,  Is.True);

            Assert.That(response.Id,  Is.EqualTo(0x5A5A),
                        "§6.7: the response MUST repeat the query ID");

            Assert.That(response.Questions.Select(question => question.Name.Canonical),
                        Is.EqualTo(new[] { host.TrimEnd('.') }),
                        "§6.7: the response MUST repeat the question");

            Assert.That(response.Answers.Select(answer => answer.Rdata),
                        Is.EqualTo(new[] { link.IPv4!.GetAddressBytes() }));

        });

    }

    #endregion

    #region Whose query it is (RFC 6762 §7.3)

    [Test]
    [Property("RFC", "6762 §5.2, §7.3")]
    public async Task A_Browser_Does_Not_Take_Its_Own_Query_For_Another_Hosts()
    {

        // §7.3: "If a host is planning to transmit (or retransmit) a query, and it sees
        // another host on the network send a query containing the same "QM" question [...],
        // then this host SHOULD treat its own query as having been sent." A host hears its
        // own multicast as well (§15), over each family it sends on. Over IPv6 the copy comes
        // back from the interface's link-local address, which is the host's own, and is not
        // another host's query.
        //
        // The series is shortened from §5.2's one second, doubling, to 200 ms, doubling, so
        // that four queries fit into the test: at 0, 200, 600 and 1400 ms, and the fifth at
        // 3000. The rule under test is §7.3's.
        var link       = RequireLinks(AddressFamily.InterNetworkV6).
                             FirstOrDefault(link => link.IPv4 is not null);

        if (link is null)
            Assert.Ignore("No interface that is up and can multicast carries both an IPv4 address and an IPv6 link-local address.");

        var port         = PrivatePort();
        var serviceType  = $"_q{Guid.NewGuid():N}"[..14] + "._tcp.local.";

        await using var listener   = await Started(new () { Port = port });
        var ear          = new Ear(listener);

        await using var transport  = await Started(new () { Port = port });
        await using var client     = new MulticastDNSClient(transport, new MulticastDNSClientOptions {
                                                                           InitialBrowseInterval  = TimeSpan.FromMilliseconds(200),
                                                                           MinInitialBrowseDelay  = TimeSpan.Zero,
                                                                           MaxInitialBrowseDelay  = TimeSpan.Zero
                                                                       });
        await client.StartAsync();
        await client.BrowseAsync(DNSServiceName.Parse(serviceType));

        await Task.Delay(TimeSpan.FromMilliseconds(2300));

        // One copy of each query: the one sent on this interface over IPv4.
        var queries      = ear.Matching(datagram => datagram.InterfaceIndex == link.Index &&
                                                    datagram.RemoteSocket.IPAddress.GetBytes().SequenceEqual(link.IPv4!.GetAddressBytes()) &&
                                                    Read(datagram.Payload) is { QR: false } query &&
                                                    query.Questions.Any(question => question.Name.Canonical == serviceType.TrimEnd('.')));

        Assert.That(queries, Has.Length.EqualTo(4),
                    "the browser asked at 0, 200, 600 and 1400 ms only if it did not take the IPv6 copy of " +
                    "its own query for another host's: §7.3 lets another host's query stand in for one's own");

    }

    #endregion

}

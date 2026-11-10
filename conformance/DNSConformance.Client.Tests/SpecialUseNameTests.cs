using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// The names a resolver library answers itself: "localhost." and every name
/// below it, and "invalid." and every name below it (RFC 6761 §6.3, §6.4), the
/// .onion names (RFC 7686 §2), and the link-local names of Multicast DNS, which
/// it does not send to a unicast server (RFC 6762 §22.1).
/// </summary>
/// <remarks>
/// <para>
/// RFC 6761 §6.3, item 3: "Name resolution APIs and libraries SHOULD recognize
/// localhost names as special and SHOULD always return the IP loopback address
/// for address queries and negative responses for all other query types. Name
/// resolution APIs SHOULD NOT send queries for localhost names to their
/// configured caching DNS server(s)." §6.4, item 3, says the same of "invalid"
/// names, with "immediate negative responses" for every query. Both sections
/// open with the scope: the domain "and any names falling within" it.
/// </para>
/// <para>
/// <see cref="CacheBoundaryTests"/> pins how <c>DNSClient</c> keeps the first
/// half for "localhost." itself: its cache is created with an entry for it. Each
/// test here asks what that entry does not reach: a name below localhost, a type
/// that is no address, a client without a cache or one whose cache was emptied,
/// and the "invalid" names, which have no entry at all.
/// </para>
/// <para>
/// Two APIs resolve names in Hermod: <c>DNSClient</c>, and
/// <c>NameResolution</c>, which describes itself as "the one place Hermod turns
/// a host into the addresses to connect to". The transport clients are not
/// asked: <c>DNSUDPClient</c> and its siblings carry a query to the server they
/// were made for, as dig does when it is asked about localhost. That is also why
/// <c>NameResolution</c> is handed one here: whatever it recognizes, it has to
/// recognize itself.
/// </para>
/// <para>
/// The server answers every name with an address in the documentation ranges,
/// so a query that reaches it comes back with an answer no special-use name may
/// have. Each test ends with a name that is not special, which the same client
/// sends to the same server: the count of zero before it is a count of a server
/// that was reachable.
/// </para>
/// </remarks>
[TestFixture]
public class SpecialUseNameTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);

    private static readonly IPv4Address Wrong4 = IPv4Address.Parse("192.0.2.61");
    private static readonly IPv6Address Wrong6 = IPv6Address.Parse("2001:db8::61");


    /// <summary>
    /// A server that has an answer for every name and every type it is asked
    /// about: an address in the documentation ranges for A and AAAA, an MX and a
    /// TXT, and an empty NOERROR for anything else.
    /// </summary>
    private static ScriptedUdpServer AnswerEveryName()

        => new (request => {

               var questions = RawDnsReader.Parse(request).Questions;

               if (questions.Count != 1)
                   return null;

               var name = $"{questions[0].Name.Canonical}.";

               return questions[0].Type switch {
                   RawDnsType.A     => RawDnsResponder.Answer(request, (name, RawDnsType.A,    300, [192, 0, 2, 61])),
                   RawDnsType.AAAA  => RawDnsResponder.Answer(request, (name, RawDnsType.AAAA, 300, [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x61])),
                   RawDnsType.MX    => RawDnsResponder.Answer(request, (name, RawDnsType.MX,   300, [0, 10,
                                                                                                    4, (Byte) 'm', (Byte) 'a', (Byte) 'i', (Byte) 'l',
                                                                                                    7, (Byte) 'e', (Byte) 'x', (Byte) 'a', (Byte) 'm', (Byte) 'p', (Byte) 'l', (Byte) 'e',
                                                                                                    0])),
                   RawDnsType.TXT   => RawDnsResponder.Answer(request, (name, RawDnsType.TXT,  300, [5, (Byte) 'a', (Byte) 's', (Byte) 'k', (Byte) 'e', (Byte) 'd'])),
                   _                => RawDnsResponder.Answer(request)
               };

           });


    private static DNSClient ClientOf(ScriptedUdpServer  Server,
                                      Boolean            UseQueryCache  = true)

        => new (IPv4Address.Localhost,
                IPPort.Parse((UInt16) Server.Port),
                QueryTimeout:   Timeout,
                UseQueryCache:  UseQueryCache);


    /// <summary>
    /// The positive control: a name that is not special, sent by the same
    /// client to the same server, comes back with the server's answer.
    /// </summary>
    private static async Task AssertTheServerWasReachable(IDNSClient         Client,
                                                          ScriptedUdpServer  Server)
    {

        var before   = Server.Requests.Count;
        var control  = await Client.Query(DNSServiceName.Parse("control.example."), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.Multiple(() => {
            Assert.That(Server.Requests.Count - before, Is.EqualTo(1),
                        "control: a name that is not special reaches the same server");
            Assert.That(control.Answers.OfType<A>().Select(record => record.IPv4Address).ToArray(), Is.EqualTo(new[] { Wrong4 }),
                        "control: and comes back with its answer");
        });

    }

    #endregion


    #region Every name below localhost is the loopback address (RFC 6761 §6.3)

    /// <summary>
    /// An A and an AAAA query for the name through a client with a cache: the
    /// two loopback addresses, and nothing sent.
    /// </summary>
    private static async Task AssertLoopbackWithoutAsking(String Name)
    {

        await using var server = AnswerEveryName();
        using       var client = ClientOf(server);

        var a     = await client.Query(DNSServiceName.Parse(Name), [ DNSResourceRecordTypes.A    ], Timeout);
        var aaaa  = await client.Query(DNSServiceName.Parse(Name), [ DNSResourceRecordTypes.AAAA ], Timeout);
        var sent  = server.Requests.Count;

        Assert.Multiple(() => {

            Assert.That(a.   Answers.OfType<A>().   Select(record => record.IPv4Address).ToArray(), Is.EqualTo(new[] { IPv4Address.Localhost }),
                        "§6.3 item 3: an IPv4 address query for a localhost name is the IPv4 loopback address");

            Assert.That(aaaa.Answers.OfType<AAAA>().Select(record => record.IPv6Address).ToArray(), Is.EqualTo(new[] { IPv6Address.Localhost }),
                        "§6.3 item 3: and an IPv6 address query the IPv6 loopback address");

            Assert.That(sent, Is.Zero,
                        "§6.3 item 3: \"SHOULD NOT send queries for localhost names to their configured caching DNS server(s)\"");

        });

        await AssertTheServerWasReachable(client, server);

    }


    [Test]
    [Property("RFC", "6761 §6.3")]
    [TestCase("www.localhost.",     TestName = "{m}: www.localhost.")]
    [TestCase("a.b.localhost.",     TestName = "{m}: a.b.localhost., two labels below it")]
    [TestCase("app.LOCALHOST.",     TestName = "{m}: app.LOCALHOST., below it and in another case")]
    public Task A_Name_Below_Localhost_Is_The_Loopback_Address_And_Is_Not_Sent(String Name)

        // §6.3 makes "localhost." special "and any names falling within
        // ".localhost."". The cache's entry is for the one name; whatever is
        // not found there goes to the server, which answers with an address that
        // is not the loopback's.
        => AssertLoopbackWithoutAsking(Name);


    [Test]
    [Property("RFC", "6761 §6.3")]
    [Property("RFC", "4343 §3")]
    public Task Localhost_In_Another_Case_Is_The_Same_Name()

        // The entry is found under its key in any case, because names compare
        // without case (RFC 4343 §3). Pinned beside the names below localhost,
        // which a fix that recognizes them by comparing text has to match the
        // same way.
        => AssertLoopbackWithoutAsking("LocalHost.");


    [Test]
    [Property("RFC", "6761 §6.3")]
    [TestCase("localhost.",     DNSResourceRecordTypes.MX,  TestName = "{m}: MX of localhost.")]
    [TestCase("localhost.",     DNSResourceRecordTypes.TXT, TestName = "{m}: TXT of localhost.")]
    [TestCase("www.localhost.", DNSResourceRecordTypes.MX,  TestName = "{m}: MX of www.localhost.")]
    public async Task Another_Type_Of_A_Localhost_Name_Is_A_Negative_Answer_And_Is_Not_Sent(String                  Name,
                                                                                         DNSResourceRecordTypes  Type)
    {

        // "negative responses for all other query types". The entry for
        // localhost holds an A and an AAAA, and since finding 74 a cached answer
        // is the RRset asked for: an MX is not in it, so the client asks the
        // server, which has one. Whether the negative answer is NODATA or
        // NXDOMAIN, §6.3 does not say; the name has addresses, which makes NODATA
        // the one that does not contradict them, but either is accepted here.
        await using var server = AnswerEveryName();
        using       var client = ClientOf(server);

        var answer  = await client.Query(DNSServiceName.Parse(Name), [ Type ], Timeout);
        var sent    = server.Requests.Count;

        Assert.Multiple(() => {

            Assert.That(answer.Answers, Is.Empty,
                        $"§6.3 item 3: a {Type} query for a localhost name has a negative response");

            Assert.That(answer.ResponseCode, Is.AnyOf(DNSResponseCodes.NoError, DNSResponseCodes.NameError),
                        "§6.3 item 3: a negative response, NODATA or NXDOMAIN, and not a failure");

            Assert.That(sent, Is.Zero,
                        "§6.3 item 3: and the query is not sent to the configured server");

        });

        await AssertTheServerWasReachable(client, server);

    }


    private static IEnumerable<TestCaseData> WithoutTheCachedEntry()
    {

        TestCaseData Case(String Label, Boolean UseQueryCache, Func<DNSClient, ScriptedUdpServer, Task<DNSInfo>> Ask)
            => new TestCaseData(UseQueryCache, Ask).SetArgDisplayNames(Label);

        var localhost = DNSServiceName.Parse("localhost.");

        // Every other test in this project makes its client with
        // UseQueryCache: false, and so does any caller who wants no cache.
        yield return Case("a client without a cache", false,
                          (client, server) => client.Query(localhost, [ DNSResourceRecordTypes.A ], Timeout));

        // ForceUpdate asks for an answer fresher than the cache's. The loopback
        // address is not a cached answer: it is what the RFC says the name is.
        yield return Case("a lookup with ForceUpdate", true,
                          (client, server) => client.Query(localhost, [ DNSResourceRecordTypes.A ], Timeout, ForceUpdate: true));

        // SetDNSServers empties the cache, so that nothing the old servers said
        // outlives them. The entry for localhost went with it.
        yield return Case("a client whose servers were set again", true,
                          (client, server) => {
                              client.SetDNSServers([ new DNSServerConfig(IPv4Address.Localhost, IPPort.Parse((UInt16) server.Port)) ]);
                              return client.Query(localhost, [ DNSResourceRecordTypes.A ], Timeout);
                          });

    }


    [TestCaseSource(nameof(WithoutTheCachedEntry))]
    [Property("RFC", "6761 §6.3")]
    public async Task Localhost_Is_The_Loopback_Address_Without_The_Cached_Entry(Boolean                                             UseQueryCache,
                                                                                 Func<DNSClient, ScriptedUdpServer, Task<DNSInfo>>  Ask)
    {

        // §6.3 item 3 is about the library, not about its cache: a client that
        // has none, or ignores it, or has just emptied it, is the same library.
        await using var server = AnswerEveryName();
        using       var client = ClientOf(server, UseQueryCache);

        var answer  = await Ask(client, server);
        var sent    = server.Requests.Count;

        Assert.Multiple(() => {

            Assert.That(answer.Answers.OfType<A>().Select(record => record.IPv4Address).ToArray(), Is.EqualTo(new[] { IPv4Address.Localhost }),
                        "§6.3 item 3: localhost is the IPv4 loopback address");

            Assert.That(sent, Is.Zero,
                        "§6.3 item 3: and it is not sent to the configured server");

        });

        await AssertTheServerWasReachable(client, server);

    }

    #endregion


    #region Every "invalid" name is NXDOMAIN, at once (RFC 6761 §6.4)

    [Test]
    [Property("RFC", "6761 §6.4")]
    [TestCase("invalid.",       DNSResourceRecordTypes.A,    TestName = "{m}: A of invalid.")]
    [TestCase("host.invalid.",  DNSResourceRecordTypes.A,    TestName = "{m}: A of host.invalid.")]
    [TestCase("host.invalid.",  DNSResourceRecordTypes.AAAA, TestName = "{m}: AAAA of host.invalid.")]
    [TestCase("a.b.INVALID.",   DNSResourceRecordTypes.MX,   TestName = "{m}: MX of a.b.INVALID., in another case")]
    public async Task An_Invalid_Name_Is_NXDOMAIN_And_Is_Not_Sent(String                  Name,
                                                                 DNSResourceRecordTypes  Type)
    {

        // §6.4 item 3: "Name resolution APIs and libraries SHOULD recognize
        // "invalid" names as special and SHOULD always return immediate negative
        // responses. Name resolution APIs SHOULD NOT send queries for "invalid"
        // names to their configured caching DNS server(s)." Item 3 says
        // "negative"; item 1 tells users they "MAY assume that queries for
        // "invalid" names will always return NXDOMAIN responses", and item 4
        // gives caching servers NXDOMAIN. A NODATA would break the promise of
        // item 1, so NXDOMAIN is what is asserted.
        await using var server = AnswerEveryName();
        using       var client = ClientOf(server);

        var answer  = await client.Query(DNSServiceName.Parse(Name), [ Type ], Timeout);
        var sent    = server.Requests.Count;

        Assert.Multiple(() => {

            Assert.That(answer.Answers, Is.Empty,
                        "§6.4 item 3: an \"invalid\" name has a negative response");

            Assert.That(answer.ResponseCode, Is.EqualTo(DNSResponseCodes.NameError),
                        "§6.4 items 1 and 4: and that response is NXDOMAIN");

            Assert.That(sent, Is.Zero,
                        "§6.4 item 3: \"SHOULD NOT send queries for \"invalid\" names to their configured caching DNS server(s)\"");

        });

        await AssertTheServerWasReachable(client, server);

    }

    #endregion


    #region Every .onion name is NXDOMAIN (RFC 7686 §2)

    [Test]
    [Property("RFC", "7686 §2")]
    [TestCase("onion.",                    DNSResourceRecordTypes.A,    TestName = "{m}: A of onion.")]
    [TestCase("hiddenservice.onion.",      DNSResourceRecordTypes.A,    TestName = "{m}: A of hiddenservice.onion.")]
    [TestCase("www.hiddenservice.onion.",  DNSResourceRecordTypes.AAAA, TestName = "{m}: AAAA of www.hiddenservice.onion.")]
    [TestCase("a.b.ONION.",                DNSResourceRecordTypes.TXT,  TestName = "{m}: TXT of a.b.ONION., in another case")]
    public async Task An_Onion_Name_Is_NXDOMAIN(String                  Name,
                                                DNSResourceRecordTypes  Type)
    {

        // RFC 7686 §2 item 3: "Resolvers MUST either respond to requests for
        // .onion names by resolving them according to [tor-rendezvous] or by
        // responding with NXDOMAIN". DNSClient speaks no Tor, so what it may
        // answer is NXDOMAIN — not the address the server has for the name.
        // Whether it asks first is not asserted: item 3 says what the answer is,
        // and the server answers every name.
        await using var server = AnswerEveryName();
        using       var client = ClientOf(server);

        var answer  = await client.Query(DNSServiceName.Parse(Name), [ Type ], Timeout);

        Assert.Multiple(() => {

            Assert.That(answer.Answers, Is.Empty,
                        "§2 item 3: a .onion name has no records a resolver without Tor could give");

            Assert.That(answer.ResponseCode, Is.EqualTo(DNSResponseCodes.NameError),
                        "§2 item 3: \"or by responding with NXDOMAIN\"");

        });

        await AssertTheServerWasReachable(client, server);

    }

    #endregion


    #region A link-local name is not sent to a unicast server (RFC 6762 §22.1)

    [Test]
    [Property("RFC", "6762 §22.1")]
    [TestCase("printer.local.",              DNSResourceRecordTypes.A,    TestName = "{m}: A of printer.local.")]
    [TestCase("local.",                      DNSResourceRecordTypes.A,    TestName = "{m}: A of local.")]
    [TestCase("My-Printer.LOCAL.",           DNSResourceRecordTypes.AAAA, TestName = "{m}: AAAA of My-Printer.LOCAL., in another case")]
    [TestCase("_ipp._tcp.local.",            DNSResourceRecordTypes.PTR,  TestName = "{m}: PTR of _ipp._tcp.local.")]
    [TestCase("4.3.254.169.in-addr.arpa.",   DNSResourceRecordTypes.PTR,  TestName = "{m}: PTR of 4.3.254.169.in-addr.arpa.")]
    [TestCase("1.8.e.f.ip6.arpa.",           DNSResourceRecordTypes.PTR,  TestName = "{m}: PTR of 1.8.e.f.ip6.arpa.")]
    [TestCase("F.B.E.F.IP6.ARPA.",           DNSResourceRecordTypes.PTR,  TestName = "{m}: PTR of F.B.E.F.IP6.ARPA., in another case")]
    public async Task A_Link_Local_Name_Is_Not_Sent_To_A_Unicast_Server(String                  Name,
                                                                        DNSResourceRecordTypes  Type)
    {

        // RFC 6762 §22.1 makes ".local." and the link-local reverse domains
        // 254.169.in-addr.arpa. and 8.e.f.ip6.arpa. to b.e.f.ip6.arpa. special,
        // with every name below them. Item 3: "Name resolution APIs and
        // libraries SHOULD recognize these names as special and SHOULD NOT send
        // queries for these names to their configured (unicast) caching DNS
        // server(s)." They are Multicast DNS names; what a unicast server says
        // about one is no answer, and only the sending is asserted.
        await using var server = AnswerEveryName();
        using       var client = ClientOf(server);

        var answer  = await client.Query(DNSServiceName.Parse(Name), [ Type ], Timeout);
        var sent    = server.Requests.Count;

        Assert.Multiple(() => {

            Assert.That(sent, Is.Zero,
                        "§22.1 item 3: \"SHOULD NOT send queries for these names to their configured (unicast) caching DNS server(s)\"");

            Assert.That(answer.Answers, Is.Empty,
                        "§22.1 item 3: so no unicast server's records come back for one");

        });

        await AssertTheServerWasReachable(client, server);

    }


    [Test]
    [Property("RFC", "6762 §22.1")]
    [TestCase("local.example.",           TestName = "{m}: local.example.")]
    [TestCase("notlocal.",                TestName = "{m}: notlocal.")]
    [TestCase("255.169.in-addr.arpa.",    TestName = "{m}: 255.169.in-addr.arpa.")]
    [TestCase("254.168.in-addr.arpa.",    TestName = "{m}: 254.168.in-addr.arpa.")]
    [TestCase("1.1254.169.in-addr.arpa.", TestName = "{m}: 1.1254.169.in-addr.arpa., a longer label")]
    [TestCase("c.e.f.ip6.arpa.",          TestName = "{m}: c.e.f.ip6.arpa.")]
    [TestCase("7.e.f.ip6.arpa.",          TestName = "{m}: 7.e.f.ip6.arpa.")]
    [TestCase("18.e.f.ip6.arpa.",         TestName = "{m}: 18.e.f.ip6.arpa., a longer label")]
    public async Task A_Name_Beside_The_Link_Local_Ones_Is_Sent(String Name)
    {

        // The six domains are the whole of it, label by label: a name whose last
        // labels only look like theirs is an ordinary name and goes to the
        // server like any other.
        await using var server = AnswerEveryName();
        using       var client = ClientOf(server);

        await client.Query(DNSServiceName.Parse(Name), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.That(server.Requests.Count, Is.EqualTo(1),
                    $"{Name} is no link-local name, and is sent");

    }


    [Test]
    [Property("RFC", "6762 §22.1")]
    public async Task A_Link_Local_Name_Is_Sent_When_The_Client_Is_Told_To()
    {

        // The option for a network that serves ".local" by unicast DNS, as
        // Active Directory domains named so do, although RFC 6762 Appendix G
        // recommends against it.
        await using var server = AnswerEveryName();
        using       var client = ClientOf(server);

        client.SendLinkLocalNamesToServers = true;

        var answer = await client.Query(DNSServiceName.Parse("printer.local."), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.Multiple(() => {
            Assert.That(server.Requests.Count, Is.EqualTo(1),
                        "told to, the client sends a link-local name to its server");
            Assert.That(answer.Answers.OfType<A>().Select(record => record.IPv4Address).ToArray(), Is.EqualTo(new[] { Wrong4 }),
                        "and the server's answer is the answer");
        });

    }

    #endregion


    #region NameResolution recognizes both itself (RFC 6761 §6.3, §6.4)

    [Test]
    [Property("RFC", "6761 §6.3")]
    [TestCase("www.localhost",   TestName = "{m}: www.localhost")]
    [TestCase("www.localhost.",  TestName = "{m}: www.localhost., with the root's dot")]
    [TestCase("localhost.",      TestName = "{m}: localhost., with the root's dot")]
    public async Task NameResolution_Resolves_A_Localhost_Name_Without_Asking(String Host)
    {

        // NameResolution takes "localhost" as the loopback addresses before any
        // DNS client is asked, and refuses a host name it has no DNS client for.
        // A localhost name is the loopback address however it is written, and
        // needs no DNS client: §6.3 item 3 asks the API to recognize it.
        var withoutClient = await ResolvedOrNull(Host, null);

        await using var server     = AnswerEveryName();
        await using var transport  = new DNSUDPClient(IPv4Address.Localhost,
                                                      IPPort.Parse((UInt16) server.Port),
                                                      QueryTimeout: Timeout);

        var withTransport  = await ResolvedOrNull(Host, transport);
        var sent           = server.Requests.Count;

        var loopback = new[] { System.Net.IPAddress.Loopback, System.Net.IPAddress.IPv6Loopback };

        Assert.Multiple(() => {

            // Empty where NameResolution refused the host.
            Assert.That(withoutClient ?? [], Is.EquivalentTo(loopback),
                        "§6.3 item 3: a localhost name is the loopback addresses, with no DNS client to ask");

            Assert.That(withTransport ?? [], Is.EquivalentTo(loopback),
                        "§6.3 item 3: and with one, the same");

            Assert.That(sent, Is.Zero,
                        "§6.3 item 3: whose server is not asked");

        });

        await AssertTheServerWasReachable(transport, server);

    }


    [Test]
    [Property("RFC", "6761 §6.4")]
    [TestCase("host.invalid",   TestName = "{m}: host.invalid")]
    [TestCase("host.invalid.",  TestName = "{m}: host.invalid., with the root's dot")]
    [TestCase("invalid",        TestName = "{m}: invalid")]
    public async Task NameResolution_Refuses_An_Invalid_Name_Without_Asking(String Host)
    {

        // An "invalid" name has no address, and §6.4 item 3 asks the API to say
        // so at once, without a query.
        await using var server     = AnswerEveryName();
        await using var transport  = new DNSUDPClient(IPv4Address.Localhost,
                                                      IPPort.Parse((UInt16) server.Port),
                                                      QueryTimeout: Timeout);

        var resolved  = await ResolvedOrNull(Host, transport);
        var sent      = server.Requests.Count;

        Assert.Multiple(() => {

            Assert.That(resolved, Is.Null,
                        "§6.4 item 3: an \"invalid\" name resolves to no address, and NameResolution says so");

            Assert.That(sent, Is.Zero,
                        "§6.4 item 3: and its server is not asked");

        });

        await AssertTheServerWasReachable(transport, server);

    }


    [Test]
    [Property("RFC", "7686 §2")]
    [TestCase("hiddenservice.onion",   TestName = "{m}: hiddenservice.onion")]
    [TestCase("hiddenservice.onion.",  TestName = "{m}: hiddenservice.onion., with the root's dot")]
    [TestCase("www.HiddenService.Onion", TestName = "{m}: www.HiddenService.Onion, in another case")]
    public async Task NameResolution_Refuses_An_Onion_Name_Without_Asking(String Host)
    {

        // RFC 7686 §2 item 3 has a resolver without Tor answer NXDOMAIN, and
        // item 2 says that applications that do not implement Tor "SHOULD
        // generate an error upon the use of .onion and SHOULD NOT perform a DNS
        // lookup".
        // Hermod's HTTP, SSH and TCP clients are such software, and their
        // lookups are NameResolution's: the error is its exception, and no DNS
        // client is asked.
        await using var server     = AnswerEveryName();
        await using var transport  = new DNSUDPClient(IPv4Address.Localhost,
                                                      IPPort.Parse((UInt16) server.Port),
                                                      QueryTimeout: Timeout);

        var resolved  = await ResolvedOrNull(Host, transport);
        var sent      = server.Requests.Count;

        Assert.Multiple(() => {

            Assert.That(resolved, Is.Null,
                        "§2 items 2 and 3: a .onion name resolves to no address without Tor, and NameResolution says so");

            Assert.That(sent, Is.Zero,
                        "§2 item 2: \"SHOULD NOT perform a DNS lookup\"");

        });

        await AssertTheServerWasReachable(transport, server);

    }


    /// <summary>
    /// What NameResolution resolves the host to, or null when it refuses it
    /// with the exception it documents for a host it found no address for.
    /// </summary>
    private static async Task<IReadOnlyList<System.Net.IPAddress>?> ResolvedOrNull(String       Host,
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

    #endregion

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 6761 §6.1 to §6.4, item 5 each, and RFC 7686 §2 item 5 — the special-use
/// names an authoritative server answers whether or not it serves a zone for
/// them.
/// </summary>
/// <remarks>
/// <para>
/// A name outside every zone this server serves is refused (RFC 1034 §4.3.2,
/// finding 41), and for almost every name that is right. RFC 6761 makes five
/// exceptions, and four of them are addressed to authoritative servers by name.
/// §6.3 item 5 has them "recognize localhost names as special and handle them as
/// described above for caching DNS servers", which is "an immediate positive
/// response giving the IP loopback address" for an address query and "an
/// immediate negative response" for any other type. §6.4 item 5 says the same
/// of "invalid" names, for which caching servers "SHOULD generate immediate
/// NXDOMAIN responses". Item 6 of both adds that their answers are "defined by
/// protocol specification" and "cannot be modified by local configuration", so
/// a record a zone holds at such a name changes nothing.
/// </para>
/// <para>
/// §6.1 and §6.2 ask less: for the private-address reverse names and for test
/// names, item 5 wants "immediate negative responses for all such queries",
/// "unless explicitly configured by the administrator to give positive
/// answers". A served name is such a configuration, and is answered as served.
/// Every other one gets a negative answer rather than REFUSED. Which negative
/// answer is the server's choice, with one exception: NXDOMAIN says that nothing
/// exists at the name or below it (RFC 8020 §2), so a name above one this server
/// serves is NODATA.
/// </para>
/// <para>
/// RFC 7686 registered .onion later, and asks more than RFC 6761 does of
/// "invalid" names: §2 item 5, "Authoritative servers MUST respond to queries
/// for .onion with NXDOMAIN", and item 6 forbids operators to configure an
/// answer. RFC 9476 registered .alt the other way round, §3.2 item 5:
/// "Authoritative DNS servers SHOULD NOT recognize names in the .alt pseudo-TLD
/// as special". One is among the guards.
/// </para>
/// <para>
/// RFC 6762 §22.1 registered the link-local names of Multicast DNS: ".local."
/// and the link-local reverse domains 254.169.in-addr.arpa. and 8.e.f.ip6.arpa.
/// to b.e.f.ip6.arpa. Item 5: "Authoritative DNS servers SHOULD NOT by default be
/// configurable to answer queries for these names, and, like caching DNS
/// servers, SHOULD generate immediate NXDOMAIN responses for all such queries
/// they may receive." A server may offer an option to answer them; by default it
/// does not.
/// </para>
/// <para>
/// Every negative answer here cites an SOA, as every other negative answer of
/// this server does (RFC 2308 §3): without one it is not cached, and a resolver
/// asks again every time.
/// </para>
/// <para>
/// §6.5 is the fifth exception, and it is the opposite one: "Authoritative DNS
/// servers SHOULD NOT recognize example names as special." The guards below hold
/// those, and the names beside the special ones, at REFUSED.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "6761")]
public class SpecialUseNameServerTests
{

    #region Data

    /// <summary>
    /// A private-address reverse name this server serves, beside the standard
    /// zone and outside it — the way the standard zone keeps its own PTR.
    /// </summary>
    private const String ServedPrivatePtr       = "5.1.168.192.in-addr.arpa.";

    private const String ConfiguredLocalhostA   = "192.0.2.97";
    private const String ConfiguredLocalhostAAAA = "2001:db8::97";
    private const String ConfiguredInvalidA     = "192.0.2.98";
    private const String ConfiguredOnionA       = "192.0.2.99";
    private const String ConfiguredLocalA       = "192.0.2.100";

    private HermodServerFixture server      = null!;
    private HermodServerFixture configured  = null!;

    #endregion

    #region Start and stop

    [OneTimeSetUp]
    public async Task StartServers()
    {

        var ttl   = ZoneFixtures.DefaultTtl;

        var zone  = ZoneFixtures.CreateStandardZone();

        zone.Add(
            new PTR(DomainName.Parse(ServedPrivatePtr), DNSQueryClasses.IN, ttl, DNSServiceName.Parse(ZoneFixtures.AName))
        );

        server      = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions { Zone = zone });

        // Records at names whose answers RFC 6761 fixes. Item 6 of §6.3 and of
        // §6.4: those answers "cannot be modified by local configuration". And
        // one at a .onion name, which RFC 7686 §2 item 5 has a server answer
        // with NXDOMAIN whatever it holds, and one at a .local name, which RFC
        // 6762 §22.1 item 5 has a server not answer by default.
        var other = ZoneFixtures.CreateStandardZone();

        other.Add(
            new A   (DomainName.Parse("localhost."),     DNSQueryClasses.IN, ttl, IPv4Address.Parse(ConfiguredLocalhostA)),
            new AAAA(DomainName.Parse("www.localhost."), DNSQueryClasses.IN, ttl, IPv6Address.Parse(ConfiguredLocalhostAAAA)),
            new A   (DomainName.Parse("host.invalid."),  DNSQueryClasses.IN, ttl, IPv4Address.Parse(ConfiguredInvalidA)),
            new A   (DomainName.Parse("host.onion."),    DNSQueryClasses.IN, ttl, IPv4Address.Parse(ConfiguredOnionA)),
            new A   (DomainName.Parse("printer.local."), DNSQueryClasses.IN, ttl, IPv4Address.Parse(ConfiguredLocalA))
        );

        configured  = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions { Zone = other });

    }

    [OneTimeTearDown]
    public async Task StopServers()
    {
        await server.    DisposeAsync();
        await configured.DisposeAsync();
    }

    #endregion

    #region (private) Ask(Server, Name, Type)

    private static UInt16 nextId = 0x6761;

    private static async Task<RawDnsMessage> Ask(HermodServerFixture  Server,
                                                 String               Name,
                                                 UInt16               Type)
    {

        var request  = RawDnsWriter.Query(nextId++, Name, Type);
        var raw      = await RawDnsProbe.UdpAsync(Server.UdpPort, request);

        Assert.That(raw, Is.Not.Null, $"the server must answer {Name}, not drop it");

        return RawDnsReader.Parse(raw!);

    }

    #endregion

    #region (private) AssertLoopback(Response, Name, Type)

    private static void AssertLoopback(RawDnsMessage  Response,
                                       String         Name,
                                       UInt16         Type)
    {

        var loopback = Type == RawDnsType.A
                           ? RawDnsWriter.IPv4("127.0.0.1")
                           : RawDnsWriter.IPv6("::1");

        Assert.Multiple(() => {

            Assert.That(Response.RCode,   Is.Zero,               $"{Name} is answered, not refused (REFUSED = 5)");
            Assert.That(Response.Answers, Has.Count.EqualTo(1),  $"one address answers {Name}: the loopback address, and nothing configured beside it");

            if (Response.Answers.Count == 1)
            {
                Assert.That(Response.Answers[0].Type,           Is.EqualTo(Type),                          "of the type asked for");
                Assert.That(Response.Answers[0].Name.Canonical, Is.EqualTo(Name.TrimEnd('.').ToLowerInvariant()), "at the name asked for");
                Assert.That(Response.Answers[0].Rdata,          Is.EqualTo(loopback),                      "the loopback address");
            }

        });

    }

    #endregion

    #region (private) AssertNegative(Response, Name)

    // A negative response is one of the two RFC 2308 §2 names: NXDOMAIN, or
    // NOERROR with no answer.
    private static void AssertNegative(RawDnsMessage  Response,
                                       String         Name)
    {

        Assert.Multiple(() => {
            Assert.That(Response.RCode,   Is.Zero.Or.EqualTo(3), $"{Name} gets a negative answer, NXDOMAIN or NODATA, not REFUSED (5)");
            Assert.That(Response.Answers, Is.Empty,              "and no answer");
            AssertCitesAnSoa(Response, Name);
        });

    }

    #endregion

    #region (private) AssertCitesAnSoa(Response, Name)

    // RFC 2308 §3: "Name servers authoritative for a zone MUST include the SOA
    // record of the zone in the authority section of the response when
    // reporting an NXDOMAIN or indicating that no data of the requested type
    // exists." It is what lets the negative answer be cached, and the zone is
    // one the name is in: the SOA's owner is the name or above it.
    private static void AssertCitesAnSoa(RawDnsMessage  Response,
                                         String         Name)
    {

        var name = Name.TrimEnd('.').ToLowerInvariant();

        var soas = Response.Authorities.
                            Where (record => record.Type == RawDnsType.SOA).
                            Select(record => record.Name.Canonical.TrimEnd('.')).
                            ToArray();

        Assert.That(soas.Any(owner => owner.Length == 0 || name == owner || name.EndsWith("." + owner, StringComparison.Ordinal)),
                    Is.True,
                    $"the negative answer for {Name} cites the SOA of a zone the name is in (RFC 2308 §3); its authority section holds SOAs at [{String.Join(", ", soas)}]");

    }

    #endregion


    // Finding 103: localhost and "invalid" names (§6.3, §6.4, items 5 and 6)

    #region A_Localhost_Name_Is_The_Loopback_Address(Name, Type)

    [Test]
    [Property("RFC", "6761 §6.3")]
    [TestCase("localhost.",      RawDnsType.A)]
    [TestCase("www.localhost.",  RawDnsType.A)]
    [TestCase("a.b.LOCALHOST.",  RawDnsType.A)]
    [TestCase("localhost.",      RawDnsType.AAAA)]
    [TestCase("www.localhost.",  RawDnsType.AAAA)]
    public async Task A_Localhost_Name_Is_The_Loopback_Address(String Name, UInt16 Type)
    {

        // §6.3: "The domain "localhost." and any names falling within
        // ".localhost." are special", and item 4, which item 5 makes this
        // server's, answers "all such address queries" with "the IP loopback
        // address".
        AssertLoopback(await Ask(server, Name, Type), Name, Type);

    }

    #endregion

    #region Another_Type_Of_A_Localhost_Name_Is_NoData(Name, Type)

    [Test]
    [Property("RFC", "6761 §6.3")]
    [Property("RFC", "2308 §2.2")]
    [TestCase("localhost.",      RawDnsType.MX)]
    [TestCase("localhost.",      RawDnsType.TXT)]
    [TestCase("www.localhost.",  RawDnsType.MX)]
    [TestCase("a.b.localhost.",  RawDnsType.PTR)]
    public async Task Another_Type_Of_A_Localhost_Name_Is_NoData(String Name, UInt16 Type)
    {

        // "for all other query types, generate an immediate negative response".
        // Of the two negative responses only NODATA fits: the name has its
        // addresses, and NXDOMAIN would say it has nothing of any type.
        var response = await Ask(server, Name, Type);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero,  $"NODATA: {Name} exists, so not NXDOMAIN (3), and it is not refused (5)");
            Assert.That(response.Answers, Is.Empty, "and nothing of that type");
            AssertCitesAnSoa(response, Name);
        });

    }

    #endregion

    #region An_Invalid_Name_Is_NXDOMAIN(Name, Type)

    [Test]
    [Property("RFC", "6761 §6.4")]
    [TestCase("invalid.",        RawDnsType.A)]
    [TestCase("host.invalid.",   RawDnsType.A)]
    [TestCase("a.b.INVALID.",    RawDnsType.AAAA)]
    [TestCase("host.invalid.",   RawDnsType.MX)]
    public async Task An_Invalid_Name_Is_NXDOMAIN(String Name, UInt16 Type)
    {

        // §6.4 item 4, made this server's by item 5: "immediate NXDOMAIN
        // responses for all such queries".
        var response = await Ask(server, Name, Type);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.EqualTo(3), $"{Name} is NXDOMAIN (3), not refused (5)");
            Assert.That(response.Answers, Is.Empty,      "and has no answer");
            AssertCitesAnSoa(response, Name);
        });

    }

    #endregion

    #region A_Configured_Record_Does_Not_Change_A_Localhost_Name(Name, Type)

    [Test]
    [Property("RFC", "6761 §6.3")]
    [TestCase("localhost.",      RawDnsType.A)]
    [TestCase("www.localhost.",  RawDnsType.AAAA)]
    public async Task A_Configured_Record_Does_Not_Change_A_Localhost_Name(String Name, UInt16 Type)
    {

        // Item 6: "the effective RDATA for localhost names is defined by
        // protocol specification and cannot be modified by local
        // configuration". The zone holds 192.0.2.97 at localhost. and
        // 2001:db8::97 at www.localhost.; the answers are still the loopback.
        AssertLoopback(await Ask(configured, Name, Type), Name, Type);

    }

    #endregion

    #region A_Configured_Record_Does_Not_Make_An_Invalid_Name_Exist()

    [Test]
    [Property("RFC", "6761 §6.4")]
    public async Task A_Configured_Record_Does_Not_Make_An_Invalid_Name_Exist()
    {

        // Item 6: "the effective RDATA for "invalid" names is defined by
        // protocol specification to be nonexistent and cannot be modified by
        // local configuration". The zone holds 192.0.2.98 at host.invalid.
        var response = await Ask(configured, "host.invalid.", RawDnsType.A);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.EqualTo(3), "host.invalid. is NXDOMAIN (3) with a record configured at it");
            Assert.That(response.Answers, Is.Empty,      "and the configured record is not served");
            AssertCitesAnSoa(response, "host.invalid.");
        });

    }

    #endregion


    // Finding 104: test names and private-address reverse names (§6.1, §6.2, item 5)

    #region A_Test_Name_No_Zone_Is_Served_For_Is_A_Negative_Answer(Name, Type)

    [Test]
    [Property("RFC", "6761 §6.2")]
    [TestCase("other.test.",      RawDnsType.A)]
    [TestCase("a.b.other.test.",  RawDnsType.AAAA)]
    [TestCase("OTHER.TEST.",      RawDnsType.MX)]
    public async Task A_Test_Name_No_Zone_Is_Served_For_Is_A_Negative_Answer(String Name, UInt16 Type)
    {

        // §6.2 item 5: "Authoritative DNS servers SHOULD recognize test names as
        // special and SHOULD, by default, generate immediate negative responses
        // for all such queries, unless explicitly configured by the
        // administrator to give positive answers for test names." The server
        // serves conformance.test. and nothing else below test.
        AssertNegative(await Ask(server, Name, Type), Name);

    }

    #endregion

    #region A_Test_Name_Above_A_Served_Zone_Is_NoData()

    [Test]
    [Property("RFC", "6761 §6.2")]
    [Property("RFC", "8020 §2")]
    public async Task A_Test_Name_Above_A_Served_Zone_Is_NoData()
    {

        // test. is a test name this server serves no zone for, so the answer is
        // negative. It cannot be NXDOMAIN: after one, RFC 8020 §2 has a resolver
        // consider "all names and resource record sets (RRsets) at or below that
        // node" unreachable, and conformance.test., the zone this server
        // serves, is below it.
        var response = await Ask(server, "test.", RawDnsType.A);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero,  "NODATA: not refused (5), and not NXDOMAIN (3) above a served zone");
            Assert.That(response.Answers, Is.Empty, "and no answer");
            AssertCitesAnSoa(response, "test.");
        });

    }

    #endregion

    #region A_Private_Address_Reverse_Name_No_Zone_Is_Served_For_Is_A_Negative_Answer(Name)

    [Test]
    [Property("RFC", "6761 §6.1")]
    [TestCase("1.0.0.10.in-addr.arpa.")]
    [TestCase("10.in-addr.arpa.")]
    [TestCase("4.3.16.172.in-addr.arpa.")]
    [TestCase("4.3.20.172.in-addr.arpa.")]
    [TestCase("31.172.in-addr.arpa.")]
    [TestCase("9.9.168.192.IN-ADDR.ARPA.")]
    [TestCase("2.168.192.in-addr.arpa.")]
    public async Task A_Private_Address_Reverse_Name_No_Zone_Is_Served_For_Is_A_Negative_Answer(String Name)
    {

        // §6.1 lists 10.in-addr.arpa., 16.172.in-addr.arpa. to
        // 31.172.in-addr.arpa. and 168.192.in-addr.arpa., "and any names
        // falling within those domains". Item 5: "Authoritative DNS servers
        // SHOULD recognize these names as special and SHOULD, by default,
        // generate immediate negative responses for all such queries, unless
        // explicitly configured by the administrator to give positive answers
        // for private-address reverse-mapping names."
        AssertNegative(await Ask(server, Name, RawDnsType.PTR), Name);

    }

    #endregion

    #region A_Private_Address_Reverse_Name_Above_A_Served_Name_Is_NoData(Name)

    [Test]
    [Property("RFC", "6761 §6.1")]
    [Property("RFC", "8020 §2")]
    [TestCase("1.168.192.in-addr.arpa.")]
    [TestCase("168.192.in-addr.arpa.")]
    public async Task A_Private_Address_Reverse_Name_Above_A_Served_Name_Is_NoData(String Name)
    {

        // The server serves a PTR at 5.1.168.192.in-addr.arpa. The names above
        // it get a negative answer, and NXDOMAIN would deny the PTR with them.
        var response = await Ask(server, Name, RawDnsType.PTR);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero,  $"NODATA for {Name}: not refused (5), and not NXDOMAIN (3) above {ServedPrivatePtr}");
            Assert.That(response.Answers, Is.Empty, "and no answer");
            AssertCitesAnSoa(response, Name);
        });

    }

    #endregion


    // Finding 106: .onion names (RFC 7686 §2, items 5 and 6)

    #region An_Onion_Name_Is_NXDOMAIN(Name, Type)

    [Test]
    [Property("RFC", "7686 §2")]
    [TestCase("onion.",                    RawDnsType.A)]
    [TestCase("hiddenservice.onion.",      RawDnsType.A)]
    [TestCase("www.hiddenservice.onion.",  RawDnsType.AAAA)]
    [TestCase("a.b.ONION.",                RawDnsType.TXT)]
    public async Task An_Onion_Name_Is_NXDOMAIN(String Name, UInt16 Type)
    {

        // RFC 7686 §2 item 5: "Authoritative servers MUST respond to queries
        // for .onion with NXDOMAIN."
        var response = await Ask(server, Name, Type);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.EqualTo(3), $"{Name} is NXDOMAIN (3), not refused (5)");
            Assert.That(response.Answers, Is.Empty,      "and has no answer");
            AssertCitesAnSoa(response, Name);
        });

    }

    #endregion

    #region A_Configured_Record_Does_Not_Make_An_Onion_Name_Exist()

    [Test]
    [Property("RFC", "7686 §2")]
    public async Task A_Configured_Record_Does_Not_Make_An_Onion_Name_Exist()
    {

        // Item 5 has no exception for a configured record, and item 6 says
        // "Operators MUST NOT configure an authoritative DNS server to answer
        // queries for .onion". The zone holds 192.0.2.99 at host.onion.
        var response = await Ask(configured, "host.onion.", RawDnsType.A);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.EqualTo(3), "host.onion. is NXDOMAIN (3) with a record configured at it");
            Assert.That(response.Answers, Is.Empty,      "and the configured record is not served");
            AssertCitesAnSoa(response, "host.onion.");
        });

    }

    #endregion


    // Finding 108: the link-local names of Multicast DNS (RFC 6762 §22.1, item 5)

    #region A_Link_Local_Name_Is_NXDOMAIN(Name, Type)

    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "6762 §22.1")]
    [TestCase("printer.local.",             RawDnsType.A)]
    [TestCase("local.",                     RawDnsType.A)]
    [TestCase("_ipp._tcp.LOCAL.",           RawDnsType.PTR)]
    [TestCase("4.3.254.169.in-addr.arpa.",  RawDnsType.PTR)]
    [TestCase("1.8.e.f.ip6.arpa.",          RawDnsType.PTR)]
    [TestCase("F.B.E.F.IP6.ARPA.",          RawDnsType.PTR)]
    public async Task A_Link_Local_Name_Is_NXDOMAIN(String Name, UInt16 Type)
    {

        // §22.1 item 5: "like caching DNS servers, SHOULD generate immediate
        // NXDOMAIN responses for all such queries they may receive."
        var response = await Ask(server, Name, Type);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.EqualTo(3), $"{Name} is NXDOMAIN (3), not refused (5)");
            Assert.That(response.Answers, Is.Empty,      "and has no answer");
            AssertCitesAnSoa(response, Name);
        });

    }

    #endregion

    #region A_Configured_Link_Local_Name_Is_Not_Served_By_Default()

    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "6762 §22.1")]
    public async Task A_Configured_Link_Local_Name_Is_Not_Served_By_Default()
    {

        // §22.1 item 5: "Authoritative DNS servers SHOULD NOT by default be
        // configurable to answer queries for these names". The zone holds
        // 192.0.2.100 at printer.local., and the server is in its default
        // configuration.
        var response = await Ask(configured, "printer.local.", RawDnsType.A);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.EqualTo(3), "printer.local. is NXDOMAIN (3) with a record configured at it");
            Assert.That(response.Answers, Is.Empty,      "and the configured record is not served");
            AssertCitesAnSoa(response, "printer.local.");
        });

    }

    #endregion


    // Guards: what is served, and what is not special

    #region A_Served_Private_Address_Reverse_Name_Is_Answered()

    [Test]
    [Property("RFC", "6761 §6.1")]
    public async Task A_Served_Private_Address_Reverse_Name_Is_Answered()
    {

        // "unless explicitly configured by the administrator to give positive
        // answers": a PTR the server holds is that configuration.
        var response = await Ask(server, ServedPrivatePtr, RawDnsType.PTR);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero,              "NOERROR");
            Assert.That(response.Answers, Has.Count.EqualTo(1), "the PTR that is served");
            if (response.Answers.Count == 1)
                Assert.That(response.Answers[0].Type, Is.EqualTo(RawDnsType.PTR));
        });

    }

    #endregion

    #region A_Name_Beside_The_Special_Ones_Is_Refused(Name)

    [Test]
    [Property("RFC", "6761 §6.5")]
    [Property("RFC", "9476 §3.2")]
    [Property("RFC", "6762 §22.1")]
    [Property("RFC", "1034 §4.3.2")]
    [TestCase("example.")]
    [TestCase("www.example.org.")]
    [TestCase("localhost.example.com.")]
    [TestCase("host.invalid.example.com.")]
    [TestCase("test.example.com.")]
    [TestCase("mylocalhost.")]
    [TestCase("invalidity.")]
    [TestCase("tests.")]
    [TestCase("onions.")]
    [TestCase("onion.example.com.")]
    [TestCase("name.alt.")]
    [TestCase("local.example.")]
    [TestCase("notlocal.")]
    [TestCase("255.169.in-addr.arpa.")]
    [TestCase("1.1254.169.in-addr.arpa.")]
    [TestCase("c.e.f.ip6.arpa.")]
    [TestCase("18.e.f.ip6.arpa.")]
    [TestCase("11.in-addr.arpa.")]
    [TestCase("15.172.in-addr.arpa.")]
    [TestCase("32.172.in-addr.arpa.")]
    [TestCase("016.172.in-addr.arpa.")]
    [TestCase("169.192.in-addr.arpa.")]
    [TestCase("168.193.in-addr.arpa.")]
    [TestCase("10.ip6.arpa.")]
    public async Task A_Name_Beside_The_Special_Ones_Is_Refused(String Name)
    {

        // §6.5 item 5: "Authoritative DNS servers SHOULD NOT recognize example
        // names as special." RFC 9476 §3.2 item 5 says the same of .alt names.
        // The others only look like special names: a
        // special name is one whose last labels are the special ones, and
        // "016" is not the label "16".
        var response = await Ask(server, Name, RawDnsType.A);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.EqualTo(5), $"{Name} is outside every served zone and not special: REFUSED");
            Assert.That(response.Answers, Is.Empty,      "and nothing is answered");
        });

    }

    #endregion

}

using NUnit.Framework;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 4592 — wildcard *matching*, as opposed to the wildcard owner name.
/// </summary>
/// <remarks>
/// <para>
/// Storing a record whose owner name begins with <c>*</c> is easy and proves
/// nothing. What RFC 4592 is about is the lookup: which queries a wildcard is
/// allowed to answer, and — the part implementations get wrong — which ones it
/// is not.
/// </para>
/// <para>
/// Everything here is observed through raw sockets against a real Hermod
/// server. No Hermod client is involved, so the answers are read by a parser
/// that shares no code with the one that wrote them.
/// </para>
/// </remarks>
[TestFixture]
public class ServerWildcardTests
{

    private HermodServerFixture server = null!;

    [OneTimeSetUp]
    public async Task StartServer()
    {
        server = await HermodServerFixture.StartAsync(
                     new HermodServerFixtureOptions {
                         Zone = ZoneFixtures.CreateWildcardZone()
                     }
                 );
    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        await server.DisposeAsync();
    }


    private async Task<RawDnsMessage> Ask(String name, UInt16 type, UInt16 id = 0x4592)
    {

        var raw = await RawDnsProbe.UdpAsync(server.UdpPort, RawDnsWriter.Query(id, name, type));

        Assert.That(raw, Is.Not.Null, $"the server must answer a query for {name}");

        return RawDnsReader.Parse(raw!);

    }


    #region Wildcard_Synthesizes_For_A_Name_That_Does_Not_Exist()

    [Test]
    [Property("RFC", "4592 §3.3.1")]
    public async Task Wildcard_Synthesizes_For_A_Name_That_Does_Not_Exist()
    {

        var response = await Ask("anything.wild.test.", RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.Zero, "a wildcard match is NOERROR, not NXDOMAIN");
            Assert.That(response.AA,      Is.True, "the data is this server's own");
            Assert.That(response.Answers, Has.Count.EqualTo(1));

            Assert.That(response.Answers[0].Rdata,
                        Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.WildcardAddress)),
                        "the RDATA comes from the wildcard record");

            // §3.3.1: "the owner name of the answer RR is set to the QNAME".
            // A resolver caches what it is told, so a response carrying the
            // literal '*' would populate caches under a name nobody queried.
            Assert.That(response.Answers[0].Name.Canonical,
                        Is.EqualTo("anything.wild.test"),
                        "the answer must carry the queried name, never the wildcard label");

            Assert.That(response.Wire, Does.Not.Contain((Byte) '*'),
                        "the asterisk must not appear anywhere in the response");

        });

    }

    #endregion

    #region Wildcard_Matches_More_Than_One_Label_Below_Itself()

    [Test]
    [Property("RFC", "4592 §3.3.1")]
    public async Task Wildcard_Matches_More_Than_One_Label_Below_Itself()
    {

        // "b.wild.test." does not exist, so the closest encloser of
        // "a.b.wild.test." is the apex and "*.wild.test." is the source of
        // synthesis. A wildcard is not restricted to one label below itself —
        // it covers everything under its parent that has no closer encloser.
        var response = await Ask("a.b.wild.test.", RawDnsType.A);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero);
            Assert.That(response.Answers, Has.Count.EqualTo(1));
            Assert.That(response.Answers[0].Rdata, Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.WildcardAddress)));
            Assert.That(response.Answers[0].Name.Canonical, Is.EqualTo("a.b.wild.test"));
        });

    }

    #endregion

    #region An_Exact_Match_Beats_The_Wildcard()

    [Test]
    [Property("RFC", "4592 §3.3.1")]
    public async Task An_Exact_Match_Beats_The_Wildcard()
    {

        var response = await Ask(ZoneFixtures.WildExactName, RawDnsType.A);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero);
            Assert.That(response.Answers, Has.Count.EqualTo(1));
            Assert.That(response.Answers[0].Rdata,
                        Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.WildExactAddress)),
                        "a name that exists is answered from its own records");
        });

    }

    #endregion

    #region Wildcard_Does_Not_Reach_Past_The_Closest_Encloser()

    [Test]
    [Property("RFC", "4592 §3.3.1")]
    public async Task Wildcard_Does_Not_Reach_Past_The_Closest_Encloser()
    {

        // The one that catches naive implementations. "sub.wild.test." exists,
        // so it is the closest encloser of "nothing.sub.wild.test." and the only
        // wildcard allowed to answer is "*.sub.wild.test.", which is not in the
        // zone. "*.wild.test." is higher up and must not be reached for.
        //
        // A server that instead walks upward taking the first wildcard it finds
        // answers 192.0.2.100 here, and thereby serves data for a subtree the
        // zone administrator never delegated to that wildcard.
        var response = await Ask(ZoneFixtures.WildBelowExact, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.EqualTo(3),
                        "NXDOMAIN: no wildcard exists at the closest encloser");

            Assert.That(response.Answers, Is.Empty);

            Assert.That(response.Authorities.Any(rr => rr.Type == RawDnsType.SOA), Is.True,
                        "RFC 2308 §3: a negative answer cites the SOA so it can be cached");

        });

    }

    #endregion

    #region Wildcard_Does_Not_Apply_To_An_Empty_Non_Terminal()

    [Test]
    [Property("RFC", "4592 §2.2.2")]
    public async Task Wildcard_Does_Not_Apply_To_An_Empty_Non_Terminal()
    {

        // "empty.wild.test." holds no records at all, but "x.empty.wild.test."
        // does — which makes the shorter name an empty non-terminal. §2.2.2: it
        // exists. Existence is what blocks the wildcard, not having records, so
        // this is NODATA and emphatically not 192.0.2.100.
        var response = await Ask(ZoneFixtures.WildEmptyName, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.Zero,
                        "the name exists, so this is NOERROR rather than NXDOMAIN");

            Assert.That(response.Answers, Is.Empty,
                        "…and it holds no A record, so no wildcard may fill in for it");

            Assert.That(response.Authorities.Any(rr => rr.Type == RawDnsType.SOA), Is.True);

        });

    }

    #endregion

    #region Empty_Non_Terminal_Still_Answers_For_Names_Below_It()

    [Test]
    [Property("RFC", "4592 §2.2.2")]
    public async Task Empty_Non_Terminal_Still_Answers_For_Names_Below_It()
    {

        var response = await Ask(ZoneFixtures.WildBelowEmpty, RawDnsType.TXT);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero);
            Assert.That(response.Answers, Has.Count.EqualTo(1));
            Assert.That(response.Answers[0].Type, Is.EqualTo(RawDnsType.TXT));
        });

    }

    #endregion

    #region Wildcard_Match_Without_The_Queried_Type_Is_NoData()

    [Test]
    [Property("RFC", "4592 §3.3.1")]
    public async Task Wildcard_Match_Without_The_Queried_Type_Is_NoData()
    {

        // The wildcard holds A and MX. A query for AAAA matches the *name* and
        // finds no type: NOERROR with an empty answer, not NXDOMAIN. Getting the
        // RCODE wrong here teaches every resolver in the path that the whole
        // name is absent.
        var response = await Ask("anything.wild.test.", RawDnsType.AAAA);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero, "NODATA, not NXDOMAIN");
            Assert.That(response.Answers, Is.Empty);
            Assert.That(response.Authorities.Any(rr => rr.Type == RawDnsType.SOA), Is.True);
        });

    }

    #endregion

    #region Wildcard_Serves_Every_Type_It_Holds()

    [Test]
    [Property("RFC", "4592 §3.3.1")]
    public async Task Wildcard_Serves_Every_Type_It_Holds()
    {

        var response = await Ask("anything.wild.test.", RawDnsType.MX);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero);
            Assert.That(response.Answers, Has.Count.EqualTo(1));
            Assert.That(response.Answers[0].Type,           Is.EqualTo(RawDnsType.MX));
            Assert.That(response.Answers[0].Name.Canonical, Is.EqualTo("anything.wild.test"));
        });

    }

    #endregion

    #region Delegation_Yields_A_Referral_Without_The_AA_Bit()

    [Test]
    [Property("RFC", "1034 §4.3.2")]
    public async Task Delegation_Yields_A_Referral_Without_The_AA_Bit()
    {

        var response = await Ask("host.child.wild.test.", RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.Zero,   "a referral is NOERROR");
            Assert.That(response.Answers, Is.Empty,  "step 3b answers with NS records, not with data");

            Assert.That(response.AA,      Is.False,
                        "AA covers the QNAME, and the QNAME belongs to the child zone");

            var nameServers = response.Authorities.Where(rr => rr.Type == RawDnsType.NS).ToArray();

            Assert.That(nameServers, Has.Length.EqualTo(1), "the child's NS records go in the authority section");
            Assert.That(nameServers[0].Name.Canonical, Is.EqualTo("child.wild.test"),
                        "owned by the delegation point, not by the queried name");

            // RFC 1034 §4.2.1: an address inside the delegated subtree is
            // unreachable without glue, because finding it would require asking
            // the very server whose address is wanted.
            var glue = response.Additionals.Where(rr => rr.Type == RawDnsType.A).ToArray();

            Assert.That(glue, Has.Length.EqualTo(1), "glue travels in the additional section");
            Assert.That(glue[0].Name.Canonical, Is.EqualTo("ns1.child.wild.test"));
            Assert.That(glue[0].Rdata, Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.WildChildGlue)));

            // The wildcard sits above the zone cut, and a zone cut ends the
            // search. It must not synthesize an answer for a delegated name.
            Assert.That(response.Answers.Any(rr => rr.Rdata.SequenceEqual(RawDnsWriter.IPv4(ZoneFixtures.WildcardAddress))),
                        Is.False,
                        "the wildcard must not reach below a delegation");

        });

    }

    #endregion

    #region The_Delegated_Name_Itself_Is_Also_A_Referral()

    [Test]
    [Property("RFC", "1034 §4.3.2")]
    public async Task The_Delegated_Name_Itself_Is_Also_A_Referral()
    {

        // The NS records live at the delegation point, so a query *for* that name
        // could look like an exact match. It is not: the child zone owns the name,
        // and the parent may only point at it.
        var response = await Ask(ZoneFixtures.WildDelegation, RawDnsType.A);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero);
            Assert.That(response.Answers, Is.Empty);
            Assert.That(response.AA,      Is.False);
            Assert.That(response.Authorities.Any(rr => rr.Type == RawDnsType.NS), Is.True);
        });

    }

    #endregion

    #region Apex_NS_Records_Are_Not_A_Delegation_To_Itself()

    [Test]
    [Property("RFC", "1034 §4.2.1")]
    public async Task Apex_NS_Records_Are_Not_A_Delegation_To_Itself()
    {

        // Every zone has NS records at its own apex. Treating those as a zone cut
        // turns the whole zone into a referral to itself and nothing is ever
        // answered — so the delegation search has to start *below* the apex.
        var response = await Ask(ZoneFixtures.WildNameServer, RawDnsType.A);

        Assert.Multiple(() => {
            Assert.That(response.AA,      Is.True, "the apex and everything under it is authoritative data");
            Assert.That(response.Answers, Has.Count.EqualTo(1));
            Assert.That(response.Answers[0].Rdata, Is.EqualTo(RawDnsWriter.IPv4("192.0.2.53")));
        });

    }

    #endregion

    #region Negative_Answer_Cites_The_Zone_Apex_Soa()

    [Test]
    [Property("RFC", "2308 §3")]
    public async Task Negative_Answer_Cites_The_Zone_Apex_Soa()
    {

        var response = await Ask(ZoneFixtures.WildBelowExact, RawDnsType.A);
        var soa      = response.Authorities.SingleOrDefault(rr => rr.Type == RawDnsType.SOA);

        Assert.Multiple(() => {

            Assert.That(soa, Is.Not.Null,
                        "without an SOA a resolver has no negative TTL and must not cache the answer at all");

            Assert.That(soa!.Name.Canonical, Is.EqualTo("wild.test"),
                        "the SOA of the zone that is authoritative for the name");

            Assert.That(response.Answers, Is.Empty);

        });

    }

    #endregion

}

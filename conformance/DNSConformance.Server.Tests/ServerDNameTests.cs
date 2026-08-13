using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 6672 — DNAME redirection, as a server has to perform it.
/// </summary>
/// <remarks>
/// <para>
/// A DNAME is a CNAME for a subtree. The record shape has been covered here for
/// a while; what had not been is the part RFC 6672 is actually about — which
/// names the redirection applies to, what the answer has to carry, and what a
/// server says when the rewritten name will not fit in a domain name.
/// </para>
/// <para>
/// The interesting requirements are all negative. §2.3 leaves the DNAME's own
/// owner name unredirected, so a zone can hold a DNAME and an MX at the same
/// name and both mean something. §2.4 forbids records below the owner, so a
/// record found there must lose to the redirection rather than win. §2.2 answers
/// an oversized substitution with YXDOMAIN rather than NXDOMAIN, because the
/// name is refused, not absent — and a resolver told NXDOMAIN would cache the
/// absence of the whole subtree.
/// </para>
/// <para>
/// Everything is observed through raw sockets and read by the independent RawDns
/// parser.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "6672")]
public class ServerDNameTests
{

    private HermodServerFixture server = null!;

    [OneTimeSetUp]
    public async Task StartServer()
    {
        server = await HermodServerFixture.StartAsync(
                     new HermodServerFixtureOptions {
                         Zone                      = ZoneFixtures.CreateDNameZone(),
                         SharePortAcrossTransports = true
                     }
                 );
    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        await server.DisposeAsync();
    }


    /// <summary>
    /// Ask over UDP, and follow RFC 7766 §5 to TCP when the answer does not fit.
    /// A DNAME chain grows the answer section by two records a step, so the
    /// pathological cases below genuinely need the retry.
    /// </summary>
    private async Task<RawDnsMessage> Ask(String name, UInt16 type, UInt16 id = 0x6672)
    {

        var query     = RawDnsWriter.Query(id, name, type);
        var datagram  = await RawDnsProbe.UdpAsync(server.UdpPort, query);

        Assert.That(datagram, Is.Not.Null, $"the server must answer a query for {name}");

        var response  = RawDnsReader.Parse(datagram!);

        if (!response.TC)
            return response;

        var stream = await RawDnsProbe.TcpAsync(server.TcpPort, query);

        Assert.That(stream, Is.Not.Null, $"a truncated answer for {name} must be retrievable over TCP");

        return RawDnsReader.Parse(stream!);

    }

    private static RawRecord? Single(RawDnsMessage Response, UInt16 Type)
        => Response.Answers.SingleOrDefault(record => record.Type == Type);


    #region A_Name_Below_The_Dname_Is_Redirected()

    [Test]
    [Property("RFC", "6672 §2.2")]
    [Property("RFC", "6672 §3.1")]
    public async Task A_Name_Below_The_Dname_Is_Redirected()
    {

        var response = await Ask(ZoneFixtures.DNameQueried, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.EqualTo(0));
            Assert.That(response.AA,    Is.True, "a DNAME answer is authoritative — the server owns the redirection");

        });

        var dname = Single(response, RawDnsType.DNAME);
        var cname = Single(response, RawDnsType.CNAME);
        var a     = Single(response, RawDnsType.A);

        Assert.Multiple(() => {

            // §3.1: "a server performing a DNAME substitution will, in all cases,
            // include the relevant DNAME RR in the answer section".
            Assert.That(dname, Is.Not.Null, "the DNAME itself must be in the answer");
            Assert.That(dname!.Name.Canonical, Is.EqualTo(ZoneFixtures.DNameOwner.TrimEnd('.')));

            // §3.1: the synthesized CNAME, owned by the queried name.
            Assert.That(cname, Is.Not.Null, "the synthesized CNAME must be in the answer");
            Assert.That(cname!.Name.Canonical, Is.EqualTo(ZoneFixtures.DNameQueried.TrimEnd('.')));

            // And the query restarted at the rewritten name.
            Assert.That(a, Is.Not.Null, "the rewritten name is in this zone, so its data completes the answer");
            Assert.That(a!.Name.Canonical, Is.EqualTo(ZoneFixtures.DNameResolved.TrimEnd('.')));
            Assert.That(a.Rdata,           Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.DNameAddress)));

        });

    }

    #endregion

    #region The_Synthesized_Cname_Points_At_The_Substituted_Name()

    [Test]
    [Property("RFC", "6672 §2.2")]
    public async Task The_Synthesized_Cname_Points_At_The_Substituted_Name()
    {

        var response = await Ask(ZoneFixtures.DNameQueried, RawDnsType.A);
        var cname    = Single(response, RawDnsType.CNAME);

        Assert.That(cname, Is.Not.Null);

        // The substitution replaces the suffix and keeps the prefix. Read the
        // CNAME's target back out of the wire rather than trusting a rendering.
        var target = RawDnsReader.ReadNameAt(response.Wire, cname!.RdataOffset).Name;

        Assert.That(target.Canonical, Is.EqualTo(ZoneFixtures.DNameResolved.TrimEnd('.')),
                    "host.alias → host.target: the labels above the owner are carried over unchanged");

    }

    #endregion

    #region The_Whole_Prefix_Is_Carried_Over()

    [Test]
    [Property("RFC", "6672 §2.2")]
    public async Task The_Whole_Prefix_Is_Carried_Over()
    {

        // Three labels above the owner, not one. A substitution that only moved
        // the leftmost label would answer a.b.c.alias with a.target.
        var response = await Ask(ZoneFixtures.DNameDeepQueried, RawDnsType.A);
        var a        = Single(response, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(a, Is.Not.Null);
            Assert.That(a!.Name.Canonical, Is.EqualTo(ZoneFixtures.DNameDeepResolved.TrimEnd('.')));
            Assert.That(a.Rdata,           Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.DNameDeepAddress)));

        });

    }

    #endregion

    #region The_Synthesized_Cname_Carries_The_Dnames_Ttl()

    [Test]
    [Property("RFC", "6672 §3.1")]
    public async Task The_Synthesized_Cname_Carries_The_Dnames_Ttl()
    {

        // This is where RFC 6672 changed RFC 2672. The older specification
        // synthesized the CNAME with TTL 0, so nothing could cache a redirection
        // longer than the record that caused it; §3.1 now equates the two and
        // requires resolvers to accept either. A test that pins the value has to
        // say which document it is reading, and this one reads 6672.
        var response = await Ask(ZoneFixtures.DNameQueried, RawDnsType.A);

        var dname    = Single(response, RawDnsType.DNAME);
        var cname    = Single(response, RawDnsType.CNAME);

        Assert.Multiple(() => {

            Assert.That(dname, Is.Not.Null);
            Assert.That(cname, Is.Not.Null);
            Assert.That(cname!.Ttl, Is.EqualTo(dname!.Ttl),
                        "RFC 6672 §3.1: the synthesized CNAME's TTL equals the DNAME's");

        });

    }

    #endregion

    #region The_Dname_Owner_Itself_Is_Not_Redirected()

    [Test]
    [Property("RFC", "6672 §2.3")]
    public async Task The_Dname_Owner_Itself_Is_Not_Redirected()
    {

        // §2.3: "the owner name of a DNAME is not redirected itself". This is the
        // whole difference from a CNAME — an alias owns nothing else, a DNAME
        // owner can, and here it owns an MX.
        var response = await Ask(ZoneFixtures.DNameOwner, RawDnsType.MX);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.EqualTo(0));

            Assert.That(response.Answers.Any(record => record.Type == RawDnsType.MX), Is.True,
                        "the MX at the DNAME's own name is an ordinary answer");

            Assert.That(response.Answers.Any(record => record.Type == RawDnsType.CNAME), Is.False,
                        "nothing was redirected, so there is nothing for a synthesized CNAME to say");

        });

    }

    #endregion

    #region The_Dname_Owner_Answers_A_Dname_Query_With_Data()

    [Test]
    [Property("RFC", "6672 §2.3")]
    public async Task The_Dname_Owner_Answers_A_Dname_Query_With_Data()
    {

        var response = await Ask(ZoneFixtures.DNameOwner, RawDnsType.DNAME);
        var dname    = Single(response, RawDnsType.DNAME);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.EqualTo(0));
            Assert.That(dname, Is.Not.Null, "asking a DNAME owner for its DNAME returns the record, not a redirection");
            Assert.That(dname!.Name.Canonical, Is.EqualTo(ZoneFixtures.DNameOwner.TrimEnd('.')));

            Assert.That(response.Answers.Any(record => record.Type == RawDnsType.CNAME), Is.False);

        });

    }

    #endregion

    #region The_Dname_Owner_With_No_Such_Type_Is_NoData()

    [Test]
    [Property("RFC", "6672 §2.3")]
    [Property("RFC", "2308 §3")]
    public async Task The_Dname_Owner_With_No_Such_Type_Is_NoData()
    {

        // There is no A at the DNAME's owner name. Since the owner is not
        // redirected, that is plain NODATA — not a redirection, and not NXDOMAIN.
        var response = await Ask(ZoneFixtures.DNameOwner, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.EqualTo(0), "the name exists");
            Assert.That(response.Answers, Is.Empty);

            Assert.That(response.Authorities.Any(record => record.Type == RawDnsType.SOA), Is.True,
                        "a negative answer carries the SOA (RFC 2308 §3)");

        });

    }

    #endregion

    #region A_Name_Beside_The_Dname_Is_Untouched()

    [Test]
    [Property("RFC", "6672 §2.3")]
    public async Task A_Name_Beside_The_Dname_Is_Untouched()
    {

        var response = await Ask(ZoneFixtures.DNameSibling, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.Answers, Has.Count.EqualTo(1));
            Assert.That(response.Answers.Single().Rdata, Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.DNameSiblingAddr)));

        });

    }

    #endregion

    #region A_Record_Below_The_Dname_Owner_Is_Occluded()

    [Test]
    [Property("RFC", "6672 §2.4")]
    public async Task A_Record_Below_The_Dname_Owner_Is_Occluded()
    {

        // §2.4: "Resource records MUST NOT exist at any subdomain of the owner of
        // a DNAME RR." The zone here breaks that on purpose, and the redirection
        // has to win — a server that answered from the occluded record would let
        // a malformed zone quietly override the rule its own DNAME states, and
        // the name would resolve differently depending on which of the two the
        // lookup happened to reach first.
        var response = await Ask(ZoneFixtures.DNameOccluded, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.Answers.Any(record => record.Type == RawDnsType.DNAME), Is.True,
                        "the redirection applies to the whole subtree, occupied or not");

            Assert.That(
                response.Answers.Any(record => record.Type  == RawDnsType.A &&
                                               record.Rdata.SequenceEqual(RawDnsWriter.IPv4(ZoneFixtures.DNameOccludedAddr))),
                Is.False,
                "the occluded record must not be served"
            );

        });

    }

    #endregion

    #region A_Dname_Out_Of_The_Zone_Redirects_And_Stops()

    [Test]
    [Property("RFC", "6672 §2.2")]
    public async Task A_Dname_Out_Of_The_Zone_Redirects_And_Stops()
    {

        // The ordinary case: the target is somewhere this server knows nothing
        // about. The answer is the redirection and no more, and the resolver
        // carries on from the CNAME — exactly as it would at the end of a CNAME
        // chain that leaves the zone.
        var response = await Ask("host." + ZoneFixtures.DNameForeignOwner, RawDnsType.A);

        var cname    = Single(response, RawDnsType.CNAME);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.EqualTo(0), "the redirection succeeded, so this is not NXDOMAIN");
            Assert.That(Single(response, RawDnsType.DNAME), Is.Not.Null);
            Assert.That(cname, Is.Not.Null);
            Assert.That(response.Answers.Any(record => record.Type == RawDnsType.A), Is.False);

        });

        Assert.That(RawDnsReader.ReadNameAt(response.Wire, cname!.RdataOffset).Name.Canonical,
                    Is.EqualTo("host." + ZoneFixtures.DNameForeign.TrimEnd('.')));

    }

    #endregion

    #region An_Oversized_Substitution_Is_YXDOMAIN()

    [Test]
    [Property("RFC", "6672 §2.2")]
    public async Task An_Oversized_Substitution_Is_YXDOMAIN()
    {

        // The target is 245 octets on the wire, so a prefix label of ten
        // characters — one length octet plus ten — lands on 256.
        var response = await Ask(new String('x', 10) + "." + ZoneFixtures.DNameLongOwner, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.EqualTo(6),
                        "RFC 6672 §2.2: an oversized substitution is YXDOMAIN (6). NXDOMAIN would tell the " +
                        "resolver the name does not exist, and it would cache the absence of the whole subtree.");

            // §2.2: "The DNAME record and its signature (if the zone is signed)
            // are included in the answer as proof for the YXDOMAIN ... RCODE."
            Assert.That(Single(response, RawDnsType.DNAME), Is.Not.Null,
                        "the DNAME travels along as the proof of why the name could not be built");

            Assert.That(response.Answers.Any(record => record.Type == RawDnsType.CNAME), Is.False,
                        "there is no rewritten name, so there is nothing for a CNAME to point at");

        });

    }

    #endregion

    #region A_Substitution_Of_Exactly_255_Octets_Still_Fits()

    [Test]
    [Property("RFC", "6672 §2.2")]
    [Property("RFC", "1035 §2.3.4")]
    public async Task A_Substitution_Of_Exactly_255_Octets_Still_Fits()
    {

        // One character less, and the rewritten name is exactly 255 octets — the
        // largest a domain name may be. The pair pins the boundary to the octet:
        // an off-by-one either way turns one of these two tests red.
        var response = await Ask(new String('x', 9) + "." + ZoneFixtures.DNameLongOwner, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.EqualTo(0), "255 octets is legal, so the substitution must succeed");
            Assert.That(Single(response, RawDnsType.CNAME), Is.Not.Null);

        });

    }

    #endregion

    #region A_Dname_Into_Its_Own_Subtree_Terminates()

    [Test]
    [Property("RFC", "6672 §2.2")]
    public async Task A_Dname_Into_Its_Own_Subtree_Terminates()
    {

        // loop.dname.test. DNAME sub.loop.dname.test. rewrites every name it
        // touches into a longer one below itself, so the chain never repeats a
        // name and loop detection by memory cannot end it. It does terminate at
        // the 255-octet limit — after some sixty passes — which is a poor reason
        // to keep going. What matters here is that the server answers at all,
        // and bounded.
        var answered = Task.Run(() => Ask("x." + ZoneFixtures.DNameLoopOwner, RawDnsType.A));

        Assert.That(await Task.WhenAny(answered, Task.Delay(TimeSpan.FromSeconds(10))), Is.SameAs(answered),
                    "a self-referential DNAME must not hang the server");

        var response = await answered;

        Assert.That(response.Answers.Count(record => record.Type == RawDnsType.DNAME), Is.LessThan(32),
                    "the chain has to be cut, and cut early enough that the answer is still an answer");

    }

    #endregion

    #region The_Question_Is_Echoed_Unrewritten()

    [Test]
    [Property("RFC", "1035 §4.1.2")]
    public async Task The_Question_Is_Echoed_Unrewritten()
    {

        // The server rewrote the name it was resolving, not the name it was
        // asked about. A resolver matches the response against its outstanding
        // query by the question section, and would discard this one if the
        // substitution had leaked into it.
        var response = await Ask(ZoneFixtures.DNameQueried, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.Questions, Has.Count.EqualTo(1));
            Assert.That(response.Questions[0].Name.Canonical, Is.EqualTo(ZoneFixtures.DNameQueried.TrimEnd('.')));
            Assert.That(response.Questions[0].Type,           Is.EqualTo(RawDnsType.A));

        });

    }

    #endregion

}

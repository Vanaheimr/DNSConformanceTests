using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 1034 §4.3.2 and RFC 2181 §10.1 — what an authoritative server does when
/// the queried name is an alias.
///
/// The rule that surprises people is that a CNAME answers *every* query type at
/// that name. A server that only returns a CNAME when CNAME was asked for will
/// hand out NXDOMAIN for perfectly resolvable names.
/// </summary>
[TestFixture]
public class ServerCnameTests
{

    private HermodServerFixture server = null!;

    [OneTimeSetUp]
    public async Task StartServer()
    {
        server = await HermodServerFixture.StartAsync();
    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        await server.DisposeAsync();
    }


    private async Task<RawDnsMessage> AskAsync(UInt16 id, String name, UInt16 type)
    {

        var raw = await RawDnsProbe.UdpAsync(server.UdpPort, RawDnsWriter.Query(id, name, type));

        Assert.That(raw, Is.Not.Null, $"server must answer a {type} query for {name}");

        return RawDnsReader.Parse(raw!);

    }


    #region Query_For_A_At_An_Alias_Returns_The_Cname()

    [Test]
    [Property("RFC", "1034 §4.3.2")]
    public async Task Query_For_A_At_An_Alias_Returns_The_Cname()
    {

        // RFC 1034 §4.3.2 step 3a: when the node holds a CNAME and QTYPE is not
        // CNAME, the server copies the CNAME into the answer and restarts the
        // query at the canonical name. Returning NOERROR with an empty answer
        // instead would tell the resolver the name genuinely has no A record.
        var response = await AskAsync(0xC001, ZoneFixtures.CNameAlias, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.Zero, "an alias resolves; it is not an NXDOMAIN");

            Assert.That(response.Answers.Any(rr => rr.Type == RawDnsType.CNAME),
                        Is.True,
                        () => $"the CNAME must be in the answer section even though A was asked for; " +
                              $"got RCODE={response.RCode} with {response.Answers.Count} answer(s)");

            // The restart at the canonical name must also produce the data that
            // was asked for — the whole point of the rule is that the client does
            // not have to come back.
            Assert.That(response.Answers.Any(rr => rr.Type == RawDnsType.A),
                        Is.True,
                        "the A record behind the alias must be appended");

        });

    }

    #endregion

    #region Query_For_The_Cname_Type_Returns_The_Cname()

    [Test]
    [Property("RFC", "1034 §3.6.2")]
    public async Task Query_For_The_Cname_Type_Returns_The_Cname()
    {

        var response = await AskAsync(0xC002, ZoneFixtures.CNameAlias, RawDnsType.CNAME);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero);
            Assert.That(response.Answers, Is.Not.Empty);
            Assert.That(response.Answers.All(rr => rr.Type == RawDnsType.CNAME), Is.True);
        });

    }

    #endregion

    #region Alias_Node_Carries_No_Data_Of_Its_Own()

    [Test]
    [Property("RFC", "2181 §10.1")]
    public async Task Alias_Node_Carries_No_Data_Of_Its_Own()
    {

        // RFC 2181 §10.1: "a CNAME record is not allowed to coexist with any other
        // data" (DNSSEC records excepted). So whatever the server returns for an
        // alias, no RRset *owned by the alias* may be anything but a CNAME — the
        // records reached by following the chain have the canonical owner name.
        foreach (var type in new[] { RawDnsType.A, RawDnsType.AAAA, RawDnsType.MX, RawDnsType.TXT })
        {

            var response = await AskAsync(0xC003, ZoneFixtures.CNameAlias, type);

            var ownedByTheAlias = response.Answers.
                                      Where(rr => rr.Name.Canonical.Equals(
                                                      ZoneFixtures.CNameAlias.TrimEnd('.'),
                                                      StringComparison.OrdinalIgnoreCase)).
                                      ToArray();

            Assert.That(ownedByTheAlias.Select(rr => rr.Type),
                        Is.All.EqualTo(RawDnsType.CNAME),
                        $"querying {type} produced non-CNAME data at the alias itself");

        }

    }

    #endregion

    #region Chained_Alias_Resolves_Or_Refers()

    [Test]
    [Property("RFC", "1034 §3.6.2")]
    public async Task Chained_Alias_Resolves_Or_Refers()
    {

        // CNameAlias2 -> CNameAlias -> AName. Every link is in this zone, so an
        // authoritative server can and should follow the whole chain rather than
        // making the resolver come back twice.
        var response = await AskAsync(0xC004, ZoneFixtures.CNameAlias2, RawDnsType.A);

        Assert.That(response.Answers, Is.Not.Empty,
                    "a chained alias must produce at least the first CNAME");

        var first = response.Answers[0];

        Assert.Multiple(() => {

            Assert.That(first.Type, Is.EqualTo(RawDnsType.CNAME),
                        "the chain must start at the queried name");

            Assert.That(first.Name.Canonical,
                        Is.EqualTo(ZoneFixtures.CNameAlias2.TrimEnd('.')).IgnoreCase);

            Assert.That(response.Answers.Count(rr => rr.Type == RawDnsType.CNAME), Is.EqualTo(2),
                        "both links of the chain belong in the answer");

            Assert.That(response.Answers.Any(rr => rr.Type == RawDnsType.A),
                        Is.True,
                        () => "the chain must end at the A record; got " +
                              String.Join(" | ", response.Answers.Select(rr => $"{rr.Name.Canonical} {rr.Type}")));

        });

    }

    #endregion

    #region Unknown_Type_At_An_Alias_Still_Returns_The_Cname()

    [Test]
    [Property("RFC", "1034 §4.3.2")]
    public async Task Unknown_Type_At_An_Alias_Still_Returns_The_Cname()
    {

        // TYPE 65280 is in the private-use range and certainly not in the zone.
        // The CNAME rule is about the *node*, not about which types it knows, so
        // an alias must answer here too rather than reporting NODATA.
        var response = await AskAsync(0xC005, ZoneFixtures.CNameAlias, 65280);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.Zero, "still not an error");

            Assert.That(response.Answers.Any(rr => rr.Type == RawDnsType.CNAME),
                        Is.True,
                        "the alias must be reported regardless of the queried type");

        });

    }

    #endregion

    #region Cname_Loop_Does_Not_Hang_The_Server()

    [Test]
    [Property("RFC", "1034 §4.3.2")]
    [Category(TestCategories.Slow)]
    public async Task Cname_Loop_Does_Not_Hang_The_Server()
    {

        // RFC 1034 §4.3.2 note: "the amount of work which a name server will do
        // in response to a query" must be bounded, and a CNAME chain is where an
        // unbounded loop is easiest to write by accident. A zone that points two
        // aliases at each other is malformed, but a server must survive being
        // handed one — and must still answer the next client.
        var loopZone = new InMemoryDNSZone().Add(
                           new CNAME(
                               DomainName.Parse("loop-a.conformance.test."),
                               DNSQueryClasses.IN,
                               TimeSpan.FromMinutes(5),
                               DomainName.Parse("loop-b.conformance.test.")
                           ),
                           new CNAME(
                               DomainName.Parse("loop-b.conformance.test."),
                               DNSQueryClasses.IN,
                               TimeSpan.FromMinutes(5),
                               DomainName.Parse("loop-a.conformance.test.")
                           )
                       );

        await using var looping = await HermodServerFixture.StartAsync(
                                            new HermodServerFixtureOptions { Zone = loopZone }
                                        );

        var raw = await RawDnsProbe.UdpAsync(
                            looping.UdpPort,
                            RawDnsWriter.Query(0xC006, "loop-a.conformance.test.", RawDnsType.A)
                        );

        Assert.That(raw, Is.Not.Null, "a cyclic chain must still produce an answer, not a hang");

        var response = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.Zero);

            // Each link may appear once. A server that kept walking would repeat
            // them until it hit its depth limit.
            Assert.That(response.Answers, Has.Count.EqualTo(2),
                        () => "expected each link exactly once; got " +
                              String.Join(" | ", response.Answers.Select(rr => $"{rr.Name.Canonical} {rr.Type}")));

            Assert.That(response.Answers.All(rr => rr.Type == RawDnsType.CNAME), Is.True);

        });

    }

    #endregion

}

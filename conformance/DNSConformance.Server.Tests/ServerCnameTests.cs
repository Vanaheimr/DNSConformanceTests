using NUnit.Framework;

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
    [Category(TestCategories.KnownIssue)]
    public async Task Query_For_A_At_An_Alias_Returns_The_Cname()
    {

        // RFC 1034 §4.3.2 step 3a: when the node holds a CNAME and QTYPE is not
        // CNAME, the server copies the CNAME into the answer and restarts the
        // query at the canonical name.
        //
        // Hermod's authoritative handler matches on owner *and* type, so an alias
        // answers only a CNAME query. Everything else comes back NOERROR with an
        // empty answer — which tells the resolver the name genuinely has no A
        // record, and the alias silently stops working.
        var response = await AskAsync(0xC001, ZoneFixtures.CNameAlias, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.Zero, "an alias resolves; it is not an NXDOMAIN");

            Assert.That(response.Answers.Any(rr => rr.Type == RawDnsType.CNAME),
                        Is.True,
                        () => $"the CNAME must be in the answer section even though A was asked for; " +
                              $"got RCODE={response.RCode} with {response.Answers.Count} answer(s)");

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
    [Category(TestCategories.KnownIssue)]
    public async Task Chained_Alias_Resolves_Or_Refers()
    {

        // CNameAlias2 -> CNameAlias -> AName. RFC 1034 lets the server either
        // follow the chain and append what it finds, or hand back the first CNAME
        // and let the resolver come back. Both are conformant; what would not be
        // is answering nothing at all.
        var response = await AskAsync(0xC004, ZoneFixtures.CNameAlias2, RawDnsType.A);

        Assert.That(response.Answers, Is.Not.Empty,
                    "a chained alias must produce at least the first CNAME");

        var first = response.Answers[0];

        Assert.Multiple(() => {

            Assert.That(first.Type, Is.EqualTo(RawDnsType.CNAME),
                        "the chain must start at the queried name");

            Assert.That(first.Name.Canonical,
                        Is.EqualTo(ZoneFixtures.CNameAlias2.TrimEnd('.')).IgnoreCase);

            TestContext.Out.WriteLine(
                "chain returned: " +
                String.Join(" | ", response.Answers.Select(rr => $"{rr.Name.Canonical} {rr.Type}"))
            );

        });

    }

    #endregion

    #region Unknown_Type_At_An_Alias_Still_Returns_The_Cname()

    [Test]
    [Property("RFC", "1034 §4.3.2")]
    [Category(TestCategories.KnownIssue)]
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

}

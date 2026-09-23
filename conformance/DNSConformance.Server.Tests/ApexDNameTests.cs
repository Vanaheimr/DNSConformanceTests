using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 6672 §2.3 — a DNAME at the zone apex, which is the one place a DNAME and
/// an NS RRset may share an owner name.
/// </summary>
/// <remarks>
/// <para>
/// "DNAME RRs MUST NOT appear at the same owner name as an NS RR unless the
/// owner name is the zone apex." Every DNAME in this suite so far has sat below
/// the apex, which is the ordinary case and also the easy one: the walk up from
/// QNAME looking for a DNAME ancestor finds it well before it runs out of
/// labels. At the apex it is the *last* candidate the walk will ever consider,
/// and a bound one step short loses it and nothing else.
/// </para>
/// <para>
/// A zone that fails this way fails silently and completely. The apex DNAME is
/// the whole point of such a zone — it exists to mirror a name space somewhere
/// else — and a server that cannot see it answers every query below the apex as
/// though the redirection were not there.
/// </para>
/// <para>
/// The same section draws the other line: "Such a DNAME cannot be used to mirror
/// a zone completely, as it does not mirror the zone apex", and the SOA and NS
/// are still needed there. So the apex answers for itself and redirects
/// everything under it, and both halves are asserted here — a walk that started
/// one step *too high* would pass the first and fail the second.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "6672 §2.3")]
public class ApexDNameTests
{

    #region Data

    private const String Mirror  = "mirror.test";
    private const String Target  = "elsewhere.example";

    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private HermodServerFixture server = null!;

    #endregion

    [OneTimeSetUp]
    public async Task StartServer()
    {
        server = await HermodServerFixture.StartAsync(
                           new HermodServerFixtureOptions { Zone = ZoneWithAnApexDName() });
    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (server is not null)
            await server.DisposeAsync();
    }


    #region A_Dname_At_The_Apex_Redirects_Everything_Below_It()

    [Test]
    [Property("RFC", "6672 §2.3, §3.1")]
    public async Task A_Dname_At_The_Apex_Redirects_Everything_Below_It()
    {

        var response = await Ask($"host.{Mirror}.", RawDnsType.A);

        var dname = response.Answers.SingleOrDefault(rr => rr.Type == RawDnsType.DNAME);
        var cname = response.Answers.SingleOrDefault(rr => rr.Type == RawDnsType.CNAME);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.Zero, "a redirection is not an error");

            // §3.1: "a server performing a DNAME substitution will, in all cases,
            // include the relevant DNAME RR in the answer section".
            Assert.That(dname, Is.Not.Null,
                        "the apex DNAME is an ancestor of the queried name like any other");

            Assert.That(dname?.Name.Canonical, Is.EqualTo(Mirror));

            Assert.That(cname, Is.Not.Null, "and the CNAME it synthesizes");
            Assert.That(cname?.Name.Canonical, Is.EqualTo($"host.{Mirror}"));

        });

    }

    #endregion

    #region A_Dname_At_The_Apex_Does_Not_Redirect_The_Apex_Itself()

    [Test]
    [Property("RFC", "6672 §2.3")]
    public async Task A_Dname_At_The_Apex_Does_Not_Redirect_The_Apex_Itself()
    {

        // "Such a DNAME cannot be used to mirror a zone completely, as it does
        // not mirror the zone apex." The owner of a DNAME is never redirected by
        // it — §2.3 says so for every DNAME — and at the apex that is what keeps
        // the SOA and the NS reachable, without which the zone cannot be served
        // at all.
        var soa = await Ask($"{Mirror}.", RawDnsType.SOA);
        var a   = await Ask($"{Mirror}.", RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(soa.RCode,   Is.Zero);
            Assert.That(soa.Answers.Any(rr => rr.Type == RawDnsType.SOA),   Is.True,
                        "the apex still answers for itself");
            Assert.That(soa.Answers.Any(rr => rr.Type == RawDnsType.CNAME), Is.False,
                        "and is not redirected by its own DNAME");

            // No A at the apex, and no redirection either: the name exists and
            // the type does not, which is NODATA.
            Assert.That(a.RCode,   Is.Zero);
            Assert.That(a.Answers, Is.Empty);
            Assert.That(a.Authorities.Any(rr => rr.Type == RawDnsType.SOA), Is.True,
                        "NODATA at the apex, with the SOA RFC 2308 asks for");

        });

    }

    #endregion


    #region Zone

    /// <summary>
    /// SOA, NS and a DNAME, all at the apex and nothing below it.
    /// </summary>
    /// <remarks>
    /// The name server is deliberately outside the zone. §2.4 forbids records at
    /// any subdomain of a DNAME's owner, and with the DNAME at the apex that is
    /// the whole zone — so a glue record for an in-zone name server would be the
    /// one thing this zone may not hold.
    /// </remarks>
    private static InMemoryDNSZone ZoneWithAnApexDName()
    {

        var apex = DomainName.Parse($"{Mirror}.");
        var zone = new InMemoryDNSZone();

        zone.Add(

            new SOA(
                apex,
                DNSQueryClasses.IN,
                Ttl,
                DomainName.Parse($"ns.{Target}."),
                SimpleEMailAddress.Parse($"hostmaster@{Mirror}"),
                2026092301,
                TimeSpan.FromHours(2),
                TimeSpan.FromHours(1),
                TimeSpan.FromDays(14),
                TimeSpan.FromMinutes(5)
            ),

            new NS   (apex, DNSQueryClasses.IN, Ttl, DomainName.Parse($"ns.{Target}.")),

            new DNAME(apex, DNSQueryClasses.IN, Ttl, DomainName.Parse($"{Target}."))

        );

        return zone;

    }

    #endregion

    #region Ask

    private async Task<RawDnsMessage> Ask(String Name, UInt16 Type)
    {

        var query    = RawDnsWriter.Query(0x6672, Name, Type);
        var datagram = await RawDnsProbe.UdpAsync(server.UdpPort, query);

        Assert.That(datagram, Is.Not.Null, $"the server must answer a query for {Name}");

        var response = RawDnsReader.Parse(datagram!);

        if (!response.TC)
            return response;

        var stream = await RawDnsProbe.TcpAsync(server.TcpPort, query);

        Assert.That(stream, Is.Not.Null, $"a truncated answer for {Name} must be retrievable over TCP");

        return RawDnsReader.Parse(stream!);

    }

    #endregion

}

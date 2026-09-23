using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 6891 §6.2.3 and §6.1.1 — the exact edge of the requestor's buffer, and
/// what a response that had to shed everything still has to carry.
/// </summary>
/// <remarks>
/// <para>
/// §6.2.3 defines the advertised payload size as "the number of octets of the
/// largest UDP payload that can be reassembled and delivered in the requestor's
/// network stack". A message of exactly that many octets is therefore one the
/// requestor can take — the boundary belongs on the inside. A responder that
/// reads the limit as exclusive truncates an answer that would have arrived, and
/// sends the client to TCP for nothing; nothing about the result looks wrong,
/// which is why one off-by-one here can live a long time.
/// </para>
/// <para>
/// The suite already asks whether an oversized answer is truncated. That
/// question is satisfied by a response of any size at all as long as TC is set,
/// so it says nothing about where the edge is or about what survives the
/// shedding.
/// </para>
/// <para>
/// Every size here is measured rather than computed. The tests ask once to learn
/// what the server produces, then ask again advertising exactly that many
/// octets — so the assertions hold whatever the records happen to encode to, and
/// no arithmetic in this file can drift away from the wire.
/// </para>
/// </remarks>
[TestFixture]
public class TruncationBoundaryTests
{

    #region Data

    private const String Zone   = "trunc.test";
    private const String One    = "one.trunc.test";
    private const String Three  = "three.trunc.test";

    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private HermodServerFixture server = null!;

    #endregion

    [OneTimeSetUp]
    public async Task StartServer()
    {
        server = await HermodServerFixture.StartAsync(
                           new HermodServerFixtureOptions { Zone = ZoneOfLargeTexts() });
    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (server is not null)
            await server.DisposeAsync();
    }


    #region A_Response_Of_Exactly_The_Advertised_Size_Is_Sent_Whole()

    [Test]
    [Property("RFC", "6891 §6.2.3")]
    public async Task A_Response_Of_Exactly_The_Advertised_Size_Is_Sent_Whole()
    {

        // What the answer weighs when nothing constrains it.
        var whole = await Ask($"{One}.", RawDnsType.TXT, 4096);

        Assert.Multiple(() => {
            Assert.That(whole.Parsed.TC, Is.False, "4096 octets is room enough");
            Assert.That(whole.Bytes.Length, Is.GreaterThan(512),
                        "the fixture has to be larger than the floor of §6.2.3, or the limit clamps to 512");
        });

        // Now say the buffer is exactly that size. "The largest UDP payload that
        // can be reassembled and delivered" includes the payload of that length.
        var exact = await Ask($"{One}.", RawDnsType.TXT, (UInt16) whole.Bytes.Length);

        Assert.Multiple(() => {

            Assert.That(exact.Parsed.TC, Is.False,
                        $"a {whole.Bytes.Length}-octet answer fits a {whole.Bytes.Length}-octet buffer");

            Assert.That(exact.Bytes.Length, Is.EqualTo(whole.Bytes.Length),
                        "and arrives whole");

            Assert.That(exact.Parsed.Answers, Is.Not.Empty);

        });

    }

    #endregion

    #region Every_Step_Of_The_Truncation_Keeps_The_Same_Edge()

    [Test]
    [Property("RFC", "6891 §6.2.3")]
    public async Task Every_Step_Of_The_Truncation_Keeps_The_Same_Edge()
    {

        // The edge is consulted twice: once for the whole answer, and once for
        // each shortened one the server tries on the way down. The test above
        // pins the first. This pins the second, which needs an answer that is
        // shed a record at a time rather than all at once.
        var whole = await Ask($"{Three}.", RawDnsType.TXT, 4096);

        Assert.That(whole.Parsed.TC,      Is.False);
        Assert.That(whole.Parsed.Answers, Has.Count.GreaterThan(1),
                    "the fixture needs several records for there to be steps at all");

        // One octet short of the whole thing, so the server has to shed.
        var shed = await Ask($"{Three}.", RawDnsType.TXT, (UInt16) (whole.Bytes.Length - 1));

        Assert.Multiple(() => {
            Assert.That(shed.Parsed.TC,      Is.True,  "something had to go");
            Assert.That(shed.Parsed.Answers, Is.Not.Empty,
                        "but not everything: what fits is kept");
            Assert.That(shed.Parsed.Answers, Has.Count.LessThan(whole.Parsed.Answers.Count));
        });

        // And now exactly what that shortened answer weighs. The server built
        // this very message a moment ago and measured it against a larger
        // allowance; measured against its own length it must still pass.
        var exact = await Ask($"{Three}.", RawDnsType.TXT, (UInt16) shed.Bytes.Length);

        TestContext.Out.WriteLine(
            $"whole {whole.Bytes.Length} octets / {whole.Parsed.Answers.Count} answers, " +
            $"shed {shed.Bytes.Length} / {shed.Parsed.Answers.Count}, " +
            $"exact {exact.Bytes.Length} / {exact.Parsed.Answers.Count}");

        Assert.That(exact.Parsed.Answers, Has.Count.EqualTo(shed.Parsed.Answers.Count),
                    $"a {shed.Bytes.Length}-octet answer fits a {shed.Bytes.Length}-octet buffer, " +
                     "so the same records survive");

    }

    #endregion

    #region An_Answer_That_Sheds_Everything_Still_Carries_Its_Opt()

    [Test]
    [Property("RFC", "6891 §6.1.1")]
    public async Task An_Answer_That_Sheds_Everything_Still_Carries_Its_Opt()
    {

        // §6.1.1: responders "MUST include an OPT record in their respective
        // responses" — there is no exception for the case where the answer had to
        // be emptied. A truncated reply without an OPT tells the client the
        // server does not speak EDNS at all, which is a different and worse
        // statement than "come back over TCP": the retry may then be made without
        // EDNS, and a DNSSEC-aware client loses the DO bit it needs.
        var response = await Ask($"{One}.", RawDnsType.TXT, 512);

        Assert.Multiple(() => {

            Assert.That(response.Parsed.TC,      Is.True,  "one large record cannot fit 512 octets");
            Assert.That(response.Parsed.Answers, Is.Empty, "and there is no smaller subset to keep");

            Assert.That(response.Parsed.Opt, Is.Not.Null,
                        "the OPT is not an answer record and is not what had to go");

        });

    }

    #endregion


    #region Zone

    /// <summary>
    /// One name with a single oversized text record, and one with several — so a
    /// response can be shed all at once or a record at a time.
    /// </summary>
    private static InMemoryDNSZone ZoneOfLargeTexts()
    {

        var apex = DomainName.Parse($"{Zone}.");
        var zone = new InMemoryDNSZone();

        zone.Add(

            new SOA(
                apex,
                DNSQueryClasses.IN,
                Ttl,
                DomainName.Parse($"ns.{Zone}."),
                SimpleEMailAddress.Parse($"hostmaster@{Zone}"),
                2026092301,
                TimeSpan.FromHours(2),
                TimeSpan.FromHours(1),
                TimeSpan.FromDays(14),
                TimeSpan.FromMinutes(5)
            ),

            new NS (apex, DNSQueryClasses.IN, Ttl, DomainName.Parse($"ns.{Zone}.")),
            new A  (DomainName.Parse($"ns.{Zone}."), DNSQueryClasses.IN, Ttl, IPv4Address.Parse("192.0.2.53")),

            // Larger than 512 on its own, so the only subset that fits is none.
            new TXT(DomainName.Parse($"{One}."),   DNSQueryClasses.IN, Ttl, new String('o', 600)),

            // Three of about three hundred octets each: the whole set does not
            // fit a small buffer, two of them might, one of them will.
            new TXT(DomainName.Parse($"{Three}."), DNSQueryClasses.IN, Ttl, new String('a', 300)),
            new TXT(DomainName.Parse($"{Three}."), DNSQueryClasses.IN, Ttl, new String('b', 300)),
            new TXT(DomainName.Parse($"{Three}."), DNSQueryClasses.IN, Ttl, new String('c', 300))

        );

        return zone;

    }

    #endregion

    #region Ask

    private async Task<(Byte[] Bytes, RawDnsMessage Parsed)> Ask(String  Name,
                                                                UInt16  Type,
                                                                UInt16  PayloadSize)
    {

        var query = RawDnsWriter.Query(0x6891, Name, Type, ednsPayloadSize: PayloadSize);
        var raw   = await RawDnsProbe.UdpAsync(server.UdpPort, query);

        Assert.That(raw, Is.Not.Null, $"the server must answer a query for {Name}");

        return (raw!, RawDnsReader.Parse(raw!));

    }

    #endregion

}

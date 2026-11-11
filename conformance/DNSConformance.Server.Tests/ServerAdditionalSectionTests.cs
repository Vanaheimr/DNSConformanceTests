using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 2230 §3.1 — the additional section processing a KX answer causes, and
/// RFC 2181 §9's rule for what happens when its results do not fit.
/// </summary>
/// <remarks>
/// <para>
/// "KX records MUST cause type A additional section processing for the host
/// specified by EXCHANGER. In the event that the host processing the DNS
/// transaction supports IPv6, KX records MUST also cause type AAAA additional
/// section processing." Additional section processing is RFC 1034 §4.3.2's step
/// 6: "Using local data only, attempt to add other RRs which may be useful". So
/// the addresses come from the zones this server holds, and a name it holds no
/// addresses for adds nothing.
/// </para>
/// <para>
/// Additional data is optional in a way answers are not. RFC 2181 §9: "The TC bit
/// should not be set merely because some extra information could have been
/// included, but there was insufficient room. This includes the results of
/// additional section processing. In such cases the entire RRSet that will not
/// fit in the response should be omitted, and the reply sent as is, with the TC
/// bit clear."
/// </para>
/// <para>
/// Everything is observed through raw sockets and read by the independent RawDns
/// parser.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "2230 §3.1")]
public class ServerAdditionalSectionTests
{

    #region Data

    private const String Origin = "additional.test.";

    /// <summary>
    /// Three exchangers with labels long enough that their addresses cannot all
    /// fit beside the three KX records in a 512-octet datagram, while the KX
    /// records alone can.
    /// </summary>
    private static readonly String[] LongExchangers = [
        "exchanger-one-with-a-label-long-enough-to-crowd-a-datagram",
        "exchanger-two-with-a-label-long-enough-to-crowd-a-datagram",
        "exchanger-tri-with-a-label-long-enough-to-crowd-a-datagram"
    ];

    private static String ZoneText()

        => $$"""
             $ORIGIN {{Origin}}
             $TTL 3600
             @         IN  SOA   ns1 hostmaster 2026111101 7200 3600 1209600 300
             @         IN  NS    ns1
             ns1       IN  A     192.0.2.53

             host      IN  KX    10 kx1
             kx1       IN  A     192.0.2.10
             kx1       IN  AAAA  2001:db8::10

             v4only    IN  KX    10 kx4
             kx4       IN  A     192.0.2.11

             two       IN  KX    10 kx1
             two       IN  KX    20 kx4

             outside   IN  KX    10 kx.elsewhere.example.

             noaddr    IN  KX    10 textonly
             textonly  IN  TXT   "a name with no address"

             many      IN  KX    10 {{LongExchangers[0]}}
             many      IN  KX    20 {{LongExchangers[1]}}
             many      IN  KX    30 {{LongExchangers[2]}}
             {{LongExchangers[0]}}  IN  A     192.0.2.21
             {{LongExchangers[0]}}  IN  AAAA  2001:db8::21
             {{LongExchangers[1]}}  IN  A     192.0.2.22
             {{LongExchangers[1]}}  IN  AAAA  2001:db8::22
             {{LongExchangers[2]}}  IN  A     192.0.2.23
             {{LongExchangers[2]}}  IN  AAAA  2001:db8::23
             """;

    private HermodServerFixture  server  = null!;
    private DNSSECSigningKey     ksk     = null!;
    private DNSSECSigningKey     zsk     = null!;

    [OneTimeSetUp]
    public async Task StartServer()
    {

        // Signed, so that the DO bit has something to ask for. A query without it
        // sees the zone exactly as if it were not (RFC 4035 §3.2.1).
        ksk = DNSSECSigningKey.Generate(DomainName.Parse(Origin), 13, KeySigningKey: true);
        zsk = DNSSECSigningKey.Generate(DomainName.Parse(Origin), 13);

        var zone = new InMemoryDNSZone().
                       Add(DNSZoneFile.Parse(ZoneText(), DomainName.Parse(Origin))).
                       Sign([ ksk, zsk ]);

        server = await HermodServerFixture.StartAsync(
                     new HermodServerFixtureOptions {
                         Zone = zone
                     }
                 );

    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        await server.DisposeAsync();
        ksk.Dispose();
        zsk.Dispose();
    }


    private async Task<RawDnsMessage> AskKX(String Label, UInt16? EdnsPayloadSize = null, Boolean DnssecOk = false)
    {

        var raw = await RawDnsProbe.UdpAsync(
                            server.UdpPort,
                            RawDnsWriter.Query(0x2230, Label + "." + Origin, RawDnsType.KX,
                                               ednsPayloadSize: EdnsPayloadSize, dnssecOk: DnssecOk)
                        );

        Assert.That(raw, Is.Not.Null, $"the server must answer a KX query for {Label}");

        var response = RawDnsReader.Parse(raw!);

        Assert.That(response.Answers.Count(rr => rr.Type == RawDnsType.KX), Is.GreaterThan(0),
                    $"{Label} holds KX records, so they are the answer");

        return response;

    }

    private static String Owner(RawRecord Record)
        => Record.Name.ToString().TrimEnd('.').ToLowerInvariant();

    /// <summary>The A and AAAA records of the additional section, as "owner type".</summary>
    private static String[] Addresses(RawDnsMessage Response)

        => [.. Response.Additionals.
                   Where (rr => rr.Type is RawDnsType.A or RawDnsType.AAAA).
                   Select(rr => $"{Owner(rr)} {(rr.Type == RawDnsType.A ? "A" : "AAAA")}").
                   Order ()];

    #endregion


    #region A_Kx_Answer_Carries_The_Exchangers_A_And_AAAA()

    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Kx_Answer_Carries_The_Exchangers_A_And_AAAA()
    {

        var response = await AskKX("host");

        Assert.Multiple(() => {

            Assert.That(Addresses(response), Is.EqualTo(new[] { "kx1.additional.test A", "kx1.additional.test AAAA" }),
                        "§3.1: type A and, for a host that supports IPv6, type AAAA additional section processing");

            Assert.That(response.TC, Is.False);

            // RFC 4035 §3.2.1: no DO bit, no DNSSEC records anywhere.
            Assert.That(response.Additionals.Any(rr => rr.Type == RawDnsType.RRSIG), Is.False);

        });

    }

    #endregion

    #region An_Exchanger_With_Only_An_A_Brings_Only_The_A()

    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task An_Exchanger_With_Only_An_A_Brings_Only_The_A()
    {

        Assert.That(Addresses(await AskKX("v4only")), Is.EqualTo(new[] { "kx4.additional.test A" }));

    }

    #endregion

    #region Every_Exchanger_Of_The_Rrset_Is_Processed()

    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task Every_Exchanger_Of_The_Rrset_Is_Processed()
    {

        // Two KX records, two exchangers: the processing is per record, not per
        // answer, and the preferred one is not the only one a client may need.
        Assert.That(Addresses(await AskKX("two")),
                    Is.EqualTo(new[] { "kx1.additional.test A", "kx1.additional.test AAAA", "kx4.additional.test A" }));

    }

    #endregion

    #region With_The_DO_Bit_The_Addresses_Come_With_Their_Signatures()

    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "4035 §3.1.1")]
    public async Task With_The_DO_Bit_The_Addresses_Come_With_Their_Signatures()
    {

        // RFC 4035 §3.1.1: "When placing a signed RRset in the Additional section,
        // the name server MUST also place its RRSIG RRs in the Additional section."
        var response   = await AskKX("host", EdnsPayloadSize: 4096, DnssecOk: true);

        var signatures = response.Additionals.
                             Where (rr => rr.Type == RawDnsType.RRSIG && Owner(rr) == "kx1.additional.test").
                             Select(rr => (UInt16) ((rr.Rdata[0] << 8) | rr.Rdata[1])).
                             Order ().
                             ToArray();

        Assert.Multiple(() => {
            Assert.That(Addresses(response), Is.EqualTo(new[] { "kx1.additional.test A", "kx1.additional.test AAAA" }));
            Assert.That(signatures,          Is.EqualTo(new[] { RawDnsType.A, RawDnsType.AAAA }),
                        "one RRSIG over each of the two address RRsets");
        });

    }

    #endregion


    #region An_Exchanger_Outside_The_Zone_Adds_Nothing()

    [Test]
    public async Task An_Exchanger_Outside_The_Zone_Adds_Nothing()
    {

        // "Using local data only": this server holds nothing at
        // kx.elsewhere.example., and has no business asking anyone else.
        Assert.That(Addresses(await AskKX("outside")), Is.Empty);

    }

    #endregion

    #region An_Exchanger_Without_Addresses_Adds_Nothing()

    [Test]
    public async Task An_Exchanger_Without_Addresses_Adds_Nothing()
    {

        // The name exists and holds a TXT, which is not what §3.1 asks for.
        var response = await AskKX("noaddr");

        Assert.Multiple(() => {
            Assert.That(Addresses(response), Is.Empty);
            Assert.That(response.Additionals.Any(rr => rr.Type == RawDnsType.TXT), Is.False);
        });

    }

    #endregion

    #region Addresses_That_Do_Not_Fit_Are_Left_Out_And_TC_Stays_Clear()

    [Test]
    [Property("RFC", "2181 §9")]
    public async Task Addresses_That_Do_Not_Fit_Are_Left_Out_And_TC_Stays_Clear()
    {

        // Without EDNS the datagram holds 512 octets (RFC 1035 §4.2.1). The three
        // KX records fit; their six address records do not fit beside them. §9:
        // whole RRsets of additional data are left out, TC stays clear, and the
        // answer is sent complete — a resolver that wants the rest asks for it.
        var response = await AskKX("many");

        Assert.Multiple(() => {

            Assert.That(response.Wire.Length, Is.LessThanOrEqualTo(512));

            Assert.That(response.TC, Is.False,
                        "TC is not set merely because additional data did not fit");

            Assert.That(response.Answers.Count(rr => rr.Type == RawDnsType.KX), Is.EqualTo(3),
                        "the answer goes out whole");

            Assert.That(Addresses(response).All(address => LongExchangers.Any(exchanger => address.StartsWith(exchanger + "."))),
                        Is.True,
                        "whatever additional data remains belongs to the exchangers asked about");

        });

    }

    #endregion

}

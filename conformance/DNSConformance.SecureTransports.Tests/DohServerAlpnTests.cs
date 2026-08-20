using System.Net;

using NUnit.Framework;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.SecureTransports.Tests;

/// <summary>
/// One port serving both versions of HTTP, with ALPN choosing — the shape a DoH
/// deployment on 443 actually has.
/// </summary>
/// <remarks>
/// <para>
/// RFC 8484 §5 requires the https scheme and §5.2 recommends HTTP/2, but it does
/// not say what to do about the clients that cannot speak it. TLS answers that:
/// RFC 9113 §3.2 requires ALPN to select <c>h2</c>, and a client offers whatever
/// it has in the same handshake. A server that advertises both lets each client
/// bring what it can, and a server that advertises only what it will serve never
/// strands one that could have been served.
/// </para>
/// <para>
/// <c>DohServerTests</c> asserts the RFC 8484 requirements on each version
/// separately. What is left to check is the negotiation itself, and the property
/// that makes it safe: which protocol was chosen must not change the answer.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "9113 §3.2")]
public class DohServerAlpnTests
{

    #region Alpn_Serves_Both_Versions_On_One_Port()

    [Test]
    [Property("RFC", "8484 §5.2, 9113 §3.2")]
    public async Task Alpn_Serves_Both_Versions_On_One_Port()
    {

        await using var server = await HermodDoHFixture.StartAsync(
                                           new HermodDoHFixtureOptions {
                                               Secured  = true,
                                               HTTP2    = true
                                           }
                                       );

        // One query, sent twice. Two separately built ones would differ in the
        // transaction ID, and the comparison below would be measuring that.
        var query = RawDnsWriter.Query(0x9113, ZoneFixtures.AName, RawDnsType.A);

        using var overH2  = RawDoHProbe.NewHttpClient();
        using var overH11 = RawDoHProbe.NewHttpClient();

        var h2  = await RawDoHProbe.PostAsync(server.Url, query, HTTPClient: overH2,  Version: HttpVersion.Version20);
        var h11 = await RawDoHProbe.PostAsync(server.Url, query, HTTPClient: overH11, Version: HttpVersion.Version11);

        TestContext.Out.WriteLine($"h2:       {RawDoHProbe.Describe(h2)}");
        TestContext.Out.WriteLine($"http/1.1: {RawDoHProbe.Describe(h11)}");

        Assert.Multiple(() => {

            Assert.That(h2. Version, Is.EqualTo(HttpVersion.Version20),
                        "a client offering h2 is given h2");

            Assert.That(h11.Version, Is.EqualTo(HttpVersion.Version11),
                        "and one that cannot is served anyway, rather than failing the handshake");

            Assert.That(h2. Status, Is.EqualTo(200), () => RawDoHProbe.Describe(h2));
            Assert.That(h11.Status, Is.EqualTo(200), () => RawDoHProbe.Describe(h11));

            // The negotiation picks the framing. RFC 8484 §4 is about the
            // message, and nothing in it depends on which framing carried it.
            Assert.That(h11.Body,      Is.EqualTo(h2.Body),
                        "ALPN chooses the framing, never the answer");

            Assert.That(h11.MediaType, Is.EqualTo(h2.MediaType));
            Assert.That(h11.MaxAge,    Is.EqualTo(h2.MaxAge));

        });

    }

    #endregion

    #region Alpn_Answer_Decodes_The_Same_Either_Way()

    [Test]
    [Property("RFC", "8484 §4.2")]
    public async Task Alpn_Answer_Decodes_The_Same_Either_Way()
    {

        // The byte comparison above would also pass if both versions were equally
        // wrong, so this reads each answer with the suite's own codec and checks
        // it against the zone rather than against its sibling.
        await using var server = await HermodDoHFixture.StartAsync(
                                           new HermodDoHFixtureOptions {
                                               Secured  = true,
                                               HTTP2    = true
                                           }
                                       );

        using var overH2  = RawDoHProbe.NewHttpClient();
        using var overH11 = RawDoHProbe.NewHttpClient();

        foreach (var (name, version, http) in new[] {
                     ("h2",       HttpVersion.Version20, overH2),
                     ("http/1.1", HttpVersion.Version11, overH11)
                 })
        {

            var id     = (UInt16) (name == "h2" ? 0x9120 : 0x9121);
            var result = await RawDoHProbe.PostAsync(
                                   server.Url,
                                   RawDnsWriter.Query(id, ZoneFixtures.AName, RawDnsType.A),
                                   HTTPClient:  http,
                                   Version:     version
                               );

            Assert.That(result.Status, Is.EqualTo(200), () => $"{name}: " + RawDoHProbe.Describe(result));

            var response = RawDnsReader.Parse(result.Body);

            Assert.Multiple(() => {
                Assert.That(result.Version,   Is.EqualTo(version),  $"{name}: negotiated");
                Assert.That(response.Id,      Is.EqualTo(id),       $"{name}: the ID is echoed");
                Assert.That(response.QR,      Is.True,              $"{name}: the message is a response");
                Assert.That(response.Answers, Has.Count.EqualTo(1), $"{name}: the question is answered");
                Assert.That(response.Answers[0].Rdata,
                            Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.AAddress)),
                            $"{name}: with the address the zone holds");
            });

        }

    }

    #endregion

}

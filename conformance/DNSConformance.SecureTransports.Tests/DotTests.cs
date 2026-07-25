using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.SecureTransports.Tests;

/// <summary>
/// RFC 7858 — DNS over TLS. Both directions: Hermod's DoT client against a
/// scripted TLS listener, and Hermod's DoT server against a raw TLS probe.
/// </summary>
[TestFixture]
[Property("RFC", "7858")]
public class DotTests
{

    #region Dot_Client_Uses_Rfc7766_Framing_Over_Tls()

    [Test]
    [Property("RFC", "7858 §3.3")]
    public async Task Dot_Client_Uses_Rfc7766_Framing_Over_Tls()
    {

        // "In order to minimize latency, clients SHOULD pipeline ... All
        //  messages ... follow RFC 7766 framing."
        await using var server = new ScriptedTlsServer(
            request => RawDnsResponder.Answer(request, ("dot.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.53")))
        );

        await using var client = new DNSTLSClient(
                                     IPv4Address.Localhost,
                                     TCPPort:                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:                TimeSpan.FromSeconds(10),
                                     RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success()
                                 );

        var response = await client.Query<A>(DomainName.Parse("dot.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the DoT server received a framed query");

        var decoded = RawDnsReader.Parse(request!);

        Assert.Multiple(() => {
            Assert.That(decoded.Questions.Single().Name.Canonical,     Is.EqualTo("dot.example"),
                        () => "the unframed message did not decode:\n" + Bytes.Dump(request!));
            Assert.That(response.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("192.0.2.53")));
        });

    }

    #endregion

    #region Dot_Client_Reuses_One_Tls_Session_For_Multiple_Queries()

    [Test]
    [Property("RFC", "7858 §3.4")]
    public async Task Dot_Client_Reuses_One_Tls_Session_For_Multiple_Queries()
    {

        // "clients SHOULD reuse [the TLS connection] for multiple DNS queries"
        // — handshaking per query would defeat the latency budget of DoT.
        await using var server = new ScriptedTlsServer(
            request => RawDnsResponder.Answer(request, ("reuse.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.54")))
        );

        await using var client = new DNSTLSClient(
                                     IPv4Address.Localhost,
                                     TCPPort:                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:                TimeSpan.FromSeconds(10),
                                     RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success()
                                 );

        for (var i = 0; i < 3; i++)
        {
            var response = await client.Query<A>(DomainName.Parse("reuse.example."), Timeout: TimeSpan.FromSeconds(10));
            Assert.That(response.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("192.0.2.54")));
        }

        TestContext.Out.WriteLine($"3 DoT queries required {server.HandshakeCount} TLS handshake(s).");

        Assert.Multiple(() => {
            Assert.That(server.Requests,       Has.Count.EqualTo(3));
            Assert.That(server.HandshakeCount, Is.EqualTo(1), "the TLS session SHOULD be reused across queries");
        });

    }

    #endregion

    #region Dot_Client_Honors_A_Rejecting_Certificate_Validator()

    [Test]
    [Property("RFC", "8310 §8.1")]
    public async Task Dot_Client_Honors_A_Rejecting_Certificate_Validator()
    {

        // If authentication fails, the client must not proceed to send the
        // query in the clear or over the unauthenticated session.
        await using var server = new ScriptedTlsServer(
            request => RawDnsResponder.Answer(request, ("reject.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.55")))
        );

        await using var client = new DNSTLSClient(
                                     IPv4Address.Localhost,
                                     TCPPort:                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:                TimeSpan.FromSeconds(5),
                                     RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Failed("rejected by test")
                                 );

        var response = await client.Query<A>(DomainName.Parse("reject.example."), Timeout: TimeSpan.FromSeconds(5));

        Assert.Multiple(() => {
            Assert.That(response.FilteredAnswers, Is.Empty, "a rejected certificate must not yield answers");
            Assert.That(server.Requests,          Is.Empty, "no query may be sent over a rejected TLS session");
        });

    }

    #endregion


    #region Dot_Server_Answers_Over_Tls_With_Correct_Framing()

    [Test]
    [Property("RFC", "7858 §3.3")]
    public async Task Dot_Server_Answers_Over_Tls_With_Correct_Framing()
    {

        // Hermod's own DoT server, probed by a raw TLS client (no Hermod client
        // code involved) so the framing judgment stays independent.
        await using var fixture = await HermodServerFixture.StartAsync(
                                            new HermodServerFixtureOptions {
                                                EnableUdp  = false,
                                                EnableTcp  = false,
                                                EnableTls  = true
                                            }
                                        );

        var request  = RawDnsWriter.Query(0x7858, ZoneFixtures.AName, RawDnsType.A);
        var raw      = await RawTlsProbe.QueryAsync(fixture.TlsPort, request);

        Assert.That(raw, Is.Not.Null, "the DoT server must answer over TLS");

        var response = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(response.Id,      Is.EqualTo((UInt16) 0x7858));
            Assert.That(response.QR,      Is.True);
            Assert.That(response.Answers, Has.Count.EqualTo(1));
            Assert.That(response.Answers[0].Rdata, Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.AAddress)));
        });

    }

    #endregion

    #region Dot_Server_Handles_Multiple_Queries_Per_Session()

    [Test]
    [Property("RFC", "7766 §6.2.1")]
    public async Task Dot_Server_Handles_Multiple_Queries_Per_Session()
    {

        await using var fixture = await HermodServerFixture.StartAsync(
                                            new HermodServerFixtureOptions {
                                                EnableUdp  = false,
                                                EnableTcp  = false,
                                                EnableTls  = true
                                            }
                                        );

        var requests  = new[] {
                            RawDnsWriter.Query(0x7001, ZoneFixtures.AName,     RawDnsType.A),
                            RawDnsWriter.Query(0x7002, ZoneFixtures.QuadAName, RawDnsType.AAAA)
                        };

        var responses = await RawTlsProbe.QueryManyAsync(fixture.TlsPort, requests);

        Assert.Multiple(() => {

            Assert.That(responses, Has.Count.EqualTo(2));

            for (var i = 0; i < responses.Count; i++)
            {
                Assert.That(responses[i], Is.Not.Null, $"query #{i + 1} on the shared TLS session was not answered");
                Assert.That(RawDnsReader.Parse(responses[i]!).Id, Is.EqualTo((UInt16) (0x7001 + i)));
            }

        });

    }

    #endregion

}

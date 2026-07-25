using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 1035 §4.1 / RFC 5452 — what Hermod's UDP client puts on the wire when
/// it issues a query, observed by a scripted server.
/// </summary>
[TestFixture]
public class ClientQueryConstructionTests
{

    private static DNSUDPClient ClientFor(Int32 port)
        => new(
               IPv4Address.Localhost,
               IPPort.Parse((UInt16) port),
               QueryTimeout: TimeSpan.FromSeconds(2)
           );


    #region Client_Sends_Single_Question_With_RD_Set()

    [Test]
    [Property("RFC", "1035 §4.1.2")]
    public async Task Client_Sends_Single_Question_With_RD_Set()
    {

        await using var server = new ScriptedUdpServer(
            request => RawDnsResponder.Answer(request, ("q.example.", RawDnsType.A, 300, [192, 0, 2, 1]))
        );

        await using var client = ClientFor(server.Port);

        _ = await client.Query<A>(DomainName.Parse("q.example."), Timeout: TimeSpan.FromSeconds(2));

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "server received a query");

        var decoded = RawDnsReader.Parse(request!);

        Assert.Multiple(() => {
            Assert.That(decoded.QR,                          Is.False, "QR=0 in a query");
            Assert.That(decoded.Opcode,                      Is.Zero,  "opcode QUERY");
            Assert.That(decoded.RD,                          Is.True,  "RD requested by default");
            Assert.That(decoded.Questions,                   Has.Count.EqualTo(1), "QDCOUNT=1");
            Assert.That(decoded.Questions[0].Name.Canonical, Is.EqualTo("q.example"));
            Assert.That(decoded.Questions[0].Type,           Is.EqualTo(RawDnsType.A));
            Assert.That(decoded.Questions[0].Class,          Is.EqualTo(RawDnsClass.IN));
        });

    }

    #endregion

    #region Client_Uses_Nonzero_Transaction_IDs_That_Vary()

    [Test]
    [Property("RFC", "5452 §9.2")]
    public async Task Client_Uses_Nonzero_Transaction_IDs_That_Vary()
    {

        var ids = new List<UInt16>();

        await using var server = new ScriptedUdpServer(
            request => {
                ids.Add(RawDnsReader.Parse(request).Id);
                return RawDnsResponder.Answer(request, ("id.example.", RawDnsType.A, 300, [192, 0, 2, 1]));
            }
        );

        for (var i = 0; i < 8; i++)
        {
            await using var client = ClientFor(server.Port);
            _ = await client.Query<A>(DomainName.Parse("id.example."), Timeout: TimeSpan.FromSeconds(2), ForceUpdate: true);
        }

        Assert.Multiple(() => {
            Assert.That(ids, Has.Count.EqualTo(8));
            // Not a strict entropy test, but all-identical IDs would defeat
            // RFC 5452 spoofing resistance.
            Assert.That(ids.Distinct().Count(), Is.GreaterThan(1), "transaction IDs must vary between queries");
        });

    }

    #endregion

    #region Client_Accepts_Matching_Response()

    [Test]
    public async Task Client_Accepts_Matching_Response()
    {

        await using var server = new ScriptedUdpServer(
            request => RawDnsResponder.Answer(request, ("ok.example.", RawDnsType.A, 300, [198, 51, 100, 7]))
        );

        await using var client = ClientFor(server.Port);

        var response = await client.Query<A>(DomainName.Parse("ok.example."), Timeout: TimeSpan.FromSeconds(2));

        Assert.Multiple(() => {
            Assert.That(response.ResponseCode,                       Is.EqualTo(DNSResponseCodes.NoError));
            Assert.That(response.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("198.51.100.7")));
        });

    }

    #endregion

    #region Client_Ignores_Response_With_Wrong_Transaction_Id()

    [Test]
    [Property("RFC", "5452 §4.1")]
    public async Task Client_Ignores_Response_With_Wrong_Transaction_Id()
    {

        // The server replies with a forged ID; Hermod must not accept it as the
        // answer to its query.
        await using var server = new ScriptedUdpServer(
            request => RawDnsResponder.WithWrongId(
                           RawDnsResponder.Answer(request, ("spoof.example.", RawDnsType.A, 300, [6, 6, 6, 6]))
                       )
        );

        await using var client = new DNSUDPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout: TimeSpan.FromSeconds(1)
                                 );

        var response = await client.Query<A>(DomainName.Parse("spoof.example."), Timeout: TimeSpan.FromSeconds(1));

        Assert.That(
            response.FilteredAnswers.Any(a => a.IPv4Address == IPv4Address.Parse("6.6.6.6")),
            Is.False,
            "a response whose ID does not match the query MUST NOT be accepted (RFC 5452 §4.1)"
        );

    }

    #endregion

    #region Client_Times_Out_On_Silence_Without_Hanging()

    [Test]
    [Property("RFC", "1035 §4.2.1")]
    public async Task Client_Times_Out_On_Silence_Without_Hanging()
    {

        await using var server = ScriptedUdpServer.Silent();

        await using var client = new DNSUDPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout: TimeSpan.FromMilliseconds(500)
                                 );

        var start     = DateTimeOffset.UtcNow;
        var response  = await client.Query<A>(DomainName.Parse("silent.example."), Timeout: TimeSpan.FromMilliseconds(500));
        var elapsed   = DateTimeOffset.UtcNow - start;

        Assert.Multiple(() => {

            Assert.That(response.IsTimeout || !response.IsValid || !response.FilteredAnswers.Any(),
                        Is.True, "a silent server must surface as timeout/empty, never a hang");

            // Generous upper bound on purpose: this catches a hang, and a tight
            // bound would only turn CPU contention during a parallel test run
            // into a spurious failure.
            Assert.That(elapsed, Is.LessThan(TimeSpan.FromSeconds(15)), "must respect the query timeout");

        });

    }

    #endregion

    #region Client_Survives_Garbage_Response()

    [Test]
    public async Task Client_Survives_Garbage_Response()
    {

        await using var server = new ScriptedUdpServer(
            request => {
                var garbage = new Byte[40];
                Random.Shared.NextBytes(garbage);
                // Keep the ID so it passes the first gate and exercises the parser.
                garbage[0] = request[0];
                garbage[1] = request[1];
                return garbage;
            }
        );

        await using var client = new DNSUDPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout: TimeSpan.FromSeconds(1)
                                 );

        var response = await client.Query<A>(DomainName.Parse("garbage.example."), Timeout: TimeSpan.FromSeconds(1));

        Assert.That(response, Is.Not.Null, "a malformed response must produce a result object, not an unhandled exception");

    }

    #endregion

}

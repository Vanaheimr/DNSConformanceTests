using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// UDP resolver behaviors beyond basic query construction: EDNS advertisement
/// (RFC 6891 §6.2.3) and RFC 5452 spoofing resistance under a response race.
/// </summary>
[TestFixture]
public class UdpClientBehaviorTests
{

    // Loopback round-trips take milliseconds; the budget is this large only so
    // that CPU contention during a parallel test run cannot cause a false red.
    private static readonly TimeSpan ShortTimeout = TimeSpan.FromSeconds(10);


    #region Client_Advertises_Edns0_With_A_Sane_Payload_Size()

    [Test]
    [Property("RFC", "6891 §6.2.3")]
    public async Task Client_Advertises_Edns0_With_A_Sane_Payload_Size()
    {

        await using var server = new ScriptedUdpServer(request =>
            RawDnsResponder.Answer(request, ("edns.example.", RawDnsType.A, 60, RawDnsWriter.IPv4("192.0.2.1"))));

        await using var client = new DNSUDPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout: ShortTimeout
                                 );

        _ = await client.Query<A>(DomainName.Parse("edns.example."), ShortTimeout);

        Assert.That(server.Requests.TryDequeue(out var request), Is.True);

        var edns = RawDnsReader.Parse(request!).Edns;

        Assert.That(edns, Is.Not.Null, "a modern resolver advertises EDNS0 (RFC 6891)");

        TestContext.Out.WriteLine($"advertised UDP payload size: {edns!.PayloadSize}");

        Assert.That(edns.PayloadSize, Is.GreaterThanOrEqualTo(512),
                    "RFC 6891 §6.2.3: values below 512 are treated as 512");

    }

    #endregion

    #region Client_Puts_The_Query_Name_On_The_Wire_With_Its_Case()

    [Test]
    [Property("RFC", "1035 §2.3.3")]
    public async Task Client_Puts_The_Query_Name_On_The_Wire_With_Its_Case()
    {

        await using var server = new ScriptedUdpServer(request =>
            RawDnsResponder.Answer(request, ("MiXeD.ExAmPlE.", RawDnsType.A, 60, RawDnsWriter.IPv4("192.0.2.4"))));

        await using var client = new DNSUDPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout: ShortTimeout
                                 );

        _ = await client.Query<A>(DomainName.Parse("MiXeD.ExAmPlE."), ShortTimeout);

        Assert.That(server.Requests.TryDequeue(out var request), Is.True);

        // Observed by the independent reader on the server side, so this is what
        // actually left the socket — not what Hermod believes it sent.
        var qname = RawDnsReader.Parse(request!).Questions.Single().Name.Presentation;

        Assert.That(qname, Is.EqualTo("MiXeD.ExAmPlE"),
                    "the capitalization the caller chose must survive to the wire");

    }

    #endregion

    #region Response_Echoing_A_Lowercased_Question_Is_Accepted()

    [Test]
    [Property("RFC", "4343")]
    public async Task Response_Echoing_A_Lowercased_Question_Is_Accepted()
    {

        // Plenty of resolvers normalize the QNAME before echoing it. RFC 4343 makes
        // that the same name, so the answer must still be accepted — a client that
        // compared the echoed question byte-for-byte would drop legitimate replies
        // from a large slice of the internet.
        await using var server = new ScriptedUdpServer(request =>
            RawDnsResponder.WithLowercasedQuestion(
                RawDnsResponder.Answer(request, ("mixed.example.", RawDnsType.A, 60, RawDnsWriter.IPv4("192.0.2.5")))));

        await using var client = new DNSUDPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout: ShortTimeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("MiXeD.ExAmPlE."), ShortTimeout);

        Assert.That(response.FilteredAnswers.Select(a => a.IPv4Address.ToString()),
                    Is.EqualTo(new[] { "192.0.2.5" }),
                    "a differently-cased echo of the question is still the same question");

    }

    #endregion

    #region Transaction_Ids_Draw_From_A_Wide_Range()

    [Test]
    [Property("RFC", "5452 §9.2")]
    public async Task Transaction_Ids_Draw_From_A_Wide_Range()
    {

        // RFC 5452 §9.2 requires unpredictable IDs. This is a smoke test, not a
        // statistical one: 20 draws from a 16-bit space should essentially never
        // collide more than a handful of times.
        var ids = new List<UInt16>();

        await using var server = new ScriptedUdpServer(request => {
            ids.Add(RawDnsReader.Parse(request).Id);
            return RawDnsResponder.Answer(request, ("ids.example.", RawDnsType.A, 60, RawDnsWriter.IPv4("192.0.2.1")));
        });

        for (var i = 0; i < 20; i++)
        {

            await using var client = new DNSUDPClient(
                                         IPv4Address.Localhost,
                                         IPPort.Parse((UInt16) server.Port),
                                         QueryTimeout: ShortTimeout
                                     );

            _ = await client.Query<A>(DomainName.Parse("ids.example."), ShortTimeout);

        }

        Assert.That(ids, Has.Count.EqualTo(20));
        Assert.That(ids.Distinct().Count(), Is.GreaterThanOrEqualTo(15),
                    $"transaction IDs must span the 16-bit space; saw: {String.Join(',', ids)}");

    }

    #endregion

    #region Spoofed_Response_Does_Not_Kill_The_Pending_Query()

    [Test]
    [Property("RFC", "5452 §4.2")]
    public async Task Spoofed_Response_Does_Not_Kill_The_Pending_Query()
    {

        // RFC 5452 §4.2: a resolver MUST ignore responses that do not match the
        // transmitted query. "Ignore" means keep waiting for the genuine answer
        // — not abort the query. Otherwise a single forged datagram from any
        // off-path attacker becomes a denial of service.
        //
        // The scripted server sends a spoofed wrong-ID datagram first, then the
        // genuine response.
        await using var server = new ScriptedUdpServer((request, _) => new[] {
            RawDnsResponder.WithWrongId(
                RawDnsResponder.Answer(request, ("race.example.", RawDnsType.A, 60, RawDnsWriter.IPv4("6.6.6.6")))),
            RawDnsResponder.Answer(request, ("race.example.", RawDnsType.A, 60, RawDnsWriter.IPv4("192.0.2.99")))
        });

        await using var client = new DNSUDPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout: ShortTimeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("race.example."), ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(response.FilteredAnswers.Any(a => a.IPv4Address.ToString() == "6.6.6.6"),
                        Is.False,
                        "the forged answer must never surface");

            Assert.That(response.FilteredAnswers.Select(a => a.IPv4Address.ToString()),
                        Is.EqualTo(new[] { "192.0.2.99" }),
                        "the genuine answer must still be delivered after ignoring the spoof");

        });

    }

    #endregion

}

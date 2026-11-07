using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 7766 (formerly 5966) — DNS transport over TCP: the TC-triggered
/// fallback and two-byte length framing, including hostile write patterns.
/// </summary>
[TestFixture]
[Property("RFC", "7766")]
public class TcpFallbackAndFramingTests
{

    #region Truncated_Udp_Response_Triggers_Tcp_Retry()

    [Test]
    [Property("RFC", "7766 §5")]
    public async Task Truncated_Udp_Response_Triggers_Tcp_Retry()
    {

        // UDP answers TC=1 with no data; TCP carries the real answer. Both
        // listeners must share one port number, since the client retries the
        // same server endpoint over TCP — and UDP and TCP have separate port
        // spaces, so the pair has to be allocated with that in mind.
        var (udpServer, tcpServer) = await ScriptedServerPair.CreateAsync(
            UdpResponder: request => RawDnsResponder.Truncated(request),
            TcpResponder: request => RawDnsResponder.Answer(request, ("tc.example.", RawDnsType.A, 300, [203, 0, 113, 9]))
        );

        await using var udp = udpServer;
        await using var tcp = tcpServer;

        await using var client = new DNSUDPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) udp.Port),
                                     QueryTimeout: TimeSpan.FromSeconds(3)
                                 );

        var response = await client.Query<A>(DomainName.Parse("tc.example."), Timeout: TimeSpan.FromSeconds(3));

        Assert.Multiple(() => {

            Assert.That(udp.Requests, Is.Not.Empty, "the UDP query must be sent first");
            Assert.That(tcp.Requests, Is.Not.Empty, "TC=1 MUST trigger a retry over TCP (RFC 7766 §5)");

            Assert.That(response.FilteredAnswers.Single().IPv4Address,
                        Is.EqualTo(IPv4Address.Parse("203.0.113.9")),
                        "the TCP answer must be the returned result");

            Assert.That(response.IsTruncated, Is.False, "the final answer is no longer truncated");

        });

    }

    #endregion

    #region A_Refused_Tcp_Retry_Reports_The_Time_The_Query_Had_And_Took()

    [Test]
    [Property("RFC", "5452 §9.1")]
    public async Task A_Refused_Tcp_Retry_Reports_The_Time_The_Query_Had_And_Took()
    {

        // The TCP side answers with a bare twelve-octet header: a whole message,
        // and no question in it, so RFC 5452 §9.1 leaves nothing to match it to
        // and the client refuses it. That refusal is a failed query, and a failed
        // query reports what every failure reports (HeaderFlagsAndFailedQueryTests):
        // the timeout it was given and the time it ran. Neither is zero. Whether
        // the client should go on waiting after such a message is not asked here.
        var (udpServer, tcpServer) = await ScriptedServerPair.CreateAsync(
            UdpResponder: request => RawDnsResponder.Truncated(request),
            TcpResponder: request => new RawDnsWriter().
                                         Header(RawDnsReader.Parse(request).Id,
                                                (UInt16) (RawDnsFlags.QR | RawDnsFlags.RD | RawDnsFlags.RA),
                                                0, 0, 0, 0).
                                         ToArray()
        );

        await using var udp = udpServer;
        await using var tcp = tcpServer;

        var timeout = TimeSpan.FromSeconds(3);

        await using var client = new DNSUDPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) udp.Port),
                                     QueryTimeout: timeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("tc.example."), Timeout: timeout);

        Assert.Multiple(() => {

            Assert.That(tcp.Requests,     Is.Not.Empty, "the positive control: the retry went out over TCP");

            Assert.That(response.IsValid, Is.False,                       "the question-less message is refused");
            Assert.That(response.Timeout, Is.EqualTo(timeout),            "the timeout the query was given");
            Assert.That(response.Runtime, Is.GreaterThan(TimeSpan.Zero),  "and the time it ran, which was not none");

        });

    }

    #endregion

    #region Tcp_Query_Uses_TwoByte_Length_Prefix()

    [Test]
    [Property("RFC", "7766 §8")]
    public async Task Tcp_Query_Uses_TwoByte_Length_Prefix()
    {

        // The scripted server strips the prefix; if the client framed wrongly,
        // the message it recorded would not parse as a DNS query at all.
        await using var server = new ScriptedTcpServer(
            request => RawDnsResponder.Answer(request, ("framed.example.", RawDnsType.A, 300, [192, 0, 2, 55]))
        );

        await using var client = new DNSTCPClient(
                                     IPv4Address.Localhost,
                                     Port:          IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:  TimeSpan.FromSeconds(3)
                                 );

        var response = await client.Query<A>(DomainName.Parse("framed.example."), Timeout: TimeSpan.FromSeconds(3));

        Assert.That(server.Requests.TryDequeue(out var request), Is.True);

        var decoded = RawDnsReader.Parse(request!);

        Assert.Multiple(() => {
            Assert.That(decoded.Questions.Single().Name.Canonical, Is.EqualTo("framed.example"),
                        () => "unframed message did not decode:\n" + Bytes.Dump(request!));
            Assert.That(response.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("192.0.2.55")));
        });

    }

    #endregion

    #region Tcp_Client_Reassembles_Dribbled_Responses()

    [Test]
    [Property("RFC", "7766 §8")]
    public async Task Tcp_Client_Reassembles_Dribbled_Responses()
    {

        // "The DNS message ... may be split across TCP segments" — the reader
        // must reassemble rather than assume one read == one message.
        await using var server = new ScriptedTcpServer(
            request => RawDnsResponder.Answer(request, ("drip.example.", RawDnsType.A, 300, [192, 0, 2, 77])),
            new ScriptedTcpOptions {
                SplitLengthPrefix  = true,
                WriteChunkSize     = 3,
                WriteChunkDelay    = TimeSpan.FromMilliseconds(2)
            }
        );

        await using var client = new DNSTCPClient(
                                     IPv4Address.Localhost,
                                     Port:          IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:  TimeSpan.FromSeconds(5)
                                 );

        var response = await client.Query<A>(DomainName.Parse("drip.example."), Timeout: TimeSpan.FromSeconds(5));

        Assert.That(response.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("192.0.2.77")));

    }

    #endregion

    #region Tcp_Connection_Is_Reused_For_Multiple_Queries()

    [Test]
    [Property("RFC", "7766 §6.2.1")]
    public async Task Tcp_Connection_Is_Reused_For_Multiple_Queries()
    {

        // "Clients ... SHOULD pipeline their queries" / connections SHOULD be
        // reused — a fresh TCP connection per query is wasteful but legal, so
        // this is recorded rather than enforced.
        await using var server = new ScriptedTcpServer(
            request => RawDnsResponder.Answer(request, ("reuse.example.", RawDnsType.A, 300, [192, 0, 2, 88]))
        );

        await using var client = new DNSTCPClient(
                                     IPv4Address.Localhost,
                                     Port:          IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:  TimeSpan.FromSeconds(3)
                                 );

        for (var i = 0; i < 3; i++)
        {
            var response = await client.Query<A>(DomainName.Parse("reuse.example."), Timeout: TimeSpan.FromSeconds(3));
            Assert.That(response.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("192.0.2.88")));
        }

        TestContext.Out.WriteLine($"3 queries used {server.ConnectionCount} TCP connection(s).");

        Assert.That(server.Requests, Has.Count.EqualTo(3), "all three queries reached the server");

    }

    #endregion

    #region Tcp_Client_Handles_Server_Closing_Connection()

    [Test]
    public async Task Tcp_Client_Handles_Server_Closing_Connection()
    {

        await using var server = new ScriptedTcpServer(
            request => RawDnsResponder.Answer(request, ("close.example.", RawDnsType.A, 300, [192, 0, 2, 99])),
            new ScriptedTcpOptions { CloseAfterFirst = true }
        );

        await using var client = new DNSTCPClient(
                                     IPv4Address.Localhost,
                                     Port:          IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:  TimeSpan.FromSeconds(3)
                                 );

        var first = await client.Query<A>(DomainName.Parse("close.example."), Timeout: TimeSpan.FromSeconds(3));
        Assert.That(first.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("192.0.2.99")));

        // Server closed the connection — the client must recover (reconnect)
        // or fail cleanly, but not throw or hang.
        var second = await client.Query<A>(DomainName.Parse("close.example."), Timeout: TimeSpan.FromSeconds(3));

        Assert.That(second, Is.Not.Null);

    }

    #endregion

}

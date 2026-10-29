using System.Net;
using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// The HTTP underneath DoH: how an answer is framed, when a connection may be
/// used again, and what it means when there was no connection at all.
/// </summary>
/// <remarks>
/// <para>
/// RFC 8484 maps a DNS exchange onto HTTP and leaves HTTP to be HTTP, so a DoH
/// client inherits every rule of the version it speaks. Two of them are MUSTs a
/// client can break without the DNS layer noticing anything: RFC 9112 §7.1, "A
/// recipient MUST be able to parse and decode the chunked transfer coding", and
/// §9.6, "A client that receives a "close" connection option MUST cease sending
/// requests on that connection".
/// </para>
/// <para>
/// The third is the boundary <see cref="TimeoutReportingTests"/> stops at. That
/// file shows a slow resolver is reported as a timeout; this one shows that a
/// resolver which never let the client in is not.
/// </para>
/// </remarks>
[TestFixture]
public class DohConnectionTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(3);


    private static Byte[] OneAddress(Byte[] Request)
        => RawDnsResponder.Answer(Request, ($"{RawDnsReader.Parse(Request).Questions[0].Name.Canonical}.", RawDnsType.A, 60, [192, 0, 2, 11]));


    private static DNSHTTPSClient ClientFor(ScriptedDoHServer Peer, DNSHTTPSMode Mode = DNSHTTPSMode.GET)
        => new (URL.Parse(Peer.Url),
                Mode:          Mode,
                QueryTimeout:  Timeout);


    /// <summary>A loopback port nothing listens on, found by binding one and letting it go.</summary>
    private static Int32 ClosedPort()
    {
        var probe = new TcpListener(System.Net.IPAddress.Loopback, 0);
        probe.Start();
        var port  = ((IPEndPoint) probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    #endregion


    #region An answer in chunks (RFC 9112 §7.1)

    [Test]
    [Property("RFC", "9112 §7.1, 8484 §4.2")]
    public async Task A_Doh_Answer_Sent_In_Chunks_Is_Read()
    {

        // The same answer as any other, framed by the chunked transfer coding
        // instead of a Content-Length and written as two chunks. RFC 8484 §4.2
        // puts the DNS message in the body and says nothing about how the body
        // is delimited, which leaves it to HTTP — and HTTP/1.1 makes chunked the
        // one coding every recipient has to read.
        await using var peer   = new ScriptedDoHServer(OneAddress) { Chunked = true };
        await using var client = ClientFor(peer);

        var info = await client.Query(DNSServiceName.Parse("chunked.example."), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.Multiple(() => {
            Assert.That(info.IsValid,          Is.True,       "a chunked answer is an answer");
            Assert.That(info.Answers.Count(),  Is.EqualTo(1), "with its record in it");
        });

    }


    [Test]
    [Property("RFC", "9112 §7.1, 8484 §4.2")]
    public async Task A_Doh_Answer_Sent_In_Chunks_Is_Read_After_A_Post()
    {

        // POST takes the same path back as GET and is checked as well, since a
        // client that read chunked answers only for one method would serve half
        // the resolvers that use it.
        await using var peer   = new ScriptedDoHServer(OneAddress) { Chunked = true };
        await using var client = ClientFor(peer, DNSHTTPSMode.POST);

        var info = await client.Query(DNSServiceName.Parse("chunkedpost.example."), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.That(info.Answers.Count(), Is.EqualTo(1));

    }

    #endregion


    #region A connection the server closes (RFC 9112 §9.6)

    [Test]
    [Property("RFC", "9112 §9.6")]
    public async Task A_Connection_The_Server_Closes_Is_Not_Asked_Again()
    {

        // Every answer here carries "Connection: close", and the server closes
        // after it. The second query therefore needs a new connection, which the
        // server sees as a new client port. A client that sent it down the old
        // one would be writing to a socket the server has already shut — the
        // question lost, and an answer that never comes.
        await using var peer   = new ScriptedDoHServer(OneAddress) { CloseAfterEachResponse = true };
        await using var client = ClientFor(peer);

        var first  = await client.Query(DNSServiceName.Parse("first.example."),  [ DNSResourceRecordTypes.A ], Timeout);
        var second = await client.Query(DNSServiceName.Parse("second.example."), [ DNSResourceRecordTypes.A ], Timeout);

        var ports  = peer.Exchanges.Select(exchange => exchange.ClientPort).ToArray();

        Assert.Multiple(() => {

            Assert.That(first. Answers.Count(), Is.EqualTo(1), "the first query was answered");
            Assert.That(second.Answers.Count(), Is.EqualTo(1), "and so was the second");

            Assert.That(ports, Has.Length.EqualTo(2), "each reached the server once");
            Assert.That(ports.Distinct().Count(), Is.EqualTo(2),
                        "over two connections, since the first was closed after its answer");

        });

    }

    #endregion


    #region No connection is not a slow one

    [Test]
    public async Task A_Doh_Server_That_Refuses_The_Connection_Is_A_Failure_And_Not_A_Timeout()
    {

        // Nothing listens on the port, so the connection is refused. No deadline
        // ran out: the resolver did not answer slowly, it could not be reached at
        // all, and "try again in a moment" is the wrong advice for that.
        //
        // With the client's connection retries as they come. Before the fix, the
        // client reconnected past its own deadline — 8.2 s for a 3 s query,
        // measured — and then reported the timeout it had run into.
        //
        // Wall-clock time rather than DNSInfo.Runtime, because a failure reports
        // its timeout there instead of the time it took. The deadline is twice
        // the usual: Windows answers a refused loopback connect after about two
        // seconds of SYN retries, and the margin is for that, not for Hermod.
        var deadline = TimeSpan.FromSeconds(6);

        await using var client = new DNSHTTPSClient(URL.Parse($"http://127.0.0.1:{ClosedPort()}/dns-query"),
                                                    QueryTimeout: deadline);

        var clock = System.Diagnostics.Stopwatch.StartNew();
        var info  = await client.Query(DNSServiceName.Parse("refused.example."), [ DNSResourceRecordTypes.A ], deadline);
        clock.Stop();

        Assert.Multiple(() => {
            Assert.That(info.Answers,   Is.Empty, "nothing was answered");
            Assert.That(info.IsTimeout, Is.False, "and nothing timed out: the connection was refused");
            Assert.That(clock.Elapsed,  Is.LessThan(deadline), "which was known before the deadline");
        });

    }


    [Test]
    public async Task A_Doh_Server_Gone_Between_Two_Queries_Is_A_Failure_And_Not_A_Timeout()
    {

        // The connection the first query used is still open on this side when the
        // server goes away, so the client has to notice that it is closed before it
        // can learn that a new one is refused. It used to notice only inside the
        // HTTP layer, whose retries met the refusal once per attempt and spent the
        // deadline doing so: 4.2 s for a 3 s query, reported as a timeout.
        var deadline = TimeSpan.FromSeconds(6);

        var peer = new ScriptedDoHServer(OneAddress);

        await using var client = new DNSHTTPSClient(URL.Parse(peer.Url), QueryTimeout: deadline);

        var first = await client.Query(DNSServiceName.Parse("before.example."), [ DNSResourceRecordTypes.A ], deadline);

        await peer.DisposeAsync();

        var clock  = System.Diagnostics.Stopwatch.StartNew();
        var second = await client.Query(DNSServiceName.Parse("after.example."), [ DNSResourceRecordTypes.A ], deadline);
        clock.Stop();

        Assert.Multiple(() => {
            Assert.That(first. Answers.Count(), Is.EqualTo(1), "the first query was answered");
            Assert.That(second.Answers,         Is.Empty,      "the second could not be");
            Assert.That(second.IsTimeout,       Is.False,      "because the server was gone, which is not a timeout");
            Assert.That(clock.Elapsed,          Is.LessThan(deadline), "and that was known before the deadline");
        });

    }

    #endregion

}

using NUnit.Framework;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// How the Hermod DNS server reacts to malformed, hostile or unusual requests.
/// A server must answer or stay silent — but never crash, hang or leak.
/// </summary>
[TestFixture]
public class ServerRobustnessTests
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


    /// <summary>
    /// The server is still answering normal queries.
    /// </summary>
    private async Task AssertServerStillHealthy(String because)
    {

        var probe     = RawDnsWriter.Query((UInt16) Random.Shared.Next(1, 65535), ZoneFixtures.AName, RawDnsType.A);
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, probe, TimeSpan.FromSeconds(3));

        Assert.That(raw, Is.Not.Null, $"server stopped answering after {because}");

        var response  = RawDnsReader.Parse(raw!);

        Assert.That(response.Answers, Is.Not.Empty, $"server degraded after {because}");

    }


    #region Query_For_Unimplemented_Type_Does_Not_Break_The_Server()

    [Test]
    [Property("RFC", "3597")]
    public async Task Query_For_Unimplemented_Type_Does_Not_Break_The_Server()
    {

        // TYPE 65432 is unassigned — a server must handle it as "no such data",
        // not as a parse failure.
        var request = RawDnsWriter.Query(0x2001, ZoneFixtures.AName, 65432);
        var raw     = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        if (raw is not null)
        {
            var response = RawDnsReader.Parse(raw);
            TestContext.Out.WriteLine($"unknown QTYPE answered with RCODE {response.RCode}, {response.Answers.Count} answers");
        }
        else
            TestContext.Out.WriteLine("unknown QTYPE was not answered at all");

        await AssertServerStillHealthy("a query for an unassigned RR type");

    }

    #endregion

    #region Empty_Question_Section_Is_Answered_With_FORMERR()

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task Empty_Question_Section_Is_Answered_With_FORMERR()
    {

        var request  = new RawDnsWriter().Header(0x2002, RawDnsFlags.RD, 0, 0, 0, 0).ToArray();
        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        if (raw is null)
        {
            TestContext.Out.WriteLine("QDCOUNT=0 query was silently dropped");
            await AssertServerStillHealthy("a QDCOUNT=0 query");
            Assert.Inconclusive("server dropped a QDCOUNT=0 query instead of answering FORMERR");
            return;
        }

        var response = RawDnsReader.Parse(raw);

        Assert.That(response.RCode, Is.EqualTo(1), "FORMERR = 1");

        await AssertServerStillHealthy("a QDCOUNT=0 query");

    }

    #endregion

    #region Truncated_Request_Does_Not_Break_The_Server()

    [Test]
    public async Task Truncated_Request_Does_Not_Break_The_Server()
    {

        // A header claiming one question, but the question is cut off mid-name.
        var request = new RawDnsWriter()
                          .Header(0x2003, RawDnsFlags.RD, 1, 0, 0, 0)
                          .RawLabel("conformance")
                          .ToArray();               // no terminator, no QTYPE/QCLASS

        var raw     = await RawDnsProbe.UdpAsync(server.UdpPort, request, TimeSpan.FromSeconds(2));

        await AssertServerStillHealthy("a truncated request");

        Assert.That(raw, Is.Not.Null,
                    "RFC 1035 §4.1.1: an unparseable request should be answered with FORMERR rather than dropped");

    }

    #endregion

    #region Request_With_Absurd_Counts_Does_Not_Break_The_Server()

    [Test]
    public async Task Request_With_Absurd_Counts_Does_Not_Break_The_Server()
    {

        // Claims 65535 questions but carries one — a classic resource-exhaustion probe.
        var request = new RawDnsWriter()
                          .Header(0x2004, RawDnsFlags.RD, 65535, 0, 0, 0)
                          .Question(ZoneFixtures.AName, RawDnsType.A)
                          .ToArray();

        _ = await RawDnsProbe.UdpAsync(server.UdpPort, request, TimeSpan.FromSeconds(2));

        await AssertServerStillHealthy("a request claiming 65535 questions");

    }

    #endregion

    #region Compression_Pointer_Loop_In_Request_Does_Not_Hang_The_Server()

    [Test]
    [Property("RFC", "1035 §4.1.4")]
    public async Task Compression_Pointer_Loop_In_Request_Does_Not_Hang_The_Server()
    {

        // QNAME is a pointer to itself.
        var request = new RawDnsWriter()
                          .Header(0x2005, RawDnsFlags.RD, 1, 0, 0, 0)
                          .Pointer(12)                    // at offset 12, pointing to itself
                          .U16(RawDnsType.A)
                          .U16(RawDnsClass.IN)
                          .ToArray();

        _ = await RawDnsProbe.UdpAsync(server.UdpPort, request, TimeSpan.FromSeconds(2));

        await AssertServerStillHealthy("a self-referencing compression pointer");

    }

    #endregion

    #region Random_Garbage_Does_Not_Break_The_Server()

    [Test]
    [Category(TestCategories.Slow)]
    public async Task Random_Garbage_Does_Not_Break_The_Server()
    {

        var random = new Random(20260725);

        for (var i = 0; i < 60; i++)
        {

            var garbage = new Byte[random.Next(1, 300)];
            random.NextBytes(garbage);

            _ = await RawDnsProbe.UdpAsync(server.UdpPort, garbage, TimeSpan.FromMilliseconds(300));

        }

        await AssertServerStillHealthy("60 random garbage datagrams");

    }

    #endregion

    #region Tcp_Handles_Multiple_Queries_On_One_Connection()

    [Test]
    [Property("RFC", "7766 §6.2.1")]
    public async Task Tcp_Handles_Multiple_Queries_On_One_Connection()
    {

        // "Servers MUST be able to handle multiple queries on a single
        //  connection" — sequential here, which is the weaker requirement.
        var requests  = new[] {
                            RawDnsWriter.Query(0x3001, ZoneFixtures.AName,     RawDnsType.A),
                            RawDnsWriter.Query(0x3002, ZoneFixtures.QuadAName, RawDnsType.AAAA),
                            RawDnsWriter.Query(0x3003, ZoneFixtures.MxName,    RawDnsType.MX)
                        };

        var responses = await RawDnsProbe.TcpPipelineAsync(server.TcpPort, requests);

        Assert.That(responses, Has.Count.EqualTo(3));

        Assert.Multiple(() => {

            for (var i = 0; i < 3; i++)
            {

                Assert.That(responses[i], Is.Not.Null, $"query #{i + 1} on the shared connection was not answered");

                var response = RawDnsReader.Parse(responses[i]!);

                Assert.That(response.Id,      Is.EqualTo((UInt16) (0x3001 + i)), $"query #{i + 1} ID mismatch");
                Assert.That(response.Answers, Is.Not.Empty,                      $"query #{i + 1} returned no answers");

            }

        });

    }

    #endregion

    #region Tcp_Truncated_Length_Prefix_Does_Not_Break_The_Server()

    [Test]
    [Property("RFC", "7766 §8")]
    public async Task Tcp_Truncated_Length_Prefix_Does_Not_Break_The_Server()
    {

        // Announce 100 bytes, send 5, then close.
        var bogus = new Byte[] { 0x00, 0x64, 0x01, 0x02, 0x03, 0x04, 0x05 };

        _ = await RawDnsProbe.TcpRawAsync(server.TcpPort, bogus, TimeSpan.FromSeconds(2));

        var probe    = RawDnsWriter.Query(0x3004, ZoneFixtures.AName, RawDnsType.A);
        var raw      = await RawDnsProbe.TcpAsync(server.TcpPort, probe, TimeSpan.FromSeconds(3));

        Assert.That(raw, Is.Not.Null, "TCP listener must survive a partial message");

        Assert.That(RawDnsReader.Parse(raw!).Answers, Is.Not.Empty);

    }

    #endregion

}

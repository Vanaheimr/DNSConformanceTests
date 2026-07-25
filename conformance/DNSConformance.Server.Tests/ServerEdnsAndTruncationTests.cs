using NUnit.Framework;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 6891 (EDNS0 on the server side) and RFC 1035 §4.2.1 (UDP message-size
/// limit and TC). These encode MUST-level requirements that a
/// dnsflagday/ISC-compliance run would also probe.
/// </summary>
[TestFixture]
public class ServerEdnsAndTruncationTests
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


    #region Response_To_Edns_Query_Contains_An_Opt_Record()

    [Test]
    [Property("RFC", "6891 §6.1.1")]
    [Category(TestCategories.KnownIssue)]   // FINDINGS.md #6
    public async Task Response_To_Edns_Query_Contains_An_Opt_Record()
    {

        // RFC 6891 §6.1.1: "Responders that choose to implement this
        // specification MUST include an OPT record in their respective
        // responses" when the query carried one.
        var request   = RawDnsWriter.Query(0x1001, ZoneFixtures.AName, RawDnsType.A, ednsPayloadSize: 4096);
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null, "server must answer an EDNS query");

        var response  = RawDnsReader.Parse(raw!);

        Assert.That(response.Opt, Is.Not.Null,
                    "an EDNS-aware responder MUST include an OPT record when the query had one");

    }

    #endregion

    #region Unknown_Edns_Version_Yields_BADVERS()

    [Test]
    [Property("RFC", "6891 §6.1.3")]
    [Category(TestCategories.KnownIssue)]   // FINDINGS.md #6
    public async Task Unknown_Edns_Version_Yields_BADVERS()
    {

        // RFC 6891 §6.1.3: "If a responder does not implement the VERSION level
        // of the request, then it MUST respond with RCODE=BADVERS." BADVERS is
        // extended RCODE 16 = extRCODE 1 in the OPT TTL, header RCODE 0.
        var request   = RawDnsWriter.Query(0x1002, ZoneFixtures.AName, RawDnsType.A,
                                           ednsPayloadSize: 4096, ednsVersion: 1);

        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null, "server must answer an EDNS version 1 query");

        var response  = RawDnsReader.Parse(raw!);

        TestContext.Out.WriteLine($"combined RCODE = {response.CombinedRcode} (BADVERS = 16), OPT present: {response.Opt is not null}");

        Assert.That(response.CombinedRcode, Is.EqualTo(16),
                    "EDNS version > 0 MUST be answered with BADVERS (extended RCODE 16)");

    }

    #endregion

    #region Unknown_Edns_Options_Are_Not_Echoed()

    [Test]
    [Property("RFC", "6891 §6.1.2")]
    public async Task Unknown_Edns_Options_Are_Not_Echoed()
    {

        // Unknown options MUST be ignored — and in particular not reflected,
        // which would make the server an amplification/─oracle gadget.
        var unknownOption = new RawDnsWriter().U16(65001).U16(4).Bytes(0xDE, 0xAD, 0xBE, 0xEF).ToArray();

        var request  = RawDnsWriter.Query(0x1003, ZoneFixtures.AName, RawDnsType.A,
                                          ednsPayloadSize: 4096, ednsOptions: unknownOption);

        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null);

        var response = RawDnsReader.Parse(raw!);

        if (response.Edns is { } edns)
            Assert.That(edns.Options.Any(o => o.Code == 65001), Is.False,
                        "unknown EDNS options MUST NOT be echoed");
        else
            Assert.Pass("no OPT in the response — nothing echoed (see the OPT-presence test)");

    }

    #endregion

    #region Large_Answer_Without_Edns_Is_Truncated_Or_Fits_512_Bytes()

    [Test]
    [Property("RFC", "1035 §4.2.1")]
    [Category(TestCategories.KnownIssue)]   // FINDINGS.md #7
    public async Task Large_Answer_Without_Edns_Is_Truncated_Or_Fits_512_Bytes()
    {

        // RFC 1035 §4.2.1: "Messages carried by UDP are restricted to 512 bytes
        // (not counting the IP or UDP headers). Longer messages are truncated
        // and the TC bit is set in the header."
        //
        // big.conformance.test carries a 600-byte TXT, so a full answer cannot
        // fit into a non-EDNS UDP response.
        var request   = RawDnsWriter.Query(0x1004, ZoneFixtures.BigTxtName, RawDnsType.TXT);
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);

        TestContext.Out.WriteLine($"non-EDNS UDP response: {raw!.Length} bytes, TC={response.TC}");

        Assert.That(
            raw.Length <= 512 || response.TC,
            Is.True,
            $"a {raw.Length}-byte UDP response without EDNS violates the 512-byte limit; " +
            "the answer MUST be truncated with TC=1 instead"
        );

    }

    #endregion

    #region Answer_Respects_The_Advertised_Edns_Payload_Size()

    [Test]
    [Property("RFC", "6891 §6.2.5")]
    [Category(TestCategories.KnownIssue)]   // FINDINGS.md #7
    public async Task Answer_Respects_The_Advertised_Edns_Payload_Size()
    {

        // The requestor advertises a small 512-byte buffer; the responder
        // "MUST NOT send UDP responses that exceed" it — larger answers must be
        // truncated with TC=1.
        var request   = RawDnsWriter.Query(0x1005, ZoneFixtures.BigTxtName, RawDnsType.TXT, ednsPayloadSize: 512);
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);

        TestContext.Out.WriteLine($"EDNS(512) response: {raw!.Length} bytes, TC={response.TC}");

        Assert.That(
            raw.Length <= 512 || response.TC,
            Is.True,
            $"response of {raw.Length} bytes exceeds the advertised 512-byte buffer without setting TC"
        );

    }

    #endregion

    #region Tcp_Delivers_The_Full_Large_Answer()

    [Test]
    [Property("RFC", "7766 §5")]
    public async Task Tcp_Delivers_The_Full_Large_Answer()
    {

        // Whatever happens over UDP, TCP must carry the complete answer.
        var request   = RawDnsWriter.Query(0x1006, ZoneFixtures.BigTxtName, RawDnsType.TXT);
        var raw       = await RawDnsProbe.TcpAsync(server.TcpPort, request);

        Assert.That(raw, Is.Not.Null, "TCP service must be available");

        var response  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(response.TC,      Is.False, "no truncation over TCP");
            Assert.That(response.Answers, Is.Not.Empty);
            Assert.That(response.Answers[0].Rdata.Length, Is.GreaterThan(512),
                        "the full 600-byte TXT RDATA must be delivered");
        });

    }

    #endregion

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 8945 §5 — the Hermod server answering TSIG-signed queries.
///
/// <para>
/// The signing primitives are covered elsewhere; what these check is that the
/// server actually reaches for them: that a signed query is verified before it
/// is served, that the reply carries a MAC bound to the request's, and that a
/// query which fails verification is refused rather than answered.
/// </para>
///
/// <para>
/// Everything goes over raw sockets and is read back with <c>RawDns</c>, so no
/// assertion here depends on Hermod agreeing with itself.
/// </para>
/// </summary>
[TestFixture]
public class TsigServerTests
{

    private static readonly Byte[]   Secret  = Convert.FromBase64String("c2VydmVyLXNpZGUtdHNpZy10ZXN0LXNlY3JldC0xMjM0NTY3OA==");

    private static TSIGKey Key(String Name = "server-key.")
        => new (DomainName.Parse(Name), Secret);

    private static async Task<HermodServerFixture> SignedServerAsync()
        => await HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
                     EnableTcp  = true,
                     TSIGKeys   = [ Key() ]
                 });


    #region Signed_Query_Is_Answered_With_A_Signed_Response()

    [Test]
    [Property("RFC", "8945 §5.3")]
    public async Task Signed_Query_Is_Answered_With_A_Signed_Response()
    {

        await using var server = await SignedServerAsync();

        var query    = RawDnsWriter.Query(0x7A11, ZoneFixtures.AName, RawDnsType.A);
        var signed   = TSIGSigner.Sign(query, Key());
        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null, "the server must answer a correctly signed query");

        var response = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(response.RCode,        Is.EqualTo(0), "a valid signature must not change the answer");
            Assert.That(response.Answers,      Is.Not.Empty,  "the query is still a query — it has to be served");
            Assert.That(response.Additionals.Any(rr => rr.Type == 250), Is.True,
                        "§5.3: the response to a signed request is itself signed");

        });

    }

    #endregion

    #region Response_Mac_Is_Bound_To_The_Request()

    [Test]
    [Property("RFC", "8945 §4.3.1")]
    public async Task Response_Mac_Is_Bound_To_The_Request()
    {

        await using var server = await SignedServerAsync();

        var query        = RawDnsWriter.Query(0x7A12, ZoneFixtures.AName, RawDnsType.A);
        var signed       = TSIGSigner.Sign(query, Key());
        var requestMAC   = TSIGSigner.Verify(signed, Key()).MAC!;

        var raw          = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.Multiple(() => {

            // With the request's MAC, the response verifies.
            Assert.That(TSIGSigner.Verify(raw!, Key(), RequestMAC: requestMAC).IsValid, Is.True,
                        "the response must verify against the request it answers");

            // Without it, it must not — that is the binding doing its work, and
            // it is what stops a signed response being replayed to answer a
            // different question.
            Assert.That(TSIGSigner.Verify(raw!, Key()).IsValid, Is.False,
                        "the response must not verify as a standalone message");

        });

    }

    #endregion

    #region Query_Signed_With_The_Wrong_Secret_Is_Refused()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public async Task Query_Signed_With_The_Wrong_Secret_Is_Refused()
    {

        await using var server = await SignedServerAsync();

        var impostor = new TSIGKey(DomainName.Parse("server-key."), Convert.FromBase64String("d3Jvbmctc2VjcmV0LXRoYXQtaXMtbm90LXRoZS1yaWdodC1vbmU="));
        var signed   = TSIGSigner.Sign(RawDnsWriter.Query(0x7A13, ZoneFixtures.AName, RawDnsType.A), impostor);

        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null,
                    "§5.2 wants an answer, not silence — a client cannot distinguish a dropped packet from a rejected one");

        var response = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(response.RCode,    Is.EqualTo(9), "NOTAUTH");
            Assert.That(response.Answers,  Is.Empty,      "nothing is served to an unauthenticated request");
        });

    }

    #endregion

    #region Query_Signed_With_An_Unknown_Key_Is_Refused()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public async Task Query_Signed_With_An_Unknown_Key_Is_Refused()
    {

        await using var server = await SignedServerAsync();

        var signed  = TSIGSigner.Sign(RawDnsWriter.Query(0x7A14, ZoneFixtures.AName, RawDnsType.A), Key("some-other-key."));
        var raw     = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null);
        Assert.That(RawDnsReader.Parse(raw!).RCode, Is.EqualTo(9), "NOTAUTH for a key the server does not hold");

    }

    #endregion

    #region Query_Signed_Outside_The_Fudge_Window_Is_Refused()

    [Test]
    [Property("RFC", "8945 §5.2.3")]
    public async Task Query_Signed_Outside_The_Fudge_Window_Is_Refused()
    {

        await using var server = await SignedServerAsync();

        // Signed an hour ago with a 300 s fudge: the MAC is perfectly good and
        // the message must still be refused, or a captured query could be
        // replayed indefinitely.
        var longAgo = (UInt64) DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
        var signed  = TSIGSigner.Sign(RawDnsWriter.Query(0x7A15, ZoneFixtures.AName, RawDnsType.A), Key(), TimeSigned: longAgo);

        var raw     = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null);
        Assert.That(RawDnsReader.Parse(raw!).RCode, Is.EqualTo(9), "NOTAUTH for a stale signature");

    }

    #endregion

    #region Unsigned_Query_Is_Still_Served()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public async Task Unsigned_Query_Is_Still_Served()
    {

        await using var server = await SignedServerAsync();

        // Holding a key is not the same as demanding one. RFC 8945 does not make
        // an unsigned query invalid, and refusing it would be a policy decision
        // this server does not take on its own.
        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, RawDnsWriter.Query(0x7A16, ZoneFixtures.AName, RawDnsType.A));
        var response = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(response.RCode,       Is.EqualTo(0));
            Assert.That(response.Answers,     Is.Not.Empty);
            Assert.That(response.Additionals.Any(rr => rr.Type == 250), Is.False,
                        "an unsigned request gets an unsigned reply");
        });

    }

    #endregion

    #region Signed_Query_Works_Over_Tcp_As_Well()

    [Test]
    [Property("RFC", "8945 §5.3")]
    public async Task Signed_Query_Works_Over_Tcp_As_Well()
    {

        await using var server = await SignedServerAsync();

        var signed  = TSIGSigner.Sign(RawDnsWriter.Query(0x7A17, ZoneFixtures.AName, RawDnsType.A), Key());
        var mac     = TSIGSigner.Verify(signed, Key()).MAC!;

        var raw     = await RawDnsProbe.TcpAsync(server.TcpPort, signed);

        Assert.That(raw, Is.Not.Null);
        Assert.That(TSIGSigner.Verify(raw!, Key(), RequestMAC: mac).IsValid, Is.True,
                    "TSIG is a property of the message, not of the transport");

    }

    #endregion

    #region A_Server_Without_Keys_Ignores_Tsig_Entirely()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public async Task A_Server_Without_Keys_Ignores_Tsig_Entirely()
    {

        // Backwards compatibility, asserted rather than assumed: configuring no
        // keys must leave behaviour exactly as it was before TSIG existed.
        await using var server = await HermodServerFixture.StartAsync();

        var signed   = TSIGSigner.Sign(RawDnsWriter.Query(0x7A18, ZoneFixtures.AName, RawDnsType.A), Key());
        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null, "the server must not choke on a TSIG it was never told about");

        var response = RawDnsReader.Parse(raw!);

        Assert.That(response.RCode, Is.EqualTo(0));

    }

    #endregion

}

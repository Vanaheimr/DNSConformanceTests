using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 2931 §3 — the Hermod server answering SIG(0)-signed queries.
/// </summary>
/// <remarks>
/// <para>
/// The signing primitives are covered in <c>Sig0SigningTests</c>; what these
/// check is that the server reaches for them at all — that a signed query is
/// verified before it is served, that one which fails is refused rather than
/// answered, and that the defaults RFC 2931 asks for are the defaults.
/// </para>
/// <para>
/// SIG(0) differs from TSIG in what it demands of a server, and the differences
/// are the interesting cases here. §3.1: "servers are not required to check a
/// request SIG(0)" outside privileged operations. §3.2: a party that does not
/// implement them "MUST ignore them without error where they are optional", and
/// a message may carry a TSIG or a SIG(0) but never both.
/// </para>
/// <para>
/// Everything goes over raw sockets and is read back with <c>RawDns</c>.
/// </para>
/// </remarks>
[TestFixture]
public class Sig0ServerTests
{

    private const UInt16 SigType = 24;
    private const UInt16 TsigType = 250;

    private static readonly DomainName ClientName = DomainName.Parse("sig0-client.conformance.test");


    private static async Task<HermodServerFixture> ServerAsync(SIG0Key    Trusted,
                                                               SIG0Key?   ResponseKey = null)

        => await HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
                     EnableTcp        = true,
                     SIG0Keys         = [ Trusted.PublicKey ],
                     SIG0ResponseKey  = ResponseKey
                 });


    #region Signed_Query_Is_Verified_And_Served()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public async Task Signed_Query_Is_Verified_And_Served()
    {

        var key = SIG0Key.Generate(ClientName);

        await using var server = await ServerAsync(key);

        var query    = RawDnsWriter.Query(0x2931, ZoneFixtures.AName, RawDnsType.A);
        var signed   = SIG0Signer.Sign(query, key);
        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null, "the server must answer a correctly signed query");

        var response = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.Zero,      "a valid signature must not change the answer");
            Assert.That(response.Answers, Is.Not.Empty, "the query is still a query — it has to be served");

            Assert.That(response.Answers[0].Rdata, Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.AAddress)));

            // §3.1 makes response signing optional, and this server was not given
            // a key to sign with, so the reply is plain. TSIG's §5.3 is the
            // opposite — a signed request there is always answered signed.
            Assert.That(response.Additionals.Any(rr => rr.Type == SigType), Is.False,
                        "with no response key configured the reply stays unsigned");

        });

    }

    #endregion

    #region Query_Signed_By_An_Untrusted_Key_Is_Refused()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public async Task Query_Signed_By_An_Untrusted_Key_Is_Refused()
    {

        var trusted  = SIG0Key.Generate(ClientName);
        var impostor = SIG0Key.Generate(ClientName);       // same name, different key pair

        await using var server = await ServerAsync(trusted);

        var signed   = SIG0Signer.Sign(RawDnsWriter.Query(0x2932, ZoneFixtures.AName, RawDnsType.A), impostor);
        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null, "silence would leave the sender retrying forever");

        var response = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            // RFC 2931 names no RCODE for this — §3.1 only says a server is "not
            // required to check". Having chosen to check, NOTAUTH is what says
            // why, and it is what TSIG uses for the same situation.
            Assert.That(response.RCode,   Is.EqualTo(9), "NOTAUTH");

            Assert.That(response.Answers, Is.Empty,
                        "no data travels with an authentication failure — the point is that the request was not served");

            Assert.That(response.QR,      Is.True);
            Assert.That(response.Id,      Is.EqualTo((UInt16) 0x2932), "the sender still has to match it to its query");

            Assert.That(response.Questions, Has.Count.EqualTo(1),
                        "the question is echoed, so the refusal can be attributed");

        });

    }

    #endregion

    #region Tampering_With_A_Signed_Query_Is_Caught()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public async Task Tampering_With_A_Signed_Query_Is_Caught()
    {

        var key = SIG0Key.Generate(ClientName);

        await using var server = await ServerAsync(key);

        var signed = SIG0Signer.Sign(RawDnsWriter.Query(0x2933, ZoneFixtures.AName, RawDnsType.A), key);

        // Rewrite one letter of the QNAME in flight. This is the attack the whole
        // mechanism exists to stop, and the one a transport-level checksum cannot.
        signed[13] ^= 0x20;

        var response = RawDnsReader.Parse((await RawDnsProbe.UdpAsync(server.UdpPort, signed))!);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.EqualTo(9), "NOTAUTH");
            Assert.That(response.Answers, Is.Empty,      "and emphatically not an answer for the rewritten name");
        });

    }

    #endregion

    #region An_Unsigned_Query_Is_Still_Served()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public async Task An_Unsigned_Query_Is_Still_Served()
    {

        var key = SIG0Key.Generate(ClientName);

        await using var server = await ServerAsync(key);

        var response = RawDnsReader.Parse(
                           (await RawDnsProbe.UdpAsync(
                                server.UdpPort,
                                RawDnsWriter.Query(0x2934, ZoneFixtures.AName, RawDnsType.A)
                            ))!
                       );

        Assert.Multiple(() => {

            // Configuring keys turns verification on for messages that *are*
            // signed. Requiring every query to be signed is a policy decision,
            // and RFC 2931 does not make it — §3.1 has SIG(0) used "on requests
            // when necessary to authenticate that the requester has some
            // required privilege", not on every lookup.
            Assert.That(response.RCode,   Is.Zero);
            Assert.That(response.Answers, Is.Not.Empty, "an unsigned query is an ordinary query");

        });

    }

    #endregion

    #region A_Signed_Query_Is_Ignored_Without_Error_When_No_Keys_Are_Configured()

    [Test]
    [Property("RFC", "2931 §3.2")]
    public async Task A_Signed_Query_Is_Ignored_Without_Error_When_No_Keys_Are_Configured()
    {

        // §3.2: a server that does not implement request SIGs "MUST ignore them
        // without error where they are optional". Answering NOTAUTH here would be
        // the tempting mistake — refusing what you cannot check *sounds* safer,
        // and would break every client that signs opportunistically.
        await using var server = await HermodServerFixture.StartAsync();

        var key      = SIG0Key.Generate(ClientName);
        var signed   = SIG0Signer.Sign(RawDnsWriter.Query(0x2935, ZoneFixtures.AName, RawDnsType.A), key);

        var response = RawDnsReader.Parse((await RawDnsProbe.UdpAsync(server.UdpPort, signed))!);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero,      "ignored, not refused");
            Assert.That(response.Answers, Is.Not.Empty, "and the query answered as though it were unsigned");
        });

    }

    #endregion

    #region A_Message_Carrying_Both_A_Tsig_And_A_Sig0_Is_Refused()

    [Test]
    [Property("RFC", "2931 §3.2")]
    public async Task A_Message_Carrying_Both_A_Tsig_And_A_Sig0_Is_Refused()
    {

        // §3.2: "Requests and responses can either have a single TSIG or one
        // SIG(0) but not both a TSIG and a SIG(0)."
        //
        // Worth refusing rather than tolerating. A server that checks only the
        // outer record and serves the request lets a sender attach a valid
        // signature of the kind that is checked and a decorative one of the kind
        // that is not — and be logged, or authorized, under whichever identity
        // the server happened to read.
        var sig0Key  = SIG0Key.Generate(ClientName);
        var tsigKey  = new TSIGKey(DomainName.Parse("both-key."), Convert.FromBase64String("c2VydmVyLXNpZGUtdHNpZy10ZXN0LXNlY3JldC0xMjM0NTY3OA=="));

        await using var server = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
                                          SIG0Keys  = [ sig0Key.PublicKey ],
                                          TSIGKeys  = [ tsigKey ]
                                      });

        var query    = RawDnsWriter.Query(0x2936, ZoneFixtures.AName, RawDnsType.A);
        var both     = SIG0Signer.Sign(TSIGSigner.Sign(query, tsigKey), sig0Key);

        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, both);

        Assert.That(raw, Is.Not.Null);

        var response = RawDnsReader.Parse(raw!);

        // Each signature on its own is perfectly acceptable to this server, so
        // the refusal is about the combination and nothing else.
        var sig0Only = RawDnsReader.Parse((await RawDnsProbe.UdpAsync(server.UdpPort, SIG0Signer.Sign(query, sig0Key)))!);
        var tsigOnly = RawDnsReader.Parse((await RawDnsProbe.UdpAsync(server.UdpPort, TSIGSigner.Sign(query, tsigKey)))!);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.EqualTo(1),
                        "FORMERR: the message is malformed rather than unauthentic");

            Assert.That(response.Answers, Is.Empty);

            Assert.That(sig0Only.Answers, Is.Not.Empty, "SIG(0) alone is fine");
            Assert.That(tsigOnly.Answers, Is.Not.Empty, "TSIG alone is fine");

        });

    }

    #endregion

    #region A_Configured_Server_Signs_Its_Reply_And_Binds_It_To_The_Query()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public async Task A_Configured_Server_Signs_Its_Reply_And_Binds_It_To_The_Query()
    {

        var clientKey = SIG0Key.Generate(ClientName);
        var serverKey = SIG0Key.Generate(DomainName.Parse("sig0-server.conformance.test"));

        await using var server = await ServerAsync(clientKey, serverKey);

        var query     = RawDnsWriter.Query(0x2937, ZoneFixtures.AName, RawDnsType.A);
        var signed    = SIG0Signer.Sign(query, clientKey);
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(response.Answers, Is.Not.Empty);

            Assert.That(response.Additionals.Any(rr => rr.Type == SigType), Is.True,
                        "with a response key configured the reply is signed");

            Assert.That(response.Additionals[^1].Type, Is.EqualTo(SigType),
                        "§3: the SIG(0) is the last record");

            // §3.1's transaction form signs "RDATA | full query | response", so
            // the reply only verifies against the very query it answers. That is
            // what stops a captured reply being replayed as the answer to a
            // different question.
            Assert.That(SIG0Signer.Verify(raw!, serverKey.PublicKey, Request: signed).IsValid, Is.True,
                        "the reply must verify against the query it answers");

            Assert.That(SIG0Signer.Verify(raw!, serverKey.PublicKey).IsValid, Is.False,
                        "…and not on its own");

            Assert.That(SIG0Signer.Verify(raw!, serverKey.PublicKey,
                                          Request: SIG0Signer.Sign(RawDnsWriter.Query(0x2938, ZoneFixtures.TxtName, RawDnsType.TXT), clientKey)).IsValid,
                        Is.False,
                        "…nor against a different one");

        });

    }

    #endregion

    #region Sig0_Works_Over_Tcp_As_Well()

    [Test]
    [Property("RFC", "2931 §3.1, 7766 §5")]
    public async Task Sig0_Works_Over_Tcp_As_Well()
    {

        var key = SIG0Key.Generate(ClientName);

        await using var server = await ServerAsync(key);

        var query    = RawDnsWriter.Query(0x2939, ZoneFixtures.AName, RawDnsType.A);

        var good     = RawDnsReader.Parse((await RawDnsProbe.TcpAsync(server.TcpPort, SIG0Signer.Sign(query, key)))!);
        var bad      = RawDnsReader.Parse((await RawDnsProbe.TcpAsync(server.TcpPort, SIG0Signer.Sign(query, SIG0Key.Generate(ClientName))))!);

        Assert.Multiple(() => {

            // The TCP listener is a separate code path from the UDP one, and a
            // check applied on only one of them is a check an attacker chooses
            // not to meet.
            Assert.That(good.RCode,   Is.Zero);
            Assert.That(good.Answers, Is.Not.Empty);

            Assert.That(bad.RCode,    Is.EqualTo(9), "NOTAUTH over TCP too");
            Assert.That(bad.Answers,  Is.Empty);

        });

    }

    #endregion

    #region An_Expired_Signature_Is_Refused()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public async Task An_Expired_Signature_Is_Refused()
    {

        var key = SIG0Key.Generate(ClientName);

        await using var server = await ServerAsync(key);

        var now      = DateTimeOffset.UtcNow;

        var stale    = SIG0Signer.Sign(RawDnsWriter.Query(0x293A, ZoneFixtures.AName, RawDnsType.A),
                                       key,
                                       Inception:  now.AddHours(-2),
                                       Expiration: now.AddHours(-1));

        var response = RawDnsReader.Parse((await RawDnsProbe.UdpAsync(server.UdpPort, stale))!);

        Assert.Multiple(() => {

            // The signature is cryptographically perfect; the window is what makes
            // a captured message stop working, and it is the only replay defence
            // SIG(0) has — there is no MAC chain and no original-ID field.
            Assert.That(response.RCode,   Is.EqualTo(9), "NOTAUTH");
            Assert.That(response.Answers, Is.Empty);

        });

    }

    #endregion

    #region The_Tsig_Path_Still_Works_Unchanged()

    [Test]
    [Property("RFC", "8945 §5.3")]
    public async Task The_Tsig_Path_Still_Works_Unchanged()
    {

        // A regression guard rather than a new requirement: SIG(0) verification
        // was threaded through the same server entry point TSIG uses, and the
        // cheapest way for that to go wrong is silently.
        var tsigKey = new TSIGKey(DomainName.Parse("still-here."), Convert.FromBase64String("c2VydmVyLXNpZGUtdHNpZy10ZXN0LXNlY3JldC0xMjM0NTY3OA=="));

        await using var server = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
                                          TSIGKeys  = [ tsigKey ],
                                          SIG0Keys  = [ SIG0Key.Generate(ClientName).PublicKey ]
                                      });

        var query    = RawDnsWriter.Query(0x293B, ZoneFixtures.AName, RawDnsType.A);
        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, TSIGSigner.Sign(query, tsigKey));
        var response = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero);
            Assert.That(response.Answers, Is.Not.Empty);
            Assert.That(response.Additionals.Any(rr => rr.Type == TsigType), Is.True,
                        "RFC 8945 §5.3 still has the reply signed, SIG(0) or no SIG(0)");
        });

    }

    #endregion

}

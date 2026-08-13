using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 7873 §5.2 — the server half of the DNS Cookie exchange.
/// </summary>
/// <remarks>
/// <para>
/// A DNS Cookie is a cheap proof that a querier can receive at the address it
/// claims to be at. The server issues a value, the client hands it back, and
/// only then does the query cost a real answer — which does nothing to an
/// honest client and everything to a spoofed source address, since the spoofer
/// never sees the cookie it would need to return.
/// </para>
/// <para>
/// That only works if the cookie is bound to something. A value the server hands
/// out and accepts from anyone is a bearer token, and proves nothing beyond
/// having once seen a packet. So the assertions below are mostly about what a
/// cookie must *not* be usable for: another client cookie, another address, or
/// forever.
/// </para>
/// <para>
/// The exchange is driven over raw sockets and read back with the independent
/// RawDns parser.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "7873 §5.2")]
public class ServerCookieTests
{

    private const UInt16 CookieOptionCode = 10;

    /// <summary>A 128-bit secret, which is what SipHash-2-4 takes as its key (RFC 9018 §4.4).</summary>
    private static readonly Byte[] Secret = Convert.FromHexString("0123456789abcdef0123456789abcdef");


    #region (private static) helpers

    private static Task<HermodServerFixture> ServerAsync(Boolean RequireCookies = false, Boolean WithSecret = true)

        => HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
               DNSCookieSecret    = WithSecret ? Secret : null,
               RequireDNSCookies  = RequireCookies
           });


    private static Byte[] CookieOptionBytes(Byte[] ClientCookie, Byte[]? ServerCookie = null)
    {

        var data = ServerCookie is null
                       ? ClientCookie
                       : [.. ClientCookie, .. ServerCookie];

        return new RawDnsWriter().
                   U16(CookieOptionCode).
                   U16((UInt16) data.Length).
                   Bytes(data).
                   ToArray();

    }

    /// <summary>A query carrying a COOKIE option built from raw octets — including illegal ones.</summary>
    private static Byte[] QueryWithRawCookie(Byte[] CookieData, UInt16 Id = 0x7873)

        => new RawDnsWriter().
               Header(Id, RawDnsFlags.RD, 1, 0, 0, 1).
               Question(ZoneFixtures.AName, RawDnsType.A).
               Opt(1232, options: new RawDnsWriter().
                                      U16(CookieOptionCode).
                                      U16((UInt16) CookieData.Length).
                                      Bytes(CookieData).
                                      ToArray()).
               ToArray();


    private static async Task<RawDnsMessage> Ask(HermodServerFixture Server, Byte[] Query)
    {

        var raw = await RawDnsProbe.UdpAsync(Server.UdpPort, Query);

        Assert.That(raw, Is.Not.Null, "the server must answer");

        return RawDnsReader.Parse(raw!);

    }


    private static (Byte[] Client, Byte[]? Server)? CookieOf(RawDnsMessage Response)
    {

        var data = Response.Edns?.Options.FirstOrDefault(option => option.Code == CookieOptionCode).Data;

        return data is null || data.Length < 8
                   ? null
                   : (data[..8], data.Length > 8 ? data[8..] : null);

    }


    private static Byte[] ClientCookie(Byte Fill)
    {
        var cookie = new Byte[8];
        Array.Fill(cookie, Fill);
        return cookie;
    }

    #endregion


    #region A_Query_With_Only_A_Client_Cookie_Is_Given_A_Server_Cookie()

    [Test]
    [Property("RFC", "7873 §5.2.3")]
    public async Task A_Query_With_Only_A_Client_Cookie_Is_Given_A_Server_Cookie()
    {

        // §5.2.3: "Servers MUST, at least occasionally, respond to such requests
        // to inform the client of the correct Server Cookie." A client that is
        // never told one can never present one, so a server that stays silent
        // here has switched the mechanism off for everybody while appearing to
        // support it.
        await using var server = await ServerAsync();

        var response = await Ask(server, QueryWithRawCookie(ClientCookie(0x11)));
        var cookie   = CookieOf(response);

        Assert.That(cookie, Is.Not.Null, "the reply must carry a COOKIE option");

        Assert.Multiple(() => {

            Assert.That(cookie!.Value.Client, Is.EqualTo(ClientCookie(0x11)),
                        "the client cookie is echoed exactly — RFC 7873 §5.3 has the client discard " +
                        "any response where it is not");

            Assert.That(cookie.Value.Server, Is.Not.Null, "and a server cookie is supplied");

            Assert.That(cookie.Value.Server!.Length, Is.InRange(8, 32),
                        "RFC 7873 §4.2: a server cookie is 8 to 32 octets");

        });

    }

    #endregion

    #region A_Returned_Server_Cookie_Is_Accepted()

    [Test]
    [Property("RFC", "7873 §5.2.5")]
    public async Task A_Returned_Server_Cookie_Is_Accepted()
    {

        // The handshake, end to end: ask, take the cookie, ask again with it.
        // Even with cookies required, the second query is served.
        await using var server = await ServerAsync(RequireCookies: true);

        var client   = ClientCookie(0x22);

        var first    = await Ask(server, QueryWithRawCookie(client));
        var issued   = CookieOf(first)!.Value.Server!;

        var second   = await Ask(server, QueryWithRawCookie([.. client, .. issued]));

        Assert.Multiple(() => {

            Assert.That(first.CombinedRcode,  Is.EqualTo(23), "the first query has no server cookie yet: BADCOOKIE");
            Assert.That(second.CombinedRcode, Is.Zero,        "the second returns one this server issued");
            Assert.That(second.Answers,       Is.Not.Empty);

        });

    }

    #endregion

    #region A_Missing_Or_Forged_Server_Cookie_Is_BadCookie()

    [Test]
    [Property("RFC", "7873 §5.2.3")]
    [Property("RFC", "7873 §5.2.4")]
    public async Task A_Missing_Or_Forged_Server_Cookie_Is_BadCookie()
    {

        await using var server = await ServerAsync(RequireCookies: true);

        var client        = ClientCookie(0x33);
        var forged        = new Byte[16];
        Array.Fill(forged, (Byte) 0x99);

        var withoutCookie = await Ask(server, QueryWithRawCookie(client));
        var withForged    = await Ask(server, QueryWithRawCookie([.. client, .. forged]));

        Assert.Multiple(() => {

            Assert.That(withoutCookie.CombinedRcode, Is.EqualTo(23), "BADCOOKIE (RFC 7873 §8)");
            Assert.That(withForged.CombinedRcode,    Is.EqualTo(23));

            Assert.That(withoutCookie.Answers, Is.Empty, "and nothing is served for it");
            Assert.That(withForged.Answers,    Is.Empty);

        });

        // §5.3 depends on this: BADCOOKIE is only actionable because the response
        // carries a cookie the client can use on its next try. Without it the
        // client would retry forever with the value that was just refused.
        Assert.Multiple(() => {

            Assert.That(CookieOf(withoutCookie)?.Server, Is.Not.Null,
                        "a BADCOOKIE response must still hand over a valid server cookie");

            Assert.That(CookieOf(withForged)?.Server,    Is.Not.Null);

        });

    }

    #endregion

    #region A_Server_Cookie_Is_Bound_To_Its_Client_Cookie()

    [Test]
    [Property("RFC", "7873 §5.2.4")]
    public async Task A_Server_Cookie_Is_Bound_To_Its_Client_Cookie()
    {

        // A server cookie that any client cookie could carry is a bearer token:
        // one observed on the wire would work for anybody who copied it. Binding
        // it makes an observed cookie worth nothing to a third party.
        await using var server = await ServerAsync(RequireCookies: true);

        var mine    = ClientCookie(0x44);
        var theirs  = ClientCookie(0x55);

        var issued  = CookieOf(await Ask(server, QueryWithRawCookie(mine)))!.Value.Server!;

        var reused  = await Ask(server, QueryWithRawCookie([.. theirs, .. issued]));

        Assert.That(reused.CombinedRcode, Is.EqualTo(23),
                    "the same server cookie under a different client cookie must not be accepted");

    }

    #endregion

    #region Cookies_Do_Not_Change_The_Answer_When_They_Are_Not_Required()

    [Test]
    [Property("RFC", "7873 §5.2.3")]
    public async Task Cookies_Do_Not_Change_The_Answer_When_They_Are_Not_Required()
    {

        // §5.2.3 leaves it to the server whether a query lacking a server cookie
        // is answered or refused. Answering is the default here, because
        // requiring cookies changes what every existing client sees — and a
        // resolver that suddenly needs a second round trip for every query is a
        // change worth asking for rather than inheriting.
        await using var server = await ServerAsync(RequireCookies: false);

        var response = await Ask(server, QueryWithRawCookie(ClientCookie(0x66)));

        Assert.Multiple(() => {

            Assert.That(response.CombinedRcode, Is.Zero);
            Assert.That(response.Answers,       Is.Not.Empty, "the answer is served straight away");

            Assert.That(CookieOf(response)?.Server, Is.Not.Null,
                        "and the server cookie is supplied anyway, so the client can use it next time");

        });

    }

    #endregion

    #region An_Illegal_Cookie_Length_Is_A_Format_Error()

    [TestCase(7,  TestName = "Illegal_cookie_length__too_short_for_a_client_cookie")]
    [TestCase(9,  TestName = "Illegal_cookie_length__one_past_a_bare_client_cookie")]
    [TestCase(15, TestName = "Illegal_cookie_length__one_short_of_a_server_cookie")]
    [TestCase(41, TestName = "Illegal_cookie_length__one_past_the_maximum")]
    [Property("RFC", "7873 §5.2.2")]
    public async Task An_Illegal_Cookie_Length_Is_A_Format_Error(Int32 Length)
    {

        // §5.2.2 names the three ways to get this wrong and gives them all the
        // same answer: "valid cookie lengths are 8 and 16 to 40 inclusive". The
        // gap from 9 to 15 is the one worth testing — it looks like a short
        // server cookie and is not, since §4.2 gives the server cookie a minimum
        // of 8. A receiver that split it anyway would produce a server cookie no
        // issuing server can recognise, and blame the client for it.
        await using var server = await ServerAsync();

        var response = await Ask(server, QueryWithRawCookie(new Byte[Length]));

        Assert.That(response.CombinedRcode, Is.EqualTo(1), "FORMERR");

    }

    #endregion

    #region A_Query_Without_A_Cookie_Is_Served_And_Answered_Without_One()

    [Test]
    [Property("RFC", "7873 §5.2.1")]
    public async Task A_Query_Without_A_Cookie_Is_Served_And_Answered_Without_One()
    {

        // §5.2.1: a query with no COOKIE option is ordinary DNS. Offering a
        // cookie to a client that did not ask for one would be harmless but
        // pointless — it has nowhere to put it.
        await using var server = await ServerAsync();

        var response = await Ask(
                           server,
                           RawDnsWriter.Query(0x7874, ZoneFixtures.AName, RawDnsType.A, ednsPayloadSize: 1232)
                       );

        Assert.Multiple(() => {

            Assert.That(response.CombinedRcode, Is.Zero);
            Assert.That(response.Answers,       Is.Not.Empty);
            Assert.That(CookieOf(response),     Is.Null, "nothing was asked, so nothing is offered");

        });

    }

    #endregion

    #region A_Server_Without_A_Secret_Ignores_Cookies_Entirely()

    [Test]
    [Property("RFC", "7873 §5.2.1")]
    public async Task A_Server_Without_A_Secret_Ignores_Cookies_Entirely()
    {

        // Cookies are off unless a secret is configured, and a server with them
        // off behaves exactly as it did before they existed — it does not fail,
        // it simply has nothing to say about the option.
        await using var server = await ServerAsync(WithSecret: false);

        var response = await Ask(server, QueryWithRawCookie(ClientCookie(0x77)));

        Assert.Multiple(() => {

            Assert.That(response.CombinedRcode, Is.Zero);
            Assert.That(response.Answers,       Is.Not.Empty);
            Assert.That(CookieOf(response),     Is.Null);

        });

    }

    #endregion


    #region The cookie itself — what a socket cannot reach

    #region RFC 9018 Appendix A — the published vectors

    #region The_Published_Server_Cookies_Are_Reproduced_Exactly()

    [TestCase("198.51.100.100",                     "2464c4abcf10c957", "e5e973e5a6b2a43f48e7dc849e37bfcf", 1559731985u,
              "2464c4abcf10c957010000005cf79f111f8130c3eee29480", TestName = "RFC9018_vector__A1_learning_a_server_cookie")]
    [TestCase("198.51.100.100",                     "2464c4abcf10c957", "e5e973e5a6b2a43f48e7dc849e37bfcf", 1559734385u,
              "2464c4abcf10c957010000005cf7a871d4a564a1442aca77", TestName = "RFC9018_vector__A2_renewing_it")]
    [TestCase("203.0.113.203",                      "fc93fc62807ddb86", "e5e973e5a6b2a43f48e7dc849e37bfcf", 1559734700u,
              "fc93fc62807ddb86010000005cf7a9acf73a7810aca2381e", TestName = "RFC9018_vector__A3_another_client")]
    [TestCase("2001:db8:220:1:59de:d0f4:8769:82b8", "22681ab97d52c298", "445536bcd2513298075a5d379663c962", 1559741961u,
              "22681ab97d52c298010000005cf7c609a6bb79d16625507a", TestName = "RFC9018_vector__A4_an_IPv6_client")]
    [Property("RFC", "9018 §4.4")]
    public void The_Published_Server_Cookies_Are_Reproduced_Exactly(String  ClientIP,
                                                                    String  ClientCookieHex,
                                                                    String  SecretHex,
                                                                    UInt32  Timestamp,
                                                                    String  ExpectedOption)
    {

        // The reason RFC 9018 exists at all, and the reason it is worth
        // following: a server cookie is normally only ever checked by the server
        // that made it, so any keyed hash would do — until an anycast cluster
        // shares one secret and a cookie issued by one node arrives at another.
        // Then the construction has to be the same construction, down to the
        // octet, and these four vectors are what "the same" means.
        //
        // §4.4 gives the formula and not the byte order of the 64-bit hash. The
        // vectors settle it: all four reproduce with the little-endian
        // serialisation SipHash's own reference implementation uses, and none
        // with the other. Worth knowing rather than guessing, since a big-endian
        // implementation would validate its own cookies perfectly and nobody
        // else's — which is the one failure this RFC is written to prevent.
        var cookie = DNSCookies.Create(
                         Convert.FromHexString(ClientCookieHex),
                         org.GraphDefined.Vanaheimr.Hermod.IPAddress.Parse(ClientIP),
                         Convert.FromHexString(SecretHex),
                         DateTimeOffset.FromUnixTimeSeconds(Timestamp)
                     );

        var option = Convert.FromHexString(ClientCookieHex).Concat(cookie).ToArray();

        Assert.That(Convert.ToHexString(option).ToLowerInvariant(), Is.EqualTo(ExpectedOption));

    }

    #endregion

    #region A_Published_Vector_Validates_Against_Its_Own_Inputs()

    [Test]
    [Property("RFC", "9018 §4.4")]
    public void A_Published_Vector_Validates_Against_Its_Own_Inputs()
    {

        // The other direction: the RFC's own cookie, handed back to this
        // implementation, is accepted. Producing a matching cookie and
        // recognising one are different code paths, and an implementation can
        // get the first right and still refuse everything.
        var clientCookie = Convert.FromHexString("2464c4abcf10c957");
        var serverCookie = Convert.FromHexString("010000005cf79f111f8130c3eee29480");
        var secret       = Convert.FromHexString("e5e973e5a6b2a43f48e7dc849e37bfcf");
        var address      = org.GraphDefined.Vanaheimr.Hermod.IPAddress.Parse("198.51.100.100");

        // The vector's timestamp is from 2019, so validity has to be measured
        // from then — the point here is the hash, not the clock.
        var issued       = DateTimeOffset.FromUnixTimeSeconds(1559731985);

        Assert.Multiple(() => {

            Assert.That(DNSCookies.Validate(serverCookie, clientCookie, address, secret, issued),
                        Is.True);

            Assert.That(DNSCookies.Validate(serverCookie, clientCookie, address, DNSCookies.GenerateSecret(), issued),
                        Is.False,
                        "and not under a secret that did not make it");

        });

    }

    #endregion

    #region A_Secret_Of_The_Wrong_Size_Is_Refused()

    [TestCase(15, TestName = "Wrong_secret_size__one_short")]
    [TestCase(17, TestName = "Wrong_secret_size__one_long")]
    [TestCase(32, TestName = "Wrong_secret_size__an_HMAC_sized_key")]
    [Property("RFC", "9018 §4.4")]
    public void A_Secret_Of_The_Wrong_Size_Is_Refused(Int32 Size)
    {

        // SipHash-2-4 takes a 128-bit key and RFC 9018 names no other. A longer
        // one is the shape a previous construction here used, and silently
        // truncating or padding it would produce cookies that no other member of
        // a cluster could check — which is the failure this whole RFC exists to
        // remove, arrived at by being lenient.
        //
        // The message is asserted, not just the type. BouncyCastle rejects a
        // wrong-sized key too, with an ArgumentException of its own, so a test
        // that only checked the type would pass with this check removed — a
        // redundant guard hiding a broken one, which is the second time this
        // suite has met that shape. The message is also the deliverable here:
        // it is what an operator who mis-sized a secret in a config file reads.
        Assert.That(
            () => DNSCookies.Create(new Byte[8], org.GraphDefined.Vanaheimr.Hermod.IPAddress.Parse("192.0.2.1"), new Byte[Size]),
            Throws.InstanceOf<ArgumentException>().With.Message.Contains("RFC 9018")
        );

    }

    #endregion

    #region The_Timestamp_Window_Survives_The_2106_Wrap()

    [Test]
    [Property("RFC", "9018 §4.3")]
    [Property("RFC", "1982")]
    public void The_Timestamp_Window_Survives_The_2106_Wrap()
    {

        // §4.3: "since the Timestamp is a 32-bit field, comparisons must use
        // serial number arithmetic [RFC1982]".
        //
        // The field runs out in February 2106 and starts again at zero. A
        // validator comparing the two as absolute instants would then see every
        // freshly issued cookie as 136 years in the future and refuse it, for an
        // hour, once — a failure nobody would be able to reproduce and everybody
        // would blame on something else. Serial arithmetic makes the distance
        // the short way round the circle, which is seconds.
        var clientCookie = new Byte[8];
        var address      = org.GraphDefined.Vanaheimr.Hermod.IPAddress.Parse("192.0.2.1");

        // Ten seconds before the field wraps.
        var beforeWrap   = DateTimeOffset.FromUnixTimeSeconds(UInt32.MaxValue - 10);
        var afterWrap    = DateTimeOffset.FromUnixTimeSeconds((Int64) UInt32.MaxValue + 20);

        var cookie       = DNSCookies.Create(clientCookie, address, Secret, beforeWrap);

        Assert.That(DNSCookies.Validate(cookie, clientCookie, address, Secret, afterWrap), Is.True,
                    "a cookie thirty seconds old is thirty seconds old, whichever side of the wrap it sits");

    }

    #endregion

    #endregion


    #region A_Server_Cookie_Is_Bound_To_The_Address_It_Was_Issued_To()

    [Test]
    [Property("RFC", "7873 §5.2.4")]
    public void A_Server_Cookie_Is_Bound_To_The_Address_It_Was_Issued_To()
    {

        // Every query in this fixture comes from loopback, so the address binding
        // cannot be exercised over a socket. It is the binding that matters most:
        // without it a cookie observed anywhere works from anywhere, and a
        // mechanism whose entire purpose is to prove where a query came from
        // proves nothing at all.
        var clientCookie = ClientCookie(0x88);
        var issuedTo     = IPv4Address.Parse("192.0.2.10");
        var elsewhere    = IPv4Address.Parse("192.0.2.11");

        var cookie       = DNSCookies.Create(clientCookie, issuedTo, Secret);

        Assert.Multiple(() => {

            Assert.That(DNSCookies.Validate(cookie, clientCookie, issuedTo,  Secret), Is.True);
            Assert.That(DNSCookies.Validate(cookie, clientCookie, elsewhere, Secret), Is.False,
                        "a cookie is worth nothing from an address it was not issued to");

        });

    }

    #endregion

    #region A_Server_Cookie_Expires()

    [Test]
    public void A_Server_Cookie_Expires()
    {

        // The timestamp is what stops a cookie captured once from being useful
        // indefinitely. It sits inside the hash rather than beside it, so a
        // client cannot move it forward to extend its own cookie's life — which
        // the second assertion is there to pin.
        var clientCookie = ClientCookie(0x99);
        var address      = IPv4Address.Parse("192.0.2.10");
        var issued       = DateTimeOffset.UtcNow;

        var cookie       = DNSCookies.Create(clientCookie, address, Secret, issued);

        Assert.Multiple(() => {

            Assert.That(DNSCookies.Validate(cookie, clientCookie, address, Secret, issued),
                        Is.True);

            Assert.That(DNSCookies.Validate(cookie, clientCookie, address, Secret, issued + TimeSpan.FromHours(2)),
                        Is.False,
                        "an hour later it is no longer usable");

            Assert.That(DNSCookies.Validate(cookie, clientCookie, address, Secret, issued - TimeSpan.FromHours(1)),
                        Is.False,
                        "and a cookie timestamped in the future is refused rather than tolerated");

        });

    }

    #endregion

    #region A_Server_Cookie_From_Another_Secret_Is_Refused()

    [Test]
    public void A_Server_Cookie_From_Another_Secret_Is_Refused()
    {

        var clientCookie = ClientCookie(0xAB);
        var address      = IPv4Address.Parse("192.0.2.10");

        var cookie       = DNSCookies.Create(clientCookie, address, Secret);

        Assert.That(DNSCookies.Validate(cookie, clientCookie, address, DNSCookies.GenerateSecret()), Is.False,
                    "the secret is the only thing that makes the cookie unforgeable");

    }

    #endregion

    #region A_Tampered_Server_Cookie_Is_Refused()

    [TestCase(0,  TestName = "Tampered_cookie__version_octet")]
    [TestCase(5,  TestName = "Tampered_cookie__timestamp")]
    [TestCase(12, TestName = "Tampered_cookie__hash")]
    public void A_Tampered_Server_Cookie_Is_Refused(Int32 Offset)
    {

        var clientCookie = ClientCookie(0xCD);
        var address      = IPv4Address.Parse("192.0.2.10");

        var cookie       = DNSCookies.Create(clientCookie, address, Secret);

        cookie[Offset]  ^= 0xFF;

        Assert.That(DNSCookies.Validate(cookie, clientCookie, address, Secret), Is.False,
                    () => "every octet of the cookie is covered:\n" + Bytes.Dump(cookie));

    }

    #endregion

    #endregion

}

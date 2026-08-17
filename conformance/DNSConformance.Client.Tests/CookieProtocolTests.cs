using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 7873 §5.3 — what a client does with the COOKIE that comes back.
/// </summary>
/// <remarks>
/// <para>
/// The encoding of the option was covered here long ago, and it is the easy
/// part. What makes a cookie worth anything is one property: the client cookie
/// is an unpredictable value that comes back only from someone who saw the
/// query. Everything else in the mechanism rests on that, and the whole of it
/// is enforced by a single sentence of §5.3 — a client "MUST discard the
/// response if it contains an illegal COOKIE option length or an incorrect
/// Client Cookie value".
/// </para>
/// <para>
/// So the interesting tests are all about a response that gets the client
/// cookie wrong, and the sharpest of them is not about the response at all but
/// about the query after it.
/// </para>
/// <para>
/// The peer is scripted, so it can send exactly what an off-path attacker
/// would, and the assertions are on the bytes the client puts on the wire next.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "7873 §5.3")]
public class CookieProtocolTests
{

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromSeconds(10);

    private const UInt16 CookieOptionCode = 10;


    #region (private static) Response builders

    private static Byte[] CookieOptionBytes(Byte[] ClientCookie, Byte[]? ServerCookie)
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

    /// <summary>
    /// An ordinary answer, with a COOKIE option of our choosing and an optional
    /// extended RCODE.
    /// </summary>
    /// <remarks>
    /// RFC 6891 §6.1.3 splits an extended RCODE across two places — the low four
    /// bits stay in the header where they always were, and the upper eight go
    /// into the OPT record's TTL. BADCOOKIE is 23, so the header nibble is 7 and
    /// the OPT byte is 1; writing only one of the two produces BADVERS (16) or
    /// NOTIMP (7) instead, which is a mistake worth making once in a test rather
    /// than in a server.
    /// </remarks>
    private static Byte[] AnswerWith(Byte[]   Request,
                                     Byte[]?  ClientCookie   = null,
                                     Byte[]?  ServerCookie   = null,
                                     Int32    Rcode          = 0)
    {

        var query          = RawDnsReader.Parse(Request, RawDnsReaderOptions.Lenient);
        var question       = query.Questions[0];
        var questionBytes  = Request[12..(12 + question.Name.WireLength + 4)];

        var answers        = Rcode == 0 ? 1 : 0;

        var writer         = new RawDnsWriter().
                                 Header(query.Id,
                                        (UInt16) (RawDnsFlags.QR | RawDnsFlags.RD | RawDnsFlags.RA |
                                                  RawDnsFlags.RCode(Rcode & 0x0F)),
                                        1, (UInt16) answers, 0, 1).
                                 Bytes(questionBytes);

        if (answers == 1)
            writer.RR("cookie.example.", RawDnsType.A, RawDnsClass.IN, 60, RawDnsWriter.IPv4("192.0.2.1"));

        writer.Opt(
            1232,
            extendedRcode: (Byte) (Rcode >> 4),
            options:       ClientCookie is null ? null : CookieOptionBytes(ClientCookie, ServerCookie)
        );

        return writer.ToArray();

    }

    /// <summary>
    /// The COOKIE option of a query the scripted peer received.
    /// </summary>
    private static Byte[]? CookieOf(Byte[] Request)

        => RawDnsReader.Parse(Request, RawDnsReaderOptions.Lenient).
               Edns?.
               Options.
               FirstOrDefault(option => option.Code == CookieOptionCode).
               Data;

    private static DNSClient ClientFor(ScriptedUdpServer Server)

        => new (IPv4Address.Localhost,
                IPPort.Parse((UInt16) Server.Port),
                QueryTimeout:   ShortTimeout,
                UseQueryCache:  false);

    private static Task<DNSInfo> Ask(DNSClient Client, String Name)

        => Client.Query(DNSServiceName.Parse(Name), [ DNSResourceRecordTypes.A ], ShortTimeout);

    #endregion


    #region A_Forged_Client_Cookie_Does_Not_Replace_The_Clients_Own()

    [Test]
    public async Task A_Forged_Client_Cookie_Does_Not_Replace_The_Clients_Own()
    {

        // The sharpest assertion in this fixture, and it is about the *second*
        // query rather than the first.
        //
        // A client that stores the whole COOKIE option from a response — client
        // cookie and all — lets a single spoofed packet choose the value it will
        // use from then on. After that the attacker can echo it at will, so every
        // later response passes the check, and the one unpredictable value in the
        // mechanism is a value the attacker picked. It is a downgrade that
        // installs itself and does not wear off.
        var forged = new Byte[8];  Array.Fill(forged, (Byte) 0xAA);
        var server = new Byte[16]; Array.Fill(server, (Byte) 0xBB);

        await using var peer   = new ScriptedUdpServer(request => AnswerWith(request, forged, server));
        using       var client = ClientFor(peer);

        await Ask(client, "first.example.");
        await Ask(client, "second.example.");

        var requests = peer.Requests.ToArray();

        Assert.That(requests, Has.Length.GreaterThanOrEqualTo(2), "both queries must have reached the peer");

        var firstCookie  = CookieOf(requests[0]);
        var secondCookie = CookieOf(requests[^1]);

        Assert.That(firstCookie,  Is.Not.Null);
        Assert.That(secondCookie, Is.Not.Null);

        Assert.Multiple(() => {

            Assert.That(secondCookie![..8], Is.Not.EqualTo(forged),
                        "the client cookie must never be taken from a response — it is the client's own " +
                        "unpredictable value, and a peer that could set it could impersonate any peer.");

            Assert.That(secondCookie!.Length, Is.EqualTo(8),
                        "and the server cookie that arrived beside the forged client cookie is not kept " +
                        "either: the response it came in was discarded, so nothing in it is trustworthy.");

        });

        // Whether the second query reuses the *same* client cookie is left open
        // on purpose. RFC 7873 §4.1 makes stability a SHOULD, and after a
        // discarded response there is no stored entry to be stable about — a
        // fresh unpredictable value is no weaker than the old one. What matters
        // is only that it was not chosen by the peer.

    }

    #endregion

    #region The_Client_Cookie_Stays_Put_Across_A_Working_Exchange()

    [Test]
    [Property("RFC", "7873 §4.1")]
    public async Task The_Client_Cookie_Stays_Put_Across_A_Working_Exchange()
    {

        // §4.1 wants the client cookie stable per server, and once an exchange
        // has worked there is a concrete reason: a server cookie is bound to the
        // client cookie it was issued for, so changing one throws the other away
        // and the next query starts the handshake over.
        var serverCookie = new Byte[16]; Array.Fill(serverCookie, (Byte) 0x5A);

        await using var peer   = new ScriptedUdpServer(request =>
                                     AnswerWith(request, CookieOf(request)![..8], serverCookie));
        using       var client = ClientFor(peer);

        await Ask(client, "one.example.");
        await Ask(client, "two.example.");
        await Ask(client, "three.example.");

        var cookies = peer.Requests.Select(CookieOf).ToArray();

        Assert.That(cookies[1]![..8], Is.EqualTo(cookies[0]![..8]));
        Assert.That(cookies[2]![..8], Is.EqualTo(cookies[0]![..8]));

    }

    #endregion

    #region A_Response_Echoing_A_Foreign_Client_Cookie_Is_Discarded()

    [Test]
    public async Task A_Response_Echoing_A_Foreign_Client_Cookie_Is_Discarded()
    {

        // §5.3, the sentence itself. A response whose client cookie is not the
        // one that was sent came from someone who did not see the query, which is
        // exactly the party the mechanism exists to exclude.
        var forged = new Byte[8];  Array.Fill(forged, (Byte) 0xAA);
        var server = new Byte[16]; Array.Fill(server, (Byte) 0xBB);

        await using var peer   = new ScriptedUdpServer(request => AnswerWith(request, forged, server));
        using       var client = ClientFor(peer);

        var response = await Ask(client, "spoofed.example.");

        Assert.That(response.Answers, Is.Empty,
                    "a response that fails the cookie check must not be handed to the caller as an answer");

    }

    #endregion

    #region A_Matching_Response_Is_Accepted_And_Its_Server_Cookie_Reused()

    [Test]
    [Property("RFC", "7873 §5.1")]
    public async Task A_Matching_Response_Is_Accepted_And_Its_Server_Cookie_Reused()
    {

        // The control for the two above: with the client cookie echoed correctly
        // the response is used, and the server cookie it carried comes back on
        // the next query — which is the entire point of the exchange.
        var serverCookie = new Byte[16]; Array.Fill(serverCookie, (Byte) 0xCD);

        await using var peer   = new ScriptedUdpServer(request =>
                                     AnswerWith(request, CookieOf(request)![..8], serverCookie));
        using       var client = ClientFor(peer);

        var response = await Ask(client, "good.example.");

        await Ask(client, "again.example.");

        var requests = peer.Requests.ToArray();
        var second   = CookieOf(requests[^1]);

        Assert.Multiple(() => {

            Assert.That(response.Answers, Is.Not.Empty, "a correctly cookied response is an answer");

            Assert.That(second,        Is.Not.Null);
            Assert.That(second!.Length, Is.EqualTo(24), "8 octets of client cookie plus the 16 the peer issued");
            Assert.That(second[8..],    Is.EqualTo(serverCookie),
                        "the server cookie must be remembered per server and sent back");

        });

    }

    #endregion

    #region A_Badcookie_Response_Is_Retried_With_The_Cookie_It_Supplied()

    [Test]
    [Property("RFC", "7873 §5.2.3")]
    public async Task A_Badcookie_Response_Is_Retried_With_The_Cookie_It_Supplied()
    {

        // §5.3: BADCOOKIE is not a refusal, it is "ask again with this". The
        // response carries a valid server cookie precisely so the second attempt
        // can succeed, and a client that treats the RCODE as an error instead
        // simply never gets an answer from a server that requires cookies.
        var issued = new Byte[16]; Array.Fill(issued, (Byte) 0xEE);

        await using var peer = new ScriptedUdpServer((request, index) => {

            var clientCookie = CookieOf(request)![..8];

            // The first query has no server cookie; answer BADCOOKIE (23) and
            // hand one over. Anything after that is served.
            return index == 0
                       ? [ AnswerWith(request, clientCookie, issued, Rcode: 23) ]   // BADCOOKIE
                       : [ AnswerWith(request, clientCookie, issued) ];

        });

        using var client = ClientFor(peer);

        var response = await Ask(client, "badcookie.example.");

        var requests = peer.Requests.ToArray();

        Assert.That(requests, Has.Length.GreaterThanOrEqualTo(2),
                    "BADCOOKIE has to produce a second attempt, or the exchange can never complete");

        Assert.Multiple(() => {

            Assert.That(CookieOf(requests[1])?[8..], Is.EqualTo(issued),
                        "and the retry carries the server cookie the BADCOOKIE response supplied");

            Assert.That(response.Answers, Is.Not.Empty, "so the caller ends up with the answer");

        });

    }

    #endregion

    #region A_Response_Without_A_Cookie_Is_Still_Accepted()

    [Test]
    [Property("RFC", "7873 §5.2.1")]
    public async Task A_Response_Without_A_Cookie_Is_Still_Accepted()
    {

        // §5.2.1 lets a server that does not implement cookies answer normally,
        // and most of the deployed world still does. Refusing those answers would
        // turn an optional robustness feature into an outage.
        await using var peer   = new ScriptedUdpServer(request => AnswerWith(request));
        using       var client = ClientFor(peer);

        var response = await Ask(client, "nocookie.example.");

        Assert.That(response.Answers, Is.Not.Empty,
                    "a server with no cookie support is not a server to be ignored");

    }

    #endregion

    #region The_Client_Cookie_Is_Stable_Even_Without_A_Server_Cookie()

    [Test]
    [Property("RFC", "7873 §4.1")]
    public async Task The_Client_Cookie_Is_Stable_Even_Without_A_Server_Cookie()
    {

        // The case that covers most of the deployed internet: a peer that answers
        // perfectly well and says nothing about cookies. There is no server
        // cookie to remember, so a client that only kept the pair had nothing to
        // keep — and generated a fresh client cookie on every single query.
        //
        // §4.1 asks for a value derived from the client address, the server
        // address and a secret, which is stable by construction whether or not
        // anything came back. The RFC's own reason is efficiency — churning it
        // means "undue inefficiency due to retries caused by that server not
        // recognizing the Client Cookie" — and the day such a peer does answer
        // with a cookie, the client already has a stable value to bind it to.
        await using var peer   = new ScriptedUdpServer(request => AnswerWith(request));
        using       var client = ClientFor(peer);

        for (var i = 0; i < 4; i++)
            await Ask(client, $"q{i}.example.");

        var cookies = peer.Requests.Select(CookieOf).ToArray();

        Assert.That(cookies, Has.Length.EqualTo(4));

        Assert.Multiple(() => {

            foreach (var cookie in cookies)
                Assert.That(cookie![..8], Is.EqualTo(cookies[0]![..8]),
                            "the client cookie must not change between queries to one server");

        });

    }

    #endregion

    #region The_Client_Always_Offers_A_Cookie()

    [Test]
    [Property("RFC", "7873 §5.1")]
    public async Task The_Client_Always_Offers_A_Cookie()
    {

        await using var peer   = new ScriptedUdpServer(request => AnswerWith(request));
        using       var client = ClientFor(peer);

        await Ask(client, "offered.example.");

        var cookie = CookieOf(peer.Requests.First());

        Assert.Multiple(() => {

            Assert.That(cookie, Is.Not.Null, "a client that never offers a cookie can never be given one");

            Assert.That(cookie!.Length, Is.EqualTo(8),
                        "the first query to a server carries a client cookie and nothing else — there is no " +
                        "server cookie to present yet (RFC 7873 §5.1)");

            Assert.That(cookie, Is.Not.EqualTo(new Byte[8]),
                        "and it is not all zeroes: an unpredictable value is the whole mechanism");

        });

    }

    #endregion

}

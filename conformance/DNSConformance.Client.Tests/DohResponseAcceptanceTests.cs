using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// Which DoH responses a client may read, and which it must refuse to read.
/// </summary>
/// <remarks>
/// <para>
/// RFC 8484 §4.2.1 ties a DNS response to the status class rather than to one
/// code: "A successful HTTP response with a 2xx status code [...] is used for any
/// valid DNS response, regardless of the DNS response code." Two rules come out
/// of one sentence — every 2xx carries an answer, and nothing else does — and a
/// client can get them wrong in opposite directions.
/// </para>
/// <para>
/// The other edge is the body. RFC 1035 §4.1.1 makes the header twelve octets,
/// and a message consisting of nothing else is a complete message: it is how a
/// response says "no records" without saying anything further. Twelve is
/// therefore the smallest legal body and not the smallest illegal one.
/// </para>
/// </remarks>
[TestFixture]
public class DohResponseAcceptanceTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(3);


    /// <summary>A bare twelve-octet header echoing the request's ID, with the given RCODE.</summary>
    private static Byte[] BareHeader(Byte[] Request, Int32 RCode)

        => new RawDnsWriter().
               Header(RawDnsReader.Parse(Request).Id,
                      (UInt16) (RawDnsFlags.QR | RawDnsFlags.RD | RawDnsFlags.RA | RawDnsFlags.RCode(RCode)),
                      0, 0, 0, 0).
               ToArray();


    /// <summary>One A answer for the name the request asked about.</summary>
    private static Byte[] OneAddress(Byte[] Request)

        => RawDnsResponder.Answer(Request, ("probe.example.", RawDnsType.A, 60, [192, 0, 2, 13]));


    private static async Task<DNSInfo> AskOverDoH(ScriptedDoHServer Peer)
    {

        await using var client = new DNSHTTPSClient(URL.Parse(Peer.Url),
                                                    QueryTimeout: Timeout);

        return await client.Query(DNSServiceName.Parse("probe.example."),
                                  [ DNSResourceRecordTypes.A ],
                                  Timeout);

    }

    #endregion


    #region A response with no question to match (RFC 5452 §9.1)

    [Test]
    [Property("RFC", "5452 §9.1, 1035 §4.1.1")]
    public async Task A_Response_Carrying_No_Question_Is_Not_Accepted()
    {

        // Twelve octets is a whole DNS message — RFC 1035 §4.1.1 gives the header
        // exactly that size — so it passes every length check there is. What it
        // cannot pass is RFC 5452 §9.1, which has a resolver match a response to
        // "Query ID, Query name, Query type, Query class": a message with QDCOUNT
        // zero carries none of the last three, so there is nothing to match and
        // nothing that licenses believing it.
        //
        // This was written the other way round first — asserting that twelve
        // octets are *read*, on the grounds that the header is a complete message.
        // It is, and the response is still refused, because being well-formed is
        // not the same as being an answer to this question. Which is also why the
        // minimum-length guard's own boundary cannot be reached from outside: at
        // exactly twelve the stricter rule behind it refuses the same message.
        await using var peer = new ScriptedDoHServer(request => BareHeader(request, 0));

        var answer = await AskOverDoH(peer);

        Assert.Multiple(() => {

            Assert.That(peer.Exchanges, Has.Count.EqualTo(1),
                        "the exchange happened, so this is a judgement about the response");

            Assert.That(answer.IsValid, Is.False,
                        "§9.1: an unmatchable response is not one a resolver may use");

        });

    }

    #endregion


    #region Where 2xx ends (RFC 8484 §4.2.1)

    [Test]
    [Property("RFC", "8484 §4.2.1")]
    public async Task A_Status_Outside_The_Two_Hundreds_Is_Not_Read_As_A_Dns_Response()
    {

        // The body here is a perfectly good DNS answer, and that is the point: the
        // client must refuse it on the status alone. §4.2.1 grants a DNS response
        // to 2xx and to nothing else, and §5 tells a DoH client to "use the same
        // semantic processing of non-successful HTTP status codes as other HTTP
        // clients" — for which a 3xx is a redirection to be followed, never a
        // payload to be parsed.
        await using var peer = new ScriptedDoHServer(OneAddress) { StatusCode = 300 };

        var answer = await AskOverDoH(peer);

        Assert.That(answer.Answers.Any(record => record.Type == DNSResourceRecordTypes.A),
                    Is.False,
                    "§4.2.1: only a 2xx status carries a DNS response, whatever the body looks like");

    }


    [Test]
    [Property("RFC", "8484 §4.2.1, 9110 §15.3")]
    public async Task A_Two_Hundred_Class_Status_That_Is_Not_Two_Hundred_Is_Read()
    {

        // The other direction of the same sentence, and the reason it says 2xx
        // rather than 200. RFC 9110 §15.3 assigns 203 its own meaning — the
        // payload has been transformed by a proxy — and a resolver reached through
        // one still answered. A client that accepts only 200 discards an answer
        // §4.2.1 grants it.
        await using var peer = new ScriptedDoHServer(OneAddress) { StatusCode = 203 };

        var answer = await AskOverDoH(peer);

        Assert.That(answer.Answers.Any(record => record.Type == DNSResourceRecordTypes.A),
                    Is.True,
                    "§4.2.1: a successful response with a 2xx status code is used for any valid " +
                    "DNS response");

    }

    #endregion


    #region One type per JSON request

    [Test]
    public async Task Json_Mode_Asks_For_Each_Type_Separately_And_Binary_Mode_Does_Not()
    {

        // Not an RFC rule: the JSON API of Google and Cloudflare is not an IETF
        // standard, and its shape is the constraint — ?type= takes one value, so
        // two types need two requests. The wire format has no such limit, because
        // a question section holds as many questions as it likes.
        //
        // So one guard decides two things, and getting either half wrong is
        // silent: a JSON client that sends both types in one request loses one of
        // them, and a wire-format client that fans out sends two messages where
        // one would do and then has to merge what comes back.
        await using var jsonPeer = new ScriptedDoHServer(_ => null) {
                                       JSONResponse = """
                                                      {"Status":0,"RA":true,"Answer":[{"name":"probe.example.","type":1,"TTL":60,"data":"192.0.2.13"}]}
                                                      """
                                   };

        await using (var jsonClient = new DNSHTTPSClient(URL.Parse(jsonPeer.Url),
                                                         Mode:          DNSHTTPSMode.JSON,
                                                         QueryTimeout:  Timeout))
        {
            await jsonClient.Query(DNSServiceName.Parse("probe.example."),
                                   [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ],
                                   Timeout);
        }

        await using var binaryPeer = new ScriptedDoHServer(OneAddress);

        await using (var binaryClient = new DNSHTTPSClient(URL.Parse(binaryPeer.Url),
                                                           QueryTimeout: Timeout))
        {
            await binaryClient.Query(DNSServiceName.Parse("probe.example."),
                                     [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ],
                                     Timeout);
        }

        Assert.Multiple(() => {

            Assert.That(jsonPeer.Exchanges, Has.Count.EqualTo(2),
                        "two types, and a query parameter that holds one, make two requests");

            Assert.That(binaryPeer.Exchanges, Has.Count.EqualTo(1),
                        "and a question section that holds both makes one");

        });

    }

    #endregion

}

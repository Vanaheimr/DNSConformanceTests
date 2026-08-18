using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.SecureTransports.Tests;

/// <summary>
/// RFC 8484 — DNS Queries over HTTPS. Hermod's DoH client is pointed at a
/// scripted RFC 8484 endpoint (plain HTTP; the HTTP semantics are what is
/// under test, not TLS) and every request it makes is inspected.
/// </summary>
[TestFixture]
[Property("RFC", "8484")]
public class DohClientTests
{

    private static ScriptedDoHServer NewServer()
        => new(request => RawDnsResponder.Answer(
                              request,
                              ("doh.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.42"))
                          ));

    // The URL-based constructor keeps the http:// scheme, so the client talks
    // plain HTTP to the scripted endpoint. RFC 8484 is an HTTP specification;
    // TLS is RFC 8484 §3's transport requirement and is covered by the DoT/PKI
    // tests rather than here, where the HTTP semantics are what is measured.
    private static DNSHTTPSClient NewClient(ScriptedDoHServer server, DNSHTTPSMode mode)
        => new(
               URL.Parse(server.Url),
               Mode:          mode,
               QueryTimeout:  TimeSpan.FromSeconds(10)
           );


    #region Get_Uses_Unpadded_Base64Url_In_The_Dns_Parameter()

    [Test]
    [Property("RFC", "8484 §4.1")]
    public async Task Get_Uses_Unpadded_Base64Url_In_The_Dns_Parameter()
    {

        await using var server = NewServer();
        await using var client = NewClient(server, DNSHTTPSMode.GET);

        var response = await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True, "the DoH endpoint received a request");

        Assert.Multiple(() => {

            Assert.That(exchange!.Method,   Is.EqualTo("GET"));
            Assert.That(exchange.RawDnsParameter, Is.Not.Null, "the query goes into the 'dns' variable");

            // "The 'dns' variable ... is encoded with base64url [RFC4648] ...
            //  and without padding" (§4.1 / §6).
            Assert.That(exchange.RawDnsParameter, Does.Not.Contain("="),  "base64url MUST be unpadded");
            Assert.That(exchange.RawDnsParameter, Does.Not.Contain("+"),  "base64url uses '-' not '+'");
            Assert.That(exchange.RawDnsParameter, Does.Not.Contain("/"),  "base64url uses '_' not '/'");
            Assert.That(exchange.RawDnsParameter, Does.Not.Contain("%"),  "the value must not need percent-encoding");

            // The decoded payload must be the DNS query.
            var decoded = RawDnsReader.Parse(exchange.DnsMessage);
            Assert.That(decoded.Questions.Single().Name.Canonical, Is.EqualTo("doh.example"));
            Assert.That(decoded.Questions.Single().Type,           Is.EqualTo(RawDnsType.A));

            Assert.That(response.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("192.0.2.42")));

        });

    }

    #endregion

    #region Get_Sends_Accept_Application_Dns_Message()

    [Test]
    [Property("RFC", "8484 §4.1")]
    public async Task Get_Sends_Accept_Application_Dns_Message()
    {

        await using var server = NewServer();
        await using var client = NewClient(server, DNSHTTPSMode.GET);

        _ = await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True);

        Assert.That(exchange!.Accept, Does.Contain("application/dns-message"),
                    "clients SHOULD indicate the media type they can process");

    }

    #endregion

    #region Post_Sends_Body_With_Application_Dns_Message_Content_Type()

    [Test]
    [Property("RFC", "8484 §4.1")]
    public async Task Post_Sends_Body_With_Application_Dns_Message_Content_Type()
    {

        await using var server = NewServer();
        await using var client = NewClient(server, DNSHTTPSMode.POST);

        var response = await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True);

        Assert.Multiple(() => {

            Assert.That(exchange!.Method,       Is.EqualTo("POST"));
            Assert.That(exchange.ContentType,   Does.Contain("application/dns-message"),
                        "the media type of the POST body MUST be application/dns-message");
            Assert.That(exchange.RawDnsParameter, Is.Null, "POST carries the message in the body, not the URI");

            var decoded = RawDnsReader.Parse(exchange.DnsMessage);
            Assert.That(decoded.Questions.Single().Name.Canonical, Is.EqualTo("doh.example"));

            Assert.That(response.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("192.0.2.42")));

        });

    }

    #endregion

    #region Doh_Query_Message_Is_A_Valid_Dns_Message()

    [Test]
    [Property("RFC", "8484 §4.1")]
    public async Task Doh_Query_Message_Is_A_Valid_Dns_Message()
    {

        await using var server = NewServer();
        await using var client = NewClient(server, DNSHTTPSMode.POST);

        _ = await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True);

        var decoded = RawDnsReader.Parse(exchange!.DnsMessage, new RawDnsReaderOptions { RejectTrailingBytes = true });

        Assert.Multiple(() => {
            Assert.That(decoded.QR,        Is.False, "a query, not a response");
            Assert.That(decoded.Opcode,    Is.Zero);
            Assert.That(decoded.Questions, Has.Count.EqualTo(1));
        });

    }

    #endregion

    #region Doh_Uses_A_Dns_Id_Of_Zero(Mode)

    [TestCase(DNSHTTPSMode.POST, TestName = "Doh_Uses_A_Dns_Id_Of_Zero_Post")]
    [TestCase(DNSHTTPSMode.GET,  TestName = "Doh_Uses_A_Dns_Id_Of_Zero_Get")]
    [Property("RFC", "8484 §4.1")]
    public async Task Doh_Uses_A_Dns_Id_Of_Zero(DNSHTTPSMode Mode)
    {

        // "In order to maximize HTTP cache friendliness, DoH clients using media
        //  formats that include the ID field from the DNS message header, such
        //  as 'application/dns-message', SHOULD use a DNS ID of 0 in every DNS
        //  request."
        await using var server   = NewServer();
        await using var client   = NewClient(server, Mode);

        var response = await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True, "the DoH endpoint received a request");

        Assert.Multiple(() => {

            Assert.That(RawDnsReader.Parse(exchange!.DnsMessage).Id, Is.Zero,
                        "the query goes out under a DNS ID of 0");

            // The client checks that a response carries the ID its query did.
            // With a zero ID that check becomes "zero came back as zero" — still
            // performed, and the answer has to survive it.
            Assert.That(response.FilteredAnswers.Single().IPv4Address,
                        Is.EqualTo(IPv4Address.Parse("192.0.2.42")),
                        "and the answer still reaches the caller");

        });

    }

    #endregion

    #region Every_Doh_Request_Uses_The_Same_Id()

    [Test]
    [Property("RFC", "8484 §4.1")]
    public async Task Every_Doh_Request_Uses_The_Same_Id()
    {

        // "...in every DNS request." A client that zeroed the first ID and then
        // reverted to random ones would satisfy a single-shot test and none of
        // the caching this is for.
        await using var server = NewServer();
        await using var client = NewClient(server, DNSHTTPSMode.POST);

        for (var i = 0; i < 5; i++)
            await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));

        var ids = new List<UInt16>();

        while (server.Exchanges.TryDequeue(out var exchange))
            ids.Add(RawDnsReader.Parse(exchange.DnsMessage).Id);

        Assert.Multiple(() => {
            Assert.That(ids, Has.Count.EqualTo(5), "five requests were made");
            Assert.That(ids, Is.All.Zero,          "and every one of them carried a DNS ID of 0");
        });

    }

    #endregion

    #region Equivalent_Queries_Produce_Byte_Identical_Requests()

    [Test]
    [Property("RFC", "8484 §4.1")]
    public async Task Equivalent_Queries_Produce_Byte_Identical_Requests()
    {

        // This is what the rule is actually for: "The use of a varying DNS ID can
        //  cause semantically equivalent DNS queries to be cached separately."
        //
        // An HTTP cache matches on the request, so two askings of the same
        // question have to *be* the same request. Asserting the ID is 0 checks
        // the mechanism; asserting the two GETs are character-for-character equal
        // checks the property the mechanism exists to produce — and would catch
        // anything else varying between them, which a look at the ID alone would
        // not.
        await using var server = NewServer();
        await using var client = NewClient(server, DNSHTTPSMode.GET);

        await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));
        await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var first),  Is.True);
        Assert.That(server.Exchanges.TryDequeue(out var second), Is.True);

        Assert.Multiple(() => {

            Assert.That(second!.RawDnsParameter, Is.EqualTo(first!.RawDnsParameter),
                        "the same question produces the same URI, which is what a cache can hit");

            Assert.That(second.Path,             Is.EqualTo(first.Path));

        });

    }

    #endregion

    #region A_Varying_Id_Can_Be_Restored()

    [Test]
    [Property("RFC", "8484 §4.1, 5452 §9.2")]
    public async Task A_Varying_Id_Can_Be_Restored()
    {

        // §4.1 is a SHOULD, and the reason it can be one is that HTTP correlates
        // request and response by itself. A caller who wants RFC 5452 §9.2's
        // random ID anyway — talking through something that does not, say — must
        // be able to have it back.
        await using var server = NewServer();
        await using var client = NewClient(server, DNSHTTPSMode.POST);
        client.ZeroTransactionId = false;

        for (var i = 0; i < 5; i++)
            await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));

        var ids = new List<UInt16>();

        while (server.Exchanges.TryDequeue(out var exchange))
            ids.Add(RawDnsReader.Parse(exchange.DnsMessage).Id);

        TestContext.Out.WriteLine($"IDs with the recommendation switched off: {String.Join(", ", ids)}");

        Assert.That(ids.Distinct().Count(), Is.GreaterThan(1),
                    "the IDs vary again once the client is told to stop zeroing them");

    }

    #endregion

    #region A_Zero_Id_Is_Covered_By_The_Signature()

    [Test]
    [Property("RFC", "8484 §4.1, 8945 §4.3.1")]
    public async Task A_Zero_Id_Is_Covered_By_The_Signature()
    {

        // A TSIG covers the message including the header the ID sits in, so the
        // ID has to be settled *before* the MAC is computed. Zeroing it
        // afterwards would produce a query whose signature does not verify —
        // which is why the ordering is asserted rather than assumed.
        var key = new TSIGKey(
                      DomainName.Parse("doh-id-key."),
                      Convert.FromBase64String("ZG9oLXplcm8taWQtdHNpZy10ZXN0LXNlY3JldC0xMjM0NTY3OA==")
                  );

        await using var server = new ScriptedDoHServer(
            request => {

                var answer = RawDnsResponder.Answer(request, ("doh.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.42")));

                return answer is null
                           ? null
                           : TSIGSigner.Sign(answer, key, RequestMAC: TSIGSigner.Verify(request, key).MAC);

            }
        );

        await using var client = NewClient(server, DNSHTTPSMode.POST);
        client.TransactionSecurity = new DNSTransactionSecurity(TSIGKey: key);

        var response = await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True, "the DoH endpoint received a signed request");

        Assert.Multiple(() => {

            Assert.That(RawDnsReader.Parse(exchange!.DnsMessage).Id,   Is.Zero,
                        "the signed query still carries a DNS ID of 0");

            Assert.That(TSIGSigner.Verify(exchange!.DnsMessage, key).IsValid, Is.True,
                        "and the MAC verifies, so the zero was in place before the signature was computed");

            Assert.That(response.FilteredAnswers.Single().IPv4Address,
                        Is.EqualTo(IPv4Address.Parse("192.0.2.42")));

        });

    }

    #endregion

    #region Http_Error_Status_Does_Not_Reach_The_Wire_Parser()

    [Test]
    [Property("RFC", "8484 §4.2.1")]
    public async Task Http_Error_Status_Does_Not_Reach_The_Wire_Parser()
    {

        // A 500 body must be surfaced as a failed lookup, never parsed as DNS.
        await using var server = new ScriptedDoHServer(_ => null);
        await using var client = NewClient(server, DNSHTTPSMode.POST);

        var response = await client.Query<A>(DomainName.Parse("error.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.Multiple(() => {
            Assert.That(response,                 Is.Not.Null);
            Assert.That(response.FilteredAnswers, Is.Empty, "an HTTP error must not produce answers");
        });

    }

    #endregion

}

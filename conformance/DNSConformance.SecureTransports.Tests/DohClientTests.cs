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

    #region Doh_Transaction_Id_Is_Reported()

    [Test]
    [Property("RFC", "8484 §4.1")]
    public async Task Doh_Transaction_Id_Is_Reported()
    {

        // "In order to maximize HTTP cache friendliness, DoH clients using media
        //  formats that include the ID field from the DNS message header, such
        //  as application/dns-message, SHOULD use a DNS ID of 0 in every DNS
        //  request." SHOULD-level — measured and reported, not enforced.
        await using var server = NewServer();
        await using var client = NewClient(server, DNSHTTPSMode.POST);

        _ = await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True);

        var id = RawDnsReader.Parse(exchange!.DnsMessage).Id;

        TestContext.Out.WriteLine($"DoH transaction ID = {id} (RFC 8484 §4.1 recommends 0 for cache friendliness)");

        Assert.Pass($"observed DoH transaction ID {id}");

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

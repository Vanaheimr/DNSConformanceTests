using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.SecureTransports.Tests;

/// <summary>
/// RFC 8484 from the other side: Hermod's DoH <i>server</i>, driven by
/// <c>RawDoHProbe</c> — .NET's own HTTP stack, the suite's own base64url, and
/// the suite's own DNS codec on the way back.
/// </summary>
/// <remarks>
/// <para>
/// DoH is two specifications stacked, and the interesting requirements live at
/// the seam. A DNS server that answers correctly can still be a non-conforming
/// DoH server: by turning NXDOMAIN into a 404, by letting an HTTP cache invent
/// its own freshness, by honouring an EDNS(0) payload size that RFC 8484 §6 says
/// it must ignore. So most of what is asserted here is not the DNS message —
/// <c>ServerResponseTests</c> covers that over Do53 — but what HTTP was told
/// about it.
/// </para>
/// <para>
/// The endpoint runs in cleartext, for the same reason <c>ScriptedDoHServer</c>
/// does on the client side: RFC 8484 §5 requires https of a deployment, but a
/// handshake between the assertion and the thing asserted buys these tests
/// nothing. <c>Server_Answers_Over_Tls_As_A_DnsServer_Listener</c> covers the
/// deployed shape.
/// </para>
/// <para>
/// Everything here runs twice, once per HTTP version, because §5.2 recommends
/// HTTP/2 without changing a single requirement of §4 — "Earlier versions of
/// HTTP are capable of conveying the semantic requirements of DoH but may result
/// in very poor performance" is a statement about speed. Hermod renders the same
/// resource two ways, so the useful question is not whether HTTP/2 works but
/// whether it still obeys everything HTTP/1.1 obeys. The probe pins the version
/// with <c>RequestVersionExact</c>, so a listener that fell back would fail
/// rather than pass as its sibling.
/// </para>
/// </remarks>
[TestFixture("HTTP/1.1")]
[TestFixture("HTTP/2")]
[Property("RFC", "8484")]
public class DohServerTests
{

    #region Data

    private const String DNSMessage = "application/dns-message";

    private readonly Boolean  http2;
    private readonly String   versionName;

    #endregion

    #region Constructor(s)

    public DohServerTests(String HTTPVersionName)
    {
        this.versionName  = HTTPVersionName;
        this.http2        = HTTPVersionName == "HTTP/2";
    }

    #endregion

    #region (private) StartServerAsync(Zone = null, TSIGKeys = null, Secured = false)

    /// <summary>
    /// The RFC 8484 endpoint under test, on whichever HTTP version this run of
    /// the fixture is about.
    /// </summary>
    private Task<HermodDoHFixture> StartServerAsync(IDNSZoneStore?         Zone       = null,
                                                    IEnumerable<TSIGKey>?  TSIGKeys   = null,
                                                    Boolean                Secured    = false)

        => HermodDoHFixture.StartAsync(
               new HermodDoHFixtureOptions {
                   HTTP2     = http2,
                   Secured   = Secured,
                   Zone      = Zone,
                   TSIGKeys  = TSIGKeys ?? []
               }
           );

    #endregion

    #region (private static) CacheZone()

    /// <summary>
    /// A zone built for §5.1: two TTLs at one name so "the smallest" means
    /// something, and an SOA whose MINIMUM differs from its own TTL so the
    /// denial rule can be told apart from the ordinary one.
    /// </summary>
    private static InMemoryDNSZone CacheZone()
    {

        var zone = new InMemoryDNSZone();

        zone.Add(

            new SOA(
                DomainName.        Parse("cache.test."),
                DNSQueryClasses.IN,
                TimeSpan.          FromHours(1),            // the SOA's own TTL: 3600
                DomainName.        Parse("ns1.cache.test."),
                SimpleEMailAddress.Parse("hostmaster@cache.test"),
                2026081801,
                TimeSpan.          FromHours(2),
                TimeSpan.          FromHours(1),
                TimeSpan.          FromDays (14),
                TimeSpan.          FromSeconds(60)          // MINIMUM: 60, deliberately not the TTL
            ),

            new NS(
                DomainName.Parse("cache.test."),
                DNSQueryClasses.IN,
                TimeSpan.  FromHours(1),
                DomainName.Parse("ns1.cache.test.")
            ),

            new A(DomainName.Parse("ns1.cache.test."),   DNSQueryClasses.IN, TimeSpan.FromHours(1),      IPv4Address.Parse("192.0.2.53")),

            new A(DomainName.Parse("mixed.cache.test."), DNSQueryClasses.IN, TimeSpan.FromMinutes(15),   IPv4Address.Parse("192.0.2.1")),
            new A(DomainName.Parse("mixed.cache.test."), DNSQueryClasses.IN, TimeSpan.FromSeconds(120),  IPv4Address.Parse("192.0.2.2"))

        );

        return zone;

    }

    #endregion

    #region (private static) PaddingOption(Length)

    /// <summary>
    /// An EDNS option blob carrying one Padding option of the given length.
    /// </summary>
    private static Byte[] PaddingOption(Int32 Length)
    {

        var blob = new Byte[4 + Length];

        blob[0] = 0x00;
        blob[1] = 0x0C;                          // RFC 7830 §3: "The OPTION-CODE for the 'Padding' option is 12."
        blob[2] = (Byte) (Length >> 8);
        blob[3] = (Byte) (Length & 0xFF);

        return blob;

    }

    #endregion

    #region (private static) IsDnsReplyTo(Body, Id)

    /// <summary>
    /// Whether a response body is a DNS reply to the query with this ID.
    /// </summary>
    /// <remarks>
    /// Used the other way round: RFC 8484 §4.2.1 says a non-2xx response must
    /// <i>not</i> carry one, so what this has to survive is a body that is not a
    /// DNS message at all.
    /// </remarks>
    private static Boolean IsDnsReplyTo(Byte[] Body, UInt16 Id)
    {

        if (Body.Length < 12)
            return false;

        try
        {
            var message = RawDnsReader.Parse(Body);
            return message.QR && message.Id == Id;
        }
        catch (Exception)
        {
            return false;
        }

    }

    #endregion

    #region (private static) SoaMinimumOf(Record)

    /// <summary>
    /// The MINIMUM field of an SOA, read off the end of its RDATA.
    /// </summary>
    /// <remarks>
    /// RFC 1035 §3.3.13 puts MINIMUM last in the SOA RDATA, after two names and
    /// four 32-bit fields. Counting from the end rather than parsing forward
    /// keeps this independent of how the two names were encoded.
    /// </remarks>
    private static TimeSpan SoaMinimumOf(RawRecord Record)
    {

        var rdata = Record.Rdata;

        return TimeSpan.FromSeconds(
                   ((UInt32) rdata[^4] << 24) |
                   ((UInt32) rdata[^3] << 16) |
                   ((UInt32) rdata[^2] <<  8) |
                    (UInt32) rdata[^1]
               );

    }

    #endregion


    #region Server_Answers_On_The_Version_It_Was_Asked_For()

    [Test]
    [Property("RFC", "8484 §5.2")]
    public async Task Server_Answers_On_The_Version_It_Was_Asked_For()
    {

        // "HTTP/2 […] is the minimum RECOMMENDED version of HTTP for use with
        //  DoH."
        //
        // Every other test in this fixture would also pass against the wrong
        // listener if the client were allowed to fall back, so this one states
        // the premise the rest depend on: the exchange really happened on the
        // version this run is about.
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.PostAsync(
                               server.Url,
                               RawDnsWriter.Query(0x0502, ZoneFixtures.AName, RawDnsType.A),
                               HTTPClient: server.Http
                           );

        TestContext.Out.WriteLine($"{versionName}: {RawDoHProbe.Describe(result)}");

        Assert.Multiple(() => {
            Assert.That(result.Status,  Is.EqualTo(200));
            Assert.That(result.Version, Is.EqualTo(server.HTTPVersion),
                        () => $"asked for {versionName}, got HTTP/{result.Version}");
        });

    }

    #endregion

    #region Server_Must_Implement_Both_Get_And_Post()

    [Test]
    [Property("RFC", "8484 §4.1")]
    public async Task Server_Must_Implement_Both_Get_And_Post()
    {

        // "DoH servers MUST implement both the POST and GET methods."
        await using var server = await StartServerAsync();

        var query = RawDnsWriter.Query(0x8484, ZoneFixtures.AName, RawDnsType.A);

        var post  = await RawDoHProbe.PostAsync(server.Url, query, HTTPClient: server.Http);
        var get   = await RawDoHProbe.GetAsync (server.Url, query, HTTPClient: server.Http);

        Assert.Multiple(() => {

            foreach (var (method, result) in new[] { ("POST", post), ("GET", get) })
            {

                Assert.That(result.Status, Is.EqualTo(200),
                            () => $"{method}: {RawDoHProbe.Describe(result)}");

                if (result.Status != 200)
                    continue;

                var response = RawDnsReader.Parse(result.Body);

                Assert.That(response.Id,        Is.EqualTo((UInt16) 0x8484), $"{method}: the ID is echoed");
                Assert.That(response.QR,        Is.True,                     $"{method}: the message is a response");
                Assert.That(response.Answers,   Has.Count.EqualTo(1),        $"{method}: the question is answered");
                Assert.That(response.Answers[0].Rdata,
                            Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.AAddress)),
                            $"{method}: with the address the zone holds");

            }

        });

    }

    #endregion

    #region Server_Decodes_Unpadded_Base64url_Of_Every_Length()

    [Test]
    [Property("RFC", "8484 §6")]
    public async Task Server_Decodes_Unpadded_Base64url_Of_Every_Length()
    {

        // "Padding characters for base64url MUST NOT be included." Which means a
        // server has to put them back: a message whose length is ≡ 1 or 2 (mod 3)
        // arrives one or two characters short of a base64 quantum, and a decoder
        // that hands the parameter straight to a strict base64 reader rejects
        // exactly two thirds of all queries.
        //
        // The names below differ in length by one octet each, so the four
        // messages cover every residue at least once.
        await using var server = await StartServerAsync();

        // The awaits happen out here on purpose: an async lambda handed to
        // Assert.Multiple binds to the synchronous overload and becomes async
        // void, so every assertion inside it would run after the block had
        // already reported success.
        var exchanges = new List<(String Name, UInt16 Id, Byte[] Query, DoHProbeResult Result)>();

        for (var extra = 0; extra < 4; extra++)
        {

            var name  = new String('a', 10 + extra) + ".conformance.test.";
            var id    = (UInt16) (0x4640 + extra);
            var query = RawDnsWriter.Query(id, name, RawDnsType.A);

            exchanges.Add((name, id, query, await RawDoHProbe.GetAsync(server.Url, query, HTTPClient: server.Http)));

        }

        TestContext.Out.WriteLine(
            "query lengths mod 3: " +
            String.Join(", ", exchanges.Select(e => $"{e.Query.Length}→{e.Query.Length % 3}"))
        );

        Assert.That(exchanges.Select(e => e.Query.Length % 3).Distinct().Count(), Is.EqualTo(3),
                    "the four queries have to cover all three residues, or the test proves nothing");

        Assert.Multiple(() => {

            foreach (var (name, id, query, result) in exchanges)
            {

                Assert.That(result.Status, Is.EqualTo(200),
                            () => $"a {query.Length}-octet query ({query.Length % 3} mod 3) " +
                                  $"encoded as {RawDoHProbe.Base64Url(query).Length} base64url characters: " +
                                  RawDoHProbe.Describe(result));

                if (result.Status != 200)
                    continue;

                var response = RawDnsReader.Parse(result.Body);

                Assert.That(response.Id, Is.EqualTo(id),
                            "the decoded message is the one that was sent");

                Assert.That(response.Questions.Single().Name.Canonical,
                            Is.EqualTo(name.TrimEnd('.')),
                            "…question and all");

            }

        });

    }

    #endregion

    #region Server_Answers_With_The_DnsMessage_Media_Type()

    [Test]
    [Property("RFC", "8484 §4.2, §7.1")]
    public async Task Server_Answers_With_The_DnsMessage_Media_Type()
    {

        // §4.2: "The only response type defined in this document is
        //  'application/dns-message'."
        //
        // §7.1 registers it with "Required parameters: N/A / Optional
        // parameters: N/A", and describes the content as "a binary format". A
        // charset on it would be a statement about the octets that is untrue of
        // every one of them.
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.PostAsync(
                               server.Url,
                               RawDnsWriter.Query(0x4200, ZoneFixtures.AName, RawDnsType.A),
                               HTTPClient: server.Http
                           );

        Assert.Multiple(() => {

            Assert.That(result.Status,    Is.EqualTo(200));

            Assert.That(result.MediaType, Is.EqualTo(DNSMessage).IgnoreCase,
                        () => RawDoHProbe.Describe(result));

            Assert.That(result.CharSet,   Is.Null,
                        () => $"RFC 8484 §7.1 defines no parameters for this media type, got '{result.ContentType}'");

        });

    }

    #endregion

    #region Server_Uses_2xx_For_A_Dns_Response_Code_That_Means_Failure()

    [Test]
    [Property("RFC", "8484 §4.2.1")]
    public async Task Server_Uses_2xx_For_A_Dns_Response_Code_That_Means_Failure()
    {

        // "A successful HTTP response with a 2xx status code […] is used for any
        //  valid DNS response, regardless of the DNS response code. For example,
        //  a successful 2xx HTTP status code is used even with a DNS message
        //  whose DNS response code indicates failure, such as SERVFAIL or
        //  NXDOMAIN."
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.PostAsync(
                               server.Url,
                               RawDnsWriter.Query(0x4231, "nothing-here.conformance.test.", RawDnsType.A),
                               HTTPClient: server.Http
                           );

        Assert.That(result.Status, Is.EqualTo(200),
                    () => "NXDOMAIN is an answer, not an HTTP failure: " + RawDoHProbe.Describe(result));

        var response = RawDnsReader.Parse(result.Body);

        Assert.Multiple(() => {
            Assert.That(response.QR,      Is.True);
            Assert.That(response.RCode,   Is.EqualTo(3), "the DNS layer still reports NXDOMAIN");
            Assert.That(response.Answers, Is.Empty);
        });

    }

    #endregion

    #region Server_Uses_2xx_For_A_Nodata_Answer()

    [Test]
    [Property("RFC", "8484 §4.2.1")]
    public async Task Server_Uses_2xx_For_A_Nodata_Answer()
    {

        // The quieter half of the same rule: NOERROR with an empty answer
        // section is a valid DNS response and travels the same way.
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.PostAsync(
                               server.Url,
                               RawDnsWriter.Query(0x4232, ZoneFixtures.AName, RawDnsType.AAAA),
                               HTTPClient: server.Http
                           );

        Assert.That(result.Status, Is.EqualTo(200), () => RawDoHProbe.Describe(result));

        var response = RawDnsReader.Parse(result.Body);

        Assert.Multiple(() => {
            Assert.That(response.RCode,       Is.EqualTo(0), "NODATA is NOERROR");
            Assert.That(response.Answers,     Is.Empty);
            Assert.That(response.Authorities.Any(rr => rr.Type == RawDnsType.SOA), Is.True,
                        "RFC 2308 §3 wants the SOA cited, and §5.1 below needs it");
        });

    }

    #endregion

    #region Server_Does_Not_Answer_The_Question_In_A_NonSuccess_Response()

    [Test]
    [Property("RFC", "8484 §4.2.1")]
    public async Task Server_Does_Not_Answer_The_Question_In_A_NonSuccess_Response()
    {

        // "HTTP responses with non-successful HTTP status codes do not contain
        //  replies to the original DNS question in the HTTP request."
        //
        // The rule cuts both ways, and this is the direction that is easy to get
        // wrong: having built a DNS message for every other path, it is tempting
        // to attach one here too — and a client that reads the body before the
        // status would then treat a refusal as an answer.
        await using var server = await StartServerAsync();

        var query  = RawDnsWriter.Query(0x4233, ZoneFixtures.AName, RawDnsType.A);

        var wrongMediaType = await RawDoHProbe.PostAsync(server.Url, query, ContentType: "application/octet-stream", HTTPClient: server.Http);
        var wrongPath      = await RawDoHProbe.PostAsync($"{server.Origin}/not-the-dns-endpoint", query, HTTPClient: server.Http);

        Assert.Multiple(() => {

            Assert.That(wrongMediaType.Status, Is.GreaterThanOrEqualTo(400));
            Assert.That(wrongPath.Status,      Is.GreaterThanOrEqualTo(400));

            Assert.That(IsDnsReplyTo(wrongMediaType.Body, 0x4233), Is.False,
                        "a 4xx must not carry a reply to the question it refused");

            Assert.That(IsDnsReplyTo(wrongPath.Body, 0x4233), Is.False,
                        "…nor may a response from a path that is not the DoH endpoint");

        });

    }

    #endregion

    #region Server_Refuses_A_Body_Announced_As_Another_Media_Type()

    [Test]
    [Property("RFC", "8484 §4.1, §4.2.1")]
    public async Task Server_Refuses_A_Body_Announced_As_Another_Media_Type()
    {

        // §4.1: "the Content-Type request header field indicates the media type
        //  of the message."
        //
        // §4.2.1 names what a client does with the refusal — it "retries with a
        // different DoH server, such as for unsupported media types (HTTP status
        // code 415)" — which only works if the refusal says 415 and not 400.
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.PostAsync(
                               server.Url,
                               RawDnsWriter.Query(0x4150, ZoneFixtures.AName, RawDnsType.A),
                               ContentType: "application/json",
                               HTTPClient: server.Http
                           );

        Assert.That(result.Status, Is.EqualTo(415), () => RawDoHProbe.Describe(result));

    }

    #endregion

    #region Server_Generates_An_Allow_Field_With_A_405()

    [Test]
    [Property("RFC", "9110 §10.2.1")]
    public async Task Server_Generates_An_Allow_Field_With_A_405()
    {

        // RFC 9110 §10.2.1: "An origin server MUST generate an Allow header
        //  field in a 405 (Method Not Allowed) response."
        //
        // And what it names has to be what RFC 8484 §4.1 requires the server to
        // implement, or the field is worse than absent.
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.SendRawAsync(HttpMethod.Put, server.Url, HTTPClient: server.Http);

        Assert.That(result.Status, Is.EqualTo(405), () => RawDoHProbe.Describe(result));

        Assert.Multiple(() => {
            Assert.That(result.Allow, Does.Contain("GET"),  () => "Allow: " + String.Join(", ", result.Allow));
            Assert.That(result.Allow, Does.Contain("POST"), () => "Allow: " + String.Join(", ", result.Allow));
        });

    }

    #endregion

    #region Server_Refuses_An_Accept_That_Rules_Out_The_Only_Media_Type()

    [Test]
    [Property("RFC", "8484 §5.4, §4.2.1")]
    public async Task Server_Refuses_An_Accept_That_Rules_Out_The_Only_Media_Type()
    {

        // §5.4: "DoH clients and DoH servers MUST support the
        //  'application/dns-message' media type."
        //
        // §4.2.1 names 406 for "where the server cannot generate a
        //  representation suitable for the client", and a client that listed
        // media types without this one has described exactly that situation.
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.PostAsync(
                               server.Url,
                               RawDnsWriter.Query(0x4060, ZoneFixtures.AName, RawDnsType.A),
                               Accept: "application/json",
                               HTTPClient: server.Http
                           );

        Assert.That(result.Status, Is.EqualTo(406), () => RawDoHProbe.Describe(result));

    }

    #endregion

    #region Server_Serves_An_Accept_That_Leaves_Room_For_It()

    [Test]
    [Property("RFC", "9110 §12.4.3")]
    [TestCase(null,                                                     TestName = "Server_Serves_An_Accept_That_Leaves_Room_For_It(absent)")]
    [TestCase("*/*")]
    [TestCase("application/*")]
    [TestCase("application/dns-message")]
    [TestCase("text/html;q=0.9, application/dns-message, */*;q=0.1")]
    public async Task Server_Serves_An_Accept_That_Leaves_Room_For_It(String? Accept)
    {

        // RFC 9110 §12.4.3 defines the wildcard "to select unspecified values",
        // so */* is the opposite of a refusal — and an absent Accept field has
        // refused nothing at all. Reading either as grounds for a 406 would turn
        // away curl and every browser, which is the failure mode this pins.
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.PostAsync(
                               server.Url,
                               RawDnsWriter.Query(0x4061, ZoneFixtures.AName, RawDnsType.A),
                               Accept: Accept,
                               HTTPClient: server.Http
                           );

        Assert.That(result.Status, Is.EqualTo(200),
                    () => $"Accept: {Accept ?? "(absent)"} — " + RawDoHProbe.Describe(result));

    }

    #endregion

    #region Server_Rejects_A_Get_Whose_Parameter_Is_Not_A_Dns_Message()

    [Test]
    [Property("RFC", "8484 §4.1")]
    [TestCase("",                  TestName = "Server_Rejects_A_Get_Whose_Parameter_Is_Not_A_Dns_Message(missing)")]
    [TestCase("?dns=")]
    [TestCase("?dns=not-base64url!!")]
    [TestCase("?dns=AAAA")]
    public async Task Server_Rejects_A_Get_Whose_Parameter_Is_Not_A_Dns_Message(String Query)
    {

        // §4.1 defines the "dns" variable as "the content of the DNS request".
        // Nothing here is one — the field is missing, empty, not base64url, or
        // decodes to four octets, which is shorter than the 12-octet header of
        // RFC 1035 §4.1.1. Each has to be refused rather than parsed.
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.SendRawAsync(HttpMethod.Get, server.Url + Query, HTTPClient: server.Http);

        Assert.That(result.Status, Is.GreaterThanOrEqualTo(400).And.LessThan(500),
                    () => $"'{Query}' — " + RawDoHProbe.Describe(result));

    }

    #endregion

    #region Server_Answers_Only_On_Its_Own_Resource()

    [Test]
    [Property("RFC", "8484 §3")]
    public async Task Server_Answers_Only_On_Its_Own_Resource()
    {

        // §3 leaves the URI to "a URI Template" the server publishes, so a DoH
        // server is one resource rather than a site — and everything else on the
        // listener is simply not it.
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.PostAsync(
                               $"{server.Origin}/",
                               RawDnsWriter.Query(0x4040, ZoneFixtures.AName, RawDnsType.A),
                               HTTPClient: server.Http
                           );

        Assert.That(result.Status, Is.EqualTo(404), () => RawDoHProbe.Describe(result));

    }

    #endregion


    #region Server_Assigns_An_Explicit_Freshness_Lifetime()

    [Test]
    [Property("RFC", "8484 §5.1")]
    public async Task Server_Assigns_An_Explicit_Freshness_Lifetime()
    {

        // "In particular, DoH servers SHOULD assign an explicit HTTP freshness
        //  lifetime […] This requirement is due to HTTP caches being able to
        //  assign their own heuristic freshness […] which would take control of
        //  the cache contents out of the hands of the DoH server."
        //
        // Sending nothing is therefore not neutral. It is the case the paragraph
        // exists to prevent.
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.GetAsync(
                               server.Url,
                               RawDnsWriter.Query(0x5100, ZoneFixtures.AName, RawDnsType.A),
                               HTTPClient: server.Http
                           );

        Assert.That(result.Status, Is.EqualTo(200));
        Assert.That(result.MaxAge, Is.Not.Null,
                    () => "no explicit freshness lifetime: " + RawDoHProbe.Describe(result));

    }

    #endregion

    #region Freshness_Lifetime_Is_At_Most_The_Smallest_Answer_Ttl()

    [Test]
    [Property("RFC", "8484 §5.1")]
    public async Task Freshness_Lifetime_Is_At_Most_The_Smallest_Answer_Ttl()
    {

        // "The assigned freshness lifetime of a DoH HTTP response MUST be less
        //  than or equal to the smallest TTL in the Answer section of the DNS
        //  response. A freshness lifetime equal to the smallest TTL in the Answer
        //  section is RECOMMENDED. […] This requirement helps prevent expired
        //  RRsets in messages in an HTTP cache from unintentionally being served."
        //
        // The two records at this name carry 900 and 120 seconds, so a server
        // reading the first TTL rather than the smallest passes everything else
        // and fails here.
        await using var server = await StartServerAsync(Zone: CacheZone());

        var result   = await RawDoHProbe.GetAsync(
                                 server.Url,
                                 RawDnsWriter.Query(0x5101, "mixed.cache.test.", RawDnsType.A),
                                 HTTPClient: server.Http
                             );

        Assert.That(result.Status, Is.EqualTo(200), () => RawDoHProbe.Describe(result));

        var response = RawDnsReader.Parse(result.Body);
        var smallest = TimeSpan.FromSeconds(response.Answers.Min(rr => rr.Ttl));

        TestContext.Out.WriteLine(
            $"answer TTLs {String.Join(", ", response.Answers.Select(rr => rr.Ttl))} " +
            $"-> cache-control: {result.CacheControl ?? "(none)"}"
        );

        Assert.Multiple(() => {

            Assert.That(response.Answers, Has.Count.EqualTo(2), "both records are in the answer");

            Assert.That(result.MaxAge, Is.Not.Null, "§5.1 asks for an explicit lifetime");

            Assert.That(result.MaxAge, Is.LessThanOrEqualTo(smallest),
                        () => $"MUST be ≤ the smallest answer TTL ({smallest.TotalSeconds:N0}s), " +
                              $"got {result.MaxAge?.TotalSeconds:N0}s");

            Assert.That(result.MaxAge, Is.EqualTo(smallest),
                        () => $"equal to the smallest TTL is the RECOMMENDED value ({smallest.TotalSeconds:N0}s)");

        });

    }

    #endregion

    #region Freshness_Lifetime_Of_A_Denial_Is_Bounded_By_The_Soa_Minimum()

    [Test]
    [Property("RFC", "8484 §5.1")]
    public async Task Freshness_Lifetime_Of_A_Denial_Is_Bounded_By_The_Soa_Minimum()
    {

        // "If the DNS response has no records in the Answer section, and the DNS
        //  response has an SOA record in the Authority section, the response
        //  freshness lifetime MUST NOT be greater than the MINIMUM field from
        //  that SOA record."
        //
        // The fixture zone's SOA carries a MINIMUM of 60 seconds and a TTL of an
        // hour, so a server that reaches for the record's TTL — the obvious
        // mistake, since that is what every other record's lifetime is — is out
        // by a factor of sixty.
        await using var server = await StartServerAsync(Zone: CacheZone());

        var result   = await RawDoHProbe.GetAsync(
                                 server.Url,
                                 RawDnsWriter.Query(0x5102, "nothing-here.cache.test.", RawDnsType.A),
                                 HTTPClient: server.Http
                             );

        Assert.That(result.Status, Is.EqualTo(200), () => RawDoHProbe.Describe(result));

        var response = RawDnsReader.Parse(result.Body);
        var soa      = response.Authorities.FirstOrDefault(rr => rr.Type == RawDnsType.SOA);

        Assert.That(soa, Is.Not.Null, "a denial cites the SOA (RFC 2308 §3), which is what §5.1 measures against");

        var minimum  = SoaMinimumOf(soa!);

        TestContext.Out.WriteLine(
            $"SOA TTL {soa!.Ttl}s, MINIMUM {minimum.TotalSeconds:N0}s " +
            $"-> cache-control: {result.CacheControl ?? "(none)"}"
        );

        Assert.Multiple(() => {

            Assert.That(response.Answers, Is.Empty,  "this is the no-answers case §5.1 is about");
            Assert.That(result.MaxAge,    Is.Not.Null);

            Assert.That(result.MaxAge, Is.LessThanOrEqualTo(minimum),
                        () => $"MUST NOT exceed the SOA MINIMUM ({minimum.TotalSeconds:N0}s), " +
                              $"got {result.MaxAge?.TotalSeconds:N0}s (the SOA's own TTL is {soa.Ttl}s)");

        });

    }

    #endregion


    #region Server_Ignores_The_Payload_Size_When_Sizing_The_Answer()

    [Test]
    [Property("RFC", "8484 §6")]
    public async Task Server_Ignores_The_Payload_Size_When_Sizing_The_Answer()
    {

        // "DoH servers using this media type MUST ignore the value given for the
        //  EDNS UDP payload size in DNS requests."
        //
        // The query below advertises 512 octets and asks for an answer that does
        // not fit in them. On UDP that is the truncation of RFC 1035 §4.2.1 and
        // RFC 6891 §6.2.5; here there is no datagram to overflow, so the full
        // answer has to come back with TC clear. A server that shares its UDP
        // sizing code across transports fails exactly this.
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.PostAsync(
                               server.Url,
                               RawDnsWriter.Query(0x0600, ZoneFixtures.BigTxtName, RawDnsType.TXT,
                                                  ednsPayloadSize: 512),
                                                  HTTPClient: server.Http
                           );

        Assert.That(result.Status, Is.EqualTo(200), () => RawDoHProbe.Describe(result));

        var response = RawDnsReader.Parse(result.Body);

        TestContext.Out.WriteLine($"advertised 512 octets, got {result.Body.Length} (TC={response.TC})");

        Assert.Multiple(() => {

            Assert.That(result.Body.Length, Is.GreaterThan(512),
                        "the answer is longer than the size the query advertised, and must be sent anyway");

            Assert.That(response.TC,      Is.False,
                        "there is no datagram to truncate for");

            Assert.That(response.Answers, Is.Not.Empty,
                        "and no records may be shed to fit a limit that does not apply");

        });

    }

    #endregion

    #region Server_Ignores_The_Payload_Size_When_Padding_The_Answer()

    [Test]
    [Property("RFC", "8484 §6, 7830 §4, 8467 §4.1")]
    public async Task Server_Ignores_The_Payload_Size_When_Padding_The_Answer()
    {

        // The same MUST where it is easiest to obey by accident and hardest to
        // notice: RFC 7830 §4 caps a padded message at "the number of octets
        // specified in the Requestor's Payload Size field", so a responder that
        // applies that cap over DoH stops at 200 octets instead of reaching the
        // 468-octet block of RFC 8467 §4.1. Both numbers look plausible in
        // isolation; only the query's advertised size tells them apart.
        await using var server = await StartServerAsync();

        var result = await RawDoHProbe.PostAsync(
                               server.Url,
                               RawDnsWriter.Query(0x0601, ZoneFixtures.AName, RawDnsType.A,
                                                  ednsPayloadSize:  200,
                                                  ednsOptions:      PaddingOption(0)),
                                                  HTTPClient: server.Http
                           );

        Assert.That(result.Status, Is.EqualTo(200), () => RawDoHProbe.Describe(result));

        TestContext.Out.WriteLine($"advertised 200 octets, padded response is {result.Body.Length}");

        Assert.That(result.Body.Length, Is.EqualTo(468),
                    () => $"the padded response should reach the 468-octet block of RFC 8467 §4.1, " +
                          $"not stop at the 200 the query advertised — got {result.Body.Length}");

    }

    #endregion

    #region Responder_Must_Pad_A_Response_To_A_Padded_Query()

    [Test]
    [Property("RFC", "7830 §4, 8467 §4.1")]
    public async Task Responder_Must_Pad_A_Response_To_A_Padded_Query()
    {

        // RFC 7830 §4: "Responders MUST pad DNS responses when the respective DNS
        //  query included the 'Padding' option."
        //
        // RFC 8467 §1 scopes its block lengths to encrypted transports "such as"
        // DoT and DoDTLS "or other encrypted DNS transports specified in the
        // future" — DoH, published the same month, is one of them.
        await using var server = await StartServerAsync();

        var bare    = await RawDoHProbe.PostAsync(
                                server.Url,
                                RawDnsWriter.Query(0x7830, ZoneFixtures.AName, RawDnsType.A,
                                                   ednsPayloadSize: 4096),
                                                   HTTPClient: server.Http
                            );

        var padded  = await RawDoHProbe.PostAsync(
                                server.Url,
                                RawDnsWriter.Query(0x7831, ZoneFixtures.AName, RawDnsType.A,
                                                   ednsPayloadSize:  4096,
                                                   ednsOptions:      PaddingOption(64)),
                                                   HTTPClient: server.Http
                            );

        Assert.That(bare.Status,   Is.EqualTo(200), () => RawDoHProbe.Describe(bare));
        Assert.That(padded.Status, Is.EqualTo(200), () => RawDoHProbe.Describe(padded));

        var opt     = RawDnsReader.Parse(padded.Body).Additionals.FirstOrDefault(rr => rr.IsOpt);
        var options = opt is null ? [] : RawEdns.From(opt).Options.Where(option => option.Code == 12).ToArray();

        TestContext.Out.WriteLine($"unpadded {bare.Body.Length} octets -> padded {padded.Body.Length}");

        Assert.Multiple(() => {

            Assert.That(options, Has.Length.EqualTo(1),
                        "RFC 7830 §4 makes padding the response mandatory once the query carried the option");

            Assert.That(padded.Body.Length % 468, Is.Zero,
                        () => $"RFC 8467 §4.1 asks for a multiple of 468 octets, got {padded.Body.Length}");

            // Reaching *a* boundary is not enough — it has to be the first one
            // that holds the message, or the padding is spending a whole block
            // it did not need. The four octets are the option's own header.
            Assert.That(padded.Body.Length - 468, Is.LessThan(bare.Body.Length + 4),
                        () => $"{padded.Body.Length} octets wastes a block; {bare.Body.Length + 4} would fit below it");

        });

    }

    #endregion

    #region Responder_Must_Not_Pad_When_The_Query_Announced_No_Edns()

    [Test]
    [Property("RFC", "7830 §4")]
    public async Task Responder_Must_Not_Pad_When_The_Query_Announced_No_Edns()
    {

        // RFC 7830 §4: "Responders MUST NOT pad DNS responses when the respective
        //  DNS query did not indicate EDNS(0) support."
        //
        // Padding lives inside the OPT record, so a response to a query with no
        // OPT has nowhere to put it — and inventing one to make room would change
        // what the response says about its own EDNS(0) support.
        await using var server = await StartServerAsync();

        var result   = await RawDoHProbe.PostAsync(
                                 server.Url,
                                 RawDnsWriter.Query(0x7832, ZoneFixtures.AName, RawDnsType.A),
                                 HTTPClient: server.Http
                             );

        Assert.That(result.Status, Is.EqualTo(200), () => RawDoHProbe.Describe(result));

        var response = RawDnsReader.Parse(result.Body);

        Assert.Multiple(() => {

            Assert.That(response.Opt, Is.Null,
                        "a response to a query without EDNS(0) carries no OPT record");

            Assert.That(result.Body.Length, Is.LessThan(468),
                        () => $"an unpadded answer is far below one block; {result.Body.Length} octets " +
                              "suggests it was padded anyway");

        });

    }

    #endregion


    #region Signed_Query_Over_Doh_Is_Verified_And_The_Reply_Signed()

    [Test]
    [Property("RFC", "8945 §5.3")]
    public async Task Signed_Query_Over_Doh_Is_Verified_And_The_Reply_Signed()
    {

        // A transaction signature covers the DNS message, not the connection, so
        // TSIG has nothing to say about HTTP — the same octets are signed as on a
        // datagram. What is worth asking is whether this transport reaches for it
        // at all: finding 19 was a transport that did not, and nothing reported
        // it. The judgment below is RawDns's — where the meta-RR sits — and the
        // MAC binding is checked the way RFC 8945 §4.3.1 defines it.
        var key = new TSIGKey(DomainName.Parse("doh-server-key."),
                              Convert.FromBase64String("ZG9oLXNlcnZlci10c2lnLXRlc3Qtc2VjcmV0LTEyMzQ1Njc4"));

        await using var server = await StartServerAsync(TSIGKeys: [ key ]);

        var query       = RawDnsWriter.Query(0x8945, ZoneFixtures.AName, RawDnsType.A);
        var signed      = TSIGSigner.Sign(query, key);
        var requestMAC  = TSIGSigner.Verify(signed, key).MAC!;

        var result      = await RawDoHProbe.PostAsync(server.Url, signed, HTTPClient: server.Http);

        Assert.That(result.Status, Is.EqualTo(200), () => RawDoHProbe.Describe(result));

        var response    = RawDnsReader.Parse(result.Body);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.EqualTo(0), "a valid signature must not change the answer");
            Assert.That(response.Answers, Is.Not.Empty,  "the query is still a query — it has to be served");

            Assert.That(response.Additionals.LastOrDefault()?.Type, Is.EqualTo(RawDnsType.TSIG),
                        "§5.3: the reply is signed, and §5.1 puts the TSIG last in the additional section");

            Assert.That(TSIGSigner.Verify(result.Body, key, RequestMAC: requestMAC).IsValid, Is.True,
                        "the reply verifies against the request it answers");

        });

    }

    #endregion

    #region Unsigned_Query_Over_Doh_Is_Still_Served()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public async Task Unsigned_Query_Over_Doh_Is_Still_Served()
    {

        // Configuring keys turns verification on; it does not turn unsigned
        // queries away. RFC 8945 requires no such refusal — that is a policy
        // decision — and a DoH endpoint that quietly started demanding TSIG the
        // moment a key was configured would be a surprising one.
        var key = new TSIGKey(DomainName.Parse("doh-server-key."),
                              Convert.FromBase64String("ZG9oLXNlcnZlci10c2lnLXRlc3Qtc2VjcmV0LTEyMzQ1Njc4"));

        await using var server = await StartServerAsync(TSIGKeys: [ key ]);

        var result   = await RawDoHProbe.PostAsync(
                                 server.Url,
                                 RawDnsWriter.Query(0x8946, ZoneFixtures.AName, RawDnsType.A),
                                 HTTPClient: server.Http
                             );

        Assert.That(result.Status, Is.EqualTo(200), () => RawDoHProbe.Describe(result));

        var response = RawDnsReader.Parse(result.Body);

        Assert.Multiple(() => {
            Assert.That(response.RCode,       Is.EqualTo(0));
            Assert.That(response.Answers,     Is.Not.Empty);
            Assert.That(response.Additionals.Any(rr => rr.Type == RawDnsType.TSIG), Is.False,
                        "nothing to bind a signature to, so the reply carries none");
        });

    }

    #endregion


    #region Server_Answers_Over_Tls_As_A_DnsServer_Listener()

    [Test]
    [Property("RFC", "8484 §5")]
    public async Task Server_Answers_Over_Tls_As_A_DnsServer_Listener()
    {

        // "This protocol MUST be used with the https URI scheme." Everything
        // above runs in cleartext to keep the HTTP layer visible; this one is the
        // deployed shape — the DoH endpoint as a listener of a real DNSServer,
        // over TLS, answering the same zone as its UDP and TCP siblings would.
        await using var server = await StartServerAsync(Secured: true);

        Assert.That(server.Url, Does.StartWith("https://"));

        var result = await RawDoHProbe.PostAsync(
                               server.Url,
                               RawDnsWriter.Query(0x0500, ZoneFixtures.AName, RawDnsType.A),
                               HTTPClient: server.Http
                           );

        Assert.That(result.Status, Is.EqualTo(200), () => RawDoHProbe.Describe(result));

        var response = RawDnsReader.Parse(result.Body);

        Assert.Multiple(() => {
            Assert.That(result.MediaType,   Is.EqualTo(DNSMessage).IgnoreCase);
            Assert.That(response.Id,        Is.EqualTo((UInt16) 0x0500));
            Assert.That(response.Answers,   Has.Count.EqualTo(1));
            Assert.That(response.Answers[0].Rdata, Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.AAddress)));
        });

    }

    #endregion

}

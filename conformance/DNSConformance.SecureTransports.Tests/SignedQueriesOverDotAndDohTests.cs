using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.SecureTransports.Tests;

/// <summary>
/// RFC 8945 and RFC 2931 over the encrypted transports: TSIG and SIG(0) applied
/// by Hermod's DoT and DoH clients.
/// </summary>
/// <remarks>
/// <para>
/// A transaction signature covers the DNS message, not the connection, so
/// neither mechanism has anything to say about TLS or HTTP — the same octets are
/// signed as on a datagram. What is worth asserting is therefore not the
/// cryptography, which <c>TsigSigningTests</c> and <c>Sig0SigningTests</c> pin
/// against hand-computed values, but whether these two transports reach for it
/// at all. Finding 19 is why that is a real question: the TCP fallback inside
/// the UDP client did not, for three rounds, and nothing anywhere reported it.
/// </para>
/// <para>
/// So each test reads the message the transport actually put on the wire with
/// <c>RawDns</c> — through the TLS framing, or out of the base64url of a
/// <c>?dns=</c> parameter — and checks the meta-RR is there, is last, and
/// verifies.
/// </para>
/// </remarks>
[TestFixture]
public class SignedQueriesOverDotAndDohTests
{

    private const UInt16 TsigType = 250;
    private const UInt16 SigType  = 24;

    private static readonly Byte[] Secret = Convert.FromBase64String("ZG90LWFuZC1kb2gtdHNpZy10ZXN0LXNlY3JldC0xMjM0NTY3OA==");

    private static TSIGKey TsigKey()
        => new (DomainName.Parse("transport-key."), Secret);

    private static SIG0Key Sig0Key()
        => SIG0Key.Generate(DomainName.Parse("transport.conformance.test"));


    /// <summary>Sign the scripted server's reply the way RFC 8945 §5.3 requires of a real one.</summary>
    private static Byte[]? SignedAnswer(Byte[] Request, TSIGKey Key, String Name, String Address)
    {

        var answer = RawDnsResponder.Answer(Request, (Name, RawDnsType.A, 300, RawDnsWriter.IPv4(Address)));

        if (answer is null)
            return null;

        // The response's MAC folds in the request's, which is what binds the two.
        TSIGSigner.TryStripTSIG(Request, out var unsigned, out _);

        var requestMAC = TSIGSigner.Verify(Request, Key).MAC;

        return TSIGSigner.Sign(answer, Key, RequestMAC: requestMAC);

    }


    #region Dot_Client_Signs_Its_Query_With_Tsig()

    [Test]
    [Property("RFC", "8945 §5.3, 7858")]
    public async Task Dot_Client_Signs_Its_Query_With_Tsig()
    {

        var key = TsigKey();

        await using var server = new ScriptedTlsServer(
            request => SignedAnswer(request, key, "dot.example.", "192.0.2.53")
        );

        await using var client = new DNSTLSClient(
                                     IPv4Address.Localhost,
                                     TCPPort:                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:                TimeSpan.FromSeconds(10),
                                     RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success()
                                 ) { TransactionSecurity = new DNSTransactionSecurity(TSIGKey: key) };

        var response = await client.Query<A>(DomainName.Parse("dot.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the DoT listener received a query");

        var decoded = RawDnsReader.Parse(request!);

        Assert.Multiple(() => {

            Assert.That(decoded.Additionals, Is.Not.Empty);
            Assert.That(decoded.Additionals[^1].Type, Is.EqualTo(TsigType),
                        "§5.1: the TSIG is the last record in the additional section — inside the TLS framing like any other");

            Assert.That(decoded.ConsumedBytes, Is.EqualTo(request!.Length),
                        "the length prefix and the message agree, TSIG included");

            Assert.That(TSIGSigner.Verify(request!, key).IsValid, Is.True,
                        "and the MAC verifies under the shared key");

            // The reply was signed too, so it survives verification and reaches
            // the caller: a client that signs but cannot check the answer would
            // pass every assertion above and return nothing.
            Assert.That(response.FilteredAnswers.Single().IPv4Address,
                        Is.EqualTo(IPv4Address.Parse("192.0.2.53")));

        });

    }

    #endregion

    #region Dot_Client_Signs_Its_Query_With_Sig0()

    [Test]
    [Property("RFC", "2931 §3.1, 7858")]
    public async Task Dot_Client_Signs_Its_Query_With_Sig0()
    {

        var key = Sig0Key();

        await using var server = new ScriptedTlsServer(
            request => RawDnsResponder.Answer(request, ("dot.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.55")))
        );

        await using var client = new DNSTLSClient(
                                     IPv4Address.Localhost,
                                     TCPPort:                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:                TimeSpan.FromSeconds(10),
                                     RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success()
                                 ) { TransactionSecurity = new DNSTransactionSecurity(SIG0Key: key) };

        var response = await client.Query<A>(DomainName.Parse("dot.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Requests.TryDequeue(out var request), Is.True);

        var decoded = RawDnsReader.Parse(request!);

        Assert.Multiple(() => {

            Assert.That(decoded.Additionals[^1].Type,             Is.EqualTo(SigType));
            Assert.That(decoded.Additionals[^1].Name.Presentation, Is.EqualTo("."), "root owner name (§3)");
            Assert.That(decoded.Additionals[^1].Class,            Is.EqualTo((UInt16) 255), "CLASS ANY");

            Assert.That(SIG0Signer.Verify(request!, key.PublicKey).IsValid, Is.True,
                        "the signature verifies under the published KEY");

            // RFC 2931 §3.1 leaves response signing optional, so an unsigned
            // reply is ordinary and must still be delivered.
            Assert.That(response.FilteredAnswers.Single().IPv4Address,
                        Is.EqualTo(IPv4Address.Parse("192.0.2.55")));

        });

    }

    #endregion

    #region Dot_Client_Discards_A_Reply_Signed_With_The_Wrong_Secret()

    [Test]
    [Property("RFC", "8945 §5.3")]
    public async Task Dot_Client_Discards_A_Reply_Signed_With_The_Wrong_Secret()
    {

        var key      = TsigKey();
        var impostor = new TSIGKey(DomainName.Parse("transport-key."),
                                   Convert.FromBase64String("d3Jvbmctc2VjcmV0LXRoYXQtaXMtbm90LXRoZS1yaWdodC1vbmU="));

        await using var server = new ScriptedTlsServer(
            request => SignedAnswer(request, impostor, "dot.example.", "192.0.2.66")
        );

        await using var client = new DNSTLSClient(
                                     IPv4Address.Localhost,
                                     TCPPort:                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:                TimeSpan.FromSeconds(10),
                                     RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success()
                                 ) { TransactionSecurity = new DNSTransactionSecurity(TSIGKey: key) };

        var response = await client.Query<A>(DomainName.Parse("dot.example."), Timeout: TimeSpan.FromSeconds(10));

        // TLS already proves the channel was not tampered with — which is exactly
        // why this is worth asserting. The two mechanisms answer different
        // questions, and a client that signed its query and then believed
        // whatever came back would have gained nothing from asking.
        Assert.That(response.Answers.Any(), Is.False,
                    "a reply that does not authenticate is not an answer, encrypted channel or not");

    }

    #endregion

    #region Doh_Get_Signs_The_Message_Inside_The_Dns_Parameter()

    [Test]
    [Property("RFC", "8484 §4.1, 8945 §5.3")]
    public async Task Doh_Get_Signs_The_Message_Inside_The_Dns_Parameter()
    {

        var key = TsigKey();

        await using var server = new ScriptedDoHServer(
                                     request => SignedAnswer(request, key, "doh.example.", "192.0.2.42")
                                 );

        var client = new DNSHTTPSClient(
                         URL.Parse(server.Url),
                         Mode:          DNSHTTPSMode.GET,
                         QueryTimeout:  TimeSpan.FromSeconds(10)
                     ) { TransactionSecurity = new DNSTransactionSecurity(TSIGKey: key) };

        var response = await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True, "the DoH endpoint received a request");

        var decoded = RawDnsReader.Parse(exchange!.DnsMessage);

        Assert.Multiple(() => {

            Assert.That(exchange.Method, Is.EqualTo("GET"));

            // §4.1's "dns" variable is the wire-format message, base64url encoded.
            // The signature is over that message, so it rides inside the parameter
            // rather than beside it — nothing about DoH is special here, and that
            // is the point.
            Assert.That(decoded.Additionals[^1].Type, Is.EqualTo(TsigType));

            Assert.That(TSIGSigner.Verify(exchange.DnsMessage, key).IsValid, Is.True,
                        "the MAC survives base64url encoding and decoding intact");

            Assert.That(exchange.RawDnsParameter, Does.Not.Contain("="),
                        "…and the parameter is still unpadded base64url, longer message or not");

            Assert.That(response.FilteredAnswers.Single().IPv4Address,
                        Is.EqualTo(IPv4Address.Parse("192.0.2.42")));

        });

    }

    #endregion

    #region Doh_Post_Signs_The_Body()

    [Test]
    [Property("RFC", "8484 §4.1, 2931 §3.1")]
    public async Task Doh_Post_Signs_The_Body()
    {

        var key = Sig0Key();

        await using var server = new ScriptedDoHServer(
                                     request => RawDnsResponder.Answer(request, ("doh.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.43")))
                                 );

        var client = new DNSHTTPSClient(
                         URL.Parse(server.Url),
                         Mode:          DNSHTTPSMode.POST,
                         QueryTimeout:  TimeSpan.FromSeconds(10)
                     ) { TransactionSecurity = new DNSTransactionSecurity(SIG0Key: key) };

        var response = await client.Query<A>(DomainName.Parse("doh.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True);

        var decoded = RawDnsReader.Parse(exchange!.DnsMessage);

        Assert.Multiple(() => {

            Assert.That(exchange.Method,      Is.EqualTo("POST"));
            Assert.That(exchange.ContentType, Does.Contain("application/dns-message"),
                        "§4.1's media type — Hermod appends a charset parameter, which is meaningless " +
                        "on a binary type but permitted and ignored by receivers");

            Assert.That(decoded.Additionals[^1].Type, Is.EqualTo(SigType),
                        "the body is the signed message, Content-Length and all");

            Assert.That(SIG0Signer.Verify(exchange.DnsMessage, key.PublicKey).IsValid, Is.True);

            Assert.That(response.FilteredAnswers.Single().IPv4Address,
                        Is.EqualTo(IPv4Address.Parse("192.0.2.43")));

        });

    }

    #endregion

    #region An_Unconfigured_Client_Signs_Nothing_On_Either_Transport()

    [Test]
    [Property("RFC", "8945 §5.3, 2931 §2.4")]
    public async Task An_Unconfigured_Client_Signs_Nothing_On_Either_Transport()
    {

        await using var tlsServer = new ScriptedTlsServer(
            request => RawDnsResponder.Answer(request, ("plain.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.70")))
        );

        await using var dohServer = new ScriptedDoHServer(
            request => RawDnsResponder.Answer(request, ("plain.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.71")))
        );

        await using var dotClient = new DNSTLSClient(
                                        IPv4Address.Localhost,
                                        TCPPort:                     IPPort.Parse((UInt16) tlsServer.Port),
                                        QueryTimeout:                TimeSpan.FromSeconds(10),
                                        RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success()
                                    );

        var dohClient = new DNSHTTPSClient(
                            URL.Parse(dohServer.Url),
                            Mode:          DNSHTTPSMode.POST,
                            QueryTimeout:  TimeSpan.FromSeconds(10)
                        );

        await dotClient.Query<A>(DomainName.Parse("plain.example."), Timeout: TimeSpan.FromSeconds(10));
        await dohClient.Query<A>(DomainName.Parse("plain.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(tlsServer.Requests.TryDequeue(out var dotRequest),  Is.True);
        Assert.That(dohServer.Exchanges.TryDequeue(out var dohExchange), Is.True);

        var dot = RawDnsReader.Parse(dotRequest!);
        var doh = RawDnsReader.Parse(dohExchange!.DnsMessage);

        Assert.Multiple(() => {

            // The default has to stay free. A signature per query is an HMAC on
            // one path and a public key operation on the other — RFC 2931 §2.4
            // asks that the latter be spent sparingly — and neither belongs on a
            // query nobody asked to authenticate.
            Assert.That(dot.Additionals.Any(rr => rr.Type is TsigType or SigType), Is.False, "DoT");
            Assert.That(doh.Additionals.Any(rr => rr.Type is TsigType or SigType), Is.False, "DoH");

        });

    }

    #endregion

}

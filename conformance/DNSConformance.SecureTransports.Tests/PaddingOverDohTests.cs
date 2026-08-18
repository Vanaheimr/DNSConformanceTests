using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.SecureTransports.Tests;

/// <summary>
/// RFC 7830 and RFC 8467 over RFC 8484's transport: the padding Hermod's DoH
/// client puts into the DNS message it sends.
/// </summary>
/// <remarks>
/// <para>
/// RFC 8467 never mentions DoH. That is not an exclusion — §1 says which
/// transports it is for: "Padding DNS messages is useful only when transport is
/// encrypted using protocols such as DNS over Transport Layer Security
/// [RFC7858], DNS over Datagram Transport Layer Security [RFC8094], or other
/// encrypted DNS transports specified in the future." DoH was published the same
/// month and is one of those, so §4.1's 128-octet query block applies here for
/// the same reason it applies to DoT.
/// </para>
/// <para>
/// RFC 8484 §9 confirms it from the other end: "DoH servers can also add DNS
/// padding [RFC7830] if the DoH client requests it in the DNS query." Requesting
/// it is the client's part, and it is the only part Hermod has — there is no DoH
/// server here to hold to the responder's MUST.
/// </para>
/// <para>
/// One rule really is different on this transport, and it is the payload-size
/// ceiling. RFC 8484 §6: "DoH servers using this media type MUST ignore the
/// value given for the EDNS UDP payload size in DNS requests." Over DoT that
/// field caps the reply; over DoH a responder is required to disregard it, so
/// the only thing it does here is force the OPT record into existence for the
/// Padding option to live in.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "7830")]
public class PaddingOverDohTests
{

    #region (private) NewServer() / NewClient(Server, Mode, PaddingBlockSize = null)

    private static ScriptedDoHServer NewServer()
        => new(request => RawDnsResponder.Answer(
                              request,
                              ("pad.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.42"))
                          ));

    /// <param name="PaddingBlockSize">
    /// Left alone unless a test is about overriding it — RFC 8467 §4.1 asks
    /// clients to pad, so the default is part of what is under test.
    /// </param>
    private static DNSHTTPSClient NewClient(ScriptedDoHServer  Server,
                                            DNSHTTPSMode       Mode               = DNSHTTPSMode.POST,
                                            UInt16?            PaddingBlockSize   = null)
    {

        var client = new DNSHTTPSClient(
                         URL.Parse(Server.Url),
                         Mode:          Mode,
                         QueryTimeout:  TimeSpan.FromSeconds(10)
                     );

        if (PaddingBlockSize.HasValue)
            client.PaddingBlockSize = PaddingBlockSize.Value;

        return client;

    }

    #endregion

    #region (private) PaddingOf(DnsMessage)

    private static IReadOnlyList<(UInt16 Code, Byte[] Data)> PaddingOf(Byte[] DnsMessage)
    {

        var opt = RawDnsReader.Parse(DnsMessage).Additionals.FirstOrDefault(rr => rr.IsOpt);

        return opt is null
                   ? []
                   : [.. RawEdns.From(opt).Options.Where(option => option.Code == 12)];

    }

    #endregion


    #region Doh_Client_Announces_Edns0()

    [Test]
    [Property("RFC", "8484 §6, 6891 §6.1.1")]
    public async Task Doh_Client_Announces_Edns0()
    {

        // The Padding option lives in the OPT record, so announcing EDNS(0) is
        // the precondition for padding anything. RFC 8484 §6 makes the size in
        // that record inert — "DoH servers using this media type MUST ignore the
        // value given for the EDNS UDP payload size in DNS requests" — but the
        // record itself is what carries the option.
        await using var server = NewServer();
        await using var client = NewClient(server);

        await client.Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True, "the DoH endpoint received a request");

        var opt = RawDnsReader.Parse(exchange!.DnsMessage).Additionals.FirstOrDefault(rr => rr.IsOpt);

        Assert.That(opt, Is.Not.Null, "the DoH client announces EDNS(0)");

    }

    #endregion

    #region Doh_Client_Pads_Its_Queries_To_A_Multiple_Of_128(Mode)

    [TestCase(DNSHTTPSMode.POST, TestName = "Doh_Client_Pads_Its_Queries_To_A_Multiple_Of_128_Post")]
    [TestCase(DNSHTTPSMode.GET,  TestName = "Doh_Client_Pads_Its_Queries_To_A_Multiple_Of_128_Get")]
    [Property("RFC", "8467 §4.1")]
    public async Task Doh_Client_Pads_Its_Queries_To_A_Multiple_Of_128(DNSHTTPSMode Mode)
    {

        // RFC 8467 §4.1: "Clients SHOULD pad queries to the closest multiple of
        //  128 octets." What is padded is the DNS message; how the request
        //  carries it — a body or a base64url parameter — is HTTP's business.
        await using var server = NewServer();
        await using var client = NewClient(server, Mode);
        await using var bare   = NewClient(server, Mode, PaddingBlockSize: 0);

        await bare.  Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));
        await client.Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var unpadded), Is.True, "the unpadded request arrived");
        Assert.That(server.Exchanges.TryDequeue(out var padded),   Is.True, "the padded request arrived");

        var message  = padded!.DnsMessage;
        var padding  = PaddingOf(message);

        TestContext.Out.WriteLine($"{Mode}: unpadded {unpadded!.DnsMessage.Length} octets -> padded {message.Length} octets, " +
                                  $"{(padding.Count == 0 ? "no padding" : $"{padding[0].Data.Length} padding octets")}");

        Assert.Multiple(() => {

            Assert.That(padding,           Has.Count.EqualTo(1),
                        "the query carries exactly one Padding option");

            Assert.That(message.Length % 128, Is.Zero,
                        () => $"RFC 8467 §4.1 asks for a multiple of 128 octets, got {message.Length}");

            // "Closest multiple", not "some multiple". The four octets are the
            // option's own header, which §4.1 calls out: "even the zero-length
            // 'Padding' option increases the length of the packet by 4 octets".
            Assert.That(message.Length - 128, Is.LessThan(unpadded.DnsMessage.Length + 4),
                        () => $"{message.Length} octets overshoots; {unpadded.DnsMessage.Length + 4} would already fit below it");

            Assert.That(padding[0].Data,   Is.All.Zero,
                        "RFC 7830 §3: the PADDING octets SHOULD be set to 0x00");

        });

    }

    #endregion

    #region A_Padded_Query_Still_Encodes_As_Unpadded_Base64url()

    [Test]
    [Property("RFC", "8484 §4.1, 8467 §4.1")]
    public async Task A_Padded_Query_Still_Encodes_As_Unpadded_Base64url()
    {

        // Two things called padding meet here, and they are unrelated: RFC 8467
        // pads the DNS message, RFC 4648 pads a base64 encoding to a multiple of
        // four characters. RFC 8484 §4.1 forbids the second — "Padding
        // characters for base64url MUST NOT be included."
        //
        // The first makes the second unavoidable to get wrong. A message whose
        // length is a multiple of 128 leaves a remainder of 2 when divided by 3,
        // which is exactly the case where base64 appends a '=' — so padding to
        // §4.1's recommended block puts every GET request into the encoding case
        // that has to be trimmed.
        await using var server = NewServer();
        await using var client = NewClient(server, DNSHTTPSMode.GET);

        await client.Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True, "the DoH endpoint received a GET");

        TestContext.Out.WriteLine($"{exchange!.DnsMessage.Length} octets (128 | {exchange.DnsMessage.Length % 128 == 0}), " +
                                  $"{exchange.RawDnsParameter?.Length} base64url characters");

        Assert.Multiple(() => {

            Assert.That(exchange.DnsMessage.Length % 128, Is.Zero,
                        "the message is padded to the recommended block");

            Assert.That(exchange.DnsMessage.Length % 3,   Is.EqualTo(2),
                        "which is the length class base64 would want to pad");

            Assert.That(exchange.RawDnsParameter,         Does.Not.Contain("="),
                        "and the '=' is nonetheless absent, as RFC 8484 §4.1 requires");

            Assert.That(exchange.RawDnsParameter,         Does.Not.Contain("%"),
                        "with nothing needing percent-encoding either");

        });

    }

    #endregion

    #region Doh_Client_Padding_Can_Be_Switched_Off()

    [Test]
    [Property("RFC", "8467 §4.1")]
    public async Task Doh_Client_Padding_Can_Be_Switched_Off()
    {

        // §4.1 pads under a SHOULD. A caller with a reason to spend no bandwidth
        // on it keeps EDNS(0) and drops only the padding.
        await using var server = NewServer();
        await using var client = NewClient(server, PaddingBlockSize: 0);

        await client.Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True, "the DoH endpoint received a request");

        Assert.Multiple(() => {

            Assert.That(RawDnsReader.Parse(exchange!.DnsMessage).Additionals.Any(rr => rr.IsOpt), Is.True,
                        "EDNS(0) is still announced");

            Assert.That(PaddingOf(exchange!.DnsMessage), Is.Empty,
                        "but no Padding option is sent");

        });

    }

    #endregion

    #region Doh_Client_Without_Edns_Sends_No_Padding()

    [Test]
    [Property("RFC", "7830 §4")]
    public async Task Doh_Client_Without_Edns_Sends_No_Padding()
    {

        // Withdrawing EDNS(0) has to withdraw padding with it, whatever the block
        // length says: there is no OPT record for the option to live in, and
        // conjuring one would announce support the caller just took back.
        await using var server = NewServer();
        await using var client = NewClient(server);
        client.UDPPayloadSize = 0;

        await client.Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True, "the DoH endpoint received a request");

        Assert.Multiple(() => {

            Assert.That(RawDnsReader.Parse(exchange!.DnsMessage).Additionals.Any(rr => rr.IsOpt), Is.False,
                        "no OPT record, so no EDNS(0) support is indicated");

            Assert.That(PaddingOf(exchange!.DnsMessage), Is.Empty,
                        "and nothing is padded");

        });

    }

    #endregion

    #region Doh_Padding_Counts_The_Tsig_It_Sends()

    [Test]
    [Property("RFC", "8467 §4.1, 8945 §5.1")]
    public async Task Doh_Padding_Counts_The_Tsig_It_Sends()
    {

        // As on DoT: what an observer counts is the finished message, TSIG
        // record included, so that is the length which has to land on the
        // boundary. Neither RFC addresses the combination.
        var key = new TSIGKey(
                      DomainName.Parse("doh-padding-key."),
                      Convert.FromBase64String("cGFkZGluZy1vdmVyLWRvaC10c2lnLXRlc3Qtc2VjcmV0LTEyMzQ=")
                  );

        await using var server = new ScriptedDoHServer(
            request => {

                var answer = RawDnsResponder.Answer(request, ("pad.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.42")));

                return answer is null
                           ? null
                           : TSIGSigner.Sign(answer, key, RequestMAC: TSIGSigner.Verify(request, key).MAC);

            }
        );

        await using var client = NewClient(server);
        client.TransactionSecurity = new DNSTransactionSecurity(TSIGKey: key);

        await client.Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True, "the DoH endpoint received a signed request");

        var message = exchange!.DnsMessage;
        var decoded = RawDnsReader.Parse(message);

        TestContext.Out.WriteLine($"signed and padded DoH query: {message.Length} octets (128 | {message.Length % 128 == 0})");

        Assert.Multiple(() => {

            Assert.That(decoded.Additionals[^1].Type, Is.EqualTo((UInt16) 250),
                        "RFC 8945 §5.1: the TSIG is still the last record");

            Assert.That(TSIGSigner.Verify(message, key).IsValid, Is.True,
                        "and the MAC covers the padded message it was computed over");

            Assert.That(message.Length % 128,         Is.Zero,
                        () => $"the signed message is what lands on the boundary, got {message.Length}");

            Assert.That(PaddingOf(message),           Has.Count.EqualTo(1),
                        "with one Padding option doing the work");

        });

    }

    #endregion

}

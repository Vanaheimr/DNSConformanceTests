using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.SecureTransports.Tests;

/// <summary>
/// RFC 7830 — the EDNS(0) Padding option — and RFC 8467's block-length policy,
/// against Hermod's DoT server. A query is short and its length says a great
/// deal about it; TLS hides the name and leaves the length behind. Padding is
/// what closes that gap, which is why RFC 7830 §4 states it as a MUST rather
/// than an optimisation.
/// </summary>
/// <remarks>
/// Everything here is read with the suite's own RawDns codec, never with the
/// implementation under test — the padding a server emits is only interesting
/// if something other than that server counted the octets.
/// </remarks>
[TestFixture]
[Property("RFC", "7830")]
public class PaddingTests
{

    #region (private) PaddingOption(Length, Fill = 0x00)

    /// <summary>
    /// An EDNS option blob carrying one Padding option of the given length.
    /// </summary>
    /// <param name="Length">How many PADDING octets to carry.</param>
    /// <param name="Fill">What to fill them with — 0x00 unless a test is about the alternative.</param>
    private static Byte[] PaddingOption(Int32  Length,
                                        Byte   Fill   = 0x00)
    {

        var blob = new Byte[4 + Length];

        blob[0] = 0x00;
        blob[1] = 0x0C;                          // RFC 7830 §3: "The OPTION-CODE for the 'Padding' option is 12."
        blob[2] = (Byte) (Length >> 8);          // RFC 7830 §3: "The OPTION-LENGTH ... is the size (in octets) of the PADDING."
        blob[3] = (Byte) (Length & 0xFF);

        for (var i = 4; i < blob.Length; i++)
            blob[i] = Fill;

        return blob;

    }

    #endregion

    #region (private) PaddingOf(RawResponse)

    /// <summary>
    /// The Padding options carried by a response, as the raw reader sees them.
    /// </summary>
    private static IReadOnlyList<(UInt16 Code, Byte[] Data)> PaddingOf(Byte[] RawResponse)
    {

        var opt = RawDnsReader.Parse(RawResponse).Additionals.FirstOrDefault(rr => rr.IsOpt);

        return opt is null
                   ? []
                   : [.. RawEdns.From(opt).Options.Where(option => option.Code == 12)];

    }

    #endregion

    #region (private) NewClient(Port, PaddingBlockSize = null)

    /// <summary>
    /// A DoT client pointed at a scripted listener on the loopback interface.
    /// </summary>
    /// <param name="PaddingBlockSize">
    /// Left alone unless a test is about overriding it. RFC 8467 §4.1 asks
    /// clients to pad, so the default is part of what is under test: a helper
    /// that set the block length on every client would keep passing if the
    /// default were switched off.
    /// </param>
    private static DNSTLSClient NewClient(Int32    Port,
                                          UInt16?  PaddingBlockSize   = null)
    {

        var client = new DNSTLSClient(
                         IPv4Address.Localhost,
                         TCPPort:                     IPPort.Parse((UInt16) Port),
                         QueryTimeout:                TimeSpan.FromSeconds(10),
                         RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success()
                     );

        if (PaddingBlockSize.HasValue)
            client.PaddingBlockSize = PaddingBlockSize.Value;

        return client;

    }

    #endregion


    #region Responder_Must_Pad_A_Response_To_A_Padded_Query()

    [Test]
    [Property("RFC", "7830 §4, 8467 §4.1")]
    public async Task Responder_Must_Pad_A_Response_To_A_Padded_Query()
    {

        // RFC 7830 §4: "Responders MUST pad DNS responses when the respective
        //  DNS query included the 'Padding' option, unless doing so would
        //  violate the maximum UDP payload size."
        //
        // RFC 8467 §4.1: a server "SHOULD pad the corresponding response to a
        //  multiple of 468 octets".
        await using var fixture = await HermodServerFixture.StartAsync(
                                            new HermodServerFixtureOptions {
                                                EnableUdp  = false,
                                                EnableTcp  = false,
                                                EnableTls  = true
                                            }
                                        );

        var bare      = await RawTlsProbe.QueryAsync(
                                  fixture.TlsPort,
                                  RawDnsWriter.Query(0x7829, ZoneFixtures.AName, RawDnsType.A, ednsPayloadSize: 4096)
                              );

        var query     = RawDnsWriter.Query(0x7830, ZoneFixtures.AName, RawDnsType.A,
                                           ednsPayloadSize:  4096,
                                           ednsOptions:      PaddingOption(64));

        var raw       = await RawTlsProbe.QueryAsync(fixture.TlsPort, query);

        Assert.That(bare, Is.Not.Null, "the DoT server answered an unpadded query at all");
        Assert.That(raw,  Is.Not.Null, "the DoT server answered a padded query at all");

        var padding   = PaddingOf(raw!);

        TestContext.Out.WriteLine($"query {query.Length} octets -> response {raw!.Length} octets " +
                                  $"(unpadded it is {bare!.Length}), " +
                                  $"{(padding.Count == 0 ? "no padding" : $"{padding[0].Data.Length} padding octets")}");

        Assert.Multiple(() => {

            Assert.That(padding,          Has.Count.EqualTo(1),
                        "RFC 7830 §4 makes padding the response mandatory once the query carried the option");

            Assert.That(raw.Length % 468, Is.Zero,
                        () => $"RFC 8467 §4.1 asks for a multiple of 468 octets, got {raw.Length}");

            // "a multiple of 468" on its own would also be satisfied by spending
            // a whole spare block. The boundary reached has to be the first one
            // that holds the message: the one below it must be too small. The
            // four octets are the Padding option's own header, which the message
            // has to carry before any filler goes into it.
            Assert.That(raw.Length - 468, Is.LessThan(bare.Length + 4),
                        () => $"{raw.Length} octets wastes a block; {bare.Length + 4} would already fit below it");

        });

    }

    #endregion

    #region Responder_Must_Not_Pad_When_The_Query_Announced_No_Edns()

    [Test]
    [Property("RFC", "7830 §4")]
    public async Task Responder_Must_Not_Pad_When_The_Query_Announced_No_Edns()
    {

        // RFC 7830 §4: "Responders MUST NOT pad DNS responses when the
        //  respective DNS query did not indicate EDNS(0) support."
        //
        // This one needs no policy decision to enforce: the Padding option
        // lives inside the OPT record, and a response to a query without
        // EDNS(0) has no OPT record to put it in.
        await using var fixture = await HermodServerFixture.StartAsync(
                                            new HermodServerFixtureOptions {
                                                EnableUdp  = false,
                                                EnableTcp  = false,
                                                EnableTls  = true
                                            }
                                        );

        var query    = RawDnsWriter.Query(0x7831, ZoneFixtures.AName, RawDnsType.A);

        var raw      = await RawTlsProbe.QueryAsync(fixture.TlsPort, query);

        Assert.That(raw, Is.Not.Null, "the DoT server answered a plain query at all");

        var decoded  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(decoded.Additionals.Any(rr => rr.IsOpt), Is.False,
                        "a response to a query without EDNS(0) carries no OPT record");

            Assert.That(PaddingOf(raw!), Is.Empty,
                        "RFC 7830 §4 forbids padding a response to a query that did not indicate EDNS(0) support");

        });

    }

    #endregion

    #region Responder_Leaves_An_Unpadded_Edns_Query_Unpadded()

    [Test]
    [Property("RFC", "7830 §4")]
    public async Task Responder_Leaves_An_Unpadded_Edns_Query_Unpadded()
    {

        // RFC 7830 §4: "Responders MAY pad DNS responses when the respective
        //  DNS query indicated EDNS(0) support and the 'Padding' option was not
        //  included."
        //
        // A MAY, so both answers conform and this test asserts a choice rather
        // than a requirement. The choice is worth pinning: padding a client
        // that never asked for it spends its bandwidth on a defence it did not
        // request, and a client that wants the defence has a way to say so.
        await using var fixture = await HermodServerFixture.StartAsync(
                                            new HermodServerFixtureOptions {
                                                EnableUdp  = false,
                                                EnableTcp  = false,
                                                EnableTls  = true
                                            }
                                        );

        var query  = RawDnsWriter.Query(0x7832, ZoneFixtures.AName, RawDnsType.A,
                                        ednsPayloadSize: 4096);

        var raw    = await RawTlsProbe.QueryAsync(fixture.TlsPort, query);

        Assert.That(raw, Is.Not.Null, "the DoT server answered an EDNS query at all");

        Assert.That(RawDnsReader.Parse(raw!).Additionals.Any(rr => rr.IsOpt), Is.True,
                    "the response echoes EDNS(0) support");

        Assert.That(PaddingOf(raw!), Is.Empty,
                    "Hermod exercises the MAY by not padding a response nobody asked to have padded");

    }

    #endregion

    #region Padded_Response_Must_Not_Exceed_The_Requestors_Payload_Size()

    [Test]
    [Property("RFC", "7830 §4")]
    public async Task Padded_Response_Must_Not_Exceed_The_Requestors_Payload_Size()
    {

        // RFC 7830 §4: "Padded DNS messages MUST NOT exceed the number of
        //  octets specified in the Requestor's Payload Size field."
        //
        // The ceiling and the recommended block length can disagree, and when
        // they do the ceiling wins — a response is shortened rather than pushed
        // past what the requestor said it would take.
        await using var fixture = await HermodServerFixture.StartAsync(
                                            new HermodServerFixtureOptions {
                                                EnableUdp  = false,
                                                EnableTcp  = false,
                                                EnableTls  = true
                                            }
                                        );

        // First learn how long this answer is without any padding, so the
        // ceiling can be placed above it — a ceiling below the bare response
        // would leave nothing to pad and make the test vacuous.
        var bareQuery  = RawDnsWriter.Query(0x7833, ZoneFixtures.BigTxtName, RawDnsType.TXT,
                                            ednsPayloadSize: 4096);

        var bare       = await RawTlsProbe.QueryAsync(fixture.TlsPort, bareQuery);

        Assert.That(bare, Is.Not.Null, "the DoT server answered the unpadded query at all");

        var ceiling    = (UInt16) (bare!.Length + 64);

        var query      = RawDnsWriter.Query(0x7834, ZoneFixtures.BigTxtName, RawDnsType.TXT,
                                            ednsPayloadSize:  ceiling,
                                            ednsOptions:      PaddingOption(64));

        var raw        = await RawTlsProbe.QueryAsync(fixture.TlsPort, query);

        Assert.That(raw, Is.Not.Null, "the DoT server answered the padded query at all");

        TestContext.Out.WriteLine($"bare {bare.Length} octets, ceiling {ceiling}, padded {raw!.Length} octets " +
                                  $"(the next 468-boundary would be {((raw.Length / 468) + 1) * 468})");

        Assert.Multiple(() => {

            Assert.That(raw.Length,      Is.LessThanOrEqualTo(ceiling),
                        () => $"RFC 7830 §4 caps the padded message at the requestor's payload size of {ceiling}");

            Assert.That(raw.Length,      Is.GreaterThan(bare.Length),
                        "the ceiling shortens the padding rather than dropping it");

            Assert.That(PaddingOf(raw!), Has.Count.EqualTo(1),
                        "the response is still padded, just not all the way to the block boundary");

        });

    }

    #endregion

    #region Padding_Option_Occurs_At_Most_Once_Per_Opt()

    [Test]
    [Property("RFC", "7830 §3")]
    public async Task Padding_Option_Occurs_At_Most_Once_Per_Opt()
    {

        // RFC 7830 §3: "The 'Padding' option MUST occur at most, once per OPT
        //  meta-RR (and hence, at most once per message)."
        //
        // The interesting case is a query that already carries one: whatever the
        // responder adds has to replace it, not join it.
        await using var fixture = await HermodServerFixture.StartAsync(
                                            new HermodServerFixtureOptions {
                                                EnableUdp  = false,
                                                EnableTcp  = false,
                                                EnableTls  = true
                                            }
                                        );

        var query  = RawDnsWriter.Query(0x7835, ZoneFixtures.AName, RawDnsType.A,
                                        ednsPayloadSize:  4096,
                                        ednsOptions:      PaddingOption(100));

        var raw    = await RawTlsProbe.QueryAsync(fixture.TlsPort, query);

        Assert.That(raw, Is.Not.Null, "the DoT server answered at all");

        Assert.That(PaddingOf(raw!), Has.Count.EqualTo(1),
                    "at most one Padding option per OPT meta-RR");

    }

    #endregion

    #region Client_Announces_Edns0_So_Padding_Has_Somewhere_To_Live()

    [Test]
    [Property("RFC", "6891 §6.1.1, 7830 §4")]
    public async Task Client_Announces_Edns0_So_Padding_Has_Somewhere_To_Live()
    {

        // The Padding option lives in the OPT record, so a client that sends no
        // OPT cannot pad — and RFC 7830 §4 then forbids the responder from
        // padding either: "Responders MUST NOT pad DNS responses when the
        // respective DNS query did not indicate EDNS(0) support." Announcing
        // EDNS(0) is the precondition for everything else in this file.
        await using var server = new ScriptedTlsServer(
            request => RawDnsResponder.Answer(request, ("pad.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.53")))
        );

        await using var client = NewClient(server.Port);

        await client.Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the DoT listener received a query");

        var opt = RawDnsReader.Parse(request!).Additionals.FirstOrDefault(rr => rr.IsOpt);

        Assert.That(opt, Is.Not.Null, "the DoT client announces EDNS(0)");

        Assert.That(RawEdns.From(opt!).PayloadSize, Is.GreaterThanOrEqualTo(468),
                    "and advertises room for a response padded to RFC 8467 §4.1's block length");

    }

    #endregion

    #region Client_Pads_Its_Queries_To_A_Multiple_Of_128()

    [Test]
    [Property("RFC", "8467 §4.1")]
    public async Task Client_Pads_Its_Queries_To_A_Multiple_Of_128()
    {

        // RFC 8467 §4.1: "Clients SHOULD pad queries to the closest multiple of
        //  128 octets", with the note that "the recommendation above only
        //  applies if the DNS transport is encrypted". DoT is encrypted by
        //  construction, so the recommendation always applies here.
        await using var server = new ScriptedTlsServer(
            request => RawDnsResponder.Answer(request, ("pad.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.53")))
        );

        await using var client = NewClient(server.Port);
        await using var bare   = NewClient(server.Port, PaddingBlockSize: 0);

        await bare.  Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));
        await client.Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Requests.TryDequeue(out var unpadded), Is.True, "the unpadded query arrived");
        Assert.That(server.Requests.TryDequeue(out var padded),   Is.True, "the padded query arrived");

        var padding = PaddingOf(padded!);

        TestContext.Out.WriteLine($"unpadded {unpadded!.Length} octets -> padded {padded!.Length} octets, " +
                                  $"{(padding.Count == 0 ? "no padding" : $"{padding[0].Data.Length} padding octets")}");

        Assert.Multiple(() => {

            Assert.That(padding,              Has.Count.EqualTo(1),
                        "the query carries exactly one Padding option");

            Assert.That(padded.Length % 128,  Is.Zero,
                        () => $"RFC 8467 §4.1 asks for a multiple of 128 octets, got {padded.Length}");

            // "Closest multiple", not "some multiple": the block below the one
            // reached has to be too small for the message. The four octets are
            // the Padding option's own header.
            Assert.That(padded.Length - 128,  Is.LessThan(unpadded.Length + 4),
                        () => $"{padded.Length} octets overshoots; {unpadded.Length + 4} would already fit below it");

            Assert.That(padding[0].Data,      Is.All.Zero,
                        "RFC 7830 §3: the PADDING octets SHOULD be set to 0x00");

        });

    }

    #endregion

    #region Client_Padding_Can_Be_Switched_Off()

    [Test]
    [Property("RFC", "8467 §4.1")]
    public async Task Client_Padding_Can_Be_Switched_Off()
    {

        // RFC 8467 §4.1 pads queries under a SHOULD, not a MUST, and RFC 7830 §4
        // leaves an unpadded EDNS(0) query under a MAY on the responder's side.
        // A caller that has a reason to spend no bandwidth on it keeps EDNS(0)
        // and drops only the padding.
        await using var server = new ScriptedTlsServer(
            request => RawDnsResponder.Answer(request, ("pad.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.53")))
        );

        await using var client = NewClient(server.Port, PaddingBlockSize: 0);

        await client.Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the DoT listener received a query");

        Assert.Multiple(() => {

            Assert.That(RawDnsReader.Parse(request!).Additionals.Any(rr => rr.IsOpt), Is.True,
                        "EDNS(0) is still announced");

            Assert.That(PaddingOf(request!), Is.Empty,
                        "but no Padding option is sent");

        });

    }

    #endregion

    #region Client_Without_Edns_Sends_No_Padding()

    [Test]
    [Property("RFC", "7830 §4")]
    public async Task Client_Without_Edns_Sends_No_Padding()
    {

        // Switching EDNS(0) off has to switch padding off with it, whatever the
        // block length says — there is no OPT record for the option to live in,
        // and a client that conjured one would be announcing support the caller
        // just withdrew.
        await using var server = new ScriptedTlsServer(
            request => RawDnsResponder.Answer(request, ("pad.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.53")))
        );

        await using var client = NewClient(server.Port);
        client.UDPPayloadSize = 0;

        await client.Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the DoT listener received a query");

        Assert.Multiple(() => {

            Assert.That(RawDnsReader.Parse(request!).Additionals.Any(rr => rr.IsOpt), Is.False,
                        "no OPT record, so no EDNS(0) support is indicated");

            Assert.That(PaddingOf(request!), Is.Empty,
                        "and nothing is padded");

        });

    }

    #endregion

    #region Client_Padding_Counts_The_Tsig_It_Sends()

    [Test]
    [Property("RFC", "8467 §4.1, 8945 §5.1")]
    public async Task Client_Padding_Counts_The_Tsig_It_Sends()
    {

        // Neither RFC says what padding and a transaction signature do to each
        // other. What an observer counts is the finished message, TSIG record
        // included, so that is the length which has to land on the boundary —
        // padding the message underneath a signature of some other length would
        // leave the observable length exactly as revealing as before.
        var key = new TSIGKey(
                      DomainName.Parse("padding-key."),
                      Convert.FromBase64String("cGFkZGluZy1vdmVyLWRvdC10c2lnLXRlc3Qtc2VjcmV0LTEyMzQ=")
                  );

        await using var server = new ScriptedTlsServer(
            request => {

                var answer = RawDnsResponder.Answer(request, ("pad.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.53")));

                return answer is null
                           ? null
                           : TSIGSigner.Sign(answer, key, RequestMAC: TSIGSigner.Verify(request, key).MAC);

            }
        );

        await using var client = NewClient(server.Port);
        client.TransactionSecurity = new DNSTransactionSecurity(TSIGKey: key);

        await client.Query<A>(DomainName.Parse("pad.example."), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the DoT listener received a signed query");

        var decoded = RawDnsReader.Parse(request!);

        TestContext.Out.WriteLine($"signed and padded query: {request!.Length} octets (128 | {request.Length % 128 == 0})");

        Assert.Multiple(() => {

            Assert.That(decoded.Additionals[^1].Type, Is.EqualTo((UInt16) 250),
                        "RFC 8945 §5.1: the TSIG is still the last record");

            Assert.That(TSIGSigner.Verify(request!, key).IsValid, Is.True,
                        "and the MAC covers the padded message it was computed over");

            Assert.That(request.Length % 128,         Is.Zero,
                        () => $"the signed message is what lands on the boundary, got {request.Length}");

            Assert.That(PaddingOf(request!),          Has.Count.EqualTo(1),
                        "with one Padding option doing the work");

        });

    }

    #endregion

    #region A_Padded_Client_Query_Puts_The_Server_Under_The_Must()

    [Test]
    [Property("RFC", "7830 §4, 8467 §4.1")]
    public async Task A_Padded_Client_Query_Puts_The_Server_Under_The_Must()
    {

        // Both halves in one line: the query Hermod's DoT client actually
        // produces is replayed, octet for octet, at Hermod's DoT server. Each
        // half is asserted on its own above; what this adds is that the client's
        // output really does satisfy the condition the server's MUST is written
        // against, rather than something adjacent to it.
        await using var listener = new ScriptedTlsServer(
            request => RawDnsResponder.Answer(request, (ZoneFixtures.AName, RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.1")))
        );

        await using var client = NewClient(listener.Port);

        await client.Query<A>(DomainName.Parse(ZoneFixtures.AName), Timeout: TimeSpan.FromSeconds(10));

        Assert.That(listener.Requests.TryDequeue(out var clientQuery), Is.True, "the DoT client produced a query");

        await using var fixture = await HermodServerFixture.StartAsync(
                                            new HermodServerFixtureOptions {
                                                EnableUdp  = false,
                                                EnableTcp  = false,
                                                EnableTls  = true
                                            }
                                        );

        var raw = await RawTlsProbe.QueryAsync(fixture.TlsPort, clientQuery!);

        Assert.That(raw, Is.Not.Null, "Hermod's DoT server answered Hermod's DoT client's own query");

        TestContext.Out.WriteLine($"client query {clientQuery!.Length} octets (128 | {clientQuery.Length % 128 == 0}) " +
                                  $"-> server response {raw!.Length} octets (468 | {raw.Length % 468 == 0})");

        Assert.Multiple(() => {

            Assert.That(clientQuery.Length % 128, Is.Zero,   "the query left on a 128-octet boundary");
            Assert.That(PaddingOf(raw!),          Has.Count.EqualTo(1),
                        "and the response came back padded, as RFC 7830 §4 requires of it");
            Assert.That(raw.Length % 468,         Is.Zero,   "on a 468-octet boundary");

        });

    }

    #endregion

    #region Block_Length_Arithmetic(MeasuredLength, BlockSize, MaxLength, Expected)

    // RFC 8467 §4.1: "In Block-Length Padding, a sender pads each message so
    //  that its padded length is a multiple of a chosen block length."
    //
    // Reaching a boundary the message already sits on costs nothing — the
    // boundary case is the one the wire tests cannot stage, because it needs a
    // response whose length is a multiple of 468 to the octet.
    [TestCase(468, 468, null,   0, TestName = "Block_Length_Arithmetic_Already_On_A_Boundary_Adds_Nothing")]
    [TestCase(936, 468, null,   0, TestName = "Block_Length_Arithmetic_Any_Boundary_Adds_Nothing")]
    [TestCase(  0, 468, null,   0, TestName = "Block_Length_Arithmetic_The_Empty_Message_Adds_Nothing")]
    [TestCase(  1, 468, null, 467, TestName = "Block_Length_Arithmetic_One_Octet_Past_Reaches_The_Next")]
    [TestCase(469, 468, null, 467, TestName = "Block_Length_Arithmetic_One_Octet_Past_A_Boundary_Reaches_The_Next")]
    [TestCase( 85, 468, null, 383, TestName = "Block_Length_Arithmetic_A_Short_Response_Reaches_468")]
    [TestCase( 29, 128, null,  99, TestName = "Block_Length_Arithmetic_A_Query_Reaches_128")]

    // RFC 7830 §4: "Padded DNS messages MUST NOT exceed the number of octets
    //  specified in the Requestor's Payload Size field." The ceiling shortens
    //  the padding; it does not turn it off, and it never goes negative on a
    //  message that is already past it.
    [TestCase( 85, 468,  300, 215, TestName = "Block_Length_Arithmetic_The_Ceiling_Shortens_The_Padding")]
    [TestCase( 85, 468,  468, 383, TestName = "Block_Length_Arithmetic_A_Ceiling_On_The_Boundary_Does_Not_Bite")]
    [TestCase(700, 468,  500,   0, TestName = "Block_Length_Arithmetic_A_Message_Already_Past_The_Ceiling_Adds_Nothing")]
    [Property("RFC", "7830 §4, 8467 §4.1")]
    public void Block_Length_Arithmetic(Int32  MeasuredLength,
                                        Int32  BlockSize,
                                        Int32? MaxLength,
                                        Int32  Expected)
    {

        Assert.That(DNSPadding.OctetsFor(MeasuredLength, (UInt16) BlockSize, MaxLength),
                    Is.EqualTo(Expected));

    }

    #endregion

    #region A_Block_Length_Of_Zero_Is_Refused()

    [Test]
    [Property("RFC", "8467 §4.1")]
    public void A_Block_Length_Of_Zero_Is_Refused()
    {

        // Not an RFC rule — RFC 8467 never contemplates a block length of zero,
        // which is exactly why it has to be refused rather than divided by.
        Assert.That(() => DNSPadding.OctetsFor(85, 0),
                    Throws.TypeOf<ArgumentOutOfRangeException>());

    }

    #endregion

    #region Padding_Replaces_An_Existing_Option_Rather_Than_Joining_It()

    [Test]
    [Property("RFC", "7830 §3")]
    public void Padding_Replaces_An_Existing_Option_Rather_Than_Joining_It()
    {

        // RFC 7830 §3: "The 'Padding' option MUST occur at most, once per OPT
        //  meta-RR (and hence, at most once per message)."
        //
        // The server path above cannot reach this: it pads a freshly built
        // response OPT, which never inherits the requestor's options, so a
        // padder that appended instead of replacing would look identical on the
        // wire. This drives the case directly — a message that already carries
        // a Padding option — and still counts the result with the suite's own
        // reader rather than with the encoder that produced it.
        var message  = DNSPacket.Query(
                           DNSServiceName.Parse("pad.example."),
                           (UInt16) 4096,
                           true,
                           [new EDNSPaddingOption(16)],
                           DNSResourceRecordTypes.A
                       );

        var padded   = DNSPadding.WithPadding(message, 64);

        using var stream = new MemoryStream();
        padded.Serialize(stream, false, []);

        var options  = PaddingOf(stream.ToArray());

        Assert.Multiple(() => {

            Assert.That(options,                Has.Count.EqualTo(1),
                        "the option already present is replaced, not joined by a second one");

            Assert.That(options[0].Data.Length, Is.EqualTo(64),
                        "and it is the new length that survives, not the old one");

        });

    }

    #endregion

    #region Padding_Octets_In_The_Response_Are_Zero()

    [Test]
    [Property("RFC", "7830 §3")]
    public async Task Padding_Octets_In_The_Response_Are_Zero()
    {

        // RFC 7830 §3: "The PADDING octets SHOULD be set to 0x00. Other values
        //  MAY be used, for example, in cases where there is a concern that the
        //  padded message could be subject to compression before encryption."
        //
        // DNS name compression runs over the message body and never reaches the
        // OPT RDATA, so the exception does not apply here and the SHOULD stands.
        await using var fixture = await HermodServerFixture.StartAsync(
                                            new HermodServerFixtureOptions {
                                                EnableUdp  = false,
                                                EnableTcp  = false,
                                                EnableTls  = true
                                            }
                                        );

        var query    = RawDnsWriter.Query(0x7836, ZoneFixtures.AName, RawDnsType.A,
                                          ednsPayloadSize:  4096,
                                          ednsOptions:      PaddingOption(64));

        var raw      = await RawTlsProbe.QueryAsync(fixture.TlsPort, query);

        Assert.That(raw, Is.Not.Null, "the DoT server answered at all");

        var padding  = PaddingOf(raw!);

        Assert.That(padding, Has.Count.EqualTo(1), "the response is padded");

        Assert.That(padding[0].Data, Is.All.Zero,
                    () => "the PADDING octets SHOULD be 0x00, found " +
                          $"{padding[0].Data.Count(octet => octet != 0x00)} non-zero of {padding[0].Data.Length}");

    }

    #endregion

    #region Padding_Octets_Of_Any_Value_Are_Accepted()

    [Test]
    [Property("RFC", "7830 §3")]
    public async Task Padding_Octets_Of_Any_Value_Are_Accepted()
    {

        // RFC 7830 §3: "PADDING octets of any value MUST be accepted in the
        //  messages received."
        //
        // A receiver that inspected the filler would reject exactly the traffic
        // the option exists to permit, so the test sends the least 0x00-looking
        // filler it can and expects an ordinary answer back.
        await using var fixture = await HermodServerFixture.StartAsync(
                                            new HermodServerFixtureOptions {
                                                EnableUdp  = false,
                                                EnableTcp  = false,
                                                EnableTls  = true
                                            }
                                        );

        var query     = RawDnsWriter.Query(0x7837, ZoneFixtures.AName, RawDnsType.A,
                                           ednsPayloadSize:  4096,
                                           ednsOptions:      PaddingOption(64, Fill: 0xFF));

        var raw       = await RawTlsProbe.QueryAsync(fixture.TlsPort, query);

        Assert.That(raw, Is.Not.Null, "a query padded with 0xFF octets was answered at all");

        var decoded   = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(decoded.RCode,                       Is.Zero,
                        "non-zero PADDING octets are not an error");

            Assert.That(decoded.Answers.Single().Name.Canonical,
                        Is.EqualTo(ZoneFixtures.AName.TrimEnd('.')),
                        () => "the padded query was answered normally:\n" + Bytes.Dump(raw!));

            Assert.That(PaddingOf(raw!), Has.Count.EqualTo(1),
                        "and the response is padded in return");

        });

    }

    #endregion

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 8945 §5 — the Hermod server answering TSIG-signed queries.
///
/// <para>
/// The signing primitives are covered elsewhere; what these check is that the
/// server actually reaches for them: that a signed query is verified before it
/// is served, that the reply carries a MAC bound to the request's, and that a
/// query which fails verification is refused rather than answered.
/// </para>
///
/// <para>
/// Everything goes over raw sockets and is read back with <c>RawDns</c>, so no
/// assertion here depends on Hermod agreeing with itself.
/// </para>
/// </summary>
[TestFixture]
public class TsigServerTests
{

    private static readonly Byte[]   Secret  = Convert.FromBase64String("c2VydmVyLXNpZGUtdHNpZy10ZXN0LXNlY3JldC0xMjM0NTY3OA==");

    private static TSIGKey Key(String Name = "server-key.")
        => new (DomainName.Parse(Name), Secret);

    private static async Task<HermodServerFixture> SignedServerAsync()
        => await HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
                     EnableTcp  = true,
                     TSIGKeys   = [ Key() ]
                 });


    #region Signed_Query_Is_Answered_With_A_Signed_Response()

    [Test]
    [Property("RFC", "8945 §5.3")]
    public async Task Signed_Query_Is_Answered_With_A_Signed_Response()
    {

        await using var server = await SignedServerAsync();

        var query    = RawDnsWriter.Query(0x7A11, ZoneFixtures.AName, RawDnsType.A);
        var signed   = TSIGSigner.Sign(query, Key());
        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null, "the server must answer a correctly signed query");

        var response = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(response.RCode,        Is.EqualTo(0), "a valid signature must not change the answer");
            Assert.That(response.Answers,      Is.Not.Empty,  "the query is still a query — it has to be served");
            Assert.That(response.Additionals.Any(rr => rr.Type == 250), Is.True,
                        "§5.3: the response to a signed request is itself signed");

        });

    }

    #endregion

    #region Response_Mac_Is_Bound_To_The_Request()

    [Test]
    [Property("RFC", "8945 §4.3.1")]
    public async Task Response_Mac_Is_Bound_To_The_Request()
    {

        await using var server = await SignedServerAsync();

        var query        = RawDnsWriter.Query(0x7A12, ZoneFixtures.AName, RawDnsType.A);
        var signed       = TSIGSigner.Sign(query, Key());
        var requestMAC   = TSIGSigner.Verify(signed, Key()).MAC!;

        var raw          = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.Multiple(() => {

            // With the request's MAC, the response verifies.
            Assert.That(TSIGSigner.Verify(raw!, Key(), RequestMAC: requestMAC).IsValid, Is.True,
                        "the response must verify against the request it answers");

            // Without it, it must not — that is the binding doing its work, and
            // it is what stops a signed response being replayed to answer a
            // different question.
            Assert.That(TSIGSigner.Verify(raw!, Key()).IsValid, Is.False,
                        "the response must not verify as a standalone message");

        });

    }

    #endregion

    #region Query_Signed_With_The_Wrong_Secret_Is_Refused()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public async Task Query_Signed_With_The_Wrong_Secret_Is_Refused()
    {

        await using var server = await SignedServerAsync();

        var impostor = new TSIGKey(DomainName.Parse("server-key."), Convert.FromBase64String("d3Jvbmctc2VjcmV0LXRoYXQtaXMtbm90LXRoZS1yaWdodC1vbmU="));
        var signed   = TSIGSigner.Sign(RawDnsWriter.Query(0x7A13, ZoneFixtures.AName, RawDnsType.A), impostor);

        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null,
                    "§5.2 wants an answer, not silence — a client cannot distinguish a dropped packet from a rejected one");

        var response = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(response.RCode,    Is.EqualTo(9), "NOTAUTH");
            Assert.That(response.Answers,  Is.Empty,      "nothing is served to an unauthenticated request");
        });

    }

    #endregion

    #region Query_Signed_With_An_Unknown_Key_Is_Refused()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public async Task Query_Signed_With_An_Unknown_Key_Is_Refused()
    {

        await using var server = await SignedServerAsync();

        var signed  = TSIGSigner.Sign(RawDnsWriter.Query(0x7A14, ZoneFixtures.AName, RawDnsType.A), Key("some-other-key."));
        var raw     = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null);
        Assert.That(RawDnsReader.Parse(raw!).RCode, Is.EqualTo(9), "NOTAUTH for a key the server does not hold");

    }

    #endregion

    #region Query_Signed_Outside_The_Fudge_Window_Is_Refused()

    [Test]
    [Property("RFC", "8945 §5.2.3")]
    public async Task Query_Signed_Outside_The_Fudge_Window_Is_Refused()
    {

        await using var server = await SignedServerAsync();

        // Signed an hour ago with a 300 s fudge: the MAC is perfectly good and
        // the message must still be refused, or a captured query could be
        // replayed indefinitely.
        var longAgo = (UInt64) DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
        var signed  = TSIGSigner.Sign(RawDnsWriter.Query(0x7A15, ZoneFixtures.AName, RawDnsType.A), Key(), TimeSigned: longAgo);

        var raw     = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null);
        Assert.That(RawDnsReader.Parse(raw!).RCode, Is.EqualTo(9), "NOTAUTH for a stale signature");

    }

    #endregion

    #region Unsigned_Query_Is_Still_Served()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public async Task Unsigned_Query_Is_Still_Served()
    {

        await using var server = await SignedServerAsync();

        // Holding a key is not the same as demanding one. RFC 8945 does not make
        // an unsigned query invalid, and refusing it would be a policy decision
        // this server does not take on its own.
        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, RawDnsWriter.Query(0x7A16, ZoneFixtures.AName, RawDnsType.A));
        var response = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(response.RCode,       Is.EqualTo(0));
            Assert.That(response.Answers,     Is.Not.Empty);
            Assert.That(response.Additionals.Any(rr => rr.Type == 250), Is.False,
                        "an unsigned request gets an unsigned reply");
        });

    }

    #endregion

    #region Signed_Query_Works_Over_Tcp_As_Well()

    [Test]
    [Property("RFC", "8945 §5.3")]
    public async Task Signed_Query_Works_Over_Tcp_As_Well()
    {

        await using var server = await SignedServerAsync();

        var signed  = TSIGSigner.Sign(RawDnsWriter.Query(0x7A17, ZoneFixtures.AName, RawDnsType.A), Key());
        var mac     = TSIGSigner.Verify(signed, Key()).MAC!;

        var raw     = await RawDnsProbe.TcpAsync(server.TcpPort, signed);

        Assert.That(raw, Is.Not.Null);
        Assert.That(TSIGSigner.Verify(raw!, Key(), RequestMAC: mac).IsValid, Is.True,
                    "TSIG is a property of the message, not of the transport");

    }

    #endregion

    #region A_Server_Without_Keys_Ignores_Tsig_Entirely()

    [Test]
    [Property("RFC", "8945 §5.2")]
    public async Task A_Server_Without_Keys_Ignores_Tsig_Entirely()
    {

        // Backwards compatibility, asserted rather than assumed: configuring no
        // keys must leave behaviour exactly as it was before TSIG existed.
        await using var server = await HermodServerFixture.StartAsync();

        var signed   = TSIGSigner.Sign(RawDnsWriter.Query(0x7A18, ZoneFixtures.AName, RawDnsType.A), Key());
        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, signed);

        Assert.That(raw, Is.Not.Null, "the server must not choke on a TSIG it was never told about");

        var response = RawDnsReader.Parse(raw!);

        Assert.That(response.RCode, Is.EqualTo(0));

    }

    #endregion

    #region A_Badtime_Refusal_Is_Signed_And_A_Badsig_One_Is_Not()

    [Test]
    [Property("RFC", "8945 §5.2.3")]
    [Property("RFC", "8945 §5.3.2")]
    public async Task A_Badtime_Refusal_Is_Signed_And_A_Badsig_One_Is_Not()
    {

        // Two refusals that look identical from the header — both NOTAUTH, both
        // empty — and which §5 requires the server to treat oppositely.
        //
        // §5.2.3: "A response indicating a BADTIME error MUST be signed by the
        // same key as the request", with the server's own clock in Other Data so
        // the sender can resynchronise and try again. The server has already
        // authenticated the message by then; only the clock was wrong.
        //
        // §5.3.2, the other way: "When a server detects an error relating to the
        // key or MAC in the incoming request, the server SHOULD send back an
        // unsigned error message ... It MUST NOT send back a signed error
        // message." There is nothing it could honestly sign with.
        //
        // Both refusals are already tested for their RCODE, which is the half
        // they agree on. Nothing looked inside the TSIG, where they must differ.
        await using var server = await SignedServerAsync();

        var StaleTimeSigned = (UInt64) DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();

        var stale      = TSIGSigner.Sign(
                             RawDnsWriter.Query(0x7A19, ZoneFixtures.AName, RawDnsType.A),
                             Key(),
                             TimeSigned: StaleTimeSigned);

        var impostor   = new TSIGKey(DomainName.Parse("server-key."),
                                     Convert.FromBase64String("d3Jvbmctc2VjcmV0LXRoYXQtaXMtbm90LXRoZS1yaWdodC1vbmU="));

        var forged     = TSIGSigner.Sign(
                             RawDnsWriter.Query(0x7A1A, ZoneFixtures.AName, RawDnsType.A),
                             impostor);

        var staleRaw   = await AskRawBytes(server, stale);
        var badTime    = TsigOf(RawDnsReader.Parse(staleRaw), "the stale request");
        var badSig     = TsigOf(RawDnsReader.Parse(await AskRawBytes(server, forged)), "the forged request");

        // The MAC is recomputed here from §4.3's digest input rather than taken on
        // trust, because "a MAC is present" is not the claim §5.2.3 makes. A signature
        // over the wrong bytes, or with the wrong key, is indistinguishable from a
        // correct one by its length alone — and it would leave the sender exactly
        // where an unsigned refusal does.
        var expected   = ExpectedResponseMac(staleRaw, badTime, MacOf(stale, "the request we sent"));

        // The server's clock, as the reply reports it, against the clock this
        // process reads. §5.2.3 exists so the sender can gauge the skew, which means
        // the number has to be the server's actual time and not a placeholder.
        var reported   = badTime.OtherData.Aggregate(0UL, (value, octet) => (value << 8) | octet);
        var ourClock   = (UInt64) DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        Assert.Multiple(() => {

            Assert.That(badTime.Error,     Is.EqualTo(18), "BADTIME");
            Assert.That(badTime.MacSize,   Is.GreaterThan(0),
                        "§5.2.3 — a BADTIME reply is signed, or the sender cannot trust the clock it is given");
            Assert.That(badTime.OtherLen,  Is.EqualTo(6),
                        "and carries the server's time as a 48-bit integer");

            Assert.That(badTime.MAC,       Is.EqualTo(expected),
                        "and the signature is the HMAC §4.3.3 describes over the request MAC, the reply, " +
                        "and the TSIG variables — not merely some octets of the right length");

            Assert.That(reported,          Is.EqualTo(ourClock).Within(120),
                        "the Other Data is the server's own clock, which is what makes the skew measurable");

            Assert.That(badTime.TimeSigned, Is.EqualTo(StaleTimeSigned),
                        "§5.2.3: the Time Signed field carries the *client's* time, the one that was refused");

            Assert.That(badSig.Error,      Is.EqualTo(16), "BADSIG");
            Assert.That(badSig.MacSize,    Is.Zero,
                        "§5.3.2 — a key or MAC failure MUST NOT be answered with a signed message");
            Assert.That(badSig.OtherLen,   Is.Zero,
                        "and tells it nothing about the clock, which was never the problem");

        });

    }

    #endregion

    #region Small independent helpers

    /// <summary>The fields of a TSIG RDATA (RFC 8945 §4.2), plus where the record began.</summary>
    private sealed record TsigFields(String  Owner,
                                     String  Algorithm,
                                     UInt64  TimeSigned,
                                     UInt16  Fudge,
                                     Int32   MacSize,
                                     Byte[]  MAC,
                                     UInt16  OriginalID,
                                     UInt16  Error,
                                     Int32   OtherLen,
                                     Byte[]  OtherData,
                                     Int32   RecordStart);


    private static async Task<RawDnsMessage> AskRaw(HermodServerFixture Server, Byte[] Query)
        => RawDnsReader.Parse(await AskRawBytes(Server, Query));


    private static async Task<Byte[]> AskRawBytes(HermodServerFixture Server, Byte[] Query)
    {

        var raw = await RawDnsProbe.UdpAsync(Server.UdpPort, Query);

        Assert.That(raw, Is.Not.Null, "§5.2 wants an answer, not silence");

        return raw!;

    }


    /// <summary>
    /// The TSIG RDATA of a message, read here rather than with Hermod's own parser:
    /// the point is what went out on the wire, and a reader that shared the writer's
    /// mistakes would agree with them.
    /// </summary>
    /// <remarks>
    /// Layout after the algorithm name, which §4.2 says is never compressed:
    /// Time Signed (6), Fudge (2), MAC Size (2), MAC, Original ID (2),
    /// Error (2), Other Len (2), Other Data.
    /// </remarks>
    private static TsigFields TsigOf(RawDnsMessage  Response,
                                     String         Because)
    {

        var record = Response.Additionals.SingleOrDefault(rr => rr.Type == RawDnsType.TSIG);

        Assert.That(record, Is.Not.Null, $"{Because} must be answered with a TSIG of its own");

        var data      = record!.Rdata;
        var offset    = 0;
        var algorithm = new List<String>();

        while (offset < data.Length && data[offset] != 0)
        {
            algorithm.Add(System.Text.Encoding.ASCII.GetString(data, offset + 1, data[offset]));
            offset += data[offset] + 1;
        }

        offset += 1;

        var timeSigned = 0UL;
        for (var i = 0; i < 6; i++)
            timeSigned = (timeSigned << 8) | data[offset + i];
        offset += 6;

        var fudge      = (UInt16) ((data[offset] << 8) | data[offset + 1]);
        offset += 2;

        var macSize    = (data[offset] << 8) | data[offset + 1];
        offset += 2;

        var mac        = data[offset..(offset + macSize)];
        offset += macSize;

        var originalId = (UInt16) ((data[offset] << 8) | data[offset + 1]);
        offset += 2;

        var error      = (UInt16) ((data[offset] << 8) | data[offset + 1]);
        offset += 2;

        var otherLen   = (data[offset] << 8) | data[offset + 1];
        offset += 2;

        var otherData  = data[offset..(offset + otherLen)];

        // The record's own start: its RDATA offset back over the length field, the
        // TTL, the class, the type and the owner name.
        var start      = record.RdataOffset - (record.Name.WireLength + 2 + 2 + 4 + 2);

        return new TsigFields($"{String.Join('.', record.Name.Canonical)}.",
                              $"{String.Join('.', algorithm)}.",
                              timeSigned,
                              fudge,
                              macSize,
                              mac,
                              originalId,
                              error,
                              otherLen,
                              otherData,
                              start);

    }


    /// <summary>The MAC a message we built carries, so a reply can be checked against it.</summary>
    private static Byte[] MacOf(Byte[] Message, String Because)
        => TsigOf(RawDnsReader.Parse(Message), Because).MAC;


    /// <summary>
    /// The MAC RFC 8945 §4.3 requires on a response, assembled here from the
    /// specification: the request's MAC with its length in front (§4.3.1), the reply
    /// with its own TSIG record removed and ARCOUNT put back (§4.3.2), then the TSIG
    /// variables in the fixed order of §4.3.3.
    /// </summary>
    private static Byte[] ExpectedResponseMac(Byte[]      ResponseWire,
                                              TsigFields  Tsig,
                                              Byte[]      RequestMac)
    {

        // What the MAC covered: everything before the TSIG record, with ARCOUNT no
        // longer counting it.
        var covered = ResponseWire[..Tsig.RecordStart];

        Assert.That(covered, Has.Length.GreaterThanOrEqualTo(12), "a DNS message is at least a header");

        var arCount = (covered[10] << 8) | covered[11];

        Assert.That(arCount, Is.GreaterThan(0), "the TSIG record is counted in ARCOUNT on the wire");

        covered[10] = (Byte) ((arCount - 1) >> 8);
        covered[11] = (Byte) ((arCount - 1) & 0xFF);

        var input   = new List<Byte>();

        input.AddRange(BigEndian16((UInt16) RequestMac.Length));
        input.AddRange(RequestMac);
        input.AddRange(covered);

        input.AddRange(CanonicalWire(Tsig.Owner));
        input.AddRange([0x00, 0xFF]);                                    // CLASS = ANY
        input.AddRange([0x00, 0x00, 0x00, 0x00]);                        // TTL   = 0
        input.AddRange(CanonicalWire(Tsig.Algorithm));

        input.AddRange(BigEndian16((UInt16) ((Tsig.TimeSigned >> 32) & 0xFFFF)));
        input.AddRange(BigEndian32((UInt32) ( Tsig.TimeSigned        & 0xFFFFFFFF)));
        input.AddRange(BigEndian16(Tsig.Fudge));
        input.AddRange(BigEndian16(Tsig.Error));
        input.AddRange(BigEndian16((UInt16) Tsig.OtherLen));
        input.AddRange(Tsig.OtherData);

        return System.Security.Cryptography.HMACSHA256.HashData(Secret, input.ToArray());

    }


    /// <summary>A name in the canonical wire form §4.3.3 hashes: lowercase, length-prefixed labels, root octet.</summary>
    private static Byte[] CanonicalWire(String Name)
    {

        var wire = new List<Byte>();

        foreach (var label in Name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            wire.Add((Byte) label.Length);
            wire.AddRange(System.Text.Encoding.ASCII.GetBytes(label.ToLowerInvariant()));
        }

        wire.Add(0);

        return [.. wire];

    }


    private static Byte[] BigEndian16(UInt16 Value)
        => [ (Byte) (Value >> 8), (Byte) (Value & 0xFF) ];

    private static Byte[] BigEndian32(UInt32 Value)
        => [ (Byte) (Value >> 24), (Byte) ((Value >> 16) & 0xFF),
             (Byte) ((Value >> 8) & 0xFF), (Byte) (Value & 0xFF) ];

    #endregion

}

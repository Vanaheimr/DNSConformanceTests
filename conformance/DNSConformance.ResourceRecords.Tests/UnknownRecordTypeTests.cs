using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 3597 — handling of unknown DNS resource record types.
/// </summary>
/// <remarks>
/// <para>
/// The RFC is short and its claim is narrow: a record whose TYPE this build has
/// no parser for is still a record. Its outer shape — owner name, TYPE, CLASS,
/// TTL, RDLENGTH — is the same as every other record's, so it can be read,
/// stored, compared, served and written back out with the RDATA never once being
/// interpreted.
/// </para>
/// <para>
/// The failure mode this guards against is not "the record is missing". A parser
/// that gives up on a type still has to step over RDLENGTH octets to reach the
/// next record, and one that returns without doing so leaves the reader inside
/// the record it refused — so the cost of one unknown type is the rest of the
/// message, and it is paid by records the parser knows perfectly well.
/// </para>
/// <para>
/// The wire images are built and read by the independent RawDns codec, so what
/// Hermod writes is checked by a parser that shares no code with it.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "3597")]
public class UnknownRecordTypeTests
{

    /// <summary>A code from the IANA private-use range, which will never be allocated.</summary>
    private const UInt16 PrivateType = 65280;

    private static readonly Byte[] HeaderWithThreeAnswers =
        [0, 0,  0x84, 0,  0, 0,  0, 3,  0, 0,  0, 0];


    #region §2 — the record is read, not skipped

    #region Unknown_Type_Is_Read_As_Opaque_Data()

    [Test]
    [Property("RFC", "3597 §2")]
    public void Unknown_Type_Is_Read_As_Opaque_Data()
    {

        var rdata  = Bytes.FromHex("deadbeef");

        var wire   = new RawDnsWriter().
                         RR("x.example.", PrivateType, RawDnsClass.IN, 300, rdata).
                         ToArray();

        var record = DNSInfo.ReadResourceRecord(new MemoryStream(wire));

        Assert.That(record, Is.Not.Null,
                    "RFC 3597 §2 has no case in which an unknown type is dropped: the record's " +
                    "outer fields are as readable as any other record's.");

        Assert.Multiple(() => {

            Assert.That((UInt16) record!.Type,          Is.EqualTo(PrivateType));
            Assert.That(record.Class,                   Is.EqualTo(DNSQueryClasses.IN));
            Assert.That(record.TimeToLive.TotalSeconds, Is.EqualTo(300));
            Assert.That(record.DomainName.ToString(),   Is.EqualTo("x.example."));

            Assert.That(record, Is.InstanceOf<UnknownRecord>());
            Assert.That(((UnknownRecord) record!).RData, Is.EqualTo(rdata),
                        "the RDATA must arrive exactly as sent — there is nothing here to interpret it with.");

        });

    }

    #endregion

    #region An_Unknown_Type_Does_Not_Cost_The_Records_Behind_It()

    [Test]
    [Property("RFC", "3597 §2")]
    public void An_Unknown_Type_Does_Not_Cost_The_Records_Behind_It()
    {

        // The unknown record sits in the middle on purpose. RDLENGTH is what
        // makes it steppable-over, and a reader that returns before consuming it
        // resumes inside this record: the next owner name is read out of this
        // record's CLASS field, and everything after that is guesswork.
        var wire = new RawDnsWriter().
                       Bytes(HeaderWithThreeAnswers).
                       RR("a.example.", RawDnsType.A, RawDnsClass.IN, 300, RawDnsWriter.IPv4("192.0.2.1")).
                       RR("x.example.", PrivateType,  RawDnsClass.IN, 300, Bytes.FromHex("deadbeef")).
                       RR("b.example.", RawDnsType.A, RawDnsClass.IN, 300, RawDnsWriter.IPv4("192.0.2.2")).
                       ToArray();

        var stream  = new MemoryStream(wire);
        stream.Position = 12;

        var records = new List<IDNSResourceRecord?>();

        Assert.That(
            () => {
                for (var i = 0; i < 3; i++)
                    records.Add(DNSInfo.ReadResourceRecord(stream));
            },
            Throws.Nothing,
            () => "reading past an unknown type threw, which means the reader was left inside it:\n" + Bytes.Dump(wire)
        );

        Assert.Multiple(() => {

            Assert.That(records, Has.Count.EqualTo(3));
            Assert.That(records.Any(record => record is null), Is.False, "no record in this message is unreadable");

            Assert.That(records[0]!.Type,             Is.EqualTo(DNSResourceRecordTypes.A));
            Assert.That((UInt16) records[1]!.Type,    Is.EqualTo(PrivateType));

            // The one that matters: a known record, behind an unknown one,
            // still read correctly.
            Assert.That(records[2]!.Type,             Is.EqualTo(DNSResourceRecordTypes.A));
            Assert.That(records[2]!.DomainName.ToString(), Is.EqualTo("b.example."),
                        "the record behind the unknown type must be read from its own bytes, " +
                        "not from wherever the previous record left the reader.");

            Assert.That(stream.Position, Is.EqualTo(wire.Length),
                        "and the reader must end exactly at the end of the message");

        });

    }

    #endregion

    #region A_Truncated_Rdata_Is_A_Malformed_Message()

    [Test]
    [Property("RFC", "3597 §2")]
    public void A_Truncated_Rdata_Is_A_Malformed_Message()
    {

        // RDLENGTH says eight octets; four are present. "Unknown type" and
        // "message ends mid-record" are different faults and only the second one
        // is the sender's doing — reporting the second as the first would let a
        // truncated message pass as a record with short RDATA.
        var wire = new RawDnsWriter().
                       Name("x.example.").
                       U16(PrivateType).
                       U16(RawDnsClass.IN).
                       U32(300).
                       U16(8).
                       Hex("deadbeef").
                       ToArray();

        Assert.That(
            () => DNSInfo.ReadResourceRecord(new MemoryStream(wire)),
            Throws.InstanceOf<InvalidDataException>()
        );

    }

    #endregion

    #endregion

    #region §3 — the record comes out the way it went in

    #region Unknown_Type_Survives_A_Wire_Round_Trip()

    [Test]
    [Property("RFC", "3597 §3")]
    public void Unknown_Type_Survives_A_Wire_Round_Trip()
    {

        var rdata    = Bytes.FromHex("00ff10204080ffee");

        var original = new UnknownRecord(
                           DNSServiceName.Parse("x.example."),
                           (DNSResourceRecordTypes) PrivateType,
                           DNSQueryClasses.IN,
                           TimeSpan.FromSeconds(300),
                           rdata
                       );

        var encoded  = RRWire.Encode(original);

        Assert.Multiple(() => {

            Assert.That(encoded.Type,  Is.EqualTo(PrivateType));
            Assert.That(encoded.Class, Is.EqualTo(RawDnsClass.IN));
            Assert.That(encoded.Ttl,   Is.EqualTo(300));
            Assert.That(encoded.Rdata, Is.EqualTo(rdata));

        });

    }

    #endregion

    #region Rdata_That_Reads_As_A_Compression_Pointer_Is_Left_Alone()

    [Test]
    [Property("RFC", "3597 §3")]
    [Property("RFC", "3597 §4")]
    public void Rdata_That_Reads_As_A_Compression_Pointer_Is_Left_Alone()
    {

        // 0xC00C is a valid RFC 1035 §4.1.4 pointer to offset 12. In the RDATA of
        // an unknown type it is two octets and nothing else: §4 forbids putting a
        // pointer there in the first place, so a receiver that expands one is
        // acting on a structure the sender was not allowed to create — and it
        // cannot tell the difference between that and two octets of payload
        // which happen to have those values.
        var rdata  = new Byte[] { 0xC0, 0x0C };

        var wire   = new RawDnsWriter().
                         Bytes([0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0]).
                         Question("victim.example.", PrivateType).
                         RR("x.example.", PrivateType, RawDnsClass.IN, 300, rdata).
                         ToArray();

        var stream = new MemoryStream(wire);
        stream.Position = 12 + new RawDnsWriter().Question("victim.example.", PrivateType).ToArray().Length;

        var record = DNSInfo.ReadResourceRecord(stream) as UnknownRecord;

        Assert.That(record, Is.Not.Null);

        Assert.That(record!.RData, Is.EqualTo(rdata),
                    "the pointer must survive as two octets — expanding it would replace the " +
                    "payload with 'victim.example.' and change RDLENGTH from 2 to 16.");

        // And it must go back out unchanged. Re-emitting an expanded name here
        // would be worse than reading it wrong, because the record would then be
        // wrong for everyone downstream.
        Assert.That(RRWire.Encode(record).Rdata, Is.EqualTo(rdata));

    }

    #endregion

    #region Serialized_Unknown_Rdata_Carries_No_Pointer()

    [Test]
    [Property("RFC", "3597 §4")]
    public void Serialized_Unknown_Rdata_Carries_No_Pointer()
    {

        // The name inside the RDATA is also the question name, so it is a
        // compression candidate at offset 12 — and an encoder that treated the
        // RDATA as a name would take the offer.
        var embedded = RawDnsWriter.NameBytes("target.example.");

        var packet   = new DNSPacket(
                           0x3597,
                           DNSQueryResponse.Response,
                           0, true, false, false, false,
                           DNSResponseCodes.NoError,
                           [ new DNSQuestion(DNSServiceName.Parse("target.example."), (DNSResourceRecordTypes) PrivateType, DNSQueryClasses.IN) ],
                           [
                               new UnknownRecord(
                                   DNSServiceName.Parse("x.example."),
                                   (DNSResourceRecordTypes) PrivateType,
                                   DNSQueryClasses.IN,
                                   TimeSpan.FromSeconds(300),
                                   embedded
                               )
                           ],
                           [],
                           []
                       );

        var ms = new MemoryStream();
        packet.Serialize(ms, UseCompression: true, CompressionOffsets: []);

        var decoded = RawDnsReader.Parse(ms.ToArray());

        Assert.That(decoded.Answers.Single().Rdata, Is.EqualTo(embedded),
                    "RFC 3597 §4: a name inside the RDATA of a type that is not well-known must go " +
                    "out in full, because a receiver treating the RDATA as opaque cannot expand a pointer.");

    }

    #endregion

    #endregion

    #region §5 — the presentation format

    #region Generic_Rdata_Is_Read_From_The_Presentation_Format()

    [TestCase(@"\# 4 deadbeef",           "deadbeef",     TestName = "Generic_Rdata__one_word")]
    [TestCase(@"\# 6 dead beef cafe",     "deadbeefcafe", TestName = "Generic_Rdata__several_words")]
    [TestCase(@"\# 0",                    "",             TestName = "Generic_Rdata__zero_length")]
    [TestCase(@"\# 4 DEADBEEF",           "deadbeef",     TestName = "Generic_Rdata__upper_case_hex")]
    [Property("RFC", "3597 §5")]
    public void Generic_Rdata_Is_Read_From_The_Presentation_Format(String RData, String ExpectedHex)
    {

        var parsed = ADNSResourceRecord.ParseZoneFileString($"x.example. 300 IN TYPE{PrivateType} {RData}");

        Assert.Multiple(() => {

            Assert.That((UInt16) parsed.Type,           Is.EqualTo(PrivateType));
            Assert.That(parsed.TimeToLive.TotalSeconds, Is.EqualTo(300));
            Assert.That(parsed, Is.InstanceOf<UnknownRecord>());
            Assert.That(((UnknownRecord) parsed).RData, Is.EqualTo(Bytes.FromHex(ExpectedHex)));

        });

    }

    #endregion

    #region Generic_Rdata_That_Contradicts_Itself_Is_Refused()

    [TestCase(@"\# 5 deadbeef",   TestName = "Generic_Rdata_refused__length_too_long")]
    [TestCase(@"\# 3 deadbeef",   TestName = "Generic_Rdata_refused__length_too_short")]
    [TestCase(@"\# 3 deadbef",    TestName = "Generic_Rdata_refused__odd_number_of_digits")]
    [TestCase(@"\# 2 dead ef0",   TestName = "Generic_Rdata_refused__odd_word")]
    [TestCase(@"\# 2 zzzz",       TestName = "Generic_Rdata_refused__not_hexadecimal")]
    [TestCase(@"\#",              TestName = "Generic_Rdata_refused__no_length")]
    [Property("RFC", "3597 §5")]
    public void Generic_Rdata_That_Contradicts_Itself_Is_Refused(String RData)
    {

        // §5 writes the length out as well as implying it, so the two can
        // disagree. Trusting either one over the other silently reshapes the
        // record — which is exactly what a zone file must never do quietly.
        Assert.That(
            ADNSResourceRecord.TryParseZoneFileString($"x.example. 300 IN TYPE{PrivateType} {RData}", out _, out _),
            Is.False
        );

    }

    #endregion

    #region Generic_Rdata_Of_A_Known_Type_Becomes_That_Type()

    [Test]
    [Property("RFC", "3597 §5")]
    public void Generic_Rdata_Of_A_Known_Type_Becomes_That_Type()
    {

        // §5, last paragraph: the generic form may be used for a type that *is*
        // known, and then "all further processing by the server MUST treat it as
        // a known type". So this line is an A record written the long way, not an
        // opaque blob that happens to be four octets.
        var parsed = ADNSResourceRecord.ParseZoneFileString(@"x.example. 300 IN TYPE1 \# 4 c0000201");

        Assert.Multiple(() => {

            Assert.That(parsed,      Is.InstanceOf<A>());
            Assert.That(parsed,      Is.Not.InstanceOf<UnknownRecord>(),
                        "a type with a parser must not be left opaque just because it was written generically");
            Assert.That(parsed.Type, Is.EqualTo(DNSResourceRecordTypes.A));
            Assert.That(((A) parsed).IPv4Address.ToString(), Is.EqualTo("192.0.2.1"));

        });

    }

    #endregion

    #region Generic_Rdata_That_The_Known_Type_Rejects_Is_Refused()

    [Test]
    [Property("RFC", "3597 §5")]
    public void Generic_Rdata_That_The_Known_Type_Rejects_Is_Refused()
    {

        // Three octets are not an IPv4 address. Because §5 requires the record to
        // be treated as an A, there is no second reading in which this line is
        // acceptable — it cannot quietly become opaque.
        Assert.That(
            ADNSResourceRecord.TryParseZoneFileString(@"x.example. 300 IN TYPE1 \# 3 c00002", out _, out _),
            Is.False
        );

    }

    #endregion

    #region An_Unknown_Type_Is_Written_As_TYPEnnn()

    [Test]
    [Property("RFC", "3597 §5")]
    public void An_Unknown_Type_Is_Written_As_TYPEnnn()
    {

        var record = new UnknownRecord(
                         DNSServiceName.Parse("x.example."),
                         (DNSResourceRecordTypes) PrivateType,
                         DNSQueryClasses.IN,
                         TimeSpan.FromSeconds(300),
                         Bytes.FromHex("deadbeef")
                     );

        var line = record.ToZoneFileString();

        Assert.Multiple(() => {

            Assert.That(line, Does.Contain($"TYPE{PrivateType}"),
                        "the bare number that an undefined enum renders as is not a substitute: §5 is " +
                        "precisely the rule that says a bare number in this position is a TTL.");

            Assert.That(line, Does.Contain(@"\# 4 deadbeef"));

        });

        // And what it wrote must come back.
        var reparsed = ADNSResourceRecord.ParseZoneFileString(line);

        Assert.Multiple(() => {
            Assert.That((UInt16) reparsed.Type,           Is.EqualTo(PrivateType));
            Assert.That(reparsed.TimeToLive.TotalSeconds, Is.EqualTo(300));
            Assert.That(((UnknownRecord) reparsed).RData, Is.EqualTo(record.RData));
        });

    }

    #endregion

    #region An_Unknown_Class_Is_Written_And_Read_As_CLASSnn()

    [Test]
    [Property("RFC", "3597 §5")]
    public void An_Unknown_Class_Is_Written_And_Read_As_CLASSnn()
    {

        var parsed = ADNSResourceRecord.ParseZoneFileString($@"x.example. 300 CLASS42 TYPE{PrivateType} \# 2 0102");

        Assert.Multiple(() => {
            Assert.That((UInt16) parsed.Class,          Is.EqualTo(42));
            Assert.That(parsed.TimeToLive.TotalSeconds, Is.EqualTo(300));
        });

        Assert.That(((ADNSResourceRecord) parsed).ToZoneFileString(), Does.Contain("CLASS42"));

    }

    #endregion

    #region A_Bare_Decimal_Is_A_Ttl_And_Not_A_Class()

    [TestCase("x.example. 3600 IN A 192.0.2.1", TestName = "Bare_decimal_is_a_TTL__ttl_before_class")]
    [TestCase("x.example. IN 3600 A 192.0.2.1", TestName = "Bare_decimal_is_a_TTL__class_before_ttl")]
    [Property("RFC", "3597 §5")]
    public void A_Bare_Decimal_Is_A_Ttl_And_Not_A_Class(String Line)
    {

        // This is what §5 gives as the reason for the TYPEnnn/CLASSnn convention:
        // it is what lets "[<TTL>] [<class>]" and "[<class>] [<TTL>]" both be read
        // without guessing. A parser that also accepts a bare decimal as a class
        // has thrown that away — it reads 3600 as class 3600, the next token
        // overwrites it with IN, and the record silently ends up with whatever
        // default TTL the caller passed in.
        var parsed = ADNSResourceRecord.ParseZoneFileString(Line, DefaultTimeToLive: TimeSpan.FromSeconds(99));

        Assert.Multiple(() => {

            Assert.That(parsed.TimeToLive.TotalSeconds, Is.EqualTo(3600),
                        "the bare decimal is the TTL");

            Assert.That(parsed.Class, Is.EqualTo(DNSQueryClasses.IN));
            Assert.That(parsed.Type,  Is.EqualTo(DNSResourceRecordTypes.A));

        });

    }

    #endregion

    #endregion

    #region §6 — equality is an octet comparison

    #region Unknown_Rdata_Is_Compared_As_Octets()

    [Test]
    [Property("RFC", "3597 §6")]
    public void Unknown_Rdata_Is_Compared_As_Octets()
    {

        // The two RDATAs differ only in the case of ASCII letters. If the octets
        // happened to be a domain name, RFC 1035 §2.3.3 would call them equal —
        // but nothing in an unknown type says which octets are a name, and a
        // comparison that guesses makes two different records compare equal.
        var lower = new UnknownRecord(DNSServiceName.Parse("x.example."), (DNSResourceRecordTypes) PrivateType,
                                      DNSQueryClasses.IN, TimeSpan.FromSeconds(300), "wwwexample "u8.ToArray());

        var upper = new UnknownRecord(DNSServiceName.Parse("x.example."), (DNSResourceRecordTypes) PrivateType,
                                      DNSQueryClasses.IN, TimeSpan.FromSeconds(300), "WWWEXAMPLE "u8.ToArray());

        var twin  = new UnknownRecord(DNSServiceName.Parse("x.example."), (DNSResourceRecordTypes) PrivateType,
                                      DNSQueryClasses.IN, TimeSpan.FromSeconds(300), "wwwexample "u8.ToArray());

        Assert.Multiple(() => {

            Assert.That(lower, Is.EqualTo(twin),     "identical octets are the same RDATA");
            Assert.That(lower, Is.Not.EqualTo(upper), "differing octets are different RDATA, whatever they might have meant");

            Assert.That(lower.GetHashCode(), Is.EqualTo(twin.GetHashCode()));

        });

    }

    #endregion

    #region Different_Type_Codes_Are_Different_Records()

    [Test]
    [Property("RFC", "3597 §6")]
    public void Different_Type_Codes_Are_Different_Records()
    {

        var rdata = Bytes.FromHex("deadbeef");

        var one   = new UnknownRecord(DNSServiceName.Parse("x.example."), (DNSResourceRecordTypes) PrivateType,
                                      DNSQueryClasses.IN, TimeSpan.FromSeconds(300), rdata);

        var other = new UnknownRecord(DNSServiceName.Parse("x.example."), (DNSResourceRecordTypes) (PrivateType + 1),
                                      DNSQueryClasses.IN, TimeSpan.FromSeconds(300), rdata);

        // Same octets, different type. An RRset is (name, class, type) — a
        // comparison that only looked at the RDATA would merge two RRsets.
        Assert.That(one, Is.Not.EqualTo(other));

    }

    #endregion

    #endregion

}

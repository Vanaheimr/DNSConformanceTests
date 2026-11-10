using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 2230 — KX, the key exchanger record: MX's shape, a preference and a
/// name, under rules MX does not have.
/// </summary>
/// <remarks>
/// <para>
/// §3.1 forbids compressing the exchanger, which RFC 1035 allows for an MX; that
/// half is asserted with the other post-1035 types in <c>RdataCompressionTests</c>,
/// where a message offers the name for compression. What is asserted here is
/// the record itself: the presentation form against BIND's, the wire layout,
/// and what becomes of RDATA that is not a KX — kept as the octets that
/// arrived, never completed or cut to fit.
/// </para>
/// <para>
/// Every expected string is <c>named-compilezone</c>'s output for the same line.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "2230")]
public class KxTests
{

    #region Data

    private static IDNSResourceRecord Read(String Line)
    {

        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");

        return record!;

    }

    private static String RDataText(IDNSResourceRecord Record)
        => Record.ToZoneFileString().Split(" KX ")[1].Trim();

    private static String Hex(Byte[] Bytes)
        => Convert.ToHexString(Bytes).ToLowerInvariant();

    #endregion


    #region The_Presentation_Form_Is_Read_And_Written_As_Bind_Writes_It(Written, Expected)

    [Test]
    [Property("RFC", "2230 §3")]
    // The exchanger keeps its case, as BIND keeps it: RFC 4343 makes the case
    // insignificant for comparison and RFC 1035 §2.3.3 asks for it to be kept.
    [TestCase("10 Mail.Example.",     "10 Mail.Example.")]
    // §3.1 gives the preference sixteen bits: both ends of them.
    [TestCase("0 kx.example.",        "0 kx.example.")]
    [TestCase("65535 kx.example.",    "65535 kx.example.")]
    // The root as exchanger, which BIND writes back as itself.
    [TestCase("10 .",                 "10 .")]
    public void The_Presentation_Form_Is_Read_And_Written_As_Bind_Writes_It(String Written, String Expected)
    {

        var record = Read($"probe.example. 300 IN KX {Written}");

        Assert.Multiple(() => {
            Assert.That(record,            Is.InstanceOf<KX>());
            Assert.That(RDataText(record), Is.EqualTo(Expected));
        });

    }

    #endregion

    #region What_Is_Not_A_KX_Is_Refused(Written)

    [Test]
    [Property("RFC", "2230 §3")]
    // One past sixteen bits, which BIND refuses as "out of range".
    [TestCase("65536 mail.example.")]
    // No exchanger, which BIND refuses as "unexpected end of input".
    [TestCase("10")]
    // "a non-negative integer": no sign, no letters, nothing after the name.
    [TestCase("-1 mail.example.")]
    [TestCase("ten mail.example.")]
    [TestCase("10 mail.example. extra")]
    public void What_Is_Not_A_KX_Is_Refused(String Written)
    {

        Assert.That(ADNSResourceRecord.TryParseZoneFileString($"probe.example. 300 IN KX {Written}", out _, out _),
                    Is.False,
                    $"'{Written}' is not the RDATA of a KX");

    }

    #endregion


    #region The_Wire_Form_Is_A_Preference_And_An_Uncompressed_Name()

    [Test]
    [Property("RFC", "2230 §3.1")]
    public void The_Wire_Form_Is_A_Preference_And_An_Uncompressed_Name()
    {

        var record = Read("probe.example. 300 IN KX 10 Mail.Example.");

        // 000a, then 04 'M' 'a' 'i' 'l' 07 'E' 'x' 'a' 'm' 'p' 'l' 'e' 00 — the
        // capitals included, because the case of a name is carried on the wire.
        Assert.That(Hex(ADNSResourceRecord.RDataOf(record)),
                    Is.EqualTo("000a" + "044d61696c" + "074578616d706c65" + "00"));

    }

    #endregion

    #region The_Generic_Form_Reads_As_A_Typed_Record()

    [Test]
    [Property("RFC", "3597 §5")]
    public void The_Generic_Form_Reads_As_A_Typed_Record()
    {

        // RFC 3597 §5's generic form reaches the wire constructor, which nothing
        // in the presentation form does. BIND reads these eight octets as
        // "10 mail.".
        var record = ADNSResourceRecord.ParseZoneFileString(@"probe.example. 300 IN KX \# 8 000a046d61696c00") as KX;

        Assert.That(record, Is.Not.Null);

        Assert.Multiple(() => {
            Assert.That(record!.Preference,     Is.EqualTo(10));
            Assert.That(record. Exchanger.FullName, Is.EqualTo("mail."));
            Assert.That(record. UnparsedRData,  Is.Null);
            Assert.That(RDataText(record),      Is.EqualTo("10 mail."));
        });

    }

    #endregion

    #region Rdata_That_Is_Not_A_KX_Is_Kept_As_It_Arrived(Hex)

    [Test]
    [Property("RFC", "3597 §2")]
    // A compression pointer: §3.1 forbids one, and a pointer read out of the
    // RDATA alone points nowhere. BIND: "disallowed".
    [TestCase("000ac00c",             TestName = "Kx_kept__compressed_exchanger")]
    // A preference and no name. BIND: "unexpected end of input".
    [TestCase("000a",                 TestName = "Kx_kept__no_exchanger")]
    // A name that runs past the RDATA.
    [TestCase("000a046d6169",         TestName = "Kx_kept__exchanger_runs_off_the_end")]
    // A name that ends before the RDATA does. BIND: "extra input data".
    [TestCase("000a046d61696c0000",   TestName = "Kx_kept__octets_after_the_exchanger")]
    public void Rdata_That_Is_Not_A_KX_Is_Kept_As_It_Arrived(String RDataHex)
    {

        // RFC 3597 §2: a record the reader cannot make sense of is still a
        // record. What it must not do is make sense of it anyway — a preference
        // of 10 and an exchanger cut short, or followed by octets nobody reads,
        // are records nobody sent. So the octets are kept, written back as they
        // came, and shown in the generic form, which is the one spelling that
        // claims nothing about them.
        var rdata  = Convert.FromHexString(RDataHex);
        var record = ADNSResourceRecord.ParseZoneFileString($@"probe.example. 300 IN KX \# {rdata.Length} {RDataHex}") as KX;

        Assert.That(record, Is.Not.Null, "the record must survive RDATA it cannot read");

        Assert.Multiple(() => {

            Assert.That(record!.UnparsedRData, Is.EqualTo(rdata));

            Assert.That(Hex(ADNSResourceRecord.RDataOf(record)), Is.EqualTo(RDataHex),
                        "and must write back exactly the octets it was given");

            Assert.That(RDataText(record), Is.EqualTo($@"\# {rdata.Length} {RDataHex}"));

        });

    }

    #endregion

    #region A_Kx_It_Cannot_Read_Does_Not_Cost_The_Record_Behind_It()

    [Test]
    [Property("RFC", "3597 §2")]
    public void A_Kx_It_Cannot_Read_Does_Not_Cost_The_Record_Behind_It()
    {

        // The reason the RDATA is read as a block of RDLENGTH octets rather than
        // field by field off the message: a name read off the message would run
        // on into the next record, and finding 21 was exactly that — one record
        // the parser did not understand, and every record behind it lost.
        var wire = new RawDnsWriter().
                       RR("probe.example.", RawDnsType.KX, RawDnsClass.IN, 300, Convert.FromHexString("000a046d6169")).
                       RR("next.example.",  RawDnsType.A,  RawDnsClass.IN, 300, [ 192, 0, 2, 1 ]).
                       ToArray();

        var stream = new MemoryStream(wire);
        var first  = DNSInfo.ReadResourceRecord(stream);
        var second = DNSInfo.ReadResourceRecord(stream);

        Assert.Multiple(() => {
            Assert.That(first,                 Is.InstanceOf<KX>());
            Assert.That(second,                Is.InstanceOf<A>());
            Assert.That(second?.DomainName.FullName.TrimEnd('.'), Is.EqualTo("next.example"));
            Assert.That(stream.Position,       Is.EqualTo(wire.Length));
        });

    }

    #endregion


    #region The_Mnemonic_Is_Known_In_Both_Directions()

    [Test]
    public void The_Mnemonic_Is_Known_In_Both_Directions()
    {

        Assert.Multiple(() => {
            Assert.That(ADNSResourceRecord.TypeName((DNSResourceRecordTypes) 36), Is.EqualTo("KX"));
            Assert.That((UInt16) DNSResourceRecordTypes.KX, Is.EqualTo(36), "RFC 2230 §3 assigned KX 36");
        });

    }

    #endregion

}

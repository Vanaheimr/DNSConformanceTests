using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 6742 — the four record types of the Identifier-Locator Network Protocol:
/// NID, L32, L64 and LP.
/// </summary>
/// <remarks>
/// <para>
/// Three of them are a preference and a fixed number of octets, and their
/// presentation forms borrow the A and AAAA syntax with a twist each: a NID or
/// L64 is four groups of an IPv6 address and must never be written with "::",
/// and an L32 is a dotted quad whose RFC got its own examples wrong (Erratum
/// 3413). The fourth, LP, is a preference and a name, uncompressed, that must
/// not be its own owner.
/// </para>
/// <para>
/// Every expected string is <c>named-compilezone</c>'s output for the same line —
/// which, for a NID and an L64, drops the leading zeros the RFC's examples carry.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "6742")]
public class IlnpRecordTests
{

    #region Data

    private static IDNSResourceRecord Read(String Line)
    {

        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");

        return record!;

    }

    private static Boolean Refused(String Line)
        => !ADNSResourceRecord.TryParseZoneFileString(Line, out _, out _);

    private static String RDataText(IDNSResourceRecord Record)
        => Record.ToZoneFileString().Split($" {ADNSResourceRecord.TypeName(Record.Type)} ")[1].Trim();

    private static String Hex(Byte[] Bytes)
        => Convert.ToHexString(Bytes).ToLowerInvariant();

    #endregion


    #region NID

    [Test]
    [Property("RFC", "6742 §2.1.3")]
    // The three examples of §2.1.3, as BIND writes them back: each group in the
    // AAAA syntax, so without its leading zeros (RFC 5952 §4.1).
    [TestCase("10 0014:4fff:ff20:ee64",  "10 14:4fff:ff20:ee64",  TestName = "Nid_example__host1_10")]
    [TestCase("20 0015:5fff:ff21:ee65",  "20 15:5fff:ff21:ee65",  TestName = "Nid_example__host1_20")]
    [TestCase("10 0016:6fff:ff22:ee66",  "10 16:6fff:ff22:ee66",  TestName = "Nid_example__host2_10")]
    // Capitals in, lowercase out (RFC 5952 §4.3).
    [TestCase("10 0014:4FFF:FF20:EE64",  "10 14:4fff:ff20:ee64",  TestName = "Nid__capitals")]
    // A group of one digit is a group.
    [TestCase("10 14:4fff:ff20:ee64",    "10 14:4fff:ff20:ee64",  TestName = "Nid__short_group")]
    // All zero, and all ones: no group shrinks to nothing and none to "::".
    [TestCase("10 0:0:0:0",              "10 0:0:0:0",            TestName = "Nid__all_zero")]
    [TestCase("65535 FFFF:FFFF:FFFF:FFFF", "65535 ffff:ffff:ffff:ffff", TestName = "Nid__all_ones")]
    public void A_Nid_Is_Read_And_Written_As_Bind_Writes_It(String Written, String Expected)
    {

        var record = Read($"host1.example.com. 300 IN NID {Written}");

        Assert.Multiple(() => {
            Assert.That(record,            Is.InstanceOf<NID>());
            Assert.That(RDataText(record), Is.EqualTo(Expected));
        });

    }

    [Test]
    [Property("RFC", "6742 §2.1.2")]
    // §2.1.2: the NodeID "MUST NOT be in the 'compressed' format (e.g., using
    // "::")", "because the NID is a 64-bit field". BIND: "syntax error" for all.
    [TestCase("10 0014:4fff::ee64",           TestName = "Nid_refused__compressed")]
    [TestCase("10 ::",                        TestName = "Nid_refused__all_compressed")]
    // Four groups, no more and no fewer.
    [TestCase("10 0014:4fff:ff20",            TestName = "Nid_refused__three_groups")]
    [TestCase("10 0014:4fff:ff20:ee64:0000",  TestName = "Nid_refused__five_groups")]
    // Four digits to a group.
    [TestCase("10 00014:4fff:ff20:ee64",      TestName = "Nid_refused__five_digits")]
    [TestCase("10 0014:4fff:ff20:ee6g",       TestName = "Nid_refused__not_hex")]
    [TestCase("10 0014:4fff:ff20:",           TestName = "Nid_refused__empty_last_group")]
    [TestCase("10 :4fff:ff20:ee64",           TestName = "Nid_refused__empty_first_group")]
    // "a 16-bit unsigned decimal integer". BIND: "out of range".
    [TestCase("65536 0014:4fff:ff20:ee64",    TestName = "Nid_refused__preference_65536")]
    [TestCase("10",                           TestName = "Nid_refused__no_node_id")]
    public void What_Is_Not_A_Nid_Is_Refused(String Written)
    {

        Assert.That(Refused($"host1.example.com. 300 IN NID {Written}"), Is.True,
                    $"'{Written}' is not the RDATA of a NID");

    }

    [Test]
    [Property("RFC", "6742 §2.1.1")]
    public void A_Nid_Is_Ten_Octets_On_The_Wire()
    {

        var record = Read("host1.example.com. 300 IN NID 10 0014:4fff:ff20:ee64") as NID;

        Assert.That(record, Is.Not.Null);

        Assert.Multiple(() => {
            Assert.That(record!.Preference,                      Is.EqualTo(10));
            Assert.That(record. NodeID,                          Is.EqualTo(0x00144fffff20ee64UL));
            Assert.That(Hex(ADNSResourceRecord.RDataOf(record)), Is.EqualTo("000a" + "00144fffff20ee64"));
        });

    }

    #endregion

    #region L64

    [Test]
    [Property("RFC", "6742 §2.3.3")]
    [TestCase("10 2001:0DB8:1140:1000",  "10 2001:db8:1140:1000",  TestName = "L64_example__host1_10")]
    [TestCase("20 2001:0DB8:2140:2000",  "20 2001:db8:2140:2000",  TestName = "L64_example__host1_20")]
    [TestCase("10 2001:0DB8:4140:4000",  "10 2001:db8:4140:4000",  TestName = "L64_example__host2_10")]
    public void An_L64_Is_Read_And_Written_As_Bind_Writes_It(String Written, String Expected)
    {

        var record = Read($"host1.example.com. 300 IN L64 {Written}");

        Assert.Multiple(() => {
            Assert.That(record,            Is.InstanceOf<L64>());
            Assert.That(RDataText(record), Is.EqualTo(Expected));
        });

    }

    [Test]
    [Property("RFC", "6742 §2.3.2")]
    public void An_L64_Is_Never_Written_Compressed()
    {

        // §2.3.2: the "'compressed' display format ... MUST NOT be used", "to
        // avoid confusion with a 128-bit IPv6 address". A run of zero groups is
        // where an AAAA writer would reach for "::", so this is the value that
        // shows whether the L64 writer is an AAAA writer in disguise.
        var record = Read("host1.example.com. 300 IN L64 10 2001:0:0:1000");

        Assert.Multiple(() => {
            Assert.That(RDataText(record), Is.EqualTo("10 2001:0:0:1000"));
            Assert.That(Refused("host1.example.com. 300 IN L64 10 2001:db8::1000"), Is.True,
                        "and is not read compressed either");
        });

    }

    [Test]
    [Property("RFC", "6742 §2.3.1")]
    public void An_L64_Is_Ten_Octets_On_The_Wire()
    {

        var record = Read("host1.example.com. 300 IN L64 10 2001:0DB8:1140:1000") as L64;

        Assert.That(record, Is.Not.Null);

        Assert.Multiple(() => {
            Assert.That(record!.Locator64,                       Is.EqualTo(0x20010db811401000UL));
            Assert.That(Hex(ADNSResourceRecord.RDataOf(record)), Is.EqualTo("000a" + "20010db811401000"));
        });

    }

    #endregion

    #region L32

    [Test]
    [Property("RFC", "6742 §2.2.3")]
    // §2.2.3's examples as Erratum 3413 corrected them, and as BIND writes them.
    [TestCase("10 10.1.2.0",  "10 10.1.2.0",  TestName = "L32_example__host1_10")]
    [TestCase("20 10.1.4.0",  "20 10.1.4.0",  TestName = "L32_example__host1_20")]
    [TestCase("10 10.1.8.0",  "10 10.1.8.0",  TestName = "L32_example__host2_10")]
    [TestCase("0 0.0.0.0",    "0 0.0.0.0",    TestName = "L32__all_zero")]
    public void An_L32_Is_Read_And_Written_As_Bind_Writes_It(String Written, String Expected)
    {

        var record = Read($"host1.example.com. 300 IN L32 {Written}");

        Assert.Multiple(() => {
            Assert.That(record,            Is.InstanceOf<L32>());
            Assert.That(RDataText(record), Is.EqualTo(Expected));
        });

    }

    [Test]
    [Property("RFC", "6742 §2.2.2")]
    // The uncorrected examples. Erratum 3413 (verified) replaced them, because
    // a leading zero is octal to a reader that follows inet_aton. BIND: "bad
    // dotted quad".
    [TestCase("10 10.1.02.0",   TestName = "L32_refused__uncorrected_example_02")]
    [TestCase("20 10.1.04.0",   TestName = "L32_refused__uncorrected_example_04")]
    [TestCase("10 010.1.2.0",   TestName = "L32_refused__leading_zero")]
    // "4 decimal numbers separated by periods".
    [TestCase("10 10.1.2",      TestName = "L32_refused__three_numbers")]
    [TestCase("10 10.1.2.0.0",  TestName = "L32_refused__five_numbers")]
    [TestCase("10 256.1.2.0",   TestName = "L32_refused__number_256")]
    [TestCase("10 10.1.2.x",    TestName = "L32_refused__not_a_number")]
    [TestCase("10 10..2.0",     TestName = "L32_refused__empty_number")]
    public void What_Is_Not_An_L32_Is_Refused(String Written)
    {

        Assert.That(Refused($"host1.example.com. 300 IN L32 {Written}"), Is.True,
                    $"'{Written}' is not the RDATA of an L32");

    }

    [Test]
    [Property("RFC", "6742 §2.2.1")]
    public void An_L32_Is_Six_Octets_On_The_Wire()
    {

        var record = Read("host1.example.com. 300 IN L32 10 10.1.2.0");

        Assert.That(Hex(ADNSResourceRecord.RDataOf(record)), Is.EqualTo("000a" + "0a010200"),
                    "identical on the wire to an A record's ADDRESS, behind the preference");

    }

    #endregion

    #region LP

    [Test]
    [Property("RFC", "6742 §2.4.3")]
    [TestCase("10 l64-subnet1.example.com.",  "10 l64-subnet1.example.com.",  TestName = "Lp_example__subnet1")]
    [TestCase("20 l32-subnet1.example.com.",  "20 l32-subnet1.example.com.",  TestName = "Lp_example__subnet_l32")]
    // The case of the name is kept, as BIND keeps it.
    [TestCase("10 L64-Subnet1.Example.COM.",  "10 L64-Subnet1.Example.COM.",  TestName = "Lp__case_kept")]
    [TestCase("10 .",                         "10 .",                         TestName = "Lp__root")]
    public void An_Lp_Is_Read_And_Written_As_Bind_Writes_It(String Written, String Expected)
    {

        var record = Read($"host1.example.com. 300 IN LP {Written}");

        Assert.Multiple(() => {
            Assert.That(record,            Is.InstanceOf<LP>());
            Assert.That(RDataText(record), Is.EqualTo(Expected));
        });

    }

    [Test]
    [Property("RFC", "6742 §2.4.1.2")]
    // §2.4.1.2: the FQDN "MUST NOT have the same value as the owner name of the
    // LP RR instance" — a locator pointer to itself, which a resolver following
    // it would follow for ever. BIND accepts such a line without a word; Hermod's
    // reader is where the zone is written down, and refuses it.
    [TestCase("10 host1.example.com.",  TestName = "Lp_refused__points_at_its_owner")]
    // The same name, by RFC 4343, in other capitals.
    [TestCase("10 HOST1.Example.com.",  TestName = "Lp_refused__points_at_its_owner_in_capitals")]
    [TestCase("65536 l64-subnet1.example.com.", TestName = "Lp_refused__preference_65536")]
    [TestCase("10",                     TestName = "Lp_refused__no_fqdn")]
    public void What_Is_Not_An_Lp_Is_Refused(String Written)
    {

        Assert.That(Refused($"host1.example.com. 300 IN LP {Written}"), Is.True,
                    $"'{Written}' is not the RDATA of an LP at host1.example.com.");

    }

    [Test]
    [Property("RFC", "6742 §2.4.1")]
    public void An_Lp_Is_A_Preference_And_An_Uncompressed_Name_On_The_Wire()
    {

        var record = Read("host1.example.com. 300 IN LP 10 L64.example.") as LP;

        Assert.That(record, Is.Not.Null);

        Assert.Multiple(() => {
            Assert.That(record!.FQDN.FullName,                   Is.EqualTo("L64.example."));
            Assert.That(Hex(ADNSResourceRecord.RDataOf(record)), Is.EqualTo("000a" + "034c3634" + "076578616d706c65" + "00"));
        });

    }

    #endregion


    #region Rdata_That_Is_Not_The_Type_It_Claims_Is_Kept_As_It_Arrived(Type, Hex)

    [Test]
    [Property("RFC", "3597 §2")]
    // A NID of nine octets and of eleven. BIND: FORMERR for both.
    [TestCase("NID", "000a00144fffff20ee",       TestName = "Nid_kept__nine_octets")]
    [TestCase("NID", "000a00144fffff20ee6400",   TestName = "Nid_kept__eleven_octets")]
    [TestCase("L64", "000a20010db81140",         TestName = "L64_kept__eight_octets")]
    // An L32 of five octets. BIND: FORMERR.
    [TestCase("L32", "000a0a0102",               TestName = "L32_kept__five_octets")]
    [TestCase("L32", "000a0a01020000",           TestName = "L32_kept__seven_octets")]
    // An LP whose FQDN is a pointer (§2.4.1.2), missing, or followed by an octet.
    [TestCase("LP",  "000ac00c",                 TestName = "Lp_kept__compressed_fqdn")]
    [TestCase("LP",  "00",                       TestName = "Lp_kept__one_octet")]
    [TestCase("LP",  "000a046d61696c0000",       TestName = "Lp_kept__octets_after_the_fqdn")]
    public void Rdata_That_Is_Not_The_Type_It_Claims_Is_Kept_As_It_Arrived(String Type, String RDataHex)
    {

        // RFC 3597 §2 keeps the record; what it does not allow is a reading that
        // invents the octets a short record lacks or drops the ones a long record
        // has (finding 54 was the former). Kept, written back, and shown in the
        // generic form.
        var rdata  = Convert.FromHexString(RDataHex);
        var record = ADNSResourceRecord.ParseZoneFileString($@"host1.example.com. 300 IN {Type} \# {rdata.Length} {RDataHex}");

        var unparsed = record switch {
                           NID nid => nid.UnparsedRData,
                           L32 l32 => l32.UnparsedRData,
                           L64 l64 => l64.UnparsedRData,
                           LP  lp  => lp. UnparsedRData,
                           _       => null
                       };

        Assert.Multiple(() => {
            Assert.That(ADNSResourceRecord.TypeName(record.Type), Is.EqualTo(Type));
            Assert.That(unparsed,                                 Is.EqualTo(rdata));
            Assert.That(Hex(ADNSResourceRecord.RDataOf(record)),  Is.EqualTo(RDataHex));
            Assert.That(RDataText(record),                        Is.EqualTo($@"\# {rdata.Length} {RDataHex}"));
        });

    }

    #endregion

    #region The_Mnemonics_Are_Known_In_Both_Directions(Code, Name)

    [Test]
    [Property("RFC", "6742 §2")]
    [TestCase(104, "NID")]
    [TestCase(105, "L32")]
    [TestCase(106, "L64")]
    [TestCase(107, "LP")]
    public void The_Mnemonics_Are_Known_In_Both_Directions(Int32 Code, String Name)
    {

        Assert.Multiple(() => {
            Assert.That(ADNSResourceRecord.TypeName((DNSResourceRecordTypes) Code),     Is.EqualTo(Name));
            Assert.That((Int32) Enum.Parse<DNSResourceRecordTypes>(Name),              Is.EqualTo(Code));
        });

    }

    #endregion

}

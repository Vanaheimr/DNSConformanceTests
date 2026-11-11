using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4034 §6.2 item 3, octet by octet — which octets of an RDATA the canonical
/// form lowercases, and which it must leave alone.
/// </summary>
/// <remarks>
/// <para>
/// <c>RdataNameCaseTests</c> holds the rule against BIND's signatures, which is
/// the measure that counts, but a signature only says "these octets" or "not
/// these octets". It cannot say which octet was wrong, and it is blind to every
/// octet the fixture happens to write in lowercase or in digits.
/// </para>
/// <para>
/// So here each type's layout is driven with RDATA built by hand, where every
/// field that is not a name holds octets that look like capital letters — a
/// preference of 0x4D41 is "MA", a port of 0x4142 is "AB" — and has to come out
/// unchanged, while the names come out lowercased. A walk that started a name one
/// field too early, or stopped one too late, lowercases a number or a signature,
/// and that is a different record.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "4034 §6.2")]
public class CanonicalRDataTests
{

    #region Data

    private static String Canonical(UInt16 Type, Byte[] RData)
        => Convert.ToHexString(DNSSECCanonical.CanonicalRData(Type, RData)).ToLowerInvariant();

    private static String Hex(Byte[] Bytes)
        => Convert.ToHexString(Bytes).ToLowerInvariant();

    private static Byte[] Name(String Text)
        => RawDnsWriter.NameBytes(Text);

    #endregion


    #region The_Names_Of_The_Listed_Types_Are_Lowercased_And_Nothing_Else(...)

    [Test]
    [Property("RFC", "3597 §7")]
    public void A_Name_Behind_A_Preference_Is_Lowercased_And_The_Preference_Is_Not()
    {

        // MX, AFSDB, RT and KX: sixteen bits, then a name. 0x4D41 is "MA".
        foreach (var type in new UInt16[] { RawDnsType.MX, RawDnsType.AFSDB, 21, RawDnsType.KX })
        {

            var rdata    = new RawDnsWriter().U16(0x4D41).Bytes(Name("Mail.EXAMPLE.")).ToArray();
            var expected = new RawDnsWriter().U16(0x4D41).Bytes(Name("mail.example.")).ToArray();

            Assert.That(Canonical(type, rdata), Is.EqualTo(Hex(expected)), $"TYPE{type}");

        }

    }

    [Test]
    [Property("RFC", "3597 §7")]
    public void A_Name_Alone_Is_Lowercased()
    {

        // NS, MD, MF, CNAME, MB, MG, MR, PTR, DNAME, and NXT's next name.
        foreach (var type in new UInt16[] { 2, 3, 4, 5, 7, 8, 9, 12, 39 })
            Assert.That(Canonical(type, Name("Ns1.Example.COM.")), Is.EqualTo(Hex(Name("ns1.example.com."))), $"TYPE{type}");

    }

    [Test]
    [Property("RFC", "3597 §7")]
    public void Both_Names_Of_A_Soa_Are_Lowercased_And_Its_Numbers_Are_Not()
    {

        // Twenty octets of serial and timers behind the two names, every one of
        // them in the range of a capital letter.
        var numbers  = new RawDnsWriter().U32(0x41424344).U32(0x45464748).U32(0x494A4B4C).U32(0x4D4E4F50).U32(0x51525354).ToArray();

        var rdata    = new RawDnsWriter().Bytes(Name("NS1.Example.")).Bytes(Name("Hostmaster.Example.")).Bytes(numbers).ToArray();
        var expected = new RawDnsWriter().Bytes(Name("ns1.example.")).Bytes(Name("hostmaster.example.")).Bytes(numbers).ToArray();

        Assert.That(Canonical(RawDnsType.SOA, rdata), Is.EqualTo(Hex(expected)));

    }

    [Test]
    [Property("RFC", "3597 §7")]
    public void Both_Names_Of_An_Rp_And_A_Minfo_Are_Lowercased()
    {

        foreach (var type in new UInt16[] { RawDnsType.RP, 14 })
        {

            var rdata    = new RawDnsWriter().Bytes(Name("Mbox.Example.")).Bytes(Name("Txt.Example.")).ToArray();
            var expected = new RawDnsWriter().Bytes(Name("mbox.example.")).Bytes(Name("txt.example.")).ToArray();

            Assert.That(Canonical(type, rdata), Is.EqualTo(Hex(expected)), $"TYPE{type}");

        }

    }

    [Test]
    [Property("RFC", "3597 §7")]
    public void Both_Names_Of_A_Px_Are_Lowercased_And_Its_Preference_Is_Not()
    {

        // PX (RFC 2163 §4): PREFERENCE, MAP822, MAPX400.
        var rdata    = new RawDnsWriter().U16(0x5A41).Bytes(Name("Map822.Example.")).Bytes(Name("MapX400.Example.")).ToArray();
        var expected = new RawDnsWriter().U16(0x5A41).Bytes(Name("map822.example.")).Bytes(Name("mapx400.example.")).ToArray();

        Assert.That(Canonical(26, rdata), Is.EqualTo(Hex(expected)));

    }

    [Test]
    [Property("RFC", "3597 §7")]
    public void An_Srv_Target_Is_Lowercased_And_Its_Three_Numbers_Are_Not()
    {

        // Priority "AB", weight "CD", port "EF" — six octets before the target.
        var rdata    = new RawDnsWriter().U16(0x4142).U16(0x4344).U16(0x4546).Bytes(Name("Sip.Example.")).ToArray();
        var expected = new RawDnsWriter().U16(0x4142).U16(0x4344).U16(0x4546).Bytes(Name("sip.example.")).ToArray();

        Assert.That(Canonical(RawDnsType.SRV, rdata), Is.EqualTo(Hex(expected)));

    }

    [Test]
    [Property("RFC", "3597 §7")]
    public void A_Naptr_Replacement_Is_Lowercased_And_Its_Three_Strings_Are_Not()
    {

        // The flags, the services and the regular expression are character-
        // strings, not names, and "U" and "E2U+SIP" are what they say: §6.2
        // lowercases "the DNS names contained within the RDATA" and nothing else.
        var rdata    = new RawDnsWriter().U16(0x4142).U16(0x4344).
                           CharacterString("U").CharacterString("E2U+SIP").CharacterString("!^.*$!SIP:X@EXAMPLE.!").
                           Bytes(Name("Replacement.Example.")).ToArray();

        var expected = new RawDnsWriter().U16(0x4142).U16(0x4344).
                           CharacterString("U").CharacterString("E2U+SIP").CharacterString("!^.*$!SIP:X@EXAMPLE.!").
                           Bytes(Name("replacement.example.")).ToArray();

        Assert.That(Canonical(RawDnsType.NAPTR, rdata), Is.EqualTo(Hex(expected)));

    }

    [Test]
    [Property("RFC", "6840 §5.1")]
    public void An_Rrsig_Signer_Is_Lowercased_And_Its_Signature_Is_Not()
    {

        // RFC 6840 §5.1: "DNS names in the RDATA section of RRSIG resource records
        // are converted to lowercase." Eighteen octets in front, the signature
        // behind — and the signature here is the ASCII of "SIGNATURE".
        var fixedFields = new RawDnsWriter().U16(RawDnsType.A).U8(8).U8(2).U32(0x41424344).U32(0x45464748).U32(0x494A4B4C).U16(0x4D4E).ToArray();
        var signature   = "SIGNATURE"u8.ToArray();

        foreach (var type in new UInt16[] { RawDnsType.RRSIG, 24 })
        {

            var rdata    = new RawDnsWriter().Bytes(fixedFields).Bytes(Name("Example.COM.")).Bytes(signature).ToArray();
            var expected = new RawDnsWriter().Bytes(fixedFields).Bytes(Name("example.com.")).Bytes(signature).ToArray();

            Assert.That(Canonical(type, rdata), Is.EqualTo(Hex(expected)), $"TYPE{type}");

        }

    }

    [Test]
    [Property("RFC", "3597 §7")]
    public void An_A6_Prefix_Name_Is_Lowercased_Behind_The_Suffix_Its_Length_Leaves()
    {

        // RFC 2874 §3.1: a prefix length of 64 leaves eight octets of suffix, and
        // the prefix name follows them. The suffix here is "ABCDEFGH".
        var suffix   = "ABCDEFGH"u8.ToArray();

        var rdata    = new RawDnsWriter().U8(64).Bytes(suffix).Bytes(Name("Prefix.Example.")).ToArray();
        var expected = new RawDnsWriter().U8(64).Bytes(suffix).Bytes(Name("prefix.example.")).ToArray();

        // A prefix length of zero: sixteen octets of address and no name at all.
        var whole    = new RawDnsWriter().U8(0).Bytes("ABCDEFGHIJKLMNOP"u8.ToArray()).ToArray();

        Assert.Multiple(() => {
            Assert.That(Canonical(38, rdata), Is.EqualTo(Hex(expected)));
            Assert.That(Canonical(38, whole), Is.EqualTo(Hex(whole)));
        });

    }

    #endregion

    #region Only_The_Letters_A_To_Z_Are_Changed()

    [Test]
    [Property("RFC", "4034 §6.2")]
    public void Only_The_Letters_A_To_Z_Are_Changed()
    {

        // "all uppercase US-ASCII letters": the octets on either side of A to Z,
        // '@' (0x40) and '[' (0x5B), are not letters, and neither is an octet
        // above 0x7F, which a label may hold (RFC 2181 §11).
        var label    = new Byte[] { 0x40, 0x41, 0x5A, 0x5B, 0x60, 0x61, 0x7A, 0xC4 };
        var rdata    = new RawDnsWriter().U8((Byte) label.Length).Bytes(label).U8(0).ToArray();
        var expected = new RawDnsWriter().U8((Byte) label.Length).Bytes([ 0x40, 0x61, 0x7A, 0x5B, 0x60, 0x61, 0x7A, 0xC4 ]).U8(0).ToArray();

        Assert.That(Canonical(RawDnsType.CNAME, rdata), Is.EqualTo(Hex(expected)));

    }

    #endregion

    #region The_Names_Of_Other_Types_Keep_Their_Case(...)

    [Test]
    [Property("RFC", "3597 §7")]
    [Property("RFC", "6840 §5.1")]
    // RFC 6840 §5.1 takes these two off the list: NSEC's names "are not converted
    // to lowercase", and HINFO holds no names at all — its two character-strings
    // are text.
    [TestCase(RawDnsType.NSEC,     "074578616d706c6503434f4d00000140",   TestName = "Rdata_unchanged__NSEC")]
    [TestCase(RawDnsType.HINFO,    "0358383604554e4958",                 TestName = "Rdata_unchanged__HINFO")]
    // Types after RFC 3597: "no downcasing of embedded domain names takes place".
    [TestCase(RawDnsType.LP,       "000a034c3634074578616d706c6500",     TestName = "Rdata_unchanged__LP")]
    [TestCase(RawDnsType.HIP,      "01020002ab01020352767300",           TestName = "Rdata_unchanged__HIP")]
    [TestCase(RawDnsType.SVCB,     "00010353766300",                     TestName = "Rdata_unchanged__SVCB")]
    [TestCase((UInt16) 45,         "0a03020247570000",                   TestName = "Rdata_unchanged__IPSECKEY")]
    // A type nobody has a parser for: its RDATA is opaque, whatever it looks like.
    [TestCase((UInt16) 65280,      "0441424344004142",                   TestName = "Rdata_unchanged__TYPE65280")]
    public void The_Names_Of_Other_Types_Keep_Their_Case(UInt16 Type, String RDataHex)
    {

        Assert.That(Canonical(Type, Convert.FromHexString(RDataHex)), Is.EqualTo(RDataHex));

    }

    #endregion

    #region A_Record_Is_Canonicalised_By_Its_Type()

    [Test]
    [Property("RFC", "4034 §6.2")]
    public void A_Record_Is_Canonicalised_By_Its_Type()
    {

        // The record overload goes through the record's own serialisation, so it
        // is the one the signer and the validator call. An MX and an LP holding
        // the same name have to come out differently.
        var mx = new MX(DomainName.Parse("probe.example."), DNSQueryClasses.IN, TimeSpan.FromHours(1), 10, DomainName.Parse("Mail.Example."));
        var lp = new LP(DomainName.Parse("probe.example."), DNSQueryClasses.IN, TimeSpan.FromHours(1), 10, DomainName.Parse("Mail.Example."));

        Assert.Multiple(() => {
            Assert.That(Hex(DNSSECCanonical.CanonicalRData(mx)), Is.EqualTo("000a" + Hex(Name("mail.example."))));
            Assert.That(Hex(DNSSECCanonical.CanonicalRData(lp)), Is.EqualTo("000a" + Hex(Name("Mail.Example."))));
        });

    }

    #endregion

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// How a record type is written down when nobody has a name for it.
///
/// RFC 3597 §5 settles it once: "the RR type ... in the form TYPE####" for a
/// type with no mnemonic. RFC 4034 §3.2 then applies that to the one field whose
/// whole content is a type — an RRSIG's Type Covered — with a MUST. RFC 1035
/// §2.3.3 adds that case carries no meaning anywhere in it.
///
/// Three places read a type out of a line, and they disagreed:
/// <see href="../../FINDINGS.md">finding 55</see>. A type bit map knew both
/// spellings. An RRSIG read both and wrote a third. A SIG could read a mnemonic
/// and the single word TYPE0, and refused every other RFC 3597 §5 spelling
/// there is.
/// </summary>
[TestFixture]
[Property("RFC", "3597 §5, 4034 §3.2, 1035 §2.3.3")]
public class TypeMnemonicTests
{

    #region Data

    private const String SignatureTail = "8 2 3600 20301231235959 20200101000000 12345 example. AQID";

    private static IDNSResourceRecord Read(String Line)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");
        return record!;
    }

    private static String Rdata(IDNSResourceRecord Record)
        => String.Join(' ', Record.ToZoneFileString().Split(' ', StringSplitOptions.RemoveEmptyEntries)[4..]);

    #endregion


    #region An unknown type is written TYPE#### (RFC 4034 §3.2 — finding 55)

    [Test]
    [Property("RFC", "4034 §3.2")]
    [Property("RFC", "3597 §5")]
    [TestCase("RRSIG", TestName = "an RRSIG over a type nobody has named")]
    [TestCase("SIG",   TestName = "a SIG over a type nobody has named")]
    public void A_Signature_Over_An_Unnamed_Type_Names_It_The_Way_The_Rfc_Does(String Type)
    {

        // RFC 4034 §3.2, in full: "The Type Covered field is represented as an RR
        // type mnemonic. When the mnemonic is not known, the TYPE representation
        // as described in [RFC3597], Section 5, MUST be used."
        //
        // A bare decimal is not that representation. It reads back here, because
        // the reader was lenient in exactly the shape the writer was wrong, and
        // that is the whole reason it went unnoticed: the round trip closed over
        // a line no other implementation would take.
        var record = Read($"probe.example. 3600 IN {Type} TYPE65280 {SignatureTail}");

        Assert.That(Rdata(record).Split(' ')[0],
                    Is.EqualTo("TYPE65280"),
                    "65280 is a type number, and RFC 3597 §5 spells a type number TYPE65280");

    }

    [Test]
    [Property("RFC", "4034 §3.2")]
    [TestCase("RRSIG", TestName = "an RRSIG over A")]
    [TestCase("SIG",   TestName = "a SIG over A")]
    public void A_Signature_Over_A_Named_Type_Uses_The_Name(String Type)
    {

        // The other side of the same sentence: when the mnemonic *is* known it is
        // the mnemonic, not TYPE1.
        var record = Read($"probe.example. 3600 IN {Type} A {SignatureTail}");

        Assert.That(Rdata(record).Split(' ')[0], Is.EqualTo("A"));

    }

    [Test]
    [Property("RFC", "2931 §3")]
    public void A_Transaction_Signature_Covers_Type_Zero()
    {

        // RFC 2931 §3 gives SIG(0) a Type Covered of zero, and zero has no
        // mnemonic — so the same rule writes it TYPE0, which is what a SIG(0) in
        // a zone file has always looked like.
        foreach (var written in new[] { "0", "TYPE0" })
            Assert.That(Rdata(Read($"probe.example. 3600 IN SIG {written} {SignatureTail}")).Split(' ')[0],
                        Is.EqualTo("TYPE0"),
                        $"'{written}' is type zero either way");

    }

    #endregion


    #region The same type, in either case (RFC 1035 §2.3.3)

    [Test]
    [Property("RFC", "1035 §2.3.3")]
    [TestCase("RRSIG", "a",     TestName = "an RRSIG over a lowercase A")]
    [TestCase("RRSIG", "TyPe1", TestName = "an RRSIG over a mixed-case TYPE1")]
    [TestCase("SIG",   "a",     TestName = "a SIG over a lowercase A")]
    [TestCase("SIG",   "type1", TestName = "a SIG over a lowercase type1")]
    public void The_Type_Covered_Is_Read_In_Either_Case(String Type, String Covered)
    {

        // "no significance should be attached to the case" — for the mnemonic and
        // for the four letters of the RFC 3597 §5 form alike. A reader that only
        // knows one spelling refuses a zone file that is entirely correct.
        var record = Read($"probe.example. 3600 IN {Type} {Covered} {SignatureTail}");

        Assert.That(Rdata(record).Split(' ')[0], Is.EqualTo("A"));

    }

    [Test]
    [Property("RFC", "1035 §2.3.3")]
    [Property("RFC", "4034 §4.1.2")]
    public void A_Type_Bit_Map_Is_Read_In_Either_Case()
    {

        // RFC 4034 §4.1.2's bit map is written as type mnemonics, and §2.3.3
        // applies to them as it does everywhere else. A second reader parses
        // these — NSEC, NSEC3 and CSYNC share it — so it is a second place for
        // the same rule to be missing.
        var lower = Read("probe.example. 3600 IN NSEC next.example. a mx aaaa");

        Assert.That(Rdata(lower), Is.EqualTo("next.example. A MX AAAA"));

    }

    [Test]
    [Property("RFC", "3597 §5")]
    [Property("RFC", "4034 §4.1.2")]
    public void A_Type_Bit_Map_Spells_An_Unnamed_Type_The_Rfc_3597_Way()
    {

        // And the bit map's own version of finding 55's rule, which this reader
        // already had: RFC 4034 §4.2 repeats §3.2's sentence for the Type Bit
        // Maps field, so a type with no mnemonic is TYPE65280 on the way out.
        //
        // On the way in this reader also takes a bare 65280, and so does RRSIG's.
        // That is leniency rather than a rule — the MUST is on what is written —
        // so it is left as it is and not pinned here in either direction.
        var record = Read("probe.example. 3600 IN NSEC next.example. A TYPE65280");

        Assert.That(Rdata(record), Is.EqualTo("next.example. A TYPE65280"));

    }

    [Test]
    [Property("RFC", "4034 §4.2")]
    [Property("RFC", "3597 §5")]
    public void A_Type_Bit_Map_Token_That_Is_Not_A_Mnemonic_Names_No_Type()
    {

        // RFC 4034 §4.2 makes the field "a sequence of RR type mnemonics", and
        // RFC 3597 §5 gives the only other spelling. A token that is neither
        // names nothing — and "A,NS" is the one that has to be said out loud,
        // because a mnemonic reader written on top of an enum will take a
        // comma-separated list and answer with the two values combined. One and
        // two combine to three, and three is MD: a denial of existence that
        // asserts a type nobody wrote.
        var nsec = Read("probe.example. 3600 IN NSEC next.example. A,NS") as NSEC;

        Assert.That(Rdata(nsec!).Trim(), Is.EqualTo("next.example."),
                    "the token named no type, so the bit map asserts none — and type 3, "
                    + "which one and two combine to, is asserted least of all");

    }

    #endregion


    #region A type that is not a type (RFC 4034 §3.2)

    [Test]
    [Property("RFC", "4034 §3.2")]
    [TestCase("RRSIG", "NOTATYPE",  TestName = "an RRSIG over a word that is not a mnemonic")]
    [TestCase("RRSIG", "TYPE99999", TestName = "an RRSIG over a number past sixteen bits")]
    [TestCase("SIG",   "NOTATYPE",  TestName = "a SIG over a word that is not a mnemonic")]
    [TestCase("SIG",   "TYPE99999", TestName = "a SIG over a number past sixteen bits")]
    public void A_Type_Covered_That_Names_Nothing_Is_Refused(String Type, String Covered)
    {

        // The field is sixteen bits wide (RFC 4034 §3.1), so a number that does
        // not fit it names no type, and neither does a word that is not a
        // mnemonic. Reading either as something leaves the signature claiming to
        // cover a type the line never stated.
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(
                        $"probe.example. 3600 IN {Type} {Covered} {SignatureTail}", out _, out _),
                    Is.False);

    }

    #endregion

}

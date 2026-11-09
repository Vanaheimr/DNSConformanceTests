using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// What a mnemonic is, and what it is not: <see href="../../FINDINGS.md">finding 98</see>.
///
/// RFC 1035 §5.1 writes a record as "[&lt;TTL&gt;] [&lt;class&gt;] &lt;type&gt; &lt;RDATA&gt;", with
/// "the standard mnemonics" for class and type. RFC 3597 §5 adds CLASSnn and
/// TYPEnnn for the values that have none, and gives the reason: that convention
/// "allows types and classes to be distinguished from each other and from TTL
/// values". Nothing else is a class or a type.
///
/// Hermod read class and type through .NET's <c>Enum.TryParse</c>, which takes
/// more than names. It takes a decimal, and it takes a comma-separated list of
/// names, whose values it combines bitwise. Finding 23 took away the class
/// reader's own fallback to a decimal; <c>Enum.TryParse</c> has one as well, for
/// every class that has a name.
/// </summary>
[TestFixture]
[Property("RFC", "1035 §5.1, 3597 §5, 4034 §3.2, §4.2")]
public class MnemonicSyntaxTests
{

    #region Data

    private static readonly TimeSpan NobodysTtl = TimeSpan.FromSeconds(99);

    private static IDNSResourceRecord Read(String Line)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error, DefaultTimeToLive: NobodysTtl),
                    Is.True,
                    $"the reader refused '{Line}': {error}");
        return record!;
    }

    private static Boolean Reads(String Line)
        => ADNSResourceRecord.TryParseZoneFileString(Line, out _, out _);

    private static String Rdata(IDNSResourceRecord Record)
        => String.Join(' ', Record.ToZoneFileString().Split(' ', StringSplitOptions.RemoveEmptyEntries)[4..]);

    private const String SignatureTail = "8 2 3600 20301231235959 20200101000000 12345 example. AQID";

    #endregion


    #region A bare decimal is a TTL, also where a class has that number (RFC 3597 §5 — finding 98)

    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "3597 §5")]
    [Property("RFC", "1035 §5.1")]
    [TestCase(  1, TestName = "{m}: 1, the number of IN")]
    [TestCase(  2, TestName = "{m}: 2, the number of CS")]
    [TestCase(  3, TestName = "{m}: 3, the number of CH")]
    [TestCase(  4, TestName = "{m}: 4, the number of HS")]
    [TestCase(254, TestName = "{m}: 254, the number of NONE")]
    [TestCase(255, TestName = "{m}: 255, the number of ANY")]
    public void A_Bare_Decimal_Is_A_Ttl_Even_When_A_Class_Has_Its_Number(Int32 Seconds)
    {

        // Finding 23 is this rule for 3600, which no class has. The header tries
        // the class first, so a number some class has was read as that class:
        // the TTL was lost to the caller's default, and with no class written
        // after it the record was in that class. Every number here is a TTL a
        // zone may use; one second is not even unusual.
        var ttlFirst    = Read($"x.example. {Seconds} IN A 192.0.2.1");
        var classFirst  = Read($"x.example. IN {Seconds} A 192.0.2.1");
        var noClass     = Read($"x.example. {Seconds} A 192.0.2.1");

        Assert.Multiple(() => {

            foreach (var (record, form) in new[] { (ttlFirst,   "TTL before class"),
                                                   (classFirst, "class before TTL"),
                                                   (noClass,    "no class at all") })
            {
                Assert.That(record.TimeToLive, Is.EqualTo(TimeSpan.FromSeconds(Seconds)), $"{form}: the number is the TTL");
                Assert.That(record.Class,      Is.EqualTo(DNSQueryClasses.IN),            $"{form}: and the class is IN");
            }

        });

    }

    #endregion


    #region A list of names is not a name (RFC 1035 §5.1, RFC 4034 §3.2, §4.2 — finding 98)

    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "1035 §5.1")]
    [TestCase("x.example. 3600 IN A,MX 10 mail.example.", TestName = "{m}: a type, A,MX, which combines to MX")]
    [TestCase("x.example. 3600 IN,CH A 192.0.2.1",        TestName = "{m}: a class, IN,CH, which combines to CH")]
    [TestCase("x.example. 3600 IN In,Ch A 192.0.2.1",     TestName = "{m}: the same in any case")]
    public void A_Comma_Separated_List_In_The_Header_Is_Neither_Class_Nor_Type(String Line)
    {

        // A, MX, IN and CH are mnemonics, and a header token is one of them or
        // none. Joined by a comma they are a token the master file has no
        // reading for. Hermod combined the values, 1 | 15 = 15 and 1 | 3 = 3,
        // and read a record of a type or class nobody wrote.
        Assert.That(Reads(Line), Is.False);

    }

    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "4034 §3.2")]
    [TestCase("RRSIG", TestName = "{m}: an RRSIG")]
    [TestCase("SIG",   TestName = "{m}: a SIG")]
    public void A_Comma_Separated_List_Is_Not_A_Type_Covered(String Type)
    {

        // RFC 4034 §3.2: "The Type Covered field is represented as an RR type
        // mnemonic." A signature read from this line claimed to cover MX.
        Assert.That(Reads($"x.example. 3600 IN {Type} A,MX {SignatureTail}"), Is.False);

    }

    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "4034 §4.2")]
    public void A_Comma_Separated_List_In_A_Type_Bit_Map_Names_No_Type()
    {

        // TypeMnemonicTests asks this with A,NS, which combines to 3, and 3 is
        // MD, which Hermod has no name for, so the token named nothing for that
        // reason alone. A,MX combines to MX, and the bit map asserted it: a
        // denial of existence that says an MX exists where the line never wrote
        // one.
        var nsec = Read("probe.example. 3600 IN NSEC next.example. A,MX") as NSEC;

        Assert.That(Rdata(nsec!).Trim(), Is.EqualTo("next.example."),
                    "the token named no type, so the bit map asserts none, MX least of all");

    }

    #endregion

}

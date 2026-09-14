using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 5952 §4 — the text an IPv6 address is written as, in the one place where
/// another implementation has to read it back: a zone file.
/// </summary>
/// <remarks>
/// <para>
/// <c>IPv6Address.ToString()</c> is shaped for an HTTP authority, where an IPv6
/// literal is bracketed. It returns <c>[::1]</c> and <c>[::]</c> for those two
/// addresses. Brackets are not zone-file syntax — BIND answers
/// <c>near '[::1]': bad IPv6 address</c> and refuses to load the zone — and
/// <c>AAAA</c> handed that string straight through as its RDATA.
/// </para>
/// <para>
/// Nothing caught it because <c>IPv6Address.Parse</c> accepts the brackets it
/// writes. The round trip closes inside Hermod and breaks at the first outside
/// reader, which is the shape of a defect that only an external judge can see.
/// </para>
/// <para>
/// The expectations below are BIND's own output for the same zone, taken from
/// <c>named-checkzone -D</c> rather than from what this suite believes.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "5952 §4")]
public class IPv6PresentationTests
{

    #region Data

    private static readonly DomainName Name = DomainName.Parse("probe.example.");

    private static AAAA Record(String Address)

        => new (Name,
                DNSQueryClasses.IN,
                TimeSpan.FromSeconds(3600),
                IPv6Address.Parse(Address));

    private static String RDataTextOf(IDNSResourceRecord Record)
        => Record.ToZoneFileString().Split("AAAA")[1].Trim();

    #endregion

    #region The canonical form (RFC 5952 §4)

    [Test]
    // §4.1: "Leading zeros MUST be suppressed."
    [TestCase("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1")]
    // §4.2.1: '"::" MUST be used to its maximum capability.'
    [TestCase("2001:db8:0:0:0:0:2:1",                    "2001:db8::2:1")]
    // §4.2.2: '"::" MUST NOT be used to shorten just one 16-bit 0 field.'
    [TestCase("2001:db8:0:1:1:1:1:1",                    "2001:db8:0:1:1:1:1:1")]
    // §4.2.3: the longest run wins, and the first of two equal runs.
    [TestCase("2001:0:0:1:0:0:0:1",                      "2001:0:0:1::1")]
    [TestCase("1:0:0:2:0:0:3:4",                         "1::2:0:0:3:4")]
    // §4.3: 'the characters "a" ... "f" MUST be represented in lowercase.'
    [TestCase("2001:DB8:AAAA:BBBB:CCCC:DDDD:EEEE:FFFF",  "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff")]
    // And the two that were bracketed.
    [TestCase("::1",                                     "::1")]
    [TestCase("::",                                      "::")]
    public void An_Aaaa_Is_Written_The_Way_Bind_Writes_It(String Address, String Expected)
    {

        Assert.That(RDataTextOf(Record(Address)),
                    Is.EqualTo(Expected),
                    $"BIND writes {Address} as {Expected}");

    }

    #endregion

    #region No brackets, anywhere

    [Test]
    public void No_Aaaa_Rdata_Carries_An_Authority_Bracket()
    {

        // The whole of the defect in one assertion: a bracket is HTTP authority
        // syntax, and a zone file has no place for it. Named separately from the
        // canonical-form cases because it is the part that makes a zone
        // unloadable rather than merely non-canonical.
        var bracketed = new[] { "::", "::1" }.
                            Select (address => RDataTextOf(Record(address))).
                            Where  (text    => text.Contains('[') || text.Contains(']')).
                            ToArray();

        Assert.That(bracketed, Is.Empty);

    }

    #endregion

    #region The round trip that used to close on itself

    [Test]
    [TestCase("::1")]
    [TestCase("::")]
    [TestCase("2001:db8::1")]
    [TestCase("2001:db8:0:1:1:1:1:1")]
    public void An_Aaaa_Reads_Back_As_The_Same_Address(String Address)
    {

        var written = Record(Address).ToZoneFileString();

        Assert.That(ADNSResourceRecord.TryParseZoneFileString(written, out var readBack, out var error),
                    Is.True,
                    $"the reader refused '{written}': {error}");

        // Reading its own output back was never the problem: Parse accepted the
        // brackets too. The assertion that matters is the text above; this one
        // guards against fixing the text by breaking the reader.
        Assert.That((readBack as AAAA)?.IPv6Address,
                    Is.EqualTo(IPv6Address.Parse(Address)));

    }

    #endregion

}

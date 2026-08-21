using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 6895 §3.2 — the CLASS registry. The document that decides which number
/// carries which name, and therefore what a record written in presentation
/// format means to the next reader.
/// </summary>
[TestFixture]
public class IanaClassRegistryTests
{

    #region Every_Mnemonic_Names_Its_Iana_Code_Point(Mnemonic, CodePoint)

    [Test]
    [Property("RFC", "6895 §3.2")]
    [TestCase(DNSQueryClasses.IN,   RawDnsClass.IN)]
    [TestCase(DNSQueryClasses.CH,   RawDnsClass.CH)]
    [TestCase(DNSQueryClasses.HS,   RawDnsClass.HS)]
    [TestCase(DNSQueryClasses.NONE, RawDnsClass.NONE)]
    [TestCase(DNSQueryClasses.ANY,  RawDnsClass.ANY)]
    public void Every_Mnemonic_Names_Its_Iana_Code_Point(DNSQueryClasses Mnemonic, UInt16 CodePoint)
    {

        // The registry is the whole content of §3.2, and a mnemonic pointing at
        // the wrong number is not a naming preference — it is a different class
        // on the wire. The expected values come from the suite's own table, not
        // from the enum under test.
        Assert.That((UInt16) Mnemonic,
                    Is.EqualTo(CodePoint),
                    $"{Mnemonic} is IANA class {CodePoint}");

    }

    #endregion

    #region The_Class_Named_None_Is_254()

    [Test]
    [Property("RFC", "6895 §3.2, 2136 §2.4")]
    public void The_Class_Named_None_Is_254()
    {

        // RFC 6895 §3.2 puts QCLASS NONE at 254; RFC 2136 §2.4 is what uses it.
        var record = ParseARecordWithClass(254);

        Assert.Multiple(() => {

            Assert.That(record.Class,
                        Is.EqualTo(DNSQueryClasses.NONE),
                        "class 254 is NONE");

            Assert.That(ADNSResourceRecord.ClassName(record.Class),
                        Is.EqualTo("NONE"),
                        "and it must be written by that name, not as a generic CLASS254");

        });

    }

    #endregion

    #region Class_Zero_Is_Reserved_And_Carries_No_Mnemonic()

    [Test]
    [Property("RFC", "6895 §3.2, 3597 §5")]
    public void Class_Zero_Is_Reserved_And_Carries_No_Mnemonic()
    {

        // §3.2 reserves class 0 and gives it no name. A name invented for it
        // does not stay local: RFC 3597 §5's generic form is what the next
        // reader parses, so writing a mnemonic here hands them a different
        // class than the one meant.
        var record = ParseARecordWithClass(0);

        Assert.Multiple(() => {

            Assert.That(record.Class,
                        Is.Not.EqualTo(DNSQueryClasses.NONE),
                        "class 0 is reserved, and is not NONE");

            Assert.That(ADNSResourceRecord.ClassName(record.Class),
                        Is.EqualTo("CLASS0"),
                        "a reserved class has no mnemonic and takes RFC 3597 §5's generic form");

        });

    }

    #endregion

    #region Registered_Classes_Render_As_Their_Mnemonics(CodePoint, Mnemonic)

    [Test]
    [Property("RFC", "6895 §3.2")]
    [TestCase((UInt16)   1, "IN")]
    [TestCase((UInt16)   2, "CS")]
    [TestCase((UInt16)   3, "CH")]
    [TestCase((UInt16)   4, "HS")]
    [TestCase((UInt16) 254, "NONE")]
    [TestCase((UInt16) 255, "ANY")]
    public void Registered_Classes_Render_As_Their_Mnemonics(UInt16 CodePoint, String Mnemonic)
    {

        Assert.That(ADNSResourceRecord.ClassName((DNSQueryClasses) CodePoint),
                    Is.EqualTo(Mnemonic),
                    $"class {CodePoint} is written {Mnemonic}");

    }

    #endregion

    #region Unregistered_Classes_Render_Generically(CodePoint)

    [Test]
    [Property("RFC", "6895 §3.2, 3597 §5")]
    [TestCase((UInt16)     0)]     // reserved
    [TestCase((UInt16)     5)]     // unassigned, low band
    [TestCase((UInt16)   128)]     // first of the QCLASS/Meta band
    [TestCase((UInt16)   253)]     // last one below NONE
    [TestCase((UInt16) 65534)]
    public void Unregistered_Classes_Render_Generically(UInt16 CodePoint)
    {

        // The other half, and the half that stops "give everything a name" from
        // passing: a code point with no mnemonic must take the generic form.
        Assert.That(ADNSResourceRecord.ClassName((DNSQueryClasses) CodePoint),
                    Is.EqualTo($"CLASS{CodePoint}"),
                    $"class {CodePoint} has no mnemonic to write");

    }

    #endregion

    #region (private static) ParseARecordWithClass(RawClass)

    /// <summary>
    /// An A record whose CLASS field carries exactly the given 16 bits, built
    /// by the suite's own writer so the value under test never passes through
    /// the code being judged.
    /// </summary>
    private static A ParseARecordWithClass(UInt16 RawClass)
    {

        // CLASS (2) + TTL (4) + RDLENGTH (2) + RDATA — the stream an RR parser
        // is handed once the owner name and TYPE have been consumed:
        var rdata = new RawDnsWriter().U16(RawClass).U32(3600).U16(4).Bytes(192, 0, 2, 1).ToArray();

        return new A(
                   DomainName.Parse("class.example."),
                   new MemoryStream(rdata)
               );

    }

    #endregion

}

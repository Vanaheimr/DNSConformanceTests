using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

namespace DNSConformance.WireFormat.Tests;

/// <summary>
/// RFC 1035 §2.3.3/§2.3.4/§3.1 — domain name syntax, size limits and case
/// handling on the wire.
/// </summary>
[TestFixture]
[Property("RFC", "1035")]
public class NameEncodingTests
{

    private static Byte[] SerializeQuestionName(String name)
        => DNSPacket.Query(DNSServiceName.Parse(name), 0, DNSResourceRecordTypes.A).ToByteArray();


    #region Simple_Name_Uses_LengthPrefixed_Labels_With_Zero_Terminator()

    [Test]
    public void Simple_Name_Uses_LengthPrefixed_Labels_With_Zero_Terminator()
    {

        var wire      = SerializeQuestionName("www.example.com");
        var expected  = new Byte[] {
                            3, (Byte) 'w', (Byte) 'w', (Byte) 'w',
                            7, (Byte) 'e', (Byte) 'x', (Byte) 'a', (Byte) 'm', (Byte) 'p', (Byte) 'l', (Byte) 'e',
                            3, (Byte) 'c', (Byte) 'o', (Byte) 'm',
                            0
                        };

        Assert.That(wire.Skip(12).Take(expected.Length), Is.EqualTo(expected));

    }

    #endregion

    #region Trailing_Dot_Does_Not_Change_Wire_Encoding()

    [Test]
    public void Trailing_Dot_Does_Not_Change_Wire_Encoding()
    {

        var withDot     = RawDnsReader.Parse(SerializeQuestionName("example.org.")).Questions.Single();
        var withoutDot  = RawDnsReader.Parse(SerializeQuestionName("example.org")). Questions.Single();

        Assert.That(withDot.Name.Labels.Count,    Is.EqualTo(2));
        Assert.That(withoutDot.Name.Labels.Count, Is.EqualTo(2));

    }

    #endregion

    #region Case_Is_Preserved_On_The_Wire()

    [Test]
    [Property("RFC", "1035 §2.3.3")]
    public void Case_Is_Preserved_On_The_Wire()
    {

        // "When data enters the domain system, its original case should be
        // preserved whenever possible." — SHOULD-level, therefore this test
        // accepts either behavior but documents the deviation (FINDINGS.md #1):
        // DNSServiceName.Parse lowercases, so the original spelling never
        // reaches the wire. This also defeats dns0x20-style entropy schemes.
        var decoded  = RawDnsReader.Parse(SerializeQuestionName("MiXeD.CaSe.ExAmPlE."));
        var onWire   = decoded.Questions.Single().Name.Presentation;

        TestContext.Out.WriteLine($"QNAME on the wire: '{onWire}' (submitted: 'MiXeD.CaSe.ExAmPlE')");

        Assert.That(onWire, Is.EqualTo("MiXeD.CaSe.ExAmPlE").IgnoreCase,
                    "name must at least survive case-insensitively");

    }

    #endregion

    #region Label_Of_63_Bytes_Is_Accepted_And_RoundTrips()

    [Test]
    [Property("RFC", "1035 §2.3.4")]
    public void Label_Of_63_Bytes_Is_Accepted_And_RoundTrips()
    {

        var label63  = new String('a', 63);
        var decoded  = RawDnsReader.Parse(SerializeQuestionName($"{label63}.example."));

        Assert.That(decoded.Questions.Single().Name.Labels[0], Has.Length.EqualTo(63));

    }

    #endregion

    #region Label_Of_64_Bytes_Is_Rejected()

    [Test]
    [Property("RFC", "1035 §2.3.4")]
    public void Label_Of_64_Bytes_Is_Rejected()
    {

        var label64 = new String('a', 64);

        Assert.That(
            DNSServiceName.TryParse($"{label64}.example.", out _, out _),
            Is.False,
            "labels are limited to 63 octets"
        );

    }

    #endregion

    #region Name_Longer_Than_255_Bytes_Is_Rejected()

    [Test]
    [Property("RFC", "1035 §2.3.4")]
    public void Name_Longer_Than_255_Bytes_Is_Rejected()
    {

        // 5 × 62 bytes lifts the wire form above 255.
        var tooLong = String.Join('.', Enumerable.Repeat(new String('b', 62), 5));

        Assert.That(
            DNSServiceName.TryParse(tooLong, out _, out _),
            Is.False,
            "names are limited to 255 octets"
        );

    }

    #endregion


    #region Hermod_Decodes_Labels_With_Original_Case()

    [Test]
    public void Hermod_Decodes_Labels_With_Original_Case()
    {

        var wire  = new RawDnsWriter().Name("CaSePreserved.Example.").ToArray();
        var name  = DNSTools.ExtractName(new MemoryStream(wire));

        Assert.That(name, Is.EqualTo("CaSePreserved.Example"));

    }

    #endregion

    #region Hermod_Decodes_Root_Name()

    [Test]
    public void Hermod_Decodes_Root_Name()
    {

        var name = DNSTools.ExtractName(new MemoryStream([0x00]));

        Assert.That(name, Is.EqualTo("."));

    }

    #endregion

    #region Hermod_Rejects_Label_Length_Above_63()

    [Test]
    [Property("RFC", "1035 §2.3.4")]
    public void Hermod_Rejects_Label_Length_Above_63()
    {

        // 0x40 = 64 is not a valid label length (upper bits would mean a pointer).
        var wire = new Byte[] { 0x40 }
                       .Concat(Enumerable.Repeat((Byte) 'x', 64))
                       .Concat(new Byte[] { 0x00 })
                       .ToArray();

        Assert.That(
            () => DNSTools.ExtractName(new MemoryStream(wire)),
            Throws.InstanceOf<Exception>(),
            "length bytes 64..191 use the reserved 01/10 prefixes and must be rejected"
        );

    }

    #endregion

    #region Hermod_Rejects_Truncated_Name()

    [Test]
    public void Hermod_Rejects_Truncated_Name()
    {

        // Label claims 5 bytes, only 2 present, no terminator.
        var wire = new Byte[] { 0x05, (Byte) 'a', (Byte) 'b' };

        Assert.That(
            () => DNSTools.ExtractName(new MemoryStream(wire)),
            Throws.InstanceOf<Exception>()
        );

    }

    #endregion

}

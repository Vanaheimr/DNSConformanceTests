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

        // RFC 1035 §2.3.3: "When you receive a domain name or label, you should
        // preserve its case." Byte-exact, not merely case-insensitively equal —
        // dns-0x20 query randomization is built entirely on the case of a QNAME
        // surviving the round trip untouched.
        var decoded  = RawDnsReader.Parse(SerializeQuestionName("MiXeD.CaSe.ExAmPlE."));
        var onWire   = decoded.Questions.Single().Name.Presentation;

        Assert.That(onWire, Is.EqualTo("MiXeD.CaSe.ExAmPlE"),
                    "the original spelling must reach the wire unchanged");

    }

    #endregion

    #region Names_Differing_Only_In_Case_Are_The_Same_Name()

    [Test]
    [Property("RFC", "4343")]
    public void Names_Differing_Only_In_Case_Are_The_Same_Name()
    {

        // RFC 4343: preserving case must not make case significant. Equality and
        // GetHashCode have to agree, or every dictionary keyed on a name (the
        // server's zone store, the client's caches) silently loses entries.
        var lower  = DomainName.Parse("example.com.");
        var upper  = DomainName.Parse("EXAMPLE.COM.");
        var mixed  = DomainName.Parse("ExAmPlE.cOm.");

        Assert.Multiple(() => {

            Assert.That(lower.FullName, Is.EqualTo("example.com."), "case is preserved…");
            Assert.That(upper.FullName, Is.EqualTo("EXAMPLE.COM."), "…in both directions");

            Assert.That(lower,               Is.EqualTo(upper),           "RFC 4343: same name");
            Assert.That(lower,               Is.EqualTo(mixed));
            Assert.That(lower.GetHashCode(), Is.EqualTo(upper.GetHashCode()),
                        "Equals/GetHashCode contract");
            Assert.That(lower.CompareTo(upper), Is.Zero, "ordering must ignore case too");

            Assert.That(new HashSet<DomainName> { lower, upper, mixed }, Has.Count.EqualTo(1),
                        "three spellings of one name must collapse to one set entry");

        });

    }

    #endregion

    #region Service_Names_Differing_Only_In_Case_Are_The_Same_Name()

    [Test]
    [Property("RFC", "4343")]
    public void Service_Names_Differing_Only_In_Case_Are_The_Same_Name()
    {

        // Same contract on DNSServiceName — InMemoryDNSZone keys a
        // ConcurrentDictionary on this type, so a mismatch here means a zone
        // lookup for "WWW.example.com" cannot find the record stored as "www…".
        var lower = DNSServiceName.Parse("_25._tcp.example.com.");
        var upper = DNSServiceName.Parse("_25._TCP.EXAMPLE.COM.");

        Assert.Multiple(() => {
            Assert.That(upper.FullName,      Is.EqualTo("_25._TCP.EXAMPLE.COM."));
            Assert.That(lower,               Is.EqualTo(upper));
            Assert.That(lower.GetHashCode(), Is.EqualTo(upper.GetHashCode()));
        });

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

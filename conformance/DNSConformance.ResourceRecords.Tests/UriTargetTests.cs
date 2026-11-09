using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// What a URI record's target is: <see href="../../FINDINGS.md">finding 99</see>.
///
/// RFC 7553 §4.4: the target is "the URI of the target, enclosed in double-quote
/// characters ('"'), where the URI is as specified in RFC 3986". §4.5 carries it
/// on the wire "as a sequence of octets". And RFC 3597 §3 makes the octets
/// untouchable: "servers MUST also exactly preserve the RDATA of RRs of known
/// type, except for changes due to compression or decompression".
///
/// Hermod read the target as a URL of its HTTP layer. That reader puts https://
/// in front of any text without "://", and it refuses the schemes it does not
/// know. RFC 3986 §1.1.2's examples include a mailto:, a news:, a tel: and a
/// urn:, and none of them has "//".
///
/// The tests assert the octets and the presentation form, not the type of
/// <c>URI.Target</c>, so they mean the same before the fix and after it.
/// </summary>
[TestFixture]
[Property("RFC", "7553 §4.4, §4.5, 3597 §3, 3986 §1.1.2")]
public class UriTargetTests
{

    #region Data

    private static IDNSResourceRecord Read(String Line)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");
        return record!;
    }

    private static String Rdata(IDNSResourceRecord Record)
        => String.Join(' ', Record.ToZoneFileString().Split(' ', StringSplitOptions.RemoveEmptyEntries)[4..]);

    private static String Generic(String Target)
    {
        var octets = Encoding.ASCII.GetBytes(Target);
        return $@"\# {4 + octets.Length} 000a0001{Convert.ToHexString(octets)}";
    }

    private static Byte[] Wire(String Target)
        => [ 0x00, 0x0a, 0x00, 0x01, .. Encoding.ASCII.GetBytes(Target) ];

    #endregion


    #region RFC 7553's own example (§5.1)

    [Test]
    [Property("RFC", "7553 §5.1")]
    public void The_Rfc_Example_Is_Carried_As_It_Was_Written()
    {

        // RFC 7553 §5.1, the one example the RFC gives. Hermod read it already:
        // its URL type knows ftp. This is the control for the cases below,
        // which differ from it only in their scheme.
        const String Target = "ftp://ftp1.example.com/public";

        var record = Read($"_ftp._tcp.example.com. 3600 IN URI 10 1 \"{Target}\"");

        Assert.Multiple(() => {
            Assert.That(Rdata(record),                         Is.EqualTo($"10 1 \"{Target}\""));
            Assert.That(ADNSResourceRecord.RDataOf(record),    Is.EqualTo(Wire(Target)));
        });

    }

    #endregion


    #region Any URI of RFC 3986 is a target (RFC 7553 §4.4, RFC 3597 §3 — finding 99)

    [Test]
    [Property("RFC", "7553 §4.4")]
    [Property("RFC", "3597 §3")]
    [Property("RFC", "3986 §1.1.2")]
    [TestCase("ftp://ftp.is.co.za/rfc/rfc1808.txt")]
    [TestCase("http://www.ietf.org/rfc/rfc2396.txt")]
    [TestCase("ldap://[2001:db8::7]/c=GB?objectClass?one")]
    [TestCase("mailto:John.Doe@example.com")]
    [TestCase("news:comp.infosystems.www.servers.unix")]
    [TestCase("tel:+1-816-555-1212")]
    [TestCase("telnet://192.0.2.16:80/")]
    [TestCase("urn:oasis:names:specification:docbook:dtd:xml:4.1.2")]
    public void Every_Example_Uri_Of_Rfc_3986_Is_A_Target_As_It_Was_Written(String Target)
    {

        // RFC 3986 §1.1.2's examples, all eight. Read from the presentation
        // form and from the generic form, which is the wire reader's, each has
        // to come out as the octets that went in. Hermod made mailto:John.Doe@
        // into https://mailto:John.Doe@, a different URI in different octets,
        // and refused the urn:.
        var written = Read($"_x._tcp.example. 3600 IN URI 10 1 \"{Target}\"");
        var wire    = Read($"_x._tcp.example. 3600 IN URI {Generic(Target)}");

        Assert.Multiple(() => {

            Assert.That(Rdata(written),                       Is.EqualTo($"10 1 \"{Target}\""), "the presentation form");
            Assert.That(ADNSResourceRecord.RDataOf(written),  Is.EqualTo(Wire(Target)),         "the octets it stands for");

            Assert.That(Rdata(wire),                          Is.EqualTo($"10 1 \"{Target}\""), "read off the wire");
            Assert.That(ADNSResourceRecord.RDataOf(wire),     Is.EqualTo(Wire(Target)),         "and written back unchanged");

        });

    }

    [Test]
    [Property("RFC", "3597 §3")]
    [Property("RFC", "7553 §4.5")]
    [TestCase("example.com/x", TestName = "{m}: a target with no scheme")]
    [TestCase("a",             TestName = "{m}: a target of one octet, the least §4.5 allows")]
    public void A_Target_Is_Never_Given_A_Scheme_It_Did_Not_Have(String Target)
    {

        // Neither is a URI of RFC 3986, which starts every URI with a scheme.
        // RFC 7553 makes two MUSTs of its target, and both are about emptiness:
        // §4.4's "MUST NOT be an empty URI" and §4.5's length "greater than
        // zero". BIND 9.20 reads both lines and writes them back as they are.
        // What a reader must not do is publish a URI the zone did not hold:
        // Hermod read these as https://example.com/x and https://a.
        var record = Read($"_x._tcp.example. 3600 IN URI {Generic(Target)}");

        Assert.Multiple(() => {
            Assert.That(Rdata(record),                         Is.EqualTo($"10 1 \"{Target}\""));
            Assert.That(ADNSResourceRecord.RDataOf(record),    Is.EqualTo(Wire(Target)));
        });

    }

    #endregion

}

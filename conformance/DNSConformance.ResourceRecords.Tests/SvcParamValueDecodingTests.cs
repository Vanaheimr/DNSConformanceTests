using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// A SvcParamValue read from a zone file is decoded, escapes and all.
/// </summary>
/// <remarks>
/// <para>
/// RFC 9460 §2.1: "The SvcParamValue is parsed using the character-string
/// decoding algorithm (Appendix A), producing a value." For a key written as
/// keyNNNNN, "the decoded value SHALL be used as its wire-format encoding".
/// Appendix A names the algorithm as the one in RFC 1035 §5.1, where \X "is used
/// to quote that character so that its special meaning does not apply", and
/// \DDD "is the octet corresponding to the decimal number described by DDD".
/// </para>
/// <para>
/// The key used here is key65280, from the private-use range, so that nothing
/// key-specific stands between the decoded value and the octets on the wire.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "9460 §2.1")]
[Property("RFC", "1035 §5.1")]
public class SvcParamValueDecodingTests
{

    #region Data

    private const UInt16 PrivateKey = 65280;

    private static IDNSResourceRecord Read(String Line)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");
        return record!;
    }

    private static IEnumerable<SVCParameter> SvcParams(IDNSResourceRecord Record)
        => Record switch {
               SVCB  svcb   => svcb. SVCParameters,
               HTTPS https  => https.SVCParameters,
               _            => throw new ArgumentException($"not an SVCB or HTTPS record: {Record.GetType().Name}")
           };

    private static Byte[] PrivateValue(String Type, String Parameters)
        => SvcParams(Read($"probe.example. 3600 IN {Type} 1 svc.example. {Parameters}")).
               Single(p => p.Key == PrivateKey).Value;

    #endregion


    /// <summary>
    /// Finding 88: an escaped quote is a quote.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void An_Escaped_Quote_Inside_A_Quoted_Value_Is_One_Quote(String Type)
    {

        // "a\"b" in quotes is the three octets a, ", b. The backslash is how the
        // quote got into the string, not part of what the string holds.
        Assert.That(PrivateValue(Type, "key65280=\"a\\\"b\""), Is.EqualTo("a\"b"u8.ToArray()));

    }


    /// <summary>
    /// Finding 88: \DDD is one octet.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void A_Decimal_Escape_Is_The_One_Octet_It_Names(String Type)
    {

        // Unquoted, so the quotes cannot be what is wrong: \000 and \255 are the
        // two ends of the range, and \092 is the backslash itself.
        Assert.That(PrivateValue(Type, "key65280=\\000a\\092\\255"), Is.EqualTo(new Byte[] { 0x00, 0x61, 0x5C, 0xFF }));

    }


    /// <summary>
    /// Finding 88: what Hermod writes, Hermod reads back as it was.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void A_Value_Survives_Hermods_Own_Presentation_Round_Trip(String Type)
    {

        // Hermod's writer already does its half: it quotes the value and writes
        // '"', '\' and every octet outside 0x20-0x7E as \DDD, which is what
        // PresentationBoundaryTests pins. The reader has to undo exactly that, or
        // a zone Hermod saves is a different zone when Hermod loads it.
        var value    = new Byte[] { 0x00, 0x1F, 0x20, 0x22, 0x5C, 0x61, 0x7E, 0x7F, 0xFF };
        var target   = DomainName.Parse("svc.example.");
        var name     = DomainName.Parse("probe.example.");
        var ttl      = TimeSpan.FromSeconds(3600);

        IDNSResourceRecord record = Type == "SVCB"
                                        ? new SVCB (name, DNSQueryClasses.IN, ttl, 1, target, [ new SVCParameter(PrivateKey, value) ])
                                        : new HTTPS(name, DNSQueryClasses.IN, ttl, 1, target, [ new SVCParameter(PrivateKey, value) ]);

        var written  = record.ToZoneFileString();
        var reread   = SvcParams(Read(written)).Single(p => p.Key == PrivateKey).Value;

        Assert.That(reread, Is.EqualTo(value), $"written as: {written}");

    }


    /// <summary>
    /// The control: a value with nothing to decode was always read right.
    /// </summary>
    [Test]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void A_Value_With_Nothing_To_Decode_Is_Its_Own_Octets(String Type)
    {

        Assert.Multiple(() => {
            Assert.That(PrivateValue(Type, "key65280=abc"),     Is.EqualTo("abc"u8.ToArray()));
            Assert.That(PrivateValue(Type, "key65280=\"a c\""), Is.EqualTo("a c"u8.ToArray()));
        });

    }

}

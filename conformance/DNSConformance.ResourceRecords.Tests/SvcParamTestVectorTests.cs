using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 9460 Appendix D.2, the ServiceMode test vectors: each presentation form
/// against the wire format the RFC prints beside it.
/// </summary>
/// <remarks>
/// <para>
/// §2.1: "The SvcParamValue is parsed using the character-string decoding
/// algorithm (Appendix A), producing a value. The value is then validated and
/// converted into wire format in a manner specific to each key." §7 gives each
/// key its format: "port" is "the corresponding 2-octet numeric value in network
/// byte order"; an "alpn" value is alpn-ids "prefixed by its length as a single
/// octet"; the address hints are "a sequence of IP addresses in network byte
/// order"; and "mandatory" holds keys "represented by their numeric values in
/// network byte order, concatenated in strictly increasing numeric order".
/// </para>
/// <para>
/// HTTPS is "a SVCB-compatible RR type" (§9) with its own copy of the code in
/// Hermod, so every vector is asked of both. The vectors are SVCB's; the RDATA
/// is the same for HTTPS.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "9460 Appendix D.2")]
[Property("RFC", "9460 §2.1")]
[Property("RFC", "9460 §7")]
public class SvcParamTestVectorTests
{

    #region Data

    private const String FooCom  = "03666f6f076578616d706c6503636f6d00";
    private const String FooOrg  = "03666f6f076578616d706c65036f726700";

    /// <summary>
    /// Figure, RDATA in presentation format, RDATA on the wire, the finding it
    /// tracks (null for the vectors Hermod already reads right), and the
    /// presentation the writer must give back for it.
    /// </summary>
    private static readonly (String Figure, String Rdata, String Wire, Int32? Finding, String? Written)[] Vectors = [

        ("3",   "1 .",
                "0001" + "00",
                null, null),

        ("4",   "16 foo.example.com. port=53",
                "0010" + FooCom + "0003" + "0002" + "0035",
                89, "port=53"),

        ("5",   "1 foo.example.com. key667=hello",
                "0001" + FooCom + "029b" + "0005" + "68656c6c6f",
                null, null),

        ("6",   "1 foo.example.com. key667=\"hello\\210qoo\"",
                "0001" + FooCom + "029b" + "0009" + "68656c6c6fd2716f6f",
                88, null),

        ("7",   "1 foo.example.com. ipv6hint=\"2001:db8::1,2001:db8::53:1\"",
                "0001" + FooCom + "0006" + "0020" + "20010db8000000000000000000000001" + "20010db8000000000000000000530001",
                89, "ipv6hint="),

        ("8",   "1 example.com. ipv6hint=\"2001:db8:122:344::192.0.2.33\"",
                "0001" + "076578616d706c6503636f6d00" + "0006" + "0010" + "20010db80122034400000000c0000221",
                89, "ipv6hint="),

        ("9",   "16 foo.example.org. alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1",
                "0010" + FooOrg + "0000" + "0004" + "00010004" + "0001" + "0009" + "026832" + "0568332d3139" + "0004" + "0004" + "c0000201",
                89, "mandatory=alpn,ipv4hint"),

        ("10a", "16 foo.example.org. alpn=\"f\\\\\\\\oo\\\\,bar,h2\"",
                "0010" + FooOrg + "0001" + "000c" + "08665c6f6f2c626172" + "026832",
                89, "alpn="),

        ("10b", "16 foo.example.org. alpn=f\\\\\\092oo\\092,bar,h2",
                "0010" + FooOrg + "0001" + "000c" + "08665c6f6f2c626172" + "026832",
                89, "alpn="),

    ];


    private static IEnumerable<TestCaseData> Cases(Boolean WithWritten, String Direction)
    {
        foreach (var type in new[] { "SVCB", "HTTPS" })
            foreach (var (figure, rdata, wire, finding, written) in Vectors)
            {

                if (WithWritten && written is null && finding is not null)
                    continue;

                var data = new TestCaseData(type, rdata, wire, written).
                               SetName($"{Direction} {type}, Figure {figure}");

                yield return finding is null ? data : data.SetCategory(TestCategories.KnownIssue);

            }
    }

    private static IEnumerable<TestCaseData> PresentationCases()  => Cases(WithWritten: false, "Read");
    private static IEnumerable<TestCaseData> WireCases()          => Cases(WithWritten: true,  "Written");


    private static IDNSResourceRecord Read(String Line)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");
        return record!;
    }

    private static String Hex(Byte[] Octets)
        => Convert.ToHexString(Octets).ToLowerInvariant();

    #endregion


    /// <summary>
    /// Findings 88 and 89: the presentation form reads as the RFC's wire format.
    /// </summary>
    [Test]
    [TestCaseSource(nameof(PresentationCases))]
    public void The_Presentation_Form_Is_Read_As_The_Wire_Format_The_Rfc_Prints(String Type, String Rdata, String Wire, String? Written)
    {

        var record = Read($"example.com. 3600 IN {Type} {Rdata}");

        Assert.That(Hex(RRWire.Encode(record).Rdata), Is.EqualTo(Wire), $"read from: {Rdata}");

    }


    /// <summary>
    /// Finding 89: the wire format is written in the key's own presentation, and
    /// that reads back as the same octets.
    /// </summary>
    [Test]
    [TestCaseSource(nameof(WireCases))]
    public void The_Wire_Format_Is_Written_In_Each_Keys_Own_Presentation(String Type, String Rdata, String Wire, String? Written)
    {

        // From the RFC 3597 generic form, so the octets are the RFC's and not
        // whatever Hermod's presentation reader makes of the text beside them.
        var record   = Read($"example.com. 3600 IN {Type} \\# {Wire.Length / 2} {Wire}");
        var rendered = record.ToZoneFileString();
        var reread   = Read(rendered);

        Assert.Multiple(() => {

            Assert.That(Hex(RRWire.Encode(reread).Rdata), Is.EqualTo(Wire),
                        $"written as: {rendered.Trim()}");

            if (Written is not null)
                Assert.That(rendered.Replace("\"", ""), Does.Contain(Written),
                            $"a well-formed value is written in its key's format, not as the opaque octets: {rendered.Trim()}");

        });

    }

}

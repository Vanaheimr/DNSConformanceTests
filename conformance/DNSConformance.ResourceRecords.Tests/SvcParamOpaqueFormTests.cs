using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// A value that is not well-formed for its key is written in the unknown-key
/// form, and reads back as the octets it was.
/// </summary>
/// <remarks>
/// <para>
/// RFC 9460 §2.1: "Arbitrary keys can be represented using the unknown-key
/// presentation format "keyNNNNN"", and for that form "the decoded value SHALL
/// be used as its wire-format encoding". So every SvcParam has a presentation,
/// whatever its octets: key3="\000" is a port of one octet, which "port=" cannot
/// write. §2.2 tells a client to consider such a record malformed; a server or a
/// zone tool that holds one still has to write it as it is, or the zone it saves
/// is a different zone from the one it loaded.
/// </para>
/// <para>
/// From the mutation sweep of Vanaheimr/Hermod#191 (<see href="../../MUTATION.md"/>,
/// the `svcparam` slice). Finding 89's fix taught the writer each key's own
/// presentation, and a check for each key decides whether the octets are well
/// formed enough for it. Every test so far handed it octets that were: the RFC's
/// own vectors. None of those checks had a case that failed it.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "9460 §2.1")]
[Property("RFC", "9460 §2.2")]
[Property("RFC", "3597 §5")]
public class SvcParamOpaqueFormTests
{

    #region Data

    private static IDNSResourceRecord Read(String Line)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");
        return record!;
    }

    private static String Hex(Byte[] Octets)
        => Convert.ToHexString(Octets).ToLowerInvariant();

    // A well-formed alpn ("h2") and port (443), for a mandatory that lists them.
    // RFC 9460 §2.4.3: "zone-file implementations SHOULD enforce self-consistency",
    // and §8: "listed keys MUST also appear in the SvcParams". A record that
    // lacks them is refused for that, which is not what these cases are about.
    private const String Alpn = "0001" + "0003" + "026832";
    private const String Port = "0003" + "0002" + "01bb";

    #endregion


    /// <summary>
    /// A value its key cannot hold is written so that it reads back unchanged.
    /// </summary>
    [Test]
    [TestCase("0000" + "0000",                            TestName = "{m}: a mandatory with no key in it")]
    [TestCase("0000" + "0003" + "000100"   + Alpn,        TestName = "{m}: a mandatory of three octets")]
    [TestCase("0000" + "0004" + "00030001" + Alpn + Port, TestName = "{m}: a mandatory whose keys are out of order")]
    [TestCase("0000" + "0004" + "00010001" + Alpn,        TestName = "{m}: a mandatory that lists a key twice")]
    [TestCase("0000" + "0002" + "0000",                   TestName = "{m}: a mandatory that lists itself")]
    [TestCase("0001" + "0001" + "00",                     TestName = "{m}: an alpn-id of no octets")]
    [TestCase("0001" + "0002" + "0268",                   TestName = "{m}: an alpn-id longer than the value")]
    [TestCase("0003" + "0003" + "000035",                 TestName = "{m}: a port of three octets")]
    [TestCase("0004" + "0000",                            TestName = "{m}: an ipv4hint with no address")]
    [TestCase("0004" + "0005" + "c000020101",             TestName = "{m}: an ipv4hint of five octets")]
    [TestCase("0006" + "0004" + "c0000201",               TestName = "{m}: an ipv6hint of four octets")]
    public void A_Value_Its_Key_Cannot_Hold_Is_Written_As_The_Octets_It_Is(String Param)
    {

        // Read from the RFC 3597 generic form, so the octets are exactly these.
        // SvcPriority 1, TargetName ".", and the SvcParam, with the keys a
        // mandatory lists after it.
        var wire = "0001" + "00" + Param;

        Assert.Multiple(() => {
            foreach (var type in new[] { "SVCB", "HTTPS" })
            {

                var record   = Read($"probe.example. 3600 IN {type} \\# {wire.Length / 2} {wire}");
                var written  = record.ToZoneFileString();

                Assert.That(ADNSResourceRecord.TryParseZoneFileString(written, out var reread, out var error),
                            Is.True,
                            $"{type}: Hermod cannot read what it wrote: {written.Trim()} ({error})");

                if (reread is not null)
                    Assert.That(Hex(RRWire.Encode(reread).Rdata), Is.EqualTo(wire),
                                $"{type}: written as {written.Trim()}");

            }
        });

    }

    /// <summary>
    /// An empty value is written as the key alone, in the unknown-key form as well.
    /// </summary>
    [Test]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void An_Empty_Value_Is_Written_As_The_Key_Alone_In_The_Unknown_Key_Form_Too(String Type)
    {

        // PresentationBoundaryTests pins this for "no-default-alpn", whose value
        // §7.1.1 says MUST be empty. A key Hermod has no format for takes the same
        // spelling: §2.1, "When the optional "=" and SvcParamValue are omitted,
        // the value is interpreted as empty". The unknown-key form has been a
        // branch of its own since finding 89, with its own test for an empty value.
        var wire     = "0001" + "00" + "ff00" + "0000";
        var written  = Read($"probe.example. 3600 IN {Type} \\# {wire.Length / 2} {wire}").ToZoneFileString();

        Assert.That(written.TrimEnd(), Does.EndWith(" key65280"), $"written as: {written.Trim()}");

    }

}

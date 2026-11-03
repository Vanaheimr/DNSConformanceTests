using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 9460 Appendix D.3, the failure cases: SvcParams that a reader of the
/// presentation format has to refuse.
/// </summary>
/// <remarks>
/// <para>
/// D.3: "This subsection contains test vectors that are not compliant with this
/// document." Six figures, each with its reason. Four of them are a value its key
/// cannot take, and Hermod's reader refuses those since finding 89 gave every key
/// its format. Two are about the SvcParams together rather than one value: a key
/// written twice (Figure 11), and a key that "mandatory" lists and the record
/// does not hold (Figure 14). Hermod read both until finding 90 was fixed, and
/// with them §7.1.1's own case of the same rule, "no-default-alpn" without
/// "alpn".
/// </para>
/// <para>
/// HTTPS is "a SVCB-compatible RR type" (§9), so every vector is asked of both.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "9460 Appendix D.3")]
[Property("RFC", "9460 §2.1")]
[Property("RFC", "9460 §2.4.3")]
[Property("RFC", "9460 §8")]
public class SvcParamFailureVectorTests
{

    #region Data

    private static Boolean Reads(String Type, String SvcParams)
        => ADNSResourceRecord.TryParseZoneFileString($"example.com. 3600 IN {Type} 1 foo.example.com. {SvcParams}",
                                                     out _,
                                                     out _);

    #endregion


    /// <summary>
    /// Finding 90, Figure 11: a key is written once.
    /// </summary>
    [Test]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void Figure_11_A_Key_Written_Twice_Is_Refused(String Type)
    {

        // §2.1: "Each SvcParamKey SHALL appear at most once in the SvcParams", and
        // "SvcParams in presentation format MAY appear in any order, but keys
        // MUST NOT be repeated." On the wire the two would be two SvcParams with
        // one key, and §2.2 tells every client to consider the record malformed
        // and "reject the entire RRset".
        Assert.That(Reads(Type, "key123=abc key123=def"), Is.False);

    }

    /// <summary>
    /// Finding 90, Figure 14: what "mandatory" lists, the record holds.
    /// </summary>
    [Test]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void Figure_14_A_Mandatory_Key_The_Record_Does_Not_Hold_Is_Refused(String Type)
    {

        // §8: "For self-consistency (Section 2.4.3), listed keys MUST also appear
        // in the SvcParams." §2.4.3: "Clients MUST reject any RR whose recognized
        // SvcParams are not self-consistent and MAY reject the entire RRset. To
        // help zone operators avoid this condition, zone-file implementations
        // SHOULD enforce self-consistency as well."
        Assert.That(Reads(Type, "mandatory=key123"), Is.False);

    }

    /// <summary>
    /// Finding 90, not one of D.3's figures but the same rule: "no-default-alpn"
    /// is only self-consistent beside "alpn".
    /// </summary>
    [Test]
    [Property("RFC", "9460 §7.1.1")]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void A_No_Default_Alpn_Without_Alpn_Is_Refused(String Type)
    {

        // §7.1.1: "When "no-default-alpn" is specified in an RR, "alpn" must also
        // be specified in order for the RR to be "self-consistent" (Section
        // 2.4.3)." SvcParamKeyFormatTests reads the two together.
        Assert.That(Reads(Type, "no-default-alpn"), Is.False);

    }

    /// <summary>
    /// The four figures Hermod refuses: a value its key cannot take.
    /// </summary>
    [Test]
    [TestCase("SVCB",  "mandatory",                           TestName = "{m}: SVCB, Figure 12, mandatory")]
    [TestCase("SVCB",  "alpn",                                TestName = "{m}: SVCB, Figure 12, alpn")]
    [TestCase("SVCB",  "port",                                TestName = "{m}: SVCB, Figure 12, port")]
    [TestCase("SVCB",  "ipv4hint",                            TestName = "{m}: SVCB, Figure 12, ipv4hint")]
    [TestCase("SVCB",  "ipv6hint",                            TestName = "{m}: SVCB, Figure 12, ipv6hint")]
    [TestCase("SVCB",  "no-default-alpn=abc",                 TestName = "{m}: SVCB, Figure 13")]
    [TestCase("SVCB",  "mandatory=mandatory",                 TestName = "{m}: SVCB, Figure 15")]
    [TestCase("SVCB",  "mandatory=key123,key123 key123=abc",  TestName = "{m}: SVCB, Figure 16")]
    [TestCase("HTTPS", "mandatory",                           TestName = "{m}: HTTPS, Figure 12, mandatory")]
    [TestCase("HTTPS", "alpn",                                TestName = "{m}: HTTPS, Figure 12, alpn")]
    [TestCase("HTTPS", "port",                                TestName = "{m}: HTTPS, Figure 12, port")]
    [TestCase("HTTPS", "ipv4hint",                            TestName = "{m}: HTTPS, Figure 12, ipv4hint")]
    [TestCase("HTTPS", "ipv6hint",                            TestName = "{m}: HTTPS, Figure 12, ipv6hint")]
    [TestCase("HTTPS", "no-default-alpn=abc",                 TestName = "{m}: HTTPS, Figure 13")]
    [TestCase("HTTPS", "mandatory=mandatory",                 TestName = "{m}: HTTPS, Figure 15")]
    [TestCase("HTTPS", "mandatory=key123,key123 key123=abc",  TestName = "{m}: HTTPS, Figure 16")]
    public void A_Value_Its_Key_Cannot_Take_Is_Refused(String Type, String SvcParams)
    {

        // Figure 12, "Missing SvcParamValues That Must Be Non-Empty"; Figure 13,
        // "The "no-default-alpn" SvcParamKey Value Must Be Empty"; Figure 15, "The
        // "mandatory" SvcParamKey Must Not Be Included in the Mandatory List";
        // Figure 16, "Multiple Instances of the Same SvcParamKey in the Mandatory
        // List".
        Assert.That(Reads(Type, SvcParams), Is.False);

    }

    /// <summary>
    /// The control: the same reader takes a record that is compliant.
    /// </summary>
    [Test]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void The_Same_Keys_Written_Compliantly_Are_Read(String Type)
    {

        // Figure 14 and Figure 16 made compliant: the listed key is there, once.
        Assert.That(Reads(Type, "mandatory=key123 key123=abc"), Is.True);

    }

}

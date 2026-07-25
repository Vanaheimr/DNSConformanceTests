using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Edns.Tests;

/// <summary>
/// RFC 7828 (edns-tcp-keepalive) and RFC 7830 / RFC 8467 (padding).
///
/// Both options are about how a message is shaped rather than what it says, and
/// both have asymmetric rules — a query and a response of the same option are
/// not allowed to look alike. That asymmetry is what is checked here.
/// </summary>
[TestFixture]
public class EdnsOptionPolicyTests
{

    #region Keepalive_Query_Option_Carries_No_Timeout()

    [Test]
    [Property("RFC", "7828 §3.2.1")]
    public void Keepalive_Query_Option_Carries_No_Timeout()
    {

        // RFC 7828 §3.2.1: a client signals keepalive support with an option whose
        // OPTION-LENGTH is 0. Sending a timeout from the client side would be
        // telling the server how long to hold *its* resources.
        var option = EDNSKeepaliveOption.CreateQuery();

        Assert.Multiple(() => {
            Assert.That(option.Code,        Is.EqualTo(11), "edns-tcp-keepalive is option code 11");
            Assert.That(option.Data,        Is.Empty,       "queries carry no TIMEOUT value");
            Assert.That(option.IdleTimeout, Is.Null);
        });

    }

    #endregion

    #region Keepalive_Response_Timeout_Is_In_Hundred_Millisecond_Units()

    [Test]
    [Property("RFC", "7828 §3.1")]
    public void Keepalive_Response_Timeout_Is_In_Hundred_Millisecond_Units()
    {

        // RFC 7828 §3.1: TIMEOUT is "an idle timeout value for the TCP connection,
        // specified in units of 100 milliseconds". 30 s is therefore 300 = 0x012C.
        var option = new EDNSKeepaliveOption(TimeSpan.FromSeconds(30));

        Assert.Multiple(() => {
            Assert.That(option.TimeoutValue, Is.EqualTo((UInt16) 300));
            Assert.That(option.Data,         Is.EqualTo(new Byte[] { 0x01, 0x2C }), "big-endian, two octets");
        });

    }

    #endregion

    #region Keepalive_Roundtrips_Through_The_Wire()

    [Test]
    [Property("RFC", "7828 §3.1")]
    public void Keepalive_Roundtrips_Through_The_Wire()
    {

        var parsedQuery     = EDNSKeepaliveOption.Parse([]);
        var parsedResponse  = EDNSKeepaliveOption.Parse([0x01, 0x2C]);

        Assert.Multiple(() => {

            Assert.That(parsedQuery.IdleTimeout,    Is.Null,
                        "a zero-length option is the query form, not a zero timeout");

            Assert.That(parsedResponse.IdleTimeout, Is.EqualTo(TimeSpan.FromSeconds(30)));

        });

    }

    #endregion

    #region Keepalive_Rejects_Lengths_Other_Than_0_Or_2(...)

    [TestCase(1, TestName = "Keepalive_Rejects_A_1_Byte_Option")]
    [TestCase(3, TestName = "Keepalive_Rejects_A_3_Byte_Option")]
    [TestCase(4, TestName = "Keepalive_Rejects_A_4_Byte_Option")]
    [Property("RFC", "7828 §3.1")]
    public void Keepalive_Rejects_Malformed_Lengths(Int32 length)
    {

        // Only 0 and 2 are defined. Anything else is malformed and must not be
        // silently reinterpreted as a timeout.
        Assert.That(
            () => EDNSKeepaliveOption.Parse(new Byte[length]),
            Throws.InstanceOf<ArgumentException>()
        );

    }

    #endregion

    #region Keepalive_Option_Is_Carried_In_The_Opt_Record()

    [Test]
    [Property("RFC", "7828 §3.2")]
    public void Keepalive_Option_Is_Carried_In_The_Opt_Record()
    {

        var packet   = DNSPacket.Query(
                           DNSServiceName.Parse("keepalive.example."),
                           4096,
                           true,
                           DnssecOK:     false,
                           EDNSOptions:  [EDNSKeepaliveOption.CreateQuery()],
                           DNSResourceRecordTypes.A
                       );

        var decoded  = RawDnsReader.Parse(packet.ToByteArray());
        var opt      = decoded.Additionals.Single(rr => rr.IsOpt);
        var edns     = RawEdns.From(opt);

        var keepalive = edns.Options.Single(o => o.Code == 11);

        Assert.That(keepalive.Data, Is.Empty,
                    "the zero-length query form must survive serialization");

    }

    #endregion

    #region Padding_Rounds_The_Message_To_A_Block_Boundary(...)

    [TestCase(100u, 128, 24,  TestName = "Padding_Pads_A_100_Byte_Message_To_128")]
    [TestCase(124u, 128, 0,   TestName = "Padding_Adds_Nothing_When_Already_Aligned")]
    [TestCase(130u, 128, 122, TestName = "Padding_Pads_A_130_Byte_Message_To_256")]
    [TestCase(100u, 468, 364, TestName = "Padding_Supports_The_468_Byte_Response_Block")]
    [Property("RFC", "8467 §4.1")]
    public void Padding_Rounds_The_Message_To_A_Block_Boundary(UInt32 currentLength,
                                                               Int32  blockSize,
                                                               Int32  expectedPadding)
    {

        // RFC 8467 §4.1 recommends padding queries to a multiple of 128 octets and
        // responses to a multiple of 468. The option's own 4-byte header counts
        // towards the total, which is the part that is easy to get wrong.
        var option = EDNSPaddingOption.Create(currentLength, (UInt16) blockSize);

        Assert.Multiple(() => {

            Assert.That(option.PaddingLength, Is.EqualTo(expectedPadding));

            Assert.That((currentLength + 4 + option.PaddingLength) % blockSize, Is.Zero,
                        "message + option header + padding must land on a block boundary");

        });

    }

    #endregion

    #region Padding_Bytes_Are_All_Zero()

    [Test]
    [Property("RFC", "7830 §3")]
    public void Padding_Bytes_Are_All_Zero()
    {

        // RFC 7830 §3: "The PADDING octets SHOULD be set to 0x00." Anything else
        // is a covert channel through an option whose entire purpose is to reveal
        // nothing.
        var option = EDNSPaddingOption.Create(100);

        Assert.Multiple(() => {
            Assert.That(option.Data, Has.Length.EqualTo(24));
            Assert.That(option.Data, Is.All.Zero);
        });

    }

    #endregion

    #region Padding_Default_Block_Size_Is_128()

    [Test]
    [Property("RFC", "8467 §4.1")]
    public void Padding_Default_Block_Size_Is_128()
    {

        Assert.That(EDNSPaddingOption.RecommendedBlockSize, Is.EqualTo(128));

    }

    #endregion

}

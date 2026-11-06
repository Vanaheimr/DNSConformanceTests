using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Multicast.Tests;

/// <summary>
/// Hermod's Multicast DNS message reader, <see cref="MulticastDNSMessage.TryParse"/>, held
/// to the message format of RFC 1035 §4.1 and the header bits of RFC 6762 §18.
/// </summary>
/// <remarks>
/// Everywhere else the reader is reached through a querier or a responder, and both drop
/// a packet they cannot read. Whether the reader refused it, or said it had read it and
/// handed over nothing, looks the same from outside: the caller fails on the nothing, and
/// the packet is dropped either way. Here the reader is asked directly.
/// </remarks>
[TestFixture]
public sealed class MulticastMessageConformanceTests
{

    #region Harness

    private static RawDnsWriter Header(UInt16  Flags        = 0,
                                       UInt16  Questions    = 0,
                                       UInt16  Answers      = 0,
                                       UInt16  Authorities  = 0,
                                       UInt16  Additionals  = 0)

        => new RawDnsWriter().Header(0, Flags, Questions, Answers, Authorities, Additionals);


    /// <summary>"a.local", written in full and ended.</summary>
    private static readonly Byte[] ShortName = [ 1, (Byte) 'a', 5, .. "local"u8, 0 ];


    public static IEnumerable<TestCaseData> Unwalkable()
    {

        yield return new TestCaseData(new Byte[11]).
                         SetName("Eleven octets, one short of a header");

        yield return new TestCaseData(Header(Questions: 1).Bytes(0x3F, (Byte) 'a', (Byte) 'b', (Byte) 'c').ToArray()).
                         SetName("A question name whose label runs past the end of the packet");

        yield return new TestCaseData(Header(Questions: 1).Bytes(1, (Byte) 'a').ToArray()).
                         SetName("A question name that ends with the packet, unterminated");

        yield return new TestCaseData(Header(Questions: 1).Bytes(ShortName).ToArray()).
                         SetName("A question without its type and class");

        yield return new TestCaseData(Header(Questions: 1).Bytes(0x40, 0, 1, 0, 1).ToArray()).
                         SetName("A question name with the label length 0x40");

        yield return new TestCaseData(Header(Questions: 1).
                                          Bytes([.. Enumerable.Repeat(new Byte[] { 1, (Byte) 'a' }, 129).SelectMany(label => label), 0, 0, 1, 0, 1]).
                                          ToArray()).
                         SetName("A question name of 129 labels");

        yield return new TestCaseData(Header(Answers: 1).Bytes(1, (Byte) 'a').ToArray()).
                         SetName("An answer whose name runs past the end of the packet");

        yield return new TestCaseData(Header(Answers: 1).Bytes(ShortName).Bytes(0, 1, 0, 1, 0).ToArray()).
                         SetName("An answer that ends within its fixed fields");

        yield return new TestCaseData(Header(Answers: 1).Bytes(ShortName).U16(RawDnsType.A).U16(RawDnsClass.IN).U32(120).U16(4).Bytes(192, 0).ToArray()).
                         SetName("An answer whose RDATA runs past the end of the packet");

        yield return new TestCaseData(Header(Authorities: 1).Bytes(1, (Byte) 'a').ToArray()).
                         SetName("A broken authority section with no additional section after it");

    }


    #endregion


    /// <summary>
    /// RFC 1035 §4.1 lays a message out as a header of twelve octets and four sections, and
    /// a name as labels up to one of length zero (§3.1), or a pointer (§4.1.4), with label
    /// lengths of 63 at most and the top two bits for pointers (§4.1.4). A packet that ends
    /// inside any of that, or that the layout cannot walk, is no message, and the reader
    /// says so.
    /// </summary>
    [TestCaseSource(nameof(Unwalkable))]
    [Property("RFC", "1035 §3.1, §4.1, §4.1.4")]
    public void A_Packet_That_Cannot_Be_Walked_Is_Refused(Byte[] Packet)
    {

        var parsed = MulticastDNSMessage.TryParse(Packet, out var message, out var error);

        Assert.Multiple(() => {
            Assert.That(parsed,  Is.False,           "the reader refuses the packet");
            Assert.That(message, Is.Null,            "and hands over no message");
            Assert.That(error,   Is.Not.Null.And.Not.Empty, "but says why");
        });

    }


    /// <summary>
    /// RFC 1035 §4.1: the four sections follow the header, and any of them may be empty. A
    /// header of twelve octets that counts nothing is a message with nothing in it.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1")]
    public void A_Header_Alone_Is_A_Message()
    {

        var parsed = MulticastDNSMessage.TryParse(Header().ToArray(), out var message, out var error);

        Assert.Multiple(() => {
            Assert.That(parsed, Is.True, error);
            Assert.That(message?.Questions.Count + message?.Answers.Count + message?.Authorities.Count + message?.Additionals.Count,
                        Is.EqualTo(0));
        });

    }


    /// <summary>
    /// RFC 1035 §4.1.1 puts AA at 0x04 and RD at 0x01 of the third header octet, and RFC
    /// 6762 §18.4 and §18.6 leave them there. The reader reads each where it is.
    /// </summary>
    [TestCase((UInt16) 0x8400, true,  false, TestName = "AA set and RD clear are read as such")]
    [TestCase((UInt16) 0x8100, false, true,  TestName = "AA clear and RD set are read as such")]
    [Property("RFC", "1035 §4.1.1, 6762 §18.4, §18.6")]
    public void The_Header_Bits_Are_Read_Where_They_Are(UInt16 Flags, Boolean AuthoritativeAnswer, Boolean RecursionDesired)
    {

        var parsed = MulticastDNSMessage.TryParse(Header(Flags).ToArray(), out var message, out var error);

        Assert.Multiple(() => {
            Assert.That(parsed,                        Is.True, error);
            Assert.That(message?.AuthoritativeAnswer,  Is.EqualTo(AuthoritativeAnswer), "AA, 0x04 of the third octet");
            Assert.That(message?.RecursionDesired,     Is.EqualTo(RecursionDesired),    "RD, 0x01 of the third octet");
        });

    }


    /// <summary>
    /// A question asks for a name, a type and a class (RFC 1035 §4.1.2), and a record answers
    /// it when all three agree, a QTYPE or QCLASS of 255 agreeing with any (§3.2.3, §3.2.5).
    /// <see cref="MulticastDNSQuestion.Matches"/> says whether a record answers a question.
    /// </summary>
    [TestCase(DNSResourceRecordTypes.A,   DNSQueryClasses.IN,  DNSQueryClasses.IN, true,  TestName = "An address of class IN answers a question of class IN")]
    [TestCase(DNSResourceRecordTypes.A,   DNSQueryClasses.IN,  DNSQueryClasses.CH, false, TestName = "An address of class CH does not answer a question of class IN")]
    [TestCase(DNSResourceRecordTypes.A,   DNSQueryClasses.ANY, DNSQueryClasses.CH, true,  TestName = "An address of class CH answers a question of class ANY")]
    [TestCase(DNSResourceRecordTypes.Any, DNSQueryClasses.IN,  DNSQueryClasses.IN, true,  TestName = "An address answers a question of type ANY")]
    [Property("RFC", "1035 §3.2.3, §3.2.5, §4.1.2")]
    public void A_Question_Is_Answered_By_Records_Of_Its_Name_Type_And_Class(DNSResourceRecordTypes  QuestionType,
                                                                             DNSQueryClasses         QuestionClass,
                                                                             DNSQueryClasses         RecordClass,
                                                                             Boolean                 Answers)
    {

        var name      = DNSServiceName.Parse("match.local.");
        var question  = new MulticastDNSQuestion(name, QuestionType, false, QuestionClass);
        var record    = new A(name, RecordClass, TimeSpan.FromSeconds(120), IPv4Address.Parse("192.0.2.7"));

        Assert.That(question.Matches(record), Is.EqualTo(Answers));

    }

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

namespace DNSConformance.WireFormat.Tests;

/// <summary>
/// RFC 1035 §4.1.1 — header section format. Hermod-serialized messages are
/// decoded with the independent RawDns reader and vice versa.
/// </summary>
[TestFixture]
[Property("RFC", "1035")]
public class HeaderTests
{

    #region Query_Serialization_Matches_Independent_Golden_Encoding()

    [Test]
    public void Query_Serialization_Matches_Independent_Golden_Encoding()
    {

        var packet  = DNSPacket.Query(
                          DNSServiceName.Parse("example.com"),
                          0,                                     // no EDNS
                          DNSResourceRecordTypes.A
                      );

        var actual  = packet.ToByteArray();

        // RFC 1035 §4.1.1: same ID, RD=1, QDCOUNT=1 — byte-identical to the
        // independent encoder's output.
        var golden  = RawDnsWriter.Query(
                          (UInt16) packet.TransactionId,
                          "example.com",
                          RawDnsType.A,
                          recursionDesired: true
                      );

        Assert.That(actual, Is.EqualTo(golden), Bytes.Diff(golden, actual));

    }

    #endregion

    #region Query_Header_Field_Positions()

    [Test]
    public void Query_Header_Field_Positions()
    {

        var packet   = DNSPacket.Query(
                           DNSServiceName.Parse("example.com"),
                           0,
                           DNSResourceRecordTypes.AAAA
                       );

        var decoded  = RawDnsReader.Parse(packet.ToByteArray());

        Assert.Multiple(() => {
            Assert.That(decoded.Id,               Is.EqualTo((UInt16) packet.TransactionId), "ID (RFC 1035 §4.1.1)");
            Assert.That(decoded.QR,               Is.False,  "QR must be 0 in queries");
            Assert.That(decoded.Opcode,           Is.Zero,   "Opcode QUERY = 0");
            Assert.That(decoded.AA,               Is.False,  "AA has no meaning in queries");
            Assert.That(decoded.TC,               Is.False,  "TC must be clear");
            Assert.That(decoded.RD,               Is.True,   "RD requested");
            Assert.That(decoded.RA,               Is.False,  "RA has no meaning in queries");
            Assert.That(decoded.Z,                Is.Zero,   "Z is reserved and MUST be zero (RFC 1035 §4.1.1)");
            Assert.That(decoded.RCode,            Is.Zero);
            Assert.That(decoded.Questions,        Has.Count.EqualTo(1));
            Assert.That(decoded.Answers,          Is.Empty);
            Assert.That(decoded.Authorities,      Is.Empty);
            Assert.That(decoded.Additionals,      Is.Empty);
            Assert.That(decoded.ConsumedBytes,    Is.EqualTo(decoded.Wire.Length), "no trailing bytes");
        });

    }

    #endregion

    #region Question_Encoding_Type_And_Class()

    [Test]
    [Property("RFC", "1035 §4.1.2")]
    public void Question_Encoding_Type_And_Class()
    {

        var packet   = DNSPacket.Query(
                           DNSServiceName.Parse("www.example.org"),
                           0,
                           DNSResourceRecordTypes.MX
                       );

        var decoded  = RawDnsReader.Parse(packet.ToByteArray());
        var question = decoded.Questions.Single();

        Assert.Multiple(() => {
            Assert.That(question.Name.Presentation, Is.EqualTo("www.example.org"));
            Assert.That(question.Type,              Is.EqualTo(RawDnsType.MX),     "QTYPE code point 15");
            Assert.That(question.Class,             Is.EqualTo(RawDnsClass.IN),    "QCLASS code point 1");
        });

    }

    #endregion

    #region Response_Flag_Bits_Are_Encoded_At_Correct_Positions()

    [Test]
    public void Response_Flag_Bits_Are_Encoded_At_Correct_Positions()
    {

        var request   = DNSPacket.Query(DNSServiceName.Parse("flags.example."), 0, DNSResourceRecordTypes.A);

        var response  = request.CreateResponse(
                            Opcode:               0,
                            AuthoritativeAnswer:  true,
                            Truncation:           true,
                            RecursionDesired:     true,
                            RecursionAvailable:   true,
                            ResponseCode:         DNSResponseCodes.Refused,   // 5
                            AnswerRRs:            [],
                            AuthorityRRs:         [],
                            AdditionalRRs:        []
                        );

        var decoded   = RawDnsReader.Parse(response.ToByteArray());

        Assert.Multiple(() => {
            Assert.That(decoded.Id,      Is.EqualTo((UInt16) request.TransactionId), "ID echoed");
            Assert.That(decoded.QR,      Is.True,               "QR=1 in responses");
            Assert.That(decoded.AA,      Is.True,               "AA bit 0x0400");
            Assert.That(decoded.TC,      Is.True,               "TC bit 0x0200");
            Assert.That(decoded.RD,      Is.True,               "RD copied from request");
            Assert.That(decoded.RA,      Is.True,               "RA bit 0x0080");
            Assert.That(decoded.Z,       Is.Zero,               "Z reserved, MUST be zero");
            Assert.That(decoded.RCode,   Is.EqualTo(5),         "REFUSED = 5 (RFC 1035 §4.1.1)");
        });

    }

    #endregion

    #region All_RCodes_Serialize_To_Their_IANA_Code_Points()

    [TestCase(DNSResponseCodes.NoError,         0)]
    [TestCase(DNSResponseCodes.FormatError,     1)]
    [TestCase(DNSResponseCodes.ServerFailure,   2)]
    [TestCase(DNSResponseCodes.NameError,       3)]
    [TestCase(DNSResponseCodes.NotImplemented,  4)]
    [TestCase(DNSResponseCodes.Refused,         5)]
    public void All_RCodes_Serialize_To_Their_IANA_Code_Points(DNSResponseCodes rcode, Int32 expected)
    {

        var request   = DNSPacket.Query(DNSServiceName.Parse("rcode.example."), 0, DNSResourceRecordTypes.A);

        var response  = request.CreateResponse(
                            0, false, false, false, false,
                            rcode,
                            [], [], []
                        );

        var decoded   = RawDnsReader.Parse(response.ToByteArray());

        Assert.That(decoded.RCode, Is.EqualTo(expected));

    }

    #endregion

    #region Opcode_Is_Encoded_In_Bits_11_To_14()

    [TestCase(0)]   // QUERY
    [TestCase(2)]   // STATUS
    [TestCase(4)]   // NOTIFY
    [TestCase(5)]   // UPDATE
    public void Opcode_Is_Encoded_In_Bits_11_To_14(Int32 opcode)
    {

        var packet   = new DNSPacket(
                           TransactionId:        0x1234,
                           QueryOrResponse:      DNSQueryResponse.Query,
                           Opcode:               (Byte) opcode,
                           AuthoritativeAnswer:  false,
                           Truncation:           false,
                           RecursionDesired:     false,
                           RecursionAvailable:   false,
                           ResponseCode:         DNSResponseCodes.NoError,
                           Questions:            [ new DNSQuestion(DNSServiceName.Parse("opcode.example."), DNSResourceRecordTypes.A, DNSQueryClasses.IN) ],
                           AnswerRRs:            [],
                           AuthorityRRs:         [],
                           AdditionalRRs:        []
                       );

        var decoded  = RawDnsReader.Parse(packet.ToByteArray());

        Assert.That(decoded.Opcode, Is.EqualTo((Byte) opcode));

    }

    #endregion

    #region Hermod_Parses_RawDns_Crafted_Header()

    [Test]
    public void Hermod_Parses_RawDns_Crafted_Header()
    {

        // Craft a response-shaped message with every flag set that Hermod models.
        var wire    = new RawDnsWriter()
                          .Header(
                               0xBEEF,
                               (UInt16) (RawDnsFlags.QR | RawDnsFlags.AA | RawDnsFlags.TC |
                                         RawDnsFlags.RD | RawDnsFlags.RA | RawDnsFlags.RCode(3)),
                               1, 0, 0, 0
                           )
                          .Question("hermod.example.", RawDnsType.A)
                          .ToArray();

        var packet  = DNSPacket.Parse(
                          IPSocket.Zero,
                          IPSocket.Zero,
                          new MemoryStream(wire)
                      );

        Assert.Multiple(() => {
            Assert.That((UInt16) packet.TransactionId,  Is.EqualTo((UInt16) 0xBEEF));
            Assert.That(packet.QueryOrResponse,         Is.EqualTo(DNSQueryResponse.Response));
            Assert.That(packet.AuthoritativeAnswer,     Is.True);
            Assert.That(packet.Truncation,              Is.True);
            Assert.That(packet.RecursionDesired,        Is.True);
            Assert.That(packet.RecursionAvailable,      Is.True);
            Assert.That(packet.ResponseCode,            Is.EqualTo(DNSResponseCodes.NameError));
            Assert.That(packet.Questions.Count(),       Is.EqualTo(1));
            Assert.That(packet.Questions.Single().DomainName.FullName.TrimEnd('.'),
                        Is.EqualTo("hermod.example").IgnoreCase);
        });

    }

    #endregion

    #region Section_Counts_Reflect_Actual_Section_Sizes()

    [Test]
    public void Section_Counts_Reflect_Actual_Section_Sizes()
    {

        var answer    = new A(DomainName.Parse("counts.example."), DNSQueryClasses.IN, TimeSpan.FromSeconds(60), IPv4Address.Parse("192.0.2.7"));
        var authority = new NS(DomainName.Parse("example."),       DNSQueryClasses.IN, TimeSpan.FromSeconds(60), DomainName.Parse("ns1.example."));

        var packet    = new DNSPacket(
                            0x0042,
                            DNSQueryResponse.Response,
                            0, true, false, false, false,
                            DNSResponseCodes.NoError,
                            [ new DNSQuestion(DNSServiceName.Parse("counts.example."), DNSResourceRecordTypes.A, DNSQueryClasses.IN) ],
                            [ answer ],
                            [ authority ],
                            []
                        );

        var decoded   = RawDnsReader.Parse(packet.ToByteArray());

        Assert.Multiple(() => {
            Assert.That(decoded.Questions,   Has.Count.EqualTo(1));
            Assert.That(decoded.Answers,     Has.Count.EqualTo(1));
            Assert.That(decoded.Authorities, Has.Count.EqualTo(1));
            Assert.That(decoded.Additionals, Is.Empty);
            Assert.That(decoded.Answers[0].Type,     Is.EqualTo(RawDnsType.A));
            Assert.That(decoded.Authorities[0].Type, Is.EqualTo(RawDnsType.NS));
        });

    }

    #endregion

}

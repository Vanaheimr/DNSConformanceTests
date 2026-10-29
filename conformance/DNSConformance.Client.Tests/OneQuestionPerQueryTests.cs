using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// A query carries one question, whatever the caller asked for.
/// </summary>
/// <remarks>
/// <para>
/// RFC 9619 §4, which updates RFC 1035: "A DNS message with OPCODE = 0 MUST NOT
/// include a QDCOUNT parameter whose value is greater than 1. It follows that the
/// Question section of a DNS message with OPCODE = 0 MUST NOT contain more than
/// one question." And from the other side, in the same section: such a message
/// "MUST be treated as an incorrectly formatted message", answered with FORMERR.
/// So a query asking two questions is not a query a server is allowed to answer.
/// </para>
/// <para>
/// <see cref="MultiTypeQueryTests"/> shows that <c>DNSClient</c> splits several
/// types into several queries. The transport clients take the same list in the
/// same <c>IDNSClient</c> signature and are public in their own right; this file
/// asks each of them.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "9619 §4")]
public class OneQuestionPerQueryTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);

    private static readonly DNSResourceRecordTypes[] TwoTypes = [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ];


    /// <summary>
    /// Answers a one-question query and stays silent for any other: a server
    /// following RFC 9619 would send FORMERR, and silence is enough to make the
    /// count the only thing that differs.
    /// </summary>
    private static Byte[]? AnswerOneQuestion(Byte[] Request)
    {

        var questions = RawDnsReader.Parse(Request).Questions;

        return questions.Count == 1
                   ? RawDnsResponder.Answer(Request, ($"{questions[0].Name.Canonical}.", RawDnsType.A, 60, [192, 0, 2, 31]))
                   : null;

    }


    private static Int32[] QuestionCounts(IEnumerable<Byte[]> Requests)
        => [.. Requests.Select(request => RawDnsReader.Parse(request).Questions.Count)];


    private static void AssertOneQuestionEach(Int32[] Counts, String Transport)
        => Assert.Multiple(() => {
               Assert.That(Counts, Is.Not.Empty, $"{Transport}: something was sent");
               Assert.That(Counts, Is.All.EqualTo(1),
                           $"{Transport}: two types are two queries of one question each, never one query of two");
           });

    #endregion


    /// <summary>
    /// Finding 86, over UDP.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Udp_Query_For_Two_Types_Asks_One_Question_At_A_Time()
    {

        await using var server = new ScriptedUdpServer(AnswerOneQuestion);
        await using var client = new DNSUDPClient(IPv4Address.Localhost,
                                                  IPPort.Parse((UInt16) server.Port),
                                                  QueryTimeout: Timeout);

        await client.Query(DNSServiceName.Parse("two.example."), TwoTypes, Timeout);

        AssertOneQuestionEach(QuestionCounts(server.Requests), "UDP");

    }


    /// <summary>
    /// Finding 86, over TCP.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Tcp_Query_For_Two_Types_Asks_One_Question_At_A_Time()
    {

        await using var server = new ScriptedTcpServer(AnswerOneQuestion);
        await using var client = new DNSTCPClient(IPv4Address.Localhost,
                                                  Port:          IPPort.Parse((UInt16) server.Port),
                                                  QueryTimeout:  Timeout);

        await client.Query(DNSServiceName.Parse("two.example."), TwoTypes, Timeout);

        AssertOneQuestionEach(QuestionCounts(server.Requests), "TCP");

    }


    /// <summary>
    /// Finding 86, over TLS.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Dot_Query_For_Two_Types_Asks_One_Question_At_A_Time()
    {

        await using var server = new ScriptedTlsServer(AnswerOneQuestion);
        await using var client = new DNSTLSClient(IPv4Address.Localhost,
                                                  TCPPort:                     IPPort.Parse((UInt16) server.Port),
                                                  QueryTimeout:                Timeout,
                                                  RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success());

        await client.Query(DNSServiceName.Parse("two.example."), TwoTypes, Timeout);

        AssertOneQuestionEach(QuestionCounts(server.Requests), "DoT");

    }


    /// <summary>
    /// Finding 86, over DoH in RFC 8484's own format. The JSON mode asks one type
    /// per request already, because its API has no way to ask two.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Doh_Query_For_Two_Types_Asks_One_Question_At_A_Time()
    {

        await using var server = new ScriptedDoHServer(AnswerOneQuestion);
        await using var client = new DNSHTTPSClient(URL.Parse(server.Url), QueryTimeout: Timeout);

        await client.Query(DNSServiceName.Parse("two.example."), TwoTypes, Timeout);

        AssertOneQuestionEach(QuestionCounts(server.Exchanges.Select(exchange => exchange.DnsMessage)), "DoH");

    }

}

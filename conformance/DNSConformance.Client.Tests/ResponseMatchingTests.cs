using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 5452 §9.1 — what a resolver must match before it believes a response.
/// </summary>
/// <remarks>
/// <para>
/// The requirement is a list, and the list is a MUST:
/// </para>
/// <para>
/// "A resolver implementation MUST match responses to all of the following
/// attributes of the query: … Query ID, Query name, Query class and type … A
/// mismatch and the response MUST be considered invalid."
/// </para>
/// <para>
/// §3 says the same from the other side — data is accepted "if and only if" the
/// question section of the reply is equivalent to that of a question waiting for
/// an answer — and §4.2 spells out that the question section is what has to be
/// verified. The transaction ID was being matched and nothing else, which left
/// sixteen bits doing the work of a check the RFC writes out in three lines.
/// </para>
/// <para>
/// Equivalence of names is RFC 4343's: case-insensitive. A resolver that folds
/// the QNAME to lower case before answering — many do — is returning the same
/// name, and <c>A_Lowercased_Question_Is_Still_The_Same_Question</c> holds that
/// door open, because a fix for this that compared octets would close it.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "5452 §9.1")]
public class ResponseMatchingTests
{

    #region Data

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromSeconds(3);

    private const String Asked = "asked.example.";

    /// <summary>
    /// A well-formed response carrying an answer, but for a question the client
    /// never asked.
    /// </summary>
    private static Byte[] AnsweringSomethingElse(Byte[]  Request,
                                                 String  Name,
                                                 UInt16  Type,
                                                 UInt16  Class)
    {

        var query = RawDnsReader.Parse(Request, RawDnsReaderOptions.Lenient);

        return new RawDnsWriter().
                   Header(query.Id,
                          (UInt16) (RawDnsFlags.QR | RawDnsFlags.RD | RawDnsFlags.RA),
                          1, 1, 0, 0).
                   Question(Name, Type, Class).
                   RR(Asked, RawDnsType.A, RawDnsClass.IN, 60, RawDnsWriter.IPv4("6.6.6.6")).
                   ToArray();

    }

    /// <summary>
    /// The forged answer first, the genuine one after it — so a passing test
    /// shows the client ignored the forgery rather than merely failing to
    /// finish.
    /// </summary>
    private static async Task<DNSInfo<A>> AskAfter(Func<Byte[], Byte[]> Forgery)
    {

        await using var server = new ScriptedUdpServer((request, _) => new[] {
                                     Forgery(request),
                                     RawDnsResponder.Answer(request, (Asked, RawDnsType.A, 60, RawDnsWriter.IPv4("192.0.2.99")))
                                 });

        await using var client = new DNSUDPClient(IPv4Address.Localhost,
                                                  IPPort.Parse((UInt16) server.Port),
                                                  QueryTimeout: ShortTimeout);

        return await client.Query<A>(DomainName.Parse(Asked), ShortTimeout);

    }

    private static void AssertTheForgeryWasIgnored(DNSInfo<A> Response, String What)

        => Assert.Multiple(() => {

               Assert.That(Response.FilteredAnswers.Any(a => a.IPv4Address.ToString() == "6.6.6.6"),
                           Is.False,
                           $"a response {What} must never be believed");

               Assert.That(Response.FilteredAnswers.Select(a => a.IPv4Address.ToString()),
                           Is.EqualTo(new[] { "192.0.2.99" }),
                           "and the genuine answer must still arrive — ignoring is not aborting");

           });

    #endregion

    #region A_Response_To_Another_Name_Is_Not_The_Answer()

    [Test]
    public async Task A_Response_To_Another_Name_Is_Not_The_Answer()
    {

        // The query name is the second item on §9.1's list, and the one an
        // attacker has the least reason to get right: a forged datagram is aimed
        // at a transaction ID, and the question it carries is whatever the
        // forger happened to put there.
        var response = await AskAfter(request => AnsweringSomethingElse(request, "elsewhere.example.", RawDnsType.A, RawDnsClass.IN));

        AssertTheForgeryWasIgnored(response, "asking about another name");

    }

    #endregion

    #region A_Response_About_Another_Type_Is_Not_The_Answer()

    [Test]
    public async Task A_Response_About_Another_Type_Is_Not_The_Answer()
    {

        var response = await AskAfter(request => AnsweringSomethingElse(request, Asked, RawDnsType.MX, RawDnsClass.IN));

        AssertTheForgeryWasIgnored(response, "about another type");

    }

    #endregion

    #region A_Response_In_Another_Class_Is_Not_The_Answer()

    [Test]
    public async Task A_Response_In_Another_Class_Is_Not_The_Answer()
    {

        // §9.1 names class and type together, and class is the one nobody
        // remembers — which is exactly why it is worth a test of its own.
        var response = await AskAfter(request => AnsweringSomethingElse(request, Asked, RawDnsType.A, 3 /* CH */));

        AssertTheForgeryWasIgnored(response, "in another class");

    }

    #endregion

    #region A_Response_With_No_Question_Is_Not_The_Answer()

    [Test]
    public async Task A_Response_With_No_Question_Is_Not_The_Answer()
    {

        // §3: data is accepted "if and only if" the question section of the reply
        // is equivalent to one waiting for an answer. An empty question section
        // is not equivalent to a question — and it is the cheapest forgery to
        // build, since it needs no knowledge of what was asked.
        var response = await AskAfter(request => {

            var query = RawDnsReader.Parse(request, RawDnsReaderOptions.Lenient);

            return new RawDnsWriter().
                       Header(query.Id,
                              (UInt16) (RawDnsFlags.QR | RawDnsFlags.RD | RawDnsFlags.RA),
                              0, 1, 0, 0).
                       RR(Asked, RawDnsType.A, RawDnsClass.IN, 60, RawDnsWriter.IPv4("6.6.6.6")).
                       ToArray();

        });

        AssertTheForgeryWasIgnored(response, "carrying no question at all");

    }

    #endregion

    #region A_Lowercased_Question_Is_Still_The_Same_Question()

    [Test]
    [Property("RFC", "4343")]
    public async Task A_Lowercased_Question_Is_Still_The_Same_Question()
    {

        // The other side of the same check, and the reason it compares names
        // rather than octets. RFC 4343: "Domain Name System (DNS) Case
        // Insensitivity" — a resolver that normalises the QNAME before answering
        // has returned the same name, and refusing it would break against most
        // of the deployed world.
        await using var server = new ScriptedUdpServer((request, _) => new[] {
                                     RawDnsResponder.WithLowercasedQuestion(
                                         RawDnsResponder.Answer(request, (Asked, RawDnsType.A, 60, RawDnsWriter.IPv4("192.0.2.99"))))
                                 });

        await using var client = new DNSUDPClient(IPv4Address.Localhost,
                                                  IPPort.Parse((UInt16) server.Port),
                                                  QueryTimeout: ShortTimeout);

        var response = await client.Query<A>(DomainName.ParseLenient("AsKeD.ExAmPlE."), ShortTimeout);

        Assert.That(response.FilteredAnswers.Select(a => a.IPv4Address.ToString()),
                    Is.EqualTo(new[] { "192.0.2.99" }),
                    "a differently-cased echo of the question is the same question");

    }

    #endregion

}

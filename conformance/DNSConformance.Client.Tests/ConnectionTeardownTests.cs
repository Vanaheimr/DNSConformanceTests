using System.Diagnostics;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;

namespace DNSConformance.Client.Tests;

/// <summary>
/// What a stream client does with the queries on a connection that ends under
/// them.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7766 §6.2.4: "DNS clients SHOULD retry unanswered queries if the
/// connection closes before receiving all outstanding responses. No specific
/// retry algorithm is specified in this document." Both stream clients ask a
/// query once more on a new connection when the old one breaks under it, and
/// once only.
/// </para>
/// <para>
/// The bound is the other half. RFC 7858 §7: "To minimize state on DNS servers
/// and connection startup time, clients SHOULD minimize the creation of new TCP
/// connections." A server that ends every connection it is given gets the
/// query and the one retry, and the caller gets a failure - not a client that
/// keeps opening connections until the deadline runs out.
/// </para>
/// <para>
/// Every test here runs over TCP and over DoT, against a server that reads
/// queries as they arrive and tells its connections apart.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "7766 §6.2.4")]
public class ConnectionTeardownTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(4);

    private static readonly DNSResourceRecordTypes[] A = [ DNSResourceRecordTypes.A ];


    /// <summary>Whether the answer is the one the scripted server gives.</summary>
    private static Boolean Answered(DNSInfo Info)
        => Info.IsValid && Info.Answers.Count() == 1;

    #endregion


    #region A connection that ends between queries

    [TestCaseSource(typeof(StreamScriptServer), nameof(StreamScriptServer.Transports))]
    public async Task A_Query_On_A_Connection_The_Server_Closed_Is_Asked_Again_On_A_New_One(String Transport)
    {

        // The server answers the first query and closes. The client does not
        // notice until it uses the connection again: its next query goes out on
        // the closed one, and the end of the stream is where it learns. That
        // query is unanswered on a connection that closed, which is §6.2.4's
        // case exactly.
        await using var server = new StreamScriptServer(Transport, async (connection, query) => {
                                     await connection.Answer(query);
                                     if (connection.Number == 1)
                                         connection.Close();
                                 });

        await using var client = server.NewClient(Timeout);

        var first  = await client.Query(DNSServiceName.Parse("first.example."),  A, Timeout);
        var second = await client.Query(DNSServiceName.Parse("second.example."), A, Timeout);

        Assert.Multiple(() => {

            Assert.That(Answered(first),         Is.True,                          "the first query was answered");
            Assert.That(Answered(second),        Is.True,                          "and the second one too, on the connection that replaced the closed one");
            Assert.That(server.ConnectionCount,  Is.EqualTo(2),                    "two connections, the second for the retry");
            Assert.That(server.Connections[1].Names,
                                                 Is.EqualTo(new[] { "second.example." }),
                                                                                   "on which the second query was asked");

        });

    }


    [TestCaseSource(typeof(StreamScriptServer), nameof(StreamScriptServer.Transports))]
    public async Task A_Query_On_A_Connection_The_Server_Reset_Is_Asked_Again_On_A_New_One(String Transport)
    {

        // A reset rather than a close, and it reaches the client while nothing
        // is outstanding: nobody is reading, so the next write is what fails.
        // That is a different place for a broken connection to show itself than
        // the end of a stream - the write rather than the read - and §6.2.4 does
        // not care which.
        await using var server = new StreamScriptServer(Transport, (connection, query) => connection.Answer(query));

        await using var client = server.NewClient(Timeout);

        var first  = await client.Query(DNSServiceName.Parse("first.example."), A, Timeout);

        // Reset by the test rather than by the server after its answer: only
        // here is the answer known to have been read, and a reset that overtakes
        // an answer the client has not read yet can take the answer with it -
        // on Windows it does. And the server after its answer could be later
        // than the second query's write, which then goes through. Then
        // time for the reset to arrive, so that it is the write that meets it.
        // Arriving later it is met by the read instead, the retry is the same,
        // and this test says nothing it does not also say above.
        server.Connections[0].Reset();

        await Task.Delay(TimeSpan.FromMilliseconds(250));

        var second = await client.Query(DNSServiceName.Parse("second.example."), A, Timeout);

        Assert.Multiple(() => {

            Assert.That(Answered(first),         Is.True,        "the first query was answered");
            Assert.That(Answered(second),        Is.True,        "and the second one too, on a connection that was not reset");
            Assert.That(server.ConnectionCount,  Is.EqualTo(2),  "two connections, the second for the retry");

        });

    }

    #endregion

    #region A server that ends every connection

    [TestCaseSource(typeof(StreamScriptServer), nameof(StreamScriptServer.Transports))]
    [Property("RFC", "7858 §7")]
    public async Task A_Server_That_Ends_Every_Connection_Gets_The_Query_And_One_Retry(String Transport)
    {

        // Each connection is closed the moment a query arrives on it. Asking
        // again is right once; asking again on every new connection would only
        // stop at the deadline, having opened as many connections as the time
        // allowed - against a server that has said, every time, that it is not
        // going to answer.
        await using var server = new StreamScriptServer(Transport, (connection, query) => {
                                     connection.Close();
                                     return Task.CompletedTask;
                                 });

        await using var client = server.NewClient(Timeout);

        var clock = Stopwatch.StartNew();
        var info  = await client.Query(DNSServiceName.Parse("refused.example."), A, Timeout);
        clock.Stop();

        Assert.Multiple(() => {

            Assert.That(server.ConnectionCount,  Is.EqualTo(2),           "the query, and one retry on a new connection");
            Assert.That(info.IsValid,            Is.False,                "the caller is told there is no answer");
            Assert.That(info.IsTimeout,          Is.False,                "as a failure: the server ended the connections, the deadline did not pass");
            Assert.That(clock.Elapsed,           Is.LessThan(Timeout / 2), "and at once rather than at the deadline");

        });

    }

    #endregion


    #region A connection that ends in the middle of an answer (finding 91)

    /// <summary>
    /// Finding 91: the answer whose octets stopped coming.
    /// </summary>
    [TestCaseSource(typeof(StreamScriptServer), nameof(StreamScriptServer.Transports))]
    public async Task A_Query_Whose_Answer_Was_Cut_Off_Is_Asked_Again_On_A_New_One(String Transport)
    {

        // The first connection sends the length of the answer and half of it,
        // and closes. The query is as unanswered as one whose connection closed
        // before a single octet - more octets of it arrived, and no answer did.
        // Every later connection answers.
        await using var server = new StreamScriptServer(Transport, (connection, query) =>
                                     connection.Number == 1
                                         ? connection.CutOff(query)
                                         : connection.Answer(query));

        await using var client = server.NewClient(Timeout);

        var info = await client.Query(DNSServiceName.Parse("cutoff.example."), A, Timeout);

        Assert.Multiple(() => {

            Assert.That(Answered(info),          Is.True,        "RFC 7766 §6.2.4: the unanswered query is asked again, and the second connection answers it");
            Assert.That(server.ConnectionCount,  Is.EqualTo(2),  "on a connection of its own");

        });

    }


    /// <summary>
    /// Finding 91: the query on the same connection whose answer never began.
    /// </summary>
    [TestCaseSource(typeof(StreamScriptServer), nameof(StreamScriptServer.Transports))]
    public async Task A_Pipelined_Query_Is_Asked_Again_When_Another_Answer_Is_Cut_Off(String Transport)
    {

        // Two queries pipelined on the first connection. The server waits until
        // it holds both, cuts the answer to the first one off and closes. The
        // second query has received nothing at all - it is the plainest case of
        // "unanswered queries" on a connection that "closes before receiving all
        // outstanding responses" there is.
        var both = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var server = new StreamScriptServer(Transport, async (connection, query) => {

                                     if (connection.Number > 1)
                                     {
                                         await connection.Answer(query);
                                         return;
                                     }

                                     if (connection.Names.Count >= 2)
                                         both.TrySetResult();

                                     await both.Task.WaitAsync(Timeout);

                                     if (StreamScriptServer.NameOf(query) == "cutoff.example.")
                                         await connection.CutOff(query);

                                 });

        await using var client = server.NewClient(Timeout);

        var cutOff    = client.Query(DNSServiceName.Parse("cutoff.example."),    A, Timeout);
        await Task.Delay(TimeSpan.FromMilliseconds(100));
        var bystander = client.Query(DNSServiceName.Parse("bystander.example."), A, Timeout);

        await Task.WhenAll(cutOff, bystander);

        Assert.Multiple(() => {

            Assert.That(server.Connections[0].Names,
                                                  Has.Member("bystander.example."),
                                                                  "the bystander was pipelined on the connection that was cut off");
            Assert.That(Answered(bystander.Result), Is.True,      "RFC 7766 §6.2.4: and is asked again when it closes, never having been answered");

        });

    }

    #endregion

}

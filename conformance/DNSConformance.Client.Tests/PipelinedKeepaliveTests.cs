using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 7828 §3.2.2 on a connection that carries more than one query at a time,
/// and on the connections that come after it.
/// </summary>
/// <remarks>
/// <para>
/// "A DNS client that receives a response that includes the edns-tcp-keepalive
/// option with a TIMEOUT value of 0 SHOULD send no more queries on that
/// connection and initiate closing the connection as soon as it has received all
/// outstanding responses."
/// </para>
/// <para>
/// Before the clients pipelined (RFC 7766 §6.2.1.1, finding 87) nothing was ever
/// outstanding when a response arrived, so "as soon as it has received all
/// outstanding responses" meant "now", and the KeepaliveTests in
/// SecureTransports measure that. With a second query on the wire the sentence
/// has two halves that can be got wrong apart: the connection stays until the
/// other answer is in, and nothing new goes out on it meanwhile.
/// </para>
/// <para>
/// And "that connection" is a connection. RFC 7828 §3.1 has TIMEOUT as "an idle
/// timeout value for the TCP connection": the one the response came on, not
/// whichever one the client happens to hold when it acts on it (finding 92).
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "7828 §3.2.2")]
public class PipelinedKeepaliveTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(6);

    private static readonly DNSResourceRecordTypes[] A = [ DNSResourceRecordTypes.A ];

    /// <summary>600 s in RFC 7828 §3.1's units of 100 ms: a connection the server is happy to keep.</summary>
    private const UInt16 Generous = 6000;


    private static Boolean Answered(DNSInfo Info)
        => Info.IsValid && Info.Answers.Count() == 1;


    /// <summary>
    /// "one" and "two" pipelined on the first connection, "one" answered with
    /// TIMEOUT 0 and "two" held; "three" asked while "two" is outstanding, and
    /// "two" let go of 300 ms later; "four" asked once both are back, and "five"
    /// after it. Every later connection is answered by <paramref name="Later"/>.
    /// The connection count is taken between "four" and "five".
    /// </summary>
    private static async Task<(StreamScriptServer Server, DNSInfo Two, DNSInfo Three, DNSInfo Four, DNSInfo Five, Int32 ConnectionsBeforeFive)>

        TimeoutZeroWithAnAnswerOutstanding(String                                              Transport,
                                           Func<StreamScriptServer.Connection, Byte[], Task>   Later)

    {

        var both     = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release  = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var server   = new StreamScriptServer(Transport, async (connection, query) => {

                           if (connection.Number > 1)
                           {
                               await Later(connection, query);
                               return;
                           }

                           if (connection.Names.Count >= 2)
                               both.TrySetResult();

                           await both.Task.WaitAsync(Timeout);

                           if (StreamScriptServer.NameOf(query) == "one.example.")
                               await connection.Answer(query, Keepalive: 0);

                           else
                           {
                               await release.Task.WaitAsync(Timeout);
                               await connection.Answer(query);
                           }

                       });

        await using var client = server.NewClient(Timeout);

        var one   = client.Query(DNSServiceName.Parse("one.example."), A, Timeout);
        await Task.Delay(TimeSpan.FromMilliseconds(100));
        var two   = client.Query(DNSServiceName.Parse("two.example."), A, Timeout);

        await one;

        var three = client.Query(DNSServiceName.Parse("three.example."), A, Timeout);

        // Long enough for "three" to have been written, if it is going to be
        // written to the first connection at all.
        await Task.Delay(TimeSpan.FromMilliseconds(300));

        release.TrySetResult();

        await Task.WhenAll(two, three);

        var four  = await client.Query(DNSServiceName.Parse("four.example."), A, Timeout);

        var connectionsBeforeFive = server.ConnectionCount;

        var five  = await client.Query(DNSServiceName.Parse("five.example."), A, Timeout);

        return (server, two.Result, three.Result, four, five, connectionsBeforeFive);

    }

    #endregion


    #region Timeout 0 with an answer still outstanding

    [TestCaseSource(typeof(StreamScriptServer), nameof(StreamScriptServer.Transports))]
    public async Task After_Timeout_Zero_No_Query_Goes_Out_On_The_Connection_And_Its_Outstanding_Answer_Is_Waited_For(String Transport)
    {

        // What became of "three" is finding 92's question, asked below. This one
        // asks about the connection the TIMEOUT 0 arrived on, and about the
        // close being done once: the later connections advertise a generous
        // timeout, so whichever of them "four" went out on is the one "five"
        // finds. Neither half depends on what finding 92 does to "three".
        var (server, two, _, _, five, before) = await TimeoutZeroWithAnAnswerOutstanding(
                                                          Transport,
                                                          (connection, query) => connection.Answer(query, Keepalive: Generous)
                                                      );

        await using var _server = server;

        Assert.Multiple(() => {

            Assert.That(server.Connections[0].Names, Is.EqualTo(new[] { "one.example.", "two.example." }),
                        "nothing more was sent on the connection the server asked the client to close");

            Assert.That(Answered(two),               Is.True,
                        "the answer outstanding on it was waited for");

            Assert.That(server.Connections.Skip(1).SelectMany(connection => connection.Names),
                                                     Has.No.Member("two.example."),
                        "on that connection, rather than the connection being closed under it and the query asked again on another");

            Assert.That(Answered(five) && server.ConnectionCount == before,
                                                     Is.True,
                        "and the close was the first connection's, done once: \"five\" went out on a connection already open");

        });

    }


    [TestCaseSource(typeof(StreamScriptServer), nameof(StreamScriptServer.Transports))]
    [Property("RFC", "7766 §6.2.4")]
    public async Task After_Timeout_Zero_A_Query_Whose_Connection_Closes_Unanswered_Is_Asked_Again(String Transport)
    {

        // The server answers "one" with TIMEOUT 0 and closes the connection
        // without answering "two" - which is what a server short of resources,
        // the reason RFC 7828 §3.3.2 gives for the 0, may well do next. "two" is
        // unanswered on a connection that closed, and RFC 7766 §6.2.4 has it
        // asked again: on a new connection, because the old one is the one the
        // client was told to leave.
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

                                     if (StreamScriptServer.NameOf(query) == "one.example.")
                                     {
                                         await connection.Answer(query, Keepalive: 0);
                                         connection.Close();
                                     }

                                 });

        await using var client = server.NewClient(Timeout);

        var one = client.Query(DNSServiceName.Parse("one.example."), A, Timeout);
        await Task.Delay(TimeSpan.FromMilliseconds(100));
        var two = client.Query(DNSServiceName.Parse("two.example."), A, Timeout);

        await Task.WhenAll(one, two);

        Assert.Multiple(() => {

            Assert.That(Answered(one.Result),    Is.True,        "the first query was answered");
            Assert.That(Answered(two.Result),    Is.True,        "the second was asked again and answered");
            Assert.That(two.Result.IsTimeout,    Is.False,       "rather than left waiting for a connection that had already gone");
            Assert.That(server.ConnectionCount,  Is.EqualTo(2),  "on a connection of its own");

        });

    }

    #endregion

    #region A TIMEOUT 0 is about the connection it arrived on (finding 92)

    /// <summary>
    /// Finding 92: the TIMEOUT 0 of a connection that is gone, applied to the one
    /// after it.
    /// </summary>
    [TestCaseSource(typeof(StreamScriptServer), nameof(StreamScriptServer.Transports))]
    [Property("RFC", "7828 §3.1, 7766 §5")]
    public async Task A_Connection_That_Never_Sent_Timeout_Zero_Is_Not_Closed_For_The_One_That_Did(String Transport)
    {

        // The first connection answers with TIMEOUT 0 and the client closes it,
        // which is right. The second one answers without the option at all: it
        // has said nothing about its idle timeout, and RFC 7766 §5 has an open
        // connection reused - "If the resolver already has an open TCP
        // connection to the server, it SHOULD reuse this connection." The
        // queries asked one after another find it open.
        await using var server = new StreamScriptServer(Transport, (connection, query) =>
                                     connection.Number == 1
                                         ? connection.Answer(query, Keepalive: 0)
                                         : connection.Answer(query));

        await using var client = server.NewClient(Timeout);

        var one   = await client.Query(DNSServiceName.Parse("one.example."),   A, Timeout);
        var two   = await client.Query(DNSServiceName.Parse("two.example."),   A, Timeout);
        var three = await client.Query(DNSServiceName.Parse("three.example."), A, Timeout);

        Assert.Multiple(() => {

            Assert.That(Answered(one) && Answered(two) && Answered(three),
                                                 Is.True,        "every query was answered");

            Assert.That(server.ConnectionCount,  Is.EqualTo(2),  "the connection that sent TIMEOUT 0 was left, and the one after it kept");

            Assert.That(server.Connections.Skip(1).FirstOrDefault()?.Names,
                                                 Is.EqualTo(new[] { "two.example.", "three.example." }),
                        "RFC 7828 §3.1: TIMEOUT is \"an idle timeout value for the TCP connection\" - " +
                        "the first connection's 0 says nothing about the second");

        });

    }


    /// <summary>
    /// Finding 92: the query that waited out a TIMEOUT 0, on the connection that
    /// replaced it.
    /// </summary>
    [TestCaseSource(typeof(StreamScriptServer), nameof(StreamScriptServer.Transports))]
    [Property("RFC", "7828 §3.1, 7766 §5")]
    public async Task A_Query_Asked_While_A_Timeout_Zero_Drains_Is_Answered_On_The_Next_Connection(String Transport)
    {

        // The scene of the test above, with the later connections answering
        // without the option. "three" waits for "two" to come back on the first
        // connection, the first connection is closed, and "three" goes out on a
        // new one - while the answer to "two", read on the old one, is still
        // being acted on. Nothing the server does makes "three" fail: it is a
        // query asked of an answering server on a connection opened for it.
        var (server, _, three, four, _, _) = await TimeoutZeroWithAnAnswerOutstanding(
                                                       Transport,
                                                       (connection, query) => connection.Answer(query)
                                                   );

        await using var _server = server;

        Assert.Multiple(() => {

            Assert.That(Answered(three),         Is.True,
                        "the query asked meanwhile went out on a new connection and was answered there");

            Assert.That(server.Connections.Skip(1).FirstOrDefault()?.Names,
                                                 Is.EqualTo(new[] { "three.example.", "four.example.", "five.example." }),
                        "where the ones after it went too: the TIMEOUT 0 was the first connection's");

            Assert.That(Answered(four),          Is.True);

        });

    }

    #endregion

    #region The same rule for a client built from a URL

    [Test]
    [Property("RFC", "7828 §3.2.2, 7858 §3.4")]
    public async Task A_Dot_Client_Built_From_A_URL_Closes_An_Idle_Session_Before_Its_Timeout()
    {

        // The DoT client has two constructors and each one builds its own
        // keepalive policy, including what it counts as idle. The KeepaliveTests
        // in SecureTransports build their clients from an address; this is the
        // other one. Two units of 100 ms, a second of silence, and the next query
        // has to find the session gone.
        await using var server = new StreamScriptServer("DoT", (connection, query) => connection.Answer(query, Keepalive: 2));

        await using var client = new DNSTLSClient(URL.Parse($"tls://127.0.0.1:{server.Port}"),
                                                  QueryTimeout:                Timeout,
                                                  RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success());

        var first  = await client.Query(DNSServiceName.Parse("first.example."),  A, Timeout);

        await Task.Delay(TimeSpan.FromSeconds(1));

        var second = await client.Query(DNSServiceName.Parse("second.example."), A, Timeout);

        Assert.Multiple(() => {

            Assert.That(Answered(first) && Answered(second), Is.True,       "both queries were answered");
            Assert.That(server.ConnectionCount,              Is.EqualTo(2), "the idle session was gone before its 200 ms were up");

        });

    }

    #endregion

}

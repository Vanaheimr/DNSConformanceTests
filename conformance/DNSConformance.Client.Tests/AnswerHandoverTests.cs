using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Client.Tests;

/// <summary>
/// An answer that arrives out of order reaches its caller when it arrives.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7766 §7: "Stub and recursive resolvers MUST be able to process responses
/// that arrive in a different order than that in which the requests were sent,
/// regardless of the transport protocol in use."
/// </para>
/// <para>
/// Both stream clients read a connection with whichever waiting query has the
/// turn, and the reader hands every answer to the query it belongs to. Handing
/// it over is half of processing it. The other half is that the query it was
/// handed to returns then - not once the reader, or whoever reads next, has
/// read another message, which on a server that answers the others later is a
/// response processed in the order the requests were sent after all.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "7766 §7")]
public class AnswerHandoverTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(6);

    /// <summary>How long the answer sent first has to reach its caller, once the server has all three queries.</summary>
    private static readonly TimeSpan Prompt  = TimeSpan.FromSeconds(1.5);

    private static readonly DNSResourceRecordTypes[] A = [ DNSResourceRecordTypes.A ];


    private static Boolean Answered(DNSInfo Info)
        => Info.IsValid && Info.Answers.Count() == 1;

    #endregion


    [TestCaseSource(typeof(StreamScriptServer), nameof(StreamScriptServer.Transports))]
    public async Task The_Answer_Sent_First_Is_Not_Held_Behind_The_Ones_Asked_Before_It(String Transport)
    {

        // Three queries pipelined on one connection, asked in the order one,
        // two, three. The server waits until it has all three and answers
        // "three" at once; "one" and "two" it holds until the test lets them go.
        // Whoever reads the answer to "three" hands it over and then someone
        // reads on - into a stream that has nothing more to give until the
        // others are released.
        var all      = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release  = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var server = new StreamScriptServer(Transport, async (connection, query) => {

                                     if (connection.Names.Count >= 3)
                                         all.TrySetResult();

                                     await all.Task.WaitAsync(Timeout);

                                     if (StreamScriptServer.NameOf(query) != "three.example.")
                                         await release.Task.WaitAsync(Timeout);

                                     await connection.Answer(query);

                                 });

        await using var client = server.NewClient(Timeout);

        var one    = client.Query(DNSServiceName.Parse("one.example."),   A, Timeout);
        await Task.Delay(TimeSpan.FromMilliseconds(50));
        var two    = client.Query(DNSServiceName.Parse("two.example."),   A, Timeout);
        await Task.Delay(TimeSpan.FromMilliseconds(50));
        var three  = client.Query(DNSServiceName.Parse("three.example."), A, Timeout);

        // The time is counted from the moment the server has all three queries
        // and answers the third, not from the moment the third was asked. The
        // first query opens the connection, and for DoT this is the first TLS
        // handshake of the test run: under the load of the whole suite the
        // server had the third query up to 1.1 s after it was asked, while the
        // answer, once sent, reached its caller within 160 ms.
        var gathered = await Task.WhenAny(all.Task, Task.Delay(Timeout)) == all.Task;
        var promptly = gathered && await Task.WhenAny(three, Task.Delay(Prompt)) == three;
        var others   = one.IsCompleted || two.IsCompleted;

        release.TrySetResult();

        await Task.WhenAll(one, two, three);

        Assert.Multiple(() => {

            Assert.That(gathered,                Is.True,        "the server had all three queries before it answered one");
            Assert.That(server.ConnectionCount,  Is.EqualTo(1),  "all three were pipelined on one connection - without this the next line measures nothing");
            Assert.That(others,                  Is.False,       "and the first two were still unanswered");
            Assert.That(promptly,                Is.True,        "while the answer to the third, sent first, had already reached its caller");

            Assert.That(Answered(one.Result) && Answered(two.Result) && Answered(three.Result),
                                                 Is.True,        "and every one of them is answered once the server lets go - " +
                                                                 "the read turn the third did not need went to someone who did");

        });

    }

}

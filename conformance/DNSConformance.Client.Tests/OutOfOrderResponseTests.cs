using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 7766 §7 — response reordering. The section has two halves, and only
/// one of them was implemented: responses are matched by Message ID and
/// question (finding 49), but a response that does not match ended the read
/// instead of being skipped. On a reused connection that leaves the stream
/// one message behind for good — finding 53.
/// </summary>
[TestFixture]
[Property("RFC", "7766 §7")]
public class OutOfOrderResponseTests
{

    #region Data

    private static readonly TimeSpan  ShortTimeout  = TimeSpan.FromMilliseconds(400);
    private static readonly TimeSpan  LateAnswer    = TimeSpan.FromMilliseconds(1500);

    private static readonly IPv4Address  SlowAddress  = IPv4Address.Parse("192.0.2.1");
    private static readonly IPv4Address  FastAddress  = IPv4Address.Parse("192.0.2.2");


    private static Byte[] AddressFor(String Name)
        => Name switch {
               "slow.example"  => [192, 0, 2, 1],
               "fast.example"  => [192, 0, 2, 2],
               _               => [192, 0, 2, 9]
           };

    private static Byte[] AnswerFor(Byte[] Request)
    {
        var name = RawDnsReader.Parse(Request).Questions.Single().Name.Canonical;
        return RawDnsResponder.Answer(Request, (name + ".", RawDnsType.A, 300, AddressFor(name)));
    }

    private static Boolean IsSlowQuery(Byte[] Request)
        => RawDnsReader.Parse(Request).Questions.Single().Name.Canonical == "slow.example";


    /// <summary>
    /// Wait for a condition rather than for a duration — the tests below depend
    /// on the late answer actually having been written, and a sleep that was a
    /// little too short would make them pass for the boring reason.
    /// </summary>
    private static async Task<Boolean> WaitUntil(Func<Boolean> Condition, TimeSpan Within)
    {

        var deadline = DateTime.UtcNow + Within;

        while (DateTime.UtcNow < deadline)
        {

            if (Condition())
                return true;

            await Task.Delay(25);

        }

        return Condition();

    }

    #endregion


    #region Prompt_Answers_On_A_Reused_Connection_Are_Correct()

    [Test]
    [Property("RFC", "7766 §6.2.1")]
    public async Task Prompt_Answers_On_A_Reused_Connection_Are_Correct()
    {

        // The baseline. Everything below turns on a reused connection carrying
        // the right answer to the right query; if that were broken on its own,
        // the tests that follow would be measuring nothing.
        await using var server = new ScriptedTcpServer(AnswerFor);

        await using var client = new DNSTCPClient(
                                     IPv4Address.Localhost,
                                     Port:          IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:  ShortTimeout
                                 );

        var slow  = await client.Query<A>(DomainName.Parse("slow.example."), Timeout: ShortTimeout);
        var fast  = await client.Query<A>(DomainName.Parse("fast.example."), Timeout: ShortTimeout);
        var again = await client.Query<A>(DomainName.Parse("fast.example."), Timeout: ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(slow. FilteredAnswers.Single().IPv4Address, Is.EqualTo(SlowAddress));
            Assert.That(fast. FilteredAnswers.Single().IPv4Address, Is.EqualTo(FastAddress));
            Assert.That(again.FilteredAnswers.Single().IPv4Address, Is.EqualTo(FastAddress));

            Assert.That(server.ConnectionCount, Is.EqualTo(1),
                        "one connection carried all three — otherwise the tests below are not about reuse");

        });

    }

    #endregion

    #region An_Answer_That_Arrives_After_The_Timeout_Is_Skipped()

    [Test]
    public async Task An_Answer_That_Arrives_After_The_Timeout_Is_Skipped()
    {

        // "Stub and recursive resolvers MUST be able to process responses that
        //  arrive in a different order than that in which the requests were
        //  sent, regardless of the transport protocol in use."
        //
        // A query that times out is still answered. That answer is waiting on
        // the connection when the next query reads, and the next query must
        // step over it rather than be broken by it.
        await using var server = new ScriptedTcpServer(
            request => {
                if (IsSlowQuery(request))
                    Thread.Sleep(LateAnswer);
                return AnswerFor(request);
            }
        );

        await using var client = new DNSTCPClient(
                                     IPv4Address.Localhost,
                                     Port:          IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:  ShortTimeout
                                 );

        var first = await client.Query<A>(DomainName.Parse("slow.example."), Timeout: ShortTimeout);

        Assert.That(first.IsTimeout, Is.True, "the first query must time out for this test to be about anything");

        // The precondition, checked rather than slept through: the answer the
        // client gave up on really did go out on the wire.
        Assert.That(await WaitUntil(() => server.ResponsesWritten >= 1, TimeSpan.FromSeconds(5)), Is.True,
                    "the late answer was never written — nothing is waiting on the connection");

        await Task.Delay(TimeSpan.FromMilliseconds(250));   // and has arrived

        var second = await client.Query<A>(DomainName.Parse("fast.example."), Timeout: TimeSpan.FromSeconds(3));

        Assert.Multiple(() => {

            Assert.That(second.FilteredAnswers.Select(a => a.IPv4Address), Is.EqualTo(new[] { FastAddress }),
                        "the answer to the query that was actually asked — not the one left over, and not nothing");

            Assert.That(server.ConnectionCount, Is.EqualTo(1),
                        "the stale message was stepped over, not escaped by opening a second connection");

        });

    }

    #endregion

    #region A_Stale_Answer_Is_Never_Handed_To_The_Caller()

    [Test]
    public async Task A_Stale_Answer_Is_Never_Handed_To_The_Caller()
    {

        // The discriminating case. The server answers the first query late and
        // then says nothing at all, so the only thing on the connection is a
        // message belonging to a query that is over. The caller must be told
        // nothing came back — after waiting, not instantly, because returning
        // instantly means the stale message was taken for an answer to this one.
        await using var server = new ScriptedTcpServer(
            request => {

                if (!IsSlowQuery(request))
                    return null;                            // silence

                Thread.Sleep(LateAnswer);
                return AnswerFor(request);

            }
        );

        await using var client = new DNSTCPClient(
                                     IPv4Address.Localhost,
                                     Port:          IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:  ShortTimeout
                                 );

        var first = await client.Query<A>(DomainName.Parse("slow.example."), Timeout: ShortTimeout);

        Assert.That(first.IsTimeout, Is.True);

        Assert.That(await WaitUntil(() => server.ResponsesWritten >= 1, TimeSpan.FromSeconds(5)), Is.True,
                    "the late answer was never written — nothing is waiting on the connection");

        await Task.Delay(TimeSpan.FromMilliseconds(250));

        var second = await client.Query<A>(DomainName.Parse("fast.example."), Timeout: ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(second.FilteredAnswers, Is.Empty,
                        "somebody else's answer is not an answer");

            Assert.That(second.IsTimeout, Is.True,
                        "with nothing else on the connection the query must time out");

            // The measurement that separates the two behaviours: broken, this
            // returns in ~0 ms because the stale message ended the read.
            Assert.That(second.Runtime, Is.GreaterThan(TimeSpan.FromMilliseconds(250)),
                        "it must have waited for an answer, not returned the moment it found the stale one");

        });

    }

    #endregion

    #region A_Message_Too_Short_For_A_Header_Does_Not_Desynchronise()

    [Test]
    [Property("RFC", "7766 §8")]
    public async Task A_Message_Too_Short_For_A_Header_Does_Not_Desynchronise()
    {

        // A length below 12 cannot be a DNS message, but its octets are framed
        // like one. Abandoning the read without consuming them leaves the
        // stream pointing into the middle of a message that was never skipped.
        await using var server = new ScriptedTcpServer(
            request => (IEnumerable<Byte[]>) [
                           new Byte[] { 0xDE, 0xAD, 0xBE, 0xEF },   // four octets, framed, unusable
                           AnswerFor(request)
                       ]
        );

        await using var client = new DNSTCPClient(
                                     IPv4Address.Localhost,
                                     Port:          IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:  TimeSpan.FromSeconds(3)
                                 );

        var response = await client.Query<A>(DomainName.Parse("fast.example."), Timeout: TimeSpan.FromSeconds(3));

        Assert.That(response.FilteredAnswers.Select(a => a.IPv4Address), Is.EqualTo(new[] { FastAddress }),
                    "the runt must be consumed and stepped over, leaving the real answer readable");

    }

    #endregion

    #region A_Timeout_Inside_A_Message_Drops_The_Connection()

    [Test]
    public async Task A_Timeout_Inside_A_Message_Drops_The_Connection()
    {

        // The half no matching rule can repair. Once the length prefix has been
        // read and the body has not, the frame boundary is unknown, and every
        // later read starts mid-message. The only correct move is to stop using
        // the connection — which costs a round trip and is still cheaper than a
        // connection that never works again.
        await using var server = new ScriptedTcpServer(
            AnswerFor,
            new ScriptedTcpOptions {
                WriteChunkSize   = 3,
                WriteChunkDelay  = TimeSpan.FromMilliseconds(200)   // ~3s for one answer
            }
        );

        await using var client = new DNSTCPClient(
                                     IPv4Address.Localhost,
                                     Port:          IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:  ShortTimeout
                                 );

        var first = await client.Query<A>(DomainName.Parse("slow.example."), Timeout: ShortTimeout);

        Assert.That(first.IsTimeout, Is.True, "the answer is still dribbling in when the client gives up");

        var second = await client.Query<A>(DomainName.Parse("fast.example."), Timeout: TimeSpan.FromSeconds(15));

        Assert.Multiple(() => {

            Assert.That(second.FilteredAnswers.Select(a => a.IPv4Address), Is.EqualTo(new[] { FastAddress }),
                        "given enough time the next query must succeed — on a connection whose framing is known");

            Assert.That(server.ConnectionCount, Is.GreaterThanOrEqualTo(2),
                        "the connection whose frame boundary was lost must have been dropped, not reused");

        });

    }

    #endregion

}

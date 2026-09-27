using System.Diagnostics;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// Following an alias, and how often a client asks again.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="DNameFollowingTests"/> covers the DNAME half of the chase in
/// detail — which names a DNAME rewrites and which it must leave alone. The
/// CNAME half had nothing: whether an alias is followed at all, whether the
/// record at the end of the chain reaches the caller, and whether a query for
/// the alias itself stops where RFC 1034 says it stops.
/// </para>
/// <para>
/// Everything here is counted on the wire. A cache hit and a chase that never
/// happened look identical from the answer alone, so the assertions are about
/// which questions the server was asked.
/// </para>
/// </remarks>
[TestFixture]
public class CnameChaseAndRetryTests
{

    #region Data

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromMilliseconds(800);


    private static DNSClient ClientFor(Int32 Port)
        => new (IPv4Address.Localhost,
                IPPort.Parse((UInt16) Port),
                QueryTimeout:   ShortTimeout,
                UseQueryCache:  false);


    private static Byte[] CnameRdata(String Target)
        => RawDnsWriter.NameBytes(Target);


    /// <summary>The questions the server was asked, as "name/type" in arrival order.</summary>
    private static String[] QuestionsAsked(ScriptedUdpServer Server)
        => [.. Server.Requests.
                   Select(request => RawDnsReader.Parse(request).Questions.Single()).
                   Select(question => $"{question.Name.Canonical}/{question.Type}")];

    #endregion


    #region How often, and how soon, a SERVFAIL is asked again (RFC 1035 §7.1)

    // Cited on §7.1 rather than §7.2, which is where this used to point. §7.1 is
    // the section that says a bound has to exist — "The amount of work which a
    // resolver will do in response to a client request must be limited" — and
    // describes it as a counter decremented on every action, "retransmission
    // timeout, retransmission, etc.". That is what both tests below are about. The
    // text of §7.2 could not be read from any source available here: two fetches of
    // it truncate at the section's first sentence and a third returned text the
    // other two contradict, so the citation moved to the section that can be
    // checked rather than staying on one that cannot.

    [Test]
    [Property("RFC", "1035 §7.1")]
    public async Task A_Servfail_Is_Asked_Again_Exactly_Max_Retries_Times()
    {

        // SERVFAIL is an answer rather than silence, so nothing at the transport
        // retransmits: every datagram here was a decision by the retry loop. The
        // count is the whole assertion, and it is taken at two different settings
        // because one number is consistent with a loop that ignores MaxRetries
        // and happens to agree at the default.
        await using var server = new ScriptedUdpServer(
            request => RawDnsResponder.Rcode(request, 2)   // SERVFAIL
        );

        using (var client = ClientFor(server.Port))
        {
            await client.Query<A>(DomainName.Parse("one.example."), ShortTimeout);
        }

        var afterDefault = QuestionsAsked(server).Length;

        using (var client = ClientFor(server.Port))
        {
            client.MaxRetries = 3;
            await client.Query<A>(DomainName.Parse("three.example."), ShortTimeout);
        }

        var afterThree = QuestionsAsked(server).Length - afterDefault;

        Assert.Multiple(() => {

            Assert.That(afterDefault, Is.EqualTo(2),
                        "the default MaxRetries is 1, so the query is made once and retried once");

            Assert.That(afterThree, Is.EqualTo(4),
                        "and with three retries allowed, four times in all");

        });

    }


    [Test]
    [Property("RFC", "1035 §7.1")]
    public async Task A_Retried_Servfail_Is_Not_Asked_Again_Immediately()
    {

        // The test above counts the questions; this one times them. They are two
        // rules and they live on two different lines, which is how this one came to
        // be missing: `while (attempts <= MaxRetries)` is what decides whether to
        // ask again, and a second `if (attempts <= MaxRetries)` just above it
        // decides only whether to pause first. The count test cannot see the second
        // one at all — remove its condition entirely and the same two datagrams go
        // out, back to back.
        //
        // Which is the whole point of the pause. RFC 1035 §7.1 counts a
        // "retransmission timeout" among the actions a resolver spends its budget
        // on, and a retry sent the instant the failure arrives spends no budget and
        // gives the server nothing: SERVFAIL is what a name server answers when it
        // is having trouble, and the reply to trouble is not the same question
        // arriving again in the same millisecond.
        //
        // Asserted as a lower bound, which is the direction that holds under load:
        // a scheduled delay can be late but never early, so a loaded machine makes
        // this gap longer and never shorter.
        var arrivals = new List<TimeSpan>();
        var clock    = Stopwatch.StartNew();

        await using var server = new ScriptedUdpServer(request => {
            arrivals.Add(clock.Elapsed);
            return RawDnsResponder.Rcode(request, 2);   // SERVFAIL
        });

        using var client = ClientFor(server.Port);

        await client.Query<A>(DomainName.Parse("slowdown.example."), ShortTimeout);

        Assert.That(arrivals, Has.Count.EqualTo(2), "one question and one retry, as the test above establishes");

        Assert.That(arrivals[1] - arrivals[0], Is.GreaterThan(TimeSpan.FromMilliseconds(150)),
                    "the retry waits before it is sent, rather than following the failure straight back out");

    }

    #endregion


    #region A query for the alias itself (RFC 1034 §3.6.2)

    [Test]
    [Property("RFC", "1034 §3.6.2")]
    public async Task A_Query_For_The_Cname_Type_Is_Not_Followed()
    {

        // Asking for the CNAME at a name is asking about the link, not about what
        // it points at. RFC 1034 §3.6.2 has the resolver return the CNAME when
        // CNAME is the type asked for, and a client that chases anyway answers a
        // question nobody put: it comes back with the target's records and the
        // caller never learns what the alias was.
        await using var server = new ScriptedUdpServer(
            request => RawDnsResponder.Answer(
                           request,
                           ("alias.example.", RawDnsType.CNAME, 300, CnameRdata("real.example."))
                       )
        );

        using var client = ClientFor(server.Port);

        var answer = await client.Query<CNAME>(DomainName.Parse("alias.example."), ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(QuestionsAsked(server), Is.EqualTo(new[] { "alias.example/5" }),
                        "one question, for the CNAME, and nothing after it");

            Assert.That(answer.FilteredAnswers.Any(), Is.True,
                        "and the link itself is what comes back");

        });

    }

    [Test]
    [Property("RFC", "1034 §3.6.2, 8482 §4.2")]
    public async Task A_Query_For_Any_At_An_Alias_Is_Not_Followed_Either()
    {

        // The companion to the test above, and the one that actually carries the
        // rule. Asking for CNAME is stopped twice over: the outer guard declines
        // to chase, and even if it did not, the answer is a CNAME and the chase
        // would see the type it was asked for and stop anyway. ANY has only the
        // outer guard — a CNAME is not "of type ANY", so nothing downstream
        // notices — which makes this the query that says whether the guard is
        // there at all.
        //
        // RFC 8482 §4.2 has a responder answer ANY at an alias with the CNAME,
        // and RFC 1034 §3.6.2 keeps a CNAME alone at its name. A client that
        // chases on top of that turns "everything here" into "everything
        // somewhere else".
        await using var server = new ScriptedUdpServer(
            request => RawDnsResponder.Answer(
                           request,
                           ("alias.example.", RawDnsType.CNAME, 300, CnameRdata("real.example."))
                       )
        );

        using var client = ClientFor(server.Port);

        await client.Query(DNSServiceName.Parse("alias.example."),
                           [ DNSResourceRecordTypes.Any ],
                           ShortTimeout);

        Assert.That(QuestionsAsked(server), Is.EqualTo(new[] { "alias.example/255" }),
                    "one question, and the alias is what the answer is about");

    }

    #endregion


    #region The record at the end of the chain (RFC 1034 §3.6.2, §4.3.2)

    [Test]
    [Property("RFC", "1034 §3.6.2, §4.3.2")]
    public async Task A_Cname_Chain_Delivers_The_Record_At_Its_End()
    {

        // RFC 1034 §4.3.2 step 3a: on a CNAME the resolver changes the name it is
        // asking about and starts again. What the caller must end up holding is
        // the record it asked for — the alias on its own is the chase stopping
        // one query short and reporting the signpost as the destination.
        await using var server = new ScriptedUdpServer(
            request => {

                var question = RawDnsReader.Parse(request).Questions.Single();

                return question.Name.Canonical == "alias.example"
                           ? RawDnsResponder.Answer(request, ("alias.example.", RawDnsType.CNAME, 300, CnameRdata("real.example.")))
                           : RawDnsResponder.Answer(request, ("real.example.",  RawDnsType.A,     300, [192, 0, 2, 9]));

            }
        );

        using var client = ClientFor(server.Port);

        var answer = await client.Query<A>(DomainName.Parse("alias.example."), ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(QuestionsAsked(server), Is.EqualTo(new[] { "alias.example/1", "real.example/1" }),
                        "the alias is asked about first, then the name it points at");

            Assert.That(answer.Answers.Any(record => record.Type == DNSResourceRecordTypes.A),
                        Is.True,
                        "§4.3.2: the address at the end of the chain is the answer to the question");

            Assert.That(answer.Answers.Any(record => record.Type == DNSResourceRecordTypes.CNAME),
                        Is.True,
                        "and the link that led there is kept, so the caller can see the redirection");

        });

    }

    [Test]
    [Property("RFC", "1034 §4.3.2, 2308 §2.1")]
    public async Task A_Chain_Stops_At_A_Name_That_Does_Not_Exist()
    {

        // RFC 2308 §2.1 describes exactly this packet: an NXDOMAIN whose answer
        // section carries the CNAMEs that led to the name which does not exist.
        // The records are there to show the path, not to invite another step —
        // the last one points at a name the server has just said is absent.
        //
        // So the chase has to stop on the response code alone. Stopping only when
        // the response is *both* an error and empty means a denial that shows its
        // working is read as an invitation, and the resolver goes on to ask about
        // a name it was told does not exist.
        await using var server = new ScriptedUdpServer(
            request => {

                var question = RawDnsReader.Parse(request).Questions.Single();

                return question.Name.Canonical switch {

                    "alias.example"  => RawDnsResponder.Answer(request, ("alias.example.", RawDnsType.CNAME, 300, CnameRdata("gone.example."))),

                    // NXDOMAIN, and the CNAME that led there is in the answer
                    // section where RFC 2308 §2.1 puts it.
                    "gone.example"   => RawDnsResponder.Build(request,
                                                              (UInt16) (RawDnsFlags.QR | RawDnsFlags.RD | RawDnsFlags.RA | RawDnsFlags.RCode(3)),
                                                              ("gone.example.", RawDnsType.CNAME, 300, CnameRdata("beyond.example."))),

                    _                => RawDnsResponder.Answer(request, ("beyond.example.", RawDnsType.A, 300, [192, 0, 2, 11]))

                };

            }
        );

        using var client = ClientFor(server.Port);

        await client.Query<A>(DomainName.Parse("alias.example."), ShortTimeout);

        Assert.That(QuestionsAsked(server), Is.EqualTo(new[] { "alias.example/1", "gone.example/1" }),
                    "the denial ends the chase; beyond.example. is never asked about");

    }

    #endregion


    #region A client told not to follow (RFC 1034 §3.6.2)

    [Test]
    [Property("RFC", "1034 §3.6.2")]
    public async Task A_Client_Told_Not_To_Follow_Returns_The_Alias_Alone()
    {

        // Following is the client's convenience, not the protocol's requirement:
        // a stub that wants to see the redirection itself — a validator, a
        // debugger, anything reconstructing what the server actually said — turns
        // it off. Then one question goes out and the CNAME comes back on its own.
        await using var server = new ScriptedUdpServer(
            request => {

                var question = RawDnsReader.Parse(request).Questions.Single();

                return question.Name.Canonical == "alias.example"
                           ? RawDnsResponder.Answer(request, ("alias.example.", RawDnsType.CNAME, 300, CnameRdata("real.example.")))
                           : RawDnsResponder.Answer(request, ("real.example.",  RawDnsType.A,     300, [192, 0, 2, 9]));

            }
        );

        using var client = ClientFor(server.Port);
        client.FollowCNAMEs = false;

        var answer = await client.Query<A>(DomainName.Parse("alias.example."), ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(QuestionsAsked(server), Is.EqualTo(new[] { "alias.example/1" }),
                        "nothing is asked about the target");

            Assert.That(answer.Answers.Any(record => record.Type == DNSResourceRecordTypes.A),
                        Is.False,
                        "and no address appears that the server was never asked for");

        });

    }

    #endregion

    #region An alias loop (RFC 1034 §5.2.2, RFC 1035 §7.1)

    /// <summary>
    /// Red: two aliases pointing at each other are chased rather than caught.
    /// </summary>
    /// <remarks>
    /// Left failing on purpose. The chase keeps a set of names it has visited, which
    /// catches a name aliased to itself, but the set is created inside the call and
    /// the next hop is taken by calling <c>Query</c> again — so every hop starts
    /// with an empty memory and a two-name cycle is followed for as long as the peer
    /// keeps answering. <c>MaxCNAMEFollows</c> does not bound it either: it counts
    /// iterations of one call's own loop, and the recursion means each call takes
    /// one or two hops before handing the rest to the next.
    /// </remarks>
    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "1034 §5.2.2, 1035 §7.1")]
    public async Task An_Alias_Loop_Is_Caught_Rather_Than_Chased()
    {

        // RFC 1034 §5.2.2: "Alias loops and aliases which point to non-existent
        // names should be caught and an error condition passed back to the client."
        // RFC 1035 §7.1 says why it is a MUST in practice — "The amount of work
        // which a resolver will do in response to a client request must be limited
        // to guard against errors in the database, such as circular CNAME
        // references" — and names this exact database error as the reason.
        //
        // The cost is borne by the server, not the client: one question produces as
        // many queries as the peer is willing to answer, so a single zone with a
        // cycle in it turns every resolver that meets it into a small flood. A
        // misconfiguration does it by accident; a hostile zone does it on purpose.
        //
        // The peer stops answering after a while so that a client which keeps
        // chasing ends this test by timing out instead of hanging it. That patience
        // is the measurement: what is asserted is how many questions were asked
        // before it ran out.
        const Int32 Patience = 12;

        await using var server = new ScriptedUdpServer((request, index) => {

            if (index >= Patience)
                return [];

            var asked  = RawDnsReader.Parse(request).Questions[0].Name.Canonical;
            var target = asked.StartsWith("ping", StringComparison.Ordinal)
                             ? "pong.example."
                             : "ping.example.";

            return [ RawDnsResponder.Answer(request, ($"{asked}.", RawDnsType.CNAME, 60, CnameRdata(target))) ];

        });

        using var client = ClientFor(server.Port);

        await client.Query(DNSServiceName.Parse("ping.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);

        Assert.That(QuestionsAsked(server), Has.Length.LessThanOrEqualTo(3),
                    "the cycle is provable after the second question, so a third is generous and a fourth is chasing");

    }

    #endregion

}

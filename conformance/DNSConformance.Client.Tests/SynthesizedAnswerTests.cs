using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// What a client says in a response no server ever sent.
/// </summary>
/// <remarks>
/// <para>
/// A stub resolver answers some questions without asking anyone: it has no
/// servers configured, or a cached NSEC already proves the name absent. The
/// object it hands back has the same shape as one that crossed a wire, and the
/// header fields in it are then claims about a message that does not exist.
/// </para>
/// <para>
/// Two of those fields are constrained by RFC 1035 §4.1.1 whatever the message's
/// provenance. AA "specifies that the responding name server is an authority for
/// the domain name in question section" — there is no responding name server
/// here, so there is nothing to be an authority. RA "denotes whether recursive
/// query support is available in the name server" — likewise. A synthesized
/// answer that sets either is describing a server that was never consulted.
/// </para>
/// <para>
/// The rest are Hermod's own vocabulary rather than the RFC's, and the
/// assertions on them say so where they appear.
/// </para>
/// </remarks>
[TestFixture]
public class SynthesizedAnswerTests
{

    #region Data

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromMilliseconds(800);


    /// <summary>A client that has nowhere to send a question.</summary>
    private static DNSClient ClientWithNoServers()
        => new (ManualDNSServers:          [],
                SearchForIPv4DNSServers:   false,
                SearchForIPv6DNSServers:   false,
                UseQueryCache:             false);


    private static DNSClient ClientFor(Int32 Port)
        => new (IPv4Address.Localhost,
                IPPort.Parse((UInt16) Port),
                QueryTimeout:   ShortTimeout,
                UseQueryCache:  false);


    private static NSEC Nsec(String Owner, String Next)
        => new (DomainName.ParseLenient(Owner),
                DNSQueryClasses.IN,
                TimeSpan.FromMinutes(5),
                DomainName.ParseLenient(Next),
                []);


    /// <summary>
    /// The seven fields all three synthesis sites in DNSClient set by hand.
    /// </summary>
    /// <remarks>
    /// All three are reached from here now. The third - every server query
    /// raising rather than answering - was described as out of reach while the
    /// only ways tried were a refused port and a silent one, and those produce a
    /// DNSInfo of their own instead. A server configured by name and never
    /// connected is the way in.
    /// </remarks>
    /// <param name="Proven">
    /// Whether this non-answer is a denial the client can prove, or a failure to
    /// obtain one. The two are not the same object and RFC 1035 §4.1.1 is why: RCODE
    /// 3 is "Meaningful only for responses from an authoritative name server", so a
    /// client that could not ask has no standing to use it and says RCODE 2 instead —
    /// "The name server was unable to process this query". A validated NSEC is the one
    /// case here where absence really was established (RFC 8198), and that one is
    /// entitled to deny.
    /// <para>
    /// IsValid follows the same line. It is the field the transports and
    /// <c>DNSSECValidator</c> test to decide whether to keep looking, so a failure
    /// marked valid is one the rest of the library stops questioning.
    /// </para>
    /// </param>
    private static void AssertSynthesizedShape(DNSInfo Answer, Boolean Proven, String Where)
    {

        Assert.Multiple(() => {

            Assert.That(Answer.ResponseCode,
                        Is.EqualTo(Proven ? DNSResponseCodes.NameError : DNSResponseCodes.ServerFailure),
                        Proven
                            ? $"{Where}: absence was established, so the denial is one this client may make"
                            : $"{Where}: §4.1.1 reserves a name error for an authoritative response, and none was obtained");


            Assert.That(Answer.AuthoritativeAnswer, Is.False,
                        $"{Where}: §4.1.1 makes AA a statement that the responding name server is an " +
                        "authority for the name, and no name server responded");

            Assert.That(Answer.RecursionAvailable, Is.False,
                        $"{Where}: §4.1.1 makes RA a statement about recursion support in the name " +
                        "server, and there is no name server to have any");

            Assert.That(Answer.IsTruncated, Is.False,
                        $"{Where}: nothing was truncated because nothing was transmitted");

            // Hermod's own fields rather than header bits: IsTimeout separates "no
            // answer came in time" from "the answer is that there is none", and
            // IsValid says the object may be read at all. Pinned as behaviour, not
            // claimed as conformance.
            Assert.That(Answer.IsTimeout, Is.False,
                        $"{Where}: no deadline passed while waiting for an answer");

            Assert.That(Answer.IsValid, Is.EqualTo(Proven),
                        Proven
                            ? $"{Where}: a proved absence is an answer, and meant to be read"
                            : $"{Where}: a failure to ask is not an answer, and saying so is what stops it being relied on");

        });

    }

    #endregion


    #region A client with nowhere to ask (RFC 1035 §4.1.1)

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task A_Client_With_No_Servers_Claims_No_Authority_And_No_Recursion()
    {

        using var client = ClientWithNoServers();

        var answer = await client.Query(DNSServiceName.Parse("nowhere.example."),
                                        [ DNSResourceRecordTypes.A ],
                                        ShortTimeout);

        AssertSynthesizedShape(answer, Proven: false, "no servers configured");

    }

    #endregion


    #region An answer the cache already proves (RFC 8198, RFC 1035 §4.1.1)

    [Test]
    [Property("RFC", "8198 §5.1, 1035 §4.1.1")]
    public async Task An_Nsec_Proved_Absence_Is_Answered_Without_Asking_Anyone()
    {

        // RFC 8198's whole point: one validated NSEC proves a range of names
        // absent, so the resolver answers from it rather than asking again. The
        // answer is then synthesized, and carries the same obligation as the one
        // above — nothing responded, so nothing is authoritative.
        await using var server = new ScriptedUdpServer(
            request => RawDnsResponder.Answer(request, ("inside.example.", RawDnsType.A, 300, [192, 0, 2, 1]))
        );

        using var client = ClientFor(server.Port);

        client.DNSCache.AddNSECRange("example.", Nsec("a.example.", "z.example."), TimeSpan.FromMinutes(5));

        var answer = await client.Query(DNSServiceName.Parse("inside.example."),
                                        [ DNSResourceRecordTypes.A ],
                                        ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(server.Requests, Is.Empty,
                        "§5.1: the cached NSEC already proves this name absent, so no question is sent");

            Assert.That(answer.ResponseCode, Is.EqualTo(DNSResponseCodes.NameError),
                        "and what the NSEC proves is that the name does not exist");

        });

        AssertSynthesizedShape(answer, Proven: true, "proved absent by a cached NSEC");

    }

    #endregion


    #region What the response says was asked for (RFC 1035 §4.1.1)

    /// <summary>
    /// What a synthesized answer says was asked for (finding 60, fixed).
    /// </summary>
    /// <remarks>
    /// All five sites - three here, two in <c>DNSUDPClient</c> - used to write a
    /// literal into the field while the caller's value sat in a parameter in scope at
    /// each of them. Two of the five wrote opposite literals, so one file disagreed
    /// with itself. Each now takes the value the method was called with, resolved once
    /// per call so that the answer and the outgoing query cannot differ about it.
    /// </remarks>
    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task A_Synthesized_Answer_Reports_The_Recursion_That_Was_Asked_For()
    {

        // RFC 1035 §4.1.1 on RD: "this bit may be set in a query and is copied
        // into the response". Hermod's field is named RecursionRequested, which
        // says the same thing in its own words — it records what the caller
        // asked, not what any server decided.
        //
        // The caller here asks with recursion switched off, and the client answers
        // without consulting anyone. Whatever it reports about the request is
        // something it knows for certain, because it is the one that was asked.
        using var client = ClientWithNoServers();

        var withoutRecursion = await client.Query(DNSServiceName.Parse("nowhere.example."),
                                                  [ DNSResourceRecordTypes.A ],
                                                  ShortTimeout,
                                                  RecursionDesired: false);

        var withRecursion    = await client.Query(DNSServiceName.Parse("nowhere.example."),
                                                  [ DNSResourceRecordTypes.A ],
                                                  ShortTimeout,
                                                  RecursionDesired: true);

        Assert.Multiple(() => {

            Assert.That(withRecursion.RecursionRequested, Is.True,
                        "recursion was asked for");

            Assert.That(withoutRecursion.RecursionRequested, Is.False,
                        "and here it was not");

        });

    }

    #endregion

    #region A client whose server has no address (RFC 1035 §4.1.1)

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task A_Server_That_Cannot_Be_Dialled_Still_Produces_An_Answer()
    {

        // The third synthesis site, and the one the other two hid. It is reached
        // when every configured server failed before a response existed — not
        // when they answered badly or not in time, since a transport that times
        // out or refuses returns a DNSInfo of its own and this site is skipped.
        //
        // A server known by name and never connected is the plain way in:
        // DNSServerConfig says so itself — "This is what a DNS-over-HTTPS or
        // DNS-over-TLS endpoint is before its socket connects, and what it stays
        // if the connection never succeeds" — and dialling one raises rather than
        // returning.
        //
        // What must not happen is the exception reaching the caller. A resolver
        // API that throws for a configuration problem makes every call site carry
        // a catch for something the resolver already knows how to say.
        using var client = new DNSClient(
                               ManualDNSServers:  [ new DNSServerConfig(DomainName.Parse("dns.example.")) ],
                               QueryTimeout:      ShortTimeout,
                               UseQueryCache:     false
                           );

        var answer = await client.Query(DNSServiceName.Parse("undialable.example."),
                                        [ DNSResourceRecordTypes.A ],
                                        ShortTimeout);

        Assert.That(answer.Answers, Is.Empty,
                    "nobody was asked, so there is nothing in the answer section");

        AssertSynthesizedShape(answer, Proven: false, "no server could be dialled");

    }

    #endregion

    #region A question with no name (RFC 1035 §4.1.2)

    [Test]
    [Property("RFC", "1035 §4.1.2")]
    public async Task A_Query_With_No_Name_Is_Answered_Rather_Than_Thrown_At()
    {

        // RFC 1035 §4.1.2 gives every question a QNAME, so a query without a name
        // is not a query. The guard that refuses one shares its condition with the
        // guard that refuses a client with no servers, and the two look
        // interchangeable from outside: with the condition joined the wrong way
        // round, a server-less client still ends up with the same name error from
        // the site above, which is why `A_Client_With_No_Servers_...` cannot tell
        // the difference and this can.
        //
        // The name is the half where the two differ, because there is nothing
        // downstream that copes with its absence: the next thing the query does
        // with the name is ask the NSEC cache about it.
        await using var server = new ScriptedUdpServer(
            request => RawDnsResponder.Answer(request, ("named.example.", RawDnsType.A, 300, [192, 0, 2, 1]))
        );

        using var client = ClientFor(server.Port);

        var answer = await client.Query((DNSServiceName) null!,
                                        [ DNSResourceRecordTypes.A ],
                                        ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(answer.ResponseCode, Is.EqualTo(DNSResponseCodes.ServerFailure),
                        "a question with no name is refused, and a refusal to ask is not a denial of the name");

            Assert.That(server.Requests, Is.Empty,
                        "and nothing was sent on its behalf");

        });

    }

    #endregion

}

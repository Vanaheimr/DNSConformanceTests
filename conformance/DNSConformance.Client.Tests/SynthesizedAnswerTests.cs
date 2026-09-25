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
    /// The six fields all three synthesis sites in DNSClient set by hand.
    /// </summary>
    private static void AssertSynthesizedShape(DNSInfo Answer, String Where)
    {

        Assert.Multiple(() => {

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
                        $"{Where}: the client did not run out of time, it declined to wait");

            Assert.That(Answer.IsValid, Is.True,
                        $"{Where}: the answer is meant to be read rather than discarded");

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

        Assert.That(answer.ResponseCode, Is.EqualTo(DNSResponseCodes.NameError),
                    "the client has nobody to ask and says so with a name error");

        AssertSynthesizedShape(answer, "no servers configured");

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

        AssertSynthesizedShape(answer, "proved absent by a cached NSEC");

    }

    #endregion


    #region What the response says was asked for (RFC 1035 §4.1.1)

    /// <summary>
    /// Red for finding 60: a synthesized answer reports recursion it was not asked for.
    /// </summary>
    /// <remarks>
    /// Left failing on purpose, as PLAN.md §9 asks. All three synthesis sites write
    /// the literal <c>RecursionDesired: true</c> while the caller's value sits in a
    /// parameter in scope at each of them, so the field says the same thing whatever
    /// was asked. Making the test agree with the code would close the only signal
    /// there is.
    /// </remarks>
    [Test]
    [Category(TestCategories.KnownIssue)]
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

}

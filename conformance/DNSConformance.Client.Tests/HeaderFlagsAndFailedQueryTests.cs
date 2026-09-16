using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// The four header bits the client reads and never checked, and what it says
/// about a query that got no answer at all.
///
/// Second file from the mutation sweep's core block, and the one whose shape
/// said something before a single test was written: of `DNSInfo`'s twenty gaps,
/// all twenty were branches — not one boundary, not one rejection path. This is
/// the type that decides what a query *came back as*, and no test had taken both
/// sides of any of those decisions.
///
/// They fall into two halves. RFC 1035 §4.1.1's flags, read out of the response
/// octets: QR, AA, RD and RA could each be inverted without a test noticing,
/// while TC, AD and CD could not — the truncation and DNSSEC rounds had already
/// pinned those three, which is exactly the shape of a suite that tests what it
/// went looking for.
///
/// And the answers that are not answers. A query that timed out, failed or came
/// back unreadable still produces a <c>DNSInfo</c>, and every flag on it is a
/// claim about a response that never arrived.
/// </summary>
[TestFixture]
[Property("RFC", "1035 §4.1.1")]
public class HeaderFlagsAndFailedQueryTests
{

    #region Data

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromSeconds(10);

    private static readonly DNSServerConfig Nowhere =
        new (IPv4Address.Parse("192.0.2.1"), IPPort.Parse(53));

    /// <summary>
    /// An answer to whatever was asked, carrying exactly the flags given — no
    /// QR or RA added behind the test's back, because which bits are set is the
    /// thing under test.
    /// </summary>
    private static Byte[] AnswerWithExactly(Byte[] Request, UInt16 Flags)

        => new RawDnsWriter().
               Header(
                   (UInt16) ((Request[0] << 8) | Request[1]),
                   (UInt16) (RawDnsFlags.QR | Flags),
                   1, 1, 0, 0
               ).
               Question("flags.example.", RawDnsType.A).
               RR("flags.example.", RawDnsType.A, RawDnsClass.IN, 60, RawDnsWriter.IPv4("192.0.2.1")).
               ToArray();

    private static async Task<DNSInfo> AskAndGetBack(UInt16 Flags)
    {

        await using var peer    = new ScriptedUdpServer(request => AnswerWithExactly(request, Flags));
        using       var client  = new DNSClient(
                                      IPv4Address.Localhost,
                                      IPPort.Parse((UInt16) peer.Port),
                                      QueryTimeout:   ShortTimeout,
                                      UseQueryCache:  false
                                  );

        return await client.Query(DNSServiceName.Parse("flags.example."),
                                  [ DNSResourceRecordTypes.A ],
                                  ShortTimeout);

    }

    #endregion


    #region The flags a response carries (RFC 1035 §4.1.1)

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task The_Client_Sees_The_Authoritative_Answer_Bit()
    {

        // RFC 1035 §4.1.1: "AA — Authoritative Answer — this bit is valid in
        // responses, and specifies that the responding name server is an
        // authority for the domain name in question section."
        //
        // Both directions matter and for different reasons. Losing a set AA
        // throws away the one thing that distinguishes an answer from the source
        // of truth from one out of somebody's cache; inventing a clear one
        // claims that authority for a cached answer.
        var authoritative  = await AskAndGetBack(RawDnsFlags.AA);
        var cached         = await AskAndGetBack(0);

        Assert.Multiple(() => {
            Assert.That(authoritative.AuthoritativeAnswer, Is.True,  "AA set by the responder");
            Assert.That(cached.       AuthoritativeAnswer, Is.False, "and not invented when it is clear");
            Assert.That(authoritative.Answers, Is.Not.Empty, "the answer still arrives either way");
        });

    }

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task The_Client_Sees_The_Recursion_Desired_Bit()
    {

        // "RD — Recursion Desired — this bit may be set in a query and is copied
        // into the response." Copied, which makes it the client's own request
        // reflected back: a response that does not carry it answered a different
        // question from the one that was asked.
        var desired     = await AskAndGetBack(RawDnsFlags.RD);
        var notDesired  = await AskAndGetBack(0);

        Assert.Multiple(() => {
            Assert.That(desired.   RecursionRequested, Is.True);
            Assert.That(notDesired.RecursionRequested, Is.False);
        });

    }

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task The_Client_Sees_The_Recursion_Available_Bit()
    {

        // "RA — Recursion Available — this be is set or cleared in a response,
        // and denotes whether recursive query support is available in the name
        // server." It is how a stub finds out that the server it is talking to
        // will not do the walking for it, and reading it wrong means never
        // finding out.
        var available    = await AskAndGetBack(RawDnsFlags.RA);
        var notAvailable = await AskAndGetBack(0);

        Assert.Multiple(() => {
            Assert.That(available.   RecursionAvailable, Is.True);
            Assert.That(notAvailable.RecursionAvailable, Is.False);
        });

    }

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task Each_Flag_Is_Read_From_Its_Own_Bit()
    {

        // The four live in two octets beside four others, and reading one of
        // them off the wrong bit is invisible as long as every test sets them
        // together. So: all four at once, then each one alone against the other
        // three clear.
        var all = await AskAndGetBack((UInt16) (RawDnsFlags.AA | RawDnsFlags.RD | RawDnsFlags.RA));

        Assert.Multiple(() => {
            Assert.That(all.AuthoritativeAnswer, Is.True);
            Assert.That(all.RecursionRequested,  Is.True);
            Assert.That(all.RecursionAvailable,  Is.True);
            Assert.That(all.IsTruncated,         Is.False, "TC was not set and must not be read out of a neighbour");
            Assert.That(all.AuthenticData,       Is.False);
            Assert.That(all.CheckingDisabled,    Is.False);
        });

        var onlyAA = await AskAndGetBack(RawDnsFlags.AA);

        Assert.Multiple(() => {
            Assert.That(onlyAA.AuthoritativeAnswer, Is.True);
            Assert.That(onlyAA.RecursionRequested,  Is.False);
            Assert.That(onlyAA.RecursionAvailable,  Is.False);
        });

    }

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task A_Response_That_Arrived_Is_Not_A_Timeout()
    {

        // The other half of finding 53. A DNSInfo built from octets that actually
        // came back says so, and a caller that cannot tell a real answer from a
        // deadline has no way to decide whether to retry.
        var answered = await AskAndGetBack(RawDnsFlags.RA);

        Assert.Multiple(() => {
            Assert.That(answered.IsTimeout, Is.False, "the response arrived");
            Assert.That(answered.IsValid,   Is.True);
            Assert.That(answered.Answers,   Is.Not.Empty);
        });

    }

    #endregion


    #region The answers that are not answers (RFC 1035 §4.1.1)

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    [Property("RFC", "7766 §7")]
    public void A_Query_That_Timed_Out_Claims_Nothing_About_A_Response()
    {

        // No octets arrived, so there is nothing to have read a flag out of.
        // §4.1.1 makes AA and RA properties of a response, and TC a statement
        // that one was shortened — all three are claims a timeout cannot make.
        // Reporting any of them true is inventing the answer that did not come.
        var timedOut = DNSInfo.TimedOut(Nowhere, 4711, TimeSpan.FromSeconds(2));

        Assert.Multiple(() => {

            Assert.That(timedOut.AuthoritativeAnswer, Is.False, "nothing answered, authoritatively or otherwise");
            Assert.That(timedOut.IsTruncated,         Is.False, "nothing arrived to be truncated");
            Assert.That(timedOut.RecursionRequested,  Is.False);
            Assert.That(timedOut.RecursionAvailable,  Is.False, "no server said whether it recurses");

            Assert.That(timedOut.IsValid,             Is.False, "and the whole of it is not a valid answer");
            Assert.That(timedOut.IsTimeout,           Is.True,  "which is the one thing it does say");

            Assert.That(timedOut.ResponseCode,        Is.EqualTo(DNSResponseCodes.ServerFailure));
            Assert.That(timedOut.Answers,             Is.Empty);

        });

    }

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public void A_Query_That_Failed_Claims_Nothing_Either_And_Is_Not_A_Timeout()
    {

        // Finding 53's distinction, from the side that has to stay distinct: a
        // network error, a closed connection or an unreadable response is not a
        // deadline, and a caller deciding whether to wait longer or move to
        // another server needs the two apart.
        var failed = DNSInfo.Failed(Nowhere, 4711, TimeSpan.FromSeconds(2));

        Assert.Multiple(() => {

            Assert.That(failed.AuthoritativeAnswer, Is.False);
            Assert.That(failed.IsTruncated,         Is.False);
            Assert.That(failed.RecursionRequested,  Is.False);
            Assert.That(failed.RecursionAvailable,  Is.False);

            Assert.That(failed.IsValid,             Is.False);
            Assert.That(failed.IsTimeout,           Is.False, "this one is not a deadline, and that is the point of it");

            Assert.That(failed.ResponseCode,        Is.EqualTo(DNSResponseCodes.ServerFailure));

        });

    }

    [Test]
    [Property("RFC", "5452 §9.1")]
    public void A_Response_With_The_Wrong_Transaction_Id_Claims_Nothing()
    {

        // RFC 5452 §9.1 has the client discard a response whose ID does not
        // match, which is finding 49's rule. What it is left holding must not
        // look like an answer: the flags belong to octets from somewhere else,
        // and carrying any of them through would be carrying Mallory's.
        var invalid = DNSInfo.Invalid(Nowhere, 4711);

        Assert.Multiple(() => {

            Assert.That(invalid.AuthoritativeAnswer, Is.False);
            Assert.That(invalid.IsTruncated,         Is.False);
            Assert.That(invalid.RecursionRequested,  Is.False);
            Assert.That(invalid.RecursionAvailable,  Is.False);

            Assert.That(invalid.IsValid,             Is.False);
            Assert.That(invalid.IsTimeout,           Is.False, "a forged reply is not a deadline");

            Assert.That(invalid.Answers,             Is.Empty);
            Assert.That(invalid.Authorities,         Is.Empty);
            Assert.That(invalid.AdditionalRecords,   Is.Empty);

        });

    }

    #endregion

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// How long the client cache may go on serving a record.
///
/// Two record types at one name share a cache entry, and the entry's lifetime
/// is recomputed from whichever answer arrived last — so the question is
/// whether each record still keeps its own clock underneath that.
///
/// As in <see cref="NegativeCachingTests"/>, a cache hit is established by the
/// absence of a request on the wire rather than by asking the cache what it
/// thinks it did. Counts are taken before and after the query under test: the
/// UDP client retransmits, so two datagrams can belong to one query, and a
/// bound on the running total is met before the second query is ever sent.
///
/// Two further tests were written here and then withdrawn — that a timed-out
/// query and a rejected response each leave nothing behind. Both are true, and
/// six mutations across three layers of the caching path failed to make either
/// of them fail, so neither could be shown to catch anything. A test that
/// cannot be killed is not evidence, and a green one that is not evidence is
/// worse than none.
/// </summary>
[TestFixture]
[Property("RFC", "1035 §3.2.1")]
public class CacheExpiryTests
{

    #region Data

    private static readonly TimeSpan  ShortTimeout  = TimeSpan.FromMilliseconds(600);

    private static DNSClient ClientFor(Int32 Port)
        => new(
               IPv4Address.Localhost,
               IPPort.Parse((UInt16) Port),
               QueryTimeout:   ShortTimeout,
               UseQueryCache:  true
           );

    /// <summary>MX RDATA: a 16-bit preference and an uncompressed exchange name.</summary>
    private static Byte[] MxRdata(UInt16 Preference, String Exchange)
        => [(Byte) (Preference >> 8), (Byte) (Preference & 0xFF), .. RawDnsWriter.NameBytes(Exchange)];

    private static Int32 QuestionsOfType(ScriptedUdpServer Server, UInt16 Type)
        => Server.Requests.
               Count(request => RawDnsReader.Parse(request).Questions.Any(question => question.Type == Type));

    #endregion


    #region A_Short_Lived_Record_Stops_Being_Served_While_A_Long_Lived_One_Does_Not()

    [Test]
    [Property("RFC", "1035 §3.2.1")]
    public async Task A_Short_Lived_Record_Stops_Being_Served_While_A_Long_Lived_One_Does_Not()
    {

        // RFC 1035 §3.2.1 makes the TTL the record's own: "the time interval that
        // the resource record may be cached before the source of the information
        // should again be consulted". Two record types at one name are cached
        // together, so the question is whether each keeps its own clock — an A
        // with one second on it must be asked for again while an MX with an hour
        // on it must not.
        //
        // This asserts the behaviour and not the mechanism. The cache has both a
        // per-record expiry filter and a periodic sweep, and either alone produces
        // this outcome, so a mutation of the filter survives this test. That is
        // recorded rather than papered over.
        await using var server = new ScriptedUdpServer(
            request => {

                var question = RawDnsReader.Parse(request).Questions.Single();

                return question.Type == RawDnsType.MX
                           ? RawDnsResponder.Answer(request, ("both.example.", RawDnsType.MX, 3600, MxRdata(10, "mail.both.example.")))
                           : RawDnsResponder.Answer(request, ("both.example.", RawDnsType.A,     1, [192, 0, 2, 7]));

            }
        );

        using var client = ClientFor(server.Port);

        var a  = await client.Query<A> (DomainName.Parse("both.example."), ShortTimeout);
        var mx = await client.Query<MX>(DomainName.Parse("both.example."), ShortTimeout);

        Assert.Multiple(() => {
            Assert.That(a. FilteredAnswers.Any(), Is.True, "the A answer arrived");
            Assert.That(mx.FilteredAnswers.Any(), Is.True, "the MX answer arrived");
        });

        // Both are cached now. Repeating the A query straight away must not reach
        // the wire — without this the assertion further down cannot tell "expired"
        // from "never cached", which is the whole distinction it exists to make.
        var beforeImmediate = QuestionsOfType(server, RawDnsType.A);

        await client.Query<A>(DomainName.Parse("both.example."), ShortTimeout);

        Assert.That(QuestionsOfType(server, RawDnsType.A), Is.EqualTo(beforeImmediate),
                    "inside its TTL the A record comes from the cache — otherwise nothing below means anything");

        await Task.Delay(TimeSpan.FromMilliseconds(1600));      // past the A's second, nowhere near the MX's hour

        var aBefore  = QuestionsOfType(server, RawDnsType.A);
        var mxBefore = QuestionsOfType(server, RawDnsType.MX);

        await client.Query<MX>(DomainName.Parse("both.example."), ShortTimeout);
        await client.Query<A> (DomainName.Parse("both.example."), ShortTimeout);

        Assert.Multiple(() => {

            Assert.That(QuestionsOfType(server, RawDnsType.MX), Is.EqualTo(mxBefore),
                        "the MX has 3598 seconds left and must still come from the cache");

            Assert.That(QuestionsOfType(server, RawDnsType.A), Is.GreaterThan(aBefore),
                        "the A's own second is over, so it must be asked for again");

        });

    }

    #endregion

}

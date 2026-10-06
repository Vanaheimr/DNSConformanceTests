using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// What a cache hit hands back, compared with the answer it stands in for.
/// </summary>
/// <remarks>
/// <para>
/// The other cache tests here establish <em>that</em> a second query is served
/// from the cache, by counting what reaches the socket. These ask what the
/// served answer holds. A hit is a promise that the caller cannot tell it apart
/// from asking again, and two things break that promise in opposite directions:
/// handing back more than was asked for, and handing back less than the answer
/// carried.
/// </para>
/// <para>
/// Both matter beyond tidiness, because the cached answer is what a validator
/// reads. A DNSSEC proof that an answer is negative lives in its authority
/// section; an answer section that has picked up the name's DNSKEY and DS RRsets
/// next to the records asked for no longer has the shape the signatures over it
/// were made for.
/// </para>
/// </remarks>
[TestFixture]
public class CachedAnswerTests
{

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);


    private static DNSClient ClientFor(Int32 port)
        => new(
               IPv4Address.Localhost,
               IPPort.Parse((UInt16) port),
               QueryTimeout:   Timeout,
               UseQueryCache:  true
           );

    private static UInt16 QuestionType(Byte[] request)
        => RawDnsReader.Parse(request, RawDnsReaderOptions.Lenient).Questions[0].Type;

    private static Byte[] Txt(String text)
        => [ (Byte) text.Length, .. System.Text.Encoding.ASCII.GetBytes(text) ];


    #region A_Cached_Answer_Holds_Only_The_Type_Asked_For()

    /// <summary>
    /// Finding 74. RFC 1035 §4.1 gives the answer section one job — "RRs answering
    /// the question" — and RFC 2308 §5 asks a cached negative answer to come back
    /// for the same name and type it was given for, which is the same rule seen
    /// from the other side. The name here has an A RRset and a TXT RRset, asked for
    /// one after the other; the A query asked again comes from the cache.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1")]
    public async Task A_Cached_Answer_Holds_Only_The_Type_Asked_For()
    {

        var requests = 0;

        await using var server = new ScriptedUdpServer(request => {

            Interlocked.Increment(ref requests);

            return QuestionType(request) switch {
                RawDnsType.A   => RawDnsResponder.Answer(request, ("both.example.", RawDnsType.A,   3600, RawDnsWriter.IPv4("192.0.2.1"))),
                RawDnsType.TXT => RawDnsResponder.Answer(request, ("both.example.", RawDnsType.TXT, 3600, Txt("hello"))),
                _              => RawDnsResponder.Negative(request, 0, "example.")
            };

        });

        using var client = ClientFor(server.Port);

        var name   = DomainName.Parse("both.example.");

        var first  = await client.Query(name, [ DNSResourceRecordTypes.A   ], Timeout);
        var txt    = await client.Query(name, [ DNSResourceRecordTypes.TXT ], Timeout);
        var second = await client.Query(name, [ DNSResourceRecordTypes.A   ], Timeout);

        Assert.Multiple(() => {

            Assert.That(first.Answers.Select(rr => rr.Type).ToArray(), Is.EqualTo(new[] { DNSResourceRecordTypes.A }),
                        "the first answer, from the wire");

            Assert.That(txt.Answers.Select(rr => rr.Type).ToArray(), Is.EqualTo(new[] { DNSResourceRecordTypes.TXT }),
                        "the TXT answer, from the wire");

            Assert.That(requests, Is.EqualTo(2),
                        $"the repeated A query is the one the cache answers; saw {requests} requests");

            Assert.That(second.Answers.Select(rr => rr.Type).ToArray(), Is.EqualTo(new[] { DNSResourceRecordTypes.A }),
                        "the cached answer to an A query holds the A RRset, and not every RRset cached under the name");

        });

    }

    #endregion

    #region A_Cached_Nodata_Answer_Keeps_Its_Authority_Section()

    /// <summary>
    /// Finding 75. RFC 2308 §5: a NODATA answer "should be cached such that it can
    /// be retrieved and returned in response to another query for the same
    /// &lt;QNAME, QTYPE, QCLASS&gt;", and the NXT record of a negative answer —
    /// NSEC today — "MUST be stored such that it can be be located and returned
    /// with SOA record in the authority section, as should any SIG records". The
    /// authority section is the answer: it is where the TTL of the negative answer
    /// comes from, and where its DNSSEC proof is.
    /// </summary>
    /// <remarks>
    /// The name has an AAAA RRset and no A RRset. The A query comes first and is
    /// NODATA; the AAAA query after it is the last answer cached under the name.
    /// The repeated A query comes from the cache and must be what the first one
    /// was: NOERROR, an empty answer section, the zone's SOA in the authority
    /// section — and not whichever answer the name was cached with last.
    /// </remarks>
    [Test]
    [Property("RFC", "2308 §5")]
    public async Task A_Cached_Nodata_Answer_Keeps_Its_Authority_Section()
    {

        var requests = 0;

        await using var server = new ScriptedUdpServer(request => {

            Interlocked.Increment(ref requests);

            return QuestionType(request) switch {
                RawDnsType.AAAA => RawDnsResponder.Answer(request, ("six.example.", RawDnsType.AAAA, 3600, RawDnsWriter.IPv6("2001:db8::1"))),
                _               => RawDnsResponder.Negative(request, 0, "example.", SoaMinimum: 3600)
            };

        });

        using var client = ClientFor(server.Port);

        var name   = DomainName.Parse("six.example.");

        var first  = await client.Query(name, [ DNSResourceRecordTypes.A    ], Timeout);
        var aaaa   = await client.Query(name, [ DNSResourceRecordTypes.AAAA ], Timeout);
        var second = await client.Query(name, [ DNSResourceRecordTypes.A    ], Timeout);

        Assert.Multiple(() => {

            Assert.That(aaaa.Answers.Select(rr => rr.Type).ToArray(), Is.EqualTo(new[] { DNSResourceRecordTypes.AAAA }),
                        "the AAAA answer, from the wire");

            Assert.That(first.Answers, Is.Empty,
                        "the first A answer is NODATA, from the wire");

            Assert.That(first.Authorities.Select(rr => rr.Type), Does.Contain(DNSResourceRecordTypes.SOA),
                        "and carries the zone's SOA");

            Assert.That(requests, Is.EqualTo(2),
                        $"the repeated A query is the one the cache answers; saw {requests} requests");

            Assert.That(second.ResponseCode, Is.EqualTo(DNSResponseCodes.NoError),
                        "the cached answer is still NODATA");

            Assert.That(second.Answers, Is.Empty,
                        "and its answer section is still empty — not the name's AAAA RRset");

            Assert.That(second.Authorities.Select(rr => rr.Type), Does.Contain(DNSResourceRecordTypes.SOA),
                        "and its authority section still holds the SOA it was cached with");

        });

    }

    #endregion

}

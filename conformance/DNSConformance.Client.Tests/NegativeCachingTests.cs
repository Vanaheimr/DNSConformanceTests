using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 2308 — negative caching of NXDOMAIN and NODATA.
///
/// Negative answers are the majority of the traffic a busy resolver sees, and
/// not caching them is how a typo in someone's config turns into sustained load
/// on the root. The TTL is not the query's — it comes from the SOA the responder
/// puts in the authority section.
///
/// Every test here counts what actually reached the socket, so a "cache hit" is
/// established by the absence of a second request rather than by asking the
/// cache whether it thinks it hit.
/// </summary>
[TestFixture]
[Property("RFC", "2308")]
public class NegativeCachingTests
{

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);


    private static DNSClient ClientFor(Int32 port, Boolean useCache = true)
        => new(
               IPv4Address.Localhost,
               IPPort.Parse((UInt16) port),
               QueryTimeout:   Timeout,
               UseQueryCache:  useCache
           );


    #region Nxdomain_Is_Answered_And_Reported()

    [Test]
    [Property("RFC", "2308 §2.1")]
    public async Task Nxdomain_Is_Answered_And_Reported()
    {

        await using var server = new ScriptedUdpServer(request =>
            RawDnsResponder.Negative(request, 3, "example.", SoaMinimum: 900));

        using var client = ClientFor(server.Port);

        var response = await client.Query<A>(DomainName.Parse("nope.example."), Timeout);

        Assert.That(response.ResponseCode, Is.EqualTo(DNSResponseCodes.NameError),
                    "an authoritative name error must surface as NXDOMAIN");

    }

    #endregion

    #region Nodata_Is_Noerror_With_No_Answers()

    [Test]
    [Property("RFC", "2308 §2.2")]
    public async Task Nodata_Is_Noerror_With_No_Answers()
    {

        // RFC 2308 §2.2: NODATA is NOERROR with an empty answer section — the name
        // exists, this type does not. Collapsing it into NXDOMAIN would tell the
        // caller the name is free when it is not.
        await using var server = new ScriptedUdpServer(request =>
            RawDnsResponder.Negative(request, 0, "example.", SoaMinimum: 900));

        using var client = ClientFor(server.Port);

        var response = await client.Query<A>(DomainName.Parse("exists.example."), Timeout);

        Assert.Multiple(() => {
            Assert.That(response.ResponseCode,    Is.EqualTo(DNSResponseCodes.NoError));
            Assert.That(response.FilteredAnswers, Is.Empty);
        });

    }

    #endregion

    #region Repeated_Nxdomain_Query_Is_Served_From_The_Cache()

    [Test]
    [Property("RFC", "2308 §5")]
    public async Task Repeated_Nxdomain_Query_Is_Served_From_The_Cache()
    {

        var requests = 0;

        await using var server = new ScriptedUdpServer(request => {
            Interlocked.Increment(ref requests);
            return RawDnsResponder.Negative(request, 3, "example.", SoaMinimum: 3600);
        });

        using var client = ClientFor(server.Port);

        var name = DomainName.Parse("cached-nxdomain.example.");

        var first  = await client.Query<A>(name, Timeout);
        var second = await client.Query<A>(name, Timeout);

        Assert.Multiple(() => {

            Assert.That(first. ResponseCode, Is.EqualTo(DNSResponseCodes.NameError));
            Assert.That(second.ResponseCode, Is.EqualTo(DNSResponseCodes.NameError),
                        "the cached negative answer must be the same answer");

            Assert.That(requests, Is.EqualTo(1),
                        $"the second query must not reach the wire; saw {requests} requests");

        });

    }

    #endregion

    #region Repeated_Nodata_Query_Is_Served_From_The_Cache()

    [Test]
    [Property("RFC", "2308 §5")]
    public async Task Repeated_Nodata_Query_Is_Served_From_The_Cache()
    {

        var requests = 0;

        await using var server = new ScriptedUdpServer(request => {
            Interlocked.Increment(ref requests);
            return RawDnsResponder.Negative(request, 0, "example.", SoaMinimum: 3600);
        });

        using var client = ClientFor(server.Port);

        var name = DomainName.Parse("cached-nodata.example.");

        var first = await client.Query<A>(name, Timeout);

        // Precondition, not the assertion under test: the negative TTL can only
        // come from the SOA, so if the SOA never arrived this test would be
        // measuring the suite rather than Hermod.
        Assert.That(first.Authorities.OfType<SOA>().Any(), Is.True,
                    "the scripted NODATA response must deliver a parseable SOA in the authority section");

        await client.Query<A>(name, Timeout);

        Assert.That(requests, Is.EqualTo(1),
                    $"a NODATA answer must be cached too (RFC 2308 §5); saw {requests} requests");

    }

    #endregion

    #region Negative_Answer_Expires_After_The_Soa_Minimum()

    [Test]
    [Property("RFC", "2308 §4")]
    [Category(TestCategories.Slow)]
    public async Task Negative_Answer_Expires_After_The_Soa_Minimum()
    {

        // RFC 2308 §4: the negative TTL is min(SOA MINIMUM, SOA record TTL).
        //
        // The two are deliberately far apart here. MINIMUM is 1 s and the SOA's own
        // TTL is an hour, so a cache that reads only the record's TTL — which is the
        // easy mistake, since every other record's lifetime does come from there —
        // would still be holding the entry three seconds later.
        var requests = 0;

        await using var server = new ScriptedUdpServer(request => {
            Interlocked.Increment(ref requests);
            return RawDnsResponder.Negative(request, 3, "example.", SoaMinimum: 1, SoaTtl: 3600);
        });

        using var client = ClientFor(server.Port);

        var name = DomainName.Parse("short-lived.example.");

        await client.Query<A>(name, Timeout);

        await Task.Delay(TimeSpan.FromSeconds(3));

        await client.Query<A>(name, Timeout);

        Assert.That(requests, Is.EqualTo(2),
                    $"the negative entry must expire after the SOA MINIMUM; saw {requests} requests");

    }

    #endregion

    #region Referral_Is_Not_Cached_As_Nodata()

    [Test]
    [Property("RFC", "2308 §2.2")]
    public async Task Referral_Is_Not_Cached_As_Nodata()
    {

        // A referral and a NODATA answer are indistinguishable by RCODE and answer
        // count — both are NOERROR with nothing in the answer section. The SOA is
        // the only difference: RFC 2308 §2.2 defines NODATA as carrying one, and a
        // referral carries NS records instead.
        //
        // Treating a referral as NODATA would cache "this type does not exist" for
        // a name whose data is merely served elsewhere, and the second query must
        // therefore still go out.
        var requests = 0;

        await using var server = new ScriptedUdpServer(request => {
            Interlocked.Increment(ref requests);
            return RawDnsResponder.Referral(request, "example.", "ns1.example.");
        });

        using var client = ClientFor(server.Port);

        var name = DomainName.Parse("delegated.example.");

        await client.Query<A>(name, Timeout);
        await client.Query<A>(name, Timeout);

        Assert.That(requests, Is.EqualTo(2),
                    $"a referral carries no SOA and must not be cached as NODATA; saw {requests} requests");

    }

    #endregion

    #region Cache_Can_Be_Disabled()

    [Test]
    public async Task Cache_Can_Be_Disabled()
    {

        // The control for the tests above: with the cache off, both queries must
        // reach the wire. Without this, a broken cache and a perfect one look the
        // same from the outside.
        var requests = 0;

        await using var server = new ScriptedUdpServer(request => {
            Interlocked.Increment(ref requests);
            return RawDnsResponder.Negative(request, 3, "example.", SoaMinimum: 3600);
        });

        using var client = ClientFor(server.Port, useCache: false);

        var name = DomainName.Parse("uncached.example.");

        await client.Query<A>(name, Timeout, ForceUpdate: true);
        await client.Query<A>(name, Timeout, ForceUpdate: true);

        Assert.That(requests, Is.EqualTo(2));

    }

    #endregion

    #region Different_Types_At_One_Name_Are_Cached_Separately()

    [Test]
    [Property("RFC", "2308 §5")]
    public async Task Different_Types_At_One_Name_Are_Cached_Separately()
    {

        // A NODATA for A says nothing about AAAA. Caching negatives per name
        // instead of per (name, type) would hide every record of every other type
        // at that name for the whole negative TTL.
        var requests = 0;

        await using var server = new ScriptedUdpServer(request => {
            Interlocked.Increment(ref requests);
            return RawDnsResponder.Negative(request, 0, "example.", SoaMinimum: 3600);
        });

        using var client = ClientFor(server.Port);

        var name = DomainName.Parse("both-types.example.");

        await client.Query<A>   (name, Timeout);
        await client.Query<AAAA>(name, Timeout);

        Assert.That(requests, Is.EqualTo(2),
                    "a negative answer is keyed by name *and* type");

    }

    #endregion

}

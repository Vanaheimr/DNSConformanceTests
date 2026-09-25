using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

namespace DNSConformance.Client.Tests;

/// <summary>
/// The edges of the client cache, driven directly rather than through the wire.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="CacheExpiryTests"/> asks the cache the same questions through a
/// scripted server, and records in its own comments why that cannot reach the
/// per-record filter: the cache has both a filter on read and a periodic sweep,
/// either of which produces the same outcome from outside, so a mutation of one
/// is covered by the other. These construct the cache with a clean-up interval
/// long enough that the sweep never runs, which leaves the filter as the only
/// thing that can answer.
/// </para>
/// <para>
/// Nothing here travels in time. <c>DNSCache</c> reads <c>Timestamp.Now</c>
/// directly and takes no clock of its own, and Styx's time travel is global
/// mutable state shared with every other fixture — and its
/// <c>TravelBackInTime</c> and <c>TravelForwardInTime</c> have the same body, so
/// "back" moves forward. Each test below is built so the edge it needs is
/// reachable by an ordinary short TTL instead.
/// </para>
/// </remarks>
[TestFixture]
public class CacheBoundaryTests
{

    #region Data

    /// <summary>Long enough that the periodic sweep cannot fire during a test.</summary>
    private static DNSCache UnsweptCache()
        => new (CleanUpEvery: TimeSpan.FromHours(1));


    private static NSEC Nsec(String Owner, String Next)
        => new (DomainName.ParseLenient(Owner),
                DNSQueryClasses.IN,
                TimeSpan.FromMinutes(5),
                DomainName.ParseLenient(Next),
                []);


    /// <summary>
    /// An SOA that differs only in the two fields RFC 2308 §5 takes a minimum over.
    /// </summary>
    /// <remarks>
    /// RNAME is typed as an e-mail address here rather than as a domain name, which
    /// is why it is written as one: the wire form is a domain name whose first label
    /// is the local part.
    /// </remarks>
    private static SOA Soa(TimeSpan  OwnTimeToLive,
                           TimeSpan  Minimum)

        => new (DomainName.Parse("example."),
                DNSQueryClasses.IN,
                OwnTimeToLive,
                DomainName.Parse("ns1.example."),
                SimpleEMailAddress.Parse("hostmaster@example."),
                Serial:   1,
                Refresh:  TimeSpan.FromHours(2),
                Retry:    TimeSpan.FromHours(1),
                Expire:   TimeSpan.FromDays(14),
                Minimum:  Minimum);


    private static DNSInfo Info(IDNSResourceRecord[]  Answers,
                                IDNSResourceRecord[]  Authorities)

        => new (Origin:                 new DNSServerConfig(IPv4Address.Localhost, IPPort.DNS),
                QueryId:                0,
                IsAuthoritativeAnswer:  false,
                IsTruncated:            false,
                RecursionDesired:       false,
                RecursionAvailable:     false,
                ResponseCode:           DNSResponseCodes.NoError,
                Answers:                Answers,
                Authorities:            Authorities,
                AdditionalRecords:      [],
                IsValid:                true,
                IsTimeout:              false,
                Timeout:                TimeSpan.Zero,
                Runtime:                TimeSpan.Zero);

    #endregion


    #region Which zones an unqualified lookup tries (RFC 8198 §5.1)

    [Test]
    [Property("RFC", "8198 §5.1, 4034 §6.1")]
    public void The_Root_Is_Among_The_Zones_A_Name_Is_Tried_Against()
    {

        // Asked without a zone, the cache tries every ancestor of the name as a
        // candidate zone. The root is an ancestor of everything, and it is not a
        // corner case here: the root zone is NSEC-signed, and synthesising
        // NXDOMAIN for the root from one cached NSEC is the example RFC 8198 was
        // written around. A loop that stops one short of the root answers every
        // other question correctly and never finds anything the root proves.
        var cache = UnsweptCache();

        cache.AddNSECRange(".", Nsec("nl.", "nz."), TimeSpan.FromMinutes(5));

        Assert.Multiple(() => {

            Assert.That(cache.IsNameNegativelyCachedByNSEC("nx."), Is.True,
                        "the gap between two root-zone delegations proves this TLD absent");

            Assert.That(cache.IsNameNegativelyCachedByNSEC("nl."), Is.False,
                        "the owner name itself exists — an NSEC never denies its own owner");

        });

    }

    #endregion


    #region A zone that is nothing but its apex (RFC 4034 §4.1.1)

    [Test]
    [Property("RFC", "4034 §4.1.1, 8198 §5.1")]
    public void A_Zone_Whose_Only_Nsec_Points_At_Its_Own_Owner_Denies_Everything_Else()
    {

        // One NSEC whose next name equals its owner is a zone holding only its
        // apex: the chain has a single link and it closes on itself, so the gap
        // it spans is the whole name space of the zone. That is the degenerate
        // end of the wrap rule — a span "after the owner, or before the next"
        // where the two are the same name — and it is the one arrangement in
        // which "wraps" has to be decided by an equality rather than by an
        // ordering.
        var cache = UnsweptCache();

        cache.AddNSECRange("example.", Nsec("example.", "example."), TimeSpan.FromMinutes(5));

        Assert.Multiple(() => {

            Assert.That(cache.IsNameNegativelyCachedByNSEC("anything.example.", "example."), Is.True,
                        "a zone with only an apex proves every other name in it absent");

            Assert.That(cache.IsNameNegativelyCachedByNSEC("zzz.example.", "example."), Is.True,
                        "including names that sort after the owner");

            Assert.That(cache.IsNameNegativelyCachedByNSEC("example.", "example."), Is.False,
                        "the apex itself exists");

        });

    }

    #endregion


    #region A range that has been fetched again (RFC 8198 §5.1)

    [Test]
    [Property("RFC", "8198 §5.1")]
    public void A_Refetched_Nsec_Replaces_The_Range_It_Supersedes()
    {

        // The same owner name, a nearer next name: the gap has shrunk because
        // something was inserted into it. Keeping both records leaves the old,
        // wider span in the cache, and the resolver goes on denying a name that
        // now exists — for as long as the stale copy lives. Replacement is what
        // stops an aggressive cache from outliving the zone it learned from.
        var cache = UnsweptCache();

        cache.AddNSECRange("example.", Nsec("a.example.", "z.example."), TimeSpan.FromMinutes(5));

        Assert.That(cache.IsNameNegativelyCachedByNSEC("m.example.", "example."), Is.True,
                    "inside the original gap");

        cache.AddNSECRange("example.", Nsec("a.example.", "d.example."), TimeSpan.FromMinutes(5));

        Assert.Multiple(() => {

            Assert.That(cache.IsNameNegativelyCachedByNSEC("m.example.", "example."), Is.False,
                        "m.example. is outside the new gap, and the old one must be gone rather than " +
                        "merely joined by its replacement");

            Assert.That(cache.IsNameNegativelyCachedByNSEC("b.example.", "example."), Is.True,
                        "while the part of the gap that remains still proves what it always did");

        });

    }

    #endregion


    #region Per-record expiry inside one entry (RFC 1035 §3.2.1, §4.1.3)

    // These two were first written with a one-second TTL and a wait of 1400 ms,
    // and the authority one then failed twice in a full suite run and passed on
    // the third. Four hundred milliseconds of margin is not margin when ninety
    // other tests are holding sockets open. A test that reports a different
    // answer depending on what ran beside it is not evidence about the code, and
    // CacheExpiryTests next door already says what happens to tests that are not
    // evidence.
    //
    // So the clock comes out entirely. RFC 1035 §3.2.1 and §4.1.3 both say of the
    // TTL field: "Zero values are interpreted to mean that the RR can only be
    // used for the transaction in progress, and should not be cached." A record
    // with a zero TTL reaches its end of life at the instant it is constructed,
    // so it is already past by the time anything reads it — no waiting, no
    // margin, and a stronger statement than the original: not "this expired in
    // time" but "this may not be served from a cache at all".

    [Test]
    [Property("RFC", "1035 §3.2.1, §4.1.3")]
    public void A_Zero_Ttl_Answer_Is_Not_Served_While_Its_Live_Neighbour_Is()
    {

        // The TTL belongs to the record, not to whatever the record is stored
        // beside. Two answers cached under one name are judged separately, so an
        // entry holding one of each must come back with the live one alone —
        // not both, and not nothing.
        var cache = UnsweptCache();
        var name  = DNSServiceName.Parse("mixed.example.");

        cache.Add(name,
                  new A (DomainName.Parse("mixed.example."), DNSQueryClasses.IN, TimeSpan.Zero,          IPv4Address.Parse("192.0.2.7")),
                  new MX(DomainName.Parse("mixed.example."), DNSQueryClasses.IN, TimeSpan.FromHours(1), 10, DomainName.Parse("mail.example.")));

        Assert.That(cache.TryGetDNSInfo(name, out var served), Is.True,
                    "the MX has an hour on it, so the entry is still worth something");

        Assert.Multiple(() => {

            Assert.That(served.Answers.Count(), Is.EqualTo(1),
                        "§3.2.1: a zero TTL record can only be used for the transaction in " +
                        "progress, and should not be cached");

            Assert.That(served.Answers.Single().Type, Is.EqualTo(DNSResourceRecordTypes.MX),
                        "and what is left is the record that has time on it");

        });

    }


    [Test]
    [Property("RFC", "1035 §3.2.1, §4.1.3")]
    public void Two_Live_Answers_Both_Come_Back()
    {

        // The control for the test above. Without it "one answer came back" is
        // equally consistent with a cache that only ever returns one, and the
        // assertion that the zero-TTL record was dropped would be saying nothing.
        var cache = UnsweptCache();
        var name  = DNSServiceName.Parse("live.example.");

        cache.Add(name,
                  new A (DomainName.Parse("live.example."), DNSQueryClasses.IN, TimeSpan.FromHours(1),     IPv4Address.Parse("192.0.2.7")),
                  new MX(DomainName.Parse("live.example."), DNSQueryClasses.IN, TimeSpan.FromHours(1), 10, DomainName.Parse("mail.example.")));

        Assert.That(cache.TryGetDNSInfo(name, out var served), Is.True);
        Assert.That(served.Answers.Count(), Is.EqualTo(2), "nothing here has expired");

    }


    [Test]
    [Property("RFC", "1035 §3.2.1, §4.1.3")]
    public void A_Zero_Ttl_Authority_Is_Not_Served_While_The_Answer_Is()
    {

        // The same rule one section down the message. An authority record is
        // judged on its own TTL too, so an entry whose answers are all live still
        // has to be rebuilt when an authority underneath them may not be cached —
        // otherwise the only part that changed is the part nobody re-checked.
        var cache = UnsweptCache();
        var name  = DNSServiceName.Parse("auth.example.");

        cache.Add(name,
                  Info(Answers:     [ new A (DomainName.Parse("auth.example."), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.8")) ],
                       Authorities: [ new NS(DomainName.Parse("example."),      DNSQueryClasses.IN, TimeSpan.Zero,         DomainName.Parse("ns1.example.")) ]));

        Assert.That(cache.TryGetDNSInfo(name, out var served), Is.True, "the answer has an hour");

        Assert.Multiple(() => {

            Assert.That(served.Authorities.Count(), Is.EqualTo(0),
                        "§4.1.3: the zero-TTL authority must not be served from the cache");

            Assert.That(served.Answers.Count(), Is.EqualTo(1),
                        "and dropping it must not take the live answer with it");

        });

    }


    [Test]
    [Property("RFC", "1035 §3.2.1, §4.1.3")]
    public void A_Live_Authority_Comes_Back_With_Its_Answer()
    {

        // The control for the authority case, for the same reason.
        var cache = UnsweptCache();
        var name  = DNSServiceName.Parse("authlive.example.");

        cache.Add(name,
                  Info(Answers:     [ new A (DomainName.Parse("authlive.example."), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.8")) ],
                       Authorities: [ new NS(DomainName.Parse("example."),          DNSQueryClasses.IN, TimeSpan.FromHours(1), DomainName.Parse("ns1.example.")) ]));

        Assert.That(cache.TryGetDNSInfo(name, out var served), Is.True);
        Assert.That(served.Authorities.Count(), Is.EqualTo(1), "nothing here has expired");

    }

    #endregion


    #region How long a denial may be kept (RFC 2308 §5)

    [Test]
    [Property("RFC", "2308 §5")]
    public void The_Negative_Cache_Ttl_Is_The_Lesser_Of_The_Soa_Minimum_And_Its_Own_Ttl()
    {

        // RFC 2308 §5: the negative TTL "is set from the minimum of the MINIMUM
        // field of the SOA record and the TTL of the SOA itself". Two fields, and
        // whichever is smaller wins — so the rule has to be checked from both
        // sides. A resolver that always took MINIMUM would keep a denial for the
        // hour that field usually carries even when the zone shortened the SOA's
        // own TTL to minutes in order to change something.
        var minimumIsSmaller = Soa(OwnTimeToLive: TimeSpan.FromMinutes(30), Minimum: TimeSpan.FromMinutes(5));
        var ttlIsSmaller     = Soa(OwnTimeToLive: TimeSpan.FromMinutes(5),  Minimum: TimeSpan.FromMinutes(30));

        Assert.Multiple(() => {

            Assert.That(DNSCache.ComputeNegativeCacheTTL(Info([], [ minimumIsSmaller ])),
                        Is.EqualTo(TimeSpan.FromMinutes(5)),
                        "§5: the MINIMUM field, when it is the smaller of the two");

            Assert.That(DNSCache.ComputeNegativeCacheTTL(Info([], [ ttlIsSmaller ])),
                        Is.EqualTo(TimeSpan.FromMinutes(5)),
                        "§5: the SOA's own TTL, when that is the smaller one");

        });

    }

    #endregion

}

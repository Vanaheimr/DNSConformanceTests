using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 8198 — aggressive use of a DNSSEC-validated cache.
///
/// <para>
/// The idea is that one NSEC record proves a whole *range* of names absent, so
/// a resolver holding it can answer NXDOMAIN for any name in that range without
/// asking again. That is a large saving, and it rests entirely on two things
/// being right: the range has to be judged in canonical DNS name order, and the
/// record has to have been DNSSEC-validated.
/// </para>
///
/// <para>
/// Both are load-bearing in the security sense rather than the performance one.
/// Get the ordering wrong and the resolver denies names that exist; skip the
/// validation and one forged packet suppresses an entire range of names for the
/// TTL — which is cheaper for an attacker than cache poisoning, because there
/// is no race to win against a specific query.
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "8198")]
public class AggressiveNsecCacheTests
{

    private static NSEC Nsec(String Owner, String Next)
        => new (DomainName.ParseLenient(Owner),
                DNSQueryClasses.IN,
                TimeSpan.FromMinutes(5),
                DomainName.ParseLenient(Next),
                []);


    /// <summary>
    /// An NXDOMAIN whose authority section carries an SOA and an NSEC spanning
    /// the whole zone — unsigned, which is exactly what an attacker can produce.
    /// </summary>
    /// <remarks>
    /// Built here rather than with <c>RawDnsResponder.Negative</c>, which puts
    /// only an SOA in the authority section. Without an NSEC in the response
    /// there is nothing for the client to cache, and a test using it would pass
    /// whether or not the validation gate exists — which is what the first
    /// version of this test did.
    /// </remarks>
    private static Byte[] NxdomainWithNsecSpanningTheZone(Byte[] Request)
    {

        var query          = RawDnsReader.Parse(Request, RawDnsReaderOptions.Lenient);
        var questionBytes  = Request[12..(12 + query.Questions[0].Name.WireLength + 4)];

        // NSEC RDATA: the next owner name, then the type bitmap. "a." → "z." is
        // a span wide enough to cover every name the test asks about.
        var nsecRdata      = new RawDnsWriter().
                                 Name("z.example.").
                                 Bytes(0x00, 0x01, 0x40).   // window 0, 1 octet, bit 1 = A
                                 ToArray();

        return new RawDnsWriter().
                   Header(query.Id,
                          (UInt16) (RawDnsFlags.QR | RawDnsFlags.AA | 3),   // NXDOMAIN
                          1, 0, 2, 0).
                   Bytes(questionBytes).
                   RR("example.", RawDnsType.SOA, RawDnsClass.IN, 900,
                      RawDnsWriter.Soa("ns1.example.", "hostmaster.example.", Minimum: 900)).
                   RR("a.example.", 47 /* NSEC */, RawDnsClass.IN, 900, nsecRdata).
                   ToArray();

    }


    #region Range_Is_Judged_In_Canonical_Order_Not_String_Order()

    [Test]
    [Property("RFC", "8198 §5.1")]
    public void Range_Is_Judged_In_Canonical_Order_Not_String_Order()
    {

        // RFC 8198 §5.1 says a name is proven absent when it sorts between an
        // NSEC's owner and its next name — and "sorts" means RFC 4034 §6.1
        // canonical order, which compares labels from the rightmost. Ordinary
        // string comparison walks the characters left to right, which is a
        // different order entirely.
        //
        // The two disagree here. "c.z.example." lives under "z.example.", which
        // is outside the span b→d at the top level, so the NSEC proves nothing
        // about it. Compared as strings it falls neatly between "b.example."
        // and "d.example.", because 'c' sits between 'b' and 'd'.
        var cache = new DNSCache();

        cache.AddNSECRange("example.", Nsec("b.example.", "d.example."), TimeSpan.FromMinutes(5));

        Assert.That(cache.IsNameNegativelyCachedByNSEC("c.z.example.", "example."),
                    Is.False,
                    "the NSEC spans b→d at the top level and says nothing about anything under " +
                    "z.example. — reporting this name as proven absent denies a name that may exist");

    }

    #endregion

    #region A_Name_Genuinely_Inside_The_Range_Is_Still_Recognised()

    [Test]
    [Property("RFC", "8198 §5.1")]
    public void A_Name_Genuinely_Inside_The_Range_Is_Still_Recognised()
    {

        // The other direction, so a fix cannot simply answer "false" to
        // everything: "c.example." really is between b and d, canonically and
        // otherwise, and the whole point of RFC 8198 is to answer it from cache.
        var cache = new DNSCache();

        cache.AddNSECRange("example.", Nsec("b.example.", "d.example."), TimeSpan.FromMinutes(5));

        Assert.That(cache.IsNameNegativelyCachedByNSEC("c.example.", "example."),
                    Is.True,
                    "this name is inside the proven gap and is what the mechanism exists to answer");

    }

    #endregion

    #region Deeper_Names_Inside_The_Gap_Are_Recognised()

    [Test]
    [Property("RFC", "8198 §5.1")]
    public void Deeper_Names_Inside_The_Gap_Are_Recognised()
    {

        // Canonically "x.b.example." sorts after "b.example." — a name is
        // preceded by every one of its ancestors — and before "d.example.",
        // because the comparison reaches the second label and b < d. String
        // comparison puts it after "d.example." instead, on the first character.
        var cache = new DNSCache();

        cache.AddNSECRange("example.", Nsec("b.example.", "d.example."), TimeSpan.FromMinutes(5));

        Assert.That(cache.IsNameNegativelyCachedByNSEC("x.b.example.", "example."),
                    Is.True,
                    "everything below the owner name and before the next name is inside the gap");

    }

    #endregion

    #region The_Last_Nsec_In_A_Zone_Wraps_Around()

    [Test]
    [Property("RFC", "8198 §5.1")]
    public void The_Last_Nsec_In_A_Zone_Wraps_Around()
    {

        // The final NSEC of a zone points back at the apex, so its span is
        // "after the owner, or before the apex" rather than an interval.
        var cache = new DNSCache();

        cache.AddNSECRange("example.", Nsec("y.example.", "example."), TimeSpan.FromMinutes(5));

        Assert.Multiple(() => {

            Assert.That(cache.IsNameNegativelyCachedByNSEC("z.example.", "example."),
                        Is.True,
                        "past the last owner name and so inside the wrapping gap");

            Assert.That(cache.IsNameNegativelyCachedByNSEC("a.example.", "example."),
                        Is.False,
                        "before the last owner name — a different NSEC covers this part of the zone");

        });

    }

    #endregion

    #region Owner_And_Next_Names_Themselves_Are_Not_Denied()

    [Test]
    [Property("RFC", "8198 §5.1")]
    public void Owner_And_Next_Names_Themselves_Are_Not_Denied()
    {

        // The span is open at both ends: the owner exists by definition — it is
        // the name the record hangs off — and so does the next name. Denying
        // either would be denying a name the zone just told us about.
        var cache = new DNSCache();

        cache.AddNSECRange("example.", Nsec("b.example.", "d.example."), TimeSpan.FromMinutes(5));

        Assert.Multiple(() => {
            Assert.That(cache.IsNameNegativelyCachedByNSEC("b.example.", "example."), Is.False);
            Assert.That(cache.IsNameNegativelyCachedByNSEC("d.example.", "example."), Is.False);
        });

    }

    #endregion

    #region The_Zone_Is_Not_Guessed_From_The_Shape_Of_The_Name()

    [Test]
    [Property("RFC", "8198 §5.1")]
    public void The_Zone_Is_Not_Guessed_From_The_Shape_Of_The_Name()
    {

        // A cached range belongs to a zone, and the querier does not know which
        // zone holds a name until something tells it. Deriving one by counting
        // labels — "the last three" — is right for a.example.com and wrong
        // wherever the zone cut sits elsewhere, which is most of the namespace.
        var cache = new DNSCache();

        cache.AddNSECRange("deep.zone.example.", Nsec("b.deep.zone.example.", "d.deep.zone.example."),
                           TimeSpan.FromMinutes(5));

        Assert.That(cache.IsNameNegativelyCachedByNSEC("c.deep.zone.example."),
                    Is.True,
                    "the range is cached under a four-label zone; a lookup that assumed three would never find it");

    }

    #endregion

    #region An_Unvalidated_Nsec_Never_Reaches_The_Cache()

    [Test]
    [Property("RFC", "8198 §3")]
    public async Task An_Unvalidated_Nsec_Never_Reaches_The_Cache()
    {

        // §3 allows aggressive use only for DNSSEC-validated records, and this
        // is the test that says why. The scripted server answers NXDOMAIN with
        // an NSEC spanning a→z — an unsigned one, which is all an off-path
        // attacker needs to produce. If the client trusts it, every name in that
        // span is denied for the TTL from a single forged packet, with no race
        // to win against any particular query.
        //
        // The second query must therefore still reach the socket.
        await using var server = new ScriptedUdpServer(NxdomainWithNsecSpanningTheZone);

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   TimeSpan.FromSeconds(5),
                               UseQueryCache:  false
                           );

        _ = await client.Query<A>(DomainName.Parse("aaa.example."), TimeSpan.FromSeconds(5));
        var seenAfterFirst = server.Requests.Count;

        _ = await client.Query<A>(DomainName.Parse("mmm.example."), TimeSpan.FromSeconds(5));

        Assert.That(server.Requests.Count, Is.GreaterThan(seenAfterFirst),
                    "a second, different name must still be asked about — answering it from an " +
                    "unvalidated NSEC range would let one forged response deny a whole span of names");

    }

    #endregion

    #region An_Expired_Range_Proves_Nothing()

    [Test]
    [Property("RFC", "8198 §5.4")]
    public void An_Expired_Range_Proves_Nothing()
    {

        var cache = new DNSCache();

        cache.AddNSECRange("example.", Nsec("b.example.", "d.example."), TimeSpan.Zero);

        Assert.That(cache.IsNameNegativelyCachedByNSEC("c.example.", "example."),
                    Is.False,
                    "an NSEC range outlives its TTL no more than any other cached record");

    }

    #endregion

}

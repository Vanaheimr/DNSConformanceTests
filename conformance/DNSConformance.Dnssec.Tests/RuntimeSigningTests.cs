using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// Signing a zone in process rather than handing it to <c>dnssec-signzone</c>
/// first — and the three ways that goes wrong quietly.
/// </summary>
/// <remarks>
/// <para>
/// Whether the signatures are *correct* is settled elsewhere and by someone
/// else: <c>dnssec-verify</c> reads a zone this signer wrote, and <c>delv</c>
/// validates answers a running Hermod serves from a zone it signed seconds
/// earlier. Neither of those can see what this fixture is about, because all
/// three failures here look like a perfectly good zone from the outside until
/// the moment they do not.
/// </para>
/// <para>
/// Signing twice, adding a record afterwards, and letting the signatures run
/// out: each produces a zone that answers, and answers wrongly, in a way whose
/// first symptom is a resolver somewhere else calling the whole zone Bogus.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "4035 §2")]
public class RuntimeSigningTests
{

    #region Data

    private const String Zone = "signing.test";

    /// <summary>RFC 8624 §3.1 lists ECDSA P-256 as recommended for signing.</summary>
    private const Byte ECDSAP256SHA256 = 13;

    private static DomainName Apex
        => DomainName.Parse($"{Zone}.");

    private static DNSSECSigningKey[] Keys()

        => [
               DNSSECSigningKey.Generate(Apex, ECDSAP256SHA256, KeySigningKey: true),
               DNSSECSigningKey.Generate(Apex, ECDSAP256SHA256, KeySigningKey: false)
           ];

    private static InMemoryDNSZone UnsignedZone()

        => new InMemoryDNSZone().
               AddZoneFile(
                   $"""
                    $ORIGIN {Zone}.
                    $TTL 3600
                    @    IN SOA  ns1 hostmaster 1 7200 3600 1209600 3600
                    @    IN NS   ns1
                    ns1  IN A    192.0.2.1
                    a    IN A    192.0.2.10
                    *    IN A    192.0.2.99
                    """
               );

    /// <summary>
    /// Every record the zone holds, whatever its owner name.
    /// </summary>
    private static async Task<List<IDNSResourceRecord>> AllRecordsOf(InMemoryDNSZone Zone)
    {

        var found = new List<IDNSResourceRecord>();

        foreach (var name in new[] { $"{RuntimeSigningTests.Zone}.", $"ns1.{RuntimeSigningTests.Zone}.",
                                     $"a.{RuntimeSigningTests.Zone}.", $"*.{RuntimeSigningTests.Zone}." })
        {
            // No RRSIG in this list on purpose: a signed answer already carries
            // the signature covering it, and asking for type RRSIG as well
            // returns every signature at the name a second time. Counting them
            // twice turned "one signature over the SOA" into two and read as a
            // signer that had signed the zone twice.
            foreach (var type in new[] { DNSResourceRecordTypes.SOA,    DNSResourceRecordTypes.NS,
                                         DNSResourceRecordTypes.A,      DNSResourceRecordTypes.DNSKEY,
                                         DNSResourceRecordTypes.NSEC })
            {

                var result = await Zone.Lookup(
                                       new DNSQuestion(DNSServiceName.Parse(name), type, DNSQueryClasses.IN),
                                       DNSSECOK: true
                                   );

                found.AddRange(result.AnswerRRs);

            }
        }

        return found;

    }

    #endregion

    #region Signing_Twice_Replaces_Rather_Than_Accumulates()

    [Test]
    public async Task Signing_Twice_Replaces_Rather_Than_Accumulates()
    {

        // A signer's output is not zone data: signing a signed zone has to
        // discard the previous RRSIGs, NSECs and DNSKEYs and start from the
        // records the zone actually holds. Adding instead would publish each key
        // twice and leave the first run's signatures in place beside the
        // second's — and a resolver is entitled to pick either, which means a
        // zone that is intermittently Bogus for as long as the old ones are
        // valid.
        var zone = UnsignedZone();

        zone.Sign(Keys());
        var afterFirst  = await AllRecordsOf(zone);

        zone.Sign(Keys());
        var afterSecond = await AllRecordsOf(zone);

        Assert.Multiple(() => {

            Assert.That(afterSecond.Count, Is.EqualTo(afterFirst.Count),
                        "signing twice must not make the zone bigger");

            Assert.That(afterSecond.Count(record => record.Type == DNSResourceRecordTypes.DNSKEY),
                        Is.EqualTo(2),
                        "one key-signing key and one zone-signing key, published once each");

            Assert.That(afterSecond.Count(record => record.Type == DNSResourceRecordTypes.RRSIG &&
                                                    record.DomainName.FullName.TrimEnd('.').Equals(Zone, StringComparison.OrdinalIgnoreCase) &&
                                                    ((RRSIG) record).TypeCovered == DNSResourceRecordTypes.SOA),
                        Is.EqualTo(1),
                        "and exactly one signature over the SOA, not one per signing run");

        });

    }

    #endregion

    #region Signing_An_Unsigned_Zone_Produces_A_Signed_One()

    [Test]
    public async Task Signing_An_Unsigned_Zone_Produces_A_Signed_One()
    {

        var zone = UnsignedZone();

        Assert.That(zone.IsSigned, Is.False, "nothing has signed it yet");
        Assert.That(zone.SignedAt, Is.Null);

        zone.Sign(Keys());

        var records = await AllRecordsOf(zone);

        Assert.Multiple(() => {

            Assert.That(zone.IsSigned, Is.True,
                        "the zone now carries the denial records that let it say no authenticated");

            Assert.That(zone.SignedAt, Is.Not.Null);

            Assert.That(records.Any(record => record.Type == DNSResourceRecordTypes.RRSIG), Is.True);
            Assert.That(records.Any(record => record.Type == DNSResourceRecordTypes.DNSKEY), Is.True);

            // The wildcard is in the zone, so it has to be in the chain as well:
            // an RRSIG over *.signing.test whose labels field counts the asterisk
            // out is the whole of RFC 4034 §3.1.3, and the field only exists in a
            // response. A mutation against it survived dnssec-verify.
            var wildcardSignature = records.OfType<RRSIG>().
                                        FirstOrDefault(sig => sig.DomainName.FullName.StartsWith("*."));

            Assert.That(wildcardSignature, Is.Not.Null, "the wildcard RRset must be signed too");

            Assert.That(wildcardSignature!.Labels, Is.EqualTo(2),
                        "signing.test is two labels, and the asterisk is not counted");

        });

    }

    #endregion

    #region Adding_A_Record_After_Signing_Makes_The_Zone_Stale()

    [Test]
    public void Adding_A_Record_After_Signing_Makes_The_Zone_Stale()
    {

        // The dangerous state, and the one that looks fine. The new RRset has no
        // RRSIG and its owner name is outside the chain of denial, so a
        // validating resolver asking for it does not get "unsigned" — it gets an
        // answer the zone's own NSEC records say should not exist. That is the
        // shape of an attack, not of an oversight, and a resolver treats it that
        // way.
        var zone = UnsignedZone().Sign(Keys());

        Assert.That(zone.SignaturesAreStale, Is.False, "a zone is not born stale");

        zone.AddZoneFileString($"new.{Zone}. 3600 IN A 192.0.2.50");

        Assert.That(zone.SignaturesAreStale, Is.True,
                    "the records have moved on from the signatures that cover them");

        zone.Sign(Keys());

        Assert.That(zone.SignaturesAreStale, Is.False,
                    "and signing again settles it");

    }

    #endregion

    #region An_Unsigned_Zone_Is_Never_Stale()

    [Test]
    public void An_Unsigned_Zone_Is_Never_Stale()
    {

        // Staleness is a statement about signatures, so a zone with none cannot
        // be stale. Without this the property would read true for every zone
        // nobody ever signed, which is the kind of alarm that teaches people to
        // ignore the alarm.
        var zone = UnsignedZone();

        zone.AddZoneFileString($"new.{Zone}. 3600 IN A 192.0.2.50");

        Assert.That(zone.SignaturesAreStale, Is.False);

    }

    #endregion

    #region The_Expiration_Is_Reachable_Without_Reading_The_Rrsigs()

    [Test]
    public async Task The_Expiration_Is_Reachable_Without_Reading_The_Rrsigs()
    {

        // The failure that arrives without anyone doing anything: a server signs
        // at start-up and serves the result for longer than the signatures last.
        // Every validating resolver in the world then calls the zone Bogus on the
        // same day, and nothing in the server changed.
        var expiration = DateTime.UtcNow.AddDays(7);
        var zone       = UnsignedZone().Sign(Keys(), Expiration: expiration);

        var records    = await AllRecordsOf(zone);
        var signatures = records.OfType<RRSIG>().ToArray();

        Assert.Multiple(() => {

            Assert.That(zone.SignaturesExpireAt, Is.Not.Null);

            Assert.That(zone.SignaturesExpireAt!.Value,
                        Is.EqualTo(expiration).Within(TimeSpan.FromSeconds(1)));

            Assert.That(signatures, Is.Not.Empty);

            // And the property has to agree with the records rather than merely
            // remember what it was asked for.
            Assert.That(signatures.Select(sig => DateTimeOffset.FromUnixTimeSeconds(sig.SignatureExpiration).UtcDateTime).Distinct(),
                        Is.EqualTo(new[] { zone.SignaturesExpireAt!.Value.AddTicks(-(zone.SignaturesExpireAt.Value.Ticks % TimeSpan.TicksPerSecond)) }),
                        "every RRSIG stops when the zone says it does");

        });

    }

    #endregion

    #region Signing_A_Zone_With_No_Soa_Is_Refused()

    [Test]
    public void Signing_A_Zone_With_No_Soa_Is_Refused()
    {

        // Without an SOA there is no apex, and without an apex RFC 4035 §2.2 has
        // no boundary to draw between what belongs to the zone and what is a
        // delegation. Signing anyway would produce signatures over records that
        // are not this zone's to sign.
        var notAZone = new InMemoryDNSZone().
                           AddZoneFileString($"a.{Zone}. 3600 IN A 192.0.2.10");

        var exception = Assert.Throws<InvalidOperationException>(() => notAZone.Sign(Keys()));

        Assert.That(exception!.Message, Does.Contain("SOA"),
                    "and the message has to say what is missing");

    }

    #endregion

}

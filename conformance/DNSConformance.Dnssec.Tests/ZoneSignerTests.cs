using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// The parts of signing a zone that BIND's <c>dnssec-verify</c> cannot see.
/// </summary>
/// <remarks>
/// <para>
/// <c>BindVerifiesHermodSignaturesTests</c> is the important test for the signer
/// — an implementation that has never seen this code accepting what it produces
/// — but it reads a zone *file*, and a zone file holds a wildcard literally.
/// Everything that only matters once a server has expanded one is invisible to
/// it.
/// </para>
/// <para>
/// That is not a guess. Making <see cref="DNSSECCanonical.LabelCount"/> count
/// the asterisk, which RFC 4034 §3.1.3 says it must not, leaves every
/// <c>dnssec-verify</c> test green: the signature still verifies against the
/// literal name in the file. It would fail at the only moment it is ever used,
/// which is a resolver reconstructing the wildcard from an expanded answer —
/// finding 10, from the other side. These tests exist because that mutation
/// survived.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "4034 §3.1.3")]
public class ZoneSignerTests
{

    #region Data

    private const String Zone = "signer.test.";

    private static DomainName Name(String Text)
        => DomainName.ParseLenient(Text);

    private static List<IDNSResourceRecord> SmallZone()

        => [
               new SOA (Name(Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                        Name("ns1." + Zone),
                        SimpleEMailAddress.Parse("hostmaster@" + Zone.TrimEnd('.')),
                        1, TimeSpan.FromHours(2), TimeSpan.FromHours(1),
                        TimeSpan.FromDays(14), TimeSpan.FromHours(1)),
               new NS  (Name(Zone),            DNSQueryClasses.IN, TimeSpan.FromHours(1), Name("ns1." + Zone)),
               new A   (Name("ns1." + Zone),   DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.53")),
               new A   (Name("a."   + Zone),   DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.1")),
               new A   (Name("*.w." + Zone),   DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.77"))
           ];

    private static List<IDNSResourceRecord> Signed(out DNSSECSigningKey Key)
    {

        Key = DNSSECSigningKey.Generate(Name(Zone), 13, KeySigningKey: true);

        return DNSSECZoneSigner.Sign(SmallZone(), Name(Zone), [ Key ]);

    }

    #endregion

    /// <summary>
    /// The small zone with an empty non-terminal and an insecure delegation —
    /// the two shapes NSEC3 has to handle that NSEC does not.
    /// </summary>
    private static List<IDNSResourceRecord> ZoneWithDelegation()
    {

        var zone = SmallZone();

        zone.Add(new A (Name("host.sub." + Zone),     DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.30")));
        zone.Add(new NS(Name("insecure." + Zone),     DNSQueryClasses.IN, TimeSpan.FromHours(1), Name("ns1.insecure." + Zone)));
        zone.Add(new A (Name("ns1.insecure." + Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.90")));

        return zone;

    }

    private static Boolean HasNSEC3For(IEnumerable<IDNSResourceRecord>  Signed,
                                       String                           Name)
    {

        var owner = NSEC3.ComputeHashedOwnerName(DomainName.ParseLenient(Name),
                                                 DomainName.ParseLenient(Zone),
                                                 0,
                                                 []);

        return Signed.OfType<NSEC3>().Any(nsec3 => nsec3.DomainName.FullName.Equals(owner.FullName, StringComparison.OrdinalIgnoreCase));

    }

    #region The_Labels_Field_Does_Not_Count_The_Wildcard()

    [Test]
    public void The_Labels_Field_Does_Not_Count_The_Wildcard()
    {

        // "The Labels field value MUST NOT count either the null (root) label
        // that terminates the owner name or the wildcard label (if present)."
        Assert.Multiple(() => {

            Assert.That(DNSSECCanonical.LabelCount("a.example.com."),    Is.EqualTo((Byte) 3), "three labels, root not counted");
            Assert.That(DNSSECCanonical.LabelCount("example.com."),      Is.EqualTo((Byte) 2));
            Assert.That(DNSSECCanonical.LabelCount("com."),              Is.EqualTo((Byte) 1));
            Assert.That(DNSSECCanonical.LabelCount("."),                 Is.EqualTo((Byte) 0), "the root has none");

            Assert.That(DNSSECCanonical.LabelCount("*.example.com."),    Is.EqualTo((Byte) 2), "the asterisk is not counted");
            Assert.That(DNSSECCanonical.LabelCount("*.w.example.com."),  Is.EqualTo((Byte) 3));

            // An asterisk that is not the leftmost label is an ordinary label and
            // is counted like any other (RFC 4592 §2.1.1).
            Assert.That(DNSSECCanonical.LabelCount("a.*.example.com."),  Is.EqualTo((Byte) 4));

        });

    }

    #endregion

    #region A_Wildcards_Signature_Carries_The_Shortened_Count()

    [Test]
    public void A_Wildcards_Signature_Carries_The_Shortened_Count()
    {

        // The same rule where it is actually written down, because this is the
        // field a resolver uses to rebuild the wildcard from an expanded answer.
        // A zone file never exercises it — the name is stored with its asterisk —
        // so nothing that reads one can tell a right count from a wrong one.
        using var key = DNSSECSigningKey.Generate(Name(Zone), 13, KeySigningKey: true);

        var signed   = DNSSECZoneSigner.Sign(SmallZone(), Name(Zone), [ key ]);

        var wildcard = signed.OfType<RRSIG>().
                              Single(rrsig => rrsig.DomainName.FullName.StartsWith("*.w.", StringComparison.OrdinalIgnoreCase) &&
                                              rrsig.TypeCovered == DNSResourceRecordTypes.A);

        var ordinary = signed.OfType<RRSIG>().
                              Single(rrsig => rrsig.DomainName.FullName.StartsWith("a.signer", StringComparison.OrdinalIgnoreCase) &&
                                              rrsig.TypeCovered == DNSResourceRecordTypes.A);

        Assert.Multiple(() => {
            Assert.That(wildcard.Labels, Is.EqualTo((Byte) 3), "*.w.signer.test. counts w, signer and test");
            Assert.That(ordinary.Labels, Is.EqualTo((Byte) 3), "a.signer.test. counts all three");
        });

    }

    #endregion

    #region An_Expanded_Wildcard_Answer_Still_Validates()

    [Test]
    [Property("RFC", "4035 §5.3.2")]
    public void An_Expanded_Wildcard_Answer_Still_Validates()
    {

        // The moment the labels field is for: a server answers a name the zone
        // does not hold, with a record whose owner is the queried name, and the
        // validator has to put the asterisk back before checking the signature.
        // Finding 10 was this failing; here it is from the signing side.
        using var key = DNSSECSigningKey.Generate(Name(Zone), 13, KeySigningKey: true);

        var signed    = DNSSECZoneSigner.Sign(SmallZone(), Name(Zone), [ key ]);

        var signature = signed.OfType<RRSIG>().
                               Single(rrsig => rrsig.DomainName.FullName.StartsWith("*.w.", StringComparison.OrdinalIgnoreCase) &&
                                               rrsig.TypeCovered == DNSResourceRecordTypes.A);

        // What a server would put on the wire for "anything.w.signer.test.": the
        // wildcard's RDATA under the queried name, and the wildcard's signature
        // unchanged beside it.
        var expanded  = new A(Name("anything.w." + Zone),
                              DNSQueryClasses.IN,
                              TimeSpan.FromHours(1),
                              IPv4Address.Parse("192.0.2.77"));

        var validator = new DNSSECValidator(new DNSClient(QueryTimeout: TimeSpan.FromSeconds(2)));

        Assert.That(validator.ValidateRRSig([ expanded ], signature, key.DNSKEY),
                    Is.EqualTo(DNSSECValidationResult.Secure),
                    "the expanded answer validates against the wildcard's signature");

    }

    #endregion

    #region Every_Authoritative_Rrset_Is_Signed()

    [Test]
    [Property("RFC", "4035 §2.2")]
    public void Every_Authoritative_Rrset_Is_Signed()
    {

        var signed = Signed(out var key);

        using (key)
        {

            var covered = signed.OfType<RRSIG>().
                                 Select(rrsig => (Name: rrsig.DomainName.FullName.ToLowerInvariant(), rrsig.TypeCovered)).
                                 ToHashSet();

            var missing = signed.Where (record => record.Type != DNSResourceRecordTypes.RRSIG).
                                 Select(record => (Name: record.DomainName.FullName.ToLowerInvariant(), TypeCovered: record.Type)).
                                 Distinct().
                                 Where (rrset  => !covered.Contains(rrset)).
                                 ToArray();

            Assert.That(missing, Is.Empty,
                        "every RRset of a zone with no delegations is authoritative and gets a signature: " +
                        String.Join(", ", missing.Select(m => $"{m.Name} {m.TypeCovered}")));

        }

    }

    #endregion

    #region The_Nsec_Chain_Names_Every_Name_And_Closes()

    [Test]
    [Property("RFC", "4035 §2.3")]
    public void The_Nsec_Chain_Names_Every_Name_And_Closes()
    {

        var signed = Signed(out var key);

        using (key)
        {

            var nsecs = signed.OfType<NSEC>().ToArray();

            var names = signed.Where (record => record.Type != DNSResourceRecordTypes.RRSIG &&
                                                record.Type != DNSResourceRecordTypes.NSEC).
                               Select(record => record.DomainName.FullName.ToLowerInvariant()).
                               Distinct().
                               Order().
                               ToArray();

            Assert.Multiple(() => {

                Assert.That(nsecs.Select(nsec => nsec.DomainName.FullName.ToLowerInvariant()).Order(),
                            Is.EqualTo(names),
                            "one NSEC per name the zone owns");

                // §2.3: the last one wraps to the apex, which is what makes it a
                // chain rather than a list.
                Assert.That(nsecs.Any(nsec => nsec.NextDomainName.FullName.Equals(Zone, StringComparison.OrdinalIgnoreCase)),
                            Is.True,
                            "the chain closes back to the apex");

            });

        }

    }

    #endregion

    #region An_Opt_Out_Chain_Says_So_On_Every_Record()

    [Test]
    [Property("RFC", "5155 §6, §3.1.2.1")]
    public void An_Opt_Out_Chain_Says_So_On_Every_Record()
    {

        // §3.1.2.1: the Opt-Out flag says that this NSEC3 "may cover" insecure
        // delegations it does not name. Leaving a delegation out of the chain
        // while the flag is clear turns the record that spans its hash into a
        // proof that the delegation does not exist — a lie about the zone's own
        // data.
        //
        // dnssec-verify does not catch this: a mutation that never sets the flag
        // left all eleven of its tests green. It is the second thing the external
        // judge cannot see, after the labels field, and for the same reason — it
        // reads the zone rather than the answers the zone would give.
        using var key = DNSSECSigningKey.Generate(Name(Zone), 13, KeySigningKey: true);

        var withOptOut     = DNSSECZoneSigner.Sign(ZoneWithDelegation(), Name(Zone), [ key ],
                                                   NSEC3: new NSEC3Parameters([], 0, OptOut: true));

        var withoutOptOut  = DNSSECZoneSigner.Sign(ZoneWithDelegation(), Name(Zone), [ key ],
                                                   NSEC3: new NSEC3Parameters([], 0, OptOut: false));

        Assert.Multiple(() => {

            Assert.That(withOptOut.OfType<NSEC3>().Select(nsec3 => nsec3.Flags).Distinct(),
                        Is.EqualTo(new Byte[] { 1 }),
                        "every NSEC3 of an opt-out chain carries the flag");

            Assert.That(withoutOptOut.OfType<NSEC3>().Select(nsec3 => nsec3.Flags).Distinct(),
                        Is.EqualTo(new Byte[] { 0 }),
                        "and none of them does otherwise");

            // §4.1.2: the NSEC3PARAM's flags are zero either way, because it
            // describes the parameters rather than the chain.
            Assert.That(withOptOut.OfType<NSEC3PARAM>().Single().Flags,
                        Is.EqualTo((Byte) 0));

            // The delegation itself: named without opt-out, absent with it.
            Assert.That(HasNSEC3For(withoutOptOut, "insecure." + Zone), Is.True,
                        "without opt-out the insecure delegation is in the chain");

            Assert.That(HasNSEC3For(withOptOut,    "insecure." + Zone), Is.False,
                        "with opt-out it is left out, which is the point of it");

        });

    }

    #endregion

    #region An_Empty_Non_Terminal_Is_Hashed_With_An_Empty_Bitmap()

    [Test]
    [Property("RFC", "5155 §7.1")]
    public void An_Empty_Non_Terminal_Is_Hashed_With_An_Empty_Bitmap()
    {

        // "sub." owns nothing and exists only because "host.sub." does. §7.1
        // requires an NSEC3 for it all the same, and its type bitmap is empty
        // because there is nothing at that name to list.
        using var key = DNSSECSigningKey.Generate(Name(Zone), 13, KeySigningKey: true);

        var signed = DNSSECZoneSigner.Sign(ZoneWithDelegation(), Name(Zone), [ key ],
                                           NSEC3: NSEC3Parameters.Recommended);

        var owner  = NSEC3.ComputeHashedOwnerName(Name("sub." + Zone), Name(Zone), 0, []);

        var nsec3  = signed.OfType<NSEC3>().
                            SingleOrDefault(n => n.DomainName.FullName.Equals(owner.FullName, StringComparison.OrdinalIgnoreCase));

        Assert.Multiple(() => {
            Assert.That(nsec3,                    Is.Not.Null, "the empty non-terminal is in the chain");
            Assert.That(nsec3!.TypeBitMaps,       Is.Empty,    "and claims no types, because it holds none");
        });

    }

    #endregion

    #region No_Nsec3_Is_Made_For_A_Name_Above_The_Apex()

    [Test]
    [Property("RFC", "5155 §7.1")]
    public void No_Nsec3_Is_Made_For_A_Name_Above_The_Apex()
    {

        // Walking up from a name to find its empty non-terminals must stop at the
        // apex. One step further is the parent zone, and an NSEC3 for that is a
        // statement about data this zone does not hold. dnssec-verify caught this
        // one, which is why the guard is here rather than only in the comment.
        using var key = DNSSECSigningKey.Generate(Name(Zone), 13, KeySigningKey: true);

        var signed  = DNSSECZoneSigner.Sign(ZoneWithDelegation(), Name(Zone), [ key ],
                                            NSEC3: NSEC3Parameters.Recommended);

        var parent  = NSEC3.ComputeHashedOwnerName(Name("test."), Name(Zone), 0, []);

        Assert.That(signed.OfType<NSEC3>().Any(n => n.DomainName.FullName.Equals(parent.FullName, StringComparison.OrdinalIgnoreCase)),
                    Is.False,
                    "the parent of the apex is not this zone's to deny");

    }

    #endregion

    #region Rsa_Sha1_Is_Refused_For_Signing()

    [Test]
    [Property("RFC", "8624 §3.1")]
    public void Rsa_Sha1_Is_Refused_For_Signing()
    {

        // RFC 8624 §3.1: MUST NOT for signing, MAY for validation. The suite has
        // fixtures BIND signed with both, and they still validate — the refusal
        // is about what this implementation produces, not what it accepts.
        Assert.Multiple(() => {
            Assert.That(() => DNSSECSigningKey.Generate(Name(Zone), 5),  Throws.TypeOf<NotSupportedException>());
            Assert.That(() => DNSSECSigningKey.Generate(Name(Zone), 7),  Throws.TypeOf<NotSupportedException>());
        });

    }

    #endregion

}

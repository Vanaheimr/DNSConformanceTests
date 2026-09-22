using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4035 §2.2 — which records at a delegation belong to the zone doing the
/// signing, and which belong to the child.
///
/// <para>
/// A delegation is the one place in a zone where the records present are not the
/// zone's own data. The NS RRset that delegates is authoritative in the *child*,
/// and the glue beneath it is a copy of the child's addresses kept so the child
/// can be reached at all. §2.2 says so plainly: an RRSIG "MUST NOT" be generated
/// for a delegation's NS RRset or for glue. The DS is the exception in the other
/// direction — it is the parent's statement about the child's key, so the parent
/// signs it. And the NSEC or NSEC3 at the delegation point is the parent's too,
/// because it is what proves what the parent does and does not delegate.
/// </para>
///
/// <para>
/// <c>ZoneSignerTests</c> asserts that every authoritative RRset is signed, but
/// against a zone with no delegations in it — so nothing watched the decision
/// that decides which records those are. A signer that signed the child's NS
/// RRset would produce signatures no resolver can use and that a parent has no
/// right to make; one that did not sign the DS would break every chain of trust
/// through it.
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "4035 §2.2")]
public class SignedDelegationTests
{

    #region Data

    private const String Zone = "delegating.test.";

    private static DomainName Name(String Text)
        => DomainName.ParseLenient(Text);

    /// <summary>
    /// A zone with both kinds of delegation: one with a DS, which a validator can
    /// follow, and one without, which it cannot.
    /// </summary>
    private static List<IDNSResourceRecord> ZoneWithDelegations(DS ChildDS)

        => [
               new SOA(Name(Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                       Name("ns1." + Zone),
                       SimpleEMailAddress.Parse("hostmaster@" + Zone.TrimEnd('.')),
                       1, TimeSpan.FromHours(2), TimeSpan.FromHours(1),
                       TimeSpan.FromDays(14), TimeSpan.FromHours(1)),

               new NS (Name(Zone),                     DNSQueryClasses.IN, TimeSpan.FromHours(1), Name("ns1." + Zone)),
               new A  (Name("ns1." + Zone),            DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.53")),
               new A  (Name("a."   + Zone),            DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.1")),

               // A secure delegation: the NS belongs to the child, the DS to this zone,
               // and the glue is the child's address kept here so it can be reached.
               new NS (Name("secure." + Zone),         DNSQueryClasses.IN, TimeSpan.FromHours(1), Name("ns1.secure." + Zone)),
               ChildDS,
               new A  (Name("ns1.secure." + Zone),     DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.80")),

               // And an insecure one: no DS, so nothing vouches for the child.
               new NS (Name("open." + Zone),           DNSQueryClasses.IN, TimeSpan.FromHours(1), Name("ns1.elsewhere.test."))
           ];

    /// <summary>
    /// The DS this zone publishes for its secure child. The digest is a real one
    /// over a real key, so that nothing about the record is malformed — what the
    /// tests below ask is whether it is signed, not whether it is right.
    /// </summary>
    private static DS ChildDelegationSigner(DNSSECSigningKey ChildKey)
        => ChildKey.DelegationSigner();

    private static Boolean IsSigned(IEnumerable<IDNSResourceRecord>  Signed,
                                    String                           Owner,
                                    DNSResourceRecordTypes           Type)

        => Signed.OfType<RRSIG>().
                  Any(rrsig => rrsig.TypeCovered == Type &&
                               rrsig.DomainName.FullName.Equals(Owner, StringComparison.OrdinalIgnoreCase));

    #endregion


    #region The_Parent_Signs_Its_Own_Records_At_A_Delegation_And_Nothing_Else()

    /// <summary>
    /// The four records that sit at or under a delegation, and the two different
    /// answers they get. RFC 4035 §2.2:
    ///
    /// <list type="bullet">
    ///   <item>the delegation's NS RRset — the child's, not signed here</item>
    ///   <item>the glue beneath it — the child's, not signed here</item>
    ///   <item>the DS — the parent's statement about the child, signed</item>
    ///   <item>the NSEC at the delegation point — the parent's, signed</item>
    /// </list>
    ///
    /// <para>
    /// All four in one test, because the decision is one expression and each of
    /// the four is one way for it to be wrong. Separately they would also each
    /// pass against a signer that signed nothing at all, or everything.
    /// </para>
    /// </summary>
    [Test]
    public void The_Parent_Signs_Its_Own_Records_At_A_Delegation_And_Nothing_Else()
    {

        using var child  = DNSSECSigningKey.Generate(Name("secure." + Zone), 13, KeySigningKey: true);
        using var key    = DNSSECSigningKey.Generate(Name(Zone),             13, KeySigningKey: true);

        var signed = DNSSECZoneSigner.Sign(ZoneWithDelegations(ChildDelegationSigner(child)),
                                           Name(Zone),
                                           [ key ]);

        Assert.Multiple(() => {

            Assert.That(IsSigned(signed, "secure." + Zone, DNSResourceRecordTypes.DS),
                        Is.True,
                        "the DS is the parent's statement about the child, and the parent signs it");

            Assert.That(IsSigned(signed, "secure." + Zone, DNSResourceRecordTypes.NSEC),
                        Is.True,
                        "so is the NSEC at the delegation point, which is what says what is delegated");

            Assert.That(IsSigned(signed, "secure." + Zone, DNSResourceRecordTypes.NS),
                        Is.False,
                        "the delegating NS RRset is authoritative in the child — §2.2 forbids a signature here");

            Assert.That(IsSigned(signed, "ns1.secure." + Zone, DNSResourceRecordTypes.A),
                        Is.False,
                        "and glue is a copy of the child's data, not the parent's to sign");

            // The control: the same zone's own records are signed, so none of the
            // four above passes because the signer did nothing.
            Assert.That(IsSigned(signed, "a." + Zone, DNSResourceRecordTypes.A),
                        Is.True,
                        "the control: an ordinary record of this zone is signed");

        });

    }

    #endregion

    #region An_Insecure_Delegation_Is_In_The_Chain_Unless_Opt_Out_Was_Asked_For()

    /// <summary>
    /// RFC 5155 §6's opt-out leaves insecure delegations out of the NSEC3 chain.
    /// It is a real and useful thing for a zone of mostly-unsigned delegations,
    /// and it is also a weakening: a name inside an opt-out span gets no proof
    /// either way, so the chain stops being able to say that a delegation does
    /// not exist.
    ///
    /// <para>
    /// That is a trade a zone operator makes, which means it has to be asked for.
    /// <c>NSEC3Parameters.Recommended</c> is RFC 9276 §3.1's advice — no salt, no
    /// extra iterations — and the third parameter goes along for the ride; a
    /// default of "on" would quietly hand every caller the weaker chain.
    /// </para>
    ///
    /// <para>
    /// <c>ZoneSignerTests</c> pins what the flag does, but passes it explicitly
    /// on both sides, so the default itself was unwatched.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "5155 §6")]
    [Property("RFC", "9276 §3.1")]
    public void An_Insecure_Delegation_Is_In_The_Chain_Unless_Opt_Out_Was_Asked_For()
    {

        using var child = DNSSECSigningKey.Generate(Name("secure." + Zone), 13, KeySigningKey: true);
        using var key   = DNSSECSigningKey.Generate(Name(Zone),             13, KeySigningKey: true);

        var zone   = ZoneWithDelegations(ChildDelegationSigner(child));

        var signed = DNSSECZoneSigner.Sign(zone, Name(Zone), [ key ],
                                           NSEC3: NSEC3Parameters.Recommended);

        var hashed = NSEC3.ComputeHashedOwnerName(Name("open." + Zone), Name(Zone), 0, []);

        Assert.Multiple(() => {

            Assert.That(NSEC3Parameters.Recommended.OptOut, Is.False,
                        "opt-out is a weakening, so it is asked for rather than inherited");

            Assert.That(signed.OfType<NSEC3>().Select(nsec3 => nsec3.Flags).Distinct(),
                        Is.EqualTo(new Byte[] { 0 }),
                        "and nothing in the chain claims it");

            Assert.That(signed.OfType<NSEC3>().
                               Any(nsec3 => nsec3.DomainName.FullName.Equals(hashed.FullName,
                                                                            StringComparison.OrdinalIgnoreCase)),
                        Is.True,
                        "so the insecure delegation is named by the chain rather than skipped over");

        });

    }

    #endregion

}

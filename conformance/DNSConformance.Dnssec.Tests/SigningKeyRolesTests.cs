using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4034 §2.1.1 and RFC 3757 — the one bit that gives a key a job, and what
/// a signer does with it.
///
/// <para>
/// DNSSEC's two key roles are a convention built on a single flag. RFC 4034
/// §2.1.1 puts the Zone Key flag at bit 7 of the Flags field and the Secure
/// Entry Point flag at bit 15, which on the wire makes a zone-signing key 256
/// and a key-signing key 257. RFC 3757 introduced the SEP bit for exactly this:
/// marking which key a parent's DS points at.
/// </para>
///
/// <para>
/// The consequence is in RFC 4035 §5.2. A validator authenticates a zone's
/// DNSKEY RRset with the DS from the parent, and the DS covers the key-signing
/// key — so the DNSKEY RRset has to be signed by that key, or the chain does not
/// close. Everything else in the zone is signed by the zone-signing key, which
/// is what lets an operator roll it without touching the parent.
/// </para>
///
/// <para>
/// Every other test of the signer generates its key with
/// <c>KeySigningKey: true</c> and stops there, so the bit's default, its reading,
/// and the split it drives were all unexercised.
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "4034 §2.1.1")]
[Property("RFC", "3757")]
public class SigningKeyRolesTests
{

    #region Data

    private const String Zone = "roles.test.";

    private static DomainName Name(String Text)
        => DomainName.ParseLenient(Text);

    private static List<IDNSResourceRecord> SmallZone()

        => [
               new SOA(Name(Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                       Name("ns1." + Zone),
                       SimpleEMailAddress.Parse("hostmaster@" + Zone.TrimEnd('.')),
                       1, TimeSpan.FromHours(2), TimeSpan.FromHours(1),
                       TimeSpan.FromDays(14), TimeSpan.FromHours(1)),

               new NS (Name(Zone),          DNSQueryClasses.IN, TimeSpan.FromHours(1), Name("ns1." + Zone)),
               new A  (Name("ns1." + Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.53")),
               new A  (Name("a."   + Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.1"))
           ];

    private static IEnumerable<RRSIG> SignaturesOver(IEnumerable<IDNSResourceRecord>  Signed,
                                                     String                           Owner,
                                                     DNSResourceRecordTypes           Type)

        => Signed.OfType<RRSIG>().
                  Where(rrsig => rrsig.TypeCovered == Type &&
                                 rrsig.DomainName.FullName.Equals(Owner, StringComparison.OrdinalIgnoreCase));

    #endregion


    #region The_Sep_Bit_Is_What_Tells_The_Two_Roles_Apart()

    /// <summary>
    /// RFC 4034 §2.1.1: bit 7 is the Zone Key flag and bit 15 the Secure Entry
    /// Point flag, counted from the most significant bit of the sixteen. So a
    /// zone-signing key is 0x0100 and a key-signing key is 0x0101 — 256 and 257,
    /// the two numbers every signed zone in the world publishes.
    ///
    /// <para>
    /// The numbers are asserted rather than the property alone, because a
    /// reading of the flag that is inverted in both directions at once is
    /// self-consistent and wrong: the key would report the role it was asked for
    /// while publishing the other one to the internet.
    /// </para>
    /// </summary>
    [Test]
    public void The_Sep_Bit_Is_What_Tells_The_Two_Roles_Apart()
    {

        using var ksk = DNSSECSigningKey.Generate(Name(Zone), 13, KeySigningKey: true);
        using var zsk = DNSSECSigningKey.Generate(Name(Zone), 13, KeySigningKey: false);

        Assert.Multiple(() => {

            Assert.That(ksk.DNSKEY.Flags, Is.EqualTo(257), "ZONE | SEP");
            Assert.That(zsk.DNSKEY.Flags, Is.EqualTo(256), "ZONE, and not SEP");

            Assert.That(ksk.IsKeySigningKey, Is.True,  "and the flag is read the way it is written");
            Assert.That(zsk.IsKeySigningKey, Is.False);

        });

    }

    #endregion

    #region A_Key_Is_A_Zone_Signing_Key_Unless_Asked_Otherwise()

    /// <summary>
    /// Which role a key gets when nobody says. A zone has one key-signing key and
    /// rolls its zone-signing keys freely, so the common case is the zone-signing
    /// one — and the uncommon case is the one that has to be written down,
    /// because a key-signing key is what a parent is asked to publish a DS for.
    ///
    /// <para>
    /// A default of "key-signing" would have every key generated without thought
    /// claim to be a secure entry point, which is a statement to the parent
    /// rather than a detail of this library.
    /// </para>
    /// </summary>
    [Test]
    public void A_Key_Is_A_Zone_Signing_Key_Unless_Asked_Otherwise()
    {

        using var key = DNSSECSigningKey.Generate(Name(Zone), 13);

        Assert.Multiple(() => {
            Assert.That(key.IsKeySigningKey, Is.False);
            Assert.That(key.DNSKEY.Flags,    Is.EqualTo(256), "and it says so on the wire");
        });

    }

    #endregion

    #region The_Dnskey_Rrset_Is_Signed_By_The_Key_A_Ds_Would_Name()

    /// <summary>
    /// RFC 4035 §5.2: the DNSKEY RRset is authenticated with the DS from the
    /// parent, and the DS covers the key-signing key. Signing the DNSKEY RRset
    /// with the zone-signing key instead produces a zone that verifies against
    /// itself and cannot be reached through its parent — which is the failure
    /// that looks fine everywhere except at the one moment it matters.
    ///
    /// <para>
    /// The other half is the point of having two keys at all: everything that is
    /// not the DNSKEY RRset is signed by the zone-signing key, so rolling it
    /// never involves the parent.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4035 §5.2")]
    [Property("RFC", "6781 §3.1")]
    public void The_Dnskey_Rrset_Is_Signed_By_The_Key_A_Ds_Would_Name()
    {

        using var ksk = DNSSECSigningKey.Generate(Name(Zone), 13, KeySigningKey: true);
        using var zsk = DNSSECSigningKey.Generate(Name(Zone), 13, KeySigningKey: false);

        Assert.That(ksk.KeyTag, Is.Not.EqualTo(zsk.KeyTag),
                    "the two keys are distinct, which is what the test rests on");

        var signed = DNSSECZoneSigner.Sign(SmallZone(), Name(Zone), [ ksk, zsk ]);

        Assert.Multiple(() => {

            Assert.That(SignaturesOver(signed, Zone, DNSResourceRecordTypes.DNSKEY).Select(rrsig => rrsig.KeyTag),
                        Is.EqualTo(new[] { ksk.KeyTag }),
                        "the apex DNSKEY RRset is signed by the key the parent's DS would name, and only by it");

            Assert.That(SignaturesOver(signed, "a." + Zone, DNSResourceRecordTypes.A).Select(rrsig => rrsig.KeyTag),
                        Is.EqualTo(new[] { zsk.KeyTag }),
                        "and the zone's own data by the key it can roll without asking the parent");

        });

    }

    #endregion

    #region A_Zone_With_Only_One_Kind_Of_Key_Still_Signs_Its_Dnskey_Rrset()

    /// <summary>
    /// The two-key split is a convention, not a requirement: RFC 6781 §3.1
    /// describes it and RFC 4035 does not demand it. A zone keyed with a single
    /// key that is not marked as a secure entry point is unusual and legal, and
    /// RFC 4035 §2.2's requirement does not soften for it — the apex DNSKEY RRset
    /// still has to carry a signature, or there is nothing for a DS to
    /// authenticate and the zone is unreachable through its parent.
    ///
    /// <para>
    /// So the signer falls back to whatever keys it has when one of the two roles
    /// is unfilled. Each direction of that fallback is its own line; this is the
    /// one no test had asked for.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4035 §2.2")]
    public void A_Zone_With_Only_One_Kind_Of_Key_Still_Signs_Its_Dnskey_Rrset()
    {

        using var zsk = DNSSECSigningKey.Generate(Name(Zone), 13, KeySigningKey: false);

        var signed = DNSSECZoneSigner.Sign(SmallZone(), Name(Zone), [ zsk ]);

        Assert.That(SignaturesOver(signed, Zone, DNSResourceRecordTypes.DNSKEY).Select(rrsig => rrsig.KeyTag),
                    Is.EqualTo(new[] { zsk.KeyTag }),
                    "with no key-signing key to reach for, the one key signs the DNSKEY RRset too");

    }

    #endregion

}

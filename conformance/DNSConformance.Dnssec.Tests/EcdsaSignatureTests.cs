using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 6605 — ECDSA Curve P-256 with SHA-256 (algorithm 13), against a second
/// zone that BIND signed with ECDSA keys.
///
/// This is a genuinely different code path from the RSA fixtures: the DNSKEY
/// carries a raw uncompressed point with no 0x04 prefix, and the signature is
/// the fixed-width r||s pair rather than an ASN.1 sequence. Both conventions are
/// easy to get wrong in a way that RSA tests would never reveal.
/// </summary>
[TestFixture]
[Property("RFC", "6605")]
public class EcdsaSignatureTests
{

    private const String EcdsaZone = "ecdsa.dnssec.test";

    private SignedZoneFixture zone = null!;

    [OneTimeSetUp]
    public void LoadFixture()
    {

        if (!SignedZoneFixture.IsAvailableFor(EcdsaZone))
            Assert.Ignore($"{EcdsaZone} fixture missing — regenerate with: wsl -e sh fixtures/zones/resign.sh");

        zone = SignedZoneFixture.Load(EcdsaZone);

    }


    private static DNSSECValidator NewValidator()
        => new(new DNSClient(QueryTimeout: TimeSpan.FromSeconds(2)));


    #region Fixture_Is_Signed_With_Algorithm_13()

    [Test]
    public void Fixture_Is_Signed_With_Algorithm_13()
    {

        Assert.Multiple(() => {

            Assert.That(zone.DnsKeys,    Is.Not.Empty);
            Assert.That(zone.Signatures, Is.Not.Empty);

            Assert.That(zone.DnsKeys.Select(k => k.Algorithm),    Is.All.EqualTo(13),
                        "the ECDSA fixture must publish only algorithm-13 keys");

            Assert.That(zone.Signatures.Select(s => s.Algorithm), Is.All.EqualTo(13));

            // RFC 6605 §4: the P-256 public key is the 64-octet uncompressed point
            // with the leading 0x04 indicator omitted.
            Assert.That(zone.DnsKeys.Select(k => k.PublicKey.Length), Is.All.EqualTo(64),
                        "a P-256 DNSKEY carries exactly x||y");

        });

    }

    #endregion

    #region Ecdsa_Rrsig_Validates(...)

    [TestCase("a.ecdsa.dnssec.test",   DNSResourceRecordTypes.A,   TestName = "Ecdsa_Rrsig_Over_A_Validates")]
    [TestCase("txt.ecdsa.dnssec.test", DNSResourceRecordTypes.TXT, TestName = "Ecdsa_Rrsig_Over_TXT_Validates")]
    [TestCase("ecdsa.dnssec.test",     DNSResourceRecordTypes.SOA, TestName = "Ecdsa_Rrsig_Over_SOA_Validates")]
    [TestCase("ecdsa.dnssec.test",     DNSResourceRecordTypes.NS,  TestName = "Ecdsa_Rrsig_Over_NS_Validates")]
    public void Ecdsa_Rrsig_Validates(String ownerName, DNSResourceRecordTypes type)
    {

        var rrset     = zone.RRset(ownerName, type);
        var signature = zone.SignatureFor(ownerName, type);

        Assert.That(rrset,     Is.Not.Empty, $"fixture has no {type} RRset for {ownerName}");
        Assert.That(signature, Is.Not.Null,  $"fixture has no RRSIG({type}) for {ownerName}");

        var key = zone.KeyFor(signature!);

        Assert.That(key, Is.Not.Null, "no DNSKEY matches the RRSIG's key tag and algorithm");

        Assert.That(NewValidator().ValidateRRSig(rrset, signature!, key!),
                    Is.EqualTo(DNSSECValidationResult.Secure),
                    "a BIND-made ECDSA P-256 signature must verify");

    }

    #endregion

    #region Ecdsa_Ds_Matches_Its_Ksk()

    [Test]
    [Property("RFC", "4509")]
    public void Ecdsa_Ds_Matches_Its_Ksk()
    {

        var ksk = zone.KeySigningKey!;

        Assert.Multiple(() => {
            Assert.That(DNSSECValidator.ComputeKeyTag(ksk), Is.EqualTo(zone.DelegationSigner.KeyTag),
                        "key tag over an ECDSA key must match dnssec-dsfromkey");
            Assert.That(DNSSECValidator.VerifyDS(ksk, zone.DelegationSigner), Is.True);
        });

    }

    #endregion

    #region Ecdsa_Signature_Under_The_Wrong_Key_Is_Rejected()

    [Test]
    [Property("RFC", "4035 §5.3.3")]
    public void Ecdsa_Signature_Under_The_Wrong_Key_Is_Rejected()
    {

        // Verifying under the KSK a signature the ZSK made must fail. With the
        // fixed-width r||s encoding a lenient parser can accidentally accept
        // almost anything, so this is worth pinning explicitly.
        var rrset     = zone.RRset("a.ecdsa.dnssec.test", DNSResourceRecordTypes.A);
        var signature = zone.SignatureFor("a.ecdsa.dnssec.test", DNSResourceRecordTypes.A)!;
        var wrongKey  = zone.DnsKeys.First(k => DNSSECValidator.ComputeKeyTag(k) != signature.KeyTag);

        Assert.That(NewValidator().ValidateRRSig(rrset, signature, wrongKey),
                    Is.Not.EqualTo(DNSSECValidationResult.Secure));

    }

    #endregion

}

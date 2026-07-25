using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// Every signature algorithm Hermod's validator claims to support, against a
/// zone BIND signed with that algorithm.
///
/// These are not variations on one test. Each algorithm family has its own key
/// and signature encoding, and the encodings are where implementations actually
/// break — RSA carries its exponent in the two forms of RFC 3110, ECDSA is a
/// fixed-width r||s pair rather than the ASN.1 sequence .NET produces by
/// default, and the Edwards curves are raw 32- and 57-octet keys handled by a
/// different library again. A verifier can be flawless for one family and
/// entirely broken for the next, and nothing but a real signature will say so.
///
/// A zone whose algorithm this machine's BIND could not sign is reported as
/// missing and the case ignores itself, so a bare checkout stays green.
/// </summary>
[TestFixture]
[Property("RFC", "4034 §5.1")]
public class SignatureAlgorithmMatrixTests
{

    #region Fixture plumbing

    /// <summary>
    /// The public key length each algorithm must produce, or 0 where it varies.
    /// RSA moduli differ by key size; the curve algorithms are fixed by their
    /// specification, so an unexpected length there is a real defect.
    /// </summary>
    private static SignedZoneFixture Require(String Origin)
    {

        if (!SignedZoneFixture.IsAvailableFor(Origin))
            Assert.Ignore($"'{Origin}' fixture missing — regenerate with: wsl -e sh fixtures/zones/resign.sh");

        return SignedZoneFixture.Load(Origin);

    }

    private static DNSSECValidator NewValidator()
        => new(new DNSClient(QueryTimeout: TimeSpan.FromSeconds(2)));

    #endregion


    #region Zone_Is_Signed_With_The_Expected_Algorithm(...)

    [TestCase("ecdsa.dnssec.test",        13, 64, TestName = "Algorithm_13_EcdsaP256_Key_Shape")]
    [TestCase("ecdsap384.dnssec.test",    14, 96, TestName = "Algorithm_14_EcdsaP384_Key_Shape")]
    [TestCase("ed25519.dnssec.test",      15, 32, TestName = "Algorithm_15_Ed25519_Key_Shape")]
    [TestCase("ed448.dnssec.test",        16, 57, TestName = "Algorithm_16_Ed448_Key_Shape")]
    [TestCase("rsasha512.dnssec.test",    10,  0, TestName = "Algorithm_10_RsaSha512_Key_Shape")]
    [TestCase("rsasha1.dnssec.test",       5,  0, TestName = "Algorithm_5_RsaSha1_Key_Shape")]
    [TestCase("nsec3rsasha1.dnssec.test",  7,  0, TestName = "Algorithm_7_RsaSha1Nsec3_Key_Shape")]
    public void Zone_Is_Signed_With_The_Expected_Algorithm(String origin,
                                                           Int32  algorithm,
                                                           Int32  publicKeyLength)
    {

        var zone = Require(origin);

        Assert.Multiple(() => {

            Assert.That(zone.DnsKeys,    Is.Not.Empty, "the fixture must publish DNSKEYs");
            Assert.That(zone.Signatures, Is.Not.Empty, "the fixture must publish RRSIGs");

            Assert.That(zone.DnsKeys.Select(k => (Int32) k.Algorithm),    Is.All.EqualTo(algorithm));
            Assert.That(zone.Signatures.Select(s => (Int32) s.Algorithm), Is.All.EqualTo(algorithm));

            // RFC 6605 §4 (P-256/P-384) and RFC 8080 §3 (Ed25519/Ed448) fix these
            // exactly: the coordinates or the raw key, with no framing octets.
            if (publicKeyLength > 0)
                Assert.That(zone.DnsKeys.Select(k => k.PublicKey.Length),
                            Is.All.EqualTo(publicKeyLength),
                            $"algorithm {algorithm} keys are {publicKeyLength} octets");

        });

    }

    #endregion

    #region Rrsigs_Validate(...)

    [TestCase("ecdsa.dnssec.test",        TestName = "Algorithm_13_EcdsaP256_Rrsigs_Validate")]
    [TestCase("ecdsap384.dnssec.test",    TestName = "Algorithm_14_EcdsaP384_Rrsigs_Validate")]
    [TestCase("ed25519.dnssec.test",      TestName = "Algorithm_15_Ed25519_Rrsigs_Validate")]
    [TestCase("ed448.dnssec.test",        TestName = "Algorithm_16_Ed448_Rrsigs_Validate")]
    [TestCase("rsasha512.dnssec.test",    TestName = "Algorithm_10_RsaSha512_Rrsigs_Validate")]
    [TestCase("rsasha1.dnssec.test",      TestName = "Algorithm_5_RsaSha1_Rrsigs_Validate")]
    [TestCase("nsec3rsasha1.dnssec.test", TestName = "Algorithm_7_RsaSha1Nsec3_Rrsigs_Validate")]
    [Property("RFC", "4034 §3.1.8")]
    public void Rrsigs_Validate(String origin)
    {

        var zone      = Require(origin);
        var validator = NewValidator();

        (String Owner, DNSResourceRecordTypes Type)[] rrsets = [
            ($"a.{origin}",    DNSResourceRecordTypes.A),
            ($"aaaa.{origin}", DNSResourceRecordTypes.AAAA),
            ($"txt.{origin}",  DNSResourceRecordTypes.TXT),
            (origin,           DNSResourceRecordTypes.SOA),
            (origin,           DNSResourceRecordTypes.NS)
        ];

        Assert.Multiple(() => {

            foreach (var (owner, type) in rrsets)
            {

                var rrset     = zone.RRset(owner, type);
                var signature = zone.SignatureFor(owner, type);

                Assert.That(rrset,     Is.Not.Empty, $"fixture has no {type} RRset for {owner}");
                Assert.That(signature, Is.Not.Null,  $"fixture has no RRSIG({type}) for {owner}");

                if (signature is null || rrset.Count == 0)
                    continue;

                var key = zone.KeyFor(signature);

                Assert.That(key, Is.Not.Null, $"no DNSKEY matches the RRSIG({type}) key tag {signature.KeyTag}");

                if (key is null)
                    continue;

                Assert.That(validator.ValidateRRSig(rrset, signature, key),
                            Is.EqualTo(DNSSECValidationResult.Secure),
                            $"BIND's {type} signature for {owner} must verify");

            }

        });

    }

    #endregion

    #region Ds_Matches_The_Ksk(...)

    [TestCase("ecdsa.dnssec.test",        TestName = "Algorithm_13_EcdsaP256_Ds_Matches")]
    [TestCase("ecdsap384.dnssec.test",    TestName = "Algorithm_14_EcdsaP384_Ds_Matches")]
    [TestCase("ed25519.dnssec.test",      TestName = "Algorithm_15_Ed25519_Ds_Matches")]
    [TestCase("ed448.dnssec.test",        TestName = "Algorithm_16_Ed448_Ds_Matches")]
    [TestCase("rsasha512.dnssec.test",    TestName = "Algorithm_10_RsaSha512_Ds_Matches")]
    [TestCase("rsasha1.dnssec.test",      TestName = "Algorithm_5_RsaSha1_Ds_Matches")]
    [TestCase("nsec3rsasha1.dnssec.test", TestName = "Algorithm_7_RsaSha1Nsec3_Ds_Matches")]
    [Property("RFC", "4034 §5.1.4")]
    public void Ds_Matches_The_Ksk(String origin)
    {

        // The key tag is a checksum over the DNSKEY RDATA and the DS digest is a
        // hash of the owner name plus that same RDATA, so both depend on the key
        // having been encoded exactly as BIND encoded it. Agreeing with
        // dnssec-dsfromkey here means Hermod reconstructs the RDATA byte for byte.
        var zone = Require(origin);
        var ksk  = zone.KeySigningKey;

        Assert.That(ksk, Is.Not.Null, "the fixture must publish a KSK");

        Assert.Multiple(() => {
            Assert.That(DNSSECValidator.ComputeKeyTag(ksk!), Is.EqualTo(zone.DelegationSigner.KeyTag),
                        "key tag must match the one dnssec-dsfromkey published");
            Assert.That(DNSSECValidator.VerifyDS(ksk!, zone.DelegationSigner), Is.True,
                        "DS digest must match");
        });

    }

    #endregion

    #region Tampered_Rdata_Is_Rejected(...)

    [TestCase("ecdsa.dnssec.test",        TestName = "Algorithm_13_EcdsaP256_Rejects_Tampering")]
    [TestCase("ecdsap384.dnssec.test",    TestName = "Algorithm_14_EcdsaP384_Rejects_Tampering")]
    [TestCase("ed25519.dnssec.test",      TestName = "Algorithm_15_Ed25519_Rejects_Tampering")]
    [TestCase("ed448.dnssec.test",        TestName = "Algorithm_16_Ed448_Rejects_Tampering")]
    [TestCase("rsasha512.dnssec.test",    TestName = "Algorithm_10_RsaSha512_Rejects_Tampering")]
    [TestCase("rsasha1.dnssec.test",      TestName = "Algorithm_5_RsaSha1_Rejects_Tampering")]
    [TestCase("nsec3rsasha1.dnssec.test", TestName = "Algorithm_7_RsaSha1Nsec3_Rejects_Tampering")]
    [Property("RFC", "4035 §5.3.3")]
    public void Tampered_Rdata_Is_Rejected(String origin)
    {

        // A verifier that accepts everything passes every test above. One altered
        // octet is what separates "verifies signatures" from "returns Secure".
        var zone      = Require(origin);
        var signature = zone.SignatureFor($"a.{origin}", DNSResourceRecordTypes.A);

        Assert.That(signature, Is.Not.Null);

        var key       = zone.KeyFor(signature!);

        Assert.That(key, Is.Not.Null);

        var tampered  = new A(
                            DomainName.Parse($"a.{origin}"),
                            DNSQueryClasses.IN,
                            TimeSpan.FromSeconds(signature!.OriginalTTL),
                            IPv4Address.Parse("192.0.2.66")   // the fixture holds 192.0.2.13
                        );

        Assert.That(NewValidator().ValidateRRSig([tampered], signature, key!),
                    Is.Not.EqualTo(DNSSECValidationResult.Secure),
                    "an altered address must not validate");

    }

    #endregion

    #region Signature_Under_The_Wrong_Key_Is_Rejected(...)

    [TestCase("ecdsa.dnssec.test",        TestName = "Algorithm_13_EcdsaP256_Rejects_Wrong_Key")]
    [TestCase("ecdsap384.dnssec.test",    TestName = "Algorithm_14_EcdsaP384_Rejects_Wrong_Key")]
    [TestCase("ed25519.dnssec.test",      TestName = "Algorithm_15_Ed25519_Rejects_Wrong_Key")]
    [TestCase("ed448.dnssec.test",        TestName = "Algorithm_16_Ed448_Rejects_Wrong_Key")]
    [TestCase("rsasha512.dnssec.test",    TestName = "Algorithm_10_RsaSha512_Rejects_Wrong_Key")]
    [TestCase("rsasha1.dnssec.test",      TestName = "Algorithm_5_RsaSha1_Rejects_Wrong_Key")]
    [TestCase("nsec3rsasha1.dnssec.test", TestName = "Algorithm_7_RsaSha1Nsec3_Rejects_Wrong_Key")]
    [Property("RFC", "4035 §5.3.3")]
    public void Signature_Under_The_Wrong_Key_Is_Rejected(String origin)
    {

        // Verifying the ZSK's signature under the KSK. Both keys are the same
        // algorithm and the same shape, so a verifier that silently ignores the
        // key material — or reads it from the wrong offset — would still say
        // Secure here.
        var zone      = Require(origin);
        var signature = zone.SignatureFor($"a.{origin}", DNSResourceRecordTypes.A);

        Assert.That(signature, Is.Not.Null);

        var rrset     = zone.RRset($"a.{origin}", DNSResourceRecordTypes.A);
        var wrongKey  = zone.DnsKeys.FirstOrDefault(k => DNSSECValidator.ComputeKeyTag(k) != signature!.KeyTag);

        Assert.That(wrongKey, Is.Not.Null, "the fixture must publish a second key to test against");

        Assert.That(NewValidator().ValidateRRSig(rrset, signature!, wrongKey!),
                    Is.Not.EqualTo(DNSSECValidationResult.Secure));

    }

    #endregion

}

using System.Security.Cryptography;
using System.Text;

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
[Property("RFC", "6605")]        // ECDSA P-256 (13) and P-384 (14)
[Property("RFC", "8080")]        // Ed25519 (15) and Ed448 (16)
[Property("RFC", "8624")]        // every algorithm 8624 asks a validator to implement, plus deprecated RSA/SHA-1
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


    #region Encoding_A_Dnskey_Needs_Only_The_Public_Half()

    /// <summary>
    /// RFC 4034 §2.1: a DNSKEY's RDATA is a public key. Every reader of one holds
    /// nothing else — a validator learns keys off the wire and never sees a
    /// private half — so the encoder has to work from the public parameters
    /// alone.
    ///
    /// <para>
    /// Asking a key object for its private parameters is not a milder request
    /// that merely returns more: a key that has only the public half refuses it
    /// outright. An encoder written that way works perfectly in the signer's own
    /// process, where the key was just generated, and throws in every validator
    /// that ever reads a DNSKEY back.
    /// </para>
    ///
    /// <para>
    /// The keys here are stripped by exporting their public parameters and
    /// importing those into a fresh object, which is what a key read off the wire
    /// amounts to. The encoding is asserted to be the same as the full key's,
    /// because the point is that the private half was never needed.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4034 §2.1")]
    public void Encoding_A_Dnskey_Needs_Only_The_Public_Half()
    {

        using var rsa          = RSA.Create(2048);
        using var rsaPublic    = RSA.Create();
        rsaPublic.ImportParameters(rsa.ExportParameters(false));

        using var ecdsa        = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ecdsaPublic  = ECDsa.Create(ecdsa.ExportParameters(false));

        Assert.Multiple(() => {

            Assert.That(DNSSECSigning.EncodePublicKey(8, rsaPublic),
                        Is.EqualTo(DNSSECSigning.EncodePublicKey(8, rsa)).AsCollection,
                        "RFC 3110's exponent and modulus are both public");

            Assert.That(DNSSECSigning.EncodePublicKey(13, ecdsaPublic),
                        Is.EqualTo(DNSSECSigning.EncodePublicKey(13, ecdsa)).AsCollection,
                        "and RFC 6605's curve point is the public point");

        });

    }

    #endregion

    #region An_Exponent_Of_Exactly_255_Octets_Uses_The_Short_Form()

    /// <summary>
    /// A key that holds nothing but the parameters it was handed. Windows CNG
    /// refuses to import a 255-octet exponent outright — "Unknown error
    /// (0xc1000001)" — and it is right to: no such key is usable. But the
    /// question here is what the *encoder* writes when it is given one, and RFC
    /// 3110 §2 answers that whether or not a platform will hold the key.
    /// </summary>
    private sealed class ParametersOnlyRsa(RSAParameters Parameters) : RSA
    {
        public override RSAParameters ExportParameters(Boolean IncludePrivateParameters)
            => IncludePrivateParameters
                   ? throw new CryptographicException("This key holds only its public half.")
                   : Parameters;

        public override void ImportParameters(RSAParameters Parameters)
            => throw new NotSupportedException();
    }

    /// <summary>
    /// RFC 3110 §2: the exponent length is "one octet" when it fits in one, and
    /// otherwise "a zero octet followed by a two octet" length. One octet holds
    /// 255, so an exponent of exactly 255 octets is the last one written the
    /// short way — and the first place an implementation gets it wrong.
    ///
    /// <para>
    /// No real key is anywhere near it: the exponent is almost always 65537,
    /// three octets, which is why the boundary goes unexercised and why the
    /// comment beside the code says as much. Reaching it takes a key object that
    /// holds parameters and nothing else, because the platform's own RSA refuses
    /// to import one — and refusing is the correct thing for it to do. What is
    /// under test is the encoding rule, not the key.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "3110 §2")]
    public void An_Exponent_Of_Exactly_255_Octets_Uses_The_Short_Form()
    {

        var exponent       = new Byte[255];
        exponent[0]        = 0x01;
        exponent[^1]       = 0x01;

        var modulus        = new Byte[256];
        modulus[0]         = 0xC0;
        modulus[^1]        = 0x01;

        using var wide     = new ParametersOnlyRsa(new RSAParameters { Modulus = modulus, Exponent = exponent });
        using var ordinary = RSA.Create(2048);

        var encoded        = DNSSECSigning.EncodePublicKey(8, wide);

        Assert.Multiple(() => {

            Assert.That(encoded[0], Is.EqualTo((Byte) 255),
                        "255 octets still fit in the one-octet form, which is the form §2 says to use");

            Assert.That(encoded, Has.Length.EqualTo(1 + 255 + 256),
                        "so there is no zero octet and no two-octet length in front of them");

            Assert.That(DNSSECSigning.EncodePublicKey(8, ordinary)[0], Is.EqualTo((Byte) 3),
                        "the control: an ordinary exponent of 65537 is three octets, written the same way");

        });

    }

    #endregion

    #region The algorithm number is a decision, not a label

    /// <summary>
    /// The octets a validator would be asked to check, and a signature over them
    /// that really does verify — under the algorithm it was made with.
    /// </summary>
    private static (Byte[] PublicKey, Byte[] Data, Byte[] Signature) RsaSha256Material(RSA Key)
    {

        var data = Encoding.ASCII.GetBytes("the octets a validator would be asked to check");

        return (DNSSECSigning.EncodePublicKey(8, Key),
                data,
                Key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

    }

    #endregion

    #region An_Algorithm_RFC_8624_Forbids_Does_Not_Verify(...)

    /// <summary>
    /// RFC 8624 §3.1's table has two columns, and the tests above cover one of
    /// them. This is the other: the algorithms whose **DNSSEC Validation** column
    /// reads MUST NOT.
    ///
    /// <list type="bullet">
    ///   <item>1, RSAMD5 — MUST NOT</item>
    ///   <item>3, DSA — MUST NOT</item>
    ///   <item>6, DSA-NSEC3-SHA1 — MUST NOT</item>
    /// </list>
    ///
    /// <para>
    /// The construction is the sharp one, because "returns false" is what a
    /// broken verifier returns too. The key, the data and the signature are the
    /// same three in both assertions, and the signature genuinely verifies: only
    /// the algorithm number changes between the control and the case. So the
    /// refusal is the number being forbidden and nothing else — and RSAMD5 in
    /// particular carries its key in the same RFC 3110 form as RSASHA256, so
    /// there is not even an encoding to hide behind.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "8624 §3.1")]
    [TestCase((Byte)  1, TestName = "1, RSAMD5")]
    [TestCase((Byte)  3, TestName = "3, DSA")]
    [TestCase((Byte)  6, TestName = "6, DSA-NSEC3-SHA1")]
    public void An_Algorithm_RFC_8624_Forbids_Does_Not_Verify(Byte Algorithm)
    {

        using var rsa = RSA.Create(2048);

        var (publicKey, data, signature) = RsaSha256Material(rsa);

        Assert.Multiple(() => {

            Assert.That(DNSSECValidator.VerifySignature(8, publicKey, data, signature),
                        Is.True,
                        "the control: under the algorithm it was made with, this signature verifies");

            Assert.That(DNSSECValidator.VerifySignature(Algorithm, publicKey, data, signature),
                        Is.False,
                        "and under one RFC 8624 §3.1 forbids for validation, the same signature must not");

        });

    }

    #endregion

    #region A_Number_No_Algorithm_Is_Assigned_To_Does_Not_Verify(...)

    /// <summary>
    /// The same question for the numbers that name nothing: reserved (0),
    /// unassigned, and the two private-use ranges of RFC 4034 Appendix A.1.
    ///
    /// <para>
    /// A validator that treated an unrecognised number as "verified" would accept
    /// any octets at all as a signature, because the attacker chooses the number.
    /// That is the whole of the property, and it is the one place in this file
    /// where the answer must not depend on cryptography working.
    /// </para>
    ///
    /// <para>
    /// 17 is in the list on purpose: it is unassigned today and may not be
    /// tomorrow. If IANA assigns it and Hermod implements it, this case fails and
    /// asks to be moved to the matrix above, which is the right way round.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4034 App. A.1")]
    [TestCase((Byte)   0, TestName = "0, reserved")]
    [TestCase((Byte)   2, TestName = "2, Diffie-Hellman, not a signature algorithm")]
    [TestCase((Byte)   4, TestName = "4, reserved")]
    [TestCase((Byte)   9, TestName = "9, reserved")]
    [TestCase((Byte)  11, TestName = "11, reserved")]
    [TestCase((Byte)  17, TestName = "17, unassigned")]
    [TestCase((Byte) 100, TestName = "100, unassigned")]
    [TestCase((Byte) 253, TestName = "253, private algorithm")]
    [TestCase((Byte) 254, TestName = "254, private OID")]
    [TestCase((Byte) 255, TestName = "255, reserved")]
    public void A_Number_No_Algorithm_Is_Assigned_To_Does_Not_Verify(Byte Algorithm)
    {

        using var rsa = RSA.Create(2048);

        var (publicKey, data, signature) = RsaSha256Material(rsa);

        Assert.That(DNSSECValidator.VerifySignature(Algorithm, publicKey, data, signature),
                    Is.False,
                    "a number nothing is assigned to cannot be a way to have a signature accepted");

    }

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

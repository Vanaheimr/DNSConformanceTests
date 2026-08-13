using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 8080 — Ed25519 (algorithm 15) and Ed448 (algorithm 16), the signing half.
/// </summary>
/// <remarks>
/// <para>
/// Verification of these two has been covered here for a while, and covering it
/// was cheap: BIND signs a fixture zone, and a verifier either accepts the
/// signature or does not. Signing is the harder claim, because "it verifies"
/// proves almost nothing — an implementation that pre-hashes the message, or
/// picks the wrong context string, or mixes up the key encoding, verifies
/// perfectly against itself and against no one else.
/// </para>
/// <para>
/// EdDSA closes that gap by being deterministic (RFC 8032 §5.1.6): one key and
/// one message give exactly one signature, with no random nonce to make two
/// correct implementations disagree. So RFC 8080 §6's examples are not merely
/// illustrative — they are an exact expected output, and reproducing them byte
/// for byte says the whole construction is right, down to the choice of PureEdDSA
/// over the pre-hashed variant.
/// </para>
/// <para>
/// Nothing here goes near Hermod's verifier. The expected values are transcribed
/// from the RFC.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "8080")]
public class EdDsaSigningTests
{

    #region The RFC 8080 §6 examples, transcribed

    // Both key pairs of each algorithm. The private keys are base64 exactly as
    // the RFC prints them; the "PrivateKey:" field of a BIND private-key file is
    // the raw octet string and nothing else for these algorithms.
    private const String Ed25519Private1 = "ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=";
    private const String Ed25519Public1  = "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=";
    private const String Ed25519Sig1     = "Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+ey" +
                                           "sqcUOMIjWoevFkjH5GaMWeG96GUVZu6ECKOQmemHDg==";

    private const String Ed25519Private2 = "DSSF3o0s0f+ElWzj9E/Osxw8hLpk55chkmx0LYN5WiY=";
    private const String Ed25519Public2  = "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=";
    private const String Ed25519Sig2     = "5LL2obmzdqjWI+Xto5eP5adXt/T5tMhasWvwcyW4L3Sz" +
                                           "fcRawOle9bodhC+oip9ayUGjY9T/rL4rN3bOuESGDA==";

    private const String Ed448Private1   = "xZ+5Cgm463xugtkY5B0Jx6erFTXp13rYegst0qRtNsOY" +
                                           "naVpMx0Z/c5EiA9x8wWbDDct/U3FhYWA";
    private const String Ed448Public1    = "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPh" +
                                           "pj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA";
    private const String Ed448Sig1       = "Nmc0rgGKpr3GKYXcB1JmqqS4NYwhmechvJTqVzt3jR+Q" +
                                           "y/lSLFoIk1L+9e39GPL+5tVzDPN3f9kAwiu8KCuPPjtl" +
                                           "227ayaCZtRKZuJax7n9NuYlZJIusX0SOIOKBGzG+yWYt" +
                                           "z1/jjbzl5GGkWvREUCUA";

    private const String Ed448Private2   = "WEykD3ht3MHkU8iH4uVOLz8JLwtRBSqiBoM6fF72+Mrp" +
                                           "/u5gjxuB1DV6NnPO2BlZdz4hdSTkOdOA";
    private const String Ed448Public2    = "kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3t" +
                                           "DjeMCJcVMRDmgcNLp5HlHAMy12VoISsA";
    private const String Ed448Sig2       = "+JjANio/LIzp7osmMYE5XD3H/YES8kXs5Vb9H8MjPS8O" +
                                           "AGZMD37+LsCIcjg5ivt0d4Om/UaqETEAsJjaYe56CEQP" +
                                           "5lhRWuD2ivBqE0zfwJTyp4WqvpULbpvaukswvv/WNEFx" +
                                           "zEYQEIm9+xDlXj4pMAMA";

    private const Byte Ed25519 = 15;
    private const Byte Ed448   = 16;

    #endregion

    #region (private static) SignedDataOfTheExample(Algorithm, KeyTag)

    /// <summary>
    /// The octets RFC 8080 §6's signatures are taken over: the RRSIG RDATA up to
    /// but excluding the signature, followed by the MX RRset in canonical form
    /// (RFC 4034 §3.1.8.1, §6.2).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The labels field is 3, and that is not a typo.</b> RFC 4034 §3.1.3
    /// counts the labels of the owner name without the root, which makes
    /// <c>example.com.</c> two — but the signatures the RFC publishes only
    /// reproduce with three, and the printed RRSIG lines read
    /// <c>RRSIG MX 3 3600 …</c>, one field short of the format: the algorithm is
    /// missing and the 3 is the labels.
    /// </para>
    /// <para>
    /// So the examples were generated with a labels value their own owner name
    /// does not justify. That is a flaw in the document, not in this code, and
    /// the right response is to reproduce it rather than correct it: the labels
    /// octet is inside the signed data, so "fixing" it to 2 changes what is being
    /// signed and the vector stops matching. What these tests measure is the
    /// EdDSA construction — whether the right octets, whatever they are, produce
    /// the right signature.
    /// </para>
    /// </remarks>
    private static Byte[] SignedDataOfTheExample(Byte Algorithm, UInt16 KeyTag)
    {

        var mxRdata = new RawDnsWriter().
                          U16(10).
                          Name("mail.example.com.").
                          ToArray();

        return new RawDnsWriter().

                   // RRSIG RDATA, minus the signature (RFC 4034 §3.1.8.1)
                   U16(RawDnsType.MX).                 // type covered
                   U8 (Algorithm).
                   U8 (3).                             // labels — see the remarks above
                   U32(3600).                          // original TTL
                   U32(1440021600).                    // expiration
                   U32(1438207200).                    // inception
                   U16(KeyTag).
                   Name("example.com.").               // signer's name, uncompressed

                   // The RRset itself, in canonical form (RFC 4034 §6.2)
                   Name("example.com.").
                   U16(RawDnsType.MX).
                   U16(RawDnsClass.IN).
                   U32(3600).
                   U16((UInt16) mxRdata.Length).
                   Bytes(mxRdata).

                   ToArray();

    }

    #endregion


    #region The_Public_Key_Derives_From_The_Private_Key()

    [TestCase(Ed25519, Ed25519Private1, Ed25519Public1, TestName = "Public_key_derivation__Ed25519_first_example")]
    [TestCase(Ed25519, Ed25519Private2, Ed25519Public2, TestName = "Public_key_derivation__Ed25519_second_example")]
    [TestCase(Ed448,   Ed448Private1,   Ed448Public1,   TestName = "Public_key_derivation__Ed448_first_example")]
    [TestCase(Ed448,   Ed448Private2,   Ed448Public2,   TestName = "Public_key_derivation__Ed448_second_example")]
    [Property("RFC", "8080 §3")]
    public void The_Public_Key_Derives_From_The_Private_Key(Byte Algorithm, String PrivateKey, String ExpectedPublicKey)
    {

        // RFC 8080 §3: the DNSKEY's public key field is the raw point and nothing
        // else — no length prefix, no curve identifier, no ASN.1. The algorithm
        // number is what says which curve it is.
        //
        // This is worth its own test rather than being implied by the signature
        // vectors: a wrong derivation would publish a KEY record no signature of
        // this key ever verifies against, and nothing on the signing side would
        // notice, because the signer never uses the public half.
        var derived = DNSSECSigning.PublicKeyFromPrivateKey(Algorithm, Convert.FromBase64String(PrivateKey));

        Assert.That(Convert.ToBase64String(derived), Is.EqualTo(ExpectedPublicKey));

    }

    #endregion

    #region The_Published_Signature_Is_Reproduced_Exactly()

    [TestCase(Ed25519, Ed25519Private1, (UInt16) 3613,  Ed25519Sig1, TestName = "Signature_vector__Ed25519_first_example")]
    [TestCase(Ed25519, Ed25519Private2, (UInt16) 35217, Ed25519Sig2, TestName = "Signature_vector__Ed25519_second_example")]
    [TestCase(Ed448,   Ed448Private1,   (UInt16) 9713,  Ed448Sig1,   TestName = "Signature_vector__Ed448_first_example")]
    [TestCase(Ed448,   Ed448Private2,   (UInt16) 38353, Ed448Sig2,   TestName = "Signature_vector__Ed448_second_example")]
    [Property("RFC", "8080 §6")]
    public void The_Published_Signature_Is_Reproduced_Exactly(Byte    Algorithm,
                                                              String  PrivateKey,
                                                              UInt16  KeyTag,
                                                              String  ExpectedSignature)
    {

        // The strongest form this suite can assert. A sign-then-verify round trip
        // only says the two halves agree with each other; matching a signature
        // computed by somebody else, years ago, says the construction is the one
        // the RFC describes — PureEdDSA over the message as it stands, Ed448 with
        // an empty context, and the exact canonical form underneath.
        var signature = DNSSECSigning.Sign(
                            Algorithm,
                            Convert.FromBase64String(PrivateKey),
                            SignedDataOfTheExample(Algorithm, KeyTag)
                        );

        Assert.That(Convert.ToBase64String(signature), Is.EqualTo(ExpectedSignature));

    }

    #endregion

    #region Signing_The_Same_Message_Twice_Gives_The_Same_Signature()

    [TestCase(Ed25519, Ed25519Private1, TestName = "Determinism__Ed25519")]
    [TestCase(Ed448,   Ed448Private1,   TestName = "Determinism__Ed448")]
    [Property("RFC", "8032 §5.1.6")]
    public void Signing_The_Same_Message_Twice_Gives_The_Same_Signature(Byte Algorithm, String PrivateKey)
    {

        // The property the vectors above rest on. If EdDSA here were randomized —
        // as ECDSA is — the tests above could not exist, and this one going red
        // would be the first sign that a build had swapped in a nonce.
        var key  = Convert.FromBase64String(PrivateKey);
        var data = "the same message twice"u8.ToArray();

        Assert.That(DNSSECSigning.Sign(Algorithm, key, data),
                    Is.EqualTo(DNSSECSigning.Sign(Algorithm, key, data)));

    }

    #endregion

    #region A_Fresh_Signature_Verifies_And_A_Foreign_One_Does_Not()

    [TestCase(Ed25519, TestName = "Round_trip__Ed25519")]
    [TestCase(Ed448,   TestName = "Round_trip__Ed448")]
    public void A_Fresh_Signature_Verifies_And_A_Foreign_One_Does_Not(Byte Algorithm)
    {

        var privateKey  = DNSSECSigning.GeneratePrivateKey(Algorithm);
        var publicKey   = DNSSECSigning.PublicKeyFromPrivateKey(Algorithm, privateKey);
        var otherPublic = DNSSECSigning.PublicKeyFromPrivateKey(Algorithm, DNSSECSigning.GeneratePrivateKey(Algorithm));

        var data        = "signed with a freshly generated key"u8.ToArray();
        var signature   = DNSSECSigning.Sign(Algorithm, privateKey, data);

        Assert.Multiple(() => {

            Assert.That(DNSSECValidator.VerifySignature(Algorithm, publicKey,   data, signature), Is.True,
                        "a key generated here must produce signatures this build's own verifier accepts");

            Assert.That(DNSSECValidator.VerifySignature(Algorithm, otherPublic, data, signature), Is.False,
                        "and a different key must not");

            Assert.That(DNSSECValidator.VerifySignature(Algorithm, publicKey, "something else"u8.ToArray(), signature), Is.False,
                        "nor a different message");

        });

    }

    #endregion

    #region The_Lengths_Are_Fixed()

    [TestCase(Ed25519, 32, 64,  TestName = "Fixed_lengths__Ed25519")]
    [TestCase(Ed448,   57, 114, TestName = "Fixed_lengths__Ed448")]
    [Property("RFC", "8080 §3")]
    [Property("RFC", "8080 §4")]
    public void The_Lengths_Are_Fixed(Byte Algorithm, Int32 KeySize, Int32 SignatureSize)
    {

        // RFC 8080 §3 and §4 give both as exact octet counts, and DNS has no
        // length field for either — the DNSKEY's public key runs to the end of
        // the RDATA and the RRSIG's signature likewise. A parser that got the
        // size wrong would read into or past the neighbouring field, so the
        // numbers are structural rather than informational.
        var privateKey = DNSSECSigning.GeneratePrivateKey(Algorithm);

        Assert.Multiple(() => {

            Assert.That(DNSSECSigning.PrivateKeySize(Algorithm),                              Is.EqualTo(KeySize));
            Assert.That(privateKey,                                                           Has.Length.EqualTo(KeySize));
            Assert.That(DNSSECSigning.PublicKeyFromPrivateKey(Algorithm, privateKey),         Has.Length.EqualTo(KeySize));
            Assert.That(DNSSECSigning.Sign(Algorithm, privateKey, [1, 2, 3]),                 Has.Length.EqualTo(SignatureSize));

        });

    }

    #endregion

    #region A_Private_Key_Of_The_Wrong_Length_Is_Refused()

    [TestCase(Ed25519, 31, TestName = "Wrong_key_length__Ed25519_one_short")]
    [TestCase(Ed25519, 33, TestName = "Wrong_key_length__Ed25519_one_long")]
    [TestCase(Ed448,   56, TestName = "Wrong_key_length__Ed448_one_short")]
    [TestCase(Ed448,   32, TestName = "Wrong_key_length__Ed448_an_Ed25519_key")]
    public void A_Private_Key_Of_The_Wrong_Length_Is_Refused(Byte Algorithm, Int32 Length)
    {

        // The last case is the one that matters: an Ed25519 key handed to Ed448
        // is the mistake a configuration file makes, and truncating or padding it
        // silently would produce signatures under a key nobody holds.
        Assert.Throws<ArgumentException>(
            () => DNSSECSigning.Sign(Algorithm, new Byte[Length], [1, 2, 3])
        );

    }

    #endregion

    #region The_Two_Key_Shapes_Do_Not_Mix()

    [Test]
    public void The_Two_Key_Shapes_Do_Not_Mix()
    {

        using var rsa = RSA.Create(2048);

        Assert.Multiple(() => {

            Assert.That(DNSSECSigning.IsSupportedForSigning(Ed25519), Is.True);
            Assert.That(DNSSECSigning.IsSupportedForSigning(Ed448),   Is.True);

            Assert.That(DNSSECSigning.UsesRawPrivateKey(Ed25519), Is.True);
            Assert.That(DNSSECSigning.UsesRawPrivateKey(Ed448),   Is.True);
            Assert.That(DNSSECSigning.UsesRawPrivateKey(8),       Is.False);
            Assert.That(DNSSECSigning.UsesRawPrivateKey(13),      Is.False);

            // An Edwards algorithm with a platform key, and an RSA algorithm with
            // raw octets. Both are configuration mistakes, and both have to fail
            // where they are made rather than produce a signature nothing accepts.
            Assert.Throws<ArgumentException>(
                () => DNSSECSigning.Sign(Ed25519, rsa, [1, 2, 3]),
                "the Edwards curves have no AsymmetricAlgorithm to sign with"
            );

            Assert.Throws<ArgumentException>(
                () => DNSSECSigning.Sign(8, new Byte[32], [1, 2, 3]),
                "and RSA has no raw private key"
            );

            Assert.Throws<ArgumentException>(
                () => DNSSECSigning.EncodePublicKey(Ed25519, rsa),
                "nor is there anything to encode: an Edwards public key is already its wire form"
            );

        });

    }

    #endregion

}

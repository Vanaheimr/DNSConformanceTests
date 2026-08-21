using System.Buffers.Binary;
using System.Security.Cryptography;

using NUnit.Framework;

using DNSConformance.Core.RawDns;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 2931 — SIG(0), the per-message signature that authenticates one DNS
/// request or one exchange under a public key rather than a shared secret.
/// </summary>
/// <remarks>
/// <para>
/// There are no published test vectors for SIG(0): RFC 2931 gives the formula
/// and no worked example. So these tests do not reproduce someone else's
/// numbers — they encode §3.1 directly, assembling the signed data by hand and
/// checking it with the platform's own RSA and ECDSA rather than with Hermod's
/// verifier. Where a test asks "is this signature good", the answer comes from
/// <c>RSA.VerifyData</c>, not from the code that made it.
/// </para>
/// <para>
/// That is weaker evidence than the RFC 5155 Appendix A vectors elsewhere in
/// this suite, and is called out as such — the same caveat the TKEY tests carry.
/// </para>
/// </remarks>
[TestFixture]
public class Sig0SigningTests
{

    private static readonly DomainName SignerName = DomainName.Parse("signer.conformance.test");

    private const Byte AlgorithmRSASHA256      = 8;
    private const Byte AlgorithmRSASHA1        = 5;
    private const Byte AlgorithmECDSAP256SHA256 = 13;


    private static Byte[] Query(UInt16 id = 0x2931)
        => RawDnsWriter.Query(id, "example.conformance.test.", RawDnsType.A);


    /// <summary>
    /// The exact octets RFC 2931 §3.1 says are signed, assembled here rather
    /// than asked for: the SIG RDATA with the signature field omitted, then the
    /// request if this covers a transaction, then the message itself.
    /// </summary>
    private static Byte[] SignedDataPerRfc2931(Byte[]      Message,
                                               Byte[]?     Request,
                                               DomainName  Signer,
                                               Byte        Algorithm,
                                               UInt32      Expiration,
                                               UInt32      Inception,
                                               UInt16      KeyTag)
    {

        var data = new List<Byte>();

        void U16(UInt16 v) { data.Add((Byte) (v >> 8)); data.Add((Byte) (v & 0xFF)); }
        void U32(UInt32 v) { data.Add((Byte) (v >> 24)); data.Add((Byte) (v >> 16)); data.Add((Byte) (v >> 8)); data.Add((Byte) v); }

        U16(0);                       // type covered — zero is what makes it a SIG(0)
        data.Add(Algorithm);
        data.Add(0);                  // labels
        U32(0);                       // original TTL
        U32(Expiration);
        U32(Inception);
        U16(KeyTag);

        foreach (var label in Signer.FullName.ToLowerInvariant().TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            data.Add((Byte) label.Length);
            data.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }

        data.Add(0);                  // root label

        if (Request is not null)
            data.AddRange(Request);

        data.AddRange(Message);

        return [.. data];

    }


    /// <summary>
    /// The SIG(0)'s RDATA fields, read straight off the wire.
    /// </summary>
    private static (UInt16 TypeCovered, Byte Algorithm, Byte Labels, UInt32 OriginalTTL,
                    UInt32 Expiration, UInt32 Inception, UInt16 KeyTag, Byte[] Signature)
        FieldsOf(RawRecord Sig)
    {

        var rdata      = Sig.Rdata;
        var signerAt   = 18;
        var offset     = signerAt;

        while (offset < rdata.Length && rdata[offset] != 0)
            offset += rdata[offset] + 1;

        offset++;   // the root label

        return (
            BinaryPrimitives.ReadUInt16BigEndian(rdata.AsSpan( 0, 2)),
            rdata[2],
            rdata[3],
            BinaryPrimitives.ReadUInt32BigEndian(rdata.AsSpan( 4, 4)),
            BinaryPrimitives.ReadUInt32BigEndian(rdata.AsSpan( 8, 4)),
            BinaryPrimitives.ReadUInt32BigEndian(rdata.AsSpan(12, 4)),
            BinaryPrimitives.ReadUInt16BigEndian(rdata.AsSpan(16, 2)),
            rdata[offset..]
        );

    }


    #region Sig0_Record_Has_The_Shape_Rfc2931_Requires()

    [Test]
    [Property("RFC", "2931 §3")]
    public void Sig0_Record_Has_The_Shape_Rfc2931_Requires()
    {

        using var rsa = RSA.Create(2048);

        var key      = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);
        var query    = Query();
        var signed   = SIG0Signer.Sign(query, SignerName, AlgorithmRSASHA256, rsa, key.KeyTag);

        var message  = RawDnsReader.Parse(signed);
        var sig      = message.Additionals[^1];
        var fields   = FieldsOf(sig);

        Assert.Multiple(() => {

            Assert.That(message.Additionals, Has.Count.EqualTo(1),
                        "ARCOUNT counts the SIG(0), even though the signature did not cover that count");

            Assert.That(sig.Type,  Is.EqualTo((UInt16) 24), "TYPE 24 — SIG, not RRSIG");

            // §3: "the owner name, class, TTL, and original TTL, are meaningless.
            // The TTL fields SHOULD be zero and the CLASS field SHOULD be ANY.
            // To conserve space, the owner name SHOULD be root."
            Assert.That(sig.Name.Presentation, Is.EqualTo("."), "the root name, one octet");
            Assert.That(sig.Class, Is.EqualTo((UInt16) 255),    "CLASS ANY");
            Assert.That(sig.Ttl,   Is.Zero,                     "TTL zero");

            Assert.That(fields.TypeCovered, Is.Zero, "type covered zero is what makes a SIG a SIG(0)");
            Assert.That(fields.Labels,      Is.Zero);
            Assert.That(fields.OriginalTTL, Is.Zero);

            Assert.That(fields.KeyTag, Is.EqualTo(key.KeyTag),
                        "the key tag names which KEY at the signer's name to fetch");

            Assert.That(fields.Expiration, Is.GreaterThan(fields.Inception),
                        "§3.1: the window is what resists replay, so it has to be a window");

            // The record is appended, and nothing in the message is rewritten
            // except the one counter that has to be: ARCOUNT. In particular the
            // ID, the flags and the question come through untouched, so a peer
            // matching the reply to its query still can.
            Assert.That(signed[..10],                 Is.EqualTo(query[..10]).AsCollection,
                        "ID, flags, QDCOUNT, ANCOUNT and NSCOUNT are left alone");

            Assert.That(signed[12..query.Length],     Is.EqualTo(query[12..]).AsCollection,
                        "and so is everything after the header");

            Assert.That(BinaryPrimitives.ReadUInt16BigEndian(query. AsSpan(10, 2)), Is.Zero);
            Assert.That(BinaryPrimitives.ReadUInt16BigEndian(signed.AsSpan(10, 2)), Is.EqualTo(1),
                        "ARCOUNT is incremented after the signature was taken, never before");

        });

    }

    #endregion

    #region Signature_Covers_Exactly_What_Rfc2931_Section_3_1_Says()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public void Signature_Covers_Exactly_What_Rfc2931_Section_3_1_Says()
    {

        using var rsa = RSA.Create(2048);

        var key     = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);
        var query   = Query();
        var signed  = SIG0Signer.Sign(query, SignerName, AlgorithmRSASHA256, rsa, key.KeyTag);

        var sig     = RawDnsReader.Parse(signed).Additionals[^1];
        var fields  = FieldsOf(sig);

        // data = RDATA | request - SIG(0)
        var expected = SignedDataPerRfc2931(query, null, SignerName, AlgorithmRSASHA256,
                                            fields.Expiration, fields.Inception, fields.KeyTag);

        Assert.That(rsa.VerifyData(expected, fields.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                    Is.True,
                    "the signature must verify over the data §3.1 defines, checked here by the platform rather than by Hermod");

        // The half of §3.1 that is easy to get wrong: the message is signed
        // "before the reply RR counts have been changed for the inclusion of the
        // SIG(0)". Signing the incremented ARCOUNT is a one-byte mistake that
        // still round-trips against your own implementation and fails against
        // every other one.
        var withIncrementedArCount = (Byte[]) query.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(withIncrementedArCount.AsSpan(10, 2), 1);

        var wrong = SignedDataPerRfc2931(withIncrementedArCount, null, SignerName, AlgorithmRSASHA256,
                                         fields.Expiration, fields.Inception, fields.KeyTag);

        Assert.That(rsa.VerifyData(wrong, fields.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                    Is.False,
                    "…and it must not verify over the message with ARCOUNT already counting the SIG(0)");

    }

    #endregion

    #region A_Signed_Request_Verifies_Under_Its_Key([RSA, ECDSA])

    [Test]
    [Property("RFC", "2931 §3.2")]
    public void A_Signed_Request_Verifies_Under_Its_Rsa_Key()
    {

        using var rsa = RSA.Create(2048);

        var key    = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);
        var signed = SIG0Signer.Sign(Query(), SignerName, AlgorithmRSASHA256, rsa, key.KeyTag);

        var result = SIG0Signer.Verify(signed, key);

        Assert.Multiple(() => {
            Assert.That(result.IsValid, Is.True, result.Description);
            Assert.That(result.Failure, Is.EqualTo(SIG0Failure.None));
            Assert.That(result.Record?.IsTransactionSignature, Is.True);
        });

    }


    [Test]
    [Property("RFC", "2931 §3.2")]
    public void A_Signed_Request_Verifies_Under_Its_Ecdsa_Key()
    {

        // The other key family worth covering: a 64-octet r||s signature and a
        // bare curve point, where RSA has a length-prefixed exponent and a PKCS#1
        // block. An implementation can be perfect for one and broken for the other.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var key    = KEY.FromPublicKey(SignerName, AlgorithmECDSAP256SHA256, ecdsa);
        var signed = SIG0Signer.Sign(Query(), SignerName, AlgorithmECDSAP256SHA256, ecdsa, key.KeyTag);

        var result = SIG0Signer.Verify(signed, key);

        Assert.Multiple(() => {
            Assert.That(result.IsValid, Is.True, result.Description);
            Assert.That(FieldsOf(RawDnsReader.Parse(signed).Additionals[^1]).Signature,
                        Has.Length.EqualTo(64),
                        "RFC 6605 §4: r || s, fixed width, no ASN.1 wrapper");
        });

    }

    #endregion

    #region A_Message_Modified_In_Flight_Does_Not_Verify()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public void A_Message_Modified_In_Flight_Does_Not_Verify()
    {

        using var rsa = RSA.Create(2048);

        var key    = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);
        var signed = SIG0Signer.Sign(Query(), SignerName, AlgorithmRSASHA256, rsa, key.KeyTag);

        // One bit inside the QNAME. This is the attack SIG(0) exists to stop.
        signed[13] ^= 0x20;

        var result = SIG0Signer.Verify(signed, key);

        Assert.Multiple(() => {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Failure, Is.EqualTo(SIG0Failure.BadSignature));
        });

    }

    #endregion

    #region A_Signature_From_A_Different_Key_Does_Not_Verify()

    [Test]
    [Property("RFC", "2931 §3.2")]
    public void A_Signature_From_A_Different_Key_Does_Not_Verify()
    {

        using var mine      = RSA.Create(2048);
        using var somebodys = RSA.Create(2048);

        var myKey     = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, mine);
        var otherKey  = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, somebodys);

        var signed    = SIG0Signer.Sign(Query(), SignerName, AlgorithmRSASHA256, somebodys, otherKey.KeyTag);

        var result    = SIG0Signer.Verify(signed, myKey);

        Assert.Multiple(() => {

            Assert.That(result.IsValid, Is.False);

            // The key tag differs, so this is caught before any RSA work is done —
            // which is the point of the tag (RFC 4034 §5.3), and matters because
            // §2.4 warns that public key operations are the expensive part and an
            // obvious thing to flood a server with.
            Assert.That(result.Failure, Is.EqualTo(SIG0Failure.UnknownKey));

        });

    }

    #endregion

    #region A_Signature_From_Another_Name_Does_Not_Verify()

    [Test]
    [Property("RFC", "2931 §3")]
    public void A_Signature_From_Another_Name_Does_Not_Verify()
    {

        using var rsa = RSA.Create(2048);

        var signersKey  = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);
        var strangerKey = KEY.FromPublicKey(DomainName.Parse("stranger.conformance.test"),
                                            AlgorithmRSASHA256, rsa);

        var signed = SIG0Signer.Sign(Query(), SignerName, AlgorithmRSASHA256, rsa, signersKey.KeyTag);

        // Same key material, different name. §3 requires a KEY at the *signer's*
        // name, so holding the right bits under the wrong name proves nothing —
        // otherwise anyone could republish someone else's key and speak for them.
        var result = SIG0Signer.Verify(signed, strangerKey);

        Assert.Multiple(() => {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Failure, Is.EqualTo(SIG0Failure.UnknownKey));
        });

    }

    #endregion

    #region A_Signature_Outside_Its_Validity_Window_Is_Rejected()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public void A_Signature_Outside_Its_Validity_Window_Is_Rejected()
    {

        using var rsa = RSA.Create(2048);

        var key   = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);
        var now   = DateTimeOffset.UtcNow;

        var stale = SIG0Signer.Sign(Query(), SignerName, AlgorithmRSASHA256, rsa, key.KeyTag,
                                    Inception:  now.AddHours(-2),
                                    Expiration: now.AddHours(-1));

        var early = SIG0Signer.Sign(Query(), SignerName, AlgorithmRSASHA256, rsa, key.KeyTag,
                                    Inception:  now.AddHours(1),
                                    Expiration: now.AddHours(2));

        var staleResult = SIG0Signer.Verify(stale, key, now);
        var earlyResult = SIG0Signer.Verify(early, key, now);

        Assert.Multiple(() => {

            // The window is the entire replay defence — the signature over an
            // expired message is still cryptographically perfect.
            Assert.That(staleResult.IsValid, Is.False);
            Assert.That(staleResult.Failure, Is.EqualTo(SIG0Failure.OutsideValidityPeriod));

            Assert.That(earlyResult.IsValid, Is.False);
            Assert.That(earlyResult.Failure, Is.EqualTo(SIG0Failure.OutsideValidityPeriod));

            // …and inside the window the very same message is fine.
            Assert.That(SIG0Signer.Verify(stale, key, now.AddHours(-1.5)).IsValid, Is.True);

        });

    }

    #endregion

    #region The_Default_Window_Is_The_Five_Minutes_Rfc2931_Recommends()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public void The_Default_Window_Is_The_Five_Minutes_Rfc2931_Recommends()
    {

        using var rsa = RSA.Create(2048);

        var key    = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);
        var now    = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var signed = SIG0Signer.Sign(Query(), SignerName, AlgorithmRSASHA256, rsa, key.KeyTag);

        var fields = FieldsOf(RawDnsReader.Parse(signed).Additionals[^1]);

        Assert.Multiple(() => {

            // §3.1: the times "should not normally extend further than 5 minutes
            // into the past and 5 minutes into the future". A generous default
            // here would quietly widen every deployment's replay window.
            Assert.That(now - fields.Inception,  Is.InRange(295, 305));
            Assert.That(fields.Expiration - now, Is.InRange(295, 305));

        });

    }

    #endregion

    #region A_Transaction_Signature_Binds_A_Response_To_Its_Request()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public void A_Transaction_Signature_Binds_A_Response_To_Its_Request()
    {

        using var rsa = RSA.Create(2048);

        var key      = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);

        var request  = Query(0x1111);
        var other    = Query(0x2222);

        var response = RawDnsWriter.Response(
                           0x1111,
                           "example.conformance.test.",
                           RawDnsType.A,
                           [("example.conformance.test.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.1"))]
                       );

        // data = RDATA | full query | response - SIG(0)
        var signed = SIG0Signer.Sign(response, SignerName, AlgorithmRSASHA256, rsa, key.KeyTag,
                                     Request: request);

        Assert.Multiple(() => {

            Assert.That(SIG0Signer.Verify(signed, key, Request: request).IsValid, Is.True,
                        "the response verifies against the request it answers");

            // Folding the query in is what stops a captured response from being
            // replayed against a different question — the whole reason §3.1 has a
            // separate transaction form at all.
            Assert.That(SIG0Signer.Verify(signed, key, Request: other).IsValid, Is.False,
                        "…and not against a different one");

            Assert.That(SIG0Signer.Verify(signed, key).IsValid, Is.False,
                        "…nor on its own");

        });

    }

    #endregion

    #region A_Sig_Covering_An_Rrset_Is_Not_A_Transaction_Signature()

    [Test]
    [Property("RFC", "2931 §3, 3755 §3")]
    public void A_Sig_Covering_An_Rrset_Is_Not_A_Transaction_Signature()
    {

        using var rsa = RSA.Create(2048);

        var key    = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);
        var signed = SIG0Signer.Sign(Query(), SignerName, AlgorithmRSASHA256, rsa, key.KeyTag);

        // Turn the type-covered field from 0 into A. The record is now a SIG over
        // an RRset that happens to be sitting where a SIG(0) goes, and it must not
        // be read as authenticating the message: "type covered = 0" is the only
        // thing that distinguishes the two uses of TYPE 24.
        var sig = RawDnsReader.Parse(signed).Additionals[^1];

        BinaryPrimitives.WriteUInt16BigEndian(signed.AsSpan(sig.RdataOffset, 2), RawDnsType.A);

        var result = SIG0Signer.Verify(signed, key);

        Assert.Multiple(() => {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Failure, Is.EqualTo(SIG0Failure.NotATransactionSignature));
        });

    }

    #endregion

    #region An_Unsigned_Message_Is_Not_Quietly_Accepted()

    [Test]
    [Property("RFC", "2931 §3.2")]
    public void An_Unsigned_Message_Is_Not_Quietly_Accepted()
    {

        using var rsa = RSA.Create(2048);

        var key    = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);
        var result = SIG0Signer.Verify(Query(), key);

        Assert.Multiple(() => {
            Assert.That(result.IsValid, Is.False, "no signature is not the same as a good signature");
            Assert.That(result.Failure, Is.EqualTo(SIG0Failure.NotSigned));
        });

    }

    #endregion

    #region Rsa_Sha1_Can_Be_Verified_But_Not_Signed_With()

    [Test]
    [Property("RFC", "8624 §3.1")]
    public void Rsa_Sha1_Can_Be_Verified_But_Not_Signed_With()
    {

        using var rsa = RSA.Create(2048);

        Assert.Multiple(() => {

            Assert.That(DNSSECSigning.IsSupportedForSigning(AlgorithmRSASHA1),   Is.False);
            Assert.That(DNSSECSigning.IsSupportedForSigning(AlgorithmRSASHA256), Is.True);

            // MUST NOT for new signatures, MAY for validation. Refusing both
            // would break every zone still signed with it; allowing both would
            // let a caller make new SHA-1 signatures by accident.
            Assert.Throws<NotSupportedException>(
                () => DNSSECSigning.Sign(AlgorithmRSASHA1, rsa, [1, 2, 3]),
                "RFC 8624 §3.1: RSA/SHA-1 MUST NOT be used to sign"
            );

            var publicKey = DNSSECSigning.EncodePublicKey(AlgorithmRSASHA1, rsa);
            var signature = rsa.SignData([1, 2, 3], HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

            Assert.That(DNSSECValidator.VerifySignature(AlgorithmRSASHA1, publicKey, [1, 2, 3], signature),
                        Is.True,
                        "…and MAY still be validated");

        });

    }

    #endregion

    #region Key_Record_Tags_Itself_The_Way_Rfc4034_Appendix_B_Says()

    [Test]
    [Property("RFC", "4034 App. B, 2931 §3")]
    public void Key_Record_Tags_Itself_The_Way_Rfc4034_Appendix_B_Says()
    {

        using var rsa = RSA.Create(2048);

        var key   = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);

        // Appendix B, written out here rather than borrowed: sum the RDATA as
        // big-endian 16-bit words, fold the carry back in, keep the low 16 bits.
        var rdata = new List<Byte> { (Byte) (key.Flags >> 8), (Byte) (key.Flags & 0xFF), key.Protocol, key.Algorithm };
        rdata.AddRange(key.PublicKey);

        UInt32 ac = 0;

        for (var i = 0; i < rdata.Count; i++)
            ac += (i & 1) == 0 ? (UInt32) rdata[i] << 8 : rdata[i];

        ac += (ac >> 16) & 0xFFFF;

        Assert.That(key.KeyTag, Is.EqualTo((UInt16) (ac & 0xFFFF)));

    }

    #endregion

    #region Rsa_Public_Key_Uses_The_Rfc3110_Layout()

    [Test]
    [Property("RFC", "3110 §2")]
    public void Rsa_Public_Key_Uses_The_Rfc3110_Layout()
    {

        using var rsa = RSA.Create(2048);

        var parameters = rsa.ExportParameters(false);
        var encoded    = DNSSECSigning.EncodePublicKey(AlgorithmRSASHA256, rsa);

        Assert.Multiple(() => {

            // §2: one octet of exponent length while it fits in one, then the
            // exponent, then the modulus filling the rest. The three-octet form
            // exists for exponents over 255 octets, which nothing real uses — and
            // which is exactly why a reader that assumes the short form works
            // everywhere until it meets a hand-built key.
            Assert.That(encoded[0], Is.EqualTo((Byte) parameters.Exponent!.Length),
                        "a short exponent is length-prefixed with a single octet");

            Assert.That(encoded[0], Is.Not.Zero,
                        "a zero here would announce the three-octet long form");

            Assert.That(encoded[1..(1 + parameters.Exponent.Length)],
                        Is.EqualTo(parameters.Exponent).AsCollection);

            Assert.That(encoded[(1 + parameters.Exponent.Length)..],
                        Is.EqualTo(parameters.Modulus!).AsCollection,
                        "and the modulus is the remainder — no length of its own");

        });

    }

    #endregion

    #region Rsa_Public_Key_Uses_The_Long_Exponent_Form(ExponentOctets)

    [Test]
    [Property("RFC", "3110 §2")]
    [TestCase(256)]     // one past the short form
    [TestCase(300)]
    [TestCase(512)]     // §2's interoperability ceiling for the exponent, in octets
    public void Rsa_Public_Key_Uses_The_Long_Exponent_Form(Int32 ExponentOctets)
    {

        // §2: the exponent's "length in octets is represented as one octet if it
        // is in the range of 1 to 255 and by a zero octet followed by a two octet
        // unsigned length if it is longer than 255 bytes". Nothing real has an
        // exponent that big, which is why the branch goes untravelled — the test
        // above covers the short form with every key BIND ever signs with.
        using var rsa = RsaWithExponentOfLength(ExponentOctets);

        var parameters = rsa.ExportParameters(false);
        var encoded    = DNSSECSigning.EncodePublicKey(AlgorithmRSASHA256, rsa);

        Assert.Multiple(() => {

            Assert.That(encoded[0], Is.Zero,
                        "the zero octet is what announces the long form");

            Assert.That((encoded[1] << 8) | encoded[2],
                        Is.EqualTo(parameters.Exponent!.Length),
                        "followed by the length as two octets, most significant first");

            Assert.That(encoded[3..(3 + parameters.Exponent.Length)],
                        Is.EqualTo(parameters.Exponent).AsCollection,
                        "then the exponent itself");

            Assert.That(encoded[(3 + parameters.Exponent.Length)..],
                        Is.EqualTo(parameters.Modulus!).AsCollection,
                        "and the modulus is still the remainder");

            Assert.That(parameters.Exponent[0], Is.Not.Zero,
                        "§2: leading zero octets are prohibited in the exponent");

            Assert.That(parameters.Modulus![0], Is.Not.Zero,
                        "§2: and in the modulus");

        });

    }

    #endregion

    #region Rsa_Public_Key_Stays_Short_At_255_Octets()

    [Test]
    [Property("RFC", "3110 §2")]
    public void Rsa_Public_Key_Stays_Short_At_255_Octets()
    {

        // The boundary, and the half that stops "always use the long form" from
        // satisfying the test above: 255 is still "in the range of 1 to 255", so
        // it takes one octet. A reader handed 0xFF here expects the exponent to
        // start at offset 1, and one that emitted the long form instead would
        // shift everything by two and hand back a modulus two octets short.
        using var rsa = RsaWithExponentOfLength(255);

        var parameters = rsa.ExportParameters(false);
        var encoded    = DNSSECSigning.EncodePublicKey(AlgorithmRSASHA256, rsa);

        Assert.Multiple(() => {

            Assert.That(encoded[0], Is.EqualTo((Byte) 255), "one octet, holding 255");

            Assert.That(encoded[1..(1 + 255)],
                        Is.EqualTo(parameters.Exponent!).AsCollection);

            Assert.That(encoded[(1 + 255)..],
                        Is.EqualTo(parameters.Modulus!).AsCollection);

        });

    }

    #endregion

    #region (private static) RsaWithExponentOfLength(Octets)

    /// <summary>
    /// An RSA public key whose exponent is exactly the given number of octets.
    /// </summary>
    /// <remarks>
    /// Hand-built, because no key generator will make one: a real exponent is
    /// three octets, and RFC 3110's long form exists for a case the world never
    /// produces. The key is not usable for anything — the exponent is not coprime
    /// to anything in particular — but the encoder under test only reads the two
    /// numbers out, and that is the whole point of testing it here rather than
    /// through a signature.
    ///
    /// Whether such a key can even be held is a platform question, and the answer
    /// differs: OpenSSL accepts it, Windows CNG refuses it outright with an
    /// opaque 0xc1000001. So this skips rather than fails there, and the Linux
    /// leg of CI is what actually exercises the long form.
    /// </remarks>
    private static RSA RsaWithExponentOfLength(Int32 Octets)
    {

        // No leading zero — §2 prohibits one — and odd, which every RSA exponent is.
        var exponent   = new Byte[Octets];
        exponent[0]    = 0x01;
        exponent[^1]   = 0x01;

        var modulus    = new Byte[256];
        modulus[0]     = 0xC0;
        modulus[^1]    = 0x01;

        var rsa = RSA.Create();

        try
        {
            rsa.ImportParameters(new RSAParameters { Exponent = exponent, Modulus = modulus });
        }
        catch (CryptographicException e)
        {
            rsa.Dispose();
            Assert.Ignore($"This platform's RSA will not hold a {Octets}-octet public exponent " +
                          $"({e.Message}). Windows CNG refuses it; OpenSSL accepts it, so the " +
                          "Linux leg is what covers RFC 3110's long form.");
            throw;   // Assert.Ignore has already thrown.
        }

        return rsa;

    }

    #endregion

    #region Ecdsa_Public_Key_Is_The_Bare_Curve_Point()

    [Test]
    [Property("RFC", "6605 §4")]
    public void Ecdsa_Public_Key_Is_The_Bare_Curve_Point()
    {

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var parameters = ecdsa.ExportParameters(false);
        var encoded    = DNSSECSigning.EncodePublicKey(AlgorithmECDSAP256SHA256, ecdsa);

        Assert.Multiple(() => {

            Assert.That(encoded, Has.Length.EqualTo(64), "P-256: two 32-octet coordinates");

            Assert.That(encoded[0], Is.Not.EqualTo((Byte) 0x04).Or.EqualTo(parameters.Q.X![0]),
                        "no 0x04 uncompressed-point marker: the algorithm number already says which curve this is");

            Assert.That(encoded[..32],  Is.EqualTo(parameters.Q.X!).AsCollection);
            Assert.That(encoded[32..],  Is.EqualTo(parameters.Q.Y!).AsCollection);

        });

    }

    #endregion

    #region Stripping_The_Sig0_Restores_The_Message_That_Was_Signed()

    [Test]
    [Property("RFC", "2931 §3.1")]
    public void Stripping_The_Sig0_Restores_The_Message_That_Was_Signed()
    {

        using var rsa = RSA.Create(2048);

        var key    = KEY.FromPublicKey(SignerName, AlgorithmRSASHA256, rsa);
        var query  = Query();
        var signed = SIG0Signer.Sign(query, SignerName, AlgorithmRSASHA256, rsa, key.KeyTag);

        Assert.That(SIG0Signer.TryStripSIG0(signed, out var unsigned, out var record), Is.True);

        Assert.Multiple(() => {

            Assert.That(unsigned, Is.EqualTo(query).AsCollection,
                        "byte for byte the message as it was before signing, ARCOUNT included");

            Assert.That(record!.SignerName.FullName.TrimEnd('.'),
                        Is.EqualTo(SignerName.FullName.TrimEnd('.')));

            Assert.That(record.IsTransactionSignature, Is.True);

            // Unlike TSIG there is no original-ID field, so a forwarder that
            // rewrites the message ID in flight breaks the signature. That is a
            // property of RFC 2931, not an omission here, and it is worth having
            // pinned so nobody "fixes" it later.
            var rewritten = (Byte[]) signed.Clone();
            BinaryPrimitives.WriteUInt16BigEndian(rewritten.AsSpan(0, 2), 0xBEEF);

            Assert.That(SIG0Signer.Verify(rewritten, key).IsValid, Is.False,
                        "SIG(0) has no way to survive an ID rewrite — TSIG's Original ID has no counterpart here");

        });

    }

    #endregion

}

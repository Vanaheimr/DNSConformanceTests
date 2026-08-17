using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 8078 §4 — the CDS/CDNSKEY records that ask a parent to turn DNSSEC off,
/// and RFC 7344 §4.1 — the rules that decide whether it may.
/// </summary>
/// <remarks>
/// <para>
/// CDS moves control of the DS RRset into the child zone, which is the point:
/// a key rollover stops needing the registrar. RFC 8078 §4 extends that to
/// removal — one record, every field zero, and the parent takes the delegation
/// out of DNSSEC entirely.
/// </para>
/// <para>
/// Which makes the acceptance rules the interesting half. The record lives in
/// the child's own zone, so anyone able to write there can ask for this; what
/// stops them is §4.1's requirement that the RRset be signed by a key the
/// *parent* already trusts. The authority to change a delegation comes from the
/// delegation, and the tests below are mostly about the ways that can be got
/// wrong.
/// </para>
/// <para>
/// The sentinel belongs to RFC 8078, not RFC 7344 — 7344 defines CDS and
/// CDNSKEY and says nothing about deletion.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "8078 §4")]
public class CdsDeleteSentinelTests
{

    private static readonly DomainName Child  = DomainName.Parse("child.example.");
    private static readonly TimeSpan   Ttl    = TimeSpan.FromHours(1);


    #region The sentinel itself

    #region The_Cds_Sentinel_Is_All_Zeroes()

    [Test]
    public void The_Cds_Sentinel_Is_All_Zeroes()
    {

        // §4: "The contents of the CDS or CDNSKEY RRset MUST contain one RR and
        // only contain the exact fields as shown below.  CDS 0 0 0 0"
        var sentinel = CDS.DeleteSentinel(Child);

        Assert.Multiple(() => {

            Assert.That(sentinel.KeyTag,     Is.Zero);
            Assert.That(sentinel.Algorithm,  Is.Zero, "algorithm 0 is what carries the meaning");
            Assert.That(sentinel.DigestType, Is.Zero);
            Assert.That(sentinel.Digest,     Is.EqualTo(new Byte[] { 0x00 }),
                        "\"The keying material payload is represented by a single 0\"");

            Assert.That(sentinel.IsDeleteSentinel, Is.True);

        });

    }

    #endregion

    #region The_Cdnskey_Sentinel_Keeps_Protocol_Three()

    [Test]
    public void The_Cdnskey_Sentinel_Keeps_Protocol_Three()
    {

        // CDNSKEY 0 3 0 0 — the 3 is the one field that is not zero, and it is
        // not part of the sentinel at all. RFC 4034 §2.1.2 fixes the protocol
        // field of every DNSKEY at 3 and says a record carrying anything else
        // "MUST be treated as invalid", so zeroing it along with the rest would
        // produce a record no validator may look at.
        var sentinel = CDNSKEY.DeleteSentinel(Child);

        Assert.Multiple(() => {

            Assert.That(sentinel.Flags,     Is.Zero);
            Assert.That(sentinel.Protocol,  Is.EqualTo(3));
            Assert.That(sentinel.Algorithm, Is.Zero);
            Assert.That(sentinel.PublicKey, Is.EqualTo(new Byte[] { 0x00 }));

            Assert.That(sentinel.IsDeleteSentinel, Is.True);

        });

    }

    #endregion

    #region The_Sentinel_Survives_The_Wire()

    [Test]
    [Property("RFC", "7344 §3.1")]
    public void The_Sentinel_Survives_The_Wire()
    {

        // RFC 7344 §3.1/§3.2: CDS and CDNSKEY are DS and DNSKEY in wire format,
        // so the sentinel is an ordinary record with unusual contents — which is
        // exactly why nothing in the codec may special-case it. Read back through
        // the independent RawDns parser.
        var cdsRdata     = Encode(CDS.    DeleteSentinel(Child));
        var cdnskeyRdata = Encode(CDNSKEY.DeleteSentinel(Child));

        Assert.Multiple(() => {

            // key tag (2) + algorithm (1) + digest type (1) + one digest octet
            Assert.That(cdsRdata,     Is.EqualTo(new Byte[] { 0, 0, 0, 0, 0 }));

            // flags (2) + protocol (1) + algorithm (1) + one key octet
            Assert.That(cdnskeyRdata, Is.EqualTo(new Byte[] { 0, 0, 3, 0, 0 }));

        });

    }

    private static Byte[] Encode(IDNSResourceRecord Record)
    {

        var ms = new MemoryStream();
        ms.Write(new Byte[] { 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 });

        Record.Serialize(ms, UseCompression: false, CompressionOffsets: []);

        return RawDnsReader.Parse(ms.ToArray()).Answers.Single().Rdata;

    }

    #endregion

    #region A_Near_Miss_Is_Not_The_Sentinel()

    [TestCase((UInt16) 1, (Byte) 0, (Byte) 0, TestName = "Not_the_sentinel__a_key_tag")]
    [TestCase((UInt16) 0, (Byte) 8, (Byte) 0, TestName = "Not_the_sentinel__a_real_algorithm")]
    [TestCase((UInt16) 0, (Byte) 0, (Byte) 2, TestName = "Not_the_sentinel__a_real_digest_type")]
    public void A_Near_Miss_Is_Not_The_Sentinel(UInt16 KeyTag, Byte Algorithm, Byte DigestType)
    {

        // §4 mandates the exact form even though only the algorithm carries the
        // meaning: "the CDS record could be 'CDS X 0 X 0' ... but for clarity,
        // the '0 0 0 0' notation is mandated". A request to turn DNSSEC off for a
        // zone is not the place to be liberal in what one accepts, so anything
        // that is not the mandated record is not the signal.
        var record = new CDS(Child, DNSQueryClasses.IN, Ttl, KeyTag, Algorithm, DigestType, [ 0x00 ]);

        Assert.That(record.IsDeleteSentinel, Is.False);

    }

    #endregion

    #region An_Empty_Or_Longer_Digest_Is_Not_The_Sentinel()

    [TestCase(0,  TestName = "Not_the_sentinel__no_digest_at_all")]
    [TestCase(2,  TestName = "Not_the_sentinel__two_zero_octets")]
    [TestCase(32, TestName = "Not_the_sentinel__a_full_length_zero_digest")]
    public void An_Empty_Or_Longer_Digest_Is_Not_The_Sentinel(Int32 DigestLength)
    {

        // "a single 0" is a length as much as a value. A thirty-two octet digest
        // of zeroes is a SHA-256 digest that happens to be improbable, not a
        // request to delete anything.
        var record = new CDS(Child, DNSQueryClasses.IN, Ttl, 0, 0, 0, new Byte[DigestLength]);

        Assert.That(record.IsDeleteSentinel, Is.False);

    }

    #endregion

    #region A_Cdnskey_Near_Miss_Is_Not_The_Sentinel()

    [TestCase((UInt16) 257, (Byte) 3, (Byte) 0, 1, TestName = "Not_the_CDNSKEY_sentinel__a_flags_value")]
    [TestCase((UInt16)   0, (Byte) 0, (Byte) 0, 1, TestName = "Not_the_CDNSKEY_sentinel__protocol_zeroed_too")]
    [TestCase((UInt16)   0, (Byte) 3, (Byte) 8, 1, TestName = "Not_the_CDNSKEY_sentinel__a_real_algorithm")]
    [TestCase((UInt16)   0, (Byte) 3, (Byte) 0, 0, TestName = "Not_the_CDNSKEY_sentinel__no_key_material")]
    [TestCase((UInt16)   0, (Byte) 3, (Byte) 0, 32, TestName = "Not_the_CDNSKEY_sentinel__a_full_length_zero_key")]
    public void A_Cdnskey_Near_Miss_Is_Not_The_Sentinel(UInt16 Flags, Byte Protocol, Byte Algorithm, Int32 KeyLength)
    {

        // The same near-misses the CDS side gets, and the protocol case is the
        // one that is easy to leave out: RFC 4034 §2.1.2 fixes that field at 3
        // for every DNSKEY, so a record with 0 there is invalid rather than a
        // more thoroughly zeroed sentinel — and recognising it as the delete
        // signal would act on a record no validator may even look at.
        var record = new CDNSKEY(Child, DNSQueryClasses.IN, Ttl, Flags, Protocol, Algorithm, new Byte[KeyLength]);

        Assert.That(record.IsDeleteSentinel, Is.False);

    }

    #endregion

    #region The_Cdnskey_Delete_Signal_Is_One_Record_And_Nothing_Else()

    [Test]
    public void The_Cdnskey_Delete_Signal_Is_One_Record_And_Nothing_Else()
    {

        var sentinel = CDNSKEY.DeleteSentinel(Child);
        var ordinary = new CDNSKEY(Child, DNSQueryClasses.IN, Ttl, 257, 3, 8, new Byte[260]);

        Assert.Multiple(() => {

            Assert.That(CDNSKEY.IsDeleteSignal([ sentinel ]),           Is.True);
            Assert.That(CDNSKEY.IsDeleteSignal([ sentinel, ordinary ]), Is.False);
            Assert.That(CDNSKEY.IsDeleteSignal([ ordinary ]),           Is.False);
            Assert.That(CDNSKEY.IsDeleteSignal([]),                     Is.False);

        });

    }

    #endregion

    #region The_Delete_Signal_Is_One_Record_And_Nothing_Else()

    [Test]
    public void The_Delete_Signal_Is_One_Record_And_Nothing_Else()
    {

        // §4: "MUST contain one RR". A sentinel standing beside an ordinary CDS
        // is a contradiction — install this DS, and also remove them all — and a
        // parent that read whichever record it happened to look at first would
        // resolve that contradiction by accident.
        var sentinel = CDS.DeleteSentinel(Child);
        var ordinary = new CDS(Child, DNSQueryClasses.IN, Ttl, 12345, 8, 2, SHA256.HashData([1, 2, 3]));

        Assert.Multiple(() => {

            Assert.That(CDS.IsDeleteSignal([ sentinel ]),            Is.True);
            Assert.That(CDS.IsDeleteSignal([ sentinel, ordinary ]),  Is.False, "not alongside a real CDS");
            Assert.That(CDS.IsDeleteSignal([ sentinel, sentinel ]),  Is.False, "and not twice over");
            Assert.That(CDS.IsDeleteSignal([ ordinary ]),            Is.False);
            Assert.That(CDS.IsDeleteSignal([]),                      Is.False);

        });

    }

    #endregion

    #endregion


    #region RFC 7344 §4.1 — whether a parent may act on it

    private static (DNSKEY Key, DS Ds) TrustedKeyPair()
    {

        using var rsa = RSA.Create(2048);

        var key = new DNSKEY(
                      Child,
                      DNSQueryClasses.IN,
                      Ttl,
                      257,                       // KSK
                      3,
                      8,
                      DNSSECSigning.EncodePublicKey(8, rsa)
                  );

        return (key, DelegationSignerFor(key));

    }

    /// <summary>
    /// The DS the parent would publish for this key — digest computed here, not taken from Hermod.
    /// </summary>
    private static DS DelegationSignerFor(DNSKEY Key)
    {

        var name   = new RawDnsWriter().Name(Key.DomainName.FullName.ToLowerInvariant()).ToArray();

        var rdata  = new RawDnsWriter().
                         U16(Key.Flags).
                         U8 (Key.Protocol).
                         U8 (Key.Algorithm).
                         Bytes(Key.PublicKey).
                         ToArray();

        return new DS(
                   Child,
                   DNSQueryClasses.IN,
                   Ttl,
                   DNSSECValidator.ComputeKeyTag(Key),
                   Key.Algorithm,
                   2,
                   SHA256.HashData([.. name, .. rdata])
               );

    }

    private static RRSIG SignatureBy(DNSKEY Key)

        => new (Child,
                DNSQueryClasses.IN,
                Ttl,
                DNSResourceRecordTypes.CDS,
                Key.Algorithm,
                2,
                3600,
                (UInt32) DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds(),
                (UInt32) DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds(),
                DNSSECValidator.ComputeKeyTag(Key),
                Child,
                [1, 2, 3]);


    #region A_Sentinel_Signed_By_A_Trusted_Key_Is_Accepted()

    [Test]
    [Property("RFC", "7344 §4.1")]
    public void A_Sentinel_Signed_By_A_Trusted_Key_Is_Accepted()
    {

        var (key, ds) = TrustedKeyPair();

        Assert.That(
            CDSAcceptance.Evaluate(Child, [ CDS.DeleteSentinel(Child) ], [ SignatureBy(key) ], [ key ], [ ds ]),
            Is.EqualTo(CDSAcceptanceResult.AcceptedAsDelete)
        );

    }

    #endregion

    #region A_Cds_Signed_By_A_Key_The_Parent_Does_Not_Know_Is_Ignored()

    [Test]
    [Property("RFC", "7344 §4.1")]
    public void A_Cds_Signed_By_A_Key_The_Parent_Does_Not_Know_Is_Ignored()
    {

        // §4.1: "MUST be signed with a key that is represented in both the
        // current DNSKEY and DS RRsets." Both — and that is the load-bearing
        // word. A key in the DNSKEY RRset alone proves only that whoever
        // published the zone published it, which an attacker who has taken the
        // zone over has also done. The parent's DS RRset is the part they cannot
        // have written.
        var (trusted, trustedDS) = TrustedKeyPair();
        var (intruder, _)        = TrustedKeyPair();     // in the zone, not in the DS

        var result = CDSAcceptance.Evaluate(
                         Child,
                         [ CDS.DeleteSentinel(Child) ],
                         [ SignatureBy(intruder) ],
                         [ trusted, intruder ],
                         [ trustedDS ]
                     );

        Assert.That(result, Is.EqualTo(CDSAcceptanceResult.NotSignedByATrustedKey),
                    "publishing a key in the child zone must not be enough to delete the delegation");

    }

    #endregion

    #region An_Unsigned_Cds_Is_Ignored()

    [Test]
    [Property("RFC", "7344 §4.1")]
    public void An_Unsigned_Cds_Is_Ignored()
    {

        var (key, ds) = TrustedKeyPair();

        Assert.That(
            CDSAcceptance.Evaluate(Child, [ CDS.DeleteSentinel(Child) ], [], [ key ], [ ds ]),
            Is.EqualTo(CDSAcceptanceResult.NotSignedByATrustedKey)
        );

    }

    #endregion

    #region A_Cds_Below_The_Apex_Is_Ignored()

    [Test]
    [Property("RFC", "7344 §4.1")]
    public void A_Cds_Below_The_Apex_Is_Ignored()
    {

        // §4.1: "MUST be at the Child zone apex." Otherwise any subdomain could
        // speak for the zone's delegation.
        var (key, ds) = TrustedKeyPair();

        var belowApex = CDS.DeleteSentinel(DomainName.Parse("sub.child.example."));

        Assert.That(
            CDSAcceptance.Evaluate(Child, [ belowApex ], [ SignatureBy(key) ], [ key ], [ ds ]),
            Is.EqualTo(CDSAcceptanceResult.NotAtApex)
        );

    }

    #endregion

    #region A_Sentinel_Mixed_With_Real_Records_Is_Refused()

    [Test]
    [Property("RFC", "8078 §4")]
    public void A_Sentinel_Mixed_With_Real_Records_Is_Refused()
    {

        var (key, ds) = TrustedKeyPair();

        var mixed     = new CDS[] {
                            CDS.DeleteSentinel(Child),
                            new (Child, DNSQueryClasses.IN, Ttl, 12345, 8, 2, SHA256.HashData([1, 2, 3]))
                        };

        Assert.That(
            CDSAcceptance.Evaluate(Child, mixed, [ SignatureBy(key) ], [ key ], [ ds ]),
            Is.EqualTo(CDSAcceptanceResult.InconsistentDeleteSignal)
        );

    }

    #endregion

    #region A_Cds_Naming_Only_Unusable_Algorithms_Would_Break_The_Delegation()

    [Test]
    [Property("RFC", "7344 §4.1")]
    public void A_Cds_Naming_Only_Unusable_Algorithms_Would_Break_The_Delegation()
    {

        // §4.1: "MUST NOT break the current delegation if applied to DS RRset."
        // A DS nobody can follow leaves the zone looking signed and being
        // unverifiable, which is worse than either signed or unsigned — a
        // validator answers SERVFAIL rather than resolving.
        var (key, ds) = TrustedKeyPair();

        // Digest type 3 is GOST R 34.11-94 (RFC 5933), deprecated by RFC 8624 and
        // absent from this build.
        var unusable  = new CDS(Child, DNSQueryClasses.IN, Ttl, 12345, 8, 3, new Byte[32]);

        Assert.That(
            CDSAcceptance.Evaluate(Child, [ unusable ], [ SignatureBy(key) ], [ key ], [ ds ]),
            Is.EqualTo(CDSAcceptanceResult.WouldBreakTheDelegation)
        );

    }

    #endregion

    #region An_Ordinary_Cds_Rollover_Is_Accepted()

    [Test]
    [Property("RFC", "7344 §4.1")]
    public void An_Ordinary_Cds_Rollover_Is_Accepted()
    {

        // The control: everything above returns a refusal, so at least one case
        // has to come back Accepted or the rules would be satisfied by a function
        // that always says no.
        var (key, ds) = TrustedKeyPair();

        var rollover  = new CDS(Child, DNSQueryClasses.IN, Ttl, 54321, 13, 2, SHA256.HashData([4, 5, 6]));

        Assert.That(
            CDSAcceptance.Evaluate(Child, [ rollover ], [ SignatureBy(key) ], [ key ], [ ds ]),
            Is.EqualTo(CDSAcceptanceResult.Accepted)
        );

    }

    #endregion

    #endregion


    #region RFC 6840 §5.2 — a delegation this validator cannot follow

    #region A_Ds_Rrset_With_No_Usable_Algorithm_Leaves_The_Zone_Unsigned()

    [Test]
    [Property("RFC", "6840 §5.2")]
    [Property("RFC", "8078 §4")]
    public void A_Ds_Rrset_With_No_Usable_Algorithm_Leaves_The_Zone_Unsigned()
    {

        // RFC 6840 §5.2: "a validator disregards any authenticated DS records
        // that specify unknown or unsupported DNSKEY algorithms. If none are
        // left, the zone is treated as if it were unsigned" — and the same
        // section extends that to unsupported digest algorithms.
        //
        // Unsigned, not broken. Reporting Bogus instead turns "I cannot check
        // this" into "this is forged", which fails the name for every client
        // behind the validator over a zone that is very likely fine and merely
        // newer than the code reading it. RFC 8078 §4 restates it for algorithm
        // 0 in particular: "the zone is treated as unsigned unless there are
        // other algorithms present".
        var digest = SHA256.HashData([1, 2, 3]);

        Assert.Multiple(() => {

            Assert.That(DNSSECValidator.HasUsableDelegationSigner([
                            new DS(Child, DNSQueryClasses.IN, Ttl, 1, 0, 2, digest)      // algorithm 0
                        ]), Is.False, "algorithm 0 is never a signature algorithm (RFC 8078 §4)");

            Assert.That(DNSSECValidator.HasUsableDelegationSigner([
                            new DS(Child, DNSQueryClasses.IN, Ttl, 1, 8, 3, digest)      // GOST digest
                        ]), Is.False, "an unsupported digest algorithm counts the same way (RFC 6840 §5.2)");

            Assert.That(DNSSECValidator.HasUsableDelegationSigner([
                            new DS(Child, DNSQueryClasses.IN, Ttl, 1, 99, 2, digest)     // unassigned
                        ]), Is.False);

            // And one usable record among unusable ones is enough — §5.2 says to
            // disregard the others, not to fail on them.
            Assert.That(DNSSECValidator.HasUsableDelegationSigner([
                            new DS(Child, DNSQueryClasses.IN, Ttl, 1, 0,  2, digest),
                            new DS(Child, DNSQueryClasses.IN, Ttl, 2, 99, 2, digest),
                            new DS(Child, DNSQueryClasses.IN, Ttl, 3, 8,  2, digest)
                        ]), Is.True);

            Assert.That(DNSSECValidator.HasUsableDelegationSigner([]), Is.False);

        });

    }

    #endregion

    #region Every_Algorithm_This_Build_Verifies_Is_Followable()

    [TestCase((Byte)  5, TestName = "Followable__RSA_SHA1")]
    [TestCase((Byte)  7, TestName = "Followable__RSA_SHA1_NSEC3")]
    [TestCase((Byte)  8, TestName = "Followable__RSA_SHA256")]
    [TestCase((Byte) 10, TestName = "Followable__RSA_SHA512")]
    [TestCase((Byte) 13, TestName = "Followable__ECDSA_P256")]
    [TestCase((Byte) 14, TestName = "Followable__ECDSA_P384")]
    [TestCase((Byte) 15, TestName = "Followable__Ed25519")]
    [TestCase((Byte) 16, TestName = "Followable__Ed448")]
    [Property("RFC", "6840 §5.2")]
    public void Every_Algorithm_This_Build_Verifies_Is_Followable(Byte Algorithm)
    {

        // The two lists have to agree. An algorithm this build can verify but
        // considers unfollowable would make every delegation using it look
        // unsigned — silently downgrading zones the validator was perfectly able
        // to check.
        Assert.That(DNSSECValidator.IsUsableDelegationSigner(Algorithm, 2), Is.True);

    }

    #endregion

    #region Malformed_Key_Material_Fails_Rather_Than_Throws()

    [TestCase((Byte)  5, TestName = "Malformed_key__RSA_SHA1")]
    [TestCase((Byte)  7, TestName = "Malformed_key__RSA_SHA1_NSEC3")]
    [TestCase((Byte)  8, TestName = "Malformed_key__RSA_SHA256")]
    [TestCase((Byte) 10, TestName = "Malformed_key__RSA_SHA512")]
    [TestCase((Byte) 13, TestName = "Malformed_key__ECDSA_P256")]
    [TestCase((Byte) 14, TestName = "Malformed_key__ECDSA_P384")]
    [TestCase((Byte) 15, TestName = "Malformed_key__Ed25519")]
    [TestCase((Byte) 16, TestName = "Malformed_key__Ed448")]
    [Property("RFC", "4035 §5.3.3")]
    public void Malformed_Key_Material_Fails_Rather_Than_Throws(Byte Algorithm)
    {

        // A DNSKEY comes off the wire, so its contents are whatever the far side
        // chose to send. Every shape below is one a broken or hostile zone can
        // publish: a key too short to hold its own length prefix, a length prefix
        // that runs past the end, a point that is not on the curve.
        //
        // The answer to all of them is "this key does not verify this signature".
        // It has to be an answer rather than an exception, because the caller
        // turns a throw into Indeterminate — which RFC 4033 §5 defines as "no
        // trust anchor covers this portion of the tree", not "the key was
        // broken". A zone that claims to be signed and presents an unusable key
        // has not become a zone nobody has an opinion about.
        Byte[][] malformed = [
            [],
            [ 0x01 ],
            [ 0x00, 0xFF, 0xFF, 0x01 ],      // three-octet exponent length claiming 65535
            [ 0x03, 0x01, 0x00, 0x01 ],      // exponent present, modulus missing
            new Byte[7],
            new Byte[33],
            [.. Enumerable.Repeat((Byte) 0xFF, 64) ]
        ];

        Assert.Multiple(() => {

            foreach (var publicKey in malformed)
            {

                var verified = true;

                Assert.That(
                    () => verified = DNSSECValidator.VerifySignature(Algorithm, publicKey, [1, 2, 3], new Byte[64]),
                    Throws.Nothing,
                    () => $"algorithm {Algorithm} threw on a {publicKey.Length}-octet key instead of refusing it"
                );

                Assert.That(verified, Is.False,
                            () => $"algorithm {Algorithm} accepted a {publicKey.Length}-octet key");

            }

        });

    }

    #endregion

    #endregion

}

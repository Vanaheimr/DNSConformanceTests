using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4035 §4.3 — the four answers a validator may give: Secure, Insecure,
/// Bogus and Indeterminate.
///
/// Everything below the entry point is already covered elsewhere (key tags, DS
/// digests, RRSIG verification). What is exercised here is the composition:
/// ValidateAsync deciding *which* verdict a response earns. That is where
/// validators historically go wrong — a failure to reach a key is not the same
/// as a bad signature, and neither is the same as an unsigned zone.
///
/// The resolver is stubbed, so these run offline and deterministically.
/// </summary>
[TestFixture]
[Property("RFC", "4035 §4.3")]
public class ChainValidationTests
{

    private SignedZoneFixture zone = null!;

    [OneTimeSetUp]
    public void LoadFixture()
    {

        if (!SignedZoneFixture.IsAvailable)
            Assert.Ignore("BIND-signed fixture zone missing — regenerate with: wsl -e sh fixtures/zones/resign.sh");

        zone = SignedZoneFixture.Load();

    }


    #region Helpers

    private static readonly DNSServerConfig Origin = new(IPv4Address.Localhost, IPPort.DNS);

    /// <summary>
    /// A response carrying the given records in its answer section.
    /// </summary>
    private static DNSInfo ResponseWith(params IDNSResourceRecord[] Answers)

        => new(
               Origin,
               0,
               true, false, true, false,
               DNSResponseCodes.NoError,
               Answers,
               [],
               [],
               true,
               false,
               TimeSpan.FromSeconds(5),
               TimeSpan.Zero
           );


    /// <summary>
    /// The same RRSIG with a different validity window.
    /// </summary>
    private static RRSIG Rewindow(RRSIG Signature, UInt32 Inception, UInt32 Expiration)

        => new(
               DomainName.Parse(Signature.DomainName.FullName.TrimEnd('.')),
               Signature.Class,
               Signature.TimeToLive,
               Signature.TypeCovered,
               Signature.Algorithm,
               Signature.Labels,
               Signature.OriginalTTL,
               Expiration,
               Inception,
               Signature.KeyTag,
               DomainName.Parse(Signature.SignerName.FullName.TrimEnd('.')),
               Signature.Signature
           );


    /// <summary>
    /// The same RRSIG under a different algorithm number. Everything else about
    /// it — the signed data it covers, the octets of the signature — is
    /// untouched, so the number is the only thing that can change the answer.
    /// </summary>
    private static RRSIG Reassign(RRSIG Signature, Byte Algorithm)

        => new(
               DomainName.Parse(Signature.DomainName.FullName.TrimEnd('.')),
               Signature.Class,
               Signature.TimeToLive,
               Signature.TypeCovered,
               Algorithm,
               Signature.Labels,
               Signature.OriginalTTL,
               Signature.SignatureExpiration,
               Signature.SignatureInception,
               Signature.KeyTag,
               DomainName.Parse(Signature.SignerName.FullName.TrimEnd('.')),
               Signature.Signature
           );


    private static UInt32 Now
        => (UInt32) DateTimeOffset.UtcNow.ToUnixTimeSeconds();


    /// <summary>
    /// The signed A RRset of the fixture zone, plus its signature.
    /// </summary>
    private (List<IDNSResourceRecord> RRset, RRSIG Signature) SignedA()
    {

        var rrset      = zone.RRset("a.dnssec.test", DNSResourceRecordTypes.A);
        var signature  = zone.SignatureFor("a.dnssec.test", DNSResourceRecordTypes.A);

        Assert.That(rrset,     Is.Not.Empty);
        Assert.That(signature, Is.Not.Null);

        return (rrset, signature!);

    }


    /// <summary>
    /// A stub resolver that serves the fixture zone's DNSKEY RRset, with the
    /// signature over it.
    /// </summary>
    private StubDnsClient ResolverServingKeys()
        => new StubDnsClient().Answer(
               "dnssec.test",
               DNSResourceRecordTypes.DNSKEY,
               zone.KeySetAnswer
           );

    private static RRSIG Sign(IEnumerable<IDNSResourceRecord> RRset, DNSSECSigningKey Key)
        => DNSSECZoneSigner.SignRRSet(RRset, Key, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(14));

    /// <summary>
    /// A stub resolver that serves the fixture zone's keys, and above it a parent
    /// <c>test.</c> that publishes the given DS RRset for the fixture — signed,
    /// with a key set of its own that is signed too. The parent's key is the
    /// anchor to use.
    /// </summary>
    /// <remarks>
    /// RFC 6840 §5.2 disregards "authenticated DS records" with an algorithm
    /// nobody can follow, and a DS RRset is authenticated by its parent's
    /// signature (RFC 4035 §5.2). The parent is generated here for that, and
    /// anchored, so that the DS RRset under test is the only thing in the chain
    /// a verdict can turn on.
    /// </remarks>
    private StubDnsClient ResolverWithSignedParent(DNSSECSigningKey Parent, params DS[] DelegationSigners)
    {

        IDNSResourceRecord[] ds         = [.. DelegationSigners];
        IDNSResourceRecord[] parentKeys = [ Parent.DNSKEY ];

        return new StubDnsClient().
                   Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, zone.KeySetAnswer).
                   Answer("dnssec.test", DNSResourceRecordTypes.DS,     [ .. ds,         Sign(ds,         Parent) ]).
                   Answer("test",        DNSResourceRecordTypes.DNSKEY, [ .. parentKeys, Sign(parentKeys, Parent) ]);

    }


    /// <summary>
    /// A stub resolver that serves one zone made here: its DNSKEY RRset, signed
    /// by its own key — the shape of a zone whose key is the trust anchor.
    /// </summary>
    private static StubDnsClient ResolverServingZone(DNSSECSigningKey Zone)
    {

        IDNSResourceRecord[] keys = [ Zone.DNSKEY ];

        return new StubDnsClient().
                   Answer(Zone.DNSKEY.DomainName.FullName, DNSResourceRecordTypes.DNSKEY, [ .. keys, Sign(keys, Zone) ]);

    }


    /// <summary>
    /// RFC 4034 §4.1.2 — the types present at a delegation without DS: NS (2),
    /// and the RRSIG (46) and NSEC (47) of the denial itself. One window, six
    /// octets, bit <c>i</c> of the block standing for type <c>i</c> with bit 0 the
    /// most significant. Written out here rather than asked of Hermod's encoder.
    /// </summary>
    private static Byte[] DelegationTypeBitMap
        => [0x00, 0x06,                                   // window 0, six octets follow
            0x20, 0x00, 0x00, 0x00, 0x00, 0x03];          // NS … RRSIG|NSEC


    /// <summary>
    /// The authority section of the parent's answer to a DS query for an unsigned
    /// delegation, RFC 4035 §5.4 and §3.1.4.1: an NSEC at the delegation point with
    /// the NS bit and neither DS nor SOA, signed by the parent.
    /// </summary>
    private static IDNSResourceRecord[] ProofOfAnUnsignedDelegation(String            Delegation,
                                                                    String            NextName,
                                                                    DNSSECSigningKey  Parent)
    {

        IDNSResourceRecord[] nsec = [ new NSEC(DomainName.Parse(Delegation),
                                               DNSQueryClasses.IN,
                                               TimeSpan.FromHours(1),
                                               DomainName.Parse(NextName),
                                               DelegationTypeBitMap) ];

        return [ .. nsec, Sign(nsec, Parent) ];

    }

    #endregion


    #region Signed_Answer_Under_A_Configured_Anchor_Is_Secure()

    [Test]
    public async Task Signed_Answer_Under_A_Configured_Anchor_Is_Secure()
    {

        // The full path: RRSIG verifies, the signing key is published, and the
        // zone's KSK matches the DS the parent would publish — which here is the
        // configured trust anchor. That is the definition of Secure.
        var (rrset, signature) = SignedA();

        var validator = new DNSSECValidator(ResolverServingKeys(), [zone.DelegationSigner]);

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure));

    }

    #endregion

    #region Answer_Without_Any_Rrsig_Is_Insecure()

    /// <summary>
    /// Finding 72. The name says what this test used to assert, and the name is
    /// kept because FINDINGS.md cites it; what it asserts now is the opposite.
    /// </summary>
    /// <remarks>
    /// <para>
    /// It used to say that no signatures at all is "an ordinary answer from an
    /// unsigned zone", and Insecure. That is true of an unsigned zone — and this
    /// is not one. The trust anchor here is the fixture zone's own key: the
    /// resolver knows <c>dnssec.test</c> is signed, and an A RRset at
    /// <c>a.dnssec.test</c> arriving without its RRSIG is what stripping the
    /// signature produces. RFC 4035 §4.3 calls Insecure "an RRset for which the
    /// resolver knows that it has no chain of signed DNSKEY and DS RRs from any
    /// trusted starting point to the RRset", and Bogus one "for which the resolver
    /// believes that it ought to be able to establish a chain of trust but for
    /// which it is unable to do so … due to missing data that the relevant DNSSEC
    /// RRs indicate should be present". The anchor indicates it.
    /// </para>
    /// <para>
    /// The unsigned internet is not broken by this. An unsigned zone below an
    /// anchor is Insecure once the delegation to it is proven unsigned —
    /// <see cref="An_Unsigned_Answer_Below_A_Proven_Unsigned_Delegation_Is_Insecure"/>
    /// — and an unsigned zone outside every anchor stays Insecure without any
    /// proof at all.
    /// </para>
    /// </remarks>
    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "4035 §4.3")]
    public async Task Answer_Without_Any_Rrsig_Is_Insecure()
    {

        var (rrset, _) = SignedA();

        var validator  = new DNSSECValidator(ResolverServingKeys(), [zone.DelegationSigner]);

        var result     = await validator.ValidateAsync(ResponseWith([.. rrset]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "an RRset of a zone the resolver holds an anchor for, with its signature taken away");

    }

    #endregion

    #region An_Unsigned_Answer_Below_A_Proven_Unsigned_Delegation_Is_Insecure()

    /// <summary>
    /// Finding 72, the other direction. RFC 4035 §5.2: a resolver that finds no DS
    /// for a delegation learns from the parent's authenticated denial that the
    /// child zone is unsigned, and the data below it is Insecure.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>p.test.</c> is anchored and signed with a key made here. It delegates
    /// <c>u.p.test.</c> without a DS, and says so the way RFC 4035 §5.4 lets it: its
    /// signed NSEC at <c>u.p.test.</c> has the NS bit and neither DS nor SOA. Below
    /// that delegation an unsigned A RRset at <c>www.u.p.test.</c> is exactly what
    /// an unsigned zone sends, and the verdict must not depend on whether the
    /// caller said what it asked.
    /// </para>
    /// <para>
    /// It did. Without a question the answer was Insecure — as was every unsigned
    /// answer, stripped or not. With the question it was Bogus — as was every
    /// unsigned answer under an anchor, proven unsigned or not, which under the
    /// root's anchor is every unsigned zone on the internet.
    /// </para>
    /// </remarks>
    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "4035 §5.2")]
    public async Task An_Unsigned_Answer_Below_A_Proven_Unsigned_Delegation_Is_Insecure()
    {

        using var parent = DNSSECSigningKey.Generate(DomainName.Parse("p.test"), 13, KeySigningKey: true);

        var name      = DomainName.Parse("www.u.p.test");

        var resolver  = ResolverServingZone(parent).
                            Authority("u.p.test", DNSResourceRecordTypes.DS,
                                      ProofOfAnUnsignedDelegation("u.p.test", "v.p.test", parent));

        var validator = new DNSSECValidator(resolver, [ parent.DelegationSigner() ]);

        var response  = ResponseWith(new A(name, DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.80")));

        Assert.Multiple(async () => {

            Assert.That(await validator.ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Insecure),
                        "below a delegation the parent proves unsigned, nothing is owed a signature");

            Assert.That(await validator.ValidateAsync(response, (name, DNSResourceRecordTypes.A)),
                        Is.EqualTo(DNSSECValidationResult.Insecure),
                        "and knowing the question changes nothing about that");

        });

    }

    #endregion

    #region An_Unsigned_Answer_Inside_An_Anchored_Zone_Is_Bogus_Either_Way()

    /// <summary>
    /// Finding 72, the control for the test above: the same zone and key, and an
    /// unsigned A RRset at a name that lies in <c>p.test.</c> itself. Nothing proves
    /// a delegation on the way, so the RRset belongs to a zone the anchor says is
    /// signed, and its missing signature is missing data.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "4035 §4.3")]
    public async Task An_Unsigned_Answer_Inside_An_Anchored_Zone_Is_Bogus_Either_Way()
    {

        using var parent = DNSSECSigningKey.Generate(DomainName.Parse("p.test"), 13, KeySigningKey: true);

        var name      = DomainName.Parse("www.p.test");

        var validator = new DNSSECValidator(ResolverServingZone(parent), [ parent.DelegationSigner() ]);

        var response  = ResponseWith(new A(name, DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.80")));

        Assert.Multiple(async () => {

            Assert.That(await validator.ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "an answer from a signed zone, with its signature taken away");

            Assert.That(await validator.ValidateAsync(response, (name, DNSResourceRecordTypes.A)),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "whether or not the caller says what it asked");

        });

    }

    #endregion

    #region Expired_Signature_Is_Bogus()

    [Test]
    [Property("RFC", "4034 §3.1.5")]
    public async Task Expired_Signature_Is_Bogus()
    {

        // RFC 4034 §3.1.5: the signature is not valid after the expiration date.
        //
        // What this case actually demonstrates is narrower than it looks, and the
        // mutation sweep is what said so. Rewriting the window rewrites the RRSIG
        // RDATA, and §3.1.8 puts that RDATA into the signed data — so the
        // signature no longer verifies either, and a validator that had stopped
        // checking the clock altogether would still call this Bogus for the other
        // reason. The case below it moves the clock instead and leaves the record
        // alone, which is the one that pins the check.
        var (rrset, signature) = SignedA();

        var expired   = Rewindow(signature, Now - 7200, Now - 3600);

        var validator = new DNSSECValidator(ResolverServingKeys(), [zone.DelegationSigner]);

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, expired]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "a signature past its expiration must not validate");

    }

    #endregion

    #region A_Signature_That_Still_Verifies_But_Has_Expired_Is_Bogus()

    /// <summary>
    /// The same rule, with nothing touched but the clock. The fixture's signature
    /// is left exactly as BIND made it — it verifies, and it goes on verifying
    /// forever, because a signature does not know what time it is. Only the
    /// window says the answer is stale.
    ///
    /// That is the whole point of RFC 4034 §3.1.5: the expiration is not a
    /// property of the cryptography, it is a separate check, and a validator that
    /// skipped it would accept a replayed answer from a zone that has since
    /// changed its mind. A test that edits the record cannot see the difference,
    /// because editing the record breaks the signature too.
    /// </summary>
    [Test]
    [Property("RFC", "4034 §3.1.5")]
    public async Task A_Signature_That_Still_Verifies_But_Has_Expired_Is_Bogus()
    {

        var (rrset, signature) = SignedA();

        Assert.That(signature.SignatureExpiration, Is.GreaterThan(Now),
                    "the fixture has to be fresh for this to mean anything — " +
                    "re-sign it with fixtures/zones/resign.sh");

        // Far enough past the fixture's own expiry that no clock skew matters.
        var pastExpiry = TimeSpan.FromSeconds(signature.SignatureExpiration - Now) + TimeSpan.FromHours(1);

        Timestamp.TravelForwardInTime(pastExpiry);

        try
        {

            var validator = new DNSSECValidator(ResolverServingKeys(), [zone.DelegationSigner]);
            var result    = await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

            Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                        "the signature still verifies; the clock is the only thing that says no");

        }
        finally
        {
            Timestamp.Reset();
        }

    }

    #endregion

    #region A_Signature_Whose_Algorithm_May_Not_Be_Used_Is_Not_Secure()

    /// <summary>
    /// RFC 8624 §3.1 marks RSAMD5 (1), DSA (3) and DSA-NSEC3-SHA1 (6) **MUST
    /// NOT** in its DNSSEC Validation column. <c>SignatureAlgorithmMatrixTests</c>
    /// pins that at the verifier; this pins what it means for the answer.
    ///
    /// <para>
    /// The signature here is BIND's own, over BIND's own RRset, relabelled as
    /// algorithm 1 and offered with a key that claims the same number. Under
    /// algorithm 8 it verifies. The verdict must not be Secure, and no amount of
    /// the cryptography being fine may make it so — which is the case worth
    /// pinning, because a validator that reached for "does this verify" before
    /// "am I allowed to use this" would answer Secure with a clear conscience.
    /// </para>
    ///
    /// <para>
    /// <b>Which</b> not-Secure verdict is a question the RFCs leave open, and the
    /// assertion is deliberately loose because of it. Hermod answers Bogus, by way
    /// of <c>ValidateRRSig</c> returning Bogus for "did not verify". There is a
    /// reading that says Insecure: RFC 6840 §5.2 requires a DS of an unusable
    /// algorithm to be disregarded and the delegation treated as unsigned, RFC
    /// 8624's own introduction says "the effect of using an unknown DNSKEY
    /// algorithm is that the zone is treated as insecure", and Hermod already
    /// applies that reasoning one layer down in <c>HasUsableDelegationSigner</c>.
    /// Neither RFC states the rule for an RRSIG, so this asserts only the half
    /// that is not in doubt.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "8624 §3.1")]
    public void A_Signature_Whose_Algorithm_May_Not_Be_Used_Is_Not_Secure()
    {

        var (rrset, signature) = SignedA();

        var signing    = zone.KeyFor(signature)!;

        var forbidden  = Reassign(signature, 1);

        var claiming   = new DNSKEY(DomainName.Parse("dnssec.test"),
                                    signing.Class,
                                    signing.TimeToLive,
                                    signing.Flags,
                                    signing.Protocol,
                                    1,
                                    signing.PublicKey);

        var validator  = new DNSSECValidator(new StubDnsClient());

        Assert.Multiple(() => {

            Assert.That(validator.ValidateRRSig(rrset, signature, signing),
                        Is.EqualTo(DNSSECValidationResult.Secure),
                        "the control: the same records and the same octets, under the number they were made with");

            Assert.That(validator.ValidateRRSig(rrset, forbidden, claiming),
                        Is.Not.EqualTo(DNSSECValidationResult.Secure),
                        "and under a number RFC 8624 §3.1 forbids, the same signature earns nothing");

        });

    }

    #endregion

    #region A_Negative_Answer_Is_Only_Checked_Against_What_Was_Asked()

    /// <summary>
    /// The answer section of a negative response is empty by definition, so the
    /// validator has to decide, before it has seen a signature, whether to look
    /// in the authority section instead. Two things have to hold: a proof has to
    /// be there, and the question has to be known — because a proof is a
    /// statement about one name and one type, and there is nothing to check it
    /// against otherwise.
    ///
    /// <para>
    /// Either condition alone is not enough, and the two ways of getting that
    /// wrong fail differently. Without a question, the denial path has no name to
    /// verify and the records prove nothing that can be checked. Without records,
    /// there is no proof to check at all, and the answer is unsigned or stripped
    /// depending on the anchors — which is the decision one branch further down,
    /// not this one.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4035 §5.4")]
    public async Task A_Negative_Answer_Is_Only_Checked_Against_What_Was_Asked()
    {

        var validator = new DNSSECValidator(new StubDnsClient());

        var withProof = new DNSInfo(Origin, 0, true, false, true, false,
                                    DNSResponseCodes.NameError,
                                    [],
                                    [new NSEC(DomainName.Parse("b.example."),
                                              DNSQueryClasses.IN,
                                              TimeSpan.FromHours(1),
                                              DomainName.Parse("d.example."),
                                              [])],
                                    [],
                                    true, false, TimeSpan.FromSeconds(5), TimeSpan.Zero);

        var noProof   = new DNSInfo(Origin, 0, true, false, true, false,
                                    DNSResponseCodes.NameError,
                                    [], [], [],
                                    true, false, TimeSpan.FromSeconds(5), TimeSpan.Zero);

        Assert.Multiple(async () => {

            Assert.That(await validator.ValidateAsync(withProof, Question: null),
                        Is.EqualTo(DNSSECValidationResult.Insecure),
                        "records that deny a name nobody named cannot be checked against anything");

            Assert.That(await validator.ValidateAsync(noProof,
                                                      (DomainName.Parse("c.example."), DNSResourceRecordTypes.A)),
                        Is.EqualTo(DNSSECValidationResult.Insecure),
                        "and a question with no proof beside it is an unsigned zone, not a broken one");

        });

    }

    #endregion

    #region A_Signature_Covers_One_Rrset_And_Not_Every_Record_Of_Its_Type()

    /// <summary>
    /// RFC 4034 §3: an RRSIG covers "the RRset" — one owner name and one type
    /// together. Gathering by type alone folds every record of that type in the
    /// message into the signed data, and the signature then fails over octets its
    /// signer never saw.
    ///
    /// <para>
    /// The consequence is not a theoretical one. An attacker who can add a record
    /// to an answer cannot forge a signature, but under that reading they would
    /// not need to: adding one unsigned A record beside a signed one would make
    /// the genuine answer fail to validate, which is a denial of service against
    /// every signed name.
    /// </para>
    ///
    /// <para>
    /// The other record is the zone's own A RRset at <c>mail.dnssec.test</c>, with
    /// BIND's signature over it. It used to be an unsigned A record at a name the
    /// zone does not have, on the reasoning that the validator checked the
    /// signatures it was given rather than demanding one per RRset. Since Hermod
    /// #148 it demands one — an answer with an unsigned RRset in it is Insecure —
    /// and an unsigned intruder would decide the verdict for that reason instead of
    /// this one.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4034 §3")]
    public async Task A_Signature_Covers_One_Rrset_And_Not_Every_Record_Of_Its_Type()
    {

        var (rrset, signature) = SignedA();

        var other     = zone.RRset("mail.dnssec.test", DNSResourceRecordTypes.A);
        var otherSig  = zone.SignatureFor("mail.dnssec.test", DNSResourceRecordTypes.A)!;

        Assert.That(other, Is.Not.Empty, "the fixture has an A RRset at mail.dnssec.test");

        var validator = new DNSSECValidator(ResolverServingKeys(), [zone.DelegationSigner]);

        Assert.That(await validator.ValidateAsync(ResponseWith([.. rrset, .. other, signature, otherSig])),
                    Is.EqualTo(DNSSECValidationResult.Secure),
                    "another name's record of the same type is not part of this RRset");

    }

    #endregion

    #region The_Validity_Window_Includes_Both_Of_Its_Own_Seconds()

    /// <summary>
    /// RFC 4034 §3.1.5: "The RRSIG record is valid from the Signature Inception
    /// field's value until the Signature Expiration field's value" — from and
    /// until, so both named seconds are inside the window and the ones either
    /// side of them are not.
    ///
    /// Four assertions for four ways to be wrong by one second, which is what a
    /// validator is wrong by when it uses the wrong comparison. None of them can
    /// be written against a clock that keeps moving: the second in question lasts
    /// a second, and a test that has to reach it before it passes is a test that
    /// fails now and then for no reason. Saying when "now" is makes all four
    /// exact — the same seam <c>TSIGSigner.Verify</c> and <c>SIG0Signer.Verify</c>
    /// have carried all along.
    /// </summary>
    [Test]
    [Property("RFC", "4034 §3.1.5")]
    public async Task The_Validity_Window_Includes_Both_Of_Its_Own_Seconds()
    {

        var (rrset, signature) = SignedA();

        var validator  = new DNSSECValidator(ResolverServingKeys(), [zone.DelegationSigner]);
        var response   = ResponseWith([.. rrset, signature]);

        var inception  = DateTimeOffset.FromUnixTimeSeconds(signature.SignatureInception);
        var expiration = DateTimeOffset.FromUnixTimeSeconds(signature.SignatureExpiration);

        Assert.Multiple(async () => {

            Assert.That(await validator.ValidateAsync(response, inception),
                        Is.EqualTo(DNSSECValidationResult.Secure),
                        "the inception second is inside the window");

            Assert.That(await validator.ValidateAsync(response, expiration),
                        Is.EqualTo(DNSSECValidationResult.Secure),
                        "and so is the expiration second");

            Assert.That(await validator.ValidateAsync(response, inception.AddSeconds(-1)),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "the second before the inception is not");

            Assert.That(await validator.ValidateAsync(response, expiration.AddSeconds(1)),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "nor the second after the expiration");

        });

    }

    #endregion

    #region Not_Yet_Valid_Signature_Is_Bogus()

    [Test]
    [Property("RFC", "4034 §3.1.5")]
    public async Task Not_Yet_Valid_Signature_Is_Bogus()
    {

        var (rrset, signature) = SignedA();

        var future    = Rewindow(signature, Now + 3600, Now + 7200);

        var validator = new DNSSECValidator(ResolverServingKeys(), [zone.DelegationSigner]);

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, future]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "a signature whose inception is in the future must not validate");

    }

    #endregion

    #region Missing_Signing_Key_Is_Bogus()

    [Test]
    public async Task Missing_Signing_Key_Is_Bogus()
    {

        // The zone answers the DNSKEY query, but none of the keys matches the
        // RRSIG's key tag. The signature can never be checked, and a response that
        // claims to be signed by a key the zone does not publish is not merely
        // unverifiable — it is wrong.
        var (rrset, signature) = SignedA();

        var resolver  = new StubDnsClient().Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY);

        var validator = new DNSSECValidator(resolver, [zone.DelegationSigner]);

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus));

    }

    #endregion

    #region Tampered_Rdata_Is_Bogus()

    [Test]
    [Property("RFC", "4035 §5.3.3")]
    public async Task Tampered_Rdata_Is_Bogus()
    {

        var (_, signature) = SignedA();

        // Same owner, same type, same signature — one different address octet.
        var tampered  = new A(
                            DomainName.Parse("a.dnssec.test"),
                            DNSQueryClasses.IN,
                            TimeSpan.FromSeconds(signature.OriginalTTL),
                            IPv4Address.Parse("192.0.2.66")
                        );

        var validator = new DNSSECValidator(ResolverServingKeys(), [zone.DelegationSigner]);

        var result    = await validator.ValidateAsync(ResponseWith(tampered, signature));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus));

    }

    #endregion

    #region Unreachable_Resolver_Is_Indeterminate()

    [Test]
    public async Task Unreachable_Resolver_Is_Indeterminate()
    {

        // Being unable to fetch the DNSKEY is not evidence of forgery. RFC 4035
        // §4.3 keeps that case separate precisely so a network failure cannot be
        // mistaken for an attack — collapsing it into Bogus would turn every
        // outage into a security alert.
        var (rrset, signature) = SignedA();

        var validator = new DNSSECValidator(
                            new StubDnsClient { Unreachable = true },
                            [zone.DelegationSigner]
                        );

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Indeterminate));

    }

    #endregion

    #region A_Delegation_Whose_Ds_Nobody_Can_Follow_Is_Insecure()

    [Test]
    [Property("RFC", "6840 §5.2")]
    [Property("RFC", "8078 §4")]
    public async Task A_Delegation_Whose_Ds_Nobody_Can_Follow_Is_Insecure()
    {

        // RFC 6840 §5.2: "a validator disregards any authenticated DS records
        // that specify unknown or unsupported DNSKEY algorithms. If none are
        // left, the zone is treated as if it were unsigned."
        //
        // Unsigned, not broken — and the distinction is the whole point of the
        // rule. Reporting Bogus turns "I cannot check this" into "this is
        // forged", which fails the name for every client behind the validator
        // over a zone that is very likely fine and merely newer than the code
        // reading it. It fires the day a child moves to an algorithm this build
        // has not learned, which is precisely when the answer must not be an
        // outage.
        //
        // The DS below is the parent's real one with its algorithm set to 0 —
        // RFC 8078 §4 reserves that value for the CDS delete sentinel and says a
        // validator "must treat it as unknown", so it is the sharpest case: the
        // digest still matches the KSK, and the delegation is still unfollowable.
        //
        // "Authenticated" is part of the rule. The DS RRset is signed by a parent
        // that is itself anchored, so the parent has said, verifiably, that the
        // delegation is one nobody can follow — the step from a DS RRset that
        // merely arrived to an Insecure verdict is finding 67's to forbid.
        var (rrset, signature) = SignedA();

        using var parent = DNSSECSigningKey.Generate(DomainName.Parse("test"), 13, KeySigningKey: true);

        var anchor      = zone.DelegationSigner;

        var unfollowable = new DS(
                               DomainName.Parse("dnssec.test"),
                               DNSQueryClasses.IN,
                               TimeSpan.FromHours(1),
                               anchor.KeyTag,
                               0,                        // algorithm 0 — never a signature algorithm
                               anchor.DigestType,
                               anchor.Digest
                           );

        var validator = new DNSSECValidator(
                            ResolverWithSignedParent(parent, unfollowable),
                            [ parent.DelegationSigner() ]
                        );

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Insecure),
                    "a delegation this validator cannot follow is one it has no opinion about, " +
                    "not one it has caught forging");

    }

    #endregion

    #region An_Unfollowable_Ds_Counts_Only_Once_The_Parents_Keys_Are_Authenticated()

    /// <summary>
    /// Finding 73. The test above, with the one word of RFC 6840 §5.2 that makes it
    /// safe taken away: "authenticated". The anchor is the parent's genuine key;
    /// the parent's DNSKEY RRset the resolver is handed holds a different key, made
    /// up for the purpose, which signs itself and signs a DS with algorithm 0.
    /// </summary>
    /// <remarks>
    /// The DS signature verifies — against a key set nothing has authenticated.
    /// The step from there to Insecure was taken before the parent's keys were
    /// checked against the anchor, so anybody able to answer two queries could
    /// declare any signed zone below an anchor unsigned.
    /// </remarks>
    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "6840 §5.2")]
    [Property("RFC", "4035 §5.2")]
    public async Task An_Unfollowable_Ds_Counts_Only_Once_The_Parents_Keys_Are_Authenticated()
    {

        var (rrset, signature) = SignedA();

        using var genuine = DNSSECSigningKey.Generate(DomainName.Parse("test"), 13, KeySigningKey: true);
        using var forged  = DNSSECSigningKey.Generate(DomainName.Parse("test"), 13, KeySigningKey: true);

        var anchor       = zone.DelegationSigner;

        IDNSResourceRecord[] unfollowable = [ new DS(DomainName.Parse("dnssec.test"),
                                                     DNSQueryClasses.IN,
                                                     TimeSpan.FromHours(1),
                                                     anchor.KeyTag,
                                                     0,
                                                     anchor.DigestType,
                                                     anchor.Digest) ];

        IDNSResourceRecord[] forgedKeys   = [ forged.DNSKEY ];

        var resolver  = new StubDnsClient().
                            Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, zone.KeySetAnswer).
                            Answer("dnssec.test", DNSResourceRecordTypes.DS,     [ .. unfollowable, Sign(unfollowable, forged) ]).
                            Answer("test",        DNSResourceRecordTypes.DNSKEY, [ .. forgedKeys,   Sign(forgedKeys,   forged) ]);

        var validator = new DNSSECValidator(resolver, [ genuine.DelegationSigner() ]);

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "a DS RRset signed by a key the anchor never vouched for authenticates nothing, " +
                    "and an unfollowable algorithm in it proves nothing either");

    }

    #endregion

    #region A_Missing_Ds_Is_No_Proof_Of_An_Unsigned_Delegation()

    /// <summary>
    /// Finding 73. RFC 4035 §5.2 ends the authentication path at a delegation only
    /// on a proof: "If the validator authenticates an NSEC RRset that proves that
    /// no DS RRset is present for this zone, then there is no authentication path
    /// leading from the parent to the child." An empty answer to the DS query,
    /// with nothing in the authority section, is no such proof — it is what an
    /// attacker on the path sends to make a signed zone look unsigned.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The parent <c>test.</c> is anchored; the child is the fixture zone, whose
    /// answer is genuinely signed. Three answers to the DS query, three verdicts:
    /// the DS itself, signed by the parent — Secure; an empty answer with the
    /// parent's signed NSEC proving the delegation has no DS — Insecure; and an
    /// empty answer with no proof at all — Bogus. The last was Insecure.
    /// </para>
    /// <para>
    /// For DANE the difference is the whole of the protocol: RFC 7672 §2.2 answers
    /// an insecure TLSA lookup with opportunistic TLS, so a forged empty DS answer
    /// took a zone's TLSA records out of play.
    /// </para>
    /// </remarks>
    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "4035 §5.2")]
    public async Task A_Missing_Ds_Is_No_Proof_Of_An_Unsigned_Delegation()
    {

        var (rrset, signature) = SignedA();

        using var parent = DNSSECSigningKey.Generate(DomainName.Parse("test"), 13, KeySigningKey: true);

        IDNSResourceRecord[] parentKeys = [ parent.DNSKEY ];
        IDNSResourceRecord[] ds         = [ zone.DelegationSigner ];

        StubDnsClient Resolver()
            => new StubDnsClient().
                   Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, zone.KeySetAnswer).
                   Answer("test",        DNSResourceRecordTypes.DNSKEY, [ .. parentKeys, Sign(parentKeys, parent) ]);

        var withDs     = Resolver().Answer   ("dnssec.test", DNSResourceRecordTypes.DS, [ .. ds, Sign(ds, parent) ]);
        var provenNone = Resolver().Authority("dnssec.test", DNSResourceRecordTypes.DS, ProofOfAnUnsignedDelegation("dnssec.test", "e.test", parent));
        var unproven   = Resolver();

        var response   = ResponseWith([.. rrset, signature]);
        var anchors    = new[] { parent.DelegationSigner() };

        Assert.Multiple(async () => {

            Assert.That(await new DNSSECValidator(withDs,     anchors).ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Secure),
                        "the control: the parent's signed DS leads into the signed child");

            Assert.That(await new DNSSECValidator(provenNone, anchors).ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Insecure),
                        "the parent proves the delegation has no DS: the child is unsigned as far as the chain goes");

            Assert.That(await new DNSSECValidator(unproven,   anchors).ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "an empty DS answer that proves nothing is missing data the anchor says should be there");

        });

    }

    #endregion

    #region A_Delegation_With_One_Usable_Ds_Among_Unusable_Ones_Still_Validates()

    [Test]
    [Property("RFC", "6840 §5.2")]
    public async Task A_Delegation_With_One_Usable_Ds_Among_Unusable_Ones_Still_Validates()
    {

        // The control for the test above, and the half of §5.2 that is easy to
        // lose: the rule is to *disregard* the unusable records, not to fail on
        // them. A validator that stopped at the first DS it could not read would
        // treat every zone mid-algorithm-rollover as unsigned — which is a
        // downgrade, and a far worse outcome than the one the rule prevents.
        var (rrset, signature) = SignedA();

        var anchor    = zone.DelegationSigner;

        var unusable  = new DS(
                            DomainName.Parse("dnssec.test"),
                            DNSQueryClasses.IN,
                            TimeSpan.FromHours(1),
                            anchor.KeyTag,
                            0,
                            anchor.DigestType,
                            anchor.Digest
                        );

        using var parent = DNSSECSigningKey.Generate(DomainName.Parse("test"), 13, KeySigningKey: true);

        var validator = new DNSSECValidator(
                            ResolverWithSignedParent(parent, unusable, anchor),
                            [ parent.DelegationSigner() ]
                        );

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure),
                    "one followable DS is enough — the others are disregarded, not fatal");

    }

    #endregion

    #region Signed_Answer_Without_A_Trust_Anchor_Is_Not_Secure()

    [Test]
    public async Task Signed_Answer_Without_A_Trust_Anchor_Is_Not_Secure()
    {

        // The signature verifies, but nothing ties the zone to a configured anchor,
        // and the stub publishes no DS for it. A verified signature under an
        // unanchored key proves only that whoever made the key also made the
        // signature — never Secure.
        var (rrset, signature) = SignedA();

        var validator = new DNSSECValidator(ResolverServingKeys());   // no anchors

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

        Assert.That(result, Is.Not.EqualTo(DNSSECValidationResult.Secure),
                    "a chain that reaches no trust anchor must never be Secure");

    }

    #endregion

    #region Validator_Fetches_The_Signers_Dnskey()

    [Test]
    public async Task Validator_Fetches_The_Signers_Dnskey()
    {

        // The signer name in the RRSIG — not the owner of the RRset — is what
        // decides whose key is fetched. Getting this wrong sends the validator to
        // the wrong zone the moment a name is served by a parent.
        var (rrset, signature) = SignedA();

        var resolver  = ResolverServingKeys();
        var validator = new DNSSECValidator(resolver, [zone.DelegationSigner]);

        await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

        Assert.That(resolver.Queries, Does.Contain(("dnssec.test", DNSResourceRecordTypes.DNSKEY)),
                    $"expected a DNSKEY query for the signer; saw: {String.Join(", ", resolver.Queries)}");

    }

    #endregion

    #region A_Zone_Cannot_Sign_For_A_Name_Outside_It()

    /// <summary>
    /// Finding 68. RFC 4035 §5.3.1: "The RRSIG RR's Signer's Name field MUST be the
    /// name of the zone that contains the RRset."
    ///
    /// <para>
    /// The chain here is as short and as sound as a chain gets: one zone,
    /// <c>attacker.test.</c>, its DNSKEY RRset signed by its own key, and a trust
    /// anchor over that key — the position of anybody who holds the key of a
    /// properly delegated, properly signed zone. With that key they sign an A
    /// record for <c>www.bank.example.</c>, a name their zone has no say over. The
    /// signature is genuine and the chain verifies; what is wrong is the claim that
    /// <c>attacker.test.</c> speaks for that name at all, and only the names say so.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4035 §5.3.1")]
    public async Task A_Zone_Cannot_Sign_For_A_Name_Outside_It()
    {

        using var attacker = DNSSECSigningKey.Generate(DomainName.Parse("attacker.test"), 13, KeySigningKey: true);

        IDNSResourceRecord[] keys    = [ attacker.DNSKEY ];
        IDNSResourceRecord[] own     = [ new A(DomainName.Parse("www.attacker.test"), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.66")) ];
        IDNSResourceRecord[] foreign = [ new A(DomainName.Parse("www.bank.example"),  DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.66")) ];

        var resolver  = new StubDnsClient().
                            Answer("attacker.test", DNSResourceRecordTypes.DNSKEY, [ .. keys, Sign(keys, attacker) ]);

        var validator = new DNSSECValidator(resolver, [ attacker.DelegationSigner() ]);

        // The control: the same key, the same chain, a name inside the zone. What
        // refuses the second answer can then only be the name.
        var ownResult     = await validator.ValidateAsync(ResponseWith([ .. own,     Sign(own,     attacker) ]));
        var foreignResult = await validator.ValidateAsync(ResponseWith([ .. foreign, Sign(foreign, attacker) ]));

        Assert.Multiple(() => {

            Assert.That(ownResult,     Is.EqualTo(DNSSECValidationResult.Secure),
                        "a zone vouches for the names inside it");

            Assert.That(foreignResult, Is.EqualTo(DNSSECValidationResult.Bogus),
                        "attacker.test. has no authority over www.bank.example., however valid its signature");

        });

    }

    #endregion

    #region A_Signature_With_Nothing_To_Cover_Vouches_For_Nothing()

    /// <summary>
    /// Finding 69. The answer holds a forged A record for <c>www.dnssec.test</c>
    /// and, beside it, BIND's genuine signature over the A RRset of
    /// <c>a.dnssec.test</c> — which the answer does not hold. Replaying a signature
    /// costs nothing; every resolver has been handed this one.
    ///
    /// <para>
    /// A signature vouches for the RRset it covers. With that RRset absent it
    /// vouches for nothing, and the forged record beside it is exactly as unsigned
    /// as it would be alone — which is the verdict of
    /// <see cref="Answer_Without_Any_Rrsig_Is_Insecure"/>, never Secure.
    /// </para>
    /// <para>
    /// This used to say that verdict was Insecure, "because an unsigned RRset is
    /// also what a signed CNAME into an unsigned zone legitimately brings along".
    /// It is, when a delegation on the way to it is proven unsigned. Here the
    /// forged record lies in <c>dnssec.test</c>, the anchored zone itself, and
    /// nothing proves anything: finding 72 makes that Bogus.
    /// </para>
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "4035 §5.3")]
    public async Task A_Signature_With_Nothing_To_Cover_Vouches_For_Nothing()
    {

        var (_, signature) = SignedA();

        var forged    = new A(DomainName.Parse("www.dnssec.test"),
                              DNSQueryClasses.IN,
                              TimeSpan.FromHours(1),
                              IPv4Address.Parse("192.0.2.66"));

        var validator = new DNSSECValidator(ResolverServingKeys(), [zone.DelegationSigner]);

        var result    = await validator.ValidateAsync(ResponseWith(forged, signature));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "the only signature in the answer covers a record the answer does not hold, " +
                    "and the record it holds lies in a zone the anchor says is signed");

    }

    #endregion

}

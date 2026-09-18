using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

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
    /// A stub resolver that serves the fixture zone's DNSKEY RRset.
    /// </summary>
    private StubDnsClient ResolverServingKeys()
        => new StubDnsClient().Answer(
               "dnssec.test",
               DNSResourceRecordTypes.DNSKEY,
               [.. zone.DnsKeys]
           );

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

    [Test]
    public async Task Answer_Without_Any_Rrsig_Is_Insecure()
    {

        // No signatures at all is not a failure — it is an ordinary answer from an
        // unsigned zone. Reporting Bogus here would break the entire unsigned
        // internet; reporting Secure would make DNSSEC meaningless.
        var (rrset, _) = SignedA();

        var validator  = new DNSSECValidator(ResolverServingKeys(), [zone.DelegationSigner]);

        var result     = await validator.ValidateAsync(ResponseWith([.. rrset]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Insecure));

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
        var (rrset, signature) = SignedA();

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
                            new StubDnsClient().
                                Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, [.. zone.DnsKeys]).
                                Answer("dnssec.test", DNSResourceRecordTypes.DS,     [ unfollowable ])
                        );

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Insecure),
                    "a delegation this validator cannot follow is one it has no opinion about, " +
                    "not one it has caught forging");

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

        var validator = new DNSSECValidator(
                            new StubDnsClient().
                                Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, [.. zone.DnsKeys]).
                                Answer("dnssec.test", DNSResourceRecordTypes.DS,     [ unusable, anchor ])
                        );

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

        Assert.That(result, Is.Not.EqualTo(DNSSECValidationResult.Insecure),
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

}

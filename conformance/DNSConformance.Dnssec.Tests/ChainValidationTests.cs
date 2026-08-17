using NUnit.Framework;

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
        // The crypto still checks out — only the clock says no — and that must
        // still be Bogus, not Secure.
        var (rrset, signature) = SignedA();

        var expired   = Rewindow(signature, Now - 7200, Now - 3600);

        var validator = new DNSSECValidator(ResolverServingKeys(), [zone.DelegationSigner]);

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, expired]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "a signature past its expiration must not validate");

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

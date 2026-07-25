using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4034 §3 / RFC 4035 §5.3 — RRSIG verification against a zone signed by
/// BIND's dnssec-signzone. Because the signatures come from an independent
/// implementation, a passing test says Hermod agrees with the rest of the DNS
/// world about canonical form, the signed-data construction and the crypto.
/// </summary>
[TestFixture]
[Property("RFC", "4034")]
public class RrsigValidationTests
{

    private SignedZoneFixture zone = null!;

    [OneTimeSetUp]
    public void LoadFixture()
    {

        if (!SignedZoneFixture.IsAvailable)
            Assert.Ignore("BIND-signed fixture zone missing — regenerate with: wsl -e sh fixtures/zones/resign.sh");

        zone = SignedZoneFixture.Load();

    }


    private DNSSECValidator NewValidator()
        => new(new DNSClient(QueryTimeout: TimeSpan.FromSeconds(2)));


    #region Fixture_Contains_Keys_And_Signatures()

    [Test]
    public void Fixture_Contains_Keys_And_Signatures()
    {

        Assert.Multiple(() => {
            Assert.That(zone.DnsKeys,        Is.Not.Empty, "the signed zone must publish DNSKEYs");
            Assert.That(zone.Signatures,     Is.Not.Empty, "the signed zone must publish RRSIGs");
            Assert.That(zone.ZoneSigningKey, Is.Not.Null,  "a ZSK (SEP clear) must be present");
            Assert.That(zone.KeySigningKey,  Is.Not.Null,  "a KSK (SEP set) must be present");
        });

    }

    #endregion

    #region Ds_Of_The_Fixture_Zone_Matches_Its_Ksk()

    [Test]
    [Property("RFC", "4034 §5.1.4")]
    public void Ds_Of_The_Fixture_Zone_Matches_Its_Ksk()
    {

        // dnssec-dsfromkey computed this DS; Hermod must arrive at the same digest.
        var ksk = zone.KeySigningKey!;

        Assert.Multiple(() => {
            Assert.That(DNSSECValidator.ComputeKeyTag(ksk), Is.EqualTo(zone.DelegationSigner.KeyTag),
                        "key tag must match the one BIND published in the DS");
            Assert.That(DNSSECValidator.VerifyDS(ksk, zone.DelegationSigner), Is.True,
                        "DS digest computed by Hermod must match BIND's");
        });

    }

    #endregion

    #region Rrsig_Over_A_Record_Validates(...)

    [TestCase("a.dnssec.test",    DNSResourceRecordTypes.A,    TestName = "Rrsig_Over_A_Record_Validates")]
    [TestCase("aaaa.dnssec.test", DNSResourceRecordTypes.AAAA, TestName = "Rrsig_Over_AAAA_Record_Validates")]
    [TestCase("mx.dnssec.test",   DNSResourceRecordTypes.MX,   TestName = "Rrsig_Over_MX_Record_Validates")]
    [TestCase("txt.dnssec.test",  DNSResourceRecordTypes.TXT,  TestName = "Rrsig_Over_TXT_Record_Validates")]
    [TestCase("dnssec.test",      DNSResourceRecordTypes.SOA,  TestName = "Rrsig_Over_SOA_Record_Validates")]
    [TestCase("dnssec.test",      DNSResourceRecordTypes.NS,   TestName = "Rrsig_Over_NS_Record_Validates")]
    [Property("RFC", "4034 §3.1.8")]
    public void Rrsig_Over_Rrset_Validates(String ownerName, DNSResourceRecordTypes type)
    {

        var rrset      = zone.RRset(ownerName, type);
        var signature  = zone.SignatureFor(ownerName, type);

        Assert.That(rrset,     Is.Not.Empty, $"fixture has no {type} RRset for {ownerName}");
        Assert.That(signature, Is.Not.Null,  $"fixture has no RRSIG({type}) for {ownerName}");

        var key = zone.KeyFor(signature!);

        Assert.That(key, Is.Not.Null, $"no DNSKEY with key tag {signature!.KeyTag} / algorithm {signature.Algorithm}");

        var result = NewValidator().ValidateRRSig(rrset, signature, key!);

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure),
                    $"BIND's RRSIG over {ownerName}/{type} must verify as Secure, got {result}");

    }

    #endregion

    #region Rrsig_Over_The_Dnskey_Rrset_Validates_With_The_Ksk()

    [Test]
    [Property("RFC", "4035 §5.3")]
    public void Rrsig_Over_The_Dnskey_Rrset_Validates_With_The_Ksk()
    {

        // The DNSKEY RRset is signed by the KSK — this is the link the chain of
        // trust walks through after the DS check.
        var rrset      = zone.RRset(zone.Origin, DNSResourceRecordTypes.DNSKEY);
        var signature  = zone.SignatureFor(zone.Origin, DNSResourceRecordTypes.DNSKEY);

        Assert.That(rrset,     Is.Not.Empty);
        Assert.That(signature, Is.Not.Null);

        var key = zone.KeyFor(signature!);

        Assert.That(key,        Is.Not.Null);
        Assert.That(key!.Flags & 0x0001, Is.EqualTo(1), "the DNSKEY RRset is signed by the SEP key");

        Assert.That(NewValidator().ValidateRRSig(rrset, signature!, key),
                    Is.EqualTo(DNSSECValidationResult.Secure));

    }

    #endregion

    #region Tampered_Rdata_Makes_The_Signature_Bogus()

    [Test]
    [Property("RFC", "4035 §5.3.3")]
    public void Tampered_Rdata_Makes_The_Signature_Bogus()
    {

        // Swap the A record's address: the signature must no longer verify.
        var signature = zone.SignatureFor("a.dnssec.test", DNSResourceRecordTypes.A);

        Assert.That(signature, Is.Not.Null);

        var key       = zone.KeyFor(signature!);
        var tampered  = new List<IDNSResourceRecord> {
                            new A(
                                DomainName.Parse("a.dnssec.test"),
                                DNSQueryClasses.IN,
                                TimeSpan.FromSeconds(3600),
                                org.GraphDefined.Vanaheimr.Hermod.IPv4Address.Parse("6.6.6.6")
                            )
                        };

        var result    = NewValidator().ValidateRRSig(tampered, signature!, key!);

        Assert.That(result, Is.Not.EqualTo(DNSSECValidationResult.Secure),
                    "modified RDATA MUST NOT validate");

    }

    #endregion

    #region Wrong_Key_Makes_The_Signature_Bogus()

    [Test]
    public void Wrong_Key_Makes_The_Signature_Bogus()
    {

        // Verify the A RRset's signature with the KSK instead of the ZSK.
        var rrset      = zone.RRset("a.dnssec.test", DNSResourceRecordTypes.A);
        var signature  = zone.SignatureFor("a.dnssec.test", DNSResourceRecordTypes.A);
        var correctKey = zone.KeyFor(signature!);
        var wrongKey   = zone.DnsKeys.FirstOrDefault(k => DNSSECValidator.ComputeKeyTag(k) != DNSSECValidator.ComputeKeyTag(correctKey!));

        Assert.That(wrongKey, Is.Not.Null, "fixture must publish more than one key");

        var result = NewValidator().ValidateRRSig(rrset, signature!, wrongKey!);

        Assert.That(result, Is.Not.EqualTo(DNSSECValidationResult.Secure),
                    "a signature MUST NOT verify under an unrelated key");

    }

    #endregion

    #region Rrset_Order_Does_Not_Affect_Validation()

    [Test]
    [Property("RFC", "4034 §6.3")]
    public void Rrset_Order_Does_Not_Affect_Validation()
    {

        // "the RRs are sorted into canonical order" before signing — so the
        // order records happen to arrive in must be irrelevant.
        var rrset      = zone.RRset("dnssec.test", DNSResourceRecordTypes.DNSKEY);
        var signature  = zone.SignatureFor("dnssec.test", DNSResourceRecordTypes.DNSKEY);
        var key        = zone.KeyFor(signature!);

        Assume.That(rrset.Count, Is.GreaterThan(1), "needs a multi-record RRset");

        var reversed   = Enumerable.Reverse(rrset).ToList();

        var forward    = NewValidator().ValidateRRSig(rrset,    signature!, key!);
        var backward   = NewValidator().ValidateRRSig(reversed, signature!, key!);

        Assert.Multiple(() => {
            Assert.That(forward,  Is.EqualTo(DNSSECValidationResult.Secure));
            Assert.That(backward, Is.EqualTo(DNSSECValidationResult.Secure),
                        "canonical ordering must be applied by the validator, not assumed from input order");
        });

    }

    #endregion

}

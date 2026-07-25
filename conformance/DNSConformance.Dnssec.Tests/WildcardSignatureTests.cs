using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4034 §3.1.3 / RFC 4035 §5.3.2 — validating an RRset that a server
/// synthesized from a wildcard.
///
/// The signature is BIND's, over "*.wild.dnssec.test."; the answer a client
/// actually receives has the wildcard expanded to the queried name. The Labels
/// field is what tells the validator that happened, and the signed data has to
/// be rebuilt with the wildcard name — not the expanded one.
/// </summary>
[TestFixture]
[Property("RFC", "4035 §5.3.2")]
public class WildcardSignatureTests
{

    private SignedZoneFixture zone = null!;

    [OneTimeSetUp]
    public void LoadFixture()
    {

        if (!SignedZoneFixture.IsAvailable)
            Assert.Ignore("BIND-signed fixture zone missing — regenerate with: wsl -e sh fixtures/zones/resign.sh");

        zone = SignedZoneFixture.Load();

    }


    private static DNSSECValidator NewValidator()
        => new(new DNSClient(QueryTimeout: TimeSpan.FromSeconds(2)));


    #region Wildcard_Rrsig_Has_Fewer_Labels_Than_Its_Owner()

    [Test]
    [Property("RFC", "4034 §3.1.3")]
    public void Wildcard_Rrsig_Has_Fewer_Labels_Than_Its_Owner()
    {

        // RFC 4034 §3.1.3: the Labels field counts the labels of the owner name
        // "not counting the null root label and not counting any leading asterisk".
        // So for "*.wild.dnssec.test." BIND writes 3, while the name itself has 4
        // labels. That difference is the entire wildcard signal.
        var signature = zone.WildcardSignature("*.wild.dnssec.test", DNSResourceRecordTypes.A);

        Assert.That(signature.Labels, Is.EqualTo(3),
                    "Labels must exclude the leading asterisk and the root label");

    }

    #endregion

    #region Wildcard_Expanded_Rrset_Validates()

    [Test]
    public void Wildcard_Expanded_Rrset_Validates()
    {

        // A client asking for "anything.wild.dnssec.test" gets an A record at that
        // name, covered by the signature made over "*.wild.dnssec.test".
        //
        // RFC 4035 §5.3.2: "If the RRSIG RR's Labels field value is less than the
        // number of labels in the RRset's owner name, then the RRset was generated
        // from a wildcard, and the validator MUST reconstruct the original owner
        // name" as "*." followed by the rightmost <Labels> labels.
        //
        // A validator that signs over the expanded name instead computes a digest
        // no signer ever produced, and every wildcard answer in the DNS becomes
        // Bogus.
        var signature = zone.WildcardSignature("*.wild.dnssec.test", DNSResourceRecordTypes.A);
        var key       = zone.KeyFor(signature);

        Assert.That(key, Is.Not.Null, "the fixture must publish the DNSKEY that signed the wildcard");

        var expanded  = new A(
                            DomainName.Parse("anything.wild.dnssec.test"),
                            DNSQueryClasses.IN,
                            TimeSpan.FromSeconds(signature.OriginalTTL),
                            IPv4Address.Parse("192.0.2.77")   // the RDATA of *.wild, see fixtures/zones/resign.sh
                        );

        var result    = NewValidator().ValidateRRSig([expanded], signature, key!);

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure),
                    "a wildcard-expanded RRset must validate against the wildcard's signature");

    }

    #endregion

    #region Wildcard_Owner_Names_Cannot_Be_Represented()

    [Test]
    [Property("RFC", "4592 §2")]
    [Category(TestCategories.KnownIssue)]
    public void Wildcard_Owner_Names_Cannot_Be_Represented()
    {

        // RFC 4592 §2: "*" is a perfectly ordinary label as far as the wire format
        // is concerned, and wildcard owner names do appear in responses — the NSEC
        // and RRSIG records that prove a wildcard match carry them.
        //
        // Hermod's DomainName rejects the label outright, so such a record cannot be
        // built or read back. Recorded here so the limitation is visible; it is the
        // reason WildcardSignature() above has to substitute a parseable owner.
        Assert.That(
            () => DomainName.Parse("*.wild.dnssec.test"),
            Throws.Nothing,
            "a wildcard owner name must be representable"
        );

    }

    #endregion

}

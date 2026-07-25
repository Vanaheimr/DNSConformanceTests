using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

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
        var signature = zone.SignatureFor("*.wild.dnssec.test", DNSResourceRecordTypes.A)!;

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
        var signature = zone.SignatureFor("*.wild.dnssec.test", DNSResourceRecordTypes.A)!;
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

    #region Wildcard_Owner_Names_Are_Representable()

    [Test]
    [Property("RFC", "4592 §2.1.1")]
    public void Wildcard_Owner_Names_Are_Representable()
    {

        // RFC 4592 §2.1.1: a wildcard domain name is one whose leftmost label is a
        // single asterisk. It is an ordinary label on the wire, and it reaches
        // clients — the NSEC and RRSIG records that prove a wildcard match carry
        // one — so an owner name read from a response must be able to hold it.
        var lenient = DomainName.ParseLenient("*.wild.dnssec.test");
        var service = DNSServiceName.Parse   ("*.wild.dnssec.test");

        Assert.Multiple(() => {

            Assert.That(lenient.FullName,  Is.EqualTo("*.wild.dnssec.test."));
            Assert.That(lenient.Labels[0], Is.EqualTo("*"), "the asterisk is a label, not a marker");
            Assert.That(service.FullName,  Is.EqualTo("*.wild.dnssec.test."));

            // A wildcard is never a hostname, so the strict parser must keep
            // rejecting it — leniency belongs on the owner-name path only.
            Assert.That(() => DomainName.Parse("*.wild.dnssec.test"),
                        Throws.InstanceOf<ArgumentException>(),
                        "the strict parser must not accept a wildcard as a hostname");

        });

    }

    #endregion

    #region Wildcard_Label_Is_Only_Accepted_Leftmost(...)

    [TestCase("a.*.example",   TestName = "Wildcard_Label_Rejected_In_The_Middle")]
    [TestCase("example.*",     TestName = "Wildcard_Label_Rejected_At_The_End")]
    [TestCase("*x.example",    TestName = "Wildcard_Rejected_When_Not_The_Whole_Label")]
    [TestCase("**.example",    TestName = "Double_Asterisk_Is_Rejected")]
    [Property("RFC", "4592 §2.1.1")]
    public void Wildcard_Label_Is_Only_Accepted_Leftmost(String name)
    {

        // RFC 4592 §2.1.1 is specific: only a leftmost label that is exactly "*"
        // makes a wildcard. An asterisk anywhere else is an ordinary label that
        // happens to contain one, and "*x" is not a wildcard at all — accepting
        // either would quietly widen what this API produces.
        Assert.That(
            () => DomainName.ParseLenient(name),
            Throws.InstanceOf<ArgumentException>(),
            $"'{name}' is not a wildcard domain name"
        );

    }

    #endregion

    #region Wildcard_Owner_Name_Round_Trips_Through_The_Wire()

    [Test]
    [Property("RFC", "4592 §2.1.1")]
    public void Wildcard_Owner_Name_Round_Trips_Through_The_Wire()
    {

        // The asterisk must survive serialization as the single octet 0x2A in a
        // one-byte label, which is what every other implementation writes.
        var record = new A(
                         DomainName.ParseLenient("*.wild.dnssec.test"),
                         DNSQueryClasses.IN,
                         TimeSpan.FromMinutes(5),
                         IPv4Address.Parse("192.0.2.77")
                     );

        var stream = new MemoryStream();
        record.Serialize(stream, UseCompression: false);

        var wire = stream.ToArray();

        Assert.Multiple(() => {

            Assert.That(wire[0], Is.EqualTo(1),      "the wildcard label is one octet long");
            Assert.That(wire[1], Is.EqualTo(0x2A),   "…and that octet is '*'");

            Assert.That(RawDnsReader.ReadNameAt(wire, 0).Name.Presentation,
                        Is.EqualTo("*.wild.dnssec.test"),
                        "the independent reader must see the same name");

        });

    }

    #endregion

}

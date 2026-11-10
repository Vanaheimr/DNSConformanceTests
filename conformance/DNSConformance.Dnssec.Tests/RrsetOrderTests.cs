using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4034 §6.3 — the order of the records of an RRset under a signature, which
/// is the order of their RDATA and of nothing else.
/// </summary>
/// <remarks>
/// <para>
/// "RRs with the same owner name, class, and type are sorted by treating the
/// RDATA portion of the canonical form of each RR as a left-justified unsigned
/// octet sequence in which the absence of an octet sorts before a zero octet."
/// The RDATA portion: not the record, whose RDLENGTH stands in front of its RDATA
/// and would sort a short record first whatever its octets say.
/// </para>
/// <para>
/// The two orders agree for records of equal length, which is every RRset of more
/// than one record in the other fixtures. <c>order.rdatacase.dnssec.test</c> holds
/// two MX records on which they disagree: <c>x.y.example.</c> is the longer, and
/// sorts first, because its first label is one octet long where <c>aa</c> is two.
/// Its names are in lowercase, so this is about the order alone.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "4034 §6.3")]
public class RrsetOrderTests
{

    #region Data

    private const String Origin = "rdatacase.dnssec.test";

    private SignedZoneFixture zone = null!;

    [OneTimeSetUp]
    public void LoadFixture()
    {

        if (!SignedZoneFixture.IsAvailableFor(Origin))
            Assert.Ignore($"{Origin} is missing — regenerate with: wsl -e sh fixtures/zones/resign.sh");

        zone = SignedZoneFixture.Load(Origin);

    }

    private static MX Mx(String Exchange)
        => new(DomainName.Parse("order.example."), DNSQueryClasses.IN, TimeSpan.FromHours(1), 10, DomainName.Parse(Exchange));

    #endregion


    #region The_Two_Orders_Disagree_For_This_Rrset()

    [Test]
    public void The_Two_Orders_Disagree_For_This_Rrset()
    {

        // The guard: if both orders put the same record first, every test below
        // passes whichever order the code under test uses.
        var rdata = zone.RRset($"order.{Origin}", DNSResourceRecordTypes.MX).
                         Select(ADNSResourceRecord.RDataOf).
                         ToArray();

        Assert.That(rdata, Has.Length.EqualTo(2));

        var byOctets = rdata.Order(Comparer<Byte[]>.Create(DNSSECCanonical.Compare)).First();
        var byLength = rdata.OrderBy(octets => octets.Length).First();

        Assert.That(byOctets, Is.Not.EqualTo(byLength),
                    "the fixture's two records have to sort differently by octets and by length");

    }

    #endregion

    #region Bind_Ordered_The_Rrset_By_Its_Rdata()

    [Test]
    [Category(TestCategories.KnownIssue)]
    public void Bind_Ordered_The_Rrset_By_Its_Rdata()
    {

        var rrset     = zone.RRset($"order.{Origin}", DNSResourceRecordTypes.MX);
        var signature = zone.SignatureFor($"order.{Origin}", DNSResourceRecordTypes.MX);

        Assert.That(signature, Is.Not.Null);

        var key = zone.KeyFor(signature!);

        Assert.That(key, Is.Not.Null);

        // A validator that orders by record rather than by RDATA hashes the two
        // records the other way round, and calls BIND's signature forged.
        Assert.That(new DNSSECValidator(new DNSClient(QueryTimeout: TimeSpan.FromSeconds(2))).ValidateRRSig(rrset, signature!, key!),
                    Is.EqualTo(DNSSECValidationResult.Secure));

    }

    #endregion

    #region The_Signed_Data_Puts_The_Shorter_Record_Second_When_Its_Octets_Say_So()

    [Test]
    [Category(TestCategories.KnownIssue)]
    public void The_Signed_Data_Puts_The_Shorter_Record_Second_When_Its_Octets_Say_So()
    {

        // The same rule without a fixture, read off the signed data itself: the
        // two records are the last octets of it, and "x.y.example." — 01 'x' —
        // comes before "aa.example." — 02 'a' 'a' — however the RRset is handed in.
        var longer   = Mx("x.y.example.");
        var shorter  = Mx("aa.example.");

        var template = new RRSIG(DomainName.Parse("order.example."), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                                 DNSResourceRecordTypes.MX, 13, 2, 3600, 1893456000, 1735689600, 12345,
                                 DomainName.Parse("example."), [ 0x00 ]);

        foreach (var rrset in new[] { new IDNSResourceRecord[] { longer, shorter }, [ shorter, longer ] })
        {

            var signedData = Convert.ToHexString(DNSSECCanonical.SignedData(rrset, template)).ToLowerInvariant();

            var first      = signedData.IndexOf("000a" + "0178" + "0179", StringComparison.Ordinal);
            var second     = signedData.IndexOf("000a" + "02616", StringComparison.Ordinal);

            Assert.That(first,  Is.GreaterThan(0));
            Assert.That(second, Is.GreaterThan(first),
                        "x.y.example. sorts first by its RDATA, although its record is the longer");

        }

    }

    #endregion

}

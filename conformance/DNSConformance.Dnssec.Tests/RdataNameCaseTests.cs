using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4034 §6.2 item 3 — the names inside RDATA, lowercased for the types on
/// RFC 3597 §7's list and for no others.
/// </summary>
/// <remarks>
/// <para>
/// The canonical form a signature is made over lowercases the owner name (item 2)
/// and, "if the type of the RR is NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR, HINFO,
/// MINFO, MX, HINFO, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX, SRV, DNAME, A6,
/// RRSIG, or NSEC", "all uppercase US-ASCII letters in the DNS names contained
/// within the RDATA" (item 3). RFC 6840 §5.1 takes NSEC and HINFO off that list.
/// RFC 3597 §7 closes it: every type published after RFC 3597 keeps the case of
/// its names in the canonical form, because a receiver with no parser for a type
/// cannot know where its names are.
/// </para>
/// <para>
/// So there are two ways to be wrong, and the suite's other fixtures could catch
/// neither: every one of them writes its names in lowercase, where lowercasing is
/// a no-op. <c>rdatacase.dnssec.test</c> writes them in mixed case — for ten types
/// on the list, and for LP and HIP, which came after it. BIND signed it; each
/// RRset has to verify.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "4034 §6.2")]
public class RdataNameCaseTests
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

    private static DNSSECValidator NewValidator()
        => new(new DNSClient(QueryTimeout: TimeSpan.FromSeconds(2)));

    private DNSSECValidationResult Validate(String Owner, DNSResourceRecordTypes Type)
    {

        var rrset     = zone.RRset(Owner, Type);
        var signature = zone.SignatureFor(Owner, Type);

        Assert.That(rrset,     Is.Not.Empty, $"the fixture has no {Type} RRset at {Owner}");
        Assert.That(signature, Is.Not.Null,  $"the fixture has no RRSIG({Type}) at {Owner}");

        var key = zone.KeyFor(signature!);

        Assert.That(key, Is.Not.Null, $"no DNSKEY for key tag {signature!.KeyTag}");

        return NewValidator().ValidateRRSig(rrset, signature, key!);

    }

    #endregion


    #region The_Fixture_Holds_Names_That_Are_Not_In_Lowercase()

    [Test]
    public void The_Fixture_Holds_Names_That_Are_Not_In_Lowercase()
    {

        // The guard on everything below. If BIND, the loader or a reader on the
        // way had lowercased these names, every case here would pass on a
        // validator that ignored item 3 entirely.
        Assert.Multiple(() => {

            Assert.That(zone.RRset($"mx.{Origin}", DNSResourceRecordTypes.MX).OfType<MX>().Single().Exchange.FullName,
                        Does.StartWith("Mail.RdataCase."));

            Assert.That(zone.RRset($"lp.{Origin}", DNSResourceRecordTypes.LP).OfType<LP>().Single().FQDN.FullName,
                        Does.StartWith("L64-Subnet.RdataCase."));

        });

    }

    #endregion

    #region An_Answer_Without_Names_In_Its_Rdata_Validates()

    [Test]
    [Property("RFC", "4034 §3.1.8")]
    public void An_Answer_Without_Names_In_Its_Rdata_Validates()
    {

        // The control: an A record of the same zone, with the same key. If this
        // fails, the fixture is stale or broken, and nothing below says anything
        // about case.
        Assert.That(Validate($"a.{Origin}", DNSResourceRecordTypes.A), Is.EqualTo(DNSSECValidationResult.Secure));

    }

    #endregion


    #region A_Name_In_The_Rdata_Of_A_Type_On_The_List_Is_Signed_In_Lowercase(Owner, Type)

    [Test]
    [Property("RFC", "3597 §7")]
    [Category(TestCategories.KnownIssue)]
    // The apex NS RRset, whose second name server is "NS2.Example.".
    [TestCase("",           DNSResourceRecordTypes.NS,     TestName = "Rdata_lowercased__NS")]
    [TestCase("cname.",     DNSResourceRecordTypes.CNAME,  TestName = "Rdata_lowercased__CNAME")]
    [TestCase("ptr.",       DNSResourceRecordTypes.PTR,    TestName = "Rdata_lowercased__PTR")]
    [TestCase("mx.",        DNSResourceRecordTypes.MX,     TestName = "Rdata_lowercased__MX")]
    [TestCase("rp.",        DNSResourceRecordTypes.RP,     TestName = "Rdata_lowercased__RP_two_names")]
    [TestCase("afsdb.",     DNSResourceRecordTypes.AFSDB,  TestName = "Rdata_lowercased__AFSDB")]
    [TestCase("naptr.",     DNSResourceRecordTypes.NAPTR,  TestName = "Rdata_lowercased__NAPTR_behind_three_strings")]
    [TestCase("kx.",        DNSResourceRecordTypes.KX,     TestName = "Rdata_lowercased__KX")]
    [TestCase("_sip._tcp.", DNSResourceRecordTypes.SRV,    TestName = "Rdata_lowercased__SRV")]
    [TestCase("redirect.",  DNSResourceRecordTypes.DNAME,  TestName = "Rdata_lowercased__DNAME")]
    public void A_Name_In_The_Rdata_Of_A_Type_On_The_List_Is_Signed_In_Lowercase(String Owner, DNSResourceRecordTypes Type)
    {

        // BIND lowercased the name before it signed. A validator that hashes the
        // name as it arrived — "Mail.RdataCase." rather than "mail.rdatacase." —
        // hashes octets nobody signed, and calls a correct answer forged.
        Assert.That(Validate(Owner + Origin, Type), Is.EqualTo(DNSSECValidationResult.Secure),
                    $"{Type} is on RFC 3597 §7's list, so its RDATA names are lowercased in the canonical form");

    }

    #endregion

    #region A_Name_In_The_Rdata_Of_A_Later_Type_Is_Signed_As_Written(Owner, Type)

    [Test]
    [Property("RFC", "3597 §7")]
    [TestCase("lp.",   DNSResourceRecordTypes.LP,   TestName = "Rdata_as_written__LP")]
    [TestCase("hip.",  DNSResourceRecordTypes.HIP,  TestName = "Rdata_as_written__HIP")]
    public void A_Name_In_The_Rdata_Of_A_Later_Type_Is_Signed_As_Written(String Owner, DNSResourceRecordTypes Type)
    {

        // The other half of the rule, and the half a fix for the first can break:
        // "for all other RR types ... the canonical form is such that no
        // downcasing of embedded domain names takes place" (RFC 3597 §7). LP is
        // RFC 6742 and HIP RFC 8005, both later — BIND signed their names in the
        // case they were written.
        Assert.That(Validate(Owner + Origin, Type), Is.EqualTo(DNSSECValidationResult.Secure),
                    $"{Type} postdates RFC 3597, so its RDATA names keep their case in the canonical form");

    }

    #endregion

}

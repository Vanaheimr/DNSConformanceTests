using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4035 §5.4 and RFC 5155 §8 — authenticated denial of existence.
///
/// <para>
/// This is the half of DNSSEC that covers answers containing nothing. A
/// signature proves data came from the zone; only these records prove data is
/// *absent*. Without checking them a validator cannot distinguish a genuine
/// "no such name" from an attacker who stripped the answer — and it fails open,
/// which is the worst direction for a security mechanism to fail in.
/// </para>
///
/// <para>
/// The NSEC3 chain comes from <c>nsec3.dnssec.test</c>, signed by BIND with
/// <c>-3 aabbccdd -H 12</c>. The salt and iteration count are the ones RFC 5155
/// Appendix A uses, so the hashes in this chain are independently checkable
/// against the published vectors as well as against BIND.
/// </para>
/// </summary>
[TestFixture]
public class DenialOfExistenceTests
{

    private SignedZoneFixture? nsec3Zone;
    private SignedZoneFixture? nsecZone;


    [OneTimeSetUp]
    public void LoadZones()
    {

        if (SignedZoneFixture.IsAvailableFor("nsec3.dnssec.test"))
            nsec3Zone = SignedZoneFixture.Load("nsec3.dnssec.test");

        if (SignedZoneFixture.IsAvailableFor("dnssec.test"))
            nsecZone  = SignedZoneFixture.Load("dnssec.test");

    }

    private SignedZoneFixture Nsec3
        => nsec3Zone ?? throw new IgnoreException("nsec3.dnssec.test is missing — run fixtures/zones/resign.sh (needs WSL + bind9utils).");

    private SignedZoneFixture Nsec
        => nsecZone  ?? throw new IgnoreException("dnssec.test is missing — run fixtures/zones/resign.sh (needs WSL + bind9utils).");


    /// <summary>
    /// A negative response: nothing in the answer section, the denial records in
    /// the authority section. That shape is the point — it is what made the gap
    /// invisible, because the validator only ever looked at answers.
    /// </summary>
    private static DNSInfo DenialResponse(IEnumerable<IDNSResourceRecord> Authorities)

        => new(
               new DNSServerConfig(IPv4Address.Localhost, IPPort.DNS),
               0,
               true, false, true, false,
               DNSResponseCodes.NameError,
               [],
               [.. Authorities],
               [],
               true,
               false,
               TimeSpan.FromSeconds(5),
               TimeSpan.Zero
           );


    #region The_Nsec3_Fixture_Really_Uses_Nsec3()

    [Test]
    public void The_Nsec3_Fixture_Really_Uses_Nsec3()
    {

        // A guard on the fixture, not on Hermod. The sibling zone named
        // "nsec3rsasha1" is signed with *algorithm* 7 and carries plain NSEC
        // records — the name refers to the signature algorithm, not to the
        // denial mechanism. Every assertion below would pass vacuously against
        // a zone that had no NSEC3 records at all.
        Assert.Multiple(() => {
            Assert.That(Nsec3.Records.OfType<NSEC3>().Count(), Is.GreaterThan(3),
                        "the fixture must carry a real NSEC3 chain");
            Assert.That(Nsec3.Records.OfType<NSEC>(),  Is.Empty,
                        "a zone signed with NSEC3 carries no plain NSEC records");
        });

    }

    #endregion

    #region Nsec3_Proves_A_Missing_Name_Does_Not_Exist()

    [Test]
    [Property("RFC", "5155 §8.4")]
    public void Nsec3_Proves_A_Missing_Name_Does_Not_Exist()
    {

        // "nothing-here" is not in the zone, and the zone has no wildcard that
        // could have synthesised it, so the chain must contain a closest-encloser
        // proof plus a record covering the wildcard.
        var verdict = DenialOfExistenceValidator.Verify(
                          DomainName.Parse("nothing-here.nsec3.dnssec.test."),
                          DNSResourceRecordTypes.A,
                          Nsec3.Records
                      );

        Assert.That(verdict, Is.EqualTo(DenialOfExistence.NameDoesNotExist));

    }

    #endregion

    #region Nsec3_Proves_A_Present_Name_Has_No_Record_Of_That_Type()

    [Test]
    [Property("RFC", "5155 §8.5")]
    public void Nsec3_Proves_A_Present_Name_Has_No_Record_Of_That_Type()
    {

        // "a" exists with an A record. Asking for MX must come back as NODATA:
        // an NSEC3 matching the name, with MX absent from its type bitmap.
        var verdict = DenialOfExistenceValidator.Verify(
                          DomainName.Parse("a.nsec3.dnssec.test."),
                          DNSResourceRecordTypes.MX,
                          Nsec3.Records
                      );

        Assert.That(verdict, Is.EqualTo(DenialOfExistence.NoDataForType));

    }

    #endregion

    #region Nsec3_Does_Not_Deny_A_Type_That_Is_Actually_There()

    [Test]
    [Property("RFC", "5155 §8.5")]
    public void Nsec3_Does_Not_Deny_A_Type_That_Is_Actually_There()
    {

        // The critical direction. "a" does have an A record, and its NSEC3 says
        // so. A validator that reported NODATA here would let an attacker delete
        // any record simply by forwarding the zone's own denial records.
        var verdict = DenialOfExistenceValidator.Verify(
                          DomainName.Parse("a.nsec3.dnssec.test."),
                          DNSResourceRecordTypes.A,
                          Nsec3.Records
                      );

        Assert.That(verdict, Is.EqualTo(DenialOfExistence.NotProven),
                    "the bitmap asserts A is present, so nothing about A is being denied");

    }

    #endregion

    #region Nsec3_Denial_Fails_Without_The_Records_That_Prove_It()

    [Test]
    [Property("RFC", "5155 §8.4")]
    public void Nsec3_Denial_Fails_Without_The_Records_That_Prove_It()
    {

        // No NSEC3 at all: an NXDOMAIN with an empty authority section proves
        // nothing, however plausible the rest of the response looks. Stripping
        // the proof is cheaper for an attacker than forging one, so this is the
        // case that has to fail closed.
        Assert.That(DenialOfExistenceValidator.Verify(
                        DomainName.Parse("nothing-here.nsec3.dnssec.test."),
                        DNSResourceRecordTypes.A,
                        Nsec3.Records.Where(r => r is not NSEC3)),
                    Is.EqualTo(DenialOfExistence.NotProven));

    }

    #endregion

    #region Every_Nsec3_Record_Is_Load_Bearing()

    [Test]
    [Property("RFC", "5155 §8.4")]
    public void Every_Nsec3_Record_Is_Load_Bearing()
    {

        // Remove each NSEC3 in turn. The proof for a missing name draws on three
        // records — the closest encloser, the next closer, the wildcard — so at
        // least one removal must break it. If none did, the verifier would be
        // reaching its verdict without consulting the chain.
        var chain   = Nsec3.Records.OfType<NSEC3>().ToArray();
        var broken  = 0;

        foreach (var omitted in chain)
        {

            var verdict = DenialOfExistenceValidator.Verify(
                              DomainName.Parse("nothing-here.nsec3.dnssec.test."),
                              DNSResourceRecordTypes.A,
                              Nsec3.Records.Where(r => !ReferenceEquals(r, omitted))
                          );

            if (verdict != DenialOfExistence.NameDoesNotExist)
                broken++;

        }

        Assert.That(broken, Is.GreaterThan(0),
                    "removing any single NSEC3 left the proof intact, which means it was never checked");

    }

    #endregion

    #region Nsec_Proves_A_Missing_Name_Does_Not_Exist()

    [Test]
    [Property("RFC", "4035 §5.4")]
    public void Nsec_Proves_A_Missing_Name_Does_Not_Exist()
    {

        // The same claim over the older mechanism: dnssec.test is signed with
        // plain NSEC, so the proof is "this name sorts inside a gap, and so does
        // the wildcard that could have covered it".
        var verdict = DenialOfExistenceValidator.Verify(
                          DomainName.Parse("nothing-here.dnssec.test."),
                          DNSResourceRecordTypes.A,
                          Nsec.Records
                      );

        Assert.That(verdict, Is.EqualTo(DenialOfExistence.NameDoesNotExist));

    }

    #endregion

    #region Nsec_Proves_A_Present_Name_Has_No_Record_Of_That_Type()

    [Test]
    [Property("RFC", "4035 §5.4")]
    public void Nsec_Proves_A_Present_Name_Has_No_Record_Of_That_Type()
    {

        var verdict = DenialOfExistenceValidator.Verify(
                          DomainName.Parse("a.dnssec.test."),
                          DNSResourceRecordTypes.MX,
                          Nsec.Records
                      );

        Assert.That(verdict, Is.EqualTo(DenialOfExistence.NoDataForType));

    }

    #endregion

    #region Nsec_Does_Not_Deny_A_Type_That_Is_Actually_There()

    [Test]
    [Property("RFC", "4035 §5.4")]
    public void Nsec_Does_Not_Deny_A_Type_That_Is_Actually_There()
    {

        var verdict = DenialOfExistenceValidator.Verify(
                          DomainName.Parse("a.dnssec.test."),
                          DNSResourceRecordTypes.A,
                          Nsec.Records
                      );

        Assert.That(verdict, Is.EqualTo(DenialOfExistence.NotProven));

    }

    #endregion

    #region Validator_Reports_A_Proven_Denial_As_Secure()

    [Test]
    [Property("RFC", "4035 §5.4")]
    public async Task Validator_Reports_A_Proven_Denial_As_Secure()
    {

        // The end-to-end path, and the one that was missing: DNSSECValidator
        // used to return Insecure for any response whose *answer* section held
        // no RRSIG. A negative answer has an empty answer section by definition,
        // so every NXDOMAIN was waved through as "unsigned zone" without the
        // proof ever being looked at.
        var validator = new DNSSECValidator(
                            new StubDnsClient().Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, [.. Nsec.DnsKeys]),
                            [Nsec.DelegationSigner]
                        );

        var result    = await validator.ValidateAsync(
                                  DenialResponse(Nsec.Records),
                                  (DomainName.Parse("nothing-here.dnssec.test."), DNSResourceRecordTypes.A)
                              );

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure));

    }

    #endregion

    #region Validator_Reports_A_Stripped_Denial_As_Bogus()

    [Test]
    [Property("RFC", "4035 §5.4")]
    public async Task Validator_Reports_A_Stripped_Denial_As_Bogus()
    {

        // An attacker who removes the NSEC records leaves a response that still
        // looks like a valid NXDOMAIN. Fail-closed is the whole point.
        var validator = new DNSSECValidator(
                            new StubDnsClient().Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, [.. Nsec.DnsKeys]),
                            [Nsec.DelegationSigner]
                        );

        var stripped  = Nsec.Records.Where(r => r is not NSEC).ToArray();

        var result    = await validator.ValidateAsync(
                                  DenialResponse(stripped),
                                  (DomainName.Parse("nothing-here.dnssec.test."), DNSResourceRecordTypes.A)
                              );

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "a denial with its proof removed must not be believed");

    }

    #endregion

    #region Canonical_Ordering_Is_By_Label_From_The_Right()

    [Test]
    [Property("RFC", "4034 §6.1")]
    public void Canonical_Ordering_Is_By_Label_From_The_Right()
    {

        // RFC 4034 §6.1 publishes this list already in canonical order, so the
        // assertion is simply that the comparator agrees with it. Two entries of
        // the RFC's list are omitted — "\001.z.example" and "\200.z.example" —
        // because they carry escaped non-printable octets, and this comparator
        // takes presentation strings rather than wire labels.
        //
        // Note it is emphatically not string ordering: "z.example" sorts *after*
        // "zABC.a.EXAMPLE" because comparison starts at the rightmost label.
        // Getting that wrong makes NSEC spans appear to cover names they do not,
        // which is precisely how a forged denial would slip through.
        String[] canonical = [
            "example.",
            "a.example.",
            "yljkjljk.a.example.",
            "Z.a.example.",
            "zABC.a.EXAMPLE.",
            "z.example.",
            "*.z.example."
        ];

        Assert.Multiple(() => {

            for (var i = 0; i + 1 < canonical.Length; i++)
                Assert.That(DenialOfExistenceValidator.CompareCanonical(canonical[i], canonical[i + 1]),
                            Is.LessThan(0),
                            $"RFC 4034 §6.1 orders '{canonical[i]}' before '{canonical[i + 1]}'");

            // §6.1 also makes the comparison case-insensitive, so a name cannot
            // be moved out of an NSEC span by changing its capitalisation.
            Assert.That(DenialOfExistenceValidator.CompareCanonical("A.EXAMPLE.", "a.example."),
                        Is.Zero);

        });

    }

    #endregion

}

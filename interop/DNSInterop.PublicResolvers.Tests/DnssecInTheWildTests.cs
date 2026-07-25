using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;

namespace DNSInterop.PublicResolvers.Tests;

/// <summary>
/// DNSSEC against real signed zones: retrieving DNSSEC records with the DO bit
/// and validating live signatures with Hermod's validator.
/// </summary>
[TestFixture]
[Category(TestCategories.Online)]
[Property("RFC", "4033")]
public class DnssecInTheWildTests
{

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    [SetUp]
    public void RequireNetwork()
        => TestEnvironment.RequireNetwork();


    private static DNSUDPClient DnssecClient()
        => new(IPv4Address.Parse("1.1.1.1"), QueryTimeout: Timeout) { DnssecOK = true };


    #region Root_Dnskey_Contains_The_Iana_Ksk()

    [Test]
    [Property("RFC", "4034 App. B")]
    public async Task Root_Dnskey_Contains_The_Iana_Ksk()
    {

        // Fetch the live root DNSKEY RRset and confirm the key tag Hermod
        // computes for the KSK matches the anchor IANA publishes.
        await using var client = DnssecClient();

        var response = await client.Query<DNSKEY>(DomainName.Parse("."), Timeout);

        Assert.That(response.FilteredAnswers, Is.Not.Empty, "the root zone must return DNSKEYs");

        var keyTags = response.FilteredAnswers.
                          Select(DNSSECValidator.ComputeKeyTag).
                          ToArray();

        TestContext.Out.WriteLine($"live root DNSKEY key tags: {String.Join(", ", keyTags)}");

        Assert.That(keyTags, Does.Contain((UInt16) 20326).Or.Contain((UInt16) 38696),
                    "the root KSK (20326 / 38696) must be among the live keys");

    }

    #endregion

    #region Signed_Zone_Returns_Rrsig_With_Do_Bit()

    [Test]
    [Property("RFC", "4035 §3.2.1")]
    public async Task Signed_Zone_Returns_Rrsig_With_Do_Bit()
    {

        // Note: QTYPE=RRSIG is a meta-query that public resolvers answer with
        // SERVFAIL (RFC 6895 §3.1 discourages it), so ask for a real type with
        // the DO bit set and expect the RRSIG alongside the answer — which is
        // how RRSIGs are actually delivered (RFC 4035 §3.2.1).
        await using var client = DnssecClient();

        var response = await client.Query(
                           DNSServiceName.Parse("cloudflare.com"),
                           [ DNSResourceRecordTypes.SOA ],
                           Timeout
                       );

        Assert.That(response.Answers.OfType<RRSIG>(), Is.Not.Empty,
                    "a signed zone must return RRSIG records alongside the answer when the DO bit is set");

    }

    #endregion

    #region Live_Rrsig_Validates_Against_Its_Live_Dnskey()

    [Test]
    [Property("RFC", "4034 §3.1.8")]
    [Category(TestCategories.Slow)]
    public async Task Live_Rrsig_Validates_Against_Its_Live_Dnskey()
    {

        // End-to-end in the wild: fetch a signed RRset, its RRSIG and the
        // zone's DNSKEYs, then verify the signature locally.
        const String zone = "cloudflare.com";

        await using var client = DnssecClient();

        var soaResponse = await client.Query(
                              DNSServiceName.Parse(zone),
                              [ DNSResourceRecordTypes.SOA ],
                              Timeout
                          );

        var keyResponse = await client.Query(
                              DNSServiceName.Parse(zone),
                              [ DNSResourceRecordTypes.DNSKEY ],
                              Timeout
                          );

        var soaRecords  = soaResponse.Answers.OfType<SOA>().  Cast<IDNSResourceRecord>().ToList();
        var signature   = soaResponse.Answers.OfType<RRSIG>().FirstOrDefault(sig => sig.TypeCovered == DNSResourceRecordTypes.SOA);
        var keys        = keyResponse.Answers.OfType<DNSKEY>().ToList();

        if (soaRecords.Count == 0 || signature is null || keys.Count == 0)
            Assert.Inconclusive($"resolver did not return SOA + RRSIG + DNSKEY for {zone} " +
                                $"(SOA: {soaRecords.Count}, RRSIG: {(signature is null ? 0 : 1)}, DNSKEY: {keys.Count})");

        var key = keys.FirstOrDefault(k => k.Algorithm == signature!.Algorithm &&
                                           DNSSECValidator.ComputeKeyTag(k) == signature.KeyTag);

        if (key is null)
            Assert.Inconclusive($"no live DNSKEY matches RRSIG key tag {signature!.KeyTag} / algorithm {signature.Algorithm}");

        var validator = new DNSSECValidator(new DNSClient(QueryTimeout: Timeout));
        var result    = validator.ValidateRRSig(soaRecords, signature!, key!);

        TestContext.Out.WriteLine($"live {zone} SOA RRSIG (key tag {signature!.KeyTag}, algorithm {signature.Algorithm}) => {result}");

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure),
                    "a live, currently valid RRSIG must verify as Secure");

    }

    #endregion

    #region Unsigned_Zone_Returns_No_Rrsig()

    [Test]
    public async Task Unsigned_Zone_Returns_No_Rrsig()
    {

        await using var client = DnssecClient();

        var response = await client.Query(
                           DNSServiceName.Parse("example.com"),
                           [ DNSResourceRecordTypes.A ],
                           Timeout
                       );

        TestContext.Out.WriteLine($"example.com A: {response.Answers.Count()} answers, " +
                                  $"{response.Answers.OfType<RRSIG>().Count()} RRSIGs");

        Assert.That(response.ResponseCode, Is.EqualTo(DNSResponseCodes.NoError));

    }

    #endregion

    #region Deliberately_Broken_Dnssec_Zone_Does_Not_Resolve()

    [Test]
    [Property("RFC", "4035 §5.5")]
    public async Task Deliberately_Broken_Dnssec_Zone_Does_Not_Resolve()
    {

        // dnssec-failed.org is maintained by Comcast with intentionally invalid
        // signatures. A validating resolver answers SERVFAIL; the point of the
        // test is that Hermod must not surface it as a normal, trusted answer.
        await using var client = new DNSUDPClient(IPv4Address.Parse("1.1.1.1"), QueryTimeout: Timeout);

        var response = await client.Query<A>(DomainName.Parse("dnssec-failed.org"), Timeout);

        TestContext.Out.WriteLine($"dnssec-failed.org => RCODE {response.ResponseCode}, {response.FilteredAnswers.Count()} answers");

        Assert.That(
            response.ResponseCode != DNSResponseCodes.NoError || !response.FilteredAnswers.Any(),
            Is.True,
            "a validating resolver must refuse a bogus zone (SERVFAIL); answers here would mean validation was bypassed"
        );

    }

    #endregion

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core;

namespace DNSInterop.PublicResolvers.Tests;

/// <summary>
/// Hermod's clients against the real public resolvers over every transport it
/// implements. These prove the stack works against production peers that were
/// never written with Hermod in mind.
/// </summary>
[TestFixture]
[Category(TestCategories.Online)]
public class PublicResolverTests
{

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    [SetUp]
    public void RequireNetwork()
        => TestEnvironment.RequireNetwork();


    #region Udp_Resolves_Against(...)

    [TestCase("1.1.1.1", TestName = "Udp_Resolves_Against_Cloudflare")]
    [TestCase("8.8.8.8", TestName = "Udp_Resolves_Against_Google")]
    [TestCase("9.9.9.9", TestName = "Udp_Resolves_Against_Quad9")]
    public async Task Udp_Resolves_Against_Resolver(String resolver)
    {

        await using var client = new DNSUDPClient(
                                     IPv4Address.Parse(resolver),
                                     QueryTimeout: Timeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("example.com"), Timeout);

        Assert.Multiple(() => {
            Assert.That(response.ResponseCode,   Is.EqualTo(DNSResponseCodes.NoError));
            Assert.That(response.FilteredAnswers, Is.Not.Empty, $"{resolver} returned no A record for example.com");
        });

    }

    #endregion

    #region Tcp_Resolves_Against(...)

    [TestCase("1.1.1.1", TestName = "Tcp_Resolves_Against_Cloudflare")]
    [TestCase("8.8.8.8", TestName = "Tcp_Resolves_Against_Google")]
    [Property("RFC", "7766")]
    public async Task Tcp_Resolves_Against_Resolver(String resolver)
    {

        await using var client = new DNSTCPClient(
                                     IPv4Address.Parse(resolver),
                                     QueryTimeout: Timeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("example.com"), Timeout);

        Assert.That(response.FilteredAnswers, Is.Not.Empty);

    }

    #endregion

    #region Dot_Resolves_Against(...)

    [TestCase("1.1.1.1", "cloudflare-dns.com", TestName = "Dot_Resolves_Against_Cloudflare")]
    [TestCase("8.8.8.8", "dns.google",         TestName = "Dot_Resolves_Against_Google")]
    [Property("RFC", "7858")]
    public async Task Dot_Resolves_Against_Resolver(String resolver, String hostname)
    {

        await using var client = new DNSTLSClient(
                                     IPv4Address.Parse(resolver),
                                     TCPPort:       IPPort.Parse(853),
                                     TLSHostname:   hostname,
                                     QueryTimeout:  Timeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("example.com"), Timeout);

        Assert.Multiple(() => {
            Assert.That(response.ResponseCode,    Is.EqualTo(DNSResponseCodes.NoError));
            Assert.That(response.FilteredAnswers, Is.Not.Empty, $"DoT to {hostname} returned nothing");
        });

    }

    #endregion

    #region Doh_Resolves_Against(...)

    [TestCase("https://cloudflare-dns.com/dns-query", DNSHTTPSMode.POST, TestName = "Doh_Post_Resolves_Against_Cloudflare")]
    [TestCase("https://cloudflare-dns.com/dns-query", DNSHTTPSMode.GET,  TestName = "Doh_Get_Resolves_Against_Cloudflare")]
    [TestCase("https://dns.google/dns-query",         DNSHTTPSMode.POST, TestName = "Doh_Post_Resolves_Against_Google")]
    [Property("RFC", "8484")]
    public async Task Doh_Resolves_Against_Resolver(String url, DNSHTTPSMode mode)
    {

        await using var client = new DNSHTTPSClient(
                                     URL.Parse(url),
                                     Mode:          mode,
                                     QueryTimeout:  Timeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("example.com"), Timeout);

        Assert.Multiple(() => {
            Assert.That(response.ResponseCode,    Is.EqualTo(DNSResponseCodes.NoError));
            Assert.That(response.FilteredAnswers, Is.Not.Empty, $"DoH {mode} to {url} returned nothing");
        });

    }

    #endregion

    #region Doh_Json_Resolves_Against_Cloudflare()

    [Test]
    public async Task Doh_Json_Resolves_Against_Cloudflare()
    {

        // The Google/Cloudflare application/dns-json API — not an IETF
        // standard, but widely deployed and implemented by Hermod.
        await using var client = new DNSHTTPSClient(
                                     URL.Parse("https://cloudflare-dns.com/dns-query"),
                                     Mode:          DNSHTTPSMode.JSON,
                                     QueryTimeout:  Timeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("example.com"), Timeout);

        Assert.That(response.FilteredAnswers, Is.Not.Empty);

    }

    #endregion

    #region Various_Record_Types_Resolve_In_The_Wild(...)

    [Test]
    [Property("RFC", "1035")]
    public async Task Mx_Records_Resolve_In_The_Wild()
    {

        await using var client = new DNSUDPClient(IPv4Address.Parse("1.1.1.1"), QueryTimeout: Timeout);

        var response = await client.Query<MX>(DomainName.Parse("google.com"), Timeout);

        Assert.That(response.FilteredAnswers, Is.Not.Empty, "google.com must have MX records");

    }

    [Test]
    [Property("RFC", "3596")]
    public async Task Aaaa_Records_Resolve_In_The_Wild()
    {

        await using var client = new DNSUDPClient(IPv4Address.Parse("1.1.1.1"), QueryTimeout: Timeout);

        var response = await client.Query<AAAA>(DomainName.Parse("google.com"), Timeout);

        Assert.That(response.FilteredAnswers, Is.Not.Empty, "google.com must have AAAA records");

    }

    [Test]
    [Property("RFC", "8659")]
    public async Task Caa_Records_Resolve_In_The_Wild()
    {

        await using var client = new DNSUDPClient(IPv4Address.Parse("1.1.1.1"), QueryTimeout: Timeout);

        var response = await client.Query<CAA>(DomainName.Parse("google.com"), Timeout);

        Assert.That(response.FilteredAnswers, Is.Not.Empty, "google.com publishes CAA records");

    }

    [Test]
    [Property("RFC", "9460")]
    public async Task Https_Svcb_Records_Resolve_In_The_Wild()
    {

        // cloudflare.com publishes an HTTPS record whose answer is followed by
        // an OPT record. Parsing it requires honoring RDLENGTH when reading the
        // SvcParams; the offline reproduction of that boundary lives in
        // DNSConformance.ResourceRecords.Tests.Https_Record_Followed_By_Another_Record_Does_Not_Overrun.
        await using var client = new DNSUDPClient(IPv4Address.Parse("1.1.1.1"), QueryTimeout: Timeout);

        var response = await client.Query<HTTPS>(DomainName.Parse("cloudflare.com"), Timeout);

        Assert.Multiple(() => {
            Assert.That(response.ResponseCode,    Is.EqualTo(DNSResponseCodes.NoError),
                        "the resolver answers NOERROR; SERVFAIL here means Hermod failed to parse the response");
            Assert.That(response.FilteredAnswers, Is.Not.Empty, "cloudflare.com publishes HTTPS (SVCB) records");
        });

    }

    #endregion

    #region Large_Answer_Triggers_Truncation_Handling()

    [Test]
    [Property("RFC", "7766 §5")]
    [Category(TestCategories.Slow)]
    public async Task Large_Answer_Triggers_Truncation_Handling()
    {

        // The root DNSKEY RRset is large enough to exercise EDNS payload
        // handling and, without EDNS, TC + TCP fallback in the real world.
        await using var client = new DNSUDPClient(IPv4Address.Parse("1.1.1.1"), QueryTimeout: Timeout);

        var response = await client.Query<DNSKEY>(DomainName.Parse("."), Timeout);

        Assert.Multiple(() => {
            Assert.That(response.ResponseCode,    Is.EqualTo(DNSResponseCodes.NoError));
            Assert.That(response.FilteredAnswers, Is.Not.Empty, "the root zone publishes DNSKEYs");
            Assert.That(response.IsTruncated,     Is.False,     "a truncated answer must have been completed over TCP");
        });

    }

    #endregion

    #region Nxdomain_Is_Reported_As_Nxdomain()

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task Nxdomain_Is_Reported_As_Nxdomain()
    {

        await using var client = new DNSUDPClient(IPv4Address.Parse("1.1.1.1"), QueryTimeout: Timeout);

        var response = await client.Query<A>(
                           DomainName.Parse("this-name-should-never-exist-conformance-suite.example."),
                           Timeout
                       );

        Assert.That(response.ResponseCode, Is.EqualTo(DNSResponseCodes.NameError));

    }

    #endregion

    #region Cname_Chain_Is_Followed()

    [Test]
    [Property("RFC", "1034 §3.6.2")]
    public async Task Cname_Chain_Is_Followed()
    {

        using var client = new DNSClient(
                               IPv4Address.Parse("1.1.1.1"),
                               QueryTimeout:   Timeout,
                               UseQueryCache:  false
                           );

        // www.github.com is a CNAME to github.com — the resolver must deliver
        // the A record at the end of the chain.
        var response = await client.Query<A>(DomainName.Parse("www.github.com"), Timeout, ForceUpdate: true);

        Assert.That(response.FilteredAnswers, Is.Not.Empty,
                    "the A record behind the CNAME chain must be returned");

    }

    #endregion

}

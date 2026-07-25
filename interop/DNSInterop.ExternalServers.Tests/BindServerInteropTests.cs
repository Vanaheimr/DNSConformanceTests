using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSInterop.ExternalServers.Tests;

/// <summary>
/// The mirror image of the LinuxTools project: here Hermod is the *client* and
/// ISC BIND is the server. Everything Hermod parses was produced by the
/// reference implementation of the DNS.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
public class BindServerInteropTests
{

    private BindServerFixture bind = null!;

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);


    [OneTimeSetUp]
    public async Task StartBind()
    {

        TestEnvironment.RequireWsl("named", "dig");

        try
        {
            bind = await BindServerFixture.StartAsync();
        }
        catch (Exception e)
        {
            Assert.Ignore($"Could not start BIND inside WSL: {e.Message}");
        }

    }

    [OneTimeTearDown]
    public async Task StopBind()
    {
        if (bind is not null)
            await bind.DisposeAsync();
    }


    private DNSUDPClient UdpClient()
        => new(IPv4Address.Parse(bind.Address), IPPort.Parse(bind.Port), QueryTimeout: Timeout);

    private DNSTCPClient TcpClient()
        => new(IPv4Address.Parse(bind.Address), Port: IPPort.Parse(bind.Port), QueryTimeout: Timeout);


    #region Hermod_Reads_An_A_Record_From_Bind()

    [Test]
    public async Task Hermod_Reads_An_A_Record_From_Bind()
    {

        await using var client = UdpClient();

        var response = await client.Query<A>(DomainName.Parse("a.interop.test"), Timeout);

        Assert.Multiple(() => {
            Assert.That(response.ResponseCode, Is.EqualTo(DNSResponseCodes.NoError));
            Assert.That(response.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("192.0.2.1")));
        });

    }

    #endregion

    #region Hermod_Reads_Multiple_A_Records_From_Bind()

    [Test]
    public async Task Hermod_Reads_Multiple_A_Records_From_Bind()
    {

        // BIND emits these with name compression, so this also exercises
        // Hermod's compression-pointer decoding against a real encoder.
        await using var client = UdpClient();

        var response  = await client.Query<A>(DomainName.Parse("multi.interop.test"), Timeout);
        var addresses = response.FilteredAnswers.Select(a => a.IPv4Address.ToString()).Order().ToArray();

        Assert.That(addresses, Is.EqualTo(new[] { "192.0.2.10", "192.0.2.11", "192.0.2.12" }));

    }

    #endregion

    #region Hermod_Reads_Record_Type_From_Bind(...)

    [Test]
    public async Task Hermod_Reads_Aaaa_From_Bind()
    {

        await using var client = UdpClient();

        var response = await client.Query<AAAA>(DomainName.Parse("aaaa.interop.test"), Timeout);

        // Compare parsed addresses, not their text: Hermod renders the fully
        // expanded form (2001:0db8:...:0001), which is equally correct.
        var expected = System.Net.IPAddress.Parse("2001:db8::1");
        var actual   = System.Net.IPAddress.Parse(response.FilteredAnswers.Single().IPv6Address.ToString());

        Assert.That(actual, Is.EqualTo(expected));

    }

    [Test]
    public async Task Hermod_Reads_Mx_From_Bind()
    {

        await using var client = UdpClient();

        var response  = await client.Query<MX>(DomainName.Parse("mx.interop.test"), Timeout);
        var exchanges = response.FilteredAnswers.
                            Select(mx => (mx.Preference, mx.Exchange.FullName.TrimEnd('.').ToLowerInvariant())).
                            Order().
                            ToArray();

        Assert.That(exchanges, Is.EqualTo(new[] {
            ((UInt16) 10, "mail1.interop.test"),
            ((UInt16) 20, "mail2.interop.test")
        }));

    }

    [Test]
    public async Task Hermod_Reads_Txt_From_Bind()
    {

        await using var client = UdpClient();

        var response = await client.Query<TXT>(DomainName.Parse("txt.interop.test"), Timeout);

        Assert.That(response.FilteredAnswers.Single().Text, Is.EqualTo("hello from BIND"));

    }

    [Test]
    public async Task Hermod_Reads_Srv_From_Bind()
    {

        await using var client = UdpClient();

        var response = await client.Query<SRV>(DNSServiceName.Parse("_dns._udp.interop.test"), Timeout);
        var srv      = response.FilteredAnswers.Single();

        Assert.Multiple(() => {
            Assert.That(srv.Priority,                          Is.EqualTo((UInt16) 10));
            Assert.That(srv.Weight,                            Is.EqualTo((UInt16) 60));
            Assert.That(srv.Port.ToUInt16(),                   Is.EqualTo((UInt16) 5353));
            Assert.That(srv.Target.FullName.TrimEnd('.'),      Is.EqualTo("ns1.interop.test").IgnoreCase);
        });

    }

    [Test]
    public async Task Hermod_Reads_Soa_From_Bind()
    {

        await using var client = UdpClient();

        var response = await client.Query<SOA>(DomainName.Parse("interop.test"), Timeout);
        var soa      = response.FilteredAnswers.Single();

        Assert.Multiple(() => {
            Assert.That(soa.Serial,                        Is.EqualTo(2026072501u));
            Assert.That(soa.Server.FullName.TrimEnd('.'),  Is.EqualTo("ns1.interop.test").IgnoreCase);
            Assert.That(soa.Refresh,                       Is.EqualTo(TimeSpan.FromSeconds(7200)));
        });

    }

    [Test]
    public async Task Hermod_Reads_Caa_From_Bind()
    {

        await using var client = UdpClient();

        var response = await client.Query<CAA>(DomainName.Parse("caa.interop.test"), Timeout);
        var caa      = response.FilteredAnswers.Single();

        Assert.Multiple(() => {
            Assert.That(caa.Tag,   Is.EqualTo("issue"));
            Assert.That(caa.Value, Is.EqualTo("letsencrypt.org"));
        });

    }

    [Test]
    public async Task Hermod_Reads_Tlsa_From_Bind()
    {

        await using var client = UdpClient();

        var response = await client.Query<TLSA>(DomainName.Parse("tlsa.interop.test"), Timeout);
        var tlsa     = response.FilteredAnswers.Single();

        Assert.Multiple(() => {
            Assert.That(tlsa.CertificateUsage, Is.EqualTo((Byte) 3));
            Assert.That(tlsa.Selector,         Is.EqualTo((Byte) 1));
            Assert.That(tlsa.MatchingType,     Is.EqualTo((Byte) 1));
        });

    }

    #endregion

    #region Hermod_Follows_A_Cname_Served_By_Bind()

    [Test]
    [Property("RFC", "1034 §3.6.2")]
    public async Task Hermod_Follows_A_Cname_Served_By_Bind()
    {

        // BIND returns the CNAME plus the target's A record in one answer.
        using var client = new DNSClient(
                               IPv4Address.Parse(bind.Address),
                               Port:           IPPort.Parse(bind.Port),
                               QueryTimeout:   Timeout,
                               UseQueryCache:  false
                           );

        var response = await client.Query<A>(DomainName.Parse("alias.interop.test"), Timeout, ForceUpdate: true);

        Assert.That(response.FilteredAnswers.Any(a => a.IPv4Address == IPv4Address.Parse("192.0.2.1")),
                    Is.True,
                    "the A record behind the CNAME must be surfaced");

    }

    #endregion

    #region Hermod_Gets_Nxdomain_From_Bind()

    [Test]
    public async Task Hermod_Gets_Nxdomain_From_Bind()
    {

        await using var client = UdpClient();

        var response = await client.Query<A>(DomainName.Parse("nothing-here.interop.test"), Timeout);

        Assert.That(response.ResponseCode, Is.EqualTo(DNSResponseCodes.NameError));

    }

    #endregion

    #region Hermod_Reads_From_Bind_Over_Tcp()

    [Test]
    [Property("RFC", "7766")]
    public async Task Hermod_Reads_From_Bind_Over_Tcp()
    {

        await using var client = TcpClient();

        var response = await client.Query<A>(DomainName.Parse("a.interop.test"), Timeout);

        Assert.That(response.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("192.0.2.1")));

    }

    #endregion

    #region Hermod_Handles_A_MultiString_Txt_From_Bind()

    [Test]
    [Property("RFC", "1035 §3.3.14")]
    public async Task Hermod_Handles_A_MultiString_Txt_From_Bind()
    {

        // big.interop.test holds two character-strings; BIND serves them in one
        // TXT RDATA. A parser reading only the first loses the remainder.
        await using var client = TcpClient();

        var response = await client.Query<TXT>(DomainName.Parse("big.interop.test"), Timeout);

        Assert.That(response.FilteredAnswers, Is.Not.Empty, "BIND serves the TXT record");

        var text = response.FilteredAnswers.Single().Text;

        TestContext.Out.WriteLine($"received {text.Length} characters of TXT data");

        Assert.That(text, Does.Contain("and a second character-string"),
                    "all character-strings of the TXT RDATA must be surfaced");

    }

    #endregion

}

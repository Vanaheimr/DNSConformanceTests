using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSInterop.ExternalServers.Tests;

/// <summary>
/// The same interop zone, served by three implementations that are not BIND and
/// not Hermod, with Hermod as the client throughout.
/// </summary>
/// <remarks>
/// <para>
/// `BindServerInteropTests` already asks whether Hermod can read what the
/// reference implementation writes. This asks the more useful question: whether
/// what it reads is a property of the *protocol* or a property of BIND. Four
/// encoders — BIND, Knot, CoreDNS and Unbound — putting the same zone file onto
/// the wire disagree in exactly the places the RFCs leave open, and agreeing
/// across all four is what makes a reading trustworthy.
/// </para>
/// <para>
/// The zone is BIND's own fixture, byte for byte. That is deliberate: a
/// difference in the answers can then only come from the server, never from
/// the data.
/// </para>
/// </remarks>
[TestFixture(ForeignServer.Knot)]
[TestFixture(ForeignServer.CoreDNS)]
[TestFixture(ForeignServer.Unbound)]
[Category(TestCategories.Docker)]
public class ForeignServerInteropTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    private readonly ForeignServer   server;
    private ForeignServerFixture     fixture = null!;

    public ForeignServerInteropTests(ForeignServer Server)
    {
        this.server = Server;
    }

    #endregion

    #region Setup

    [OneTimeSetUp]
    public async Task StartServer()
    {

        if (!Wsl.IsAvailable)
            Assert.Ignore("No POSIX shell available — skipping.");

        if (!ForeignServerFixture.IsAvailable(server))
            Assert.Ignore($"{server} is not runnable here. Needs a Docker daemon and the image: " +
                          $"`docker pull {ForeignServerFixture.Image(server)}`.");

        try
        {
            fixture = await ForeignServerFixture.StartAsync(server);
        }
        catch (Exception e)
        {
            Assert.Fail($"Could not start {server}: {e.Message}");
        }

    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (fixture is not null)
            await fixture.DisposeAsync();
    }


    private DNSUDPClient UdpClient()
        => new (IPv4Address.Parse(fixture.Address), IPPort.Parse(fixture.Port), QueryTimeout: Timeout);

    private DNSTCPClient TcpClient()
        => new (IPv4Address.Parse(fixture.Address), Port: IPPort.Parse(fixture.Port), QueryTimeout: Timeout);

    #endregion


    #region Hermod_Reads_An_A_Record()

    [Test]
    public async Task Hermod_Reads_An_A_Record()
    {

        await using var client = UdpClient();

        var response = await client.Query<A>(DomainName.Parse("a.interop.test"), Timeout);

        Assert.Multiple(() => {
            Assert.That(response.ResponseCode,                        Is.EqualTo(DNSResponseCodes.NoError));
            Assert.That(response.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("192.0.2.1")));
        });

    }

    #endregion

    #region Hermod_Reads_An_Rrset_Of_Three()

    [Test]
    public async Task Hermod_Reads_An_Rrset_Of_Three()
    {

        // Ordering within an RRset is the server's business — several rotate it
        // deliberately — so the comparison is of sets, not sequences.
        await using var client = UdpClient();

        var response  = await client.Query<A>(DomainName.Parse("multi.interop.test"), Timeout);
        var addresses = response.FilteredAnswers.Select(a => a.IPv4Address.ToString()).Order().ToArray();

        Assert.That(addresses, Is.EqualTo(new[] { "192.0.2.10", "192.0.2.11", "192.0.2.12" }));

    }

    #endregion

    #region Hermod_Reads_Aaaa()

    [Test]
    public async Task Hermod_Reads_Aaaa()
    {

        await using var client = UdpClient();

        var response = await client.Query<AAAA>(DomainName.Parse("aaaa.interop.test"), Timeout);

        // Compared as an address rather than as text: Hermod renders IPv6 in the
        // long form, and whether it compresses runs of zeroes is a question about
        // its formatter, not about what the three servers put on the wire.
        Assert.That(response.FilteredAnswers.Single().IPv6Address,
                    Is.EqualTo(IPv6Address.Parse("2001:db8::1")));

    }

    #endregion

    #region Hermod_Reads_Mx_In_Priority_Order()

    [Test]
    public async Task Hermod_Reads_Mx_In_Priority_Order()
    {

        await using var client = UdpClient();

        var response = await client.Query<MX>(DomainName.Parse("mx.interop.test"), Timeout);
        var byPref   = response.FilteredAnswers.OrderBy(mx => mx.Preference).ToArray();

        Assert.Multiple(() => {
            Assert.That(byPref,                                 Has.Length.EqualTo(2));
            Assert.That(byPref[0].Preference,                   Is.EqualTo((UInt16) 10));
            Assert.That(byPref[0].Exchange.FullName.TrimEnd('.'), Is.EqualTo("mail1.interop.test").IgnoreCase);
            Assert.That(byPref[1].Preference,                   Is.EqualTo((UInt16) 20));
            Assert.That(byPref[1].Exchange.FullName.TrimEnd('.'), Is.EqualTo("mail2.interop.test").IgnoreCase);
        });

    }

    #endregion

    #region Hermod_Reads_Txt()

    [Test]
    public async Task Hermod_Reads_Txt()
    {

        await using var client = UdpClient();

        var response = await client.Query<TXT>(DomainName.Parse("txt.interop.test"), Timeout);

        Assert.That(response.FilteredAnswers.Single().Text, Is.EqualTo("hello from BIND"));

    }

    #endregion

    #region Hermod_Reads_Srv()

    [Test]
    public async Task Hermod_Reads_Srv()
    {

        await using var client = UdpClient();

        var response = await client.Query<SRV>(DNSServiceName.Parse("_dns._udp.interop.test"), Timeout);
        var srv      = response.FilteredAnswers.Single();

        Assert.Multiple(() => {
            Assert.That(srv.Priority,                     Is.EqualTo((UInt16) 10));
            Assert.That(srv.Weight,                       Is.EqualTo((UInt16) 60));
            Assert.That(srv.Port.ToUInt16(),              Is.EqualTo((UInt16) 5353));
            Assert.That(srv.Target.FullName.TrimEnd('.'), Is.EqualTo("ns1.interop.test").IgnoreCase);
        });

    }

    #endregion

    #region Hermod_Reads_Soa()

    [Test]
    public async Task Hermod_Reads_Soa()
    {

        await using var client = UdpClient();

        var response = await client.Query<SOA>(DomainName.Parse("interop.test"), Timeout);
        var soa      = response.FilteredAnswers.Single();

        Assert.Multiple(() => {
            Assert.That(soa.Serial,                       Is.EqualTo(2026072501u));
            Assert.That(soa.Server.FullName.TrimEnd('.'), Is.EqualTo("ns1.interop.test").IgnoreCase);
            Assert.That(soa.Refresh,                      Is.EqualTo(TimeSpan.FromSeconds(7200)));
        });

    }

    #endregion

    #region Hermod_Reads_Caa()

    [Test]
    public async Task Hermod_Reads_Caa()
    {

        await using var client = UdpClient();

        var response = await client.Query<CAA>(DomainName.Parse("caa.interop.test"), Timeout);
        var caa      = response.FilteredAnswers.Single();

        Assert.Multiple(() => {
            Assert.That(caa.Tag,   Is.EqualTo("issue"));
            Assert.That(caa.Value, Is.EqualTo("letsencrypt.org"));
        });

    }

    #endregion

    #region Hermod_Gets_Nxdomain()

    [Test]
    public async Task Hermod_Gets_Nxdomain()
    {

        await using var client = UdpClient();

        var response = await client.Query<A>(DomainName.Parse("nothing-here.interop.test"), Timeout);

        Assert.That(response.ResponseCode, Is.EqualTo(DNSResponseCodes.NameError));

    }

    #endregion

    #region Hermod_Reads_The_Same_Record_Over_Tcp()

    [Test]
    public async Task Hermod_Reads_The_Same_Record_Over_Tcp()
    {

        // RFC 7766 makes TCP mandatory for every DNS implementation, and the
        // framing is the one thing all four of these have to agree on before any
        // of the rest matters.
        await using var client = TcpClient();

        var response = await client.Query<A>(DomainName.Parse("a.interop.test"), Timeout);

        Assert.That(response.FilteredAnswers.Single().IPv4Address, Is.EqualTo(IPv4Address.Parse("192.0.2.1")));

    }

    #endregion

}

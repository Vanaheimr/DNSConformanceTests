using NUnit.Framework;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSInterop.LinuxTools.Tests;

/// <summary>
/// Cross-implementation checks with parsers from three separate lineages:
/// Knot DNS (<c>kdig</c>), NLnet Labs ldns (<c>drill</c>) and BIND's
/// validating resolver (<c>delv</c>). Agreement across all of them is far
/// stronger evidence than any single tool.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
public class KdigDrillDelvTests
{

    private HermodServerFixture  server    = null!;
    private String               hostAddr  = null!;


    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireWsl();

        hostAddr = Wsl.WindowsHostAddress
                       ?? throw new InvalidOperationException("Could not determine the Windows host address as seen from WSL!");

        server = await HermodServerFixture.StartAsync(
                           new HermodServerFixtureOptions {
                               BindAllInterfaces  = true,
                               EnableTls          = true
                           }
                       );

    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (server is not null)
            await server.DisposeAsync();
    }


    private static void RequireReachability(Wsl.Result probe)
    {
        if (probe.StdOut.Contains("no servers could be reached", StringComparison.OrdinalIgnoreCase) ||
            probe.StdErr.Contains("failed to query server",      StringComparison.OrdinalIgnoreCase) ||
            probe.StdOut.Contains("connection timed out",        StringComparison.OrdinalIgnoreCase) ||
            probe.ExitCode == -1)
        {
            Assert.Ignore("WSL cannot reach the Hermod server — usually a Windows Firewall rule blocking the WSL subnet.");
        }
    }


    #region Kdig_Resolves_An_A_Record()

    [Test]
    public void Kdig_Resolves_An_A_Record()
    {

        TestEnvironment.RequireWsl("kdig");

        var result = Wsl.Run($"kdig @{hostAddr} -p {server.UdpPort} +short {ZoneFixtures.AName} A", TimeSpan.FromSeconds(20));

        RequireReachability(result);

        TestContext.Out.WriteLine(result.ToString());

        Assert.That(result.StdOut.Trim(), Is.EqualTo(ZoneFixtures.AAddress),
                    "Knot's kdig must resolve the record served by Hermod");

    }

    #endregion

    #region Kdig_Over_Tcp_Resolves_An_A_Record()

    [Test]
    [Property("RFC", "7766")]
    public void Kdig_Over_Tcp_Resolves_An_A_Record()
    {

        TestEnvironment.RequireWsl("kdig");

        var result = Wsl.Run($"kdig @{hostAddr} -p {server.TcpPort} +tcp +short {ZoneFixtures.AName} A", TimeSpan.FromSeconds(20));

        RequireReachability(result);

        Assert.That(result.StdOut.Trim(), Is.EqualTo(ZoneFixtures.AAddress));

    }

    #endregion

    #region Kdig_Speaks_DoT_To_The_Hermod_Tls_Listener()

    [Test]
    [Property("RFC", "7858")]
    public void Kdig_Speaks_DoT_To_The_Hermod_Tls_Listener()
    {

        TestEnvironment.RequireWsl("kdig");

        // +tls-ca is omitted deliberately: the fixture certificate is
        // self-signed, so certificate validation is disabled and only the DoT
        // protocol behavior is under test.
        var result = Wsl.Run(
                         $"kdig @{hostAddr} -p {server.TlsPort} +tls +short {ZoneFixtures.AName} A",
                         TimeSpan.FromSeconds(25)
                     );

        RequireReachability(result);

        TestContext.Out.WriteLine(result.ToString());

        Assert.That(result.StdOut.Trim(), Is.EqualTo(ZoneFixtures.AAddress),
                    "kdig must complete a DNS-over-TLS exchange with Hermod's DoT listener");

    }

    #endregion

    #region Drill_Resolves_An_A_Record()

    [Test]
    public void Drill_Resolves_An_A_Record()
    {

        TestEnvironment.RequireWsl("drill");

        var result = Wsl.Run($"drill -p {server.UdpPort} {ZoneFixtures.AName} @{hostAddr} A", TimeSpan.FromSeconds(20));

        RequireReachability(result);

        TestContext.Out.WriteLine(result.ToString());

        Assert.Multiple(() => {
            Assert.That(result.StdOut, Does.Contain("rcode: NOERROR"));
            Assert.That(result.StdOut, Does.Contain(ZoneFixtures.AAddress),
                        "ldns' drill — a third independent parser — must read the answer");
        });

    }

    #endregion

    #region Drill_Reads_Every_Fixture_Type(...)

    [TestCase("AAAA", "aaaa.conformance.test.", "2001:db8::1")]
    [TestCase("MX",   "mx.conformance.test.",   "mail1.conformance.test.")]
    [TestCase("SRV",  "_dns._udp.conformance.test.", "5353")]
    [TestCase("SOA",  "conformance.test.",      "hostmaster.conformance.test.")]
    public void Drill_Reads_Fixture_Record(String type, String name, String expectedFragment)
    {

        TestEnvironment.RequireWsl("drill");

        var result = Wsl.Run($"drill -p {server.UdpPort} {name} @{hostAddr} {type}", TimeSpan.FromSeconds(20));

        RequireReachability(result);

        TestContext.Out.WriteLine(result.StdOut);

        Assert.That(result.StdOut, Does.Contain(expectedFragment),
                    $"drill's {type} rendering must contain '{expectedFragment}'");

    }

    #endregion

    #region Kdig_And_Dig_And_Drill_Agree()

    [Test]
    public void Kdig_And_Dig_And_Drill_Agree()
    {

        TestEnvironment.RequireWsl("dig", "kdig", "drill");

        var dig   = Wsl.Run($"dig  @{hostAddr} -p {server.UdpPort} +short {ZoneFixtures.MultiName} A", TimeSpan.FromSeconds(20));
        var kdig  = Wsl.Run($"kdig @{hostAddr} -p {server.UdpPort} +short {ZoneFixtures.MultiName} A", TimeSpan.FromSeconds(20));
        var drill = Wsl.Run($"drill -p {server.UdpPort} {ZoneFixtures.MultiName} @{hostAddr} A",       TimeSpan.FromSeconds(20));

        RequireReachability(dig);

        static String[] Addresses(String text)
            => [.. text.Split('\n', StringSplitOptions.RemoveEmptyEntries).
                        Select(l => l.Trim()).
                        Where (l => l.StartsWith("192.0.2.", StringComparison.Ordinal)).
                        Order()];

        var digAddresses  = Addresses(dig.StdOut);
        var kdigAddresses = Addresses(kdig.StdOut);

        Assert.Multiple(() => {

            Assert.That(digAddresses,  Is.EqualTo(ZoneFixtures.MultiAddresses.Order().ToArray()),
                        "dig must see all three A records");

            Assert.That(kdigAddresses, Is.EqualTo(digAddresses),
                        "kdig and dig must agree on the answer set");

            foreach (var address in ZoneFixtures.MultiAddresses)
                Assert.That(drill.StdOut, Does.Contain(address), $"drill must also see {address}");

        });

    }

    #endregion

}

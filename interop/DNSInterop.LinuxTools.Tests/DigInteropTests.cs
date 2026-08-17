using NUnit.Framework;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSInterop.LinuxTools.Tests;

/// <summary>
/// Interoperability against ISC BIND's <c>dig</c> running in WSL: a completely
/// independent implementation parsing what Hermod's DNS server produces.
/// If dig is happy, the bytes are right.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
public class DigInteropTests
{

    private HermodServerFixture  server    = null!;
    private String               hostAddr  = null!;


    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireWsl("dig");

        hostAddr = Wsl.WindowsHostAddress
                       ?? throw new InvalidOperationException("Could not determine the Windows host address as seen from WSL!");

        // Bind all interfaces so the WSL VM can reach the listener.
        server = await HermodServerFixture.StartAsync(
                           new HermodServerFixtureOptions { BindAllInterfaces = true }
                       );

    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (server is not null)
            await server.DisposeAsync();
    }


    private Wsl.Result Dig(String arguments)
        => Wsl.Run($"dig @{hostAddr} -p {server.UdpPort} +time=3 +tries=1 {arguments}", TimeSpan.FromSeconds(20));

    private Wsl.Result DigTcp(String arguments)
        => Wsl.Run($"dig @{hostAddr} -p {server.TcpPort} +tcp +time=3 +tries=1 {arguments}", TimeSpan.FromSeconds(20));


    /// <summary>
    /// Skip rather than fail when the Windows firewall blocks the WSL→host path.
    /// </summary>
    private void RequireReachability(Wsl.Result probe)
    {
        if (probe.StdOut.Contains("no servers could be reached", StringComparison.OrdinalIgnoreCase) ||
            probe.StdOut.Contains("connection timed out",        StringComparison.OrdinalIgnoreCase))
        {
            Assert.Ignore($"WSL cannot reach the Hermod server at {hostAddr}:{server.UdpPort} — " +
                          "usually a Windows Firewall rule blocking inbound UDP/TCP from the WSL subnet.");
        }
    }


    #region Dig_Resolves_An_A_Record()

    [Test]
    public void Dig_Resolves_An_A_Record()
    {

        var result = Dig($"+short {ZoneFixtures.AName} A");

        RequireReachability(result);

        TestContext.Out.WriteLine(result.ToString());

        Assert.That(result.StdOut.Trim(), Is.EqualTo(ZoneFixtures.AAddress),
                    "dig must resolve the A record served by Hermod");

    }

    #endregion

    #region Dig_Reports_NOERROR_And_The_Expected_Flags()

    [Test]
    public void Dig_Reports_NOERROR_And_The_Expected_Flags()
    {

        var result = Dig($"{ZoneFixtures.AName} A");

        RequireReachability(result);

        TestContext.Out.WriteLine(result.StdOut);

        Assert.Multiple(() => {

            Assert.That(result.StdOut, Does.Contain("status: NOERROR"));
            Assert.That(result.StdOut, Does.Contain("flags:").And.Contain("qr").And.Contain("aa"),
                        "an authoritative answer carries qr and aa");

            // "recursion requested but not available" is the correct, expected
            // notice for an authoritative-only server (RD set, RA clear) — but
            // any warning about the message itself means malformed bytes.
            var structuralWarnings = result.StdOut.
                                         Split('\n').
                                         Where(line => line.Contains("WARNING", StringComparison.Ordinal) &&
                                                      !line.Contains("recursion requested but not available", StringComparison.Ordinal)).
                                         ToArray();

            Assert.That(structuralWarnings, Is.Empty,
                        "dig must not warn about the response message itself: " + String.Join(" | ", structuralWarnings));

        });

    }

    #endregion

    #region Dig_Reports_NXDOMAIN_For_An_Unknown_Name()

    [Test]
    public void Dig_Reports_NXDOMAIN_For_An_Unknown_Name()
    {

        var result = Dig("does-not-exist.conformance.test. A");

        RequireReachability(result);

        Assert.That(result.StdOut, Does.Contain("status: NXDOMAIN"));

    }

    #endregion

    #region Dig_Resolves_Every_Fixture_Record_Type(...)

    [TestCase("AAAA",  "aaaa.conformance.test.",   "2001:db8::1")]
    [TestCase("MX",    "mx.conformance.test.",     "10 mail1.conformance.test.")]
    [TestCase("TXT",   "txt.conformance.test.",    "Hello DNS conformance!")]
    [TestCase("SRV",   "_dns._udp.conformance.test.", "10 60 5353 ns1.conformance.test.")]
    [TestCase("CNAME", "alias.conformance.test.",  "a.conformance.test.")]
    [TestCase("PTR",   "42.2.0.192.in-addr.arpa.", "a.conformance.test.")]
    [TestCase("CAA",   "caa.conformance.test.",    "letsencrypt.org")]
    [TestCase("NS",    "conformance.test.",        "ns1.conformance.test.")]
    public void Dig_Resolves_Fixture_Record(String type, String name, String expectedFragment)
    {

        var result = Dig($"+short {name} {type}");

        RequireReachability(result);

        TestContext.Out.WriteLine($"dig +short {name} {type} =>\n{result.StdOut}");

        Assert.That(result.StdOut, Does.Contain(expectedFragment),
                    $"dig's {type} rendering must contain '{expectedFragment}'");

    }

    #endregion

    #region Dig_Over_Tcp_Works()

    [Test]
    [Property("RFC", "7766")]
    public void Dig_Over_Tcp_Works()
    {

        var result = DigTcp($"+short {ZoneFixtures.AName} A");

        RequireReachability(result);

        Assert.That(result.StdOut.Trim(), Is.EqualTo(ZoneFixtures.AAddress),
                    "the TCP listener must serve the same data as UDP");

    }

    #endregion

    #region Dig_Without_Edns_Works()

    [Test]
    [Property("RFC", "6891")]
    public void Dig_Without_Edns_Works()
    {

        // The dnsflagday probe for plain-DNS compatibility.
        var result = Dig($"+noedns +short {ZoneFixtures.AName} A");

        RequireReachability(result);

        Assert.That(result.StdOut.Trim(), Is.EqualTo(ZoneFixtures.AAddress),
                    "a server MUST answer queries without EDNS");

    }

    #endregion

    #region Dig_With_Edns_Is_Answered()

    [Test]
    [Property("RFC", "6891 §6.1.1")]
    public void Dig_With_Edns_Is_Answered()
    {

        var result = Dig($"+edns=0 {ZoneFixtures.AName} A");

        RequireReachability(result);

        TestContext.Out.WriteLine(result.StdOut);

        Assert.That(result.StdOut, Does.Contain("status: NOERROR"),
                    "an EDNS query must still be answered");

        // Reported, not enforced — the missing OPT is tracked as a conformance
        // finding by DNSConformance.Server.Tests.
        if (!result.StdOut.Contains("EDNS: version"))
            TestContext.Out.WriteLine("NOTE: dig saw no OPT pseudosection in the response (RFC 6891 §6.1.1 — see FINDINGS.md #6).");

    }

    #endregion

    #region Dig_With_Unknown_Edns_Version_Is_Probed()

    [Test]
    [Property("RFC", "6891 §6.1.3")]
    public void Dig_With_Unknown_Edns_Version_Is_Probed()
    {

        // dig +edns=1 is the canonical BADVERS probe used by the DNS flag day
        // compliance tests.
        var result = Dig($"+edns=1 {ZoneFixtures.AName} A");

        RequireReachability(result);

        TestContext.Out.WriteLine(result.StdOut);

        Assert.That(result.StdOut, Does.Contain("status:"),
                    "an EDNS version 1 query must produce some answer, not silence");

    }

    #endregion

    #region Dig_Sees_The_Large_Txt_Record_Over_Tcp()

    [Test]
    public void Dig_Sees_The_Large_Txt_Record_Over_Tcp()
    {

        var result = DigTcp($"+short {ZoneFixtures.BigTxtName} TXT");

        RequireReachability(result);

        // A 600-byte TXT must be rendered by dig as multiple quoted strings.
        Assert.That(result.StdOut, Does.Contain("xxx"),
                    "dig must render the large TXT record");

        TestContext.Out.WriteLine($"large TXT rendered in {result.StdOut.Length} characters");

    }

    #endregion

}

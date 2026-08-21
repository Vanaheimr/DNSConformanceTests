using System.Text.Json;

using NUnit.Framework;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSInterop.ExternalServers.Tests;

/// <summary>
/// Zonemaster — the registry-grade zone checker run by IIS and AFNIC — pointed
/// at a Hermod-served zone in undelegated mode.
/// </summary>
/// <remarks>
/// <para>
/// The second outside verdict in this suite, after ISC's <c>genreport</c>: Zonemaster
/// decides for itself what is wrong with a zone, from its own reading of the
/// RFCs and of registry practice. Undelegated mode is what makes it usable
/// here — <c>--ns NAME/IP</c> supplies "the entirety of the parent-side
/// delegation information", so no real parent has to delegate anything.
/// </para>
/// <para>
/// Two pieces of plumbing are needed. Zonemaster speaks to port 53 and offers
/// no way to change that, while the fixture binds an ephemeral port on the
/// Windows side; and the checker runs in a container. So a socat pair bridges
/// the WSL VM's own address on 53 to Hermod, and the container runs with
/// <c>--network host</c> to reach it. Port 53 is free on that address —
/// WSL's own resolver holds 53 only on the gateway address, 10.255.255.254.
/// </para>
/// </remarks>
[TestFixture]
[Category(TestCategories.Docker)]
public class ZonemasterUndelegatedTests
{

    #region Data

    private const String Image     = "zonemaster/cli";
    private const String NsName    = "ns1.conformance.test.";
    private const String ZoneName  = "conformance.test.";

    /// <summary>
    /// Every tag Zonemaster reports at ERROR level, with why it is there. The
    /// set is asserted exactly: a tag that disappears fails the test just as
    /// loudly as a new one, because the first is the signal to delete its entry.
    /// </summary>
    /// <remarks>
    /// Every one of them is a property of a laboratory rather than of the
    /// server: the fixture zone deliberately uses TEST-NET-1 for its name server
    /// address and has a single NS where registries want two, and the bridge
    /// means the address handed over as glue is not the one the zone publishes.
    /// The one entry that was about Hermod, <c>IS_A_RECURSOR</c>, is gone —
    /// finding 41 closed it, and this list is where that became visible.
    /// </remarks>
    private static readonly Dictionary<String, String> KnownErrors = new () {

        ["A01_NO_GLOBALLY_REACHABLE_ADDR"] = "lab: the server is on a private address",
        ["A01_DOCUMENTATION_ADDR"]         = "lab: the fixture zone publishes 192.0.2.53, TEST-NET-1 by design",
        ["A01_LOCAL_USE_ADDR"]             = "lab: the bridge address is the WSL VM's private one",
        ["IN_BAILIWICK_ADDR_MISMATCH"]     = "harness: glue is the bridge address, the zone publishes 192.0.2.53",
        ["EXTRA_NAME_PARENT"]              = "harness: same mismatch seen from the parent side",
        ["TOTAL_NAME_MISMATCH"]            = "harness: same mismatch again",
        ["NOT_ENOUGH_NS_DEL"]              = "lab: the fixture zone has one name server, registries want two",
        ["NOT_ENOUGH_NS_CHILD"]            = "lab: same",
        ["NOT_ENOUGH_IPV4_NS_CHILD"]       = "lab: same",
        ["NOT_ENOUGH_IPV4_NS_DEL"]         = "lab: same",


    };

    private HermodServerFixture  server     = null!;
    private String               vmAddress  = null!;
    private System.Diagnostics.Process?  relayUdp;
    private System.Diagnostics.Process?  relayTcp;
    private String[]             errorTags  = [];

    #endregion

    #region Setup

    [OneTimeSetUp]
    public async Task StartEverything()
    {

        TestEnvironment.RequireWsl("socat", "docker");

        if (!Wsl.Run("docker info --format '{{.ServerVersion}}'", TimeSpan.FromSeconds(30), asRoot: true).Success)
            Assert.Ignore("No Docker daemon. This WSL distribution runs init rather than systemd, so nothing " +
                          "starts it: `wsl -u root -e /usr/sbin/dockerd`, or enable systemd in /etc/wsl.conf.");

        if (!Wsl.Run($"docker image inspect {Image}", TimeSpan.FromSeconds(60), asRoot: true).Success)
            Assert.Ignore($"The {Image} image is not present — `docker pull {Image}`.");

        var host  = Wsl.WindowsHostAddress
                        ?? throw new InvalidOperationException("Could not determine the Windows host address as seen from WSL!");

        vmAddress = Wsl.VmAddress
                        ?? throw new InvalidOperationException("Could not determine the WSL VM's own address!");

        server    = await HermodServerFixture.StartAsync(
                              new HermodServerFixtureOptions {
                                  BindAllInterfaces          = true,
                                  SharePortAcrossTransports  = true
                              });

        Wsl.Run("pkill -f 'socat.*LISTEN:53' || true", TimeSpan.FromSeconds(15), asRoot: true);

        // Held by processes this side owns. A socat backgrounded inside one
        // Wsl.Run is reaped the moment that wsl.exe returns, so it is already
        // gone by the next call — which looks exactly like a firewall problem.
        relayUdp = Wsl.StartDetached($"socat -T 5 UDP4-LISTEN:53,bind={vmAddress},fork,reuseaddr UDP4:{host}:{server.UdpPort}", asRoot: true);
        relayTcp = Wsl.StartDetached($"socat TCP4-LISTEN:53,bind={vmAddress},fork,reuseaddr TCP4:{host}:{server.TcpPort}",      asRoot: true);

        // One run serves every assertion below: it takes about half a minute,
        // most of it Zonemaster waiting on the fixture's unreachable TEST-NET-1
        // address and on its own network lookups.
        var run = Wsl.Run($"docker run --rm --network host {Image} " +
                          $"--ns {NsName}/{vmAddress} --no-ipv6 --level ERROR --no-progress --json --raw {ZoneName}",
                          TimeSpan.FromSeconds(900), asRoot: true);

        if (!run.Success || run.StdOut.Length == 0)
            Assert.Ignore($"Zonemaster did not run: rc={run.ExitCode}, stdout='{run.StdOut}', stderr='{run.StdErr}'");

        errorTags = ParseErrorTags(run.StdOut);

    }

    [OneTimeTearDown]
    public async Task StopEverything()
    {

        try { relayUdp?.Kill(entireProcessTree: true); } catch { /* already gone */ }
        try { relayTcp?.Kill(entireProcessTree: true); } catch { /* already gone */ }

        Wsl.Run("pkill -f 'socat.*LISTEN:53' || true", TimeSpan.FromSeconds(15), asRoot: true);

        if (server is not null)
            await server.DisposeAsync();

    }

    #endregion


    #region The_Bridge_Actually_Carries_Dns()

    [Test]
    public void The_Bridge_Actually_Carries_Dns()
    {

        // Everything below reads a report produced by a container talking to a
        // socat talking to Hermod. If any link is down, Zonemaster still emits a
        // report — a shorter one, about a server that answered nothing — and the
        // exact-set assertion would fail in a way that reads like a Hermod
        // regression. This says which it was.
        var udp = Wsl.Run($"dig @{vmAddress} +time=3 +tries=1 {ZoneFixtures.AName} A +short",       TimeSpan.FromSeconds(20));
        var tcp = Wsl.Run($"dig @{vmAddress} +tcp +time=3 +tries=1 {ZoneFixtures.AName} A +short",  TimeSpan.FromSeconds(20));

        Assert.Multiple(() => {
            Assert.That(udp.StdOut.Trim(), Is.EqualTo(ZoneFixtures.AAddress), "the UDP bridge reaches Hermod");
            Assert.That(tcp.StdOut.Trim(), Is.EqualTo(ZoneFixtures.AAddress), "and the TCP bridge too");
        });

    }

    #endregion

    #region Zonemaster_Reports_Only_The_Errors_We_Know_About()

    [Test]
    public void Zonemaster_Reports_Only_The_Errors_We_Know_About()
    {

        Assert.That(errorTags,
                    Is.EqualTo(KnownErrors.Keys.OrderBy(k => k).ToArray()),
                    "the ERROR tags must match the recorded set exactly. A tag that vanished is a reason to " +
                    "delete its entry, not to widen this; a new one is a finding. " +
                    $"Got: {String.Join(", ", errorTags)}");

    }

    #endregion

    #region Every_Recorded_Error_Says_Why_It_Is_Tolerated()

    [Test]
    public void Every_Recorded_Error_Says_Why_It_Is_Tolerated()
    {

        // A tolerated failure with no reason beside it decays into a tolerated
        // failure nobody remembers deciding on.
        Assert.That(KnownErrors.Values.Where(String.IsNullOrWhiteSpace),
                    Is.Empty,
                    "every entry in KnownErrors carries its justification");

    }

    #endregion


    #region (private static) ParseErrorTags(Json)

    /// <summary>
    /// The distinct ERROR-level tags of a Zonemaster JSON report, sorted.
    /// </summary>
    /// <remarks>
    /// Tags rather than messages on purpose: the human-readable text is
    /// translated and reworded between releases, while the tag is the stable
    /// identity of a test outcome.
    /// </remarks>
    private static String[] ParseErrorTags(String Json)
    {

        // --raw prints one JSON document; take the first line that parses.
        foreach (var line in Json.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {

            if (!line.TrimStart().StartsWith('{'))
                continue;

            using var document = JsonDocument.Parse(line);

            return [.. document.RootElement.
                          GetProperty("results").
                          EnumerateArray().
                          Where  (r => r.GetProperty("level").GetString() == "ERROR").
                          Select (r => r.GetProperty("tag").GetString()!).
                          Distinct().
                          Order()];

        }

        Assert.Fail($"no JSON document in Zonemaster's output: '{Json}'");
        return [];

    }

    #endregion

}

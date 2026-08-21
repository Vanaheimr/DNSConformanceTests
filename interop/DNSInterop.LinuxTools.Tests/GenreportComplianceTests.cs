using System.Text.RegularExpressions;

using NUnit.Framework;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSInterop.LinuxTools.Tests;

/// <summary>
/// ISC's <c>genreport</c> — the EDNS compliance battery behind dnsflagday.net —
/// fired at Hermod's DNS server from WSL.
/// </summary>
/// <remarks>
/// <para>
/// This is the one place where the verdict is not the suite's own. Everything
/// else here measures Hermod against this suite's reading of the RFCs; genreport
/// was written from an independent reading, by the people who maintain BIND, and
/// it decides for itself which of its roughly thirty probes a server failed. The
/// same principle as "never test Hermod with Hermod", one level up.
/// </para>
/// <para>
/// Build it once per machine with <c>interop/genreport/build-genreport.sh</c>.
/// </para>
/// </remarks>
[TestFixture]
[Category(TestCategories.Wsl)]
public class GenreportComplianceTests
{

    /// <summary>
    /// Probes whose verdict is knowingly not "ok", with the reason. The set is
    /// asserted exactly, so this fails both when a new probe starts failing and
    /// when one of these starts passing — the second being a reason to delete
    /// the entry rather than to widen it.
    /// </summary>
    private static readonly Dictionary<String, String> KnownDivergences = new () {
        // Empty, and meant to stay that way. genreport accepts every probe it
        // fires at this server; the last entry here was opcodeflg, closed by
        // finding 40.
    };

    private HermodServerFixture  server    = null!;
    private String               hostAddr  = null!;


    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireWsl("genreport");

        hostAddr = Wsl.WindowsHostAddress
                       ?? throw new InvalidOperationException("Could not determine the Windows host address as seen from WSL!");

        // All interfaces so the WSL VM can reach the listener — and one port for
        // both transports, because genreport's tcp and ednstcp probes reuse the
        // address they were given. Two ports would report those as timeouts and
        // blame the server for the harness.
        server = await HermodServerFixture.StartAsync(
                           new HermodServerFixtureOptions {
                               BindAllInterfaces          = true,
                               SharePortAcrossTransports  = true
                           }
                       );

    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (server is not null)
            await server.DisposeAsync();
    }


    #region The_Edns_Battery_Finds_Nothing_To_Complain_About()

    [Test]
    [Property("RFC", "6891, 3225, 7873, 7871")]
    public void The_Edns_Battery_Finds_Nothing_To_Complain_About()
    {

        // The default grouping, and the one dnsflagday actually judges servers
        // on: EDNS version 0 and an unknown version 1, an undefined option code,
        // undefined flags, DO, the option list, a signed zone, EDNS over TCP.
        var verdicts = RunBattery("");

        Assert.That(Failing(verdicts),
                    Is.Empty,
                    $"genreport's EDNS battery must report no failure — got: {Format(verdicts)}");

    }

    #endregion

    #region The_Full_Battery_Diverges_Only_Where_It_Is_Known_To()

    [Test]
    [Property("RFC", "1035 §4.1.1, 6895 §2")]
    public void The_Full_Battery_Diverges_Only_Where_It_Is_Known_To()
    {

        // The wider grouping adds the header flags one at a time, an unknown
        // opcode with and without flags, an unknown RR type, and plain TCP.
        var verdicts = RunBattery("-f");
        var failing  = Failing(verdicts).Select(kv => kv.Key).OrderBy(k => k).ToArray();

        Assert.That(failing,
                    Is.EqualTo(KnownDivergences.Keys.OrderBy(k => k).ToArray()),
                    "the probes genreport is unhappy with must match the recorded set exactly — " +
                    "one that started passing is a reason to delete its entry, not to widen this. " +
                    $"Got: {Format(verdicts)}");

    }

    #endregion

    #region The_Battery_Actually_Ran()

    [Test]
    public void The_Battery_Actually_Ran()
    {

        // A report of "nothing failed" is worth exactly what the evidence that
        // anything was asked is worth. genreport names every probe it ran, so
        // the names are the guard against a run that quietly did nothing.
        var verdicts = RunBattery("-f");

        Assert.Multiple(() => {

            Assert.That(verdicts,      Has.Count.GreaterThanOrEqualTo(25), "the full grouping is roughly thirty probes");
            Assert.That(verdicts.Keys, Does.Contain("dns"),                "the plain query probe");
            Assert.That(verdicts.Keys, Does.Contain("edns"),               "the EDNS version 0 probe");
            Assert.That(verdicts.Keys, Does.Contain("tcp"),                "the TCP probe");
            Assert.That(verdicts.Keys, Does.Contain("ednstcp"),            "the EDNS-over-TCP probe");

        });

    }

    #endregion


    #region (private) RunBattery(Flags)

    /// <summary>
    /// One genreport run against the fixture, as a probe-name to verdict map.
    /// </summary>
    private Dictionary<String, String> RunBattery(String Flags)
    {

        var input   = $"conformance.test. ns1.conformance.test. {hostAddr}";
        var command = "echo " + Quote(input) +
                      $" | genreport -4 -P {server.UdpPort} {Flags} -o";

        var result  = Wsl.Run(command, TimeSpan.FromSeconds(180));

        // genreport reports once per address: "<zone>. @<addr> (<ns>): name=value ..."
        var marker  = "): ";
        var line    = result.StdOut.
                          Split('\n', StringSplitOptions.RemoveEmptyEntries).
                          FirstOrDefault(l => l.Contains(marker, StringComparison.Ordinal));

        if (line is null)
            Assert.Ignore($"genreport produced no report line — stdout: '{result.StdOut}', stderr: '{result.StdErr}'");

        var verdicts = new Dictionary<String, String>();
        var tail     = line![(line.IndexOf(marker, StringComparison.Ordinal) + marker.Length)..];

        foreach (Match match in Regex.Matches(tail, @"(?<name>[A-Za-z0-9@_]+)=(?<verdict>\S+)"))
            verdicts[match.Groups["name"].Value] = match.Groups["verdict"].Value;

        // Everything timing out is the Windows firewall blocking the WSL subnet,
        // not a compliance result. Skip rather than accuse the server.
        if (verdicts.Count > 0 &&
            verdicts.Values.All(v => v.StartsWith("timeout", StringComparison.Ordinal)))
        {
            Assert.Ignore($"WSL cannot reach the Hermod server at {hostAddr}:{server.UdpPort} — " +
                          "usually a Windows Firewall rule blocking inbound UDP/TCP from the WSL subnet.");
        }

        return verdicts;

    }

    private static String Quote(String Text)
        => "'" + Text.Replace("'", "'\\''") + "'";

    #endregion

    #region (private static) Failing(Verdicts), Format(Verdicts)

    /// <summary>
    /// The probes genreport did not accept. Its convention is a verdict of "ok"
    /// optionally followed by comma-separated remarks — "ok,nsid" is a pass that
    /// also noticed an NSID option, while "timeout" or a bare flag name is not.
    /// </summary>
    private static KeyValuePair<String, String>[] Failing(Dictionary<String, String> Verdicts)

        => Verdicts.
               Where  (kv => kv.Value != "ok" &&
                            !kv.Value.StartsWith("ok,", StringComparison.Ordinal)).
               OrderBy(kv => kv.Key).
               ToArray();

    private static String Format(Dictionary<String, String> Verdicts)

        => String.Join(" ", Verdicts.OrderBy(kv => kv.Key).
                                     Select (kv => $"{kv.Key}={kv.Value}"));

    #endregion

}

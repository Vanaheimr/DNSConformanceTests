using System.Net;
using System.Net.Sockets;

using NUnit.Framework;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Core;

/// <summary>
/// One-time capability probing (network / WSL / docker) with
/// Assert.Ignore-based gating so prerequisite-less environments skip
/// instead of fail.
/// </summary>
public static class TestEnvironment
{

    #region Network

    private static readonly Lazy<Boolean> hasNetwork = new(() => {

        foreach (var resolver in new[] { "1.1.1.1", "8.8.8.8" })
        {
            try
            {

                using var udp = new UdpClient();
                udp.Connect(IPAddress.Parse(resolver), 53);

                var probe = RawDnsWriter.Query(0x2454, "example.com", RawDnsType.A);
                udp.Send(probe);

                var receiveTask = udp.ReceiveAsync();

                if (receiveTask.Wait(TimeSpan.FromSeconds(3)) && receiveTask.Result.Buffer.Length >= 12)
                    return true;

            }
            catch
            {
                // try next resolver
            }
        }

        return false;

    });

    /// <summary>
    /// True when a public resolver answers a raw UDP DNS probe.
    /// </summary>
    public static Boolean HasNetwork
        => hasNetwork.Value;

    public static void RequireNetwork()
    {
        if (!HasNetwork)
            Assert.Ignore("No outbound DNS connectivity (probed 1.1.1.1 and 8.8.8.8 on UDP/53) — skipping Online test.");
    }

    #endregion

    #region WSL

    /// <summary>
    /// Require the GNU/Linux DNS tools these interop tests drive.
    /// </summary>
    /// <param name="tools">The executables the calling test needs on the PATH.</param>
    /// <remarks>
    /// The category is still called <c>WSL</c> because that is where these tools
    /// live on a developer machine. On a Linux host — a CI runner, say — the
    /// same tests run against the tools directly, with no bridge and no
    /// firewall between them and the server under test.
    /// </remarks>
    public static void RequireWsl(params String[] tools)
    {

        var packages = "bind9-dnsutils knot-dnsutils ldnsutils bind9 bind9utils";

        if (!Wsl.IsAvailable)
            Assert.Ignore(Wsl.UsesWslBridge
                              ? $"WSL is not available — skipping. Install WSL, then: wsl -u root apt-get install -y {packages}"
                              :  "No POSIX shell available — skipping.");

        foreach (var tool in tools)
            if (!Wsl.HasTool(tool))
                Assert.Ignore(Wsl.UsesWslBridge
                                  ? $"'{tool}' not found inside WSL — skipping. Install it, e.g.: wsl -u root apt-get install -y {packages}"
                                  : $"'{tool}' not found on the PATH — skipping. Install it, e.g.: apt-get install -y {packages}");

    }

    #endregion

    #region Docker

    private static readonly Lazy<Boolean> hasDocker = new(() => {
        try
        {

            var psi = new System.Diagnostics.ProcessStartInfo {
                          FileName                = "docker",
                          Arguments               = "info --format {{.ServerVersion}}",
                          RedirectStandardOutput  = true,
                          RedirectStandardError   = true,
                          UseShellExecute         = false,
                          CreateNoWindow          = true
                      };

            using var process = System.Diagnostics.Process.Start(psi);

            if (process is null)
                return false;

            if (!process.WaitForExit(5000))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return false;
            }

            return process.ExitCode == 0;

        }
        catch
        {
            return false;
        }
    });

    public static Boolean HasDockerDaemon
        => hasDocker.Value;

    public static void RequireDocker()
    {
        if (!HasDockerDaemon)
            Assert.Ignore("No reachable Docker daemon — skipping Docker-based interop test.");
    }

    #endregion

}

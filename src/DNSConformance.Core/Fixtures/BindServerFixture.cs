using System.Diagnostics;

namespace DNSConformance.Core.Fixtures;

/// <summary>
/// Runs an authoritative ISC BIND (<c>named</c>) instance inside WSL, serving
/// the interop fixture zones on a loopback high port, so that Hermod's DNS
/// *client* can be measured against a reference server implementation.
///
/// BIND listens on 127.0.0.1 inside the WSL VM; WSL's NAT mode forwards
/// localhost connections from Windows, so Hermod reaches it at 127.0.0.1.
/// </summary>
public sealed class BindServerFixture : IAsyncDisposable
{

    private readonly String    workDirWsl;
    private readonly Process?  host;

    public UInt16  Port      { get; }
    public String  LogTail   { get; private set; } = "";

    /// <summary>
    /// The address Windows-side clients must use. WSL2's NAT localhost relay
    /// forwards TCP but not UDP, so this is the VM's own eth0 address.
    /// </summary>
    public String  Address   { get; private set; } = "127.0.0.1";

    private BindServerFixture(UInt16 port, String workDirWsl, Process? host)
    {
        Port            = port;
        this.workDirWsl = workDirWsl;
        this.host       = host;
    }


    /// <summary>True when WSL is available and named is installed.</summary>
    public static Boolean IsAvailable
        => Wsl.IsAvailable && Wsl.HasTool("named");


    public static async Task<BindServerFixture> StartAsync(UInt16? Port = null)
    {

        var port      = Port ?? (UInt16) Random.Shared.Next(20000, 60000);

        var fixtures  = FindFixturesDirectory()
                            ?? throw new DirectoryNotFoundException("fixtures/bind not found!");

        // The work directory must live on WSL's native filesystem: named refuses
        // to run with its directory/pid-file on the /mnt/c DrvFs mount.
        var workDirWsl  = $"/tmp/hermod-bind-{Guid.NewGuid():N}";
        var fixturesWsl = Wsl.ToWslPath(fixtures);

        var signedZone  = Path.Combine(fixtures, "zones", "signed", "dnssec.test.zone.signed");

        var stageSigned = File.Exists(signedZone)
                              ? $"cp '{fixturesWsl}/zones/signed/dnssec.test.zone.signed' '{workDirWsl}/'"
                              // Without the signed zone BIND would refuse to start — emit a stub.
                              : $"printf '$TTL 3600\\n@ IN SOA ns1.dnssec.test. hostmaster.dnssec.test. ( 1 7200 3600 1209600 3600 )\\n@ IN NS ns1.dnssec.test.\\nns1 IN A 192.0.2.53\\n' > '{workDirWsl}/dnssec.test.zone.signed'";

        var stage = Wsl.Run(
                        $"mkdir -p '{workDirWsl}' && " +
                        $"cp '{fixturesWsl}/bind/interop.test.zone' '{workDirWsl}/' && " +
                        $"{stageSigned} && " +
                        // Substitute the template and strip CRs in one pass.
                        $"sed -e 's|__DIR__|{workDirWsl}|g' -e 's|__PORT__|{port}|g' '{fixturesWsl}/bind/named.conf.template' | tr -d '\\r' > '{workDirWsl}/named.conf' && " +
                        $"named-checkconf '{workDirWsl}/named.conf' && echo staged",
                        TimeSpan.FromSeconds(30),
                        asRoot: true
                    );

        if (!stage.StdOut.Contains("staged"))
            throw new InvalidOperationException($"Could not stage the BIND fixture directory:\n{stage}");

        // WSL terminates a session's whole process tree when wsl.exe exits, so
        // neither '&' nor setsid/nohup keeps named alive. Instead run it in the
        // foreground and hold the launching process open for the fixture's
        // lifetime; disposing kills it. Natively the held process is simply
        // /bin/sh running named.
        var host = Wsl.StartDetached($"named -c {workDirWsl}/named.conf -g > {workDirWsl}/named.log 2>&1");

        var fixture = new BindServerFixture(port, workDirWsl, host) {
                          Address = Wsl.VmAddress ?? "127.0.0.1"
                      };

        // Wait for the listener to accept queries.
        for (var attempt = 0; attempt < 25; attempt++)
        {

            await Task.Delay(200);

            var probe = Wsl.Run($"dig @127.0.0.1 -p {port} +time=1 +tries=1 +short a.interop.test A", TimeSpan.FromSeconds(6));

            if (probe.StdOut.Contains("192.0.2.1"))
                return fixture;

        }

        fixture.LogTail = Wsl.Run($"tail -20 {workDirWsl}/named.log 2>/dev/null", TimeSpan.FromSeconds(10), asRoot: true).StdOut;

        await fixture.DisposeAsync();

        throw new InvalidOperationException(
            $"BIND did not become ready on port {port}.\nstaging: {stage.StdOut.Trim()}\nlog:\n{fixture.LogTail}"
        );

    }


    private static String? FindFixturesDirectory()
    {

        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {

            var candidate = Path.Combine(directory.FullName, "fixtures");

            if (Directory.Exists(Path.Combine(candidate, "bind")))
                return candidate;

            directory = directory.Parent;

        }

        return null;

    }


    public ValueTask DisposeAsync()
    {

        // Kill only the named instance bound to this fixture's config, then the
        // wsl.exe process holding its session open.
        Wsl.Run($"pkill -f 'named -c {workDirWsl}/named.conf' || true", TimeSpan.FromSeconds(10), asRoot: true);

        try
        {
            if (host is { HasExited: false })
                host.Kill(entireProcessTree: true);
        }
        catch { /* already gone */ }

        host?.Dispose();

        Wsl.Run($"rm -rf {workDirWsl} || true", TimeSpan.FromSeconds(10), asRoot: true);

        return ValueTask.CompletedTask;

    }

}

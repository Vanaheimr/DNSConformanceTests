using System.Text;

namespace DNSConformance.Core.Fixtures;

/// <summary>
/// One of the foreign authoritative servers the suite can put behind the
/// interop zone.
/// </summary>
/// <remarks>
/// BIND has a fixture of its own, because it is installed as a package and the
/// DNSSEC fixtures are signed with it. These three arrive as containers, which
/// is the only practical way to have three more implementations on hand — and
/// the point of having them is narrow but real: every one of them writes the
/// same zone onto the wire in its own encoder, so anything Hermod reads back
/// identically from all four is a property of the protocol rather than of one
/// implementation's habits.
/// </remarks>
public enum ForeignServer
{

    /// <summary>Knot DNS (CZ.NIC), an authoritative server.</summary>
    Knot,

    /// <summary>CoreDNS, the Kubernetes DNS, serving a zone through its file plugin.</summary>
    CoreDNS,

    /// <summary>
    /// Unbound (NLnet Labs), a validating resolver pressed into authoritative
    /// service through <c>auth-zone</c>. Off-label but legitimate, and its
    /// encoder is a fourth independent one.
    /// </summary>
    Unbound

}


/// <summary>
/// A foreign authoritative server running in a container, serving
/// <c>interop.test</c> from the same zone file BIND is given.
/// </summary>
public sealed class ForeignServerFixture : IAsyncDisposable
{

    #region Data

    private readonly String  containerName;
    private readonly String  workDir;

    /// <summary>The server this fixture is running.</summary>
    public ForeignServer  Server    { get; }

    /// <summary>The port it answers on.</summary>
    public UInt16         Port      { get; }

    /// <summary>The address a client on this machine must use to reach it.</summary>
    public String         Address   { get; private set; } = "127.0.0.1";

    /// <summary>Whatever the container last said, kept for failure messages.</summary>
    public String         LogTail   { get; private set; } = "";

    #endregion

    private ForeignServerFixture(ForeignServer  Server,
                                 UInt16         Port,
                                 String         ContainerName,
                                 String         WorkDir)
    {
        this.Server         = Server;
        this.Port           = Port;
        this.containerName  = ContainerName;
        this.workDir        = WorkDir;
    }


    #region Image(Server), IsAvailable(...)

    /// <summary>The container image each server comes from.</summary>
    public static String Image(ForeignServer Server)

        => Server switch {
               ForeignServer.Knot     => "cznic/knot",
               ForeignServer.CoreDNS  => "coredns/coredns",
               ForeignServer.Unbound  => "mvance/unbound",
               _                      => throw new ArgumentOutOfRangeException(nameof(Server))
           };

    /// <summary>
    /// Whether a container of this server could be started right now: a shell, a
    /// Docker daemon answering, and the image already pulled.
    /// </summary>
    /// <remarks>
    /// The image is deliberately not pulled on demand. A test run that quietly
    /// downloads a hundred megabytes is a test run whose first failure is a
    /// timeout somewhere unrelated; the workflow and the README both say to pull
    /// them up front.
    /// </remarks>
    public static Boolean IsAvailable(ForeignServer Server)

        => Wsl.IsAvailable                                                                          &&
           Wsl.Run("docker info --format '{{.ServerVersion}}'", TimeSpan.FromSeconds(30), asRoot: true).Success &&
           Wsl.Run($"docker image inspect {Image(Server)}",     TimeSpan.FromSeconds(60), asRoot: true).Success;

    #endregion

    #region (static) StartAsync(Server, Port = null)

    public static async Task<ForeignServerFixture> StartAsync(ForeignServer  Server,
                                                              UInt16?        Port   = null)
    {

        var port           = Port ?? (UInt16) Random.Shared.Next(20000, 60000);
        var containerName  = $"hermod-interop-{Server.ToString().ToLowerInvariant()}-{Guid.NewGuid():N}"[..40];
        var workDir        = $"/tmp/hermod-foreign-{Guid.NewGuid():N}";

        var fixtures       = FindFixturesDirectory()
                                 ?? throw new DirectoryNotFoundException("fixtures/bind/interop.test.zone not found!");

        var fixturesWsl    = Wsl.ToWslPath(fixtures);

        // The zone is BIND's, byte for byte, with the CRs a Windows checkout adds
        // stripped — none of these three tolerate them. $ORIGIN is prepended
        // because unbound's auth-zone parser wants the zone to name itself, while
        // Knot and CoreDNS take the origin from their configuration.
        var stage = Wsl.Run(
                        $"mkdir -p '{workDir}/run' && " +
                        $"{{ printf '$ORIGIN interop.test.\\n'; tr -d '\\r' < '{fixturesWsl}/bind/interop.test.zone'; }} > '{workDir}/interop.test.zone' && " +
                        $"cat > '{workDir}/{ConfigFileName(Server)}' <<'HERMODCFG'\n{Config(Server, port)}\nHERMODCFG\n" +
                        "echo staged",
                        TimeSpan.FromSeconds(30),
                        asRoot: true
                    );

        if (!stage.StdOut.Contains("staged"))
            throw new InvalidOperationException($"Could not stage the {Server} fixture directory:\n{stage.StdOut}\n{stage.StdErr}");

        var fixture = new ForeignServerFixture(Server, port, containerName, workDir) {
                          Address = Wsl.VmAddress ?? "127.0.0.1"
                      };

        // --network host puts the server on the WSL VM's own addresses, which is
        // what lets a client on the Windows side reach it at all: WSL2's NAT
        // relay forwards TCP but not UDP, so the VM has to be addressed directly.
        var run = Wsl.Run(
                      $"docker rm -f {containerName} >/dev/null 2>&1; " +
                      $"docker run -d --name {containerName} --network host " +
                      $"-v {workDir}:/zones {Entrypoint(Server)}{Image(Server)} {Command(Server)}",
                      TimeSpan.FromSeconds(120),
                      asRoot: true
                  );

        if (!run.Success)
        {
            await fixture.DisposeAsync();
            throw new InvalidOperationException($"Could not start {Server}: {run.StdOut}\n{run.StdErr}");
        }

        for (var attempt = 0; attempt < 30; attempt++)
        {

            await Task.Delay(250);

            var probe = Wsl.Run($"dig @127.0.0.1 -p {port} +time=1 +tries=1 +short a.interop.test A",
                                TimeSpan.FromSeconds(6));

            if (probe.StdOut.Contains("192.0.2.1"))
                return fixture;

        }

        fixture.LogTail = Wsl.Run($"docker logs --tail 20 {containerName} 2>&1", TimeSpan.FromSeconds(20), asRoot: true).StdOut;

        var logs = fixture.LogTail;
        await fixture.DisposeAsync();

        throw new InvalidOperationException($"{Server} did not answer on port {port}.\nlog:\n{logs}");

    }

    #endregion

    #region (private static) ConfigFileName(Server), Command(Server), Config(Server, Port)

    private static String ConfigFileName(ForeignServer Server)

        => Server switch {
               ForeignServer.Knot     => "knot.conf",
               ForeignServer.CoreDNS  => "Corefile",
               ForeignServer.Unbound  => "unbound.conf",
               _                      => throw new ArgumentOutOfRangeException(nameof(Server))
           };

    /// <summary>
    /// Unbound's image expects a whole command rather than arguments, so its
    /// first word lands as the executable and the container dies with a
    /// "-d: executable file not found". The other two take arguments as they are.
    /// </summary>
    private static String Entrypoint(ForeignServer Server)

        => Server == ForeignServer.Unbound
               ? "--entrypoint unbound "
               : "";

    private static String Command(ForeignServer Server)

        => Server switch {
               ForeignServer.Knot     => "knotd -c /zones/knot.conf",
               ForeignServer.CoreDNS  => "-conf /zones/Corefile",
               ForeignServer.Unbound  => "-d -c /zones/unbound.conf",
               _                      => throw new ArgumentOutOfRangeException(nameof(Server))
           };

    /// <summary>
    /// The smallest configuration that makes each of them serve one zone.
    /// </summary>
    /// <remarks>
    /// Kept here rather than under <c>fixtures/</c> because each carries a quirk
    /// that is only intelligible next to the others, and the quirks are the
    /// interesting part of getting three foreign servers to agree to the same
    /// job.
    /// </remarks>
    private static String Config(ForeignServer Server, UInt16 Port)

        => Server switch {

               // zonefile-sync -1 keeps knotd from writing the zone back out,
               // which it otherwise wants a journal for.
               ForeignServer.Knot =>
                   new StringBuilder().
                       AppendLine("server:").
                       AppendLine($"    listen: 0.0.0.0@{Port}").
                       AppendLine("    rundir: \"/zones/run\"").
                       AppendLine().
                       AppendLine("database:").
                       AppendLine("    storage: \"/zones/run\"").
                       AppendLine().
                       AppendLine("zone:").
                       AppendLine("  - domain: interop.test.").
                       AppendLine("    file: \"/zones/interop.test.zone\"").
                       AppendLine("    zonefile-sync: -1").
                       ToString(),

               ForeignServer.CoreDNS =>
                   new StringBuilder().
                       AppendLine($"interop.test:{Port} {{").
                       AppendLine("    file /zones/interop.test.zone").
                       AppendLine("}").
                       ToString(),

               // local-zone "test." nodefault is the one that is easy to lose an
               // afternoon to: RFC 6761 reserves .test, unbound ships a built-in
               // local zone for it, and that shadows the auth-zone silently — the
               // zone file is read, logged as read, and every query still comes
               // back NXDOMAIN.
               ForeignServer.Unbound =>
                   new StringBuilder().
                       AppendLine("server:").
                       AppendLine($"    interface: 0.0.0.0@{Port}").
                       AppendLine("    access-control: 0.0.0.0/0 allow").
                       AppendLine("    username: \"\"").
                       AppendLine("    chroot: \"\"").
                       AppendLine("    directory: \"/zones\"").
                       AppendLine("    logfile: \"\"").
                       AppendLine("    do-ip6: no").
                       AppendLine("    module-config: \"iterator\"").
                       AppendLine("    local-zone: \"test.\" nodefault").
                       AppendLine().
                       AppendLine("auth-zone:").
                       AppendLine("    name: \"interop.test.\"").
                       AppendLine("    zonefile: \"/zones/interop.test.zone\"").
                       AppendLine("    for-downstream: yes").
                       AppendLine("    for-upstream: no").
                       ToString(),

               _ => throw new ArgumentOutOfRangeException(nameof(Server))

           };

    #endregion

    #region (private static) FindFixturesDirectory()

    private static String? FindFixturesDirectory()
    {

        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {

            var candidate = Path.Combine(directory.FullName, "fixtures");

            if (File.Exists(Path.Combine(candidate, "bind", "interop.test.zone")))
                return candidate;

            directory = directory.Parent;

        }

        return null;

    }

    #endregion

    #region DisposeAsync()

    public ValueTask DisposeAsync()
    {

        Wsl.Run($"docker rm -f {containerName} >/dev/null 2>&1; rm -rf {workDir}",
                TimeSpan.FromSeconds(60),
                asRoot: true);

        return ValueTask.CompletedTask;

    }

    #endregion

}

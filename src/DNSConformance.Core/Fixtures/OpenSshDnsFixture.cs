using System.Diagnostics;
using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

namespace DNSConformance.Core.Fixtures;

/// <summary>
/// DNS over SSH with nothing of Hermod's on the server side: OpenSSH's
/// <c>sshd</c> inside WSL with a <c>Subsystem dns@open.charging.cloud</c> line
/// that runs <c>socat</c> to an ISC BIND on the VM's loopback - appendix B.1 of
/// the white paper "DNS over SSH", with a throwaway host key and a throwaway
/// user key.
/// </summary>
/// <remarks>
/// <para>
/// BIND is the <see cref="BindServerFixture"/>, serving the interop zone. What
/// this adds is the SSH in front of it: a host key made by <c>ssh-keygen</c>, an
/// <c>authorized_keys</c> holding the one key Hermod generated for the run,
/// marked <c>restrict</c> as appendix B has it, and a <c>sshd</c> on a high port
/// of the VM's own address, which is where a client on the Windows side reaches
/// it.
/// </para>
/// <para>
/// Everything lives under <c>/tmp</c>: <c>sshd</c> will not take a host key from
/// the DrvFs mount, whose files are readable by all. Nothing is installed and
/// nothing of the machine's own SSH configuration is read or changed.
/// </para>
/// </remarks>
public sealed class OpenSshDnsFixture : IAsyncDisposable
{

    private readonly String    workDirWsl;
    private readonly Process?  host;

    /// <summary>The name of the subsystem, as the <c>Subsystem</c> line of sshd_config has it.</summary>
    public const String SubsystemName = "dns@open.charging.cloud";

    /// <summary>The BIND behind the subsystem, which can be asked directly as well.</summary>
    public BindServerFixture  Bind          { get; }

    /// <summary>The address Windows-side clients dial: the VM's own.</summary>
    public String             Address       { get; }

    public UInt16             Port          { get; }

    /// <summary>Who signs in: whoever sshd runs as.</summary>
    public String             Login         { get; }

    /// <summary>The public key blob of the host key ssh-keygen made, for a client to pin.</summary>
    public Byte[]             HostKeyBlob   { get; }

    /// <summary>The key the server accepts.</summary>
    public ISshHostKey        ClientKey     { get; }

    private OpenSshDnsFixture(BindServerFixture Bind, String Address, UInt16 Port, String Login, Byte[] HostKeyBlob, ISshHostKey ClientKey, String WorkDirWsl, Process? Host)
    {
        this.Bind         = Bind;
        this.Address      = Address;
        this.Port         = Port;
        this.Login        = Login;
        this.HostKeyBlob  = HostKeyBlob;
        this.ClientKey    = ClientKey;
        workDirWsl        = WorkDirWsl;
        host              = Host;
    }


    /// <summary>
    /// The login of a client: the user key, and the host key pinned - to the
    /// server's, unless told otherwise.
    /// </summary>
    public SshClientOptions ClientOptions(Byte[]? PinnedHostKeyBlob = null)
    {

        var pinned = PinnedHostKeyBlob ?? HostKeyBlob;

        return new SshClientOptions {
                   Username       = Login,
                   VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(pinned),
                   Credentials    = [ ClientKey ]
               };

    }

    /// <summary>The last lines sshd wrote, for a test that has to say why it failed.</summary>
    public String LogTail()
        => Wsl.Run($"tail -30 {workDirWsl}/sshd.log 2>/dev/null", TimeSpan.FromSeconds(10), asRoot: true).StdOut;

    /// <summary>
    /// How many lines of sshd's log hold the given text, e.g. "Accepted
    /// publickey": what the server itself says happened, counted.
    /// </summary>
    public Int32 LogCount(String Text)
        => Int32.TryParse(Wsl.Run($"grep -c -F '{Text}' {workDirWsl}/sshd.log 2>/dev/null", TimeSpan.FromSeconds(10), asRoot: true).StdOut.Trim(), out var count)
               ? count
               : 0;


    public static async Task<OpenSshDnsFixture> StartAsync()
    {

        var bind        = await BindServerFixture.StartAsync();

        var port        = (UInt16) Random.Shared.Next(20000, 60000);
        var workDirWsl  = $"/tmp/hermod-sshd-{Guid.NewGuid():N}";
        var clientKey   = SshHostKey.GenerateEd25519();
        var authorized  = $"restrict ssh-ed25519 {Convert.ToBase64String(clientKey.PublicKeyBlob)} hermod-interop";

        Process? host   = null;

        try
        {

            // Appendix B.1, with the paths of a temporary directory and
            // StrictModes off for it, as the appendix says its own test ran.
            // /run/sshd is the privilege separation directory sshd insists on.
            var stage = Wsl.Run(
                            $"mkdir -p '{workDirWsl}' /run/sshd && " +
                            $"ssh-keygen -q -t ed25519 -N '' -f '{workDirWsl}/host_key' && " +
                            $"printf '%s\\n' '{authorized}' > '{workDirWsl}/authorized_keys' && " +
                            $"chmod 600 '{workDirWsl}/authorized_keys' && " +
                            $"printf '%s\\n' " +
                                $"'Port {port}' " +
                                $"'ListenAddress 0.0.0.0' " +
                                $"'HostKey {workDirWsl}/host_key' " +
                                $"'PidFile {workDirWsl}/sshd.pid' " +
                                $"'AuthorizedKeysFile {workDirWsl}/authorized_keys' " +
                                $"'PasswordAuthentication no' " +
                                $"'KbdInteractiveAuthentication no' " +
                                $"'StrictModes no' " +
                                $"'UsePAM no' " +
                                $"'PermitRootLogin prohibit-password' " +
                                $"'Subsystem {SubsystemName} /usr/bin/socat STDIO TCP:127.0.0.1:{bind.Port}' " +
                                $"> '{workDirWsl}/sshd_config' && " +
                            $"/usr/sbin/sshd -t -f '{workDirWsl}/sshd_config' && " +
                            $"echo login=$(id -un) && cat '{workDirWsl}/host_key.pub' && echo staged",
                            TimeSpan.FromSeconds(30),
                            asRoot: true
                        );

            if (!stage.StdOut.Contains("staged"))
                throw new InvalidOperationException($"Could not stage sshd:\n{stage}");

            var lines    = stage.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var login    = lines.First(line => line.StartsWith("login=", StringComparison.Ordinal))["login=".Length..];
            var hostKey  = Convert.FromBase64String(lines.First(line => line.StartsWith("ssh-ed25519 ", StringComparison.Ordinal)).Split(' ')[1]);

            // In the foreground, held open for the fixture's lifetime - see
            // BindServerFixture for why nothing else survives under WSL.
            host         = Wsl.StartDetached($"/usr/sbin/sshd -D -e -f {workDirWsl}/sshd_config > {workDirWsl}/sshd.log 2>&1");

            var address  = Wsl.VmAddress ?? "127.0.0.1";

            var fixture  = new OpenSshDnsFixture(bind, address, port, login, hostKey, clientKey, workDirWsl, host);

            // Ready when the port takes a connection from this side - which is
            // also the answer to whether the VM can be reached from here at all.
            for (var attempt = 0; attempt < 25; attempt++)
            {

                await Task.Delay(200);

                try
                {
                    using var probe = new TcpClient();
                    await probe.ConnectAsync(address, port).WaitAsync(TimeSpan.FromSeconds(2));
                    return fixture;
                }
                catch (Exception)
                { }

            }

            var log = fixture.LogTail();

            await fixture.DisposeAsync();

            throw new InvalidOperationException($"sshd did not become reachable at {address}:{port}.\nlog:\n{log}");

        }
        catch when (host is null)
        {
            Wsl.Run($"rm -rf {workDirWsl} || true", TimeSpan.FromSeconds(10), asRoot: true);
            await bind.DisposeAsync();
            throw;
        }

    }


    public async ValueTask DisposeAsync()
    {

        // Only the sshd of this fixture's config, and the sessions it forked.
        Wsl.Run($"pkill -f 'sshd -D -e -f {workDirWsl}/sshd_config' || true", TimeSpan.FromSeconds(10), asRoot: true);

        try
        {
            if (host is { HasExited: false })
                host.Kill(entireProcessTree: true);
        }
        catch { /* already gone */ }

        host?.Dispose();

        Wsl.Run($"rm -rf {workDirWsl} || true", TimeSpan.FromSeconds(10), asRoot: true);

        await Bind.DisposeAsync();

    }

}

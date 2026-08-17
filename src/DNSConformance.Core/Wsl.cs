using System.Diagnostics;
using System.Text;

namespace DNSConformance.Core;

/// <summary>
/// Bridge to the GNU/Linux DNS tools (dig, kdig, delv, drill, named,
/// dnssec-signzone, …) the interop tests drive.
/// </summary>
/// <remarks>
/// <para>
/// On Windows those tools live inside WSL and every command goes through
/// <c>wsl.exe</c>, which is where the name comes from. On a Linux host they are
/// simply installed, and the bridge runs <c>/bin/sh</c> directly.
/// </para>
/// <para>
/// The distinction matters for more than the process launch. Under WSL the
/// tools sit in a separate network namespace, so reaching a server on the
/// Windows side means finding a gateway address and the Windows firewall gets a
/// vote; natively there is one host, one loopback, and no firewall in the way.
/// That is why the same interop tests can be permanently skipped on a developer
/// machine and run without ceremony on a Linux CI runner.
/// </para>
/// </remarks>
public static class Wsl
{

    private static readonly Dictionary<String, Boolean> toolCache = [];
    private static readonly Lock                        cacheLock = new();

    /// <summary>
    /// Whether commands have to be tunnelled through <c>wsl.exe</c> rather than
    /// executed directly.
    /// </summary>
    public static Boolean UsesWslBridge
        => OperatingSystem.IsWindows();


    public sealed record Result(Int32 ExitCode, String StdOut, String StdErr)
    {

        public Boolean Success
            => ExitCode == 0;

        public override String ToString()
            => $"exit {ExitCode}\nstdout:\n{StdOut}\nstderr:\n{StdErr}";

    }


    /// <summary>
    /// Run a POSIX shell command — inside the default WSL distribution on
    /// Windows, or directly on a Linux host.
    /// </summary>
    /// <param name="shellCommand">The command, as <c>sh</c> would read it.</param>
    /// <param name="timeout">How long to wait before killing the process tree.</param>
    /// <param name="asRoot">Run as root. Under WSL that is a flag; natively it means the process is expected to already be root, as it is inside a CI container — no sudo is invoked, because a runner that needs one should say so rather than prompt.</param>
    public static Result Run(String    shellCommand,
                             TimeSpan? timeout   = null,
                             Boolean   asRoot    = false)
    {

        using var process = Process.Start(BuildStartInfo(shellCommand, asRoot))
                                ?? throw new InvalidOperationException("Could not start the shell!");

        var stdOutTask = process.StandardOutput.ReadToEndAsync();
        var stdErrTask = process.StandardError. ReadToEndAsync();

        if (!process.WaitForExit((Int32) (timeout ?? TimeSpan.FromSeconds(30)).TotalMilliseconds))
        {

            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch { /* already gone */ }

            return new Result(-1, stdOutTask.IsCompleted ? stdOutTask.Result : "", $"timeout after {timeout ?? TimeSpan.FromSeconds(30)}");

        }

        return new Result(process.ExitCode, stdOutTask.Result, stdErrTask.Result);

    }


    /// <summary>
    /// Start a long-running command without waiting for it to finish — through
    /// <c>wsl.exe</c> on Windows, directly via <c>/bin/sh</c> on a Linux host.
    /// The caller owns the returned process and must kill it (named runs until stopped).
    /// </summary>
    public static Process StartDetached(String shellCommand, Boolean asRoot = true)

        => Process.Start(BuildStartInfo(shellCommand, asRoot))
               ?? throw new InvalidOperationException("Could not start the shell!");


    /// <summary>
    /// The launch recipe both entry points share. Under the bridge the command
    /// is embedded into wsl.exe's argument string, which needs its quotes
    /// escaped. Natively it goes through ArgumentList instead, and deliberately
    /// so: an Arguments string is re-parsed with backslash rules, so a fixture
    /// writing a config file via <c>printf '%s\n'</c> would come out the other
    /// side as a literal backslash-n — the whole file one long line.
    /// ArgumentList hands the command to <c>sh -c</c> byte for byte.
    /// </summary>
    private static ProcessStartInfo BuildStartInfo(String shellCommand, Boolean asRoot)
    {

        var psi = new ProcessStartInfo {
                      FileName                = UsesWslBridge ? "wsl.exe" : "/bin/sh",
                      RedirectStandardOutput  = true,
                      RedirectStandardError   = true,
                      UseShellExecute         = false,
                      CreateNoWindow          = true,
                      StandardOutputEncoding  = Encoding.UTF8,
                      StandardErrorEncoding   = Encoding.UTF8
                  };

        if (UsesWslBridge)
        {
            psi.Arguments = asRoot
                                ? $"-u root -e sh -c \"{shellCommand.Replace("\"", "\\\"")}\""
                                : $"-e sh -c \"{shellCommand.Replace("\"", "\\\"")}\"";
        }
        else
        {
            // asRoot is not sudo: natively the process is expected to already be root,
            // as it is inside a CI container.
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add(shellCommand);
        }

        return psi;

    }


    /// <summary>
    /// True when a POSIX shell can be run: <c>wsl.exe</c> exists and its default
    /// distribution starts, or — on a Linux host — <c>/bin/sh</c> answers.
    /// </summary>
    public static Boolean IsAvailable
        => available.Value;

    private static readonly Lazy<Boolean> available = new(() => {
        try
        {
            return Run("true", TimeSpan.FromSeconds(20)).Success;
        }
        catch
        {
            return false;
        }
    });


    /// <summary>
    /// True when the given tool is on the WSL PATH.
    /// </summary>
    public static Boolean HasTool(String tool)
    {

        lock (cacheLock)
        {

            if (toolCache.TryGetValue(tool, out var known))
                return known;

            var has = IsAvailable && Run($"command -v {tool}", TimeSpan.FromSeconds(15)).Success;
            toolCache[tool] = has;
            return has;

        }

    }


    /// <summary>
    /// The Windows host address as seen from inside WSL.
    /// Mirrored networking → 127.0.0.1; NAT → the default-route gateway.
    /// </summary>
    public static String? WindowsHostAddress
        => windowsHostAddress.Value;

    private static readonly Lazy<String?> windowsHostAddress = new(() => {

        if (!IsAvailable)
            return null;

        // Natively there is no "host" to reach across a boundary: the tools and
        // the server under test share one loopback.
        if (!UsesWslBridge)
            return "127.0.0.1";

        var mode = Run("wslinfo --networking-mode 2>/dev/null || true", TimeSpan.FromSeconds(15)).StdOut.Trim();

        if (mode.Equals("mirrored", StringComparison.OrdinalIgnoreCase))
            return "127.0.0.1";

        var gateway = Run("ip route show default | awk '{print $3; exit}'", TimeSpan.FromSeconds(15)).StdOut.Trim();

        return gateway.Length > 0 ? gateway : null;

    });


    /// <summary>
    /// The WSL VM's own address as seen from Windows (eth0). Needed because
    /// WSL2's NAT localhost relay forwards TCP but not UDP — UDP clients on the
    /// Windows side must address the VM directly.
    /// </summary>
    public static String? VmAddress
        => vmAddress.Value;

    private static readonly Lazy<String?> vmAddress = new(() => {

        if (!IsAvailable)
            return null;

        // There is no VM natively — the "other side" is this machine.
        if (!UsesWslBridge)
            return "127.0.0.1";

        var mode = Run("wslinfo --networking-mode 2>/dev/null || true", TimeSpan.FromSeconds(15)).StdOut.Trim();

        if (mode.Equals("mirrored", StringComparison.OrdinalIgnoreCase))
            return "127.0.0.1";

        var address = Run("ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1", TimeSpan.FromSeconds(15)).StdOut.Trim();

        return address.Length > 0 ? address : null;

    });


    /// <summary>
    /// Convert a path to the form the shell will see: the <c>/mnt/…</c>
    /// equivalent under WSL, and the path itself on a Linux host.
    /// </summary>
    public static String ToWslPath(String windowsPath)
    {

        if (!UsesWslBridge)
            return Path.GetFullPath(windowsPath);

        var full = Path.GetFullPath(windowsPath).Replace('\\', '/');

        if (full.Length >= 2 && full[1] == ':')
            return $"/mnt/{Char.ToLowerInvariant(full[0])}{full[2..]}";

        return full;

    }

}

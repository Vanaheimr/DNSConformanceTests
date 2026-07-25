using System.Diagnostics;
using System.Text;

namespace DNSConformance.Core;

/// <summary>
/// Bridge to the local WSL distribution for running GNU/Linux DNS tools
/// (dig, kdig, delv, drill, named, dnssec-signzone, …) from tests.
/// </summary>
public static class Wsl
{

    private static readonly Dictionary<String, Boolean> toolCache = [];
    private static readonly Lock                        cacheLock = new();


    public sealed record Result(Int32 ExitCode, String StdOut, String StdErr)
    {

        public Boolean Success
            => ExitCode == 0;

        public override String ToString()
            => $"exit {ExitCode}\nstdout:\n{StdOut}\nstderr:\n{StdErr}";

    }


    /// <summary>Run a POSIX shell command inside the default WSL distribution.</summary>
    public static Result Run(String    shellCommand,
                             TimeSpan? timeout   = null,
                             Boolean   asRoot    = false)
    {

        var arguments = asRoot
                            ? $"-u root -e sh -c \"{shellCommand.Replace("\"", "\\\"")}\""
                            : $"-e sh -c \"{shellCommand.Replace("\"", "\\\"")}\"";

        var psi = new ProcessStartInfo {
                      FileName                = "wsl.exe",
                      Arguments               = arguments,
                      RedirectStandardOutput  = true,
                      RedirectStandardError   = true,
                      UseShellExecute         = false,
                      CreateNoWindow          = true,
                      StandardOutputEncoding  = Encoding.UTF8,
                      StandardErrorEncoding   = Encoding.UTF8
                  };

    using var process = Process.Start(psi)
                            ?? throw new InvalidOperationException("Could not start wsl.exe!");

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


    /// <summary>True when wsl.exe exists and the default distribution starts.</summary>
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


    /// <summary>True when the given tool is on the WSL PATH.</summary>
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

        var mode = Run("wslinfo --networking-mode 2>/dev/null || true", TimeSpan.FromSeconds(15)).StdOut.Trim();

        if (mode.Equals("mirrored", StringComparison.OrdinalIgnoreCase))
            return "127.0.0.1";

        var address = Run("ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1", TimeSpan.FromSeconds(15)).StdOut.Trim();

        return address.Length > 0 ? address : null;

    });


    /// <summary>Convert a Windows path to its /mnt/... WSL equivalent.</summary>
    public static String ToWslPath(String windowsPath)
    {

        var full = Path.GetFullPath(windowsPath).Replace('\\', '/');

        if (full.Length >= 2 && full[1] == ':')
            return $"/mnt/{Char.ToLowerInvariant(full[0])}{full[2..]}";

        return full;

    }

}

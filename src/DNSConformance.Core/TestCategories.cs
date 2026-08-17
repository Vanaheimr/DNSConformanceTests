namespace DNSConformance.Core;

/// <summary>
/// NUnit category names used to gate tests on external prerequisites.
/// Default CI filter: TestCategory!=Online&amp;TestCategory!=WSL&amp;TestCategory!=Docker.
/// </summary>
public static class TestCategories
{

    /// <summary>
    /// Needs outbound internet (public resolvers).
    /// </summary>
    public const String Online      = "Online";

    /// <summary>
    /// Needs WSL with the GNU/Linux DNS tools installed (dig/kdig/delv/drill/named).
    /// </summary>
    public const String Wsl         = "WSL";

    /// <summary>
    /// Needs a reachable Docker daemon.
    /// </summary>
    public const String Docker      = "Docker";

    /// <summary>
    /// Longer-running tests (&gt; ~5 s).
    /// </summary>
    public const String Slow        = "Slow";

    /// <summary>
    /// Encodes an RFC requirement Hermod is currently known to violate — see FINDINGS.md.
    /// </summary>
    public const String KnownIssue  = "KnownIssue";

}

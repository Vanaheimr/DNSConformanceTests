using System.Globalization;
using System.Text.RegularExpressions;

using NUnit.Framework;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// Whether the BIND-signed fixtures are still inside their validity window.
/// </summary>
/// <remarks>
/// <para>
/// Not a conformance test. It exists because the committed fixtures carry real
/// signatures with real lifetimes — `dnssec-signzone` gives them thirty days —
/// and the day they lapse, roughly twenty DNSSEC tests go red at once with
/// messages about Hermod. "Expected Secure, But was Bogus" is a true statement
/// and an actively misleading one: an expired RRSIG *is* bogus, the validator is
/// right, and the defect is in the fixture.
/// </para>
/// <para>
/// It happened on 2026-09-14, two days after the signatures lapsed, and cost an
/// investigation that ruled out a Hermod revision before anyone looked at a
/// date. One named test failing with a date and a script name would have said it
/// immediately, which is all this is.
/// </para>
/// <para>
/// The files are read here rather than through <see cref="SignedZoneFixture"/>:
/// a guard that depends on the parser it is meant to exonerate is no guard. The
/// RRSIG presentation form puts the two timestamps next to each other —
/// expiration first, then inception, per RFC 4034 §3.2 — and nothing else in a
/// signed zone is two fourteen-digit numbers in a row.
/// </para>
/// </remarks>
[TestFixture]
public class FixtureFreshnessTests
{

    #region Data

    /// <summary>
    /// `&lt;expiration&gt; &lt;inception&gt; &lt;key tag&gt; &lt;signer&gt;`, as
    /// RFC 4034 §3.2 orders them in presentation format.
    /// </summary>
    private static readonly Regex ValidityWindow =
        new (@"(?<expiration>\d{14})\s+(?<inception>\d{14})\s+\d{1,5}\s+\S+",
             RegexOptions.Compiled);

    private sealed record Signature(String File, DateTime Inception, DateTime Expiration);

    #endregion

    #region The_Signed_Fixtures_Have_Not_Expired()

    [Test]
    public void The_Signed_Fixtures_Have_Not_Expired()
    {

        var signatures = ReadAllSignatures();
        var now        = DateTime.UtcNow;
        var earliest   = signatures.MinBy(s => s.Expiration)!;

        // Reported on the way past, so a green run still says how much room is
        // left rather than only that there is some.
        TestContext.Out.WriteLine(
            $"{signatures.Count} signatures across {signatures.Select(s => s.File).Distinct().Count()} zones; " +
            $"the first to lapse is {earliest.File} on {earliest.Expiration:yyyy-MM-dd HH:mm} UTC, " +
            $"in {(earliest.Expiration - now).TotalDays:F1} days.");

        Assert.That(earliest.Expiration,
                    Is.GreaterThan(now),
                    $"The signed DNSSEC fixtures expired on {earliest.Expiration:yyyy-MM-dd HH:mm} UTC " +
                    $"({(now - earliest.Expiration).TotalDays:F1} days ago), starting with {earliest.File}. " +
                    "Every test that expects a Secure verdict will report Bogus until they are renewed, " +
                    "and the validator is right to say so. Re-sign them: " +
                    "wsl -e sh -c 'cd /mnt/d/Coding/Vanaheimr/DNSConformanceTests && sh fixtures/zones/resign.sh'");

    }

    #endregion

    #region The_Signed_Fixtures_Are_Already_Valid()

    [Test]
    public void The_Signed_Fixtures_Are_Already_Valid()
    {

        // The other end of the window, and not hypothetical: a signature made on
        // a machine whose clock runs ahead is not yet valid here, and produces
        // the same Bogus verdicts from the other direction. RFC 4034 §3.1.5 has
        // both bounds, so a guard that only watches one is half a guard.
        var signatures = ReadAllSignatures();
        var now        = DateTime.UtcNow;
        var latest     = signatures.MaxBy(s => s.Inception)!;

        Assert.That(latest.Inception,
                    Is.LessThanOrEqualTo(now),
                    $"The signed DNSSEC fixtures do not become valid until " +
                    $"{latest.Inception:yyyy-MM-dd HH:mm} UTC, starting with {latest.File} — " +
                    "usually a clock that ran ahead while they were signed. Re-sign them here.");

    }

    #endregion

    #region Every_Signed_Zone_Actually_Carries_Signatures()

    [Test]
    public void Every_Signed_Zone_Actually_Carries_Signatures()
    {

        // What stops the two tests above from passing by finding nothing. A
        // truncated or half-written fixture has no validity window to be outside
        // of, and would sail through both.
        var directory = RequireSignedZoneDirectory();
        var empty     = new List<String>();

        foreach (var file in Directory.GetFiles(directory, "*.signed"))
            if (!ValidityWindow.IsMatch(File.ReadAllText(file)))
                empty.Add(Path.GetFileName(file));

        Assert.Multiple(() => {

            Assert.That(Directory.GetFiles(directory, "*.signed"),
                        Is.Not.Empty,
                        "there are signed zones to check at all");

            Assert.That(empty,
                        Is.Empty,
                        $"every signed zone carries at least one RRSIG — these do not: {String.Join(", ", empty)}");

        });

    }

    #endregion


    #region (private static) ReadAllSignatures(), RequireSignedZoneDirectory()

    private static List<Signature> ReadAllSignatures()
    {

        var directory  = RequireSignedZoneDirectory();
        var signatures = new List<Signature>();

        foreach (var file in Directory.GetFiles(directory, "*.signed"))
            foreach (Match match in ValidityWindow.Matches(File.ReadAllText(file)))
                signatures.Add(
                    new Signature(
                        Path.GetFileName(file),
                        Timestamp(match.Groups["inception"] .Value),
                        Timestamp(match.Groups["expiration"].Value)
                    )
                );

        Assert.That(signatures, Is.Not.Empty, "no RRSIG validity windows found in the signed fixtures");

        return signatures;

    }

    private static String RequireSignedZoneDirectory()
    {

        var directory = SignedZoneFixture.SignedZoneDirectory;

        if (directory is null || !Directory.Exists(directory))
            Assert.Ignore("fixtures/zones/signed is not present — nothing to check.");

        return directory!;

    }

    /// <summary>
    /// RFC 4034 §3.2: the presentation form of a signature time is
    /// <c>YYYYMMDDHHmmSS</c> in UTC.
    /// </summary>
    private static DateTime Timestamp(String Text)

        => DateTime.ParseExact(
               Text,
               "yyyyMMddHHmmss",
               CultureInfo.InvariantCulture,
               DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal
           );

    #endregion

}

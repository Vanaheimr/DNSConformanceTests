using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;

namespace DNSInterop.LinuxTools.Tests;

/// <summary>
/// BIND and Hermod reading the same hand-written zone file, compared record for
/// record rather than spot-checked.
/// </summary>
/// <remarks>
/// <para>
/// The DNSSEC fixtures are <c>named-compilezone</c> output: one record per line,
/// every name written out in full, every TTL a bare number. Three findings in a
/// row hid behind that shape rather than behind the code. A relative wildcard
/// (finding 51) and a bracketed <c>::1</c> (finding 50) cannot appear in such a
/// file at all, so the corpus could not refute them — and finding 50 was
/// actually *recorded* as an accepted divergence, because the only half of it
/// the fixtures could show was the harmless half.
/// </para>
/// <para>
/// <c>fixtures/bind/format.test.zone</c> is the answer: hand-written, containing
/// the directives, relative names, unit TTLs, wildcards and IPv6 forms the
/// generated corpus cannot contain. It is deliberately *not*
/// <c>interop.test.zone</c>, which four foreign servers are handed and which two
/// tests ask for a name that must come back NXDOMAIN — a wildcard there would
/// answer it instead.
/// </para>
/// <para>
/// The comparison is an exact set in both directions, so a record Hermod invents
/// fails as loudly as one it drops.
/// </para>
/// </remarks>
[TestFixture]
[Category(TestCategories.Wsl)]
[Property("RFC", "1035 §5.1")]
public class BindAgreesOnTheFormatZoneTests
{

    #region Data

    private const String Origin = "format.test.";

    private static String ZoneFile()
    {

        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {

            var candidate = Path.Combine(directory.FullName, "fixtures", "bind", "format.test.zone");

            if (File.Exists(candidate))
                return candidate;

            directory = directory.Parent;

        }

        Assert.Ignore("fixtures/bind/format.test.zone is not present.");
        return "";

    }

    /// <summary>
    /// One record, reduced to what both sides have to agree on: the owner name
    /// case-folded (RFC 4343), the TTL in seconds, the type, and the RDATA in
    /// presentation form.
    /// </summary>
    private readonly record struct Line(String Owner, UInt32 Ttl, String Type, String RData)
    {
        public override String ToString()
            => $"{Owner} {Ttl} {Type} {RData}";
    }

    /// <summary>
    /// The one thing the two sides are allowed to spell differently: the case of
    /// the hexadecimal digits in an RFC 3597 §5 generic RDATA.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §5 asks for "words of hexadecimal data" and says nothing about case; the
    /// section's own examples use both, <c>abcd ef 01 23 45</c> in one and
    /// <c>0A000001</c> in another. BIND writes upper, Hermod writes lower, and
    /// neither is more right.
    /// </para>
    /// <para>
    /// Finding 50 is the reason this is narrow rather than a general
    /// case-insensitive comparison. That divergence was also written down as
    /// harmless and was not: the half that mattered simply was not in the
    /// corpus. So this folds case only for RDATA that actually begins with the
    /// generic token, and leaves every other field — base-64 keys included,
    /// where case is content — compared exactly.
    /// </para>
    /// </remarks>
    private static Line Normalized(Line Line)

        => Line.RData.StartsWith(@"\#")
               ? Line with { RData = Line.RData.ToUpperInvariant() }
               : Line;

    /// <summary>
    /// Read BIND's flattened output. Each line is owner, TTL, class, type and
    /// the rest; the whitespace between them is BIND's own and carries nothing.
    /// </summary>
    private static Line[] AsBindReadsIt(String Path)
    {

        var result = Wsl.Run($"named-checkzone -D -o - {Origin} {Wsl.ToWslPath(Path)}",
                             TimeSpan.FromSeconds(30));

        if (result.ExitCode != 0)
            Assert.Fail($"named-checkzone refused the fixture: {result.StdErr}{result.StdOut}");

        var lines = new List<Line>();

        foreach (var text in result.StdOut.Split('\n'))
        {

            var line = text.Trim();

            if (line.Length == 0 || line.StartsWith(';') || line == "OK")
                continue;

            var fields = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);

            // owner ttl class type rdata…
            if (fields.Length < 5 || fields[2] != "IN")
                continue;

            lines.Add(new Line(
                          fields[0].TrimEnd('.').ToLowerInvariant(),
                          UInt32.Parse(fields[1]),
                          fields[3],
                          String.Join(" ", fields[4..])
                      ));

        }

        return [.. lines];

    }

    /// <summary>
    /// The same file through Hermod's own reader.
    /// </summary>
    private static Line[] AsHermodReadsIt(String Path)

        => [.. DNSZoneFile.Parse(
                   File.ReadAllText(Path),
                   DomainName.Parse(Origin)
               ).
               Select(record => new Line(
                                    record.DomainName.FullName.TrimEnd('.').ToLowerInvariant(),
                                    (UInt32) record.TimeToLive.TotalSeconds,
                                    ADNSResourceRecord.TypeName(record.Type),
                                    record.ToZoneFileString().
                                        Split(ADNSResourceRecord.TypeName(record.Type))[^1].
                                        Trim()
                                ))];

    #endregion

    #region Bind_And_Hermod_Read_The_Same_Records()

    [Test]
    public void Bind_And_Hermod_Read_The_Same_Records()
    {

        TestEnvironment.RequireWsl("named-checkzone");

        var path   = ZoneFile();
        var bind   = AsBindReadsIt  (path);
        var hermod = AsHermodReadsIt(path);

        Assert.That(bind, Is.Not.Empty, "the fixture has to produce records at all");

        var bindSet   = bind.  Select(Normalized).ToArray();
        var hermodSet = hermod.Select(Normalized).ToArray();

        var missing = bindSet.  Where(line => !hermodSet.Contains(line)).ToArray();
        var extra   = hermodSet.Where(line => !bindSet.  Contains(line)).ToArray();

        Assert.Multiple(() => {

            Assert.That(missing, Is.Empty,
                        "BIND read these and Hermod did not:" + Environment.NewLine +
                        String.Join(Environment.NewLine, missing.Select(l => "  " + l)));

            Assert.That(extra, Is.Empty,
                        "Hermod produced these and BIND did not:" + Environment.NewLine +
                        String.Join(Environment.NewLine, extra.Select(l => "  " + l)));

            Assert.That(hermod, Has.Length.EqualTo(bind.Length));

        });

    }

    #endregion

    #region The_Fixture_Still_Contains_What_It_Is_For()

    [Test]
    public void The_Fixture_Still_Contains_What_It_Is_For()
    {

        // The test above is only worth running while the file still holds the
        // cases it exists for. A fixture quietly trimmed of its wildcard or its
        // ::1 would keep passing and stop proving anything — which is precisely
        // how the generated corpus came to be missing them.
        var text = File.ReadAllText(ZoneFile());

        Assert.Multiple(() => {

            Assert.That(text, Does.Match(@"(?m)^\*\s"),          "a bare relative wildcard");
            Assert.That(text, Does.Contain("::1"),               "the loopback address finding 50 bracketed");
            Assert.That(text, Does.Match(@"(?m)^\$ORIGIN"),      "an $ORIGIN directive");
            Assert.That(text, Does.Match(@"\d+[hdwm]\s"),        "at least one TTL written with units");
            Assert.That(text, Does.Contain("_"),                 "an underscore name");
            Assert.That(text, Does.Contain(@"\#"),               "the RFC 3597 §5 generic form");

        });

    }

    #endregion

}

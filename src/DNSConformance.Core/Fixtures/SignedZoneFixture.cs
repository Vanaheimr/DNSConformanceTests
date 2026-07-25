using System.Globalization;
using System.Text;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Core.Fixtures;

/// <summary>
/// Loads the BIND-signed fixture zone (fixtures/zones/signed) so that Hermod's
/// DNSSEC validation is measured against signatures produced by an independent
/// implementation.
///
/// The file is the flattened output of <c>named-compilezone</c>: exactly one
/// resource record per line. Regenerate with <c>fixtures/zones/resign.sh</c>.
/// </summary>
public sealed class SignedZoneFixture
{

    public required String                              Origin      { get; init; }
    public required IReadOnlyList<IDNSResourceRecord>   Records     { get; init; }
    public required IReadOnlyList<DNSKEY>               DnsKeys     { get; init; }
    public required IReadOnlyList<RRSIG>                Signatures  { get; init; }
    public required DS                                  DelegationSigner { get; init; }

    /// <summary>The raw flattened zone file, for records the typed loader skips.</summary>
    public required IReadOnlyList<String>               RawLines    { get; init; }


    /// <summary>All records of one owner name and type — an RRset in the RFC 4034 §3.1 sense.</summary>
    public List<IDNSResourceRecord> RRset(String ownerName, DNSResourceRecordTypes type)
        => [.. Records.Where(rr => rr.Type == type &&
                                   String.Equals(rr.DomainName.FullName.TrimEnd('.'), ownerName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))];


    /// <summary>The RRSIG covering the given owner/type, if present.</summary>
    public RRSIG? SignatureFor(String ownerName, DNSResourceRecordTypes type)
        => Signatures.FirstOrDefault(sig => sig.TypeCovered == type &&
                                            String.Equals(sig.DomainName.FullName.TrimEnd('.'), ownerName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase));


    /// <summary>The DNSKEY matching an RRSIG's key tag and algorithm.</summary>
    public DNSKEY? KeyFor(RRSIG signature)
        => DnsKeys.FirstOrDefault(key => key.Algorithm == signature.Algorithm &&
                                         DNSSECValidator.ComputeKeyTag(key) == signature.KeyTag);


    /// <summary>
    /// The RRSIG covering a wildcard owner such as "*.wild.dnssec.test.".
    ///
    /// Two things make this awkward enough to deserve its own accessor. Hermod's
    /// <see cref="DomainName"/> cannot represent a "*" label at all, so the typed
    /// loader skips these lines; and the RRSIG's own owner name is not part of the
    /// signed data (RFC 4034 §3.1.8.1), so substituting a parseable owner changes
    /// nothing about what the signature covers. What matters — Labels, OriginalTTL,
    /// the validity window, KeyTag, SignerName and the signature itself — is
    /// preserved exactly.
    /// </summary>
    public RRSIG WildcardSignature(String                  WildcardOwner,
                                   DNSResourceRecordTypes  Type,
                                   String                  SubstituteOwner = "wildcard.invalid")
    {

        var wanted = WildcardOwner.TrimEnd('.') + ".";

        foreach (var line in RawLines)
        {

            var fields = line.Split((Char[]?) null, StringSplitOptions.RemoveEmptyEntries);

            if (fields.Length < 5                                                      ||
                !fields[0].Equals(wanted, StringComparison.OrdinalIgnoreCase)          ||
                fields[3] != "RRSIG"                                                   ||
                !fields[4].Equals(Type.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var rewritten = String.Join(' ', new[] { SubstituteOwner }.Concat(fields[1..]));

            if (TryParseFlatLine(rewritten, out var record) && record is RRSIG signature)
                return signature;

        }

        throw new InvalidOperationException(
                  $"No {Type} RRSIG for '{WildcardOwner}' in the {Origin} fixture — run fixtures/zones/resign.sh."
              );

    }


    /// <summary>The zone signing key (SEP bit clear) / key signing key (SEP bit set).</summary>
    public DNSKEY? ZoneSigningKey  => DnsKeys.FirstOrDefault(k => (k.Flags & 0x0001) == 0);
    public DNSKEY? KeySigningKey   => DnsKeys.FirstOrDefault(k => (k.Flags & 0x0001) != 0);


    #region Directory / availability

    /// <summary>The fixtures/zones/signed directory, located relative to the test assembly.</summary>
    public static String? SignedZoneDirectory
        => signedZoneDirectory.Value;

    private static readonly Lazy<String?> signedZoneDirectory = new(() => {

        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {

            var candidate = Path.Combine(directory.FullName, "fixtures", "zones", "signed");

            if (Directory.Exists(candidate))
                return candidate;

            directory = directory.Parent;

        }

        return null;

    });

    public static Boolean IsAvailable
        => IsAvailableFor("dnssec.test");

    public static Boolean IsAvailableFor(String Origin)
        => SignedZoneDirectory is not null &&
           File.Exists(Path.Combine(SignedZoneDirectory, $"{Origin}.zone.flat"));

    #endregion


    #region Load()

    public static SignedZoneFixture Load(String origin = "dnssec.test")
    {

        var directory = SignedZoneDirectory
                            ?? throw new FileNotFoundException("fixtures/zones/signed not found — run fixtures/zones/resign.sh (needs WSL + bind9utils).");

        var flatFile  = Path.Combine(directory, $"{origin}.zone.flat");

        if (!File.Exists(flatFile))
            throw new FileNotFoundException($"{flatFile} not found — run fixtures/zones/resign.sh (needs WSL + bind9utils).");

        var records  = new List<IDNSResourceRecord>();
        var rawLines = new List<String>();

        foreach (var rawLine in File.ReadAllLines(flatFile))
        {

            var line = rawLine.Trim();

            if (line.Length == 0 || line.StartsWith(';'))
                continue;

            rawLines.Add(line);

            if (TryParseFlatLine(line, out var record))
                records.Add(record);

        }

        var dsLine = File.ReadAllLines(Path.Combine(directory, $"{origin}.ds")).
                          First(l => l.Contains(" DS ", StringComparison.Ordinal));

        return new SignedZoneFixture {
                   Origin            = origin,
                   Records           = records,
                   DnsKeys           = [.. records.OfType<DNSKEY>()],
                   Signatures        = [.. records.OfType<RRSIG>()],
                   DelegationSigner  = ParseDs(dsLine),
                   RawLines          = rawLines
               };

    }

    #endregion


    #region Flat zone-file line parsing

    /// <summary>
    /// Parse "owner TTL IN TYPE rdata..." for the record types the DNSSEC
    /// fixtures use. Deliberately small and explicit: this is reference code
    /// for the suite, so it must not depend on Hermod's own zone-file parser.
    /// </summary>
    private static Boolean TryParseFlatLine(String line, out IDNSResourceRecord record)
    {

        record = null!;

        var fields = line.Split((Char[]?) null, StringSplitOptions.RemoveEmptyEntries);

        if (fields.Length < 5)
            return false;

        var owner = fields[0].TrimEnd('.');

        if (!UInt32.TryParse(fields[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var ttlSeconds))
            return false;

        if (fields[2] != "IN")
            return false;

        var ttl   = TimeSpan.FromSeconds(ttlSeconds);
        var type  = fields[3];
        var rdata = fields[4..];

        try
        {

            switch (type)
            {

                case "A":
                    record = new A(DomainName.Parse(owner), DNSQueryClasses.IN, ttl,
                                   org.GraphDefined.Vanaheimr.Hermod.IPv4Address.Parse(rdata[0]));
                    return true;

                case "AAAA":
                    record = new AAAA(DomainName.Parse(owner), DNSQueryClasses.IN, ttl,
                                      org.GraphDefined.Vanaheimr.Hermod.IPv6Address.Parse(rdata[0]));
                    return true;

                case "NS":
                    record = new NS(DomainName.Parse(owner), DNSQueryClasses.IN, ttl, DomainName.Parse(rdata[0].TrimEnd('.')));
                    return true;

                case "MX":
                    record = new MX(DomainName.Parse(owner), DNSQueryClasses.IN, ttl,
                                    UInt16.Parse(rdata[0]), DomainName.Parse(rdata[1].TrimEnd('.')));
                    return true;

                case "TXT":
                    record = new TXT(DomainName.Parse(owner), DNSQueryClasses.IN, ttl,
                                     String.Join(' ', rdata).Trim('"'));
                    return true;

                case "DNSKEY":
                    record = new DNSKEY(
                                 DomainName.Parse(owner),
                                 DNSQueryClasses.IN,
                                 ttl,
                                 UInt16.Parse(rdata[0]),
                                 Byte.  Parse(rdata[1]),
                                 Byte.  Parse(rdata[2]),
                                 Convert.FromBase64String(String.Concat(rdata[3..]))
                             );
                    return true;

                case "RRSIG":
                    record = new RRSIG(
                                 DomainName.Parse(owner),
                                 DNSQueryClasses.IN,
                                 ttl,
                                 ParseType(rdata[0]),
                                 Byte.  Parse(rdata[1]),
                                 Byte.  Parse(rdata[2]),
                                 UInt32.Parse(rdata[3]),
                                 ParseSigTime(rdata[4]),
                                 ParseSigTime(rdata[5]),
                                 UInt16.Parse(rdata[6]),
                                 DomainName.Parse(rdata[7].TrimEnd('.')),
                                 Convert.FromBase64String(String.Concat(rdata[8..]))
                             );
                    return true;

                case "SOA":
                    record = new SOA(
                                 DomainName.Parse(owner),
                                 DNSQueryClasses.IN,
                                 ttl,
                                 DomainName.Parse(rdata[0].TrimEnd('.')),
                                 org.GraphDefined.Vanaheimr.Hermod.Mail.SimpleEMailAddress.Parse(
                                     DNSTools.ReplaceFirstDotWithAt(rdata[1].TrimEnd('.'))
                                 ),
                                 UInt32.Parse(rdata[2]),
                                 TimeSpan.FromSeconds(UInt32.Parse(rdata[3])),
                                 TimeSpan.FromSeconds(UInt32.Parse(rdata[4])),
                                 TimeSpan.FromSeconds(UInt32.Parse(rdata[5])),
                                 TimeSpan.FromSeconds(UInt32.Parse(rdata[6]))
                             );
                    return true;

                default:
                    // NSEC and others are not needed by the current tests.
                    return false;

            }

        }
        catch
        {
            return false;
        }

    }


    private static DNSResourceRecordTypes ParseType(String text)
        => Enum.TryParse<DNSResourceRecordTypes>(text, true, out var type)
               ? type
               : throw new FormatException($"Unknown RR type '{text}'!");


    /// <summary>RRSIG timestamps are YYYYMMDDHHmmSS in the presentation format (RFC 4034 §3.2).</summary>
    private static UInt32 ParseSigTime(String text)
        => (UInt32) DateTimeOffset.ParseExact(
                        text,
                        "yyyyMMddHHmmss",
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal
                    ).ToUnixTimeSeconds();


    private static DS ParseDs(String line)
    {

        // "dnssec.test. IN DS 35687 8 2 C55F..."
        var fields = line.Split((Char[]?) null, StringSplitOptions.RemoveEmptyEntries);
        var dsAt   = Array.IndexOf(fields, "DS");

        return new DS(
                   DomainName.Parse(fields[0].TrimEnd('.')),
                   DNSQueryClasses.IN,
                   TimeSpan.FromHours(1),
                   UInt16.Parse(fields[dsAt + 1]),
                   Byte.  Parse(fields[dsAt + 2]),
                   Byte.  Parse(fields[dsAt + 3]),
                   Convert.FromHexString(String.Concat(fields[(dsAt + 4)..]))
               );

    }

    #endregion

}

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

    /// <summary>
    /// The raw flattened zone file, for records the typed loader skips.
    /// </summary>
    public required IReadOnlyList<String>               RawLines    { get; init; }


    /// <summary>
    /// All records of one owner name and type — an RRset in the RFC 4034 §3.1 sense.
    /// </summary>
    public List<IDNSResourceRecord> RRset(String ownerName, DNSResourceRecordTypes type)
        => [.. Records.Where(rr => rr.Type == type &&
                                   String.Equals(rr.DomainName.FullName.TrimEnd('.'), ownerName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))];


    /// <summary>
    /// The RRSIG covering the given owner/type, if present.
    /// </summary>
    public RRSIG? SignatureFor(String ownerName, DNSResourceRecordTypes type)
        => Signatures.FirstOrDefault(sig => sig.TypeCovered == type &&
                                            String.Equals(sig.DomainName.FullName.TrimEnd('.'), ownerName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase));


    /// <summary>
    /// The DNSKEY matching an RRSIG's key tag and algorithm.
    /// </summary>
    public DNSKEY? KeyFor(RRSIG signature)
        => DnsKeys.FirstOrDefault(key => key.Algorithm == signature.Algorithm &&
                                         DNSSECValidator.ComputeKeyTag(key) == signature.KeyTag);


    /// <summary>
    /// The zone signing key (SEP bit clear) / key signing key (SEP bit set).
    /// </summary>
    public DNSKEY? ZoneSigningKey  => DnsKeys.FirstOrDefault(k => (k.Flags & 0x0001) == 0);
    public DNSKEY? KeySigningKey   => DnsKeys.FirstOrDefault(k => (k.Flags & 0x0001) != 0);


    /// <summary>
    /// The whole fixture as a zone a Hermod server can be pointed at.
    /// </summary>
    /// <remarks>
    /// Every record goes in exactly as BIND wrote it, signatures and denial
    /// records included. Nothing is re-signed and nothing is computed: what the
    /// server then puts on the wire has to be a *selection* from these records,
    /// which is what makes it checkable — a served RRSIG or NSEC3 that is not
    /// byte-identical to one in this list was invented somewhere.
    /// </remarks>
    public InMemoryDNSZone ToZone()
        => new InMemoryDNSZone().Add(Records);


    #region Directory / availability

    /// <summary>
    /// The fixtures/zones/signed directory, located relative to the test assembly.
    /// </summary>
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
    ///
    /// Owner names go through ParseLenient, because a zone file legitimately holds
    /// label forms a hostname never has — underscore names and wildcards. RDATA
    /// targets stay on the strict parser: a CNAME or MX may not point at a wildcard.
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
                    record = new A(DomainName.ParseLenient(owner), DNSQueryClasses.IN, ttl,
                                   org.GraphDefined.Vanaheimr.Hermod.IPv4Address.Parse(rdata[0]));
                    return true;

                case "AAAA":
                    record = new AAAA(DomainName.ParseLenient(owner), DNSQueryClasses.IN, ttl,
                                      org.GraphDefined.Vanaheimr.Hermod.IPv6Address.Parse(rdata[0]));
                    return true;

                case "NS":
                    record = new NS(DomainName.ParseLenient(owner), DNSQueryClasses.IN, ttl, DomainName.Parse(rdata[0].TrimEnd('.')));
                    return true;

                case "DNAME":
                    record = new DNAME(DomainName.ParseLenient(owner), DNSQueryClasses.IN, ttl, DomainName.Parse(rdata[0].TrimEnd('.')));
                    return true;

                case "MX":
                    record = new MX(DomainName.ParseLenient(owner), DNSQueryClasses.IN, ttl,
                                    UInt16.Parse(rdata[0]), DomainName.Parse(rdata[1].TrimEnd('.')));
                    return true;

                case "TXT":
                    record = new TXT(DomainName.ParseLenient(owner), DNSQueryClasses.IN, ttl,
                                     String.Join(' ', rdata).Trim('"'));
                    return true;

                case "DNSKEY":
                    record = new DNSKEY(
                                 DomainName.ParseLenient(owner),
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
                                 DomainName.ParseLenient(owner),
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
                                 DomainName.ParseLenient(owner),
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

                case "NSEC":
                    // "<next owner> <type> <type> …" (RFC 4034 §4.2).
                    record = new NSEC(
                                 DomainName.ParseLenient(owner),
                                 DNSQueryClasses.IN,
                                 ttl,
                                 DomainName.ParseLenient(rdata[0]),
                                 EncodeTypeBitMaps(rdata[1..])
                             );
                    return true;

                case "NSEC3":
                    // "<alg> <flags> <iterations> <salt> <next hash> <type>…"
                    // (RFC 5155 §3.3). The salt is "-" when there is none, and
                    // the next hashed owner is Base32hex rather than hex.
                    record = new NSEC3(
                                 DomainName.ParseLenient(owner),
                                 DNSQueryClasses.IN,
                                 ttl,
                                 Byte.  Parse(rdata[0]),
                                 Byte.  Parse(rdata[1]),
                                 UInt16.Parse(rdata[2]),
                                 rdata[3] == "-" ? [] : Convert.FromHexString(rdata[3]),
                                 NSEC3.Base32HexDecode(rdata[4]),
                                 EncodeTypeBitMaps(rdata[5..])
                             );
                    return true;

                case "NSEC3PARAM":
                    record = new NSEC3PARAM(
                                 DomainName.ParseLenient(owner),
                                 DNSQueryClasses.IN,
                                 ttl,
                                 Byte.  Parse(rdata[0]),
                                 Byte.  Parse(rdata[1]),
                                 UInt16.Parse(rdata[2]),
                                 rdata[3] == "-" ? [] : Convert.FromHexString(rdata[3])
                             );
                    return true;

                default:
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


    /// <summary>
    /// Encode a list of RR type names as a type bit map (RFC 4034 §4.1.2).
    /// </summary>
    /// <remarks>
    /// Written here rather than borrowed from Hermod on purpose: these bitmaps
    /// are the input to the denial-of-existence tests, and a fixture that shared
    /// an encoder with the code under test would agree with its own mistakes.
    ///
    /// Layout is one block per 256-type window, each "window number, length,
    /// bitmap", windows in increasing order and never empty. Bit 0 of an octet
    /// is its most significant bit.
    /// </remarks>
    private static Byte[] EncodeTypeBitMaps(IEnumerable<String> Types)
    {

        var windows = new SortedDictionary<Byte, Byte[]>();

        foreach (var name in Types)
        {

            if (!Enum.TryParse<DNSResourceRecordTypes>(name, true, out var type))
                continue;

            var number = (UInt16) type;
            var window = (Byte) (number >> 8);

            if (!windows.TryGetValue(window, out var bitmap))
            {
                bitmap = new Byte[32];
                windows[window] = bitmap;
            }

            bitmap[(number & 0xFF) >> 3] |= (Byte) (0x80 >> (number & 0x07));

        }

        var result = new List<Byte>();

        foreach (var (window, bitmap) in windows)
        {

            // Trailing all-zero octets are not transmitted.
            var length = 32;
            while (length > 0 && bitmap[length - 1] == 0)
                length--;

            if (length == 0)
                continue;

            result.Add(window);
            result.Add((Byte) length);
            result.AddRange(bitmap[..length]);

        }

        return [.. result];

    }


    /// <summary>
    /// RRSIG timestamps are YYYYMMDDHHmmSS in the presentation format (RFC 4034 §3.2).
    /// </summary>
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

namespace DNSConformance.Core.RawDns;

/// <summary>
/// A DNS name as read from the wire by the independent RawDns reader:
/// original label bytes (case preserved), presentation form, and whether
/// compression pointers were followed while reading it.
/// </summary>
public sealed class RawName
{

    public required IReadOnlyList<Byte[]>  Labels          { get; init; }

    /// <summary>
    /// True if at least one RFC 1035 §4.1.4 compression pointer was followed.
    /// </summary>
    public required Boolean                Compressed      { get; init; }

    /// <summary>
    /// Bytes this name occupied at its primary location (pointers count as 2).
    /// </summary>
    public required Int32                  WireLength      { get; init; }

    /// <summary>
    /// Presentation form: labels joined by '.', special characters escaped per RFC 1035 §5.1, always ending in the root dot for non-root names omitted (root = ".").
    /// </summary>
    public String Presentation
        => Labels.Count == 0
               ? "."
               : String.Join('.', Labels.Select(EscapeLabel));

    /// <summary>
    /// Lower-cased presentation form for case-insensitive comparisons (RFC 1035 §2.3.3).
    /// </summary>
    public String Canonical
        => Presentation.ToLowerInvariant();

    private static String EscapeLabel(Byte[] label)
    {

        var sb = new System.Text.StringBuilder(label.Length);

        foreach (var b in label)
        {

            if (b is (Byte) '.' or (Byte) '\\')
                sb.Append('\\').Append((Char) b);

            else if (b < 0x21 || b > 0x7E)
                sb.Append('\\').Append(((Int32) b).ToString("D3"));

            else
                sb.Append((Char) b);

        }

        return sb.ToString();

    }

    public override String ToString()
        => Presentation;

}


public sealed class RawQuestion
{
    public required RawName  Name    { get; init; }
    public required UInt16   Type    { get; init; }
    public required UInt16   Class   { get; init; }
}


public sealed class RawRecord
{

    public required RawName  Name          { get; init; }
    public required UInt16   Type          { get; init; }
    public required UInt16   Class         { get; init; }
    public required UInt32   Ttl           { get; init; }
    public required Byte[]   Rdata         { get; init; }

    /// <summary>
    /// Absolute offset of the RDATA within the whole message (needed to decode compressed names inside RDATA).
    /// </summary>
    public required Int32    RdataOffset   { get; init; }

    public Boolean IsOpt
        => Type == RawDnsType.OPT;

}


/// <summary>
/// Decoded EDNS(0) view over an OPT record (RFC 6891 §6.1).
/// </summary>
public sealed class RawEdns
{

    public required UInt16                                      PayloadSize     { get; init; }
    public required Byte                                        ExtendedRcode   { get; init; }
    public required Byte                                        Version         { get; init; }
    public required UInt16                                      Flags           { get; init; }
    public required IReadOnlyList<(UInt16 Code, Byte[] Data)>   Options         { get; init; }

    /// <summary>
    /// DNSSEC OK bit (RFC 4035 §3.2.1 / RFC 6891 §6.1.4) = MSB of the flags.
    /// </summary>
    public Boolean Do
        => (Flags & 0x8000) != 0;

    public static RawEdns From(RawRecord Opt)
    {

        if (Opt.Type != RawDnsType.OPT)
            throw new ArgumentException("Not an OPT record!", nameof(Opt));

        var options  = new List<(UInt16, Byte[])>();
        var rdata    = Opt.Rdata;
        var offset   = 0;

        while (offset + 4 <= rdata.Length)
        {

            var code = (UInt16) ((rdata[offset]     << 8) | rdata[offset + 1]);
            var len  = (UInt16) ((rdata[offset + 2] << 8) | rdata[offset + 3]);
            offset  += 4;

            if (offset + len > rdata.Length)
                throw new RawDnsFormatException($"EDNS option {code} claims {len} bytes but only {rdata.Length - offset} remain!", Opt.RdataOffset + offset);

            options.Add((code, rdata[offset..(offset + len)]));
            offset += len;

        }

        if (offset != rdata.Length)
            throw new RawDnsFormatException($"{rdata.Length - offset} trailing bytes after last EDNS option!", Opt.RdataOffset + offset);

        return new RawEdns {
                   PayloadSize    = Opt.Class,
                   ExtendedRcode  = (Byte)   ((Opt.Ttl >> 24) & 0xFF),
                   Version        = (Byte)   ((Opt.Ttl >> 16) & 0xFF),
                   Flags          = (UInt16)  (Opt.Ttl        & 0xFFFF),
                   Options        = options
               };

    }

}


/// <summary>
/// An independently parsed DNS message (RFC 1035 §4.1). Produced by
/// <see cref="RawDnsReader"/>; never touches Hermod code.
/// </summary>
public sealed class RawDnsMessage
{

    public required UInt16                    Id              { get; init; }
    public required UInt16                    Flags           { get; init; }
    public required IReadOnlyList<RawQuestion> Questions      { get; init; }
    public required IReadOnlyList<RawRecord>  Answers         { get; init; }
    public required IReadOnlyList<RawRecord>  Authorities     { get; init; }
    public required IReadOnlyList<RawRecord>  Additionals     { get; init; }

    /// <summary>
    /// The full wire image this message was parsed from.
    /// </summary>
    public required Byte[]                    Wire            { get; init; }

    /// <summary>
    /// How many bytes of <see cref="Wire"/> the parser consumed (trailing-garbage detection).
    /// </summary>
    public required Int32                     ConsumedBytes   { get; init; }

    // Header flag decomposition (RFC 1035 §4.1.1, RFC 4035 §3 for AD/CD):
    public Boolean  QR      => (Flags & 0x8000) != 0;
    public Byte     Opcode  => (Byte) ((Flags >> 11) & 0x0F);
    public Boolean  AA      => (Flags & 0x0400) != 0;
    public Boolean  TC      => (Flags & 0x0200) != 0;
    public Boolean  RD      => (Flags & 0x0100) != 0;
    public Boolean  RA      => (Flags & 0x0080) != 0;
    public Byte     Z       => (Byte) ((Flags >> 6) & 0x01);
    public Boolean  AD      => (Flags & 0x0020) != 0;
    public Boolean  CD      => (Flags & 0x0010) != 0;
    public Byte     RCode   => (Byte) (Flags & 0x0F);

    /// <summary>
    /// The (single) OPT record, if any (RFC 6891 §6.1.1 allows at most one).
    /// </summary>
    public RawRecord? Opt
        => Additionals.FirstOrDefault(rr => rr.IsOpt);

    public RawEdns? Edns
        => Opt is { } opt ? RawEdns.From(opt) : null;

    /// <summary>
    /// Combined 12-bit RCODE: upper 8 bits from OPT TTL, lower 4 from the header (RFC 6891 §6.1.3).
    /// </summary>
    public Int32 CombinedRcode
        => Edns is { } edns
               ? (edns.ExtendedRcode << 4) | RCode
               : RCode;

}


/// <summary>
/// Well-known RR type code points (RFC 1035, 3596, 4034, 6891, ... / IANA registry).
/// </summary>
public static class RawDnsType
{
    public const UInt16 A          = 1;
    public const UInt16 NS         = 2;
    public const UInt16 CNAME      = 5;
    public const UInt16 SOA        = 6;
    public const UInt16 PTR        = 12;
    public const UInt16 HINFO      = 13;
    public const UInt16 MX         = 15;
    public const UInt16 TXT        = 16;
    public const UInt16 RP         = 17;
    public const UInt16 AFSDB      = 18;
    public const UInt16 AAAA       = 28;
    public const UInt16 LOC        = 29;
    public const UInt16 SRV        = 33;
    public const UInt16 NAPTR      = 35;
    public const UInt16 CERT       = 37;
    public const UInt16 DNAME      = 39;
    public const UInt16 OPT        = 41;
    public const UInt16 DS         = 43;
    public const UInt16 SSHFP      = 44;
    public const UInt16 RRSIG      = 46;
    public const UInt16 NSEC       = 47;
    public const UInt16 DNSKEY     = 48;
    public const UInt16 NSEC3      = 50;
    public const UInt16 NSEC3PARAM = 51;
    public const UInt16 TLSA       = 52;
    public const UInt16 SMIMEA     = 53;
    public const UInt16 CDS        = 59;
    public const UInt16 CDNSKEY    = 60;
    public const UInt16 OPENPGPKEY = 61;
    public const UInt16 CSYNC      = 62;
    public const UInt16 ZONEMD     = 63;
    public const UInt16 SVCB       = 64;
    public const UInt16 HTTPS      = 65;
    public const UInt16 EUI48      = 108;
    public const UInt16 EUI64      = 109;
    public const UInt16 TKEY       = 249;
    public const UInt16 TSIG       = 250;
    public const UInt16 ANY        = 255;
    public const UInt16 URI        = 256;
    public const UInt16 CAA        = 257;
}


public static class RawDnsClass
{
    public const UInt16 IN   = 1;
    public const UInt16 CH   = 3;
    public const UInt16 HS   = 4;
    public const UInt16 NONE = 254;
    public const UInt16 ANY  = 255;
}


/// <summary>
/// Header flag masks / builders for crafting test messages.
/// </summary>
public static class RawDnsFlags
{

    public const UInt16 QR = 0x8000;
    public const UInt16 AA = 0x0400;
    public const UInt16 TC = 0x0200;
    public const UInt16 RD = 0x0100;
    public const UInt16 RA = 0x0080;
    public const UInt16 AD = 0x0020;
    public const UInt16 CD = 0x0010;

    public static UInt16 Opcode(Int32 opcode)
        => (UInt16) ((opcode & 0x0F) << 11);

    public static UInt16 RCode(Int32 rcode)
        => (UInt16) (rcode & 0x0F);

}


public sealed class RawDnsFormatException(String Message, Int32 Offset) : Exception($"{Message} (at wire offset {Offset})")
{
    public Int32 WireOffset { get; } = Offset;
}

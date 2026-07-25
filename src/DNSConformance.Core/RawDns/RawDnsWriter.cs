using System.Text;

namespace DNSConformance.Core.RawDns;

/// <summary>
/// Independent DNS wire-format builder, written directly from RFC 1035 §3/§4.
/// Used to craft byte-exact queries/responses (including deliberately broken
/// ones) without going through Hermod. Big-endian throughout (RFC 1035 §2.3.2).
/// </summary>
public sealed class RawDnsWriter
{

    private readonly MemoryStream ms = new();

    /// <summary>Current absolute offset — equals the offset the *next* byte will occupy.</summary>
    public Int32 Position
        => (Int32) ms.Position;


    public RawDnsWriter U8(Byte value)
    {
        ms.WriteByte(value);
        return this;
    }

    public RawDnsWriter U16(UInt16 value)
    {
        ms.WriteByte((Byte) (value >> 8));
        ms.WriteByte((Byte) (value & 0xFF));
        return this;
    }

    public RawDnsWriter U16(Int32 value)
        => U16((UInt16) value);

    public RawDnsWriter U32(UInt32 value)
    {
        ms.WriteByte((Byte) (value >> 24));
        ms.WriteByte((Byte) (value >> 16));
        ms.WriteByte((Byte) (value >>  8));
        ms.WriteByte((Byte) (value & 0xFF));
        return this;
    }

    public RawDnsWriter Bytes(params Byte[] bytes)
    {
        ms.Write(bytes);
        return this;
    }

    public RawDnsWriter Bytes(ReadOnlySpan<Byte> bytes)
    {
        ms.Write(bytes);
        return this;
    }

    public RawDnsWriter Hex(String hex)
        => Bytes(Core.Bytes.FromHex(hex));


    #region Names

    /// <summary>
    /// Write a domain name uncompressed (RFC 1035 §3.1): length-prefixed labels,
    /// terminated by the zero octet. "." or "" mean the root name.
    /// Enforces the 63-byte label and 255-byte name limits — use
    /// <see cref="RawLabel"/> + <see cref="EndName"/> to build illegal names.
    /// </summary>
    public RawDnsWriter Name(String name)
    {

        var trimmed = name.Trim();

        if (trimmed is "." or "")
            return U8(0);

        var total = 0;

        foreach (var label in trimmed.TrimEnd('.').Split('.'))
        {

            var bytes = Encoding.ASCII.GetBytes(label);

            if (bytes.Length is 0 or > 63)
                throw new ArgumentException($"Label '{label}' must be 1..63 bytes (RFC 1035 §2.3.4)!", nameof(name));

            total += bytes.Length + 1;
            U8((Byte) bytes.Length);
            Bytes(bytes);

        }

        total += 1; // root terminator

        if (total > 255)
            throw new ArgumentException($"Name '{name}' exceeds 255 wire bytes (RFC 1035 §2.3.4)!", nameof(name));

        return U8(0);

    }

    /// <summary>Write a single raw label (length byte + payload) without any validation — for negative tests.</summary>
    public RawDnsWriter RawLabel(Byte declaredLength, Byte[] payload)
        => U8(declaredLength).Bytes(payload);

    public RawDnsWriter RawLabel(String label)
        => RawLabel((Byte) label.Length, Encoding.ASCII.GetBytes(label));

    /// <summary>Terminate a name built from raw labels.</summary>
    public RawDnsWriter EndName()
        => U8(0);

    /// <summary>Write an RFC 1035 §4.1.4 compression pointer to the given absolute offset.</summary>
    public RawDnsWriter Pointer(Int32 offset)
    {

        if (offset is < 0 or > 0x3FFF)
            throw new ArgumentOutOfRangeException(nameof(offset), "Compression pointers carry 14-bit offsets!");

        return U16((UInt16) (0xC000 | offset));

    }

    #endregion

    #region Character strings

    /// <summary>Write a &lt;character-string&gt; (RFC 1035 §3.3): one length octet + up to 255 bytes.</summary>
    public RawDnsWriter CharacterString(String text)
        => CharacterString(Encoding.ASCII.GetBytes(text));

    public RawDnsWriter CharacterString(Byte[] bytes)
    {

        if (bytes.Length > 255)
            throw new ArgumentException("character-string is limited to 255 bytes (RFC 1035 §3.3)!");

        return U8((Byte) bytes.Length).Bytes(bytes);

    }

    #endregion

    #region Message building blocks

    /// <summary>Write the 12-byte header (RFC 1035 §4.1.1).</summary>
    public RawDnsWriter Header(UInt16  id,
                               UInt16  flags,
                               UInt16  qdCount,
                               UInt16  anCount,
                               UInt16  nsCount,
                               UInt16  arCount)

        => U16(id).U16(flags).U16(qdCount).U16(anCount).U16(nsCount).U16(arCount);


    /// <summary>Write a question entry (RFC 1035 §4.1.2).</summary>
    public RawDnsWriter Question(String  name,
                                 UInt16  type,
                                 UInt16  cls = RawDnsClass.IN)

        => Name(name).U16(type).U16(cls);


    /// <summary>Write a complete resource record with explicit RDATA (RFC 1035 §4.1.3). RDLENGTH is derived.</summary>
    public RawDnsWriter RR(String  name,
                           UInt16  type,
                           UInt16  cls,
                           UInt32  ttl,
                           Byte[]  rdata)

        => Name(name).U16(type).U16(cls).U32(ttl).U16((UInt16) rdata.Length).Bytes(rdata);


    /// <summary>Write an OPT pseudo-RR (RFC 6891 §6.1.2): root name, TYPE=41, CLASS=payload size, TTL=extRCODE/version/flags.</summary>
    public RawDnsWriter Opt(UInt16  payloadSize,
                            Byte    extendedRcode  = 0,
                            Byte    version        = 0,
                            UInt16  flags          = 0,
                            Byte[]? options        = null)
    {

        options ??= [];

        return U8(0)                                    // root owner name
              .U16(RawDnsType.OPT)
              .U16(payloadSize)
              .U32((UInt32) ((extendedRcode << 24) | (version << 16) | flags))
              .U16((UInt16) options.Length)
              .Bytes(options);

    }

    #endregion


    public Byte[] ToArray()
        => ms.ToArray();


    #region Static conveniences

    /// <summary>Build a plain query for one question (optionally with EDNS0 OPT).</summary>
    public static Byte[] Query(UInt16   id,
                               String   name,
                               UInt16   type,
                               UInt16   cls               = RawDnsClass.IN,
                               Boolean  recursionDesired  = true,
                               UInt16?  ednsPayloadSize   = null,
                               Boolean  dnssecOk          = false,
                               Byte     ednsVersion       = 0,
                               Byte[]?  ednsOptions       = null)
    {

        var writer = new RawDnsWriter()
                        .Header(
                             id,
                             recursionDesired ? RawDnsFlags.RD : (UInt16) 0,
                             1, 0, 0,
                             (UInt16) (ednsPayloadSize.HasValue ? 1 : 0)
                         )
                        .Question(name, type, cls);

        if (ednsPayloadSize.HasValue)
            writer.Opt(
                ednsPayloadSize.Value,
                version: ednsVersion,
                flags:   (UInt16) (dnssecOk ? 0x8000 : 0),
                options: ednsOptions
            );

        return writer.ToArray();

    }

    /// <summary>Build a minimal NOERROR response echoing the given question with the given answer RRs.</summary>
    public static Byte[] Response(UInt16                                                       id,
                                  String                                                       questionName,
                                  UInt16                                                       questionType,
                                  IReadOnlyList<(String Name, UInt16 Type, UInt32 Ttl, Byte[] Rdata)> answers,
                                  UInt16                                                       flags = RawDnsFlags.QR | RawDnsFlags.RD | RawDnsFlags.RA)
    {

        var writer = new RawDnsWriter()
                        .Header(id, flags, 1, (UInt16) answers.Count, 0, 0)
                        .Question(questionName, questionType);

        foreach (var (name, type, ttl, rdata) in answers)
            writer.RR(name, type, RawDnsClass.IN, ttl, rdata);

        return writer.ToArray();

    }

    /// <summary>RDATA helper: uncompressed domain name as bytes (for NS/CNAME/PTR/MX targets etc.).</summary>
    public static Byte[] NameBytes(String name)
        => new RawDnsWriter().Name(name).ToArray();

    /// <summary>RDATA helper: IPv4 address bytes.</summary>
    /// <summary>SOA RDATA (RFC 1035 §3.3.13), uncompressed. MINIMUM is the field
    /// RFC 2308 §4 repurposed as the negative-caching TTL.</summary>
    public static Byte[] Soa(String  MName,
                             String  RName,
                             UInt32  Serial   = 1,
                             UInt32  Refresh  = 7200,
                             UInt32  Retry    = 3600,
                             UInt32  Expire   = 1209600,
                             UInt32  Minimum  = 3600)

        => new RawDnsWriter().
               Name(MName).
               Name(RName).
               U32(Serial).
               U32(Refresh).
               U32(Retry).
               U32(Expire).
               U32(Minimum).
               ToArray();


    public static Byte[] IPv4(String dotted)
    {

        var parts = dotted.Split('.');

        if (parts.Length != 4)
            throw new ArgumentException("Not a dotted-quad IPv4 address!", nameof(dotted));

        return [.. parts.Select(Byte.Parse)];

    }

    /// <summary>RDATA helper: IPv6 address bytes (16).</summary>
    public static Byte[] IPv6(String text)
        => System.Net.IPAddress.Parse(text).GetAddressBytes();

    #endregion

}

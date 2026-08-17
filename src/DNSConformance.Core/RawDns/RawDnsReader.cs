namespace DNSConformance.Core.RawDns;

public sealed class RawDnsReaderOptions
{

    /// <summary>
    /// RFC 1035 §4.1.4: a compression pointer refers to a PRIOR occurrence.
    /// Strict mode (default) rejects pointers that point at or beyond their own
    /// location. Enable to tolerate forward pointers when analyzing lenient peers.
    /// </summary>
    public Boolean  AllowForwardPointers    { get; init; } = false;

    /// <summary>
    /// Upper bound on pointer hops per name (loop and stretch protection).
    /// </summary>
    public Int32    MaxPointerHops          { get; init; } = 32;

    /// <summary>
    /// Reject messages with unparsed trailing bytes.
    /// </summary>
    public Boolean  RejectTrailingBytes     { get; init; } = false;

    public static readonly RawDnsReaderOptions Strict  = new();
    public static readonly RawDnsReaderOptions Lenient = new() { AllowForwardPointers = true };

}


/// <summary>
/// Independent DNS wire-format parser, written directly from RFC 1035 §4
/// (+ RFC 3596 / 4034 / 6891 code points). This is the measuring stick for the
/// conformance suite — it never calls into Hermod. Strict by default: any
/// structural violation throws <see cref="RawDnsFormatException"/> with the
/// offending wire offset.
/// </summary>
public static class RawDnsReader
{

    #region Parse(wire, options = strict)

    public static RawDnsMessage Parse(Byte[] wire, RawDnsReaderOptions? options = null)
    {

        options ??= RawDnsReaderOptions.Strict;

        if (wire.Length < 12)
            throw new RawDnsFormatException($"DNS message header requires 12 bytes, got {wire.Length}!", 0);

        var offset   = 0;

        var id       = ReadU16(wire, ref offset);
        var flags    = ReadU16(wire, ref offset);
        var qdCount  = ReadU16(wire, ref offset);
        var anCount  = ReadU16(wire, ref offset);
        var nsCount  = ReadU16(wire, ref offset);
        var arCount  = ReadU16(wire, ref offset);

        var questions = new List<RawQuestion>(qdCount);

        for (var i = 0; i < qdCount; i++)
        {

            var name = ReadName(wire, ref offset, options);

            questions.Add(new RawQuestion {
                Name   = name,
                Type   = ReadU16(wire, ref offset),
                Class  = ReadU16(wire, ref offset)
            });

        }

        var answers      = ReadRecords(wire, ref offset, anCount, "answer",     options);
        var authorities  = ReadRecords(wire, ref offset, nsCount, "authority",  options);
        var additionals  = ReadRecords(wire, ref offset, arCount, "additional", options);

        if (options.RejectTrailingBytes && offset != wire.Length)
            throw new RawDnsFormatException($"{wire.Length - offset} unparsed trailing bytes!", offset);

        return new RawDnsMessage {
                   Id             = id,
                   Flags          = flags,
                   Questions      = questions,
                   Answers        = answers,
                   Authorities    = authorities,
                   Additionals    = additionals,
                   Wire           = wire,
                   ConsumedBytes  = offset
               };

    }

    #endregion

    #region ReadName(wire, ref offset) / ReadNameAt(wire, offset)

    /// <summary>
    /// Decode a possibly compressed name starting at <paramref name="offset"/>, advancing it past the name's primary encoding.
    /// </summary>
    public static RawName ReadName(Byte[] wire, ref Int32 offset, RawDnsReaderOptions? options = null)
    {

        options ??= RawDnsReaderOptions.Strict;

        var labels      = new List<Byte[]>();
        var start       = offset;
        var cursor      = offset;
        var primaryEnd  = -1;           // set once the first pointer is taken
        var hops        = 0;
        var compressed  = false;
        var nameBytes   = 0;            // uncompressed reconstruction length check (RFC 1035 §2.3.4: 255)

        while (true)
        {

            if (cursor >= wire.Length)
                throw new RawDnsFormatException("Name runs past end of message!", cursor);

            var len = wire[cursor];

            if ((len & 0xC0) == 0xC0)
            {

                if (cursor + 1 >= wire.Length)
                    throw new RawDnsFormatException("Truncated compression pointer!", cursor);

                var target = ((len & 0x3F) << 8) | wire[cursor + 1];

                if (primaryEnd < 0)
                    primaryEnd = cursor + 2;

                if (!options.AllowForwardPointers && target >= cursor)
                    throw new RawDnsFormatException($"Compression pointer to offset {target} does not reference a PRIOR location (RFC 1035 §4.1.4)!", cursor);

                if (target >= wire.Length)
                    throw new RawDnsFormatException($"Compression pointer target {target} outside message!", cursor);

                if (++hops > options.MaxPointerHops)
                    throw new RawDnsFormatException($"More than {options.MaxPointerHops} compression pointer hops — loop?", cursor);

                compressed = true;
                cursor     = target;
                continue;

            }

            if ((len & 0xC0) != 0)
                throw new RawDnsFormatException($"Label length byte 0x{len:X2} uses reserved 10/01 prefix (RFC 1035 §4.1.4)!", cursor);

            if (len == 0)
            {

                if (primaryEnd < 0)
                    primaryEnd = cursor + 1;

                break;

            }

            if (cursor + 1 + len > wire.Length)
                throw new RawDnsFormatException($"Label of {len} bytes runs past end of message!", cursor);

            nameBytes += len + 1;

            if (nameBytes + 1 > 255)
                throw new RawDnsFormatException("Reconstructed name exceeds 255 bytes (RFC 1035 §2.3.4)!", cursor);

            labels.Add(wire[(cursor + 1)..(cursor + 1 + len)]);
            cursor += 1 + len;

        }

        offset = primaryEnd;

        return new RawName {
                   Labels      = labels,
                   Compressed  = compressed,
                   WireLength  = primaryEnd - start
               };

    }

    /// <summary>
    /// Decode a name at an absolute offset without a running cursor (e.g. inside RDATA). Returns the name and its primary wire length.
    /// </summary>
    public static (RawName Name, Int32 Length) ReadNameAt(Byte[] wire, Int32 offset, RawDnsReaderOptions? options = null)
    {
        var cursor = offset;
        var name   = ReadName(wire, ref cursor, options);
        return (name, cursor - offset);
    }

    #endregion

    #region Helpers

    private static List<RawRecord> ReadRecords(Byte[]               wire,
                                               ref Int32            offset,
                                               UInt16               count,
                                               String               section,
                                               RawDnsReaderOptions  options)
    {

        var records = new List<RawRecord>(count);

        for (var i = 0; i < count; i++)
        {

            var name = ReadName(wire, ref offset, options);

            if (offset + 10 > wire.Length)
                throw new RawDnsFormatException($"Truncated {section} record #{i} fixed fields!", offset);

            var type      = ReadU16(wire, ref offset);
            var cls       = ReadU16(wire, ref offset);
            var ttl       = ReadU32(wire, ref offset);
            var rdLength  = ReadU16(wire, ref offset);

            if (offset + rdLength > wire.Length)
                throw new RawDnsFormatException($"{section} record #{i} RDLENGTH {rdLength} exceeds remaining {wire.Length - offset} bytes!", offset);

            records.Add(new RawRecord {
                Name         = name,
                Type         = type,
                Class        = cls,
                Ttl          = ttl,
                Rdata        = wire[offset..(offset + rdLength)],
                RdataOffset  = offset
            });

            offset += rdLength;

        }

        return records;

    }

    private static UInt16 ReadU16(Byte[] wire, ref Int32 offset)
    {

        if (offset + 2 > wire.Length)
            throw new RawDnsFormatException("Truncated 16-bit field!", offset);

        var value = (UInt16) ((wire[offset] << 8) | wire[offset + 1]);
        offset += 2;
        return value;

    }

    private static UInt32 ReadU32(Byte[] wire, ref Int32 offset)
    {

        if (offset + 4 > wire.Length)
            throw new RawDnsFormatException("Truncated 32-bit field!", offset);

        var value = ((UInt32) wire[offset] << 24) |
                    ((UInt32) wire[offset + 1] << 16) |
                    ((UInt32) wire[offset + 2] << 8) |
                              wire[offset + 3];
        offset += 4;
        return value;

    }

    #endregion

}

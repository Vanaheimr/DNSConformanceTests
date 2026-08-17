using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// Bridges between Hermod resource records and the independent RawDns codec:
/// Hermod-serialize → RawDns-decode, and RawDns-craft → Hermod-parse.
/// </summary>
internal static class RRWire
{

    private static readonly Byte[] HeaderWithOneAnswer =
        [0, 0,  0, 0,  0, 0,  0, 1,  0, 0,  0, 0];


    /// <summary>
    /// Serialize a Hermod record (uncompressed) and return the RawDns view of it.
    /// </summary>
    public static RawRecord Encode(IDNSResourceRecord record)
    {

        var ms = new MemoryStream();
        ms.Write(HeaderWithOneAnswer);

        record.Serialize(ms, UseCompression: false, CompressionOffsets: []);

        var message = RawDnsReader.Parse(ms.ToArray());

        return message.Answers.Single();

    }


    /// <summary>
    /// Full message bytes with this single record in the answer section.
    /// </summary>
    public static Byte[] EncodeMessage(IDNSResourceRecord record)
    {

        var ms = new MemoryStream();
        ms.Write(HeaderWithOneAnswer);

        record.Serialize(ms, UseCompression: false, CompressionOffsets: []);

        return ms.ToArray();

    }


    /// <summary>
    /// Build the stream a Hermod (name, Stream) record constructor expects:
    /// CLASS (2) + TTL (4) + RDLENGTH (2) + RDATA. The name and TYPE have
    /// notionally been consumed already.
    /// </summary>
    public static MemoryStream RdataStream(Byte[]  rdata,
                                           UInt16  cls   = RawDnsClass.IN,
                                           UInt32  ttl   = 300)

        => new(new RawDnsWriter()
                   .U16(cls)
                   .U32(ttl)
                   .U16((UInt16) rdata.Length)
                   .Bytes(rdata)
                   .ToArray());

}

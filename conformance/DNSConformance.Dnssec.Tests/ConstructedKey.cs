using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// A zone key the suite makes and signs with by itself — ECDSA P-256 (algorithm
/// 13), with the signed data built here from RFC 4034 rather than asked of Hermod.
///
/// <para>
/// The fixtures stay BIND-signed, because a validator measured against its own
/// signatures measures nothing. But a chain of trust needs zones above the fixture
/// — a parent that signs the fixture's DS, a root that signs the parent's — and
/// BIND has not signed those. Since finding 67 the validator verifies every one of
/// those signatures, so they have to be real; this is where they come from, built
/// the way the DS digests in these tests already are: from the RFC, by the suite.
/// </para>
///
/// <para>
/// Only RRsets whose RDATA holds no domain name are supported (DNSKEY, DS, A), so
/// the canonical form needs no name canonicalisation inside RDATA (RFC 4034 §6.2,
/// item 3) and cannot quietly get it wrong.
/// </para>
/// </summary>
internal sealed class ConstructedKey : IDisposable
{

    private const Byte ECDSAP256SHA256 = 13;

    private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>The key as the zone publishes it.</summary>
    public DNSKEY DNSKEY { get; }

    /// <summary>The key tag (RFC 4034 Appendix B).</summary>
    public UInt16 KeyTag
        => DNSSECValidator.ComputeKeyTag(DNSKEY);


    /// <param name="Zone">The zone apex the key is published at; "." for the root.</param>
    /// <param name="Flags">Zone Key and SEP by default (257).</param>
    public ConstructedKey(String Zone, UInt16 Flags = 0x0101)
    {

        var q = key.ExportParameters(false).Q;

        DNSKEY = new DNSKEY(Name(Zone),
                            DNSQueryClasses.IN,
                            TimeSpan.FromHours(1),
                            Flags,
                            3,
                            ECDSAP256SHA256,
                            [.. q.X!, .. q.Y!]);

    }


    #region Sign(RRset, Inception = null, Expiration = null)

    /// <summary>
    /// An RRSIG over the RRset, made with this key, valid from a day ago for thirty
    /// days unless told otherwise.
    /// </summary>
    public RRSIG Sign(IReadOnlyCollection<IDNSResourceRecord>  RRset,
                      DateTimeOffset?                          Inception    = null,
                      DateTimeOffset?                          Expiration   = null)
    {

        var first       = RRset.First();
        var owner       = first.DomainName.FullName;
        var type        = first.Type;
        var ttl         = (UInt32) first.TimeToLive.TotalSeconds;
        var labels      = (Byte) owner.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries).Length;
        var inception   = (UInt32) (Inception  ?? DateTimeOffset.UtcNow.AddDays(-1)).ToUnixTimeSeconds();
        var expiration  = (UInt32) (Expiration ?? DateTimeOffset.UtcNow.AddDays(30)).ToUnixTimeSeconds();

        // RFC 4034 §3.1.8.1: signature = sign(RRSIG_RDATA | RR(1) | RR(2)...),
        // where RRSIG_RDATA is the RDATA without the signature field.
        var data = new MemoryStream();

        WriteUInt16(data, (UInt16) type);
        data.WriteByte(ECDSAP256SHA256);
        data.WriteByte(labels);
        WriteUInt32(data, ttl);
        WriteUInt32(data, expiration);
        WriteUInt32(data, inception);
        WriteUInt16(data, KeyTag);
        data.Write(CanonicalName(DNSKEY.DomainName.FullName));

        // §6.3: the RRs of the set in canonical order, which is the order of their
        // RDATA as left-justified unsigned octet sequences. Every RR carries the
        // owner name in canonical form and the original TTL (§6.2).
        foreach (var rdata in RRset.Select(RData).OrderBy(rdata => rdata, OctetOrder.Instance))
        {
            data.Write(CanonicalName(owner));
            WriteUInt16(data, (UInt16) type);
            WriteUInt16(data, 1);                       // IN
            WriteUInt32(data, ttl);
            WriteUInt16(data, (UInt16) rdata.Length);
            data.Write(rdata);
        }

        // RFC 6605 §4: the signature is r | s, 32 octets each.
        var signature = key.SignData(data.ToArray(), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        return new RRSIG(DomainName.ParseLenient(owner.TrimEnd('.') is { Length: > 0 } o ? o : "."),
                         DNSQueryClasses.IN,
                         TimeSpan.FromSeconds(ttl),
                         type,
                         ECDSAP256SHA256,
                         labels,
                         ttl,
                         expiration,
                         inception,
                         KeyTag,
                         DomainName.ParseLenient(DNSKEY.DomainName.FullName.TrimEnd('.') is { Length: > 0 } s ? s : "."),
                         signature);

    }

    #endregion

    #region DelegationSigner()

    /// <summary>
    /// The DS for this key (RFC 4034 §5.1.4): SHA-256 over the canonical owner name
    /// followed by the DNSKEY RDATA — what the parent publishes, or what a resolver
    /// configures as its trust anchor.
    /// </summary>
    public DS DelegationSigner()

        => new (Name(DNSKEY.DomainName.FullName),
                DNSQueryClasses.IN,
                TimeSpan.FromHours(1),
                KeyTag,
                DNSKEY.Algorithm,
                2,
                SHA256.HashData([.. CanonicalName(DNSKEY.DomainName.FullName), .. RData(DNSKEY)]));

    #endregion

    #region Signed(RRset)

    /// <summary>The RRset followed by this key's signature over it — what a server answers.</summary>
    public IDNSResourceRecord[] Signed(params IDNSResourceRecord[] RRset)
        => [.. RRset, Sign(RRset)];

    #endregion


    #region (static) Name(Text)

    /// <summary>A Hermod name for a zone, the root included.</summary>
    public static DomainName Name(String Text)
        => DomainName.ParseLenient(Text.TrimEnd('.') is { Length: > 0 } name ? name : ".");

    #endregion

    #region (private static) RData(Record)

    private static Byte[] RData(IDNSResourceRecord Record)
    {

        var rdata = new MemoryStream();

        switch (Record)
        {

            case DNSKEY dnskey:
                WriteUInt16(rdata, dnskey.Flags);
                rdata.WriteByte(dnskey.Protocol);
                rdata.WriteByte(dnskey.Algorithm);
                rdata.Write(dnskey.PublicKey);
                break;

            case DS ds:
                WriteUInt16(rdata, ds.KeyTag);
                rdata.WriteByte(ds.Algorithm);
                rdata.WriteByte(ds.DigestType);
                rdata.Write(ds.Digest);
                break;

            case A a:
                rdata.Write(a.IPv4Address.GetBytes());
                break;

            default:
                throw new NotSupportedException($"{Record.Type} is not one of the RDATA forms this signer builds itself.");

        }

        return rdata.ToArray();

    }

    #endregion

    #region (private static) CanonicalName(Name)

    /// <summary>RFC 4034 §6.2: wire form, uncompressed, lower case.</summary>
    private static Byte[] CanonicalName(String Name)
    {

        var wire = new MemoryStream();

        foreach (var label in Name.ToLowerInvariant().TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            wire.WriteByte((Byte) bytes.Length);
            wire.Write(bytes);
        }

        wire.WriteByte(0x00);

        return wire.ToArray();

    }

    #endregion

    #region (private) OctetOrder

    private sealed class OctetOrder : IComparer<Byte[]>
    {

        public static readonly OctetOrder Instance = new();

        public Int32 Compare(Byte[]? x, Byte[]? y)
            => x.AsSpan().SequenceCompareTo(y.AsSpan());

    }

    #endregion

    #region (private static) WriteUInt16 / WriteUInt32

    private static void WriteUInt16(Stream Stream, UInt16 Value)
    {
        Span<Byte> bytes = stackalloc Byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, Value);
        Stream.Write(bytes);
    }

    private static void WriteUInt32(Stream Stream, UInt32 Value)
    {
        Span<Byte> bytes = stackalloc Byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, Value);
        Stream.Write(bytes);
    }

    #endregion


    public void Dispose()
        => key.Dispose();

}

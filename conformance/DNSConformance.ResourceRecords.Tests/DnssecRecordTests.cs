using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 4034 (DNSKEY, RRSIG, DS, NSEC), RFC 5155 (NSEC3, NSEC3PARAM),
/// RFC 7344 (CDS, CDNSKEY), RFC 7477 (CSYNC), RFC 8976 (ZONEMD) —
/// DNSSEC-related RDATA wire formats.
/// </summary>
[TestFixture]
public class DnssecRecordTests
{

    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(3600);


    #region DNSKEY_Rdata_Flags_Protocol_Algorithm_Key()

    [Test]
    [Property("RFC", "4034 §2.1")]
    public void DNSKEY_Rdata_Flags_Protocol_Algorithm_Key()
    {

        var publicKey  = Bytes.FromHex("0123456789abcdef");

        var record     = new DNSKEY(DomainName.Parse("example."), DNSQueryClasses.IN, Ttl, 257, 3, 8, publicKey);
        var encoded    = RRWire.Encode(record);

        var golden     = new RawDnsWriter()
                             .U16(257)          // Flags: ZK + SEP
                             .U8(3)             // Protocol MUST be 3 (§2.1.2)
                             .U8(8)             // RSASHA256
                             .Bytes(publicKey)
                             .ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region DS_Rdata_KeyTag_Algorithm_DigestType_Digest()

    [Test]
    [Property("RFC", "4034 §5.1")]
    public void DS_Rdata_KeyTag_Algorithm_DigestType_Digest()
    {

        var digest   = Bytes.FromHex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D");

        var record   = new DS(DomainName.Parse("example."), DNSQueryClasses.IN, Ttl, 20326, 8, 2, digest);
        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter()
                           .U16(20326)
                           .U8(8)
                           .U8(2)              // SHA-256
                           .Bytes(digest)
                           .ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region RRSIG_Rdata_Field_Layout()

    [Test]
    [Property("RFC", "4034 §3.1")]
    public void RRSIG_Rdata_Field_Layout()
    {

        var signature  = Bytes.FromHex("deadbeefcafe");

        var record     = new RRSIG(
                             DomainName.Parse("www.example."),
                             DNSQueryClasses.IN,
                             Ttl,
                             DNSResourceRecordTypes.A,
                             8,                      // RSASHA256
                             2,                      // labels
                             3600,                   // original TTL
                             1893456000,             // expiration (2030-01-01)
                             1577836800,             // inception  (2020-01-01)
                             12345,
                             DomainName.Parse("example."),
                             signature
                         );

        var encoded    = RRWire.Encode(record);

        var golden     = new RawDnsWriter()
                             .U16(RawDnsType.A)
                             .U8(8)
                             .U8(2)
                             .U32(3600)
                             .U32(1893456000)
                             .U32(1577836800)
                             .U16(12345)
                             .Name("example.")       // §3.1.7: "A sender MUST NOT use DNS name compression on the Signer's Name field"
                             .Bytes(signature)
                             .ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region NSEC_TypeBitmap_Matches_RFC4034_Worked_Example()

    [Test]
    [Property("RFC", "4034 §4.3")]
    public void NSEC_TypeBitmap_Matches_RFC4034_Worked_Example()
    {

        // The §4.3 example: types A, MX, RRSIG, NSEC and TYPE1234 encode to
        //   window 0:  06 40 01 00 00 00 03
        //   window 4:  1B 00(×26) 20
        var bitmap  = Bytes.FromHex(
                          "00 06 40 01 00 00 00 03" +
                          "04 1B 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                          "00 00 00 00 00 00 00 00 00 00 00 00 20"
                      );

        var record  = new NSEC(
                          DomainName.Parse("alfa.example.com."),
                          DNSQueryClasses.IN,
                          Ttl,
                          DomainName.Parse("host.example.com."),
                          bitmap
                      );

        var encoded = RRWire.Encode(record);

        var golden  = new RawDnsWriter()
                          .Name("host.example.com.")   // §4.1.1: no compression for Next Domain Name
                          .Bytes(bitmap)
                          .ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region NSEC_ZoneFile_Bitmap_Encoding_Matches_RFC4034_Worked_Example()

    [Test]
    [Property("RFC", "4034 §4.3")]
    public void NSEC_ZoneFile_Bitmap_Encoding_Matches_RFC4034_Worked_Example()
    {

        // Same example through the presentation-format parser:
        //   alfa.example.com. 86400 IN NSEC host.example.com. A MX RRSIG NSEC TYPE1234
        var parsed = ADNSResourceRecord.ParseZoneFileString(
                         "alfa.example.com. 86400 IN NSEC host.example.com. A MX RRSIG NSEC TYPE1234"
                     );

        Assert.That(parsed, Is.InstanceOf<NSEC>());

        var expectedBitmap = Bytes.FromHex(
                                 "00 06 40 01 00 00 00 03" +
                                 "04 1B 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
                                 "00 00 00 00 00 00 00 00 00 00 00 00 20"
                             );

        Assert.That(((NSEC) parsed).TypeBitMaps, Is.EqualTo(expectedBitmap),
                    Bytes.Diff(expectedBitmap, ((NSEC) parsed).TypeBitMaps.ToArray()));

    }

    #endregion

    #region NSEC3_Rdata_Layout_With_Salt_And_Hash()

    [Test]
    [Property("RFC", "5155 §3.2")]
    public void NSEC3_Rdata_Layout_With_Salt_And_Hash()
    {

        var salt     = Bytes.FromHex("aabbccdd");
        var nextHash = Bytes.FromHex("1ab6a2b60b0e2d0b172b5b9e6bbe93c3d5e3c1a4");  // 20 bytes (SHA-1)
        var bitmap   = Bytes.FromHex("00 01 40");                                   // window 0, 1 byte, type A

        var record   = new NSEC3(
                           DomainName.Parse("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example."),
                           DNSQueryClasses.IN,
                           Ttl,
                           1,          // SHA-1
                           1,          // Opt-Out
                           12,
                           salt,
                           nextHash,
                           bitmap
                       );

        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter()
                           .U8(1)
                           .U8(1)
                           .U16(12)
                           .U8((Byte) salt.Length).Bytes(salt)
                           .U8((Byte) nextHash.Length).Bytes(nextHash)
                           .Bytes(bitmap)
                           .ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region NSEC3PARAM_Rdata_Layout()

    [Test]
    [Property("RFC", "5155 §4.2")]
    public void NSEC3PARAM_Rdata_Layout()
    {

        var salt     = Bytes.FromHex("beef");

        var record   = new NSEC3PARAM(DomainName.Parse("example."), DNSQueryClasses.IN, Ttl, 1, 0, 10, salt);
        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter()
                           .U8(1).U8(0).U16(10)
                           .U8((Byte) salt.Length).Bytes(salt)
                           .ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region CDS_And_CDNSKEY_Mirror_Parent_Formats()

    [Test]
    [Property("RFC", "7344 §3.1/§3.2")]
    public void CDS_And_CDNSKEY_Mirror_Parent_Formats()
    {

        var digest    = Bytes.FromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        var cds       = new CDS(DomainName.Parse("child.example."), DNSQueryClasses.IN, Ttl, 1111, 13, 2, digest);
        var cdsWire   = RRWire.Encode(cds);

        Assert.That(cdsWire.Type,  Is.EqualTo((UInt16) 59));
        Assert.That(cdsWire.Rdata, Is.EqualTo(new RawDnsWriter().U16(1111).U8(13).U8(2).Bytes(digest).ToArray()));

        var key       = Bytes.FromHex("aabb");
        var cdnskey   = new CDNSKEY(DomainName.Parse("child.example."), DNSQueryClasses.IN, Ttl, 256, 3, 13, key);
        var keyWire   = RRWire.Encode(cdnskey);

        Assert.That(keyWire.Type,  Is.EqualTo((UInt16) 60));
        Assert.That(keyWire.Rdata, Is.EqualTo(new RawDnsWriter().U16(256).U8(3).U8(13).Bytes(key).ToArray()));

    }

    #endregion

    #region CSYNC_Rdata_Serial_Flags_Bitmap()

    [Test]
    [Property("RFC", "7477 §2.1.1")]
    public void CSYNC_Rdata_Serial_Flags_Bitmap()
    {

        var bitmap   = Bytes.FromHex("00 04 60 00 00 08");   // NS, A, AAAA per RFC 7477 example

        var record   = new CSYNC(DomainName.Parse("child.example."), DNSQueryClasses.IN, Ttl, 66, 3, bitmap);
        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter().U32(66).U16(3).Bytes(bitmap).ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region ZONEMD_Rdata_Serial_Scheme_Algorithm_Digest()

    [Test]
    [Property("RFC", "8976 §2.2")]
    public void ZONEMD_Rdata_Serial_Scheme_Algorithm_Digest()
    {

        var digest   = new Byte[48];                       // SHA-384 length
        for (var i = 0; i < digest.Length; i++)
            digest[i] = (Byte) i;

        var record   = new ZONEMD(DomainName.Parse("example."), DNSQueryClasses.IN, Ttl, 2018031900, 1, 1, digest);
        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter().U32(2018031900).U8(1).U8(1).Bytes(digest).ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion


    #region DNSKEY_RoundTrips_Through_Wire()

    [Test]
    public void DNSKEY_RoundTrips_Through_Wire()
    {

        var publicKey  = new Byte[64];
        Random.Shared.NextBytes(publicKey);

        var original   = new DNSKEY(DomainName.Parse("rt.example."), DNSQueryClasses.IN, Ttl, 256, 3, 13, publicKey);
        var wire       = RRWire.Encode(original);

        var reparsed   = new DNSKEY(
                             DomainName.Parse("rt.example."),
                             RRWire.RdataStream(wire.Rdata, wire.Class, wire.Ttl)
                         );

        Assert.Multiple(() => {
            Assert.That(reparsed.Flags,      Is.EqualTo(original.Flags));
            Assert.That(reparsed.Protocol,   Is.EqualTo(original.Protocol));
            Assert.That(reparsed.Algorithm,  Is.EqualTo(original.Algorithm));
            Assert.That(reparsed.PublicKey,  Is.EqualTo(original.PublicKey));
        });

    }

    #endregion

    #region RRSIG_RoundTrips_Through_Wire()

    [Test]
    public void RRSIG_RoundTrips_Through_Wire()
    {

        var signature  = new Byte[128];
        Random.Shared.NextBytes(signature);

        var original   = new RRSIG(
                             DomainName.Parse("rt.example."),
                             DNSQueryClasses.IN,
                             Ttl,
                             DNSResourceRecordTypes.MX,
                             13, 2, 300,
                             1893456000, 1577836800,
                             4711,
                             DomainName.Parse("example."),
                             signature
                         );

        var wire       = RRWire.Encode(original);

        var reparsed   = new RRSIG(
                             DomainName.Parse("rt.example."),
                             RRWire.RdataStream(wire.Rdata, wire.Class, wire.Ttl)
                         );

        Assert.Multiple(() => {
            Assert.That(reparsed.TypeCovered,          Is.EqualTo(original.TypeCovered));
            Assert.That(reparsed.Algorithm,            Is.EqualTo(original.Algorithm));
            Assert.That(reparsed.Labels,               Is.EqualTo(original.Labels));
            Assert.That(reparsed.OriginalTTL,          Is.EqualTo(original.OriginalTTL));
            Assert.That(reparsed.SignatureExpiration,  Is.EqualTo(original.SignatureExpiration));
            Assert.That(reparsed.SignatureInception,   Is.EqualTo(original.SignatureInception));
            Assert.That(reparsed.KeyTag,               Is.EqualTo(original.KeyTag));
            Assert.That(reparsed.SignerName.FullName,  Is.EqualTo(original.SignerName.FullName));
            Assert.That(reparsed.Signature,            Is.EqualTo(original.Signature));
        });

    }

    #endregion

}

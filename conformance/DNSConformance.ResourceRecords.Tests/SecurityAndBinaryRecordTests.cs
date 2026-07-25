using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 6698 (TLSA), RFC 8162 (SMIMEA), RFC 4255 (SSHFP), RFC 4398 (CERT),
/// RFC 7929 (OPENPGPKEY), RFC 7043 (EUI48/EUI64), RFC 9460 (SVCB/HTTPS).
/// </summary>
[TestFixture]
public class SecurityAndBinaryRecordTests
{

    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(300);


    #region TLSA_Rdata_Usage_Selector_MatchingType_Data()

    [Test]
    [Property("RFC", "6698 §2.1")]
    public void TLSA_Rdata_Usage_Selector_MatchingType_Data()
    {

        var hash     = Bytes.FromHex("d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971");

        var record   = new TLSA(
                           DomainName.Parse("_443._tcp.www.example.com.".Replace("_", "u")),   // safe owner; underscore handling is covered elsewhere
                           DNSQueryClasses.IN,
                           Ttl,
                           3,        // DANE-EE
                           1,        // SPKI
                           1,        // SHA2-256
                           hash
                       );

        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter().U8(3).U8(1).U8(1).Bytes(hash).ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region TLSA_Owner_With_Underscore_Labels()

    [Test]
    [Property("RFC", "6698 §3")]
    public void TLSA_Owner_With_Underscore_Labels()
    {

        // The TLSA owner name format is _port._proto.host — parsing the
        // wire form must tolerate underscored labels.
        var rdata   = new RawDnsWriter().U8(1).U8(1).U8(1).Bytes(Bytes.FromHex("aa bb cc")).ToArray();

        var wire    = new Byte[] { 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 }
                          .Concat(new RawDnsWriter()
                              .Name("_443._tcp.www.example.com.")
                              .U16(RawDnsType.TLSA)
                              .U16(RawDnsClass.IN)
                              .U32(300)
                              .U16((UInt16) rdata.Length)
                              .Bytes(rdata)
                              .ToArray())
                          .ToArray();

        var decoded = RawDnsReader.Parse(wire);

        Assert.That(decoded.Answers.Single().Name.Presentation, Is.EqualTo("_443._tcp.www.example.com"));

    }

    #endregion

    #region SMIMEA_Shares_The_TLSA_Format()

    [Test]
    [Property("RFC", "8162 §2")]
    public void SMIMEA_Shares_The_TLSA_Format()
    {

        var data     = Bytes.FromHex("00112233");

        var record   = new SMIMEA(DomainName.Parse("smimea.example."), DNSQueryClasses.IN, Ttl, 3, 0, 0, data);
        var encoded  = RRWire.Encode(record);

        Assert.Multiple(() => {
            Assert.That(encoded.Type,  Is.EqualTo((UInt16) 53));
            Assert.That(encoded.Rdata, Is.EqualTo(new RawDnsWriter().U8(3).U8(0).U8(0).Bytes(data).ToArray()));
        });

    }

    #endregion

    #region SSHFP_Rdata_Algorithm_FpType_Fingerprint()

    [Test]
    [Property("RFC", "4255 §3.1")]
    public void SSHFP_Rdata_Algorithm_FpType_Fingerprint()
    {

        var fingerprint = Bytes.FromHex("123456789abcdef67890123456789abcdef67890");   // SHA-1: 20 bytes

        var record   = new SSHFP(
                           DomainName.Parse("ssh.example."),
                           DNSQueryClasses.IN,
                           Ttl,
                           SSHFP_Algorithm.RSA,          // 1
                           SSHFP_FingerprintType.SHA1,   // 1
                           fingerprint
                       );

        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter().U8(1).U8(1).Bytes(fingerprint).ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region CERT_Rdata_Type_KeyTag_Algorithm_Certificate()

    [Test]
    [Property("RFC", "4398 §2")]
    public void CERT_Rdata_Type_KeyTag_Algorithm_Certificate()
    {

        var certificate = Bytes.FromHex("308201");

        var record   = new CERT(DomainName.Parse("cert.example."), DNSQueryClasses.IN, Ttl, 1 /* PKIX */, 12345, 8, certificate);
        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter().U16(1).U16(12345).U8(8).Bytes(certificate).ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region OPENPGPKEY_Rdata_Is_The_Raw_Key()

    [Test]
    [Property("RFC", "7929 §2")]
    public void OPENPGPKEY_Rdata_Is_The_Raw_Key()
    {

        var key      = Bytes.FromHex("99 01 0d 04 5f 9e");

        var record   = new OPENPGPKEY(DomainName.Parse("pgp.example."), DNSQueryClasses.IN, Ttl, key);
        var encoded  = RRWire.Encode(record);

        Assert.That(encoded.Rdata, Is.EqualTo(key), "no framing around the transferable public key");

    }

    #endregion

    #region EUI48_And_EUI64_Fixed_Width()

    [Test]
    [Property("RFC", "7043 §3.1/§4.1")]
    public void EUI48_And_EUI64_Fixed_Width()
    {

        var mac48    = Bytes.FromHex("00-00-5E-00-53-2A");
        var mac64    = Bytes.FromHex("00-00-5E-EF-10-00-00-2A");

        var eui48    = RRWire.Encode(new EUI48(DomainName.Parse("eui48.example."), DNSQueryClasses.IN, Ttl, mac48));
        var eui64    = RRWire.Encode(new EUI64(DomainName.Parse("eui64.example."), DNSQueryClasses.IN, Ttl, mac64));

        Assert.Multiple(() => {
            Assert.That(eui48.Rdata, Is.EqualTo(mac48), "EUI48 RDATA = 6 octets");
            Assert.That(eui64.Rdata, Is.EqualTo(mac64), "EUI64 RDATA = 8 octets");
        });

    }

    #endregion


    #region SVCB_AliasMode_Has_Priority_Zero_And_No_Params()

    [Test]
    [Property("RFC", "9460 §2.4.2")]
    public void SVCB_AliasMode_Has_Priority_Zero_And_No_Params()
    {

        var record   = new SVCB(
                           DomainName.Parse("svcb.example."),
                           DNSQueryClasses.IN,
                           Ttl,
                           0,
                           DomainName.Parse("pool.svc.example."),
                           []
                       );

        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter().U16(0).Name("pool.svc.example.").ToArray();

        Assert.Multiple(() => {
            Assert.That(encoded.Type,  Is.EqualTo((UInt16) 64));
            Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));
        });

    }

    #endregion

    #region HTTPS_ServiceMode_With_Alpn_Parameter()

    [Test]
    [Property("RFC", "9460 §7.1")]
    public void HTTPS_ServiceMode_With_Alpn_Parameter()
    {

        // SvcParam alpn (key 1): value = length-prefixed alpn-ids: "h2","h3".
        var alpnValue  = new RawDnsWriter()
                             .U8(2).Bytes((Byte) 'h', (Byte) '2')
                             .U8(2).Bytes((Byte) 'h', (Byte) '3')
                             .ToArray();

        var record     = new HTTPS(
                             DomainName.Parse("https.example."),
                             DNSQueryClasses.IN,
                             Ttl,
                             1,
                             DomainName.Parse("."),      // TargetName "." = owner itself (§2.5)
                             [ new SVCParameter(1, alpnValue) ]
                         );

        var encoded    = RRWire.Encode(record);

        var golden     = new RawDnsWriter()
                             .U16(1)
                             .U8(0)                       // root target
                             .U16(1)                      // SvcParamKey alpn
                             .U16((UInt16) alpnValue.Length)
                             .Bytes(alpnValue)
                             .ToArray();

        Assert.Multiple(() => {
            Assert.That(encoded.Type,  Is.EqualTo((UInt16) 65));
            Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));
        });

    }

    #endregion

    #region Https_Parses_A_RealWorld_Record_With_Multiple_SvcParams()

    [Test]
    [Property("RFC", "9460 §2.2")]
    public void Https_Parses_A_RealWorld_Record_With_Multiple_SvcParams()
    {

        // Captured verbatim from 1.1.1.1 for cloudflare.com/HTTPS. Decoded:
        //   SvcPriority 1, TargetName "." (root = owner itself)
        //   key 1 (alpn)     len 6  = "h3","h2"
        //   key 4 (ipv4hint) len 8  = 104.16.132.229, 104.16.133.229
        //   key 6 (ipv6hint) len 32 = 2606:4700::6810:84e5, 2606:4700::6810:85e5
        //
        // RFC 9460 §2.2: SvcParams MUST appear in strictly increasing key order,
        // which they do here — this is a well-formed record that every other
        // resolver renders fine (dig +short prints it without complaint).
        var rdata = Bytes.FromHex(
                        "0001" +                        // SvcPriority 1
                        "00" +                          // TargetName = root
                        "0001" + "0006" + "0268330268" + "32" +
                        "0004" + "0008" + "681084e5681085e5" +
                        "0006" + "0020" + "26064700000000000000000068 1084e5".Replace(" ", "") +
                                          "260647000000000000000000681085e5"
                    );

        var stream = RRWire.RdataStream(rdata);
        var record = new HTTPS(DomainName.Parse("cloudflare.com."), stream);

        Assert.Multiple(() => {

            Assert.That(record.Priority, Is.EqualTo((UInt16) 1));
            Assert.That(record.SVCParameters.Select(p => p.Key), Is.EqualTo(new UInt16[] { 1, 4, 6 }),
                        "alpn, ipv4hint and ipv6hint must all be decoded, in key order");

            // RFC 1035 §4.1.3: RDLENGTH "specifies the length in octets of the
            // RDATA field" — a parser MUST stop there. Reading to end-of-stream
            // instead works only when the record happens to be last in the
            // message; otherwise it swallows the following records.
            Assert.That(stream.Position, Is.EqualTo(stream.Length),
                        "parser must consume exactly RDLENGTH bytes");

        });

    }

    #endregion

    #region Https_Record_Followed_By_Another_Record_Does_Not_Overrun()

    [Test]
    [Property("RFC", "1035 §4.1.3")]
    [Category(TestCategories.KnownIssue)]   // FINDINGS.md #4
    public void Https_Record_Followed_By_Another_Record_Does_Not_Overrun()
    {

        // The RDLENGTH-overrun made concrete: an HTTPS record followed by an A
        // record in the same section. If the SvcParam loop reads past its own
        // RDATA, the A record's bytes are consumed as bogus SvcParams and the
        // rest of the message is unparseable. This is exactly what happens to a
        // real cloudflare.com/HTTPS answer, whose OPT record trails the HTTPS RR.
        var httpsRdata  = new RawDnsWriter()
                              .U16(1)                    // SvcPriority
                              .U8(0)                     // TargetName = root
                              .U16(1).U16(3).Bytes(0x02, (Byte) 'h', (Byte) '2')   // alpn
                              .ToArray();

        var stream      = new MemoryStream(new RawDnsWriter()
                              .U16(RawDnsClass.IN)
                              .U32(300)
                              .U16((UInt16) httpsRdata.Length)
                              .Bytes(httpsRdata)
                              // --- a following record, which MUST remain intact ---
                              .Name("next.example.")
                              .U16(RawDnsType.A)
                              .U16(RawDnsClass.IN)
                              .U32(60)
                              .U16(4)
                              .Bytes(192, 0, 2, 1)
                              .ToArray());

        var https       = new HTTPS(DomainName.Parse("svc.example."), stream);

        Assert.That(https.SVCParameters.Select(p => p.Key), Is.EqualTo(new UInt16[] { 1 }));

        // The stream must now sit exactly at the start of the next record.
        var expectedPosition = 2 + 4 + 2 + httpsRdata.Length;

        Assert.That(stream.Position, Is.EqualTo(expectedPosition),
                    "after parsing, the stream must sit at the end of the HTTPS RDATA so the next record can be read");

    }

    #endregion

    #region HTTPS_RoundTrips_Through_Wire()

    [Test]
    public void HTTPS_RoundTrips_Through_Wire()
    {

        var alpn      = new RawDnsWriter().U8(2).Bytes((Byte) 'h', (Byte) '2').ToArray();

        var original  = new HTTPS(
                            DomainName.Parse("rt.example."),
                            DNSQueryClasses.IN,
                            Ttl,
                            16,
                            DomainName.Parse("svc.rt.example."),
                            [ new SVCParameter(1, alpn) ]
                        );

        var wire      = RRWire.Encode(original);

        var reparsed  = new HTTPS(
                            DomainName.Parse("rt.example."),
                            RRWire.RdataStream(wire.Rdata, wire.Class, wire.Ttl)
                        );

        Assert.Multiple(() => {
            Assert.That(reparsed.Priority,                       Is.EqualTo(original.Priority));
            Assert.That(reparsed.TargetName.FullName,            Is.EqualTo(original.TargetName.FullName));
            Assert.That(reparsed.SVCParameters.Single().Key,     Is.EqualTo((UInt16) 1));
            Assert.That(reparsed.SVCParameters.Single().Value,   Is.EqualTo(alpn));
        });

    }

    #endregion

}

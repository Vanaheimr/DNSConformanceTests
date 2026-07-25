using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Edns.Tests;

/// <summary>
/// RFC 6891 — the OPT pseudo-RR on the wire, plus the typed EDNS options
/// (RFC 7871, 7873, 7828, 7830, 8914).
/// </summary>
[TestFixture]
[Property("RFC", "6891")]
public class EdnsWireFormatTests
{

    #region Query_With_Edns_Contains_Exactly_One_WellFormed_Opt()

    [Test]
    public void Query_With_Edns_Contains_Exactly_One_WellFormed_Opt()
    {

        var packet   = DNSPacket.Query(
                           DNSServiceName.Parse("edns.example."),
                           4096,
                           true,
                           DNSResourceRecordTypes.A
                       );

        var decoded  = RawDnsReader.Parse(packet.ToByteArray());
        var opts     = decoded.Additionals.Where(rr => rr.IsOpt).ToArray();

        Assert.That(opts, Has.Length.EqualTo(1), "RFC 6891 §6.1.1: at most one OPT, in the additional section");

        var opt   = opts.Single();
        var edns  = RawEdns.From(opt);

        Assert.Multiple(() => {
            Assert.That(opt.Name.Labels,        Is.Empty,                "OPT owner MUST be the root name (§6.1.2)");
            Assert.That(edns.PayloadSize,       Is.EqualTo((UInt16) 4096), "CLASS carries the payload size");
            Assert.That(edns.Version,           Is.Zero,                 "EDNS version 0");
            Assert.That(edns.ExtendedRcode,     Is.Zero);
            Assert.That(edns.Do,                Is.False);
            Assert.That(edns.Options,           Is.Empty);
        });

    }

    #endregion

    #region Opt_Golden_Bytes_For_4096_With_DO()

    [Test]
    [Property("RFC", "6891 §6.1.2-6.1.4")]
    public void Opt_Golden_Bytes_For_4096_With_DO()
    {

        var packet  = DNSPacket.Query(
                          DNSServiceName.Parse("do.example."),
                          4096,
                          true,
                          DnssecOK:     true,
                          EDNSOptions:  null,
                          DNSResourceRecordTypes.A
                      );

        var wire    = packet.ToByteArray();

        // The OPT record is the last 11 bytes:
        //   00            root name
        //   00 29         TYPE 41
        //   10 00         CLASS 4096
        //   00 00 80 00   TTL: extRCODE=0, version=0, flags=0x8000 (DO)
        //   00 00         RDLENGTH 0
        var golden  = Bytes.FromHex("00 0029 1000 00 00 8000 0000");

        Assert.That(wire[^11..], Is.EqualTo(golden), Bytes.Diff(golden, wire[^11..]));

    }

    #endregion

    #region UdpPayloadSize_Zero_Disables_Edns()

    [Test]
    public void UdpPayloadSize_Zero_Disables_Edns()
    {

        var packet   = DNSPacket.Query(DNSServiceName.Parse("noedns.example."), 0, DNSResourceRecordTypes.A);
        var decoded  = RawDnsReader.Parse(packet.ToByteArray());

        Assert.That(decoded.Additionals.Where(rr => rr.IsOpt), Is.Empty);

    }

    #endregion


    #region CookieOption_Wire_Format()

    [Test]
    [Property("RFC", "7873 §4")]
    public void CookieOption_Wire_Format()
    {

        var cookie   = EDNSCookieOption.CreateInitial();

        var packet   = DNSPacket.Query(
                           DNSServiceName.Parse("cookie.example."),
                           4096,
                           true,
                           false,
                           [ cookie ],
                           DNSResourceRecordTypes.A
                       );

        var decoded  = RawDnsReader.Parse(packet.ToByteArray());
        var edns     = decoded.Edns!;

        var (code, data) = edns.Options.Single();

        Assert.Multiple(() => {
            Assert.That(code,         Is.EqualTo((UInt16) 10), "COOKIE option code 10");
            Assert.That(data.Length,  Is.EqualTo(8),           "initial client cookie is exactly 8 bytes (§4)");
        });

    }

    #endregion

    #region ClientSubnetOption_Wire_Format()

    [Test]
    [Property("RFC", "7871 §6")]
    public void ClientSubnetOption_Wire_Format()
    {

        var subnet   = new EDNSClientSubnetOption(
                           System.Net.IPAddress.Parse("203.0.113.128"),
                           SourcePrefixLength: 24
                       );

        var packet   = DNSPacket.Query(
                           DNSServiceName.Parse("ecs.example."),
                           4096,
                           true,
                           false,
                           [ subnet ],
                           DNSResourceRecordTypes.A
                       );

        var decoded  = RawDnsReader.Parse(packet.ToByteArray());
        var (code, data) = decoded.Edns!.Options.Single();

        Assert.Multiple(() => {

            Assert.That(code, Is.EqualTo((UInt16) 8), "CLIENT-SUBNET option code 8");

            // FAMILY(2)=1 IPv4, SOURCE PREFIX-LENGTH=24, SCOPE PREFIX-LENGTH=0,
            // ADDRESS: 3 bytes (truncated to the prefix, §6: "MUST NOT contain
            // more address octets than the prefix requires").
            Assert.That(data[0],  Is.Zero);
            Assert.That(data[1],  Is.EqualTo(1),   "address family 1 = IPv4");
            Assert.That(data[2],  Is.EqualTo(24),  "source prefix length");
            Assert.That(data[3],  Is.Zero,         "scope prefix length MUST be 0 in queries");
            Assert.That(data.Length, Is.EqualTo(4 + 3), "address truncated to 3 octets for /24");
            Assert.That(data[4..], Is.EqualTo(new Byte[] { 203, 0, 113 }));

        });

    }

    #endregion

    #region PaddingOption_Is_Zero_Bytes()

    [Test]
    [Property("RFC", "7830 §3")]
    public void PaddingOption_Is_Zero_Bytes()
    {

        var padding  = EDNSPaddingOption.Create(100);

        var packet   = DNSPacket.Query(
                           DNSServiceName.Parse("pad.example."),
                           4096,
                           true,
                           false,
                           [ padding ],
                           DNSResourceRecordTypes.A
                       );

        var decoded  = RawDnsReader.Parse(packet.ToByteArray());
        var (code, data) = decoded.Edns!.Options.Single();

        Assert.Multiple(() => {
            Assert.That(code, Is.EqualTo((UInt16) 12), "PADDING option code 12");
            Assert.That(data, Is.All.Zero, "'The PADDING octets SHOULD be set to 0x00'");
        });

    }

    #endregion

    #region Unknown_Option_Codes_Are_Preserved_As_Generic_Options()

    [Test]
    [Property("RFC", "6891 §6.1.2")]
    public void Unknown_Option_Codes_Are_Preserved_As_Generic_Options()
    {

        var parsed = EDNSOption.Parse(65001, [1, 2, 3]);

        Assert.Multiple(() => {
            Assert.That(parsed,       Is.TypeOf<EDNSOption>(), "unknown codes must not be dropped or throw");
            Assert.That(parsed.Code,  Is.EqualTo((UInt16) 65001));
            Assert.That(parsed.Data,  Is.EqualTo(new Byte[] { 1, 2, 3 }));
        });

    }

    #endregion

    #region ExtendedDnsError_Parses_InfoCode_And_Text()

    [Test]
    [Property("RFC", "8914 §2")]
    public void ExtendedDnsError_Parses_InfoCode_And_Text()
    {

        // INFO-CODE 18 (Prohibited) + EXTRA-TEXT.
        var data    = new Byte[] { 0x00, 0x12 }
                          .Concat(Encoding.UTF8.GetBytes("blocked by policy"))
                          .ToArray();

        var parsed  = EDNSOption.Parse(15, data);

        Assert.That(parsed, Is.TypeOf<EDNSExtendedDNSError>());

        var ede = (EDNSExtendedDNSError) parsed;

        Assert.Multiple(() => {
            Assert.That((UInt16) ede.InfoCode, Is.EqualTo((UInt16) 18));
            Assert.That(ede.ExtraText,         Is.EqualTo("blocked by policy"));
        });

    }

    #endregion

    #region Opt_With_Options_RoundTrips_Through_Hermod_Parser()

    [Test]
    public void Opt_With_Options_RoundTrips_Through_Hermod_Parser()
    {

        // RawDns-crafted OPT with a cookie option → Hermod OPT(Stream) parser.
        var cookieData  = Bytes.FromHex("0102030405060708");
        var options     = new RawDnsWriter().U16(10).U16((UInt16) cookieData.Length).Bytes(cookieData).ToArray();

        // Stream starts right after the owner name + TYPE were consumed:
        var stream      = new MemoryStream(new RawDnsWriter()
                              .U16(1232)                    // CLASS: payload size
                              .U32(0x00008000)              // extRCODE 0, version 0, DO
                              .U16((UInt16) options.Length)
                              .Bytes(options)
                              .ToArray());

        var opt = new OPT(DNSServiceName.Parse("."), stream);

        Assert.Multiple(() => {
            Assert.That(opt.UDPPayloadSize,        Is.EqualTo((UInt16) 1232));
            Assert.That(opt.Version,               Is.Zero);
            Assert.That(opt.Flags & 0x8000,        Is.EqualTo(0x8000), "DO bit");
            Assert.That(opt.Options.Single(),      Is.TypeOf<EDNSCookieOption>());
            Assert.That(opt.Options.Single().Data, Is.EqualTo(cookieData));
        });

    }

    #endregion

    #region Malformed_Option_Length_Does_Not_Crash_Opt_Parser()

    [Test]
    public void Malformed_Option_Length_Does_Not_Crash_Opt_Parser()
    {

        // Option claims 200 bytes, RDATA has 4.
        var stream = new MemoryStream(new RawDnsWriter()
                         .U16(512)
                         .U32(0)
                         .U16(8)                       // RDLENGTH 8
                         .U16(10).U16(200)             // cookie option claiming 200 bytes
                         .U16(0).U16(0)                // filler
                         .ToArray());

        Assert.That(() => new OPT(DNSServiceName.Parse("."), stream), Throws.Nothing,
                    "malformed option lengths must be handled gracefully");

    }

    #endregion

}

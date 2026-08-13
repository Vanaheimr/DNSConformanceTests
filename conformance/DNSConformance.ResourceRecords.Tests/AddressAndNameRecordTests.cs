using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 1035 §3.3/§3.4, RFC 3596, RFC 1183, RFC 2782, RFC 3403, RFC 6672 —
/// address and name-bearing RDATA formats.
/// </summary>
[TestFixture]
public class AddressAndNameRecordTests
{

    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(300);


    #region A_Rdata_Is_Four_Address_Octets()

    [Test]
    [Property("RFC", "1035 §3.4.1")]
    public void A_Rdata_Is_Four_Address_Octets()
    {

        var record   = new A(DomainName.Parse("a.example."), DNSQueryClasses.IN, Ttl, IPv4Address.Parse("192.0.2.1"));
        var encoded  = RRWire.Encode(record);

        Assert.Multiple(() => {
            Assert.That(encoded.Type,   Is.EqualTo(RawDnsType.A));
            Assert.That(encoded.Class,  Is.EqualTo(RawDnsClass.IN));
            Assert.That(encoded.Ttl,    Is.EqualTo(300u));
            Assert.That(encoded.Rdata,  Is.EqualTo(new Byte[] { 192, 0, 2, 1 }), "RDATA = the raw 32-bit address");
        });

    }

    #endregion

    #region A_Parses_RawDns_Crafted_Rdata()

    [Test]
    public void A_Parses_RawDns_Crafted_Rdata()
    {

        var record = new A(
                         DomainName.Parse("a.example."),
                         RRWire.RdataStream([203, 0, 113, 77])
                     );

        Assert.That(record.IPv4Address.ToString(), Is.EqualTo("203.0.113.77"));
        Assert.That(record.TimeToLive.TotalSeconds, Is.EqualTo(300));

    }

    #endregion

    #region AAAA_Rdata_Is_Sixteen_Address_Octets()

    [Test]
    [Property("RFC", "3596 §2.2")]
    public void AAAA_Rdata_Is_Sixteen_Address_Octets()
    {

        var record   = new AAAA(DomainName.Parse("aaaa.example."), DNSQueryClasses.IN, Ttl, IPv6Address.Parse("2001:db8::1"));
        var encoded  = RRWire.Encode(record);

        Assert.Multiple(() => {
            Assert.That(encoded.Type,  Is.EqualTo(RawDnsType.AAAA));
            Assert.That(encoded.Rdata, Is.EqualTo(RawDnsWriter.IPv6("2001:db8::1")));
        });

    }

    #endregion

    #region CNAME_NS_PTR_DNAME_Rdata_Is_A_Single_Name()

    [Test]
    [Property("RFC", "1035 §3.3.1/§3.3.11/§3.3.12, 6672 §2.1")]
    public void CNAME_NS_PTR_DNAME_Rdata_Is_A_Single_Name()
    {

        var owner = DomainName.Parse("owner.example.");

        var cases = new (IDNSResourceRecord Record, UInt16 Type, String Target)[] {
            (new CNAME(owner, DNSQueryClasses.IN, Ttl, DomainName.Parse("target.example.")),      RawDnsType.CNAME, "target.example"),
            (new NS   (owner, DNSQueryClasses.IN, Ttl, DomainName.Parse("ns1.example.")),         RawDnsType.NS,    "ns1.example"),
            (new PTR  (owner, DNSQueryClasses.IN, Ttl, DNSServiceName.Parse("host.example.")),    RawDnsType.PTR,   "host.example"),
            (new DNAME(owner, DNSQueryClasses.IN, Ttl, DomainName.Parse("sub.example.")),         RawDnsType.DNAME, "sub.example")
        };

        Assert.Multiple(() => {

            foreach (var (record, type, target) in cases)
            {

                var encoded = RRWire.Encode(record);

                Assert.That(encoded.Type, Is.EqualTo(type));

                var golden = RawDnsWriter.NameBytes(target);
                Assert.That(encoded.Rdata, Is.EqualTo(golden),
                            $"{type}: RDATA must be exactly the uncompressed target name — {Bytes.Diff(golden, encoded.Rdata)}");

            }

        });

    }

    #endregion

    #region MX_Rdata_Is_Preference_Then_Exchange()

    [Test]
    [Property("RFC", "1035 §3.3.9")]
    public void MX_Rdata_Is_Preference_Then_Exchange()
    {

        var record   = new MX(DomainName.Parse("mx.example."), DNSQueryClasses.IN, Ttl, 10, DomainName.Parse("mail.example."));
        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter().U16(10).Name("mail.example.").ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region MX_Parses_RawDns_Crafted_Rdata()

    [Test]
    public void MX_Parses_RawDns_Crafted_Rdata()
    {

        var rdata   = new RawDnsWriter().U16(42).Name("in.example.").ToArray();

        var record  = new MX(
                          DomainName.Parse("mx.example."),
                          RRWire.RdataStream(rdata)
                      );

        Assert.Multiple(() => {
            Assert.That(record.Preference,                             Is.EqualTo((UInt16) 42));
            Assert.That(record.Exchange.FullName.TrimEnd('.'),         Is.EqualTo("in.example").IgnoreCase);
        });

    }

    #endregion

    #region SOA_Rdata_Field_Order_And_Widths()

    [Test]
    [Property("RFC", "1035 §3.3.13")]
    public void SOA_Rdata_Field_Order_And_Widths()
    {

        var record  = new SOA(
                          DomainName.Parse("example."),
                          DNSQueryClasses.IN,
                          Ttl,
                          DomainName.Parse("ns1.example."),
                          org.GraphDefined.Vanaheimr.Hermod.Mail.SimpleEMailAddress.Parse("hostmaster@example."),
                          2026072501,
                          TimeSpan.FromHours(2),
                          TimeSpan.FromHours(1),
                          TimeSpan.FromDays(14),
                          TimeSpan.FromMinutes(5)
                      );

        var encoded = RRWire.Encode(record);

        // MNAME + RNAME + 5 × 32 bit:
        var golden  = new RawDnsWriter()
                          .Name("ns1.example.")
                          .Name("hostmaster.example.")
                          .U32(2026072501)
                          .U32(7200)
                          .U32(3600)
                          .U32(1209600)
                          .U32(300)
                          .ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region SRV_Rdata_Priority_Weight_Port_Target()

    [Test]
    [Property("RFC", "2782")]
    public void SRV_Rdata_Priority_Weight_Port_Target()
    {

        var record   = new SRV(
                           DNSServiceName.Parse("_sip._tcp.example."),
                           DNSQueryClasses.IN,
                           Ttl,
                           10, 60, IPPort.Parse(5060),
                           DomainName.Parse("sipserver.example.")
                       );

        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter()
                           .U16(10).U16(60).U16(5060)
                           .Name("sipserver.example.")
                           .ToArray();

        Assert.Multiple(() => {

            Assert.That(encoded.Name.Presentation, Is.EqualTo("_sip._tcp.example"),
                        "underscored service owner names must survive");

            // The RDATA layout: two 16-bit fields, a port, and the target as an
            // ordinary name. This says nothing about RFC 2782's "name compression
            // is NOT to be used for this field" — RRWire.Encode serializes with
            // compression off, so a target that ignored the rule would encode
            // identically here. That claim is measured in
            // WireFormat.Tests/RdataCompressionTests, where the name is on offer
            // at offset 12 and declining it is a decision.
            Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

        });

    }

    #endregion

    #region RP_Rdata_Is_Two_Names()

    [Test]
    [Property("RFC", "1183 §2.2")]
    public void RP_Rdata_Is_Two_Names()
    {

        var record   = new RP(
                           DomainName.Parse("rp.example."),
                           DNSQueryClasses.IN,
                           Ttl,
                           DomainName.Parse("admin.example."),
                           DomainName.Parse("info.example.")
                       );

        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter().Name("admin.example.").Name("info.example.").ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region AFSDB_Rdata_Is_Subtype_And_Hostname()

    [Test]
    [Property("RFC", "1183 §1")]
    public void AFSDB_Rdata_Is_Subtype_And_Hostname()
    {

        var record   = new AFSDB(
                           DomainName.Parse("afs.example."),
                           DNSQueryClasses.IN,
                           Ttl,
                           1,
                           DomainName.Parse("afsdb.example.")
                       );

        var encoded  = RRWire.Encode(record);
        var golden   = new RawDnsWriter().U16(1).Name("afsdb.example.").ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region NAPTR_Rdata_Order_Preference_Strings_Replacement()

    [Test]
    [Property("RFC", "3403 §4.1")]
    public void NAPTR_Rdata_Order_Preference_Strings_Replacement()
    {

        var record   = new NAPTR(
                           DomainName.Parse("naptr.example."),
                           DNSQueryClasses.IN,
                           Ttl,
                           100,
                           50,
                           "S",
                           "SIP+D2U",
                           "",
                           DomainName.Parse("sip.example.")
                       );

        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter()
                           .U16(100).U16(50)
                           .CharacterString("S")
                           .CharacterString("SIP+D2U")
                           .CharacterString("")
                           .Name("sip.example.")
                           .ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion


    #region RoundTrip_Through_Wire_Preserves_Values()

    [Test]
    public void RoundTrip_Through_Wire_Preserves_Values()
    {

        // Serialize with Hermod → craft the ctor stream → parse with Hermod.
        var original  = new MX(DomainName.Parse("rt.example."), DNSQueryClasses.IN, Ttl, 7, DomainName.Parse("x.example."));
        var wire      = RRWire.Encode(original);

        var reparsed  = new MX(
                            DomainName.Parse("rt.example."),
                            RRWire.RdataStream(wire.Rdata, wire.Class, wire.Ttl)
                        );

        Assert.Multiple(() => {
            Assert.That(reparsed.Preference,  Is.EqualTo(original.Preference));
            Assert.That(reparsed.Exchange,    Is.EqualTo(original.Exchange));
            Assert.That((UInt32) reparsed.TimeToLive.TotalSeconds, Is.EqualTo(wire.Ttl));
        });

    }

    #endregion

}

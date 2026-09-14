using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 4025 — IPSECKEY, whose gateway field has four shapes and a preceding
/// octet that says which.
/// </summary>
/// <remarks>
/// <para>
/// A field whose meaning is decided by another field is where a record parser
/// usually goes wrong, and this stack has got that shape wrong twice already:
/// LOC's version octet (finding 29) and APL's address family. Here it is worse
/// than either, because gateway type 3 carries a wire-encoded name whose length
/// is written nowhere — RFC 4025 §2.3 says it "is self-describing, so the length
/// is implicit" — so the boundary between the gateway and the public key has to
/// be found by walking labels. Getting that wrong does not fail: it silently
/// moves the boundary.
/// </para>
/// <para>
/// Every expected string below is `named-checkzone -D`'s output for the same
/// zone, so the presentation format is measured against BIND rather than against
/// this suite's reading of §3.1.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "4025")]
public class IpsecKeyTests
{

    #region Data

    /// <summary>The key every example in RFC 4025 §3.2 uses.</summary>
    private const String Key = "AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==";

    private static IDNSResourceRecord Read(String Line)
    {

        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");

        return record!;

    }

    private static String RDataText(IDNSResourceRecord Record)
        => Record.ToZoneFileString().Split("IPSECKEY")[1].Trim();

    private static String Hex(Byte[] Bytes)
        => Convert.ToHexString(Bytes).ToLowerInvariant();

    #endregion

    #region The four examples of RFC 4025 §3.2

    [Test]
    [Property("RFC", "4025 §3.2")]
    // Gateway type 1: a 4-byte IPv4 address.
    [TestCase("10 1 2 192.0.2.38 " + Key,              "10 1 2 192.0.2.38 " + Key)]
    // Gateway type 0: "the gateway field MUST be '.'"
    [TestCase("10 0 2 . " + Key,                       "10 0 2 . " + Key)]
    // Gateway type 3: a wire-encoded domain name.
    [TestCase("10 3 2 mygateway.example.com. " + Key,  "10 3 2 mygateway.example.com. " + Key)]
    // Gateway type 2: sixteen octets of IPv6 — written back in RFC 5952 §4's
    // canonical form, lowercase and compressed, which is what BIND writes.
    [TestCase("10 2 2 2001:0DB8:0:8002::2000:1 " + Key, "10 2 2 2001:db8:0:8002::2000:1 " + Key)]
    public void The_Rfc_Examples_Read_And_Write_The_Way_Bind_Writes_Them(String Written, String Expected)
    {

        Assert.That(RDataText(Read($"probe.example. 7200 IN IPSECKEY {Written}")),
                    Is.EqualTo(Expected));

    }

    #endregion

    #region The gateway types on the wire

    [Test]
    [Property("RFC", "4025 §2.3")]
    public void Each_Gateway_Type_Occupies_The_Octets_It_Says_It_Does()
    {

        var none = Read("probe.example. 7200 IN IPSECKEY 10 0 2 . " + Key);
        var ipv4 = Read("probe.example. 7200 IN IPSECKEY 10 1 2 192.0.2.38 " + Key);
        var ipv6 = Read("probe.example. 7200 IN IPSECKEY 10 2 2 2001:db8::1 " + Key);
        var name = Read("probe.example. 7200 IN IPSECKEY 10 3 2 gw.example. " + Key);

        var key = Convert.FromBase64String(Key);

        Assert.Multiple(() => {

            // Three fixed octets, then 0 / 4 / 16 / a wire-encoded name, then
            // the key. The key length is the same in all four, so any gateway
            // whose length is read wrong moves the boundary and corrupts it.
            Assert.That(Hex(ADNSResourceRecord.RDataOf(none)),
                        Is.EqualTo("0a" + "00" + "02" + Hex(key)));

            Assert.That(Hex(ADNSResourceRecord.RDataOf(ipv4)),
                        Is.EqualTo("0a" + "01" + "02" + "c0000226" + Hex(key)));

            Assert.That(Hex(ADNSResourceRecord.RDataOf(ipv6)),
                        Is.EqualTo("0a" + "02" + "02" + "20010db8000000000000000000000001" + Hex(key)));

            // "gw.example." uncompressed: 02 'g' 'w' 07 'e'…'e' 00
            Assert.That(Hex(ADNSResourceRecord.RDataOf(name)),
                        Is.EqualTo("0a" + "03" + "02" + "026777076578616d706c6500" + Hex(key)));

        });

    }

    [Test]
    [Property("RFC", "4025 §2.3")]
    public void The_Public_Key_Begins_Where_The_Gateway_Name_Ends()
    {

        // The assertion the implicit length is really about. Read the type-3
        // record back off the wire and require both halves: a parser that took
        // one label too many would produce a shorter key and a longer name, and
        // both would still look like plausible records.
        var record = Read("probe.example. 7200 IN IPSECKEY 10 3 2 gw.example. " + Key) as IPSECKEY;

        Assert.That(record, Is.Not.Null);

        Assert.Multiple(() => {

            Assert.That(record!.GatewayName?.FullName, Is.EqualTo("gw.example.").IgnoreCase);

            Assert.That(record.PublicKey, Is.EqualTo(Convert.FromBase64String(Key)),
                        "the key must survive the gateway that precedes it");

            Assert.That(record.Gateway, Has.Length.EqualTo(12),
                        "2+1 for gw, 7+1 for example, 1 for the root label");

        });

    }

    #endregion

    [Test]
    [Property("RFC", "4025 §2.3")]
    [TestCase(0,  "",                          TestName = "Wire_Gateway_Type_0_None")]
    [TestCase(1,  "c0000226",                  TestName = "Wire_Gateway_Type_1_IPv4")]
    [TestCase(2,  "20010db8000000000000000000000001", TestName = "Wire_Gateway_Type_2_IPv6")]
    [TestCase(3,  "026777076578616d706c6500",  TestName = "Wire_Gateway_Type_3_Name")]
    public void The_Wire_Reader_Splits_Gateway_From_Key_For_Every_Type(Int32 GatewayType, String GatewayHex)
    {

        // GatewayLengthOf is reached only from the wire constructor, and every
        // other test here comes in through the presentation format. Without this
        // one, the implicit-length walk of §2.3 — the single most delicate thing
        // in the record — is exercised for exactly one gateway type, and
        // mutations to the other three survive. The APL round had the same hole
        // and two mutants lived in it.
        //
        // The RFC 3597 §5 generic form is the way to the wire constructor.
        var key   = Convert.FromBase64String(Key);
        var rdata = Convert.FromHexString("0a" + GatewayType.ToString("x2") + "02" + GatewayHex) .
                        Concat(key).
                        ToArray();

        var record = ADNSResourceRecord.ParseZoneFileString(
                         $"probe.example. 7200 IN IPSECKEY \\# {rdata.Length} {Hex(rdata)}"
                     ) as IPSECKEY;

        Assert.That(record, Is.Not.Null);

        Assert.Multiple(() => {

            Assert.That(record!.GatewayType, Is.EqualTo(GatewayType));

            Assert.That(Hex(record.Gateway), Is.EqualTo(GatewayHex),
                        "the gateway must be exactly the octets its type claims");

            // The half that a mis-read length corrupts silently: one octet too
            // many and the key is short by one, which still decodes to base-64
            // and still looks like a key.
            Assert.That(record.PublicKey, Is.EqualTo(key),
                        "and the key must be everything after it, to the octet");

        });

    }

    #region The name is not compressed

    [Test]
    [Property("RFC", "4025 §2.4")]
    [Property("RFC", "3597 §4")]
    public void The_Gateway_Name_Is_Never_Compressed()
    {

        // §2.4: "The domain name MUST NOT be compressed." RFC 3597 §4 says the
        // same for every type postdating RFC 1035, and finding 22 was this rule
        // being broken by eleven of them at once. A compressed name here would
        // also be unreadable to anyone who took §2.3 at its word and walked the
        // labels.
        // The owner name and the gateway share every label, which is exactly the
        // situation a compressing serializer would take advantage of.
        var record = Read("probe.example. 7200 IN IPSECKEY 10 3 2 gw.probe.example. " + Key);
        var rdata  = ADNSResourceRecord.RDataOf(record);

        // Walk the gateway's labels from octet 3 and require every length byte to
        // be a length: a pointer has its top two bits set, and one appearing here
        // would also break §2.3's implicit length, since a pointer is two octets
        // where a reader is counting labels.
        var pointerFound = false;
        var index        = 3;

        while (index < rdata.Length && rdata[index] != 0)
        {

            if ((rdata[index] & 0xC0) != 0)
            {
                pointerFound = true;
                break;
            }

            index += rdata[index] + 1;

        }

        Assert.Multiple(() => {

            Assert.That(pointerFound, Is.False,
                        "a compression pointer in the gateway would violate §2.4");

            // And the positive half: the shared labels are present a second time
            // rather than pointed at.
            Assert.That(Hex(rdata), Does.Contain("0570726f6265"),
                        "the label \"probe\" must appear in the RDATA in full");

            Assert.That(Hex(rdata), Does.Contain("076578616d706c65"),
                        "and so must \"example\"");

        });

    }

    #endregion

    #region A record with no key at all

    [Test]
    [Property("RFC", "4025 §2.5")]
    public void A_Record_With_No_Key_Round_Trips()
    {

        // §2.5: algorithm 0 "indicates that no key is present", and the key field
        // "MUST be construed to be zero octets in length".
        //
        // BIND cannot represent this record. named-checkzone refuses it in the
        // presentation form *and* in the RFC 3597 §5 generic form — "unexpected
        // end of input" either way — so there is no interoperable spelling to
        // copy and no outside judge to defer to. The line is written the way §2.5
        // describes it, with the key simply absent, and read back the same.
        var record = Read("probe.example. 7200 IN IPSECKEY 10 1 0 192.0.2.38") as IPSECKEY;

        Assert.That(record, Is.Not.Null);

        Assert.Multiple(() => {

            Assert.That(record!.Algorithm, Is.EqualTo(0));
            Assert.That(record. PublicKey, Is.Empty);
            Assert.That(record. GatewayIPv4?.ToString(), Is.EqualTo("192.0.2.38"));

            Assert.That(Hex(ADNSResourceRecord.RDataOf(record)),
                        Is.EqualTo("0a" + "01" + "00" + "c0000226"),
                        "seven octets and no key");

            Assert.That(RDataText(record), Is.EqualTo("10 1 0 192.0.2.38"));

            // Untrimmed, because the helper above trims and the whole claim of
            // this test is that nothing is written where the key would be. A
            // mutation that appends an empty key field leaves exactly one
            // trailing space, and Trim() made it invisible: the test passed
            // while asserting nothing about the thing it is named after.
            Assert.That(record.ToZoneFileString(), Does.Not.Match(@"\s$"),
                        "an empty key field would show up as trailing whitespace");

        });

    }

    #endregion

    #region An unassigned gateway type

    [Test]
    [Property("RFC", "4025 §2.3")]
    [Property("RFC", "3597 §2")]
    public void An_Unassigned_Gateway_Type_Does_Not_Cost_The_Record()
    {

        // RFC 4025 assigns four gateway types and says nothing about a fifth, so
        // a record carrying one says nothing about how long its gateway is.
        // There is no boundary to find — but there is also no reason to throw:
        // finding 21 was a parser that threw on something it did not recognise
        // and took every record behind it down with it.
        var wire = Convert.FromHexString("0A0402" + Convert.ToHexString(Convert.FromBase64String(Key)));

        var record = ADNSResourceRecord.ParseZoneFileString(
                         $"probe.example. 7200 IN IPSECKEY \\# {wire.Length} {Convert.ToHexString(wire).ToLowerInvariant()}"
                     ) as IPSECKEY;

        Assert.That(record, Is.Not.Null, "the record must survive an unassigned gateway type");

        Assert.Multiple(() => {
            Assert.That(record!.GatewayType, Is.EqualTo(4));
            Assert.That(record. Gateway,     Is.Empty);
            Assert.That(Hex(ADNSResourceRecord.RDataOf(record)), Is.EqualTo(Hex(wire)),
                        "and the octets have to come back unchanged");
        });

    }

    #endregion

    #region The mnemonic

    [Test]
    public void The_Mnemonic_Is_Known_In_Both_Directions()
    {

        Assert.Multiple(() => {
            Assert.That(ADNSResourceRecord.TypeName((DNSResourceRecordTypes) 45), Is.EqualTo("IPSECKEY"));
            Assert.That((UInt16) DNSResourceRecordTypes.IPSECKEY, Is.EqualTo(45), "IANA assigned IPSECKEY 45");
        });

    }

    #endregion

}

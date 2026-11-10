using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 8005 — HIP, a record whose lengths are written in two fields and left
/// out of a third.
/// </summary>
/// <remarks>
/// <para>
/// §5 puts the HIT length and the PK length in front of the HIT and the key, and
/// gives the rendezvous servers no length at all: they run to the end of the
/// RDATA, one root label after another (§5.6). Three boundaries, two of them
/// written down and one implied, and getting any of them wrong moves octets from
/// one field into the next without anything failing.
/// </para>
/// <para>
/// The presentation form (§6) separates the fields by whitespace alone, which is
/// why the HIT and the key "MUST NOT contain" any. Every expected string below
/// is <c>named-compilezone</c>'s output for the same line; BIND writes the HIT in
/// capitals.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "8005")]
public class HipTests
{

    #region Data

    /// <summary>The Host Identity of every example in RFC 8005 §7.</summary>
    private const String Key = "AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48AWkskmdHaVDP4BcelrTI3rMXdXF5D";

    /// <summary>The HIT of every example in RFC 8005 §7.</summary>
    private const String Hit = "200100107B1A74DF365639CC39F1D578";

    private static IDNSResourceRecord Read(String Line)
    {

        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");

        return record!;

    }

    private static String RDataText(IDNSResourceRecord Record)
        => Record.ToZoneFileString().Split(" HIP ")[1].Trim();

    private static String Hex(Byte[] Bytes)
        => Convert.ToHexString(Bytes).ToLowerInvariant();

    #endregion


    #region The_Three_Examples_Of_Section_7(Servers)

    [Test]
    [Property("RFC", "8005 §7")]
    // "a node with an HI and a HIT but no RVS"
    [TestCase("",                                       TestName = "Hip_example__no_rendezvous_server")]
    // "a node with an HI, a HIT, and one RVS"
    [TestCase(" rvs.example.com.",                      TestName = "Hip_example__one_rendezvous_server")]
    // "a node with an HI, a HIT, and two RVSs"
    [TestCase(" rvs1.example.com. rvs2.example.com.",   TestName = "Hip_example__two_rendezvous_servers")]
    public void The_Three_Examples_Of_Section_7(String Servers)
    {

        // §7 wraps the key across lines "since it does not fit in a single line
        // of this document" — and says the field contains no whitespace. Written
        // out, it is one token, inside the parentheses the examples use.
        var record = Read($"www.example.com. 300 IN HIP ( 2 {Hit} {Key}{Servers} )");

        Assert.Multiple(() => {
            Assert.That(record,            Is.InstanceOf<HIP>());
            Assert.That(RDataText(record), Is.EqualTo($"2 {Hit} {Key}{Servers}"));
        });

    }

    #endregion

    #region The_Hit_Is_Read_In_Either_Case_And_Written_In_Capitals()

    [Test]
    [Property("RFC", "8005 §6")]
    public void The_Hit_Is_Read_In_Either_Case_And_Written_In_Capitals()
    {

        // §6 says Base16 and nothing about case; BIND reads both and writes
        // capitals, and the octets are the same either way.
        var record = Read($"www.example.com. 300 IN HIP 2 {Hit.ToLowerInvariant()} AwEAAQ==") as HIP;

        Assert.That(record, Is.Not.Null);

        Assert.Multiple(() => {
            Assert.That(Convert.ToHexString(record!.HIT), Is.EqualTo(Hit));
            Assert.That(RDataText(record),                Is.EqualTo($"2 {Hit} AwEAAQ=="));
        });

    }

    #endregion

    #region What_Is_Not_A_HIP_Is_Refused(Written)

    [Test]
    [Property("RFC", "8005 §6")]
    // An odd number of hex digits is not a number of octets. BIND: "bad hex encoding".
    [TestCase("2 2001001 AwEAAQ==",                             TestName = "Hip_refused__odd_hit")]
    // "-" is how NSEC3 writes an empty salt, and HIP has no empty HIT (§5).
    [TestCase("2 - AwEAAQ==",                                   TestName = "Hip_refused__dash_for_hit")]
    // The key is REQUIRED (§5). BIND: "unexpected end of input".
    [TestCase("2 200100107b1a74df365639cc39f1d578",            TestName = "Hip_refused__no_key")]
    // The algorithm is eight bits (§5.2). BIND: "out of range".
    [TestCase("256 200100107b1a74df365639cc39f1d578 AwEAAQ==", TestName = "Hip_refused__algorithm_256")]
    [TestCase("x 200100107b1a74df365639cc39f1d578 AwEAAQ==",   TestName = "Hip_refused__algorithm_not_a_number")]
    // Not base-64.
    [TestCase("2 200100107b1a74df365639cc39f1d578 AwE",        TestName = "Hip_refused__key_not_base64")]
    public void What_Is_Not_A_HIP_Is_Refused(String Written)
    {

        Assert.That(ADNSResourceRecord.TryParseZoneFileString($"www.example.com. 300 IN HIP {Written}", out _, out _),
                    Is.False,
                    $"'{Written}' is not the RDATA of a HIP");

    }

    #endregion

    #region A_Key_Split_By_Whitespace_Is_Not_One_Key()

    [Test]
    [Property("RFC", "8005 §6")]
    public void A_Key_Split_By_Whitespace_Is_Not_One_Key()
    {

        // §6: the key "MUST NOT contain whitespace(s) to distinguish it from the
        // Rendezvous Server field". So "AwEA AQID" is not the six octets of
        // "AwEAAQID" but a three-octet key followed by a server named "AQID" —
        // which is how BIND reads it too. Both halves are valid base-64, so a
        // reader that joined the tokens back together would get a plausible key
        // and lose the server without failing.
        var record = Read($"www.example.com. 300 IN HIP 2 {Hit} AwEA AQID.") as HIP;

        Assert.That(record, Is.Not.Null);

        Assert.Multiple(() => {
            Assert.That(record!.PublicKey,                                          Is.EqualTo(Convert.FromBase64String("AwEA")));
            Assert.That(record. RendezvousServers.Select(server => server.FullName), Is.EqualTo(new[] { "AQID." }));
        });

    }

    #endregion


    #region The_Wire_Form_Puts_Each_Field_Where_Its_Length_Says(...)

    [Test]
    [Property("RFC", "8005 §5")]
    public void The_Wire_Form_Puts_Each_Field_Where_Its_Length_Says()
    {

        var record = Read($"www.example.com. 300 IN HIP 2 {Hit} AwEAAQ== rvs1.example. Rvs2.Example.");

        // HIT length 16, algorithm 2, PK length 4, the HIT, the key, and the two
        // servers — uncompressed (§5.6), in order, the case of the second kept.
        Assert.That(Hex(ADNSResourceRecord.RDataOf(record)),
                    Is.EqualTo("10" + "02" + "0004" +
                               Hit.ToLowerInvariant() +
                               "03010001" +
                               "0472767331" + "076578616d706c65" + "00" +
                               "0452767332" + "074578616d706c65" + "00"));

    }

    #endregion

    #region The_Generic_Form_Reads_Every_Boundary(...)

    [Test]
    [Property("RFC", "8005 §5")]
    [Property("RFC", "3597 §5")]
    public void The_Generic_Form_Reads_Every_Boundary()
    {

        // The wire constructor, reached through the generic form: a one-octet
        // HIT, a two-octet key and two servers, so that a boundary read one octet
        // early or late shows in the field on either side of it. BIND reads the
        // first seven octets alone as "2 AB AQI=".
        var rdata  = "01" + "02" + "0002" + "ab" + "0102" +
                     "0161" + "00" +
                     "0162" + "00";

        var record = ADNSResourceRecord.ParseZoneFileString(
                         $@"www.example.com. 300 IN HIP \# {rdata.Length / 2} {rdata}") as HIP;

        Assert.That(record, Is.Not.Null);

        Assert.Multiple(() => {
            Assert.That(record!.PKAlgorithm,     Is.EqualTo(2));
            Assert.That(Hex(record.HIT),         Is.EqualTo("ab"));
            Assert.That(Hex(record.PublicKey),   Is.EqualTo("0102"));
            Assert.That(record.RendezvousServers.Select(server => server.FullName),
                        Is.EqualTo(new[] { "a.", "b." }),
                        "both servers, in the order they came, the second ending at the last octet");
            Assert.That(record.UnparsedRData,    Is.Null);
            Assert.That(RDataText(record),       Is.EqualTo("2 AB AQI= a. b."));
        });

    }

    #endregion

    #region Rdata_That_Is_Not_A_HIP_Is_Kept_As_It_Arrived(Hex)

    [Test]
    [Property("RFC", "8005 §5")]
    [Property("RFC", "3597 §2")]
    // A HIT of length zero: the HIT is REQUIRED. BIND: FORMERR.
    [TestCase("00020002aabb",                  TestName = "Hip_kept__empty_hit")]
    // A key of length zero: so is the key. BIND: FORMERR.
    [TestCase("01020000ab00",                  TestName = "Hip_kept__empty_key")]
    // A key longer than what is left. BIND: FORMERR.
    [TestCase("01020002ab01",                  TestName = "Hip_kept__key_runs_off_the_end")]
    // Fewer octets than the four of the fixed header.
    [TestCase("010200",                        TestName = "Hip_kept__short_header")]
    // A server name that is a pointer (§5.6: "MUST NOT be compressed"). BIND: "disallowed".
    [TestCase("01020002ab0102c00c",            TestName = "Hip_kept__compressed_server")]
    // A server name with no root label before the RDATA ends.
    [TestCase("01020002ab0102037276",          TestName = "Hip_kept__server_runs_off_the_end")]
    public void Rdata_That_Is_Not_A_HIP_Is_Kept_As_It_Arrived(String RDataHex)
    {

        var rdata  = Convert.FromHexString(RDataHex);
        var record = ADNSResourceRecord.ParseZoneFileString($@"www.example.com. 300 IN HIP \# {rdata.Length} {RDataHex}") as HIP;

        Assert.That(record, Is.Not.Null, "the record must survive RDATA it cannot read");

        Assert.Multiple(() => {
            Assert.That(record!.UnparsedRData,                   Is.EqualTo(rdata));
            Assert.That(Hex(ADNSResourceRecord.RDataOf(record)), Is.EqualTo(RDataHex));
            Assert.That(RDataText(record),                       Is.EqualTo($@"\# {rdata.Length} {RDataHex}"));
        });

    }

    #endregion


    #region The_Mnemonic_Is_Known_In_Both_Directions()

    [Test]
    public void The_Mnemonic_Is_Known_In_Both_Directions()
    {

        Assert.Multiple(() => {
            Assert.That(ADNSResourceRecord.TypeName((DNSResourceRecordTypes) 55), Is.EqualTo("HIP"));
            Assert.That((UInt16) DNSResourceRecordTypes.HIP, Is.EqualTo(55), "IANA assigned HIP 55");
        });

    }

    #endregion

}

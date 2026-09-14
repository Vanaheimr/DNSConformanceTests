using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 3123 (APL) and RFC 4701 (DHCID): two types the stack could only carry in
/// the RFC 3597 §5 generic form.
/// </summary>
/// <remarks>
/// <para>
/// Neither absence was a violation — <c>TYPE42</c> and <c>TYPE49</c> round-trip
/// through the generic form, which is what RFC 3597 is for. This is coverage:
/// the mnemonic, the presentation format, and the wire encoding.
/// </para>
/// <para>
/// APL is the one with a MUST in it. RFC 3123 §4: "the sender MUST NOT include
/// trailing zero octets in the AFDPART regardless of the value of PREFIX",
/// because "there is no semantic difference between 10.0.0.0/16 and 10/16". An
/// encoder that writes all four octets is wrong on the wire while looking right
/// in every text comparison, so the octets are asserted directly.
/// </para>
/// </remarks>
[TestFixture]
public class AplAndDhcidTests
{

    #region Data

    private static readonly DomainName Name = DomainName.Parse("probe.example.");

    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(3600);

    /// <summary>
    /// Read a zone-file line through the stack's own reader.
    /// </summary>
    private static IDNSResourceRecord Read(String Line)
    {

        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");

        Assert.That(record, Is.Not.Null);

        return record!;

    }

    /// <summary>
    /// The RDATA octets a record serialises to, without the owner name, type,
    /// class, TTL or the RDLENGTH that precedes them.
    /// </summary>
    private static Byte[] RDataOf(IDNSResourceRecord Record)
        => ADNSResourceRecord.RDataOf(Record);

    private static String Hex(Byte[] Bytes)
        => Convert.ToHexString(Bytes).ToLowerInvariant();

    #endregion

    #region The mnemonics themselves

    [Test]
    [Property("RFC", "3123")]
    [Property("RFC", "4701")]
    public void The_Two_Mnemonics_Are_Known_In_Both_Directions()
    {

        // Before this, TypeName fell through to the RFC 3597 §5 "TYPE" + code
        // form and the reader refused the mnemonic outright — so a zone file
        // BIND wrote with "APL" on the line could not be read at all.
        Assert.Multiple(() => {

            Assert.That(ADNSResourceRecord.TypeName((DNSResourceRecordTypes) 42), Is.EqualTo("APL"));
            Assert.That(ADNSResourceRecord.TypeName((DNSResourceRecordTypes) 49), Is.EqualTo("DHCID"));

            Assert.That((UInt16) DNSResourceRecordTypes.APL,   Is.EqualTo(42), "IANA assigned APL 42");
            Assert.That((UInt16) DNSResourceRecordTypes.DHCID, Is.EqualTo(49), "IANA assigned DHCID 49");

        });

    }

    #endregion

    #region APL — presentation format (RFC 3123 §5)

    [Test]
    [Property("RFC", "3123 §5")]
    public void The_Apl_Example_From_The_Rfc_Reads_And_Writes_Back()
    {

        // RFC 3123 §5's own example, negation included.
        var line   = "probe.example.          3600    IN   APL        1:192.168.32.0/21 !1:192.168.38.0/28";
        var record = Read(line) as APL;

        Assert.That(record, Is.Not.Null, "an APL line must produce an APL record");

        var items = record!.Items.ToArray();

        Assert.Multiple(() => {

            Assert.That(items, Has.Length.EqualTo(2));

            Assert.That(items[0].AddressFamily, Is.EqualTo(1));
            Assert.That(items[0].Prefix,        Is.EqualTo(21));
            Assert.That(items[0].Negated,       Is.False);

            Assert.That(items[1].AddressFamily, Is.EqualTo(1));
            Assert.That(items[1].Prefix,        Is.EqualTo(28));
            Assert.That(items[1].Negated,       Is.True, "the '!' is the whole point of the second item");

            Assert.That(record.ToZoneFileString().Split("APL")[1].Trim(),
                        Is.EqualTo("1:192.168.32.0/21 !1:192.168.38.0/28"),
                        "and it must come back out the way it went in");

        });

    }

    [Test]
    [Property("RFC", "3123 §5")]
    public void An_Apl_Carries_Both_Address_Families()
    {

        // The RFC's second example, which puts IPv4 and IPv6 in one list.
        var record = Read("probe.example. 3600 IN APL 1:224.0.0.0/4 2:FF00:0:0:0:0:0:0:0/8") as APL;

        Assert.That(record, Is.Not.Null);

        var items = record!.Items.ToArray();

        Assert.Multiple(() => {

            Assert.That(items, Has.Length.EqualTo(2));
            Assert.That(items[0].AddressFamily, Is.EqualTo(1));
            Assert.That(items[1].AddressFamily, Is.EqualTo(2));

            // RFC 5952 §4 is what a zone file wants back: lowercase, no leading
            // zeros, the zero run compressed. IPv6Address.ToString() would have
            // written eight padded groups here, and "[::]" for the all-zero
            // address - authority syntax, not zone-file syntax.
            var written = record.ToZoneFileString();

            Assert.That(written.Split("APL")[1].Trim(),
                        Is.EqualTo("1:224.0.0.0/4 2:ff00::/8"));

            // Writing it is half the claim. BIND loads this zone and dumps it
            // back in exactly this form, so the reader has to accept its own
            // output too - otherwise the suite would be asserting a string
            // rather than a round trip.
            Assert.That(((Read(written) as APL)!).Items.Select(i => i.ToString()),
                        Is.EqualTo(new[] { "1:224.0.0.0/4", "2:ff00::/8" }));

        });

    }

    [Test]
    [Property("RFC", "3123 §4")]
    public void Trailing_Zero_Octets_Are_Left_Out_Of_The_Wire_Form()
    {

        // "Trailing zero octets do not bear any information (e.g., there is no
        // semantic difference between 10.0.0.0/16 and 10/16)" and "the sender
        // MUST NOT include trailing zero octets in the AFDPART regardless of
        // the value of PREFIX."
        //
        // This is the assertion that cannot be made in presentation form: both
        // encodings print the same text, and only the octets tell them apart.
        var record = Read("probe.example. 3600 IN APL 1:10.0.0.0/16");

        Assert.That(Hex(RDataOf(record)),
                    Is.EqualTo("0001" + "10" + "01" + "0a"),
                    "family 1, prefix 16, one octet of AFDPART, and that octet is 10 - " +
                    "not four octets ending in three zeros");

    }

    [Test]
    [Property("RFC", "3123 §4")]
    public void The_Negation_Flag_Is_The_High_Bit_Of_The_Length_Octet()
    {

        var plain   = Read("probe.example. 3600 IN APL  1:192.168.0.0/16");
        var negated = Read("probe.example. 3600 IN APL !1:192.168.0.0/16");

        Assert.Multiple(() => {

            // The fourth octet carries N in its top bit and AFDLENGTH in the
            // remaining seven: 0x02 against 0x82 for the same two-octet AFDPART.
            Assert.That(Hex(RDataOf(plain)),   Is.EqualTo("0001" + "10" + "02" + "c0a8"));
            Assert.That(Hex(RDataOf(negated)), Is.EqualTo("0001" + "10" + "82" + "c0a8"));

        });

    }

    [Test]
    [Property("RFC", "3123 §4")]
    public void An_Empty_Prefix_List_Is_A_Legal_Apl()
    {

        // RFC 3123 §4 puts no lower bound on the number of items. An APL with
        // none denies everything, which is a meaningful thing to publish - and
        // an empty RDATA is exactly where a parser loop tends to fall over.
        var record = Read("probe.example. 3600 IN APL");

        Assert.Multiple(() => {
            Assert.That((record as APL)?.Items.Count(), Is.EqualTo(0));
            Assert.That(RDataOf(record),                Is.Empty);
        });

    }

    [Test]
    [Property("RFC", "3123 §5")]
    [Property("RFC", "3597 §5")]
    public void An_Address_Family_With_No_Text_Form_Falls_Back_To_The_Generic_Form()
    {

        // RFC 3123 §5 names two address families and gives no syntax for any
        // other. Rather than invent one - or throw, and leave the record
        // unwritable - the whole record is written in the RFC 3597 §5 generic
        // form, which is valid for any type and reads back through the same
        // wire constructor.
        var original = new APL(
                           Name,
                           DNSQueryClasses.IN,
                           Ttl,
                           [ new APLItem(3, 8, false, [ 0xAB, 0xCD ]) ]
                       );

        var text = original.ToZoneFileString();

        Assert.That(text, Does.Contain(@"\# 6 0003080"), "the generic form, not invented syntax");

        var readBack = Read(text) as APL;

        Assert.That(readBack, Is.Not.Null);

        Assert.Multiple(() => {

            var item = readBack!.Items.Single();

            Assert.That(item.AddressFamily, Is.EqualTo(3));
            Assert.That(item.Prefix,        Is.EqualTo(8));
            Assert.That(item.AFDPart,       Is.EqualTo(new Byte[] { 0xAB, 0xCD }));

            Assert.That(Hex(RDataOf(readBack)), Is.EqualTo(Hex(RDataOf(original))),
                        "and the round trip is lossless");

        });

    }

    [Test]
    [Property("RFC", "3123 §4")]
    public void The_Negation_Flag_Is_Read_Back_Off_The_Wire()
    {

        // Two mutations survived without this test, and both lived in the wire
        // reader: `negated = false`, and masking AFDLENGTH with 0xFF so that the
        // flag is swallowed into the length. Every other test here builds its
        // items from presentation text, and the one test that does reach the
        // wire constructor carries an item that is not negated and whose length
        // octet therefore has its top bit clear - the exact shape in which both
        // mutations are invisible.
        //
        // The RFC 3597 §5 generic form is the way in: it hands these six octets
        // straight to the wire constructor.
        //
        //   0001   family 1, IPv4
        //   10     prefix 16
        //   82     N set, AFDLENGTH 2
        //   c0a8   192.168
        var record = Read(@"probe.example. 3600 IN APL \# 6 00011082c0a8") as APL;

        Assert.That(record, Is.Not.Null);

        var item = record!.Items.Single();

        Assert.Multiple(() => {

            Assert.That(item.Negated,       Is.True, "the top bit of the fourth octet is N");
            Assert.That(item.AFDPart,       Is.EqualTo(new Byte[] { 0xC0, 0xA8 }),
                        "and the remaining seven bits are the length, so two octets follow");
            Assert.That(item.AddressFamily, Is.EqualTo(1));
            Assert.That(item.Prefix,        Is.EqualTo(16));

            Assert.That(record.ToZoneFileString().Split("APL")[1].Trim(),
                        Is.EqualTo("!1:192.168.0.0/16"));

        });

    }

    #endregion

    #region DHCID — presentation format (RFC 4701 §3.5)

    [Test]
    [Property("RFC", "4701 §3.5")]
    [TestCase("AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=", 2, "the DHCPv6 DUID example")]
    [TestCase("AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdWL3b/NaiUDlW2No=", 1, "the DHCPv4 client-id example")]
    [TestCase("AAABxLmlskllE0MVjd57zHcWmEH3pCQ6VytcKD//7es/deY=", 0, "the link-layer address example")]
    public void The_Dhcid_Examples_From_The_Rfc_Read_And_Write_Back(String  Base64,
                                                                    Int32   IdentifierType,
                                                                    String  Which)
    {

        var record = Read($"probe.example. 3600 IN DHCID {Base64}") as DHCID;

        Assert.That(record, Is.Not.Null, $"{Which} must produce a DHCID record");

        Assert.Multiple(() => {

            // RFC 4701 §3.1: two octets of identifier type, one of digest type,
            // then the digest. §3.4 gives digest type 1 as SHA-256, hence 32.
            Assert.That(record!.IdentifierType, Is.EqualTo((UInt16) IdentifierType));
            Assert.That(record. DigestType,     Is.EqualTo(1), "digest type 1 is SHA-256");
            Assert.That(record. Digest,         Has.Length.EqualTo(32));

            // §3.5: the RDATA is "a single block in base-64 encoding" - the
            // whole block, type codes included, not just the digest.
            Assert.That(record.ToZoneFileString().Split("DHCID")[1].Trim(), Is.EqualTo(Base64));

            Assert.That(RDataOf(record), Has.Length.EqualTo(35), "2 + 1 + 32");

        });

    }

    [Test]
    [Property("RFC", "4701 §3.5")]
    public void A_Dhcid_Survives_The_Wire()
    {

        var original = new DHCID(
                           Name,
                           DNSQueryClasses.IN,
                           Ttl,
                           2,
                           1,
                           Enumerable.Range(0, 32).Select(i => (Byte) i).ToArray()
                       );

        var readBack = Read(original.ToZoneFileString()) as DHCID;

        Assert.That(readBack, Is.Not.Null);

        Assert.Multiple(() => {
            Assert.That(readBack!.Data,           Is.EqualTo(original.Data));
            Assert.That(readBack. IdentifierType, Is.EqualTo(2));
            Assert.That(readBack. DigestType,     Is.EqualTo(1));
            Assert.That(Hex(RDataOf(readBack)),   Is.EqualTo(Hex(RDataOf(original))));
        });

    }

    #endregion

}

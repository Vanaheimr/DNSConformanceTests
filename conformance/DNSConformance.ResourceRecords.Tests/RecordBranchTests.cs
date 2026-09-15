using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// Conditions whose two sides were never both taken — RFC 9460 §2.1, RFC 4255
/// §3.1.3, RFC 4025 §2.5, RFC 1876 §3 and RFC 1035 §2.3.3.
///
/// Fifth entry from the mutation sweep (<see href="../../MUTATION.md"/>). A
/// branch gap is the quietest of the three kinds: not a rejection that never
/// fires and not a limit that is never touched, but an `&amp;&amp;` that could be an
/// `||`, or a flag that could start out the other way round, because every test
/// so far happened to take the same side of it.
///
/// Each region below is one rule from one RFC, and the tests are arranged so
/// that both sides of every condition are exercised — which is what a branch
/// needs and a happy-path test cannot give it.
/// </summary>
[TestFixture]
[Property("RFC", "9460 §2.1, 4255 §3.1.3, 4025 §2.5, 1876 §3, 1035 §2.3.3")]
public class RecordBranchTests
{

    #region Data

    private static readonly DomainName Name = DomainName.Parse("probe.example.");

    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(3600);

    private static IDNSResourceRecord Read(String Line)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");
        return record!;
    }

    private static Boolean Reads(String Line)
        => ADNSResourceRecord.TryParseZoneFileString(Line, out _, out _);

    private static readonly String Sha1Hex   = new('a', 40);   // 20 octets
    private static readonly String Sha256Hex = new('b', 64);   // 32 octets

    #endregion


    #region A quoted SvcParam value keeps its spaces (RFC 9460 §2.1)

    [Test]
    [Property("RFC", "9460 §2.1")]
    public void A_Space_Inside_A_Quoted_Value_Does_Not_End_The_Parameter()
    {

        // RFC 9460 §2.1 writes SvcParams as "key=value" separated by whitespace,
        // with the value optionally quoted — and a quoted value may contain the
        // whitespace that otherwise separates them. Splitting on every space
        // would cut `alpn="h2 h3"` in half and leave `h3"` as a parameter of its
        // own, which is the sort of thing that parses and then means nothing.
        var withSpace = SVCB.TryParseFromJSON(Name, Ttl, "1 . alpn=\"h2 h3\" port=8080");
        var plain     = SVCB.TryParseFromJSON(Name, Ttl, "1 . alpn=h2 port=8080");

        Assert.Multiple(() => {

            Assert.That(withSpace?.SVCParameters.Count(), Is.EqualTo(2),
                        "the space inside the quotes belongs to the value, not to the separator");

            Assert.That(plain?.SVCParameters.Count(), Is.EqualTo(2),
                        "and an unquoted value still separates on the space after it");

        });

    }

    [Test]
    [Property("RFC", "9460 §2.1")]
    public void Runs_Of_Spaces_Between_Parameters_Are_One_Separator()
    {

        // Two spaces are not an empty parameter between them. The splitter has
        // to notice that it is already at the start of nothing and skip.
        var record = SVCB.TryParseFromJSON(Name, Ttl, "1 .   alpn=h2    port=8080  ");

        Assert.That(record?.SVCParameters.Count(), Is.EqualTo(2));

    }

    [Test]
    [Property("RFC", "9460 §2.1")]
    public void Https_Splits_Its_Parameters_The_Same_Way()
    {

        // HTTPS is SVCB with a different type number and its own copy of the
        // splitter, so the rule has to hold twice. A test for one of them says
        // nothing about the other — which is how findings 31, 32 and 34 happened.
        var withSpace = HTTPS.TryParseFromJSON(Name, Ttl, "1 . alpn=\"h2 h3\" port=8080");

        Assert.That(withSpace?.SVCParameters.Count(), Is.EqualTo(2));

    }

    #endregion

    #region An SSHFP fingerprint is as long as its type says (RFC 4255 §3.1.3)

    [Test]
    [Property("RFC", "4255 §3.1.3")]
    [Property("RFC", "6594 §3")]
    public void Each_Fingerprint_Type_Has_Exactly_One_Length()
    {

        // RFC 4255 §3.1.3 gives SHA-1 twenty octets; RFC 6594 §3 adds SHA-256 at
        // thirty-two. The check is on octets and not on hex characters, and it
        // has to pass for both types — a condition joined the wrong way refuses
        // the type it was not written for while still looking like a length
        // check.
        var sha1   = Read($"probe.example. 3600 IN SSHFP 1 1 {Sha1Hex}")   as SSHFP;
        var sha256 = Read($"probe.example. 3600 IN SSHFP 2 2 {Sha256Hex}") as SSHFP;

        Assert.Multiple(() => {
            Assert.That(sha1!.  Fingerprint, Has.Length.EqualTo(20), "RFC 4255 §3.1.3");
            Assert.That(sha256!.Fingerprint, Has.Length.EqualTo(32), "RFC 6594 §3");
        });

    }

    [Test]
    [Property("RFC", "4255 §3.1.3")]
    public void A_Fingerprint_Of_The_Wrong_Length_Is_Not_A_Fingerprint()
    {

        // The generic form hands the wire reader two octets where twenty are
        // required. Accepting it published a fingerprint of AABB followed by
        // eighteen zeros — the reader completed what the wire had cut off, and
        // RFC 4255 §3.1.3's length check then passed because of the padding
        // rather than because of the data (finding 54).
        Assert.Multiple(() => {

            Assert.That(Reads(@"probe.example. 3600 IN SSHFP \# 4 0101aabb"), Is.False,
                        "two octets are not a SHA-1 fingerprint, and eighteen zeros do not make them one");

            Assert.That(Reads(@"probe.example. 3600 IN SSHFP \# 4 0202aabb"), Is.False,
                        "nor a SHA-256 one");

        });

    }

    #endregion

    #region An IPSECKEY gateway is what its type says (RFC 4025 §2.5)

    [Test]
    [Property("RFC", "4025 §2.5")]
    public void A_Gateway_Is_Read_As_The_Type_Before_It_Says()
    {

        // RFC 4025 §2.5: the gateway field's meaning is decided by the gateway
        // type octet, and nothing else. Reading it by length alone would make a
        // four-octet name into an IPv4 address.
        var none = Read("probe.example. 3600 IN IPSECKEY 10 0 2 . AQNRU3mG7TVTO2BkR47u")      as IPSECKEY;
        var ipv4 = Read("probe.example. 3600 IN IPSECKEY 10 1 2 192.0.2.38 AQNRU3mG7TVTO2Bk") as IPSECKEY;
        var ipv6 = Read("probe.example. 3600 IN IPSECKEY 10 2 2 2001:db8::1 AQNRU3mG7TVTO2Bk") as IPSECKEY;
        var name = Read("probe.example. 3600 IN IPSECKEY 10 3 2 gw.example. AQNRU3mG7TVTO2Bk") as IPSECKEY;

        Assert.Multiple(() => {

            Assert.That(none!.GatewayIPv4, Is.Null);
            Assert.That(none!.GatewayIPv6, Is.Null);
            Assert.That(none!.GatewayName, Is.Null, "gateway type 0 is no gateway at all");

            Assert.That(ipv4!.GatewayIPv4, Is.Not.Null);
            Assert.That(ipv4!.GatewayIPv6, Is.Null);
            Assert.That(ipv4!.GatewayName, Is.Null, "four octets are an address here, not a name");

            Assert.That(ipv6!.GatewayIPv6, Is.Not.Null);
            Assert.That(ipv6!.GatewayIPv4, Is.Null);
            Assert.That(ipv6!.GatewayName, Is.Null);

            Assert.That(name!.GatewayName, Is.Not.Null);
            Assert.That(name!.GatewayIPv4, Is.Null);
            Assert.That(name!.GatewayIPv6, Is.Null);

        });

    }

    [Test]
    [Property("RFC", "4025 §2.5")]
    public void A_Name_Gateway_Of_Four_Octets_Is_Still_A_Name()
    {

        // The case that separates "the type says so" from "the length says so":
        // `ab.` is one label of two characters and a root, which is four octets
        // on the wire — exactly the width of an IPv4 address. Only the gateway
        // type tells the two apart, and a condition joined with `||` instead of
        // `&&` would hand back 0x02.0x61.0x62.0x00 as an address.
        var four = Read("probe.example. 3600 IN IPSECKEY 10 3 2 ab. AQNRU3mG7TVTO2Bk") as IPSECKEY;

        // And sixteen octets of name, which is the width of an IPv6 address.
        var sixteen = Read("probe.example. 3600 IN IPSECKEY 10 3 2 abcdefghijklmn. AQNRU3mG7TVTO2Bk") as IPSECKEY;

        Assert.Multiple(() => {

            Assert.That(four!.Gateway,     Has.Length.EqualTo(4), "four octets, and a name all the same");
            Assert.That(four!.GatewayIPv4, Is.Null,               "the type says name, so it is a name");
            Assert.That(four!.GatewayName, Is.Not.Null);

            Assert.That(sixteen!.Gateway,     Has.Length.EqualTo(16));
            Assert.That(sixteen!.GatewayIPv6, Is.Null,            "sixteen octets, and still a name");
            Assert.That(sixteen!.GatewayName, Is.Not.Null);

        });

    }

    [Test]
    [Property("RFC", "4025 §2.5")]
    public void An_Address_Gateway_Whose_Octets_Read_As_A_Name_Is_Still_An_Address()
    {

        // The mirror of the case above, and the sharper one. 2.97.98.0 is the
        // address whose four octets are 02 61 62 00 — a label of two characters,
        // "ab", and a root. Handed to a name reader they parse perfectly, so the
        // only thing standing between an address and a name here is the gateway
        // type octet doing its job.
        var record = Read("probe.example. 3600 IN IPSECKEY 10 1 2 2.97.98.0 AQNRU3mG7TVTO2Bk") as IPSECKEY;

        Assert.Multiple(() => {
            Assert.That(record!.Gateway,     Is.EqualTo(new Byte[] { 0x02, 0x61, 0x62, 0x00 }));
            Assert.That(record!.GatewayIPv4, Is.Not.Null, "the type says address");
            Assert.That(record!.GatewayName, Is.Null,     "so it is an address, however well those octets spell a name");
        });

    }

    #endregion

    #region LOC's hemispheres, in either case (RFC 1876 §3)

    [Test]
    [Property("RFC", "1876 §3")]
    // §3's presentation format ends each coordinate with a hemisphere letter,
    // and a zone file may be written in either case. The southern and western
    // letters are the ones that carry a sign, so reading them as northern and
    // eastern puts the location on the wrong side of the equator without
    // failing anything.
    [TestCase("52 22 23.000 N 4 53 32.000 E",  1,  1, TestName = "north and east, upper case")]
    [TestCase("52 22 23.000 n 4 53 32.000 e",  1,  1, TestName = "north and east, lower case")]
    [TestCase("52 22 23.000 S 4 53 32.000 W", -1, -1, TestName = "south and west, upper case")]
    [TestCase("52 22 23.000 s 4 53 32.000 w", -1, -1, TestName = "south and west, lower case")]
    public void A_Hemisphere_Letter_Decides_The_Sign_In_Either_Case(String  Data,
                                                                    Int32   LatitudeSign,
                                                                    Int32   LongitudeSign)
    {

        var record = LOC.TryParseFromJSON(Name, Ttl, Data);

        Assert.That(record, Is.Not.Null, $"'{Data}' is RFC 1876 §3 syntax");

        Assert.Multiple(() => {

            Assert.That(Math.Sign(record!.LatitudeInMilliArcSeconds),  Is.EqualTo(LatitudeSign),
                        "the latitude is on the side the letter says");

            Assert.That(Math.Sign(record!.LongitudeInMilliArcSeconds), Is.EqualTo(LongitudeSign),
                        "and so is the longitude");

        });

    }

    [Test]
    [Property("RFC", "1876 §3")]
    public void The_Hemisphere_Letter_Is_Consumed_And_Not_Read_Twice()
    {

        // The letter both sets the sign and advances the cursor, and those are
        // two separate conditions over the same four spellings. Leave one of
        // them out and the field after the letter is read as the letter again,
        // so the altitude lands in the longitude.
        var record = LOC.TryParseFromJSON(Name, Ttl, "52 22 23.000 S 4 53 32.000 W -2.00m");

        Assert.Multiple(() => {
            Assert.That(Math.Sign(record!.LatitudeInMilliArcSeconds),  Is.EqualTo(-1));
            Assert.That(Math.Sign(record!.LongitudeInMilliArcSeconds), Is.EqualTo(-1));
            Assert.That(record!.AltitudeInCentimetres,                 Is.EqualTo(-200),
                        "and the altitude after the letter is the altitude");
        });

    }

    #endregion

    #region Mnemonics are read in either case (RFC 1035 §2.3.3)

    [Test]
    [Property("RFC", "1035 §2.3.3")]
    // "no significance should be attached to the case" — and a zone file is
    // written by hand, so both cases turn up. The reader tries class, TTL and
    // type against the same token, and a case-sensitive attempt at any of them
    // is a token it will never reach.
    [TestCase("example.com. 3600 IN A 192.0.2.1",   TestName = "upper case, as the RFCs print them")]
    [TestCase("example.com. 3600 in a 192.0.2.1",   TestName = "lower case, as people type them")]
    [TestCase("example.com. 3600 In Aaaa ::1",      TestName = "mixed case in the type")]
    [TestCase("example.com. 3600 ch txt \"hello\"", TestName = "a class that is not IN, in lower case")]
    public void A_Class_And_A_Type_Are_Read_In_Any_Case(String Line)
    {
        Assert.That(Reads(Line), Is.True, $"'{Line}' is a record however it is spelled");
    }

    [Test]
    [Property("RFC", "1035 §2.3.3")]
    [Property("RFC", "4034 §3.1")]
    public void An_Rrsig_Reads_The_Type_It_Covers_In_Any_Case()
    {

        // RRSIG carries a type mnemonic inside its own RDATA, parsed by a second
        // reader that has to fold case the same way the header's does.
        var upper = Read("a.example.com. 3600 IN RRSIG A 8 3 3600 20261014083329 20260914083329 1234 example.com. AQID") as RRSIG;
        var lower = Read("a.example.com. 3600 IN rrsig a 8 3 3600 20261014083329 20260914083329 1234 example.com. AQID") as RRSIG;

        Assert.Multiple(() => {
            Assert.That(upper!.TypeCovered, Is.EqualTo(DNSResourceRecordTypes.A));
            Assert.That(lower!.TypeCovered, Is.EqualTo(DNSResourceRecordTypes.A),
                        "the covered type is a mnemonic like any other");
        });

    }

    #endregion

}

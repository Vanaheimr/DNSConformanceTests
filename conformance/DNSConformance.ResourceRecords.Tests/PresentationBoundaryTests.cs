using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// Where a presentation format stops: the last field a line may leave out, the
/// smallest value a field may hold, and the first octet a writer has to escape.
///
/// Sixth entry from the mutation sweep (<see href="../../MUTATION.md"/>) and the
/// second half of the boundaries. RFC 1876 §3, RFC 9460 §2.1 and RFC 5155 §3.3
/// all describe a text form whose tail is optional, and an optional tail is a
/// comparison against the number of tokens that were actually there. Every one
/// of those comparisons had been exercised from the middle and never from the
/// end: the suite always wrote the full form.
///
/// A comparison at the end of a list is worse than most to get wrong by one,
/// because being wrong by one reads one token past the end — and in a parser
/// wrapped in a catch, an index out of range comes back as "this is not a LOC
/// record" rather than as a crash. A record that silently stops existing is the
/// kind of defect that survives a long time.
/// </summary>
[TestFixture]
[Property("RFC", "1876 §3, 9460 §2.1, 5155 §3.3, 7871 §6, 1035 §5.1")]
public class PresentationBoundaryTests
{

    #region Data

    private static readonly DomainName Name  = DomainName.Parse("probe.example.");
    private static readonly TimeSpan   Ttl   = TimeSpan.FromSeconds(3600);

    private const UInt32 Equator = 1u << 31;

    private static IDNSResourceRecord Read(String Line)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");
        return record!;
    }

    private static String Rdata(IDNSResourceRecord Record)
        => String.Join(' ', Record.ToZoneFileString().Split(' ', StringSplitOptions.RemoveEmptyEntries)[4..]);

    #endregion


    #region A LOC that stops early (RFC 1876 §3)

    // RFC 1876 §3 writes LOC as
    //
    //   d1 [m1 [s1]] {"N"|"S"} d2 [m2 [s2]] {"E"|"W"} alt["m"] [siz["m"] [hp["m"] [vp["m"]]]]
    //
    // — every bracket an opportunity for the line to stop, and every stop a
    // comparison against how many tokens arrived. The four lines below stop at
    // four different brackets, and each of them is the last token a reader may
    // look at.

    [Test]
    [Property("RFC", "1876 §3")]
    public void A_Loc_May_Stop_After_Its_Latitude()
    {

        var loc = Read("probe.example. 3600 IN LOC 52 22 23.000 N") as LOC;

        Assert.That(loc, Is.Not.Null, "a latitude with nothing after it is short, not unreadable");

        Assert.Multiple(() => {
            Assert.That(loc!.Latitude,  Is.EqualTo(Equator + 52 * 3_600_000u + 22 * 60_000u + 23_000u));
            Assert.That(loc!.Longitude, Is.EqualTo(Equator), "no longitude was given, so the prime meridian stands");
            Assert.That(loc!.Size,      Is.EqualTo(LOC.DefaultSize));
        });

    }

    [Test]
    [Property("RFC", "1876 §3")]
    public void A_Loc_May_Stop_After_A_Longitude_With_No_Minutes()
    {

        // Three stops in one line: the longitude's minutes, its seconds and its
        // hemisphere are all absent, and the token after each of them is the end.
        var loc = Read("probe.example. 3600 IN LOC 52 22 N 4") as LOC;

        Assert.That(loc, Is.Not.Null);

        Assert.Multiple(() => {
            Assert.That(loc!.Latitude,  Is.EqualTo(Equator + 52 * 3_600_000u + 22 * 60_000u));
            Assert.That(loc!.Longitude, Is.EqualTo(Equator + 4 * 3_600_000u));
        });

    }

    [Test]
    [Property("RFC", "1876 §3")]
    public void A_Loc_May_Stop_Before_Its_Altitude()
    {

        var loc = Read("probe.example. 3600 IN LOC 52 22 23.000 N 4 53 32.000 E") as LOC;

        Assert.That(loc, Is.Not.Null);

        Assert.Multiple(() => {
            Assert.That(loc!.Longitude, Is.EqualTo(Equator + 4 * 3_600_000u + 53 * 60_000u + 32_000u));
            Assert.That(loc!.Altitude,  Is.EqualTo(10_000_000u), "RFC 1876 §2 puts sea level 100km above the bottom of the range");
        });

    }

    #endregion

    #region The smallest size a LOC can state (RFC 1876 §2)

    [Test]
    [Property("RFC", "1876 §2")]
    public void A_Loc_Size_Of_Zero_Is_A_Size_And_Not_A_Missing_Field()
    {

        // RFC 1876 §2 encodes size as base and power of ten, "each ranging from
        // zero to nine" — so zero is expressible, and §3 gives it a meaning: a
        // point rather than a sphere. A reader that treats a stated zero as an
        // absent field substitutes the one-metre default and moves the entity.
        var loc = Read("probe.example. 3600 IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m") as LOC;

        Assert.That(loc!.Size, Is.EqualTo((Byte) 0x00),
                    "a size of zero centimetres is 0x00, not the 1m default");

    }

    [Test]
    [Property("RFC", "1876 §2")]
    public void Nine_Centimetres_Keeps_Its_Digit()
    {

        // "a pair of four-bit unsigned integers, each ranging from zero to nine,
        // with the most significant four bits representing the base and the
        // second number representing the power of ten" — nine centimetres is
        // base nine and power zero, and nine is the largest base there is. A
        // reader that carries the reduction one step further writes 1e1 for it,
        // which is ten centimetres.
        var loc = Read("probe.example. 3600 IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.09m") as LOC;

        Assert.That(loc!.Size, Is.EqualTo((Byte) 0x90));

    }

    [Test]
    [Property("RFC", "1876 §2")]
    [Property("RFC", "1876 §3")]
    [TestCase("abc",     TestName = "a size that is not a number")]
    [TestCase("-1.00m",  TestName = "a size below zero")]
    public void A_Size_That_Says_Nothing_Leaves_The_Default_Standing(String Size)
    {

        // §3 makes size optional and §2 encodes it as two four-bit unsigned
        // integers, so a token that is not a number and a token below zero are
        // both outside what the field can hold. Neither is a size, and the RFC's
        // default is what stands in either case — reading the first as zero
        // shrinks the entity to a point, and the second wraps into 0x99, which
        // is ninety thousand kilometres.
        var loc = Read($"probe.example. 3600 IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m {Size}") as LOC;

        Assert.That(loc!.Size, Is.EqualTo(LOC.DefaultSize));

    }

    [Test]
    [Property("RFC", "1876 §3")]
    public void The_Longitude_Hemisphere_Is_A_Token_Of_Its_Own()
    {

        // The letter both sets the sign and advances past itself, and the field
        // behind it is the altitude. A reader that does not step over "E" reads
        // the letter as the altitude and the altitude as the size — every field
        // after the hemisphere shifted by one, with nothing failing.
        var loc = Read("probe.example. 3600 IN LOC 52 22 23.000 N 4 53 32.000 E 100.00m 2.00m") as LOC;

        Assert.Multiple(() => {
            Assert.That(loc!.Altitude, Is.EqualTo(10_010_000u), "100 metres above the reference");
            Assert.That(loc!.Size,     Is.EqualTo(LOC.EncodeScaled(200)), "two metres, in centimetres");
        });

    }

    [Test]
    [Property("RFC", "1876 §3")]
    public void A_Token_That_Is_Not_A_Hemisphere_Stays_Where_It_Is()
    {

        // The other side of the same four comparisons. §3 names exactly four
        // spellings for the longitude hemisphere, so a token that is none of them
        // is not the hemisphere and is still the next field's. A reader that
        // steps over it anyway loses the altitude, and everything behind it
        // shifts up by one — with nothing failing, because every field after
        // the hemisphere is optional.
        var loc = Read("probe.example. 3600 IN LOC 52 22 23.000 N 4 53 32.000 100.00m") as LOC;

        Assert.That(loc!.Altitude, Is.EqualTo(10_010_000u),
                    "100.00m is the altitude, not a hemisphere the reader consumed");

    }

    #endregion


    #region A SvcParam with no value (RFC 9460 §2.1, §7.1)

    [Test]
    [Property("RFC", "9460 §2.1")]
    [Property("RFC", "9460 §7.1")]
    public void A_SvcParam_With_An_Empty_Value_Is_Written_As_The_Key_Alone()
    {

        // RFC 9460 §2.1: SvcParam = SvcParamKey ["=" SvcParamValue] — the "="
        // and everything after it are one optional group. §7.1 says the value of
        // "no-default-alpn" MUST be empty, so it is exactly the key on its own.
        var svcb   = new SVCB (Name, DNSQueryClasses.IN, Ttl, 1, DomainName.Parse("svc.example."), [new SVCParameter(2, [])]);
        var https  = new HTTPS(Name, DNSQueryClasses.IN, Ttl, 1, DomainName.Parse("svc.example."), [new SVCParameter(2, [])]);

        Assert.Multiple(() => {

            Assert.That(Rdata(svcb),  Does.Contain("no-default-alpn").
                                      And.Not.Contain("no-default-alpn="),
                        "a key that takes no value is not written with an empty one");

            Assert.That(Rdata(https), Does.Contain("no-default-alpn").
                                      And.Not.Contain("no-default-alpn="));

        });

    }

    [Test]
    [Property("RFC", "9460 §2.1")]
    [Property("RFC", "1035 §5.1")]
    public void A_SvcParam_Value_Escapes_Exactly_What_Is_Not_Printable()
    {

        // RFC 9460 §2.1 writes a SvcParamValue as an RFC 1035 §5.1
        // character-string, where an octet outside the printable range is
        // written \DDD. Printable is 0x20 through 0x7E inclusive — both ends
        // included, which is what the two comparisons here decide. A writer
        // that excludes either end escapes an octet that did not need it; one
        // that includes 0x1F or 0x7F emits a control character into a zone file.
        var value  = new Byte[] { 0x1F, 0x20, 0x7E, 0x7F };
        var svcb   = new SVCB (Name, DNSQueryClasses.IN, Ttl, 1, DomainName.Parse("svc.example."), [new SVCParameter(65280, value)]);
        var https  = new HTTPS(Name, DNSQueryClasses.IN, Ttl, 1, DomainName.Parse("svc.example."), [new SVCParameter(65280, value)]);

        Assert.Multiple(() => {
            Assert.That(Rdata(svcb),  Does.Contain("\\031 ~\\127"),
                        "0x20 and 0x7E are printable and stay themselves; 0x1F and 0x7F do not");
            Assert.That(Rdata(https), Does.Contain("\\031 ~\\127"));
        });

    }

    [Test]
    [Property("RFC", "9460 §2.1")]
    [Property("RFC", "9460 §2.4.2")]
    [TestCase("SVCB",  "0 alias.example.",   TestName = "an SVCB in AliasMode")]
    [TestCase("SVCB",  "1 svc.example.",     TestName = "an SVCB in ServiceMode")]
    [TestCase("HTTPS", "0 alias.example.",   TestName = "an HTTPS in AliasMode")]
    [TestCase("HTTPS", "1 svc.example.",     TestName = "an HTTPS in ServiceMode")]
    public void A_Record_With_No_SvcParams_At_All_Is_Complete(String Type, String Rdata)
    {

        // §2.1 makes SvcParams a *( SP SvcParam ) — none of them is a legal
        // count, and §2.4.2 says an AliasMode record SHOULD have none. The line
        // then ends after the target name, which is one token before the reader
        // would like to look.
        var record = Read($"probe.example. 3600 IN {Type} {Rdata}");

        Assert.That(record, Is.Not.Null);
        Assert.That(record.ToZoneFileString(), Does.Contain(Rdata.Split(' ')[1]));

    }

    [Test]
    [Property("RFC", "9460 §2.2")]
    [Property("RFC", "9460 §7.1")]
    public void A_Zero_Length_SvcParam_Is_The_Last_Four_Octets_Of_The_Rdata()
    {

        // On the wire a SvcParam is a two-octet key, a two-octet length and then
        // that many octets (§2.2). A record whose only parameter takes no value
        // therefore ends exactly four octets after the target name — the
        // smallest amount of RDATA a parameter loop may still enter.
        //
        //   0001            SvcPriority 1
        //   01 78 00        TargetName "x."
        //   0002 0000       key 2 (no-default-alpn), length 0
        var svcb = Read(@"probe.example. 3600 IN SVCB \# 9 000101780000020000") as SVCB;

        Assert.That(svcb, Is.Not.Null, "four remaining octets are one whole SvcParam, not a trailing scrap");

        Assert.Multiple(() => {
            Assert.That(svcb!.Priority,                  Is.EqualTo((UInt16) 1));
            Assert.That(svcb!.SVCParameters.Count(),     Is.EqualTo(1));
            Assert.That(svcb!.SVCParameters.First().Key, Is.EqualTo((UInt16) 2));
            Assert.That(svcb!.SVCParameters.First().Value, Is.Empty);
        });

    }

    [Test]
    [Property("RFC", "9460 §2.4.2")]
    [Property("RFC", "2915 §2")]
    [TestCase("SVCB",  "0 .",              TestName = "an SVCB whose target is the root")]
    [TestCase("HTTPS", "0 .",              TestName = "an HTTPS whose target is the root")]
    public void A_Target_Of_The_Root_Is_A_Target(String Type, String Rdata)
    {

        // RFC 9460 §2.4.2: in AliasMode "a TargetName of '.' indicates that the
        // service is not available or does not exist". It is the one target that
        // means something by being empty, and a reader that treats the empty
        // remainder of "." as a missing field loses the statement entirely.
        var record = Read($"probe.example. 3600 IN {Type} {Rdata}");

        Assert.That(record.ToZoneFileString(), Does.Contain(" 0 ."),
                    "the root is written as the root");

    }

    [Test]
    [Property("RFC", "2915 §2")]
    public void A_Naptr_Replacement_Of_The_Root_Is_A_Replacement()
    {

        // RFC 2915 §2 gives NAPTR a REPLACEMENT that "will be '.' to indicate
        // that the value of the REGEXP field should be used instead" — so the
        // root is not an absent field here either, it is the terminal rule.
        var terminal = Read("probe.example. 3600 IN NAPTR 100 10 \"u\" \"E2U+sip\" \"!^.*$!sip:x@example.!\" .") as NAPTR;

        Assert.That(terminal!.Replacement.FullName, Is.EqualTo("."));

        // And the other side of the same comparison, which is the ordinary case:
        // §2's non-terminal rule replaces the name with another name, and a
        // reader that answers "." for everything that is not empty throws the
        // replacement away and sends every lookup to the root.
        var nonTerminal = Read("probe.example. 3600 IN NAPTR 100 10 \"s\" \"SIP+D2U\" \"\" _sip._udp.example.") as NAPTR;

        Assert.That(nonTerminal!.Replacement.FullName, Is.EqualTo("_sip._udp.example."));

    }

    #endregion


    #region A salt that is not there, and a hash that is (RFC 5155 §3.3)

    [Test]
    [Property("RFC", "5155 §3.3")]
    public void An_Absent_Nsec3_Salt_Is_A_Hyphen()
    {

        // RFC 5155 §3.3: the Salt field "is represented as '-' (without quotes)
        // when the Salt Length field has value 0". An empty hex string in its
        // place moves every field after it one token to the left.
        var nsec3      = new NSEC3     (Name, DNSQueryClasses.IN, Ttl, 1, 0, 12, [], new Byte[20], []);
        var nsec3param = new NSEC3PARAM(Name, DNSQueryClasses.IN, Ttl, 1, 0, 12, []);

        Assert.Multiple(() => {
            Assert.That(Rdata(nsec3).     Split(' ')[3], Is.EqualTo("-"));
            Assert.That(Rdata(nsec3param).Split(' ')[3], Is.EqualTo("-"));
        });

    }

    [Test]
    [Property("RFC", "5155 §3.3")]
    [Property("RFC", "4648 §7")]
    public void The_Next_Hashed_Owner_Name_Is_Base32Hex()
    {

        // §3.3: "an unpadded sequence of case-insensitive base32 digits with
        // the extended hex alphabet". Twenty octets are a hundred and sixty
        // bits, which is thirty-two digits with nothing left over. The expected
        // text is SHA-1("conformance") encoded independently; the suite never
        // asks Hermod what the answer should be.
        //
        // This one closes nothing, and says so. It was written to kill a
        // survivor — the encoder's inner loop, which the sweep reported as
        // movable by one bit — and the mutation run came back SURVIVED. It is
        // right to: whenever a five-bit group is emitted it is still the k-th
        // group of the stream, and the trailing partial group is written with
        // an expression that coincides with the loop's at exactly the offset in
        // question. The two readings produce the same string for every input
        // length. Kept anyway, because nothing else here pins base32hex against
        // an answer computed outside Hermod.
        var hash = Convert.FromHexString("5500404C3C99E02EF45882A956E67C3AC9B6615B");

        var nsec3 = new NSEC3(Name, DNSQueryClasses.IN, Ttl, 1, 0, 12, [0xAA, 0xBB], hash, []);

        Assert.That(Rdata(nsec3).Split(' ')[4],
                    Is.EqualTo("AK040J1SJ7G2TT2OGAKLDPJS7B4RCOAR").IgnoreCase,
                    "thirty-two base32hex digits, unpadded");

    }

    #endregion


    #region A line that a reader has to be able to read back (RFC 1035 §5.1)

    [Test]
    [Property("RFC", "8945 §4.2")]
    [Property("RFC", "1035 §5.1")]
    public void A_Tsig_Survives_Its_Own_Presentation_Form()
    {

        // Six fields, six tokens, and a reader that wants at least six. RFC 8945
        // §4.2 names them: algorithm, time signed, fudge, MAC, original ID and
        // error. A reader that wants one more than the writer ever emits turns
        // every one of its own lines back into nothing.
        var tsig = new TSIG(Name, DNSQueryClasses.ANY, TimeSpan.Zero,
                            DomainName.Parse("hmac-sha256."),
                            1700000000, 300,
                            [0x01, 0x02, 0x03, 0x04],
                            4711, 0, []);

        var again = Read(tsig.ToZoneFileString()) as TSIG;

        Assert.That(again, Is.Not.Null, "the reader refused a line the writer had just produced");

        Assert.Multiple(() => {
            Assert.That(again!.AlgorithmName.FullName, Is.EqualTo("hmac-sha256."));
            Assert.That(again!.TimeSigned,             Is.EqualTo(1700000000UL));
            Assert.That(again!.Fudge,                  Is.EqualTo((UInt16) 300));
            Assert.That(again!.MAC,                    Is.EqualTo(new Byte[] { 0x01, 0x02, 0x03, 0x04 }));
            Assert.That(again!.OriginalID,             Is.EqualTo((UInt16) 4711));
        });

    }

    [Test]
    [Property("RFC", "2930 §2")]
    [Property("RFC", "1035 §5.1")]
    public void A_Tkey_Survives_Its_Own_Presentation_Form()
    {

        var tkey = new TKEY(Name, DNSQueryClasses.ANY, TimeSpan.Zero,
                            DomainName.Parse("gss-tsig."),
                            1690000000, 1700000000,
                            3, 0,
                            [0x0A, 0x0B, 0x0C],
                            []);

        var again = Read(tkey.ToZoneFileString()) as TKEY;

        Assert.That(again, Is.Not.Null);

        Assert.Multiple(() => {
            Assert.That(again!.Algorithm.FullName, Is.EqualTo("gss-tsig."));
            Assert.That(again!.Inception,          Is.EqualTo(1690000000u));
            Assert.That(again!.Expiration,         Is.EqualTo(1700000000u));
            Assert.That(again!.Mode,               Is.EqualTo((UInt16) 3));
            Assert.That(again!.KeyData,            Is.EqualTo(new Byte[] { 0x0A, 0x0B, 0x0C }));
        });

    }

    #endregion


    #region A target that is not there (RFC 7553 §4.4, §4.5)

    [Test]
    [Property("RFC", "7553 §4.4")]
    [Property("RFC", "7553 §4.5")]
    public void A_Uri_Record_With_No_Target_Is_Not_A_Uri_Record()
    {

        // Two MUSTs on the same octet. RFC 7553 §4.4: "The Target MUST NOT be an
        // empty URI". §4.5: "The length of the Target field MUST be greater than
        // zero". The RDATA is a two-octet Priority and a two-octet Weight before
        // it, so an RDLENGTH of exactly four is a URI record with no URI in it —
        // the one length this type may never have.
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(
                        @"probe.example. 3600 IN URI \# 4 000a0001", out _, out var error),
                    Is.False,
                    "four octets of RDATA leave nothing for the target");

        Assert.That(error, Is.Not.Null);

        // And the other side of it: one octet more is a target, and it is kept
        // as it arrived rather than measured against anything.
        var record = Read(@"probe.example. 3600 IN URI \# 21 000a0001687474703a2f2f652e6578616d706c652f") as URI;

        Assert.Multiple(() => {
            Assert.That(record!.Priority, Is.EqualTo((UInt16) 10));
            Assert.That(record!.Weight,   Is.EqualTo((UInt16) 1));
            Assert.That(record!.Target.ToString(), Is.EqualTo("http://e.example/"));
        });

    }

    #endregion


    #region The least an option and a gateway can carry (RFC 7871 §6, RFC 4025 §2.5)

    [Test]
    [Property("RFC", "7871 §6")]
    public void A_Client_Subnet_Option_May_Carry_No_Address_At_All()
    {

        // RFC 7871 §6 gives the option FAMILY, SOURCE PREFIX-LENGTH, SCOPE
        // PREFIX-LENGTH and then "ADDRESS ... truncated to the number of bits
        // indicated by SOURCE PREFIX-LENGTH". A source prefix of zero bits
        // truncates the address to nothing, which §7.1.2 uses to say "do not
        // scope this query" — four octets, and a whole option.
        var ecs = EDNSClientSubnetOption.Parse([0x00, 0x01, 0x00, 0x00]);

        Assert.Multiple(() => {
            Assert.That(ecs.Family,             Is.EqualTo((UInt16) 1));
            Assert.That(ecs.SourcePrefixLength, Is.EqualTo((Byte) 0));
            Assert.That(ecs.ScopePrefixLength,  Is.EqualTo((Byte) 0));
        });

    }

    [Test]
    [Property("RFC", "4025 §2.5")]
    [Property("RFC", "3597 §2")]
    public void A_Gateway_Name_That_Runs_Off_The_End_Stops_At_The_End()
    {

        // RFC 4025 §2.5 makes gateway type 3 "a wire-encoded domain name", and
        // §2.4 forbids compressing it — so the only thing that ends it is the
        // root label. A record that stops before one arrives is malformed, and
        // RFC 3597 §2 still wants the reader to get past it: the walk has to end
        // at the last octet rather than one after it.
        //
        //   0a        precedence
        //   03        gateway type: a name
        //   00        algorithm: no key
        //   03 66 6f 6f   label "foo", and then nothing
        var record = Read(@"probe.example. 3600 IN IPSECKEY \# 7 0a030003666f6f") as IPSECKEY;

        Assert.That(record, Is.Not.Null);

        Assert.Multiple(() => {
            Assert.That(record!.GatewayType,   Is.EqualTo((Byte) 3));
            Assert.That(record!.Gateway.Length, Is.EqualTo(4), "four octets arrived, so four octets are the gateway");
            Assert.That(record!.PublicKey,     Is.Empty);
        });

    }

    #endregion

}

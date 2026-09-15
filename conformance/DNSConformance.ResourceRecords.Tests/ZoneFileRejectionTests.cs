using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// What the zone-file reader refuses, and what a type bit map answers when the
/// type is not in it — RFC 1035 §5.1, RFC 3597 §5, RFC 4034 §3.2 and §4.1.2.
///
/// Third entry from the mutation sweep (<see href="../../MUTATION.md"/>), and the
/// one in the base class every record type passes through. Seventeen of its
/// `return false` statements could be turned into `return true` without a test
/// noticing: a line with no type, a line with no RDATA, a TTL that overflows the
/// field, a generic-form length that is not a number, a signature time outside
/// the epoch the wire format can hold.
///
/// The type bit map is the one worth reading twice. `TypeBitMapContains` is what
/// authenticated denial of existence turns on — RFC 4035 §5.4 proves a type
/// absent precisely by its bit being clear — and it had no direct test at all.
/// Its three refusals are not errors but answers: "not in this window", "past
/// the end of this window's bitmap", and "this bitmap is truncated". Each of
/// them says a type does not exist, which is the most consequential "no" in
/// DNSSEC.
/// </summary>
[TestFixture]
[Property("RFC", "1035 §5.1, 4034 §4.1.2")]
public class ZoneFileRejectionTests
{

    #region Data

    private static Boolean Reads(String Line)
        => ADNSResourceRecord.TryParseZoneFileString(Line, out _, out _);

    private static String Refused(String Line)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.False,
                    $"the reader accepted '{Line}'");
        Assert.That(record, Is.Null, "a refused line must not produce a record");
        Assert.That(error,  Is.Not.Null.And.Not.Empty, "a refusal must say why");
        return error!;
    }

    /// <summary>
    /// One RFC 4034 §4.1.2 window: the window number, the bitmap length, and the
    /// bitmap. Bit 0 is the most significant bit of the first octet, so type
    /// <c>n</c> within a window sets <c>0x80 &gt;&gt; (n % 8)</c> in octet
    /// <c>n / 8</c>.
    /// </summary>
    private static Byte[] Window(Byte Number, params UInt16[] Types)
    {

        var highest = Types.Max(t => t % 256);
        var length  = (Byte) (highest / 8 + 1);
        var bitmap  = new Byte[length];

        foreach (var type in Types)
            bitmap[type % 256 / 8] |= (Byte) (0x80 >> (type % 8));

        return [Number, length, .. bitmap];

    }

    #endregion


    #region A line that is not a resource record (RFC 1035 §5.1)

    [Test]
    [Property("RFC", "1035 §5.1")]
    // §5.1's line is "<domain-name><rr> [<comment>]" with <rr> carrying a type
    // and its RDATA. Each of these is missing a part of that, and each is a
    // separate refusal in the reader.
    [TestCase("example.com. 3600 IN",
              TestName = "three tokens, so nothing can be both type and data")]
    [TestCase("example.com. A",
              TestName = "two tokens")]
    [TestCase("example.com. 3600 IN 7200",
              TestName = "a header with no type in it at all")]
    [TestCase("example.com. 3600 IN A",
              TestName = "a type with no RDATA behind it")]
    [TestCase("example.com. 3600 IN NOTATYPE 192.0.2.1",
              TestName = "a type token that is neither a mnemonic nor TYPEnnn")]
    public void A_Line_Missing_A_Part_Of_Section_5_1_Is_Refused(String Line)
    {
        Refused(Line);
    }

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Refusal_Names_The_Part_That_Is_Missing()
    {

        // Which refusal happened, not merely that one did. A type with nothing
        // behind it can be caught in the header, where the reader knows the RDATA
        // is missing, or later by the type's own parser being handed an empty
        // string — and only the first can say so. The message is what a zone
        // author acts on, and a test that asks only "was it refused" cannot tell
        // a helpful reader from a silent one.
        Assert.Multiple(() => {

            // "Missing RDATA" and not "Could not parse RDATA": both messages
            // contain the word, and only the first one means the header caught
            // it. Asserting the word alone reads as a test and is not one.
            Assert.That(Refused("example.com. 3600 IN A"),
                        Does.Contain("Missing RDATA"),
                        "the header knows the RDATA is missing and must say so itself");

            Assert.That(Refused("example.com. 3600 IN 7200"),
                        Does.Contain("Missing DNS resource record type"),
                        "and a header with no type in it names that instead");

            // A token that is no type at all is a header problem, and the
            // message has to name the token. Reported as bad RDATA it sends the
            // zone author to the wrong end of the line.
            Assert.That(Refused("example.com. 3600 IN NOTATYPE 192.0.2.1"),
                        Does.Contain("NOTATYPE"),
                        "the offending token belongs in the message");

        });

    }

    [Test]
    [Property("RFC", "1035 §2.3.4")]
    public void An_Owner_Name_That_Is_Not_A_Name_Is_Refused()
    {

        // §2.3.4: "labels 63 octets or less". A longer one is not a name, and the
        // line it owns is not a record however well-formed the rest of it is.
        var tooLong = new String('a', 64);

        Refused($"{tooLong}.example.com. 3600 IN A 192.0.2.1");

    }

    [Test]
    public void The_Same_Line_With_Its_Missing_Part_Restored_Reads()
    {

        // The control. Every refusal above has to be caused by the part that was
        // taken out, not by something else in the line — otherwise the test would
        // pass for a reader that refuses everything.
        Assert.Multiple(() => {
            Assert.That(Reads("example.com. 3600 IN A 192.0.2.1"),  Is.True);
            Assert.That(Reads("example.com. 3600 IN TYPE1 192.0.2.1"), Is.True, "TYPEnnn is a type token too");
        });

    }

    #endregion

    #region TTLs a field cannot hold (RFC 1035 §3.2.1, §5.1)

    [Test]
    [Property("RFC", "1035 §3.2.1")]
    // The TTL field is 32 bits, so a value it cannot hold is not a TTL, and a
    // token that is not a TTL at all must stay available to be read as a type.
    [TestCase("",             TestName = "nothing")]
    [TestCase("4294967296",   TestName = "one past the 32-bit field")]
    [TestCase("99999999999",  TestName = "far past it")]
    [TestCase("4294967296s",  TestName = "a number past the field, and then a unit")]
    [TestCase("2000000h",     TestName = "units multiplying past the field")]
    [TestCase("4294967295s1s", TestName = "the largest value, and then one second more")]
    [TestCase("2w3",          TestName = "a number with no unit after it")]
    [TestCase("h",            TestName = "a unit with no number before it")]
    [TestCase("1x",           TestName = "a unit that is not one")]
    [TestCase("A",            TestName = "a record type, which must not read as a TTL")]
    [TestCase("99999999999999999999999s",
              TestName = "a digit run no integer type can hold")]
    public void A_Ttl_The_Field_Cannot_Hold_Is_Not_A_Ttl(String Text)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileTimeToLive(Text, out _), Is.False,
                    $"'{Text}' is not a TTL");
    }

    [Test]
    [Property("RFC", "1035 §3.2.1")]
    public void The_Largest_Ttl_The_Field_Holds_Is_Still_A_Ttl()
    {

        // The other side, which a refusal test cannot see: a comparison shifted
        // one step would start refusing the largest legal TTL, and every test
        // above would still pass.
        Assert.Multiple(() => {

            Assert.That(ADNSResourceRecord.TryParseZoneFileTimeToLive("4294967295", out var max), Is.True);
            Assert.That(max, Is.EqualTo(TimeSpan.FromSeconds(4294967295)));

            Assert.That(ADNSResourceRecord.TryParseZoneFileTimeToLive("0", out var zero), Is.True);
            Assert.That(zero, Is.EqualTo(TimeSpan.Zero));

            Assert.That(ADNSResourceRecord.TryParseZoneFileTimeToLive("1d12h", out var mixed), Is.True,
                        "BIND's units are what zone files are actually written with");
            Assert.That(mixed, Is.EqualTo(TimeSpan.FromHours(36)));

            // 4294967295 seconds is the largest TTL there is however it is
            // spelled, and 1000000h is 3.6 billion seconds, which fits. Both
            // were in the refusal list above until the tests were run: the
            // arithmetic was mine, and wrong, and the reader was right.
            Assert.That(ADNSResourceRecord.TryParseZoneFileTimeToLive("4294967295s", out var maxWithUnit), Is.True);
            Assert.That(maxWithUnit, Is.EqualTo(TimeSpan.FromSeconds(4294967295)));

            Assert.That(ADNSResourceRecord.TryParseZoneFileTimeToLive("1000000h", out var big), Is.True);
            Assert.That(big, Is.EqualTo(TimeSpan.FromHours(1000000)));

        });

    }

    #endregion

    #region The generic form's length field (RFC 3597 §5)

    [Test]
    [Property("RFC", "3597 §5")]
    // §5: "\# <rdlength> <rdata>", where rdlength is "the RDATA field length in
    // octets, given as a decimal integer". Each of these is not that.
    [TestCase(@"example.com. 3600 IN TYPE65280 \# xy deadbeef",
              TestName = "a length that is not a decimal integer")]
    [TestCase(@"example.com. 3600 IN TYPE65280 \# 65536 deadbeef",
              TestName = "a length past the 16-bit RDLENGTH field")]
    [TestCase(@"example.com. 3600 IN TYPE65280 \# -4 deadbeef",
              TestName = "a negative length")]
    [TestCase(@"example.com. 3600 IN TYPE65280 \# 3 deadbeef",
              TestName = "a length that disagrees with the octets given")]
    [TestCase(@"example.com. 3600 IN TYPE65280 \# 4 deadbee",
              TestName = "an odd number of hexadecimal digits")]
    public void A_Generic_Form_That_Is_Not_Section_5_Syntax_Is_Refused(String Line)
    {
        Refused(Line);
    }

    [Test]
    [Property("RFC", "3597 §5")]
    public void The_Same_Generic_Form_With_A_Length_That_Agrees_Reads()
    {
        Assert.That(Reads(@"example.com. 3600 IN TYPE65280 \# 4 deadbeef"), Is.True);
    }

    #endregion

    #region Signature times the wire format cannot hold (RFC 4034 §3.2)

    [Test]
    [Property("RFC", "4034 §3.2")]
    // §3.2 gives the times two forms: "the number of seconds since 1 January
    // 1970 00:00:00 UTC" or "in the form YYYYMMDDHHmmSS in UTC". Neither can
    // carry a moment outside a 32-bit unsigned count of seconds.
    [TestCase("2026101408332X", TestName = "a fourteen-character form that is not a time")]
    [TestCase("20261332083329", TestName = "month thirteen")]
    [TestCase("19600101000000", TestName = "before the epoch")]
    [TestCase("21500101000000", TestName = "past what 32 bits of seconds can count")]
    public void A_Signature_Time_Outside_The_Field_Is_Refused(String Expiration)
    {
        Refused($"a.example.com. 3600 IN RRSIG A 8 3 3600 {Expiration} 20260914083329 1234 example.com. AQID");
    }

    [Test]
    [Property("RFC", "4034 §3.2")]
    public void Both_Published_Forms_Of_A_Signature_Time_Read()
    {

        Assert.Multiple(() => {

            Assert.That(Reads("a.example.com. 3600 IN RRSIG A 8 3 3600 20261014083329 20260914083329 1234 example.com. AQID"),
                        Is.True, "§3.2's YYYYMMDDHHmmSS form");

            Assert.That(Reads("a.example.com. 3600 IN RRSIG A 8 3 3600 1792312409 1789806809 1234 example.com. AQID"),
                        Is.True, "§3.2's seconds-since-the-epoch form, which a reader owes as well");

        });

    }

    #endregion

    #region A type bit map's three ways of saying no (RFC 4034 §4.1.2)

    [Test]
    [Property("RFC", "4034 §4.1.2")]
    public void A_Bit_That_Is_Set_Is_The_Only_Yes()
    {

        // One window, one octet, the bit for A. Everything else in the same
        // octet is absent, and saying otherwise would assert a type the zone
        // never published.
        var bitmap = Window(0, (UInt16) DNSResourceRecordTypes.A);

        Assert.Multiple(() => {
            Assert.That(ADNSResourceRecord.TypeBitMapContains(bitmap, DNSResourceRecordTypes.A),  Is.True);
            Assert.That(ADNSResourceRecord.TypeBitMapContains(bitmap, DNSResourceRecordTypes.NS), Is.False,
                        "the neighbouring bit in the same octet is clear");
        });

    }

    [Test]
    [Property("RFC", "4034 §4.1.2")]
    [Property("RFC", "4035 §5.4")]
    public void A_Type_Past_The_End_Of_A_Window_Is_Absent_And_Not_An_Error()
    {

        // The window declares one octet, so it speaks for types 0 to 7 and about
        // nothing else. MX is type 15, which lives in the second octet — the one
        // this window does not have. The answer is "absent", and RFC 4035 §5.4
        // makes that answer a proof, so it must not come from reading past the
        // end of the bitmap.
        var bitmap = Window(0, (UInt16) DNSResourceRecordTypes.A);

        Assert.Multiple(() => {
            Assert.That(bitmap[1], Is.EqualTo((Byte) 1), "the window is one octet long");
            Assert.That(ADNSResourceRecord.TypeBitMapContains(bitmap, DNSResourceRecordTypes.MX), Is.False);
        });

    }

    [Test]
    [Property("RFC", "4034 §4.1.2")]
    public void A_Type_In_A_Window_That_Is_Not_There_Is_Absent()
    {

        // CAA is type 257, which is window 1. A bitmap carrying only window 0
        // says nothing about it, and "says nothing" has to read as absent.
        var windowZero = Window(0, (UInt16) DNSResourceRecordTypes.A);
        var bothWindows = (Byte[]) [.. windowZero, .. Window(1, (UInt16) DNSResourceRecordTypes.CAA)];

        Assert.Multiple(() => {

            Assert.That(ADNSResourceRecord.TypeBitMapContains(windowZero,  DNSResourceRecordTypes.CAA), Is.False,
                        "window 1 is not in this bitmap");

            Assert.That(ADNSResourceRecord.TypeBitMapContains(bothWindows, DNSResourceRecordTypes.CAA), Is.True,
                        "and when it is, the type is found in it");

            Assert.That(ADNSResourceRecord.TypeBitMapContains(bothWindows, DNSResourceRecordTypes.A), Is.True,
                        "without losing the first window on the way");

        });

    }

    [Test]
    [Property("RFC", "4034 §4.1.2")]
    public void A_Truncated_Bitmap_Asserts_Nothing()
    {

        // The window claims five octets and three are present. A reader that
        // trusts the declared length walks off the end of the record; one that
        // notices has nothing left to assert, which is the only safe answer —
        // and the same shape as finding 4, where a length was believed over the
        // octets that were actually there.
        Byte[] truncated = [0x00, 0x05, 0x40];

        Assert.Multiple(() => {
            Assert.That(ADNSResourceRecord.TypeBitMapContains(truncated, DNSResourceRecordTypes.A),  Is.False);
            Assert.That(ADNSResourceRecord.TypeBitMapContains(truncated, DNSResourceRecordTypes.MX), Is.False);
        });

    }

    [Test]
    [Property("RFC", "4034 §4.1.2")]
    public void An_Empty_Bitmap_Asserts_Nothing()
    {
        Assert.That(ADNSResourceRecord.TypeBitMapContains([], DNSResourceRecordTypes.A), Is.False);
    }

    #endregion

}

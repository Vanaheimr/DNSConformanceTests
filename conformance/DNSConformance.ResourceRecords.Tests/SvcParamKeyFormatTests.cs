using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// What each SvcParamKey's presentation admits, read up to its edges.
/// </summary>
/// <remarks>
/// <para>
/// From the mutation sweep of Vanaheimr/Hermod#191 (<see href="../../MUTATION.md"/>,
/// the `svcparam` slice). The fix gave SVCB and HTTPS one reader that converts
/// each value into its key's wire format, and the test vectors of RFC 9460
/// Appendix D.2 cover the middle of every key: a port of 53, two IPv6 hints, an
/// escaped comma. Nothing asked where a key stops - the largest port, the longest
/// alpn-id, a hint of the other family - and nothing wrote a key on its own at the
/// end of a line.
/// </para>
/// <para>
/// Each case names a value one step inside or outside the RFC's rule, and is
/// asked of SVCB and of HTTPS, which §9 makes "SVCB-compatible".
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "9460 §2.1")]
[Property("RFC", "9460 §7")]
[Property("RFC", "9460 Appendix A")]
public class SvcParamKeyFormatTests
{

    #region Data

    /// <summary>
    /// SvcPriority 1 and the TargetName svc.example., as every RDATA here begins.
    /// </summary>
    private const String Head = "0001" + "03737663076578616d706c6500";

    private static Boolean TryRead(String Type, String SvcParams, out IDNSResourceRecord? Record)
        => ADNSResourceRecord.TryParseZoneFileString($"probe.example. 3600 IN {Type} 1 svc.example. {SvcParams}",
                                                     out Record,
                                                     out _);

    private static String Rdata(String Type, String SvcParams)
    {
        Assert.That(TryRead(Type, SvcParams, out var record), Is.True, $"the reader refused '{SvcParams}'");
        return Convert.ToHexString(RRWire.Encode(record!).Rdata).ToLowerInvariant();
    }

    private static void Refused(String Type, String SvcParams, String Why)
        => Assert.That(TryRead(Type, SvcParams, out _), Is.False, Why);

    #endregion


    #region A key on its own (§2.1, §7.1.1)

    /// <summary>
    /// A key written without "=" has the empty value, wherever on the line it is.
    /// </summary>
    [Test]
    [TestCase("SVCB",  "alpn=h2 no-default-alpn",  "0001" + "0003" + "026832" + "0002" + "0000")]
    [TestCase("SVCB",  "no-default-alpn alpn=h2",  "0001" + "0003" + "026832" + "0002" + "0000")]
    [TestCase("SVCB",  "port=53 key65280",         "0003" + "0002" + "0035"   + "ff00" + "0000")]
    [TestCase("SVCB",  "key65280 port=53",         "0003" + "0002" + "0035"   + "ff00" + "0000")]
    [TestCase("HTTPS", "alpn=h2 no-default-alpn",  "0001" + "0003" + "026832" + "0002" + "0000")]
    [TestCase("HTTPS", "no-default-alpn alpn=h2",  "0001" + "0003" + "026832" + "0002" + "0000")]
    [TestCase("HTTPS", "port=53 key65280",         "0003" + "0002" + "0035"   + "ff00" + "0000")]
    [TestCase("HTTPS", "key65280 port=53",         "0003" + "0002" + "0035"   + "ff00" + "0000")]
    public void A_Key_Written_Alone_Has_The_Empty_Value(String Type, String SvcParams, String Params)
    {

        // §2.1: "When the optional "=" and SvcParamValue are omitted, the value is
        // interpreted as empty." §7.1.1 makes "no-default-alpn" the key that is
        // only ever written so: "the presentation and wire-format values MUST be
        // empty". At the end of the line the reader looks for an "=" past the
        // last character; before another parameter, the blank is not an "=" and
        // the next parameter is not this one's value.
        Assert.That(Rdata(Type, SvcParams), Is.EqualTo(Head + Params));

    }

    /// <summary>
    /// An "=" with nothing after it reads the same at the end of the line as
    /// before another parameter.
    /// </summary>
    [Test]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void An_Equals_Sign_With_Nothing_After_It_Reads_The_Same_Wherever_The_Line_Ends(String Type)
    {

        // Appendix A's contiguous char-string is 1*( non-special / escaped ), so
        // "key65280=" followed by nothing is not strictly a SvcParamValue, and a
        // reader may take it as the empty value or refuse it. Which one is not
        // asked here. What is asked is that the answer does not depend on whether
        // the line happens to end straight after the "=".
        var middle  = TryRead(Type, "key65280= port=53", out var first);
        var end     = TryRead(Type, "port=53 key65280=", out var second);

        Assert.That(end, Is.EqualTo(middle), "accepted in the middle of the line and not at its end, or the reverse");

        if (middle && end)
            Assert.That(RRWire.Encode(second!).Rdata, Is.EqualTo(RRWire.Encode(first!).Rdata));

    }

    #endregion

    #region alpn (§7.1.1)

    /// <summary>
    /// An alpn-id is 1 to 255 octets, and 255 is one of them.
    /// </summary>
    [Test]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void An_Alpn_Id_Is_One_To_255_Octets(String Type)
    {

        // §7.1.1: an alpn-id "is a sequence of 1-255 octets", and on the wire each
        // goes "prefixed by its length as a single octet" - which 255 still fits
        // and 256 does not.
        var longest = new String('a', 255);

        Assert.Multiple(() => {

            Assert.That(Rdata(Type, "alpn=" + longest),
                        Is.EqualTo(Head + "0001" + "0100" + "ff" + String.Concat(Enumerable.Repeat("61", 255))));

            Refused(Type, "alpn=" + longest + "a", "256 octets do not fit behind a one-octet length");

        });

    }

    /// <summary>
    /// In a value list a backslash escapes a comma or a backslash, and nothing else.
    /// </summary>
    [Test]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void A_Backslash_In_A_Value_List_Escapes_A_Comma_Or_A_Backslash_And_Nothing_Else(String Type)
    {

        // Appendix A.1: escaped-item = 1*(item-allowed / "\," / "\\"), where
        // item-allowed "is OCTET minus "," and "\"". A list is decoded after the
        // character-string, so the zone text "h\\x" is the value h\x, whose
        // backslash escapes an x - which the list syntax has no form for. "h\\,x"
        // is the value h\,x, the one alpn-id "h,x".
        Assert.Multiple(() => {

            Refused(Type, "alpn=h\\\\x", "a backslash that escapes neither a comma nor a backslash");

            Assert.That(Rdata(Type, "alpn=h\\\\,x"), Is.EqualTo(Head + "0001" + "0004" + "03682c78"),
                        "the control: an escaped comma is a comma inside the alpn-id");

        });

    }

    #endregion

    #region port (§7.2)

    /// <summary>
    /// A port is a decimal integer from 0 to 65535, and nothing else.
    /// </summary>
    [Test]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void A_Port_Is_A_Decimal_Integer_From_0_To_65535(String Type)
    {

        // §7.2: "The presentation value of the SvcParamValue is a single decimal
        // integer between 0 and 65535 in ASCII. Any other value (e.g., an empty
        // value) is a syntax error." Both ends are ports. A sign is not part of a
        // decimal integer in ASCII, even where a number parser would accept one.
        Assert.Multiple(() => {

            Assert.That(Rdata(Type, "port=0"),     Is.EqualTo(Head + "0003" + "0002" + "0000"));
            Assert.That(Rdata(Type, "port=65535"), Is.EqualTo(Head + "0003" + "0002" + "ffff"));

            Refused(Type, "port=65536", "one past the largest port");
            Refused(Type, "port=+80",   "a sign is not a digit");

        });

    }

    #endregion

    #region ipv4hint and ipv6hint (§7.3)

    /// <summary>
    /// An address hint holds addresses of its own family, and an address only.
    /// </summary>
    [Test]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void An_Address_Hint_Holds_Addresses_Of_Its_Own_Family_And_Nothing_Else(String Type)
    {

        // §7.3: the value is "one or more IP addresses of the appropriate family",
        // and the wire format "a sequence of IP addresses in network byte order
        // (for the respective address family)": four octets each for ipv4hint,
        // sixteen for ipv6hint. An IPv4 address in an ipv6hint would go on the
        // wire as four octets where sixteen are counted. A zone index has no
        // place in sixteen octets at all, so a hint written with one would be
        // published as a different statement than the one written.
        Assert.Multiple(() => {

            Refused(Type, "ipv6hint=192.0.2.1",   "an IPv4 address is not of ipv6hint's family");
            Refused(Type, "ipv4hint=2001:db8::1", "an IPv6 address is not of ipv4hint's family");
            Refused(Type, "ipv6hint=fe80::1%1",   "the wire format has no place for a zone index");

            Assert.That(Rdata(Type, "ipv6hint=fe80::1"),
                        Is.EqualTo(Head + "0006" + "0010" + "fe800000000000000000000000000001"),
                        "the control: the same address without the zone index");

        });

    }

    #endregion

    #region The character-string around every value (Appendix A)

    /// <summary>
    /// A decimal escape is three digits, even where a blank follows the second.
    /// </summary>
    [Test]
    [TestCase("SVCB")]
    [TestCase("HTTPS")]
    public void A_Decimal_Escape_Is_Three_Digits_Even_Where_A_Blank_Follows_Two(String Type)
    {

        // Appendix A: escaped = "\" ( non-digit / dec-octet ), and a dec-octet "is
        // a number 0-255 as a three-digit decimal number". So "\12 " is neither:
        // its first character is a digit, and "12 " is not three digits - whatever
        // a number parser that allows trailing white space would make of it.
        // Quoted, so that the blank is part of the value rather than its end.
        Assert.Multiple(() => {

            Refused(Type, "key65280=\"a\\12 b\"", "two digits and a blank are not a decimal escape");

            Assert.That(Rdata(Type, "key65280=\"a\\012 b\""), Is.EqualTo(Head + "ff00" + "0004" + "610c2062"),
                        "the control: the same octet written with its three digits");

        });

    }

    /// <summary>
    /// A character outside ASCII is the octets of its UTF-8 encoding, from the
    /// first one past ASCII on.
    /// </summary>
    [Test]
    public void A_Character_Past_Ascii_Is_Its_Utf8_Octets_From_The_First_One_On()
    {

        // Appendix A: zone files represent "arbitrary octet sequences in basic
        // ASCII text", so a character past 0x7F is outside the syntax, and a
        // reader that is handed text rather than octets has to decide what it
        // stands for. Hermod's reader takes it as UTF-8, which is what a reader of
        // the zone file's own octets sees when the file is UTF-8 (FINDINGS.md,
        // Interpretations). Whatever the rule, U+0080 is the first character it
        // applies to and not the last one it does not.
        var name    = DomainName.Parse("probe.example.");
        var ttl     = TimeSpan.FromSeconds(3600);
        var text    = "\u007F\u0080é";
        var octets  = Encoding.UTF8.GetBytes(text);

        var svcb    = SVCB. TryParseFromJSON(name, ttl, "1 . key65280=" + text);
        var https   = HTTPS.TryParseFromJSON(name, ttl, "1 . key65280=" + text);

        Assert.Multiple(() => {
            Assert.That(svcb?. SVCParameters.Single().Value, Is.EqualTo(octets), "SVCB: 7F, then C2 80 and C3 A9");
            Assert.That(https?.SVCParameters.Single().Value, Is.EqualTo(octets), "HTTPS");
        });

    }

    #endregion

}

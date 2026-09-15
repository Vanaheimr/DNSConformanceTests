using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// What TXT refuses, ignores and splits — RFC 1035 §3.3.14 and RFC 6763 §6.4.
///
/// Found by the mutation sweep (<see href="../../MUTATION.md"/>), which reported
/// TXT's quoted-string reader, its length validation and its DNS-SD key rules as
/// changeable almost at will: three `return false` statements could each be made
/// to succeed, the 255-byte limit could be shifted by one, and every branch of
/// the tokenizer's state machine could be inverted, without a single test in the
/// suite noticing. Every TXT test written before this one fed it text that was
/// already correct.
///
/// The quoted-string reader is private and reached through
/// <c>TryParseFromJSON</c>, which is where it matters: the JSON APIs hand over a
/// `data` field that may be one text or several quoted strings, and telling those
/// apart wrongly is how a multi-string TXT becomes one string with quotes in it.
/// That is the neighbourhood of finding 48.
/// </summary>
[TestFixture]
[Property("RFC", "1035 §3.3.14, 6763 §6.4")]
public class TxtRejectionTests
{

    #region Data

    private static readonly DomainName Name = DomainName.Parse("txt.example.");

    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(300);

    private static TXT FromJSON(String Data)
    {
        var record = TXT.TryParseFromJSON(Name, Ttl, Data);
        Assert.That(record, Is.Not.Null, $"the reader returned nothing at all for '{Data}'");
        return record!;
    }

    #endregion


    #region Several quoted strings stay several, and everything else is one

    [Test]
    [Property("RFC", "1035 §3.3.14")]
    public void Two_Quoted_Strings_In_A_Data_Field_Stay_Two_Character_Strings()
    {

        // "TXT-DATA: One or more <character-string>s." The JSON APIs write a
        // multi-string TXT as several quoted strings in one field, and the
        // boundary between them is data: "v=spf1" "include:_spf.example.com"
        // is two strings, not one with quotes embedded in the middle.
        var record = FromJSON("\"first\" \"second\"");

        Assert.That(record.Strings, Is.EqualTo(new[] { "first", "second" }));

    }

    [Test]
    [Property("RFC", "1035 §3.3.14")]
    public void An_Escaped_Quote_Belongs_To_The_String_It_Is_Inside()
    {

        // A backslash inside a quoted string makes the next character data,
        // which is the only way a '"' can appear in one. Lose that and the
        // string ends early and everything after it becomes a parse failure.
        var record = FromJSON("\"a\\\"b\" \"c\"");

        Assert.That(record.Strings, Is.EqualTo(new[] { "a\"b", "c" }));

    }

    [Test]
    [Property("RFC", "6763 §6.1")]
    public void An_Empty_Quoted_String_Is_Still_A_String()
    {

        // RFC 6763 §6.1: "a single length byte, followed by 0-255 bytes of text
        // data" — zero included, so "" is a character-string and not an absence
        // of one.
        //
        // It is also the only input that reaches the reader's escape flag before
        // any ordinary character has: every other test here begins its first
        // string with a letter, which the reader appends the same way whether it
        // thinks the character is escaped or not. A mutation that starts the
        // reader in the escaped state survived all of them.
        var record = FromJSON("\"\" \"second\"");

        Assert.That(record.Strings, Is.EqualTo(new[] { "", "second" }));

    }

    [Test]
    // Not a list of quoted strings, each for its own reason, and each of them a
    // separate `return false` in the reader. What comes back is a single text:
    // refusing to split is not refusing to parse.
    [TestCase("plain text",            TestName = "no quotes at all")]
    [TestCase("",                      TestName = "nothing at all")]
    [TestCase("   ",                   TestName = "whitespace only")]
    [TestCase("x \"a\" \"b\"",         TestName = "a word before the first quote")]
    [TestCase("\"a\" x \"b\"",         TestName = "a word between two strings")]
    [TestCase("\"a\" \"b\" x",         TestName = "a word after the last string")]
    [TestCase("\"unterminated",        TestName = "a quote that is never closed")]
    [TestCase("\"a\" \"unterminated",  TestName = "the second string never closed")]
    public void A_Data_Field_That_Is_Not_A_List_Of_Quoted_Strings_Is_One_Text(String Data)
    {

        var record = FromJSON(Data);

        Assert.That(record.Strings, Has.Count.EqualTo(1),
                    $"'{Data}' is not a list of quoted strings, so it is one character-string");

    }

    #endregion

    #region The 255-byte limit of a character-string (RFC 1035 §3.3.14)

    [Test]
    [Property("RFC", "1035 §3.3.14")]
    [Property("RFC", "6763 §6.1")]
    public void A_Character_String_Of_Exactly_255_Bytes_Is_Legal_And_256_Is_Not()
    {

        // RFC 6763 §6.1 spells out what §3.3.14's length octet implies: "a single
        // length byte, followed by 0-255 bytes of text data". Both sides, because
        // a limit asserted from one side only is a limit that can move: refusing
        // 255 would be as wrong as accepting 256, and far quieter.
        var exactly255 = new String('a', 255);
        var one256     = new String('a', 256);

        Assert.Multiple(() => {

            Assert.That(() => new TXT(Name, DNSQueryClasses.IN, Ttl, (IEnumerable<String>) [exactly255]),
                        Throws.Nothing,
                        "255 bytes is the longest character-string there is, and it is legal");

            Assert.That(() => new TXT(Name, DNSQueryClasses.IN, Ttl, (IEnumerable<String>) [one256]),
                        Throws.TypeOf<ArgumentException>(),
                        "256 does not fit the length octet and cannot be sent");

        });

    }

    [Test]
    [Property("RFC", "1035 §3.3.14")]
    public void The_Limit_Counts_Utf8_Octets_And_Not_Characters()
    {

        // 128 two-octet characters are 256 octets and 128 characters. The length
        // octet counts the former, so a limit checked against String.Length would
        // accept a record that cannot be encoded.
        var text = new String('ä', 128);

        Assert.Multiple(() => {

            Assert.That(text.Length,                       Is.EqualTo(128));
            Assert.That(Encoding.UTF8.GetByteCount(text),  Is.EqualTo(256));

            Assert.That(() => new TXT(Name, DNSQueryClasses.IN, Ttl, (IEnumerable<String>) [text]),
                        Throws.TypeOf<ArgumentException>(),
                        "256 octets is 256 octets however few characters they spell");

        });

    }

    #endregion

    #region DNS-SD keys: what a key may be (RFC 6763 §6.4)

    [Test]
    [Property("RFC", "6763 §6.4")]
    // "The characters of a key MUST be printable US-ASCII values (0x20-0x7E),
    //  excluding '=' (0x3D)."
    [TestCase("key\twith\ttabs", TestName = "a control character below 0x20")]
    [TestCase("key\nnewline",    TestName = "a newline")]
    [TestCase("key",       TestName = "0x7F, one past the printable range")]
    [TestCase("schlüssel",       TestName = "a character outside US-ASCII")]
    [TestCase("key=part",        TestName = "an equals sign, which is the delimiter")]
    [TestCase("",                TestName = "an empty key")]
    public void A_Key_Outside_Printable_Ascii_Is_Refused(String Key)
    {

        Assert.That(() => TXT.FromKeyValues(
                              DNSServiceName.Parse("txt.example."),
                              DNSQueryClasses.IN,
                              Ttl,
                              [ new KeyValuePair<String, String?>(Key, "value") ]
                          ),
                    Throws.TypeOf<ArgumentException>(),
                    $"'{Key}' is not printable US-ASCII without '=' and cannot be a key");

    }

    [Test]
    [Property("RFC", "6763 §6.4")]
    public void Both_Ends_Of_The_Printable_Range_Are_Keys()
    {

        // 0x20 and 0x7E are inside the interval §6.4 names, and a comparison
        // shifted one step would quietly refuse them. A space is a legal key
        // character; it is only the '=' that is carved out.
        var record = TXT.FromKeyValues(
                         DNSServiceName.Parse("txt.example."),
                         DNSQueryClasses.IN,
                         Ttl,
                         [ new KeyValuePair<String, String?>(" ~", "value") ]
                     );

        Assert.That(record.KeyValues.ContainsKey(" ~"), Is.True,
                    "0x20 and 0x7E are both inside the printable range §6.4 gives");

    }

    #endregion

    #region DNS-SD values: what a string means (RFC 6763 §6.4)

    [Test]
    [Property("RFC", "6763 §6.4")]
    public void The_Section_6_4_Reading_Of_Four_Strings()
    {

        // Four strings, four rules, one record:
        //
        //   ""          nothing to read
        //   "=orphan"   "strings beginning with an '=' character (i.e., the key
        //               is missing) MUST be silently ignored"
        //   "flag"      "if there is no '=' ... then it is a boolean attribute,
        //               simply identified as being present, with no value"
        //   "k=v"       key and value, split at the first '='
        var record = new TXT(
                         Name,
                         DNSQueryClasses.IN,
                         Ttl,
                         (IEnumerable<String>) [ "", "=orphan", "flag", "k=v" ]
                     );

        var keyValues = record.KeyValues;

        Assert.Multiple(() => {

            Assert.That(keyValues.Keys, Is.EquivalentTo(new[] { "flag", "k" }),
                        "the empty string and the one with no key are both ignored, and nothing else is");

            Assert.That(keyValues["flag"], Is.Null,
                        "§6.4: no '=' means a boolean attribute, present and without a value");

            Assert.That(keyValues["k"], Is.EqualTo("v"));

        });

    }

    [Test]
    [Property("RFC", "6763 §6.4")]
    public void A_Value_Keeps_Every_Equals_Sign_After_The_First()
    {

        // The split is at the *first* '=' and the rest is data. Splitting at the
        // last one, or refusing the string, would corrupt every base64 value
        // that ends in padding.
        var record = new TXT(Name, DNSQueryClasses.IN, Ttl, (IEnumerable<String>) [ "k=YQ==" ]);

        Assert.That(record.KeyValues["k"], Is.EqualTo("YQ=="),
                    "everything after the first '=' is the value, padding included");

    }

    [Test]
    [Property("RFC", "6763 §6.4")]
    public void An_Empty_Value_Is_Not_The_Same_As_No_Value()
    {

        // "k=" is a key with an empty value; "k" is a key with no value at all.
        // Reading them the same way loses the distinction §6.4 draws between an
        // attribute that is present and one that is set to nothing.
        var record = new TXT(Name, DNSQueryClasses.IN, Ttl, (IEnumerable<String>) [ "empty=", "flag" ]);

        Assert.Multiple(() => {
            Assert.That(record.KeyValues["empty"], Is.EqualTo(String.Empty), "present, and set to nothing");
            Assert.That(record.KeyValues["flag"],  Is.Null,                  "present, and not set at all");
        });

    }

    [Test]
    [Property("RFC", "6763 §6.4")]
    public void Only_The_First_Occurrence_Of_A_Key_Counts()
    {

        // "If a client receives a TXT record containing the same key more than
        //  once, then the client MUST silently ignore all but the first
        //  occurrence of that attribute." Keys compare case-insensitively, so
        //  "Key" is the same key as "key" and does not get a second entry.
        var record = new TXT(Name, DNSQueryClasses.IN, Ttl, (IEnumerable<String>) [ "k=first", "K=second", "k=third" ]);

        Assert.Multiple(() => {
            Assert.That(record.KeyValues, Has.Count.EqualTo(1));
            Assert.That(record.KeyValues["k"], Is.EqualTo("first"), "the first occurrence, and silently only that one");
        });

    }

    #endregion

}

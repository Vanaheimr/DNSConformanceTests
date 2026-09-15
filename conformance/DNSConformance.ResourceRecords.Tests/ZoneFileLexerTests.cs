using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// What a backslash means, and where a line is allowed to run out.
///
/// Seventh entry from the mutation sweep (<see href="../../MUTATION.md"/>), and
/// the first of the branches. A branch gap is a condition whose two sides were
/// never both taken; in a lexer almost every condition is one, because the
/// suite's zone-file lines had all been written the same way — no escapes, no
/// leading blank, never stopping early.
///
/// RFC 1035 §5.1 gives the master file two escape forms and says what each one
/// means. They are syntax, not data: a reader that carries them through into the
/// record publishes octets the zone never contained, which is
/// <see href="../../FINDINGS.md">finding 56</see>.
/// </summary>
[TestFixture]
[Property("RFC", "1035 §5.1")]
public class ZoneFileLexerTests
{

    #region Data

    private static IDNSResourceRecord Read(String Line)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");
        return record!;
    }

    private static String Refuse(String Line)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out _, out var error),
                    Is.False,
                    $"'{Line}' should not have been accepted");
        Assert.That(error, Is.Not.Null);
        return error!;
    }

    #endregion


    #region An escape is syntax, not data (RFC 1035 §5.1 — finding 56)

    [Test]
    [Property("RFC", "1035 §5.1")]
    [Property("RFC", "1035 §3.3.14")]
    // RFC 1035 §5.1 gives two forms and both of them disappear into the octets
    // they denote:
    //
    //   "\X where X is any character other than a digit (0-9), is used to quote
    //    that character so that its special meaning does not apply"
    //   "\DDD where each D is a digit is the octet corresponding to the decimal
    //    number described by DDD"
    //
    // Reading them as themselves puts a backslash into a record that never
    // carried one — and a DKIM or SPF policy is a single quoted string, which is
    // exactly the case that used to bypass the reader that knew this.
    [TestCase("\"say \\\"hi\\\" now\"", "say \"hi\" now",  TestName = "an escaped quote is a quote")]
    [TestCase("\"a\\\\b\"",             "a\\b",            TestName = "an escaped backslash is one backslash")]
    [TestCase("\"a\\098c\"",            "abc",             TestName = "\\098 is the octet 98, which is 'b'")]
    [TestCase("\"v=spf1 -all\"",        "v=spf1 -all",     TestName = "a policy with nothing to escape")]
    [TestCase("\"\\032\"",              " ",               TestName = "\\032 is a blank inside a character-string")]
    public void An_Escape_Denotes_What_It_Quotes(String Written, String Meant)
    {

        var txt = Read($"probe.example. 3600 IN TXT {Written}") as TXT;

        Assert.That(txt!.Text, Is.EqualTo(Meant),
                    "the backslashes are the master file's, not the record's");

    }

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void What_An_Escape_Meant_Survives_Being_Written_Down_Again()
    {

        // The other half: whatever the octets are, writing them has to produce a
        // line that reads back to the same octets. That held before finding 56
        // as well — it just held around the wrong octets, which is why nothing
        // noticed.
        var once   = Read("probe.example. 3600 IN TXT \"say \\\"hi\\\" now\"");
        var twice  = Read(once.ToZoneFileString());

        Assert.That((twice as TXT)!.Text, Is.EqualTo("say \"hi\" now"));

    }

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Backslash_Holds_A_Quoted_String_Together()
    {

        // The lexer's side of the same rule. An escaped quote must not close the
        // string, or everything after it becomes separate tokens — and a TXT
        // record silently gains character-strings nobody wrote.
        var txt = Read("probe.example. 3600 IN TXT \"one \\\"two\\\" three\"") as TXT;

        Assert.That(txt!.Strings.Count(), Is.EqualTo(1),
                    "an escaped quote is a character, and a character does not end a string");

    }

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Backslash_Quotes_One_Character_And_Not_The_Rest_Of_The_Line()
    {

        // And the other direction: an escape that never ends would swallow the
        // blank between two character-strings, and two would arrive as one.
        var txt = Read("probe.example. 3600 IN TXT \"a\\\\b\" \"second\"") as TXT;

        Assert.Multiple(() => {
            Assert.That(txt!.Strings.Count(), Is.EqualTo(2));
            Assert.That(txt!.Strings.First(), Is.EqualTo("a\\b"));
            Assert.That(txt!.Strings.Last(),  Is.EqualTo("second"));
        });

    }

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Line_May_Begin_With_A_Blank()
    {

        // §5.1 makes blanks separators and gives <blank><rr> a meaning of its
        // own, so a blank before the owner name is not part of it. A lexer that
        // starts one character into the line makes the first one part of the
        // token, and the name stops being a name.
        var record = Read("  probe.example. 3600 IN A 192.0.2.1");

        Assert.That(record.DomainName.FullName, Is.EqualTo("probe.example."));

    }

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Blank_Inside_A_Character_String_Is_Data()
    {

        // The two rules meet here. A blank between character-strings separates
        // them and a blank inside one is an octet of it, so "a\"  b" is a single
        // string carrying two blanks — but only if the escaped quote did not end
        // the string three characters earlier. A lexer that lets it end splits
        // the line, and the two halves come back joined by one blank instead of
        // two: the same text, one octet shorter, with nothing to show for it.
        var txt = Read("probe.example. 3600 IN TXT \"a\\\"  b\"") as TXT;

        Assert.Multiple(() => {
            Assert.That(txt!.Strings.Count(), Is.EqualTo(1));
            Assert.That(txt!.Text,            Is.EqualTo("a\"  b"), "two blanks, both of them data");
        });

    }

    #endregion


    #region Where a line is allowed to run out (RFC 1035 §5.1)

    [Test]
    [Property("RFC", "1035 §5.1")]
    [TestCase("probe.example. IN 3600 CH",   TestName = "a class, a TTL and another class")]
    [TestCase("probe.example. 3600 IN 7200", TestName = "a TTL, a class and another TTL")]
    [TestCase("probe.example. IN IN IN",     TestName = "three classes")]
    public void A_Line_That_Never_Reaches_Its_Type_Says_That(String Line)
    {

        // RFC 1035 §5.1: "<rr> contents take one of the following forms:
        // [<TTL>] [<class>] <type> <RDATA>" — the type is the one field with no
        // brackets around it. Naming the missing field is the whole value of the
        // message: "missing RDATA" for a line that has no type sends the reader
        // looking at the wrong half of it, which is the mistake the third round
        // of this sweep found in a test of its own.
        Assert.That(Refuse(Line),
                    Does.Contain("Missing DNS resource record type"));

    }

    [Test]
    [Property("RFC", "1035 §5.1")]
    [TestCase("probe.example.",         TestName = "an owner name and nothing else")]
    [TestCase("probe.example. IN",      TestName = "a class and no type")]
    [TestCase("probe.example. IN 3600", TestName = "a class, a TTL and no type")]
    public void A_Line_Too_Short_To_Be_A_Record_Is_Refused_Before_Anything_Else(String Line)
    {

        // Three tokens cannot be a resource record whatever they are: §5.1's
        // shortest form is an owner name, a type and its RDATA, and the two
        // optional fields in between do not change that. This is a different
        // refusal from the one above, and saying which is which is the point —
        // a message naming "type" for a line that is simply too short sends the
        // reader to the wrong field, and an assertion that looks for the word
        // "type" cannot tell the two apart. That is how this very test read
        // before the seventh round looked at it.
        Assert.That(Refuse(Line),
                    Does.Contain("at least name, class, type and RDATA"));

    }

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Line_Whose_Rdata_Is_The_Problem_Does_Not_Blame_Its_Name()
    {

        // Which half of the line is at fault. A name no parser will take skips
        // the type dispatch silently, so such a line used to be reported as bad
        // RDATA when the RDATA was perfect — and the message now names the owner
        // instead. That is two conditions, and a reader that stops checking the
        // first one blames the name of every record whose RDATA is wrong.
        var error = Refuse("probe.example. 3600 IN MX notanumber mail.example.");

        Assert.That(error, Does.Contain("RDATA").And.Not.Contain("owner name"),
                    "the name is fine; the preference is not a number");

    }

    [Test]
    [Property("RFC", "7477 §2.1")]
    public void A_Csync_May_Name_No_Types_At_All()
    {

        // RFC 7477 §2.1 gives CSYNC an SOA Serial, Flags and a Type Bit Map, and
        // §2.1.3 makes the bit map a list of types to process — a list of none
        // is a record with nothing to do, not a record with a field missing.
        var csync = Read("probe.example. 3600 IN CSYNC 66 3") as CSYNC;

        Assert.Multiple(() => {
            Assert.That(csync!.SOASerial, Is.EqualTo(66u));
            Assert.That(csync!.Flags,     Is.EqualTo((UInt16) 3));
        });

        Assert.That(Refuse("probe.example. 3600 IN CSYNC 66"),
                    Is.Not.Empty,
                    "the flags are not optional the way the bit map is");

    }

    #endregion


    #region A time that is not a time (RFC 8945 §4.2, RFC 2930 §2)

    [Test]
    [Property("RFC", "8945 §4.2")]
    [TestCase("notatime",        TestName = "not digits at all")]
    [TestCase("2023111422132",   TestName = "thirteen digits")]
    [TestCase("20231301221320",  TestName = "a thirteenth month")]
    [TestCase("20231114251320",  TestName = "the twenty-fifth hour")]
    public void A_Signature_Time_That_Is_Not_One_Is_Refused(String Stamp)
    {

        // The zone-file form of a TSIG time is the fourteen digits RFC 8945 §4.2
        // and RFC 2930 §2 use everywhere else, and a reader that accepts
        // something else has to invent the seconds it stands for.
        Assert.That(Refuse($"probe.example. 0 ANY TSIG hmac-sha256. {Stamp} 300 AQIDBA== 4711 0"),
                    Is.Not.Empty);

    }

    [Test]
    [Property("RFC", "8945 §4.2")]
    public void A_Signature_Time_That_Is_One_Is_Taken()
    {

        var tsig = Read("probe.example. 0 ANY TSIG hmac-sha256. 20231114221320 300 AQIDBA== 4711 0") as TSIG;

        Assert.That(tsig!.TimeSigned, Is.EqualTo(1700000000UL),
                    "14 November 2023, 22:13:20 UTC");

    }

    #endregion

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 1035 §5.1 — the parts of the master file format that decide what a *line*
/// is before anything decides what a record is: which directives are understood,
/// where a backslash stops a semicolon from being a comment, and what happens to
/// a line the reader cannot make a record of.
///
/// <see cref="MasterFileFormatTests"/> covers what the format means. This covers
/// what it refuses, which is the half a zone file only ever exercises by being
/// wrong — and a reader that refuses in the wrong way is how finding 45 put a
/// relative name at the top level and said nothing.
/// </summary>
[TestFixture]
[Property("RFC", "1035 §5.1")]
public class MasterFileSyntaxTests
{

    #region Data

    private static readonly DomainName Origin = DomainName.Parse("example.com.");

    #endregion


    // ------------------------------------------------------------ directives

    #region Dollar_Origin_Without_A_Name_Is_Refused()

    /// <summary>
    /// RFC 1035 §5.1: "$ORIGIN &lt;domain-name&gt; [&lt;comment&gt;]". The name is
    /// not optional, and a $ORIGIN that changed nothing would leave every
    /// relative name after it pointing somewhere the file did not say.
    /// </summary>
    [Test]
    public void Dollar_Origin_Without_A_Name_Is_Refused()
    {

        Assert.That(DNSZoneFile.TryParse("$ORIGIN\na IN A 192.0.2.1\n", out _, out var error, Origin),
                    Is.False);

        Assert.That(error, Does.Contain("$ORIGIN needs a domain name"),
                    "the directive is refused for having no argument at all");

    }

    #endregion

    #region Dollar_Origin_With_Something_That_Is_Not_A_Name_Is_Refused()

    /// <summary>
    /// And an argument that is not a domain name is refused for that reason
    /// rather than for the first one — the two failures are different lines of
    /// the reader and a zone that hits one should not be told about the other.
    /// </summary>
    [Test]
    public void Dollar_Origin_With_Something_That_Is_Not_A_Name_Is_Refused()
    {

        Assert.That(DNSZoneFile.TryParse("$ORIGIN -nope-.example.com.\na IN A 192.0.2.1\n", out _, out var error, Origin),
                    Is.False);

        Assert.That(error, Does.Contain("is not a domain name"),
                    "the argument is present and still not a name");

    }

    #endregion

    #region A_Good_Dollar_Origin_Is_Taken()

    /// <summary>
    /// The other side of both refusals, so that neither test is passed by a
    /// reader that refuses every $ORIGIN there is.
    /// </summary>
    [Test]
    public void A_Good_Dollar_Origin_Is_Taken()
    {

        Assert.That(DNSZoneFile.TryParse("$ORIGIN sub.example.com.\na IN A 192.0.2.1\n",
                                         out var records, out var error, Origin),
                    Is.True,
                    error);

        Assert.That(records!.Single().DomainName.FullName,
                    Is.EqualTo("a.sub.example.com.").IgnoreCase);

    }

    #endregion


    // ------------------------------------------------------ the owner name

    #region An_Omitted_Owner_On_The_First_Line_Is_Refused()

    /// <summary>
    /// RFC 1035 §5.1: "if a line begins with a blank, then the owner is assumed
    /// to be the same as that of the previous RR". The first line of a file has
    /// no previous RR, so there is nothing to assume — and assuming anyway is
    /// how a record ends up owned by whatever the reader happened to have lying
    /// around.
    /// </summary>
    [Test]
    public void An_Omitted_Owner_On_The_First_Line_Is_Refused()
    {

        Assert.That(DNSZoneFile.TryParse("    IN  A  192.0.2.1\n", out _, out var error, Origin),
                    Is.False);

        Assert.That(error, Does.Contain("there is no record before it"),
                    "the owner is omitted and there is nothing to repeat");

    }

    #endregion

    #region A_Line_Carrying_Only_An_Owner_Name_Is_Refused()

    /// <summary>
    /// An RR is an owner, a type and the RDATA that goes with it. A line holding
    /// a name and nothing else is not a record, and the reader has to say so
    /// rather than read past the end of the tokens it does not have.
    /// </summary>
    [Test]
    public void A_Line_Carrying_Only_An_Owner_Name_Is_Refused()
    {

        // Whatever the message, the answer is false and not an exception: this
        // reads a file somebody else wrote.
        Boolean parsed = true;
        String? error  = null;

        Assert.That(() => parsed = DNSZoneFile.TryParse("lonely.example.com.\n", out _, out error, Origin),
                    Throws.Nothing,
                    "a line with nothing after the name is refused, not stumbled over");

        Assert.That(parsed, Is.False);
        Assert.That(error,  Is.Not.Null.And.Not.Empty);

    }

    #endregion

    #region A_Line_That_Is_Not_A_Record_Is_Refused_With_Its_Line_Number()

    /// <summary>
    /// A file is refused at the line that is wrong, and says which — a zone of
    /// any size is unfixable otherwise.
    /// </summary>
    [Test]
    public void A_Line_That_Is_Not_A_Record_Is_Refused_With_Its_Line_Number()
    {

        Assert.That(DNSZoneFile.TryParse("a  IN  A     192.0.2.1\n" +
                                         "b  IN  A     not-an-address\n" +
                                         "c  IN  A     192.0.2.3\n",
                                         out _, out var error, Origin),
                    Is.False);

        Assert.That(error, Does.Contain("Line 2"),
                    "the second line is the one that is wrong");

    }

    #endregion


    // ------------------------------------------- the backslash and the comment

    #region A_Semicolon_Behind_A_Backslash_Is_Not_A_Comment()

    /// <summary>
    /// RFC 1035 §5.1 gives the semicolon to comments — "; ... a semi-colon is
    /// used to start a comment" — and the backslash to escapes: "\X ... is used
    /// to quote that character so that its special meaning does not apply". A
    /// quoted semicolon has no special meaning left to apply, so it is data.
    ///
    /// This matters to exactly the records people put semicolons in: a DKIM key
    /// and a DMARC policy are both a list of "tag=value;" pairs, and a reader
    /// that took the first semicolon as a comment would silently truncate every
    /// one of them.
    /// </summary>
    [Test]
    public void A_Semicolon_Behind_A_Backslash_Is_Not_A_Comment()
    {

        Assert.That(DNSZoneFile.TryParse("dkim  IN  TXT  v=DKIM1\\; k=rsa\n",
                                         out var records, out var error, Origin),
                    Is.True,
                    error);

        Assert.That(records!.Single(), Is.InstanceOf<TXT>());

        Assert.That(((TXT) records.Single()).Strings,
                    Is.EqualTo(new[] { "v=DKIM1\\; k=rsa" }),
                    "everything behind the escaped semicolon is still RDATA; had it " +
                    "started a comment, the record would end at the backslash");

    }

    #endregion

    #region A_Semicolon_Not_Behind_A_Backslash_Still_Is_A_Comment()

    /// <summary>
    /// The other half, without which the test above is passed by a reader that
    /// has no comments at all.
    /// </summary>
    [Test]
    public void A_Semicolon_Not_Behind_A_Backslash_Still_Is_A_Comment()
    {

        Assert.That(DNSZoneFile.TryParse("host  IN  A  192.0.2.1   ; the comment\n",
                                         out var records, out var error, Origin),
                    Is.True,
                    error);

        Assert.That(((A) records!.Single()).IPv4Address.ToString(), Is.EqualTo("192.0.2.1"));

    }

    #endregion

    #region An_Escape_Quotes_One_Character_And_Not_The_Rest_Of_The_Line()

    /// <summary>
    /// §5.1's escape is <c>\X</c> — one character, not the rest of the line. The
    /// character that shows it is the parenthesis rather than the semicolon:
    /// "Parentheses are used to group data that crosses a line boundary", and a
    /// reader whose escape never ended would stop counting them, so a record
    /// written across several lines would be cut off at the first one.
    ///
    /// Here the backslash comes first and the parenthesis after it on the same
    /// line, so the continuation only survives if the escape ended in between.
    ///
    /// **The semicolon cannot show it**, which is worth writing down because it
    /// is where this test started. A comment swallowed into the RDATA by an
    /// escape that never ended is stripped again by the record parser
    /// downstream, so the record comes out the same either way and the test
    /// passes without testing anything. Two versions of it did, and the mutation
    /// run is what said so both times.
    /// </summary>
    [Test]
    public void An_Escape_Quotes_One_Character_And_Not_The_Rest_Of_The_Line()
    {

        Assert.That(DNSZoneFile.TryParse("esc  IN  TXT  has\\;semi  (\n" +
                                         "     more\n" +
                                         "     )\n",
                                         out var records, out var error, Origin),
                    Is.True,
                    error);

        Assert.Multiple(() => {

            Assert.That(records, Has.Count.EqualTo(1),
                        "the parenthesis after the escape still groups the three lines into one record");

            Assert.That(((TXT) records!.Single()).Strings,
                        Is.EqualTo(new[] { "has\\;semi more" }),
                        "and the escaped semicolon is data inside it");

        });

    }

    #endregion

    #region A_Parenthesis_Behind_A_Backslash_Does_Not_Continue_The_Line()

    /// <summary>
    /// The same escape governs the other character §5.1 gives a meaning to:
    /// "Parentheses are used to group data that crosses a line boundary". A
    /// quoted parenthesis is data, so it must not open a group — a record that
    /// swallowed the following line would take a second record with it.
    /// </summary>
    [Test]
    public void A_Parenthesis_Behind_A_Backslash_Does_Not_Continue_The_Line()
    {

        Assert.That(DNSZoneFile.TryParse("one  IN  TXT  literal\\(paren\n" +
                                         "two  IN  A    192.0.2.2\n",
                                         out var records, out var error, Origin),
                    Is.True,
                    error);

        Assert.That(records, Has.Count.EqualTo(2),
                    "the escaped parenthesis did not swallow the line after it");

    }

    #endregion

}

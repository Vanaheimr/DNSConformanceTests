using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.WireFormat.Tests;

/// <summary>
/// RFC 1035 §2.3.1/§2.3.4/§4.1.4/§5.1 and RFC 4343 — what a domain name is made
/// of, how long it is allowed to be, what a backslash means in its presentation
/// form, and which two names are the same name.
///
/// Hermod holds a name in two types, and the split is a real one: <c>DomainName</c>
/// is host name syntax (letters, digits and hyphens — RFC 1035 §2.3.1), while
/// <c>DNSServiceName</c> is the presentation format of a name (RFC 1035 §5.1),
/// which is a strictly larger language. Both are exercised here against the same
/// rules, because a rule that holds for one of them must hold for the other.
/// </summary>
[TestFixture]
[Property("RFC", "1035")]
public class NameSyntaxAndLimitTests
{

    #region (helper) WireLength(Name)

    /// <summary>
    /// The length of a name's wire form, counted by this suite rather than asked
    /// of Hermod: one length octet plus the label for every label, and the zero
    /// octet of the root (RFC 1035 §3.1).
    /// </summary>
    private static Int32 WireLength(params String[] Labels)
        => Labels.Sum(label => 1 + Encoding.UTF8.GetByteCount(label)) + 1;

    #endregion


    // ------------------------------------------------------------------ null

    #region A_Null_Name_Is_Null_Or_Empty()

    /// <summary>
    /// The three IsNullOrEmpty/IsNotNullOrEmpty pairs — one per name type — all
    /// have to answer for a null receiver, which is the only reason an extension
    /// method rather than a property exists.
    /// </summary>
    [Test]
    public void A_Null_Name_Is_Null_Or_Empty()
    {

        DomainName?      nullDomainName   = null;
        DNSServiceName?  nullServiceName  = null;
        IDomainName?     nullInterface    = null;

        Assert.Multiple(() => {

            Assert.That(nullDomainName. IsNullOrEmpty(),     Is.True,  "a null domain name is null or empty");
            Assert.That(nullDomainName. IsNotNullOrEmpty(),  Is.False, "a null domain name is not 'not null or empty'");

            Assert.That(nullServiceName.IsNullOrEmpty(),     Is.True,  "a null service name is null or empty");
            Assert.That(nullServiceName.IsNotNullOrEmpty(),  Is.False, "a null service name is not 'not null or empty'");

            Assert.That(nullInterface.  IsNullOrEmpty(),     Is.True,  "a null IDomainName is null or empty");
            Assert.That(nullInterface.  IsNotNullOrEmpty(),  Is.False, "a null IDomainName is not 'not null or empty'");

        });

    }

    #endregion

    #region A_Parsed_Name_Is_Not_Null_Or_Empty()

    [Test]
    public void A_Parsed_Name_Is_Not_Null_Or_Empty()
    {

        var domainName   = DomainName.    Parse("example.com");
        var serviceName  = DNSServiceName.Parse("_sip._tcp.example.com.");
        IDomainName asInterface = domainName;

        Assert.Multiple(() => {

            Assert.That(domainName. IsNullOrEmpty(),     Is.False);
            Assert.That(domainName. IsNotNullOrEmpty(),  Is.True);

            Assert.That(serviceName.IsNullOrEmpty(),     Is.False);
            Assert.That(serviceName.IsNotNullOrEmpty(),  Is.True);

            Assert.That(asInterface.IsNullOrEmpty(),     Is.False);
            Assert.That(asInterface.IsNotNullOrEmpty(),  Is.True);

        });

    }

    #endregion


    // ------------------------------------------------------- label accessors

    #region A_Single_Label_Name_Has_No_Parent()

    /// <summary>
    /// RFC 1035 §3.1: a name is a sequence of labels, and the parent of a name is
    /// that sequence without its first label. A single-label name's parent is the
    /// root, which this API reports as null rather than as an empty name.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §3.1")]
    public void A_Single_Label_Name_Has_No_Parent()
    {

        Assert.Multiple(() => {

            Assert.That(DomainName.Parse("com.").            ParentDomain,
                        Is.Null,
                        "a one-label name has no parent below the root");

            Assert.That(DomainName.Parse("example.com.").    ParentDomain?.FullName,
                        Is.EqualTo("com."),
                        "the parent of a two-label name is its last label");

            Assert.That(DomainName.Parse("www.example.com.").ParentDomain?.FullName,
                        Is.EqualTo("example.com."));

        });

    }

    #endregion

    #region The_Second_Level_Domain_Needs_Two_Labels()

    [Test]
    public void The_Second_Level_Domain_Needs_Two_Labels()
    {

        var oneLabel  = DomainName.Parse("com.");
        var twoLabels = DomainName.Parse("example.com.");

        Assert.Multiple(() => {

            Assert.That(oneLabel. SecondLevelDomain,               Is.Empty,
                        "a one-label name has no second-level domain");
            Assert.That(oneLabel. SecondLevelDomainName,           Is.Null);

            Assert.That(twoLabels.SecondLevelDomain,               Is.EqualTo("example"),
                        "two labels are exactly enough for a second-level domain");
            Assert.That(twoLabels.SecondLevelDomainName?.FullName, Is.EqualTo("example.com."));

            Assert.That(DomainName.Parse("www.example.com.").SecondLevelDomain,
                        Is.EqualTo("example"),
                        "the second-level domain is counted from the right");

        });

    }

    #endregion


    // ------------------------------------------------------- what is a label

    #region An_Underscore_Label_Is_Not_A_Host_Name()

    /// <summary>
    /// RFC 1035 §2.3.1 gives host name syntax as letters, digits and hyphens; an
    /// underscore is none of those. RFC 2181 §11 then makes clear that the DNS
    /// itself imposes no such restriction on an owner name, which is why the
    /// lenient parser exists and why the strict one has to keep refusing.
    /// </summary>
    [Test]
    [Property("RFC", "2181 §11")]
    public void An_Underscore_Label_Is_Not_A_Host_Name()
    {

        Assert.Multiple(() => {

            Assert.That(DomainName.TryParse       ("_dmarc.example.com", out _, out _),
                        Is.False,
                        "an underscore label is not host name syntax");

            Assert.That(DomainName.TryParseLenient("_dmarc.example.com", out var lenient, out _),
                        Is.True,
                        "but it is a perfectly ordinary owner name");

            Assert.That(lenient?.FullName, Is.EqualTo("_dmarc.example.com."));

        });

    }

    #endregion

    #region An_Empty_Domain_Name_Is_Rejected()

    [Test]
    public void An_Empty_Domain_Name_Is_Rejected()
    {

        Assert.Multiple(() => {

            Assert.That(DomainName.    TryParse("",    out _, out var e1), Is.False);
            Assert.That(e1, Does.Contain("must not be null or empty"));

            Assert.That(DomainName.    TryParse("   ", out _, out var e2), Is.False,
                        "a name of nothing but whitespace is empty too");
            Assert.That(e2, Does.Contain("must not be null or empty"));

            Assert.That(DNSServiceName.TryParse("",    out _, out var e3), Is.False);
            Assert.That(e3, Does.Contain("must not be null or empty"));

        });

    }

    #endregion

    #region A_Name_Is_A_Subdomain_Only_Of_A_Real_Name()

    [Test]
    public void A_Name_Is_A_Subdomain_Only_Of_A_Real_Name()
    {

        var www = DomainName.Parse("www.example.com.");

        Assert.Multiple(() => {

            Assert.That(www.IsSubdomainOf(null!),                             Is.False,
                        "nothing is a subdomain of no name at all");

            Assert.That(www.IsSubdomainOf(DomainName.Parse("example.com.")),  Is.True);

            Assert.That(www.IsSubdomainOf(DomainName.Parse("EXAMPLE.COM.")),  Is.True,
                        "RFC 4343: the comparison is case-insensitive");

            Assert.That(www.IsSubdomainOf(DomainName.Parse("example.org.")),  Is.False);

        });

    }

    #endregion


    // -------------------------------------------------------- RFC 1035 §5.1

    #region An_Escaped_Dot_Belongs_To_Its_Label()

    /// <summary>
    /// RFC 1035 §5.1: "\X where X is any character other than a digit (0-9), is
    /// used to quote that character so that its special meaning does not apply.
    /// For example, \. can be used to place a dot character in a label." The dot
    /// that separates labels and the dot inside a label are written the same way
    /// and told apart only by the backslash.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §5.1")]
    public void An_Escaped_Dot_Belongs_To_Its_Label()
    {

        Assert.That(DNSServiceName.TryParse("a\\.b.example.", out var name, out var error),
                    Is.True,
                    error);

        Assert.Multiple(() => {

            Assert.That(name!.Labels.Count, Is.EqualTo(2),
                        "the escaped dot does not start a new label");

            Assert.That(name.Labels[0],     Is.EqualTo("a.b"),
                        "the label holds a literal dot");

            Assert.That(name.Labels[1],     Is.EqualTo("example"));

            Assert.That(name.FullName,      Is.EqualTo("a\\.b.example."),
                        "and writing it back out escapes the dot again");

        });

        // The other half of the same rule, and the reason there are two types.
        // §5.1 is master file syntax, not host name syntax: RFC 1035 §2.3.1 and
        // RFC 1123 §2.1 give a host name letters, digits and hyphens, and a label
        // made of those has no character with a special meaning to escape. So the
        // host name parser is right to refuse what the presentation parser reads.
        Assert.That(DomainName.TryParse("a\\.b.example.", out _, out _),
                    Is.False,
                    "an escape is presentation format, and a host name has none");

    }

    #endregion

    #region A_Name_That_Is_Nothing_But_An_Escaped_Dot()

    /// <summary>
    /// The smallest name in which a backslash changes the reading: "\." is one
    /// label consisting of a single dot character, not the root. Whether the
    /// trailing dot terminates the name depends on the backslash in front of it,
    /// which is at the very first position of the text.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Name_That_Is_Nothing_But_An_Escaped_Dot()
    {

        Assert.That(DNSServiceName.TryParse("\\.", out var name, out var error),
                    Is.True,
                    error);

        Assert.Multiple(() => {

            Assert.That(name!.Labels.Count, Is.EqualTo(1),
                        "an escaped dot is a label, not a root terminator");

            Assert.That(name.Labels[0],     Is.EqualTo("."));

        });

        Assert.That(DNSServiceName.TryParse(".", out var root, out _),
                    Is.True);

        Assert.That(root!.Labels, Is.Empty,
                    "while an unescaped dot on its own is the root");

    }

    #endregion

    #region A_Backslash_Escapes_The_Backslash()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Backslash_Escapes_The_Backslash()
    {

        Assert.That(DNSServiceName.TryParse("a\\\\b.example.", out var name, out var error),
                    Is.True,
                    error);

        Assert.Multiple(() => {

            Assert.That(name!.Labels[0], Is.EqualTo("a\\b"),
                        "two backslashes are one backslash in the label");

            Assert.That(name.FullName,   Is.EqualTo("a\\\\b.example."));

        });

    }

    #endregion

    #region A_Name_Ending_In_An_Incomplete_Escape_Is_Rejected()

    /// <summary>
    /// A backslash with nothing behind it quotes nothing. The parser has to say
    /// so rather than read past the end of the text.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Name_Ending_In_An_Incomplete_Escape_Is_Rejected()
    {

        Assert.Multiple(() => {

            Assert.That(DNSServiceName.TryParse("a\\", out _, out var error),
                        Is.False,
                        "a trailing backslash escapes nothing");

            Assert.That(error, Does.Contain("incomplete escape"));

            Assert.That(DNSServiceName.TryParse("\\", out _, out _),
                        Is.False,
                        "and a name of nothing but a backslash is no name");

        });

    }

    #endregion

    #region A_Name_With_An_Empty_Label_Is_Rejected()

    /// <summary>
    /// RFC 1035 §3.1: only the root has a zero-length label, and it is the last
    /// one. Two dots in a row ask for an empty label somewhere else.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §3.1")]
    public void A_Name_With_An_Empty_Label_Is_Rejected()
    {

        Assert.Multiple(() => {

            Assert.That(DNSServiceName.TryParse("a..b", out _, out var inner),
                        Is.False,
                        "an empty label in the middle of a name");
            Assert.That(inner, Does.Contain("empty label"));

            Assert.That(DNSServiceName.TryParse("a..", out _, out var trailing),
                        Is.False,
                        "an empty label just before the root terminator");
            Assert.That(trailing, Does.Contain("empty label"));

        });

    }

    #endregion

    #region Labels_Handed_Over_Directly_Are_Validated_Too()

    /// <summary>
    /// <c>FromLabels</c> skips the presentation format altogether, which is the
    /// point of it — a label holding a dot needs no escaping there. The rules
    /// about what a label may contain still apply.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §2.3.4")]
    public void Labels_Handed_Over_Directly_Are_Validated_Too()
    {

        Assert.Multiple(() => {

            Assert.That(() => DNSServiceName.FromLabels("example", ""),
                        Throws.ArgumentException,
                        "an empty label is no label");

            Assert.That(() => DNSServiceName.FromLabels(new String('a', 64), "example"),
                        Throws.ArgumentException,
                        "RFC 1035 §2.3.4: labels are 63 octets or less");

            Assert.That(DNSServiceName.FromLabels("a.b", "example").Labels[0],
                        Is.EqualTo("a.b"),
                        "but a dot inside a label needs no escaping here");

        });

    }

    #endregion

    #region A_Label_That_Is_Not_Valid_Unicode_Is_Rejected()

    /// <summary>
    /// A label is octets on the wire, and Hermod encodes it as UTF-8. A lone
    /// surrogate is not encodable: it has to be refused rather than quietly
    /// replaced by U+FFFD, which would put octets on the wire that the caller
    /// never asked for.
    /// </summary>
    [Test]
    public void A_Label_That_Is_Not_Valid_Unicode_Is_Rejected()
    {

        Assert.That(() => DNSServiceName.FromLabels("bad\uD800label", "example"),
                    Throws.ArgumentException,
                    "an unpaired surrogate cannot be encoded as UTF-8");

    }

    #endregion


    // ------------------------------------------------------- RFC 1035 §2.3.4

    #region A_Name_Of_Exactly_255_Octets_Is_Accepted()

    /// <summary>
    /// RFC 1035 §2.3.4: "names 255 octets or less". The octets are the wire form
    /// of §3.1 — a length octet and its label for each label, plus the root's
    /// zero octet — not the characters of the presentation form, and the limit is
    /// inclusive.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §2.3.4")]
    public void A_Name_Of_Exactly_255_Octets_Is_Accepted()
    {

        var labels = new[] {
                         new String('a', 63),
                         new String('b', 63),
                         new String('c', 63),
                         new String('d', 61)
                     };

        Assert.That(WireLength(labels), Is.EqualTo(255),
                    "this suite's own count of the wire form");

        var text = String.Join('.', labels) + ".";

        Assert.That(DomainName.    TryParse(text, out _, out var domainError),   Is.True, domainError);
        Assert.That(DNSServiceName.TryParse(text, out _, out var serviceError),  Is.True, serviceError);

    }

    #endregion

    #region A_Name_Of_256_Octets_Is_Rejected()

    [Test]
    [Property("RFC", "1035 §2.3.4")]
    public void A_Name_Of_256_Octets_Is_Rejected()
    {

        var labels = new[] {
                         new String('a', 63),
                         new String('b', 63),
                         new String('c', 63),
                         new String('d', 62)
                     };

        Assert.That(WireLength(labels), Is.EqualTo(256),
                    "one octet over the limit");

        var text = String.Join('.', labels) + ".";

        Assert.Multiple(() => {

            Assert.That(DomainName.    TryParse(text, out _, out _), Is.False,
                        "RFC 1035 §2.3.4: names are 255 octets or less");

            Assert.That(DNSServiceName.TryParse(text, out _, out _), Is.False,
                        "and the same limit holds for the presentation parser");

        });

    }

    #endregion

    #region A_Wildcard_Name_Is_Measured_Like_Any_Other()

    /// <summary>
    /// RFC 4592 §2.1.1 makes the asterisk an ordinary label as far as the wire
    /// format is concerned, so it costs its two octets like any other label and
    /// the §2.3.4 limit is measured over the whole name including it.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §2.3.4")]
    public void A_Wildcard_Name_Is_Measured_Like_Any_Other()
    {

        var labels = new[] {
                         "*",
                         new String('a', 63),
                         new String('b', 63),
                         new String('c', 63),
                         new String('d', 60)
                     };

        Assert.That(WireLength(labels), Is.EqualTo(256),
                    "the asterisk label costs its length octet too");

        var text = String.Join('.', labels) + ".";

        Assert.Multiple(() => {

            Assert.That(DomainName.    TryParseLenient(text, out _, out _),
                        Is.False,
                        "RFC 1035 §2.3.4: names are 255 octets or less, asterisk included");

            Assert.That(DNSServiceName.TryParse       (text, out _, out _),
                        Is.False,
                        "and the two name types have to agree about it");

        });

    }

    #endregion

    #region A_Wildcard_Name_Of_Exactly_255_Octets_Is_Accepted()

    [Test]
    [Property("RFC", "4592 §2.1.1")]
    public void A_Wildcard_Name_Of_Exactly_255_Octets_Is_Accepted()
    {

        var labels = new[] {
                         "*",
                         new String('a', 63),
                         new String('b', 63),
                         new String('c', 63),
                         new String('d', 59)
                     };

        Assert.That(WireLength(labels), Is.EqualTo(255));

        var text = String.Join('.', labels) + ".";

        Assert.That(DomainName.TryParseLenient(text, out var name, out var error),
                    Is.True,
                    error);

        Assert.That(name!.Labels[0], Is.EqualTo("*"));

        Assert.That(DNSServiceName.TryParse(text, out _, out var serviceError),
                    Is.True,
                    serviceError);

    }

    #endregion


    // ------------------------------------------------------------- RFC 4343

    #region Every_Ascii_Letter_Folds_And_Nothing_Else_Does()

    /// <summary>
    /// RFC 4343: DNS names compare case-insensitively, and the case in question
    /// is ASCII only — the rule is about the 26 letters, not about whatever the
    /// current culture believes a letter to be.
    /// </summary>
    [Test]
    [Property("RFC", "4343")]
    public void Every_Ascii_Letter_Folds_And_Nothing_Else_Does()
    {

        Assert.Multiple(() => {

            for (var letter = 'A'; letter <= 'Z'; letter++)
            {

                var upper = DNSServiceName.Parse($"{letter}.example.");
                var lower = DNSServiceName.Parse($"{Char.ToLowerInvariant(letter)}.example.");

                Assert.That(upper.Equals(lower),      Is.True,
                            $"'{letter}' and '{Char.ToLowerInvariant(letter)}' are the same label");

                Assert.That(upper.GetHashCode(),      Is.EqualTo(lower.GetHashCode()),
                            $"'{letter}' has to hash like its lower case");

                Assert.That(upper.CompareTo(lower),   Is.Zero,
                            $"'{letter}' has to order like its lower case");

            }

            var full = DNSServiceName.Parse("XYZ.Example.");

            Assert.That(full.Equals(DNSServiceName.Parse("xyz.example.")), Is.True);

            Assert.That(full.FullName, Is.EqualTo("XYZ.Example."),
                        "RFC 1035 §2.3.3: the case itself is preserved");

        });

    }

    #endregion


    // ------------------------------------------------------- RFC 1035 §4.1.4

    #region A_Name_At_The_Last_Pointable_Offset_Is_Recorded()

    /// <summary>
    /// RFC 1035 §4.1.4: a compression pointer carries a 14-bit offset, so 16383 is
    /// the last position in a message that can ever be pointed at. It can be, and
    /// a name that starts there is still a compression target.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1.4")]
    public void A_Name_At_The_Last_Pointable_Offset_Is_Recorded()
    {

        var domainOffsets  = new Dictionary<String, Int32>();
        var serviceOffsets = new Dictionary<String, Int32>();

        DomainName.    Parse("example.com.").Serialize(new MemoryStream(), 0x3FFF, true, domainOffsets);
        DNSServiceName.Parse("example.com.").Serialize(new MemoryStream(), 0x3FFF, true, serviceOffsets);

        Assert.Multiple(() => {

            Assert.That(domainOffsets,  Does.ContainKey("example.com.").WithValue(0x3FFF),
                        "16383 is a representable pointer offset");

            Assert.That(serviceOffsets, Does.ContainKey("example.com.").WithValue(0x3FFF));

            // The second suffix, "com.", starts eight octets further in and is
            // already out of range — so exactly one of the two was recorded.
            Assert.That(domainOffsets,  Has.Count.EqualTo(1),
                        "and the suffix behind it is not");

            Assert.That(serviceOffsets, Has.Count.EqualTo(1));

        });

    }

    #endregion

    #region A_Name_Beyond_The_Pointer_Range_Is_Never_Recorded()

    /// <summary>
    /// One octet further and the offset no longer fits in fourteen bits. Recording
    /// it would hand a later name a pointer whose top bits are silently dropped,
    /// which does not point where the name is: the message would decode to
    /// something nobody wrote.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1.4")]
    public void A_Name_Beyond_The_Pointer_Range_Is_Never_Recorded()
    {

        var domainOffsets  = new Dictionary<String, Int32>();
        var serviceOffsets = new Dictionary<String, Int32>();

        DomainName.    Parse("example.com.").Serialize(new MemoryStream(), 0x4000, true, domainOffsets);
        DNSServiceName.Parse("example.com.").Serialize(new MemoryStream(), 0x4000, true, serviceOffsets);

        Assert.Multiple(() => {

            Assert.That(domainOffsets,  Is.Empty,
                        "16384 cannot be reached by a 14-bit pointer");

            Assert.That(serviceOffsets, Is.Empty);

        });

    }

    #endregion

    #region A_Name_Beyond_The_Pointer_Range_Is_Still_Written_Out_In_Full()

    /// <summary>
    /// Not being a compression target is not the same as not being written. The
    /// name itself still has to appear on the wire, uncompressed.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1.4")]
    public void A_Name_Beyond_The_Pointer_Range_Is_Still_Written_Out_In_Full()
    {

        var stream = new MemoryStream();

        DomainName.Parse("example.com.").Serialize(stream, 0x4000, true, []);

        Assert.That(stream.ToArray(),
                    Is.EqualTo(new Byte[] {
                        7, (Byte) 'e', (Byte) 'x', (Byte) 'a', (Byte) 'm', (Byte) 'p', (Byte) 'l', (Byte) 'e',
                        3, (Byte) 'c', (Byte) 'o', (Byte) 'm',
                        0
                    }));

    }

    #endregion

    #region The_Root_Is_A_Single_Zero_Octet()

    /// <summary>
    /// RFC 1035 §3.1: the root is the null label, and a name that is nothing but
    /// the root is nothing but the terminating zero octet. Two of them would be an
    /// empty label followed by the root, which is a different — and malformed —
    /// name.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §3.1")]
    public void The_Root_Is_A_Single_Zero_Octet()
    {

        var domainStream  = new MemoryStream();
        var serviceStream = new MemoryStream();

        DomainName.    Parse(".").Serialize(domainStream,  0, true, []);
        DNSServiceName.Parse(".").Serialize(serviceStream, 0, true, []);

        Assert.Multiple(() => {

            Assert.That(domainStream. ToArray(), Is.EqualTo(new Byte[] { 0 }));
            Assert.That(serviceStream.ToArray(), Is.EqualTo(new Byte[] { 0 }));

        });

    }

    #endregion


    // ---------------------------------------------------------------- order

    #region Domain_Names_Order_By_Their_Folded_Text()

    /// <summary>
    /// The four ordering operators have to agree with CompareTo at the one place
    /// where they differ from each other: two names that are equal. Less-than is
    /// false there and less-or-equal is true, and a test that only ever compares
    /// two different names cannot tell the two operators apart.
    /// </summary>
    [Test]
    [Property("RFC", "4343")]
    public void Domain_Names_Order_By_Their_Folded_Text()
    {

        var a     = DomainName.Parse("a.example.");
        var b     = DomainName.Parse("b.example.");
        var aGain = DomainName.Parse("A.example.");

        Assert.Multiple(() => {

            Assert.That(a <  b, Is.True);
            Assert.That(a <= b, Is.True);
            Assert.That(a >  b, Is.False);
            Assert.That(a >= b, Is.False);

            Assert.That(a <  aGain, Is.False, "equal names are not less than each other");
            Assert.That(a <= aGain, Is.True,  "but they are less than or equal");
            Assert.That(a >  aGain, Is.False, "equal names are not greater than each other");
            Assert.That(a >= aGain, Is.True,  "but they are greater than or equal");

        });

    }

    #endregion

    #region Service_Names_Order_By_Their_Folded_Text()

    [Test]
    [Property("RFC", "4343")]
    public void Service_Names_Order_By_Their_Folded_Text()
    {

        var a     = DNSServiceName.Parse("a.example.");
        var b     = DNSServiceName.Parse("b.example.");
        var aGain = DNSServiceName.Parse("A.example.");

        Assert.Multiple(() => {

            Assert.That(a <  b, Is.True);
            Assert.That(a <= b, Is.True);
            Assert.That(a >  b, Is.False);
            Assert.That(a >= b, Is.False);

            Assert.That(a <  aGain, Is.False, "equal names are not less than each other");
            Assert.That(a <= aGain, Is.True,  "but they are less than or equal");
            Assert.That(a >  aGain, Is.False, "equal names are not greater than each other");
            Assert.That(a >= aGain, Is.True,  "but they are greater than or equal");

        });

    }

    #endregion

}

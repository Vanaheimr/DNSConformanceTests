using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.SecureTransports.Tests;

/// <summary>
/// Which certificate vouches for which host name.
///
/// RFC 8310 §8.1 gives a DNS-over-TLS client its authentication duty, and the
/// name comparison it points at is RFC 9525's — the document that replaced
/// RFC 6125 in 2023 and settled the cases RFC 6125 had left as SHOULD NOTs.
/// <c>DNSNamePattern</c> is that comparison, and every certificate Hermod checks
/// over DoT or DoH goes through it.
///
/// First entry from the mutation sweep's second block: the code every query
/// passes through rather than the record types. Twenty-two of its lines could be
/// changed without a test in this repository noticing — and it is the one place
/// where being wrong means trusting a certificate that was issued for something
/// else.
///
/// The wildcard rules read backwards if you know the DNS ones. In a zone,
/// RFC 4592's <c>*.foo.example</c> can stand for a name several labels deeper.
/// In a certificate it cannot: §7.1 says a wildcard vouches "for any
/// single-label hostnames within their domain, but not multiple levels of
/// domains".
/// </summary>
[TestFixture]
[Property("RFC", "9525 §6.3, 8310 §8.1")]
public class CertificateNameMatchingTests
{

    #region Data

    private static DNSNamePattern Pattern(String Text)
    {
        Assert.That(DNSNamePattern.TryParse(Text, out var pattern, out var error),
                    Is.True,
                    $"'{Text}' should be a valid presented identifier: {error}");
        return pattern!;
    }

    private static String Refuse(String Text)
    {
        Assert.That(DNSNamePattern.TryParse(Text, out _, out var error),
                    Is.False,
                    $"'{Text}' is not a valid presented identifier and must not parse as one");
        Assert.That(error, Is.Not.Null);
        return error!;
    }

    #endregion


    #region What a certificate may present (RFC 9525 §6.3)

    [Test]
    [Property("RFC", "9525 §6.3")]
    [TestCase("",     TestName = "nothing at all")]
    [TestCase("   ",  TestName = "only blanks")]
    public void A_Presented_Identifier_Has_To_Be_Something(String Text)
    {

        // The identifier is what the certificate claims to be. An empty claim is
        // not a weak claim, it is no claim, and a comparison that accepts one has
        // to decide what it covers.
        Assert.That(Refuse(Text), Is.Not.Empty);

    }

    [Test]
    [Property("RFC", "9525 §6.3")]
    [TestCase("*.*.example.com",   TestName = "a wildcard in two labels")]
    [TestCase("www.*.example.com", TestName = "a wildcard that is not the left-most label")]
    [TestCase("w*.example.com",    TestName = "a wildcard after a character")]
    [TestCase("*w.example.com",    TestName = "a wildcard before a character")]
    [TestCase("f*o.example.com",   TestName = "a wildcard inside a label")]
    public void A_Wildcard_Is_The_Whole_Left_Most_Label_Or_It_Is_Nothing(String Text)
    {

        // RFC 9525 §6.3, the two requirements, and what happens when they are not
        // met: "The wildcard character appears only as the complete content of
        // the left-most label" — and "If the requirements are not met, the
        // presented identifier is invalid and MUST be ignored."
        //
        // The partial forms are the ones worth naming. RFC 6125 had tolerated
        // "f*.example.com" as a SHOULD NOT and implementations disagreed about
        // what it covered; RFC 9525 made it invalid outright. Reading one as a
        // wildcard means accepting a certificate for names its issuer never
        // considered.
        Assert.That(Refuse(Text),
                    Does.Contain("left-most label"),
                    "the message should say which of the two rules was broken");

    }

    [Test]
    [Property("RFC", "9525 §6.3")]
    [Property("RFC", "9525 §3")]
    public void A_Wildcard_Needs_A_Domain_To_Be_A_Wildcard_Of()
    {

        // A bare "*" meets the letter of both requirements — one wildcard
        // character, and it is the complete content of the left-most label — and
        // is refused anyway. It would vouch for every single-label name there is,
        // "localhost" among them. §3 lets an application be stricter about
        // wildcards than the document, and there is nothing here worth being less
        // strict for.
        Assert.That(Refuse("*"), Is.Not.Empty);

    }

    [Test]
    [Property("RFC", "9525 §6.3")]
    [TestCase("..",             TestName = "two separators and no labels")]
    [TestCase("exa mple.com",   TestName = "a blank inside a label")]
    public void What_Is_Not_A_Name_Below_The_Wildcard_Is_Not_A_Pattern(String Text)
    {

        // What remains once a well-formed wildcard label is taken off the front
        // is an ordinary host name, and it has to be one.
        Assert.That(Refuse(Text), Is.Not.Empty);

    }

    [Test]
    [Property("RFC", "9525 §6.3")]
    [TestCase("www.example.com", false, TestName = "a plain host name")]
    [TestCase("*.example.com",   true,  TestName = "a wildcard over one domain")]
    [TestCase("*.a.b.example",   true,  TestName = "a wildcard over a deeper domain")]
    public void A_Well_Formed_Identifier_Is_Taken_As_One(String Text, Boolean IsWildcard)
    {

        var pattern = Pattern(Text);

        Assert.That(pattern.IsWildcard, Is.EqualTo(IsWildcard));

    }

    [Test]
    [Property("RFC", "9525 §6.3")]
    public void An_Invalid_Identifier_Is_Ignored_Rather_Than_Fatal()
    {

        // "the presented identifier is invalid and MUST be ignored" — ignored,
        // not rejected along with the rest. A certificate carrying one bad
        // subjectAltName and one good one still vouches for the good one, and a
        // reader that gave up on the first would fail a connection the RFC says
        // should succeed.
        var patterns = DNSNamePattern.ParseAll([
                           "*.*.example.com",
                           "www.example.com",
                           "*",
                           "*.example.com"
                       ]).ToArray();

        Assert.That(patterns.Select(p => p.FullName),
                    Is.EqualTo(new[] { "www.example.com", "*.example.com" }));

    }

    #endregion


    #region What a wildcard covers (RFC 9525 §6.3, §7.1)

    [Test]
    [Property("RFC", "9525 §7.1")]
    [TestCase("www.example.com",   true,  TestName = "one label above the domain")]
    [TestCase("example.com",       false, TestName = "the domain itself — no label to stand for")]
    [TestCase("a.b.example.com",   false, TestName = "two labels above the domain")]
    [TestCase("a.b.c.example.com", false, TestName = "three labels above the domain")]
    public void A_Wildcard_Stands_For_Exactly_One_Label(String HostName, Boolean Matches)
    {

        // §7.1: wildcard certificates "automatically vouch for any single-label
        // hostnames within their domain, but not multiple levels of domains".
        //
        // Both ends matter. Covering too little turns a valid certificate into a
        // failed connection; covering too much is the whole reason the rule
        // exists — "a.b.example.com" may be a different operator entirely.
        Assert.That(Pattern("*.example.com").Matches(DomainName.Parse(HostName)),
                    Is.EqualTo(Matches));

    }

    [Test]
    [Property("RFC", "9525 §6.3")]
    [TestCase("www.example.org",  TestName = "a different top-level domain")]
    [TestCase("www.other.com",    TestName = "a different second-level domain")]
    [TestCase("www.exampl.com",   TestName = "a domain one letter off")]
    public void Every_Label_Below_The_Wildcard_Has_To_Match(String HostName)
    {

        // "Each label MUST match in order for the names to be considered a
        // match, except as supplemented by the rule about checking wildcard
        // labels." The wildcard supplements the left-most label and nothing else.
        Assert.That(Pattern("*.example.com").Matches(DomainName.Parse(HostName)),
                    Is.False);

    }

    [Test]
    [Property("RFC", "4343")]
    [Property("RFC", "9525 §6.3")]
    public void A_Name_Matches_Whatever_Its_Case()
    {

        // RFC 4343: DNS names compare case-insensitively, and a certificate's
        // subjectAltName is a DNS name. A comparison that reads case would fail a
        // connection over how the operator happened to type the host.
        Assert.Multiple(() => {
            Assert.That(Pattern("*.EXAMPLE.com").Matches(DomainName.Parse("WwW.example.COM")), Is.True);
            Assert.That(Pattern("WWW.Example.Com").Matches(DomainName.Parse("www.example.com")), Is.True);
        });

    }

    [Test]
    [Property("RFC", "9525 §6.3")]
    public void An_Identifier_Without_A_Wildcard_Covers_Itself_And_No_More()
    {

        var pattern = Pattern("www.example.com");

        Assert.Multiple(() => {
            Assert.That(pattern.Matches(DomainName.Parse("www.example.com")),   Is.True);
            Assert.That(pattern.Matches(DomainName.Parse("other.example.com")), Is.False);
            Assert.That(pattern.Matches(DomainName.Parse("example.com")),       Is.False);
            Assert.That(pattern.Matches(DomainName.Parse("a.www.example.com")), Is.False);
        });

    }

    [Test]
    [Property("RFC", "9525 §6.3")]
    public void Nothing_Is_Not_A_Host_Name_And_Matches_Nothing()
    {

        // The reference identifier is the name the client set out to reach. Text
        // that cannot be a host name at all is a caller's mistake, and answering
        // "no match" is the only safe reading of it — the alternative is a
        // comparison that throws inside a certificate check.
        var pattern = Pattern("*.example.com");

        Assert.Multiple(() => {
            Assert.That(pattern.Matches((DomainName?) null), Is.False);
            Assert.That(pattern.Matches((String?)     null), Is.False);
            Assert.That(pattern.Matches("not a host name"),  Is.False);
            Assert.That(pattern.Matches(""),                 Is.False);
            Assert.That(pattern.Matches("www.example.com"),  Is.True, "and a name that is one still matches");
        });

    }

    #endregion


    #region A pattern as a value

    [Test]
    public void An_Absent_Pattern_Is_Empty_Rather_Than_An_Error()
    {

        // Asked of nothing, these have to answer. A certificate with no
        // subjectAltName at all is the ordinary case they exist for.
        DNSNamePattern? nothing = null;

        Assert.Multiple(() => {
            Assert.That(nothing.IsNullOrEmpty(),    Is.True);
            Assert.That(nothing.IsNotNullOrEmpty(), Is.False);
        });

        DNSNamePattern? something = Pattern("*.example.com");

        Assert.Multiple(() => {
            Assert.That(something.IsNullOrEmpty(),    Is.False);
            Assert.That(something.IsNotNullOrEmpty(), Is.True);
        });

    }

    [Test]
    [Property("RFC", "4343")]
    public void Two_Patterns_Are_The_Same_Pattern_Or_They_Are_Not()
    {

        // The same pattern, not two patterns that cover the same names:
        // "*.example.com" and "www.example.com" are different however much they
        // overlap. Matches answers the other question.
        var one   = Pattern("*.example.com");
        var same  = Pattern("*.EXAMPLE.com");
        var other = Pattern("www.example.com");

        Assert.Multiple(() => {
            Assert.That(one.Equals(same),       Is.True,  "case is not part of the identity");
            Assert.That(one.GetHashCode(),      Is.EqualTo(same.GetHashCode()));
            Assert.That(one.Equals(other),      Is.False);
            Assert.That(one.Equals((DNSNamePattern?) null), Is.False);
        });

    }

    [Test]
    public void Patterns_Order_By_Their_Text()
    {

        // Four operators over one comparison, and each of them is a separate
        // place for it to be wrong. A type that carries an identity has to order
        // like one, or a sorted list of the names a certificate presents is not
        // sorted.
        var a = Pattern("a.example.com");
        var b = Pattern("b.example.com");

        Assert.Multiple(() => {

            Assert.That(a <  b, Is.True);
            Assert.That(a <= b, Is.True);
            Assert.That(a >  b, Is.False);
            Assert.That(a >= b, Is.False);

            Assert.That(b >  a, Is.True);
            Assert.That(b >= a, Is.True);

            Assert.That(a <= Pattern("a.example.com"), Is.True,  "equal is not less, but it is not greater either");
            Assert.That(a >= Pattern("a.example.com"), Is.True);
            Assert.That(a <  Pattern("a.example.com"), Is.False);
            Assert.That(a >  Pattern("a.example.com"), Is.False);

        });

    }

    #endregion

}

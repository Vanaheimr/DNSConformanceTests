using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 6672 §2.2 — the substitution rule on its own, away from any server or
/// resolver.
/// </summary>
/// <remarks>
/// <para>
/// One sentence defines it: "A DNAME substitution is performed by replacing the
/// suffix labels of the name being sought matching the owner name of the DNAME
/// resource record with the string of labels in the RDATA field."
/// </para>
/// <para>
/// The word doing the work is <i>labels</i>. Names are sequences of labels that
/// happen to be written with dots between them, and a rule about label suffixes
/// is not the same rule as one about character suffixes — the two disagree
/// precisely where a shorter name is spelled inside a longer one, which is
/// exactly where a redirection reaches into a zone that is not related to it.
/// </para>
/// <para>
/// Both the authoritative side and the resolver side call this, so it is tested
/// once, here, rather than twice through two transports.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "6672 §2.2")]
public class DNameSubstitutionTests
{

    private static DNAMESubstitution Substitute(String QName, String Owner, String Target, out String? Result)
    {

        var outcome = DNAME.TrySubstitute(
                          DNSServiceName.Parse(QName),
                          DNSServiceName.Parse(Owner),
                          DomainName.Parse(Target),
                          out var rewritten
                      );

        Result = rewritten?.FullName;

        return outcome;

    }


    #region Subordinate_Names_Are_Rewritten()

    [TestCase("host.old.example.",    "old.example.", "new.example.", "host.new.example.",    TestName = "Substitution__one_label_above")]
    [TestCase("a.b.c.old.example.",   "old.example.", "new.example.", "a.b.c.new.example.",   TestName = "Substitution__three_labels_above")]
    [TestCase("host.old.example.",    "old.example.", "a.b.c.net.",   "host.a.b.c.net.",      TestName = "Substitution__longer_target")]
    [TestCase("x.y.old.example.",     "example.",     "net.",         "x.y.old.net.",         TestName = "Substitution__owner_high_up")]
    public void Subordinate_Names_Are_Rewritten(String QName, String Owner, String Target, String Expected)
    {

        Assert.That(Substitute(QName, Owner, Target, out var result), Is.EqualTo(DNAMESubstitution.Redirected));

        Assert.That(result, Is.EqualTo(Expected));

    }

    #endregion

    #region The_Match_Is_Case_Insensitive()

    [Test]
    [Property("RFC", "4343")]
    public void The_Match_Is_Case_Insensitive()
    {

        // RFC 4343: names differing only in case are the same name. The prefix,
        // however, is carried over as it was written — it is the querier's
        // spelling and nothing here has cause to change it.
        Assert.That(Substitute("HoSt.OLD.Example.", "old.example.", "new.example.", out var result),
                    Is.EqualTo(DNAMESubstitution.Redirected));

        Assert.That(result, Is.EqualTo("HoSt.new.example."));

    }

    #endregion

    #region Names_That_Are_Not_Subordinate_Are_Left_Alone()

    [TestCase("old.example.",        "old.example.",     TestName = "No_substitution__the_owner_itself")]
    [TestCase("notold.example.",     "old.example.",     TestName = "No_substitution__shares_a_spelling_not_a_label_boundary")]
    [TestCase("example.",            "old.example.",     TestName = "No_substitution__above_the_owner")]
    [TestCase("other.example.",      "old.example.",     TestName = "No_substitution__beside_the_owner")]
    [TestCase("host.old.example.org.", "old.example.",   TestName = "No_substitution__owner_is_an_infix_not_a_suffix")]
    [Property("RFC", "6672 §2.3")]
    public void Names_That_Are_Not_Subordinate_Are_Left_Alone(String QName, String Owner)
    {

        // "notold.example." is the one that separates a label comparison from a
        // string comparison: it ends with the characters of "old.example." and is
        // not below it. A resolver that got this wrong would follow the DNAME to
        // "notnew.example." — a name in a zone the DNAME's owner has no
        // relationship with, reached by a redirection nobody authorized.
        //
        // "old.example." itself is the case §2.3 names outright: "the owner name
        // of a DNAME is not redirected itself."
        Assert.That(Substitute(QName, Owner, "new.example.", out var result),
                    Is.EqualTo(DNAMESubstitution.NotSubordinate));

        Assert.That(result, Is.Null);

    }

    #endregion

    #region The_Name_Limit_Is_Counted_In_Octets()

    [Test]
    [Property("RFC", "1035 §2.3.4")]
    public void The_Name_Limit_Is_Counted_In_Octets()
    {

        // Four labels of 60 are 4 × (1 + 60) + 1 = 245 octets. A one-label prefix
        // costs its length plus its own length octet, so nine characters land on
        // exactly 255 and ten go over.
        var target = new String('a', 60) + "." + new String('b', 60) + "." +
                     new String('c', 60) + "." + new String('d', 60) + ".";

        Assert.Multiple(() => {

            Assert.That(Substitute(new String('x', 9) + ".old.example.", "old.example.", target, out var fits),
                        Is.EqualTo(DNAMESubstitution.Redirected),
                        "255 octets is the largest a domain name may be, and largest is still legal");

            Assert.That(fits, Is.Not.Null);

            Assert.That(Substitute(new String('x', 10) + ".old.example.", "old.example.", target, out var over),
                        Is.EqualTo(DNAMESubstitution.ExceedsNameLimit),
                        "one octet more is not a name, and RFC 6672 §2.2 answers that with YXDOMAIN");

            Assert.That(over, Is.Null);

        });

    }

    #endregion

    #region Too_Long_Is_Told_Apart_From_Not_Applicable()

    [Test]
    [Property("RFC", "6672 §2.2")]
    public void Too_Long_Is_Told_Apart_From_Not_Applicable()
    {

        // The two failures mean opposite things to a server. A name the DNAME
        // does not cover is answered from the zone as if the DNAME were not
        // there; a name it covers but cannot build is answered YXDOMAIN with the
        // DNAME as proof. Folding both into a single "false" would make the
        // second indistinguishable from the first, and the server would answer
        // NXDOMAIN — telling every resolver that an entire subtree is absent.
        var target = new String('a', 60) + "." + new String('b', 60) + "." +
                     new String('c', 60) + "." + new String('d', 60) + ".";

        Assert.That(Substitute(new String('x', 40) + ".unrelated.example.", "old.example.", target, out _),
                    Is.EqualTo(DNAMESubstitution.NotSubordinate),
                    "a name that is not covered is not covered, however long it is");

    }

    #endregion

    #region The_Synthesized_Cname_Takes_The_Dnames_Ttl()

    [Test]
    [Property("RFC", "6672 §3.1")]
    public void The_Synthesized_Cname_Takes_The_Dnames_Ttl()
    {

        // RFC 2672 synthesized this with a TTL of zero; RFC 6672 §3.1 equates it
        // with the DNAME's and has resolvers accept either. Pinning the value is
        // only meaningful alongside which document is being read.
        var cname = DNAME.SynthesizeCNAME(
                        DNSServiceName.Parse("host.old.example."),
                        DNSServiceName.Parse("host.new.example."),
                        TimeSpan.FromSeconds(3600)
                    );

        Assert.Multiple(() => {

            Assert.That(cname.DomainName.FullName,     Is.EqualTo("host.old.example."));
            Assert.That(cname.CName.FullName,          Is.EqualTo("host.new.example."));
            Assert.That(cname.TimeToLive.TotalSeconds, Is.EqualTo(3600));
            Assert.That(cname.Class,                   Is.EqualTo(DNSQueryClasses.IN));

        });

    }

    #endregion

}

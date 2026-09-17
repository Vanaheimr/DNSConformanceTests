using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.WireFormat.Tests;

/// <summary>
/// RFC 1035 §4.1.2 — a question is a name, a type and a class, and all three of
/// them are the question. RFC 5452 §9.1 is why that matters beyond tidiness: a
/// resolver must match a response to the query it answers on the name, the class
/// and the type among other things, so a question that compared equal on two of
/// its three fields would accept an answer to a question nobody asked.
/// </summary>
[TestFixture]
[Property("RFC", "1035 §4.1.2")]
public class QuestionIdentityTests
{

    #region Data

    private static DNSQuestion Question(String Name,
                                        DNSResourceRecordTypes Type   = DNSResourceRecordTypes.A,
                                        DNSQueryClasses        Class  = DNSQueryClasses.IN)

        => new (DNSServiceName.Parse(Name), Type, Class);

    #endregion


    #region Two_Questions_Are_One_Question_Only_If_All_Three_Fields_Agree()

    /// <summary>
    /// Each of the three fields is varied on its own, so that no two of them can
    /// stand in for the third.
    /// </summary>
    [Test]
    [Property("RFC", "5452 §9.1")]
    public void Two_Questions_Are_One_Question_Only_If_All_Three_Fields_Agree()
    {

        var question = Question("example.com.", DNSResourceRecordTypes.A, DNSQueryClasses.IN);

        Assert.Multiple(() => {

            Assert.That(question.Equals(Question("example.com.", DNSResourceRecordTypes.A, DNSQueryClasses.IN)),
                        Is.True,
                        "the same name, type and class is the same question");

            Assert.That(question.Equals(Question("other.com.",   DNSResourceRecordTypes.A,    DNSQueryClasses.IN)),
                        Is.False,
                        "a different name is a different question, whatever else agrees");

            Assert.That(question.Equals(Question("example.com.", DNSResourceRecordTypes.AAAA, DNSQueryClasses.IN)),
                        Is.False,
                        "and so is a different type");

            Assert.That(question.Equals(Question("example.com.", DNSResourceRecordTypes.A,    DNSQueryClasses.CH)),
                        Is.False,
                        "and so is a different class");

            Assert.That(question.Equals(Question("other.com.",   DNSResourceRecordTypes.AAAA, DNSQueryClasses.CH)),
                        Is.False,
                        "three differences are not three chances to agree");

        });

    }

    #endregion

    #region A_Question_Is_Not_Equal_To_Nothing()

    /// <summary>
    /// <c>Equals</c> takes a nullable argument, so null is an answer it owes
    /// rather than a case it may assume away.
    /// </summary>
    [Test]
    public void A_Question_Is_Not_Equal_To_Nothing()
    {

        var question = Question("example.com.");

        Assert.Multiple(() => {

            Assert.That(question.Equals((DNSQuestion?) null), Is.False,
                        "no question equals no question at all");

            Assert.That(question.Equals((Object?) null),      Is.False);

            Assert.That(question.Equals(question),            Is.True);

        });

    }

    #endregion

    #region A_Question_Orders_By_Name_First_Then_Type_Then_Class()

    /// <summary>
    /// The order of the three fields in the comparison is itself a rule, and the
    /// only way to see it is to make the fields disagree with one another: each
    /// case below has an earlier field saying one thing and a later field saying
    /// the opposite, so a comparison that consulted them in the wrong order — or
    /// consulted a later one at all once an earlier one had decided — comes out
    /// with the other sign.
    /// </summary>
    [Test]
    public void A_Question_Orders_By_Name_First_Then_Type_Then_Class()
    {

        Assert.Multiple(() => {

            // The name says "less"; the type says "greater". The name wins.
            Assert.That(Question("a.example.", DNSResourceRecordTypes.AAAA).
                            CompareTo(Question("b.example.", DNSResourceRecordTypes.A)),
                        Is.Negative,
                        "a name that compares less decides it, whatever the type says");

            // The names agree, the type says "greater", the class says "less".
            Assert.That(Question("x.example.", DNSResourceRecordTypes.AAAA, DNSQueryClasses.IN).
                            CompareTo(Question("x.example.", DNSResourceRecordTypes.A, DNSQueryClasses.CH)),
                        Is.Positive,
                        "with the names equal the type decides it, whatever the class says");

            // Name and type agree, so the class is reached and decides.
            Assert.That(Question("x.example.", DNSResourceRecordTypes.A, DNSQueryClasses.IN).
                            CompareTo(Question("x.example.", DNSResourceRecordTypes.A, DNSQueryClasses.CH)),
                        Is.Negative,
                        "and only with both equal does the class get a say");

            // All three agree.
            Assert.That(Question("x.example.").CompareTo(Question("x.example.")),
                        Is.Zero);

        });

    }

    #endregion


    #region A_Query_Asks_For_Recursion()

    /// <summary>
    /// RFC 1035 §4.1.1: RD "directs the name server to pursue the query
    /// recursively". The short form of <c>Query</c> is what a stub resolver
    /// calls, and a stub that did not ask for recursion would get a referral it
    /// has no code to follow.
    ///
    /// Read off the header octets rather than off the object, because the bit is
    /// only worth anything once it is on the wire.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public void A_Query_Asks_For_Recursion()
    {

        var wire     = DNSPacket.Query(DNSServiceName.Parse("example.com.")).ToByteArray();
        var decoded  = RawDnsReader.Parse(wire);

        Assert.That(decoded.RD, Is.True,
                    "the default query sets RD");

    }

    #endregion

    #region A_Query_With_No_Type_Named_Asks_For_Any()

    /// <summary>
    /// RFC 1035 §4.1.2 gives every question a QTYPE, so a query that names no
    /// type still has to ask for something. The something is QTYPE 255, "*", a
    /// request for all records (§3.2.3) — and a query carrying no question at all
    /// would be a message with QDCOUNT 0, which is not a query.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §3.2.3")]
    public void A_Query_With_No_Type_Named_Asks_For_Any()
    {

        var wire     = DNSPacket.Query(DNSServiceName.Parse("example.com."),
                                       512,
                                       RecursionDesired:  true,
                                       DnssecOK:          false,
                                       EDNSOptions:       null).
                           ToByteArray();

        var decoded  = RawDnsReader.Parse(wire);

        Assert.Multiple(() => {

            Assert.That(decoded.Questions, Has.Count.EqualTo(1),
                        "naming no type is not the same as asking nothing");

            Assert.That(decoded.Questions[0].Type, Is.EqualTo(255),
                        "QTYPE 255 is ANY");

        });

    }

    #endregion

}

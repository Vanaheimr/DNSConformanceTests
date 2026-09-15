using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// The two labels RFC 2782 puts in front of a name, as a value.
///
/// RFC 2782's owner name is <c>_Service._Proto.Name</c>: two labels, each with a
/// leading underscore, and both of them part of what identifies the service.
/// <c>SRV_Spec</c> is that pair, and the sweep reported nearly every condition in
/// it as invertible — an emptiness test that answers the same for both halves,
/// an ordering that never reaches its second field, an equality that never needs
/// both to agree. Together they are the same failure finding 52's neighbour had:
/// a type that carries an identity and does not compare like one.
/// </summary>
[TestFixture]
[Property("RFC", "2782")]
public class SrvServiceSpecTests
{

    #region Both labels, or it is not a service (RFC 2782)

    [Test]
    [Property("RFC", "2782")]
    [TestCase("sip", "",    TestName = "a service with no protocol")]
    [TestCase("",    "tcp", TestName = "a protocol with no service")]
    [TestCase("",    "",    TestName = "neither")]
    [TestCase(" ",   "tcp", TestName = "a service that is only a blank")]
    [TestCase("_",   "tcp", TestName = "a service that is only its underscore")]
    public void A_Service_Specification_Needs_Both_Of_Its_Labels(String Service, String Protocol)
    {

        // RFC 2782 names the owner _Service._Proto.Name and gives neither label
        // a default. One half is not half a service: it is a name that would
        // resolve somewhere else entirely.
        Assert.That(SRV_Spec.TryParse(Service, Protocol, out var spec), Is.False,
                    $"'{Service}' / '{Protocol}' is not a service specification");

        Assert.That(spec.IsNullOrEmpty, Is.True, "and nothing usable is handed back");

    }

    [Test]
    [Property("RFC", "2782")]
    public void A_Service_Specification_With_Both_Labels_Is_One()
    {

        Assert.That(SRV_Spec.TryParse("sip", "tcp", out var spec), Is.True);

        Assert.Multiple(() => {
            Assert.That(spec.IsNullOrEmpty,    Is.False);
            Assert.That(spec.IsNotNullOrEmpty, Is.True);
            Assert.That(spec.ToString(),       Does.Contain("sip").And.Contain("tcp"));
        });

    }

    [Test]
    [Property("RFC", "2782")]
    public void The_Underscore_Is_The_Format_And_Not_The_Name()
    {

        // RFC 2782 writes the labels with a leading underscore so they cannot
        // collide with a host name. The underscore belongs to the encoding, so
        // naming the service with or without one is naming the same service.
        Assert.That(SRV_Spec.TryParse("_sip", "_tcp", out var withUnderscores), Is.True);
        Assert.That(SRV_Spec.TryParse("sip",  "tcp",  out var without),         Is.True);

        Assert.That(withUnderscores, Is.EqualTo(without));

    }

    [Test]
    [Property("RFC", "2782")]
    public void An_Absent_Service_Specification_Is_Empty_Rather_Than_An_Error()
    {

        // The nullable form of the same question, which callers ask of an
        // optional service. Asking it of nothing has to answer, not throw.
        SRV_Spec? nothing = null;

        Assert.Multiple(() => {
            Assert.That(nothing.IsNullOrEmpty(),    Is.True);
            Assert.That(nothing.IsNotNullOrEmpty(), Is.False);
        });

        SRV_Spec? something = SRV_Spec.Parse("sip", "tcp");

        Assert.Multiple(() => {
            Assert.That(something.IsNullOrEmpty(),    Is.False);
            Assert.That(something.IsNotNullOrEmpty(), Is.True);
        });

    }

    #endregion


    #region Two labels, and both of them count (RFC 2782)

    [Test]
    [Property("RFC", "2782")]
    public void Two_Services_Differing_Only_In_Their_Protocol_Are_Different()
    {

        // _sip._tcp and _sip._udp are two owner names, two SRV record sets and
        // two sets of targets. An equality that stops at the first label makes
        // them one, and a client that looked up one gets the other's endpoints.
        var tcp = SRV_Spec.Parse("sip", "tcp");
        var udp = SRV_Spec.Parse("sip", "udp");

        Assert.Multiple(() => {
            Assert.That(tcp.Equals(udp), Is.False, "the protocol is part of the identity");
            Assert.That(tcp == udp,      Is.False);
            Assert.That(tcp != udp,      Is.True);
        });

    }

    [Test]
    [Property("RFC", "2782")]
    public void Two_Services_Differing_Only_In_Their_Service_Are_Different()
    {

        var sip  = SRV_Spec.Parse("sip",  "tcp");
        var xmpp = SRV_Spec.Parse("xmpp", "tcp");

        Assert.That(sip.Equals(xmpp), Is.False, "and so is the service");

    }

    [Test]
    [Property("RFC", "2782")]
    public void The_Same_Service_Twice_Is_The_Same_Service()
    {

        var one = SRV_Spec.Parse("sip", "tcp");
        var two = SRV_Spec.Parse("sip", "tcp");

        Assert.Multiple(() => {
            Assert.That(one.Equals(two),     Is.True);
            Assert.That(one.GetHashCode(),   Is.EqualTo(two.GetHashCode()),
                        "or a set would hold both and a lookup would find neither");
        });

    }

    [Test]
    [Property("RFC", "2782")]
    public void Ordering_Reaches_The_Protocol_Only_When_The_Service_Agrees()
    {

        // Two conditions in one comparison. The service decides first, and the
        // protocol decides only the ties — a comparison that consults the second
        // field when the first has already answered sorts by the wrong one.
        var aZ = SRV_Spec.Parse("a", "z");
        var bA = SRV_Spec.Parse("b", "a");
        var aA = SRV_Spec.Parse("a", "a");

        Assert.Multiple(() => {

            Assert.That(aZ.CompareTo(bA), Is.LessThan(0),
                        "'a' before 'b', whatever the protocols are");

            Assert.That(aA.CompareTo(aZ), Is.LessThan(0),
                        "and with the services equal, the protocol breaks the tie");

            Assert.That(aA.CompareTo(aA), Is.Zero);

        });

    }

    #endregion


    #region A service nobody has resolved (RFC 2782)

    [Test]
    [Property("RFC", "2782")]
    public void Selecting_From_A_Service_With_No_Endpoints_Is_An_Answer()
    {

        // RFC 2782's client procedure begins with the SRV records it has, and
        // having none is a state it describes: "If there is no SRV RR ... the
        // client ... should fall back". Reporting that as nothing is the answer;
        // reaching into the list to find out is a crash on the ordinary path of
        // a service that has not been looked up yet.
        var manager = new DNSSRVManager();

        Assert.That(manager.SelectEndpoint("_sip._tcp.example."), Is.Null);

    }

    [Test]
    [Property("RFC", "2782")]
    public void Selecting_From_A_Service_That_Has_Endpoints_Returns_One()
    {

        var manager = new DNSSRVManager();

        manager.AddOrUpdate(
            "_sip._tcp.example.",
            [new DNSSRVEndpoint("sip.example.", 10, 100, IPPort.Parse(5060), TimeSpan.FromSeconds(300))]
        );

        var chosen = manager.SelectEndpoint("_sip._tcp.example.");

        Assert.That(chosen,         Is.Not.Null);
        Assert.That(chosen!.Port,   Is.EqualTo(IPPort.Parse(5060)));

    }

    #endregion

}

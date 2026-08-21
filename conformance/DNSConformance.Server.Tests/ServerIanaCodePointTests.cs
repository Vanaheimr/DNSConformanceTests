using NUnit.Framework;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 6895 §3.1 and §3.2 — the TYPE and CLASS registries, judged from outside
/// the server. Both spaces are partitioned rather than flat: some code points
/// may only ever appear in a question, and a responder that lets one out into a
/// record has told the reader something the registry says cannot be true.
/// </summary>
[TestFixture]
public class ServerIanaCodePointTests
{

    // RFC 6895 §3.1: "QTYPEs can only be used in queries." These are the ones
    // assigned downwards from 255, plus the two mail types RFC 1035 §3.2.3
    // defined and 6895 still lists.
    private static readonly UInt16[] QTypeOnly = [251, 252, 253, 254, 255];

    private HermodServerFixture server = null!;

    [OneTimeSetUp]
    public async Task StartServer()
    {
        server = await HermodServerFixture.StartAsync();
    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        await server.DisposeAsync();
    }


    #region A_Qtype_Only_Code_Point_Is_Never_A_Record_Type(QType)

    [Test]
    [Property("RFC", "6895 §3.1")]
    [TestCase((UInt16) 251)]     // IXFR
    [TestCase((UInt16) 252)]     // AXFR
    [TestCase((UInt16) 253)]     // MAILB
    [TestCase((UInt16) 254)]     // MAILA
    [TestCase((UInt16) 255)]     // ANY / *
    public async Task A_Qtype_Only_Code_Point_Is_Never_A_Record_Type(UInt16 QType)
    {

        // Asking with one of these is legal. Answering with a record that
        // *carries* one is not: §3.1 divides the space precisely so that a
        // cache can tell stored data from a transient query construct.
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort,
                            RawDnsWriter.Query(0x6895, ZoneFixtures.AName, QType));

        Assert.That(raw, Is.Not.Null, $"the server must answer a query for QTYPE {QType}");

        var response  = RawDnsReader.Parse(raw!);
        var offenders = response.Answers.
                            Concat(response.Authorities).
                            Concat(response.Additionals).
                            Where(rr => QTypeOnly.Contains(rr.Type)).
                            ToArray();

        Assert.That(offenders,
                    Is.Empty,
                    $"a QTYPE-only code point must not appear as a record TYPE, found {String.Join(", ", offenders.Select(rr => rr.Type))}");

    }

    #endregion

    #region A_Query_For_A_Qtype_Only_Code_Point_Is_Answered_Without_Data(QType)

    [Test]
    [Property("RFC", "6895 §3.1, 2308 §2.2")]
    [TestCase((UInt16) 253)]     // MAILB, obsolete since RFC 1035
    [TestCase((UInt16) 254)]     // MAILA, likewise
    public async Task A_Query_For_A_Qtype_Only_Code_Point_Is_Answered_Without_Data(UInt16 QType)
    {

        // There is no such thing as data of this type, so the correct answer is
        // the one RFC 2308 §2.2 describes for a name that exists without the
        // type asked for: NOERROR, nothing in the answer section, and the SOA
        // that says how long that may be believed.
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort,
                            RawDnsWriter.Query(0x6895, ZoneFixtures.AName, QType));

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(response.RCode,    Is.Zero,     "NODATA is NOERROR, not a failure");
            Assert.That(response.Answers,  Is.Empty,    $"there is no record of type {QType} to return");
            Assert.That(response.Authorities.Any(rr => rr.Type == RawDnsType.SOA),
                        Is.True,
                        "a NODATA answer cites the zone's SOA");

        });

    }

    #endregion

    #region An_Any_Query_Is_Answered_With_Data_Types()

    [Test]
    [Property("RFC", "6895 §3.1")]
    public async Task An_Any_Query_Is_Answered_With_Data_Types()
    {

        // The counterpart, and what stops the rule above from being satisfied by
        // never answering anything: QTYPE 255 must be *served*, and every record
        // it returns must carry a data TYPE. §3.1 reserves 128-255 for Q and
        // Meta TYPEs, so no answer record may fall in that band.
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort,
                            RawDnsWriter.Query(0x6895, ZoneFixtures.AName, RawDnsType.ANY));

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(response.Answers, Is.Not.Empty,
                        "a * query against a name that exists returns its records");

            Assert.That(response.Answers.Where(rr => rr.Type >= 128 && rr.Type <= 255),
                        Is.Empty,
                        "128-255 is the Q/Meta band; an answer record must carry a data TYPE");

        });

    }

    #endregion

    #region Type_Zero_Is_Never_Answered_With_Data()

    [Test]
    [Property("RFC", "6895 §3.1")]
    public async Task Type_Zero_Is_Never_Answered_With_Data()
    {

        // §3.1: RRTYPE zero "must never be allocated for ordinary use". There is
        // therefore nothing it can legitimately match.
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort,
                            RawDnsWriter.Query(0x6895, ZoneFixtures.AName, 0));

        Assert.That(raw, Is.Not.Null, "a query for TYPE 0 must be answered rather than dropped");

        var response  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(response.Answers, Is.Empty,
                        "TYPE 0 is never allocated, so no record can match it");

            Assert.That(response.Answers.Concat(response.Authorities).Concat(response.Additionals).
                            Where(rr => rr.Type == 0),
                        Is.Empty,
                        "and none may carry it either");

        });

    }

    #endregion

    #region A_Qclass_Only_Code_Point_Is_Never_A_Record_Class()

    [Test]
    [Property("RFC", "6895 §3.2")]
    public async Task A_Qclass_Only_Code_Point_Is_Never_A_Record_Class()
    {

        // §3.2 divides the CLASS space the same way, and 255 is the QCLASS the
        // question may carry. The records that come back belong to a real data
        // class — asking "any class" does not make "any class" an answer.
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort,
                            RawDnsWriter.Query(0x6895, ZoneFixtures.AName, RawDnsType.A, RawDnsClass.ANY));

        Assert.That(raw, Is.Not.Null, "a * class query must be answered");

        var response  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(response.Questions.Single().Class,
                        Is.EqualTo(RawDnsClass.ANY),
                        "the question is echoed with the QCLASS it was asked with");

            Assert.That(response.Answers, Is.Not.Empty,
                        "a * class query against a name that exists is served");

            Assert.That(response.Answers.Where(rr => rr.Class == RawDnsClass.ANY ||
                                                     rr.Class == RawDnsClass.NONE),
                        Is.Empty,
                        "254 and 255 are QCLASSes; a record must carry a data class");

        });

    }

    #endregion

}

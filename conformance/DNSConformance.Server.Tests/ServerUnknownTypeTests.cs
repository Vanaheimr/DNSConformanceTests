using NUnit.Framework;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 3597 §2/§3 — serving a zone the server cannot read.
/// </summary>
/// <remarks>
/// <para>
/// Parsing an unknown type is the easy half. The harder claim is that an
/// authoritative server can do its whole job around one: hold it, tell it apart
/// from the other types at the same name, decide it is the answer to one
/// question and not to another, synthesise it from a wildcard, and put the RDATA
/// back on the wire exactly as it arrived — all from the outer shape of a
/// record, with the RDATA never once interpreted.
/// </para>
/// <para>
/// The type codes come from the IANA private-use range, so they are unknown by
/// construction rather than by accident of this build's age.
/// </para>
/// <para>
/// Everything is observed through raw sockets and read by the independent RawDns
/// parser: no Hermod client is involved, so no shared assumption about the
/// records can make a wrong answer look right.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "3597")]
public class ServerUnknownTypeTests
{

    private HermodServerFixture server = null!;

    [OneTimeSetUp]
    public async Task StartServer()
    {
        server = await HermodServerFixture.StartAsync(
                     new HermodServerFixtureOptions {
                         Zone = ZoneFixtures.CreateOpaqueZone()
                     }
                 );
    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        await server.DisposeAsync();
    }


    private async Task<RawDnsMessage> Ask(String name, UInt16 type, UInt16 id = 0x3597)
    {

        var raw = await RawDnsProbe.UdpAsync(server.UdpPort, RawDnsWriter.Query(id, name, type));

        Assert.That(raw, Is.Not.Null, $"the server must answer a query for {name}");

        return RawDnsReader.Parse(raw!);

    }


    #region An_Unknown_Type_Is_Served_Verbatim()

    [Test]
    [Property("RFC", "3597 §3")]
    public async Task An_Unknown_Type_Is_Served_Verbatim()
    {

        var response = await Ask(ZoneFixtures.OpaqueName, ZoneFixtures.OpaqueType);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.EqualTo(0));
            Assert.That(response.AA,      Is.True);
            Assert.That(response.Answers, Has.Count.EqualTo(2), "both records of the RRset must be answered");

        });

        Assert.Multiple(() => {

            foreach (var answer in response.Answers)
            {
                Assert.That(answer.Type,           Is.EqualTo(ZoneFixtures.OpaqueType));
                Assert.That(answer.Class,          Is.EqualTo(RawDnsClass.IN));
                Assert.That(answer.Name.Canonical, Is.EqualTo(ZoneFixtures.OpaqueName.TrimEnd('.')));
            }

            // Order within an RRset is not specified, so the set is compared as a set.
            Assert.That(
                response.Answers.Select(answer => Convert.ToHexString(answer.Rdata)).OrderBy(hex => hex),
                Is.EqualTo(new[] { ZoneFixtures.OpaqueRData1, ZoneFixtures.OpaqueRData2 }.
                               Select(Convert.ToHexString).OrderBy(hex => hex)),
                "RFC 3597 §3: the RDATA has to come out the way it went in — there is nothing " +
                "in this build that could legitimately change it, because nothing here knows what it means."
            );

        });

    }

    #endregion

    #region An_Unknown_Type_Is_Not_An_Answer_To_Another_Question()

    [Test]
    [Property("RFC", "3597 §2")]
    [Property("RFC", "2308 §3")]
    public async Task An_Unknown_Type_Is_Not_An_Answer_To_Another_Question()
    {

        // The name exists and has records; none of them is an A. That is NODATA:
        // NOERROR, no answers, and the SOA in the authority section so the
        // negative answer can be cached (RFC 2308 §3). A server that treated
        // "I cannot read this type" as "this name has nothing" would send
        // NXDOMAIN here, and every resolver would cache the name as absent.
        var response = await Ask(ZoneFixtures.OpaqueName, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.EqualTo(0), "the name exists, so this is NODATA and not NXDOMAIN");
            Assert.That(response.AA,      Is.True);
            Assert.That(response.Answers, Is.Empty);

            Assert.That(response.Authorities.Any(record => record.Type == RawDnsType.SOA), Is.True,
                        "a negative answer carries the SOA (RFC 2308 §3)");

        });

    }

    #endregion

    #region A_Known_Type_Is_Answered_From_A_Name_That_Also_Holds_An_Unknown_One()

    [Test]
    [Property("RFC", "3597 §2")]
    public async Task A_Known_Type_Is_Answered_From_A_Name_That_Also_Holds_An_Unknown_One()
    {

        var response = await Ask(ZoneFixtures.OpaqueMixedName, RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.EqualTo(0));
            Assert.That(response.Answers, Has.Count.EqualTo(1),
                        "the unknown type at the same name is a different RRset and is not part of this answer");

            Assert.That(response.Answers.Single().Type,  Is.EqualTo(RawDnsType.A));
            Assert.That(response.Answers.Single().Rdata, Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.OpaqueMixedAddress)));

        });

    }

    #endregion

    #region An_Unknown_Type_Is_Answered_From_A_Name_That_Also_Holds_A_Known_One()

    [Test]
    [Property("RFC", "3597 §2")]
    public async Task An_Unknown_Type_Is_Answered_From_A_Name_That_Also_Holds_A_Known_One()
    {

        var response = await Ask(ZoneFixtures.OpaqueMixedName, ZoneFixtures.OpaqueSecondType);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.EqualTo(0));
            Assert.That(response.Answers, Has.Count.EqualTo(1));

            Assert.That(response.Answers.Single().Type,  Is.EqualTo(ZoneFixtures.OpaqueSecondType));
            Assert.That(response.Answers.Single().Rdata, Is.EqualTo(ZoneFixtures.OpaqueMixedRData));

        });

    }

    #endregion

    #region Rdata_That_Reads_As_A_Compression_Pointer_Is_Served_Unchanged()

    [Test]
    [Property("RFC", "3597 §3")]
    [Property("RFC", "3597 §4")]
    public async Task Rdata_That_Reads_As_A_Compression_Pointer_Is_Served_Unchanged()
    {

        // The RDATA is 0xC00C — a valid pointer to offset 12, which in this very
        // response is where the question name begins. Anything that took it for a
        // name would answer with "pointerish.opaque.test." in place of the two
        // octets the zone holds, and RDLENGTH would grow from 2 to 24.
        //
        // RFC 3597 §4 is why nothing may: a pointer has no business being inside
        // the RDATA of a type that is not well-known, so an implementation that
        // acts on one is acting on a structure that should not exist — and cannot
        // tell it apart from two octets of payload that happen to read that way.
        var response = await Ask(ZoneFixtures.OpaquePointerName, ZoneFixtures.OpaquePointerType);

        Assert.That(response.Answers, Has.Count.EqualTo(1));

        Assert.That(response.Answers.Single().Rdata, Is.EqualTo(ZoneFixtures.OpaquePointerRData),
                    () => "the two RDATA octets must arrive unchanged:\n" + Bytes.Dump(response.Wire));

    }

    #endregion

    #region A_Wildcard_Synthesizes_An_Unknown_Type()

    [Test]
    [Property("RFC", "3597 §2")]
    [Property("RFC", "4592 §3.3.1")]
    public async Task A_Wildcard_Synthesizes_An_Unknown_Type()
    {

        // Synthesis rewrites the owner name and nothing else (RFC 4592 §3.3.1) —
        // which is exactly what an unknown type needs, and exactly what an
        // implementation that rebuilds records field by field cannot do. The
        // wildcard label must not appear in the answer.
        var response = await Ask(ZoneFixtures.OpaqueWildcardName, ZoneFixtures.OpaqueType);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.EqualTo(0));
            Assert.That(response.AA,      Is.True);
            Assert.That(response.Answers, Has.Count.EqualTo(1));

        });

        Assert.Multiple(() => {

            Assert.That(response.Answers.Single().Name.Canonical, Is.EqualTo(ZoneFixtures.OpaqueWildcardName.TrimEnd('.')),
                        "the answer is owned by the name that was asked for, never by the wildcard");

            Assert.That(response.Answers.Single().Rdata, Is.EqualTo(ZoneFixtures.OpaqueWildcardRData),
                        "and the RDATA is copied, not rebuilt");

        });

    }

    #endregion

    #region An_Absent_Name_Is_Still_NXDOMAIN_For_An_Unknown_Type()

    [Test]
    [Property("RFC", "3597 §2")]
    public async Task An_Absent_Name_Is_Still_NXDOMAIN_For_An_Unknown_Type()
    {

        // The mirror image of the NODATA case: an unreadable QTYPE must not turn
        // a name that does not exist into one that merely has no data.
        var response = await Ask("nothing-here." + ZoneFixtures.OpaqueOrigin, ZoneFixtures.OpaqueType);

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.EqualTo(3), "NXDOMAIN");
            Assert.That(response.Answers, Is.Empty);

            Assert.That(response.Authorities.Any(record => record.Type == RawDnsType.SOA), Is.True);

        });

    }

    #endregion

    #region The_Question_Is_Echoed_With_Its_Unknown_Qtype()

    [Test]
    [Property("RFC", "3597 §2")]
    public async Task The_Question_Is_Echoed_With_Its_Unknown_Qtype()
    {

        // RFC 1035 §4.1.2: the question section is copied into the response. A
        // server that could not represent the QTYPE would have to change it, and
        // a resolver matching the answer against its outstanding query would
        // discard the response.
        var response = await Ask(ZoneFixtures.OpaqueName, ZoneFixtures.OpaqueType);

        Assert.Multiple(() => {

            Assert.That(response.Questions,             Has.Count.EqualTo(1));
            Assert.That(response.Questions[0].Type,     Is.EqualTo(ZoneFixtures.OpaqueType));
            Assert.That(response.Questions[0].Class,    Is.EqualTo(RawDnsClass.IN));
            Assert.That(response.Questions[0].Name.Canonical, Is.EqualTo(ZoneFixtures.OpaqueName.TrimEnd('.')));

        });

    }

    #endregion

}

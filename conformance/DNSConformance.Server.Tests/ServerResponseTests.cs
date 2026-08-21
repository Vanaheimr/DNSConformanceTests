using NUnit.Framework;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Server.Tests;

/// <summary>
/// RFC 1035 §4.1.1 — what a real Hermod DNSServer puts on the wire, observed
/// through raw sockets (no Hermod client involved).
/// </summary>
[TestFixture]
public class ServerResponseTests
{

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


    #region Response_Echoes_Id_And_Question_And_Sets_QR_And_AA()

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task Response_Echoes_Id_And_Question_And_Sets_QR_And_AA()
    {

        var request   = RawDnsWriter.Query(0x4711, ZoneFixtures.AName, RawDnsType.A);
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null, "server must answer");

        var response  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(response.Id,      Is.EqualTo((UInt16) 0x4711), "ID MUST be copied from the request");
            Assert.That(response.QR,      Is.True,   "QR=1");
            Assert.That(response.Opcode,  Is.Zero,   "opcode copied");
            Assert.That(response.AA,      Is.True,   "authoritative data ⇒ AA=1");
            Assert.That(response.RCode,   Is.Zero,   "NOERROR");
            Assert.That(response.Z,       Is.Zero,   "Z MUST be zero");

            Assert.That(response.Questions,                   Has.Count.EqualTo(1), "question section echoed");
            Assert.That(response.Questions[0].Name.Canonical, Is.EqualTo(ZoneFixtures.AName.TrimEnd('.')));
            Assert.That(response.Questions[0].Type,           Is.EqualTo(RawDnsType.A));
            Assert.That(response.Questions[0].Class,          Is.EqualTo(RawDnsClass.IN));

            Assert.That(response.Answers, Has.Count.EqualTo(1));
            Assert.That(response.Answers[0].Type,  Is.EqualTo(RawDnsType.A));
            Assert.That(response.Answers[0].Rdata, Is.EqualTo(RawDnsWriter.IPv4(ZoneFixtures.AAddress)));

        });

    }

    #endregion

    #region Question_Case_Is_Echoed_Unchanged()

    [Test]
    [Property("RFC", "1035 §4.1.2")]
    public async Task Question_Case_Is_Echoed_Unchanged()
    {

        // Case-preserving echo of the QNAME is what makes dns-0x20 query
        // randomization work; it is also what dig checks when it warns about
        // mismatched replies.
        var mixedCase  = "A.CoNfOrMaNcE.tEsT.";
        var request    = RawDnsWriter.Query(0x0C0C, mixedCase, RawDnsType.A);
        var raw        = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null);

        var response   = RawDnsReader.Parse(raw!);
        var echoed     = response.Questions.Single().Name.Presentation;

        Assert.Multiple(() => {

            Assert.That(echoed, Is.EqualTo(mixedCase.TrimEnd('.')),
                        "the QNAME must be echoed with its capitalization intact");

            Assert.That(response.Answers, Is.Not.Empty,
                        "…while the lookup itself is case-insensitive (RFC 1035 §2.3.3)");

            // The answer's owner name comes back in the *zone's* spelling, not the
            // query's. That is conformant: §2.3.3 is SHOULD-level and the case the
            // zone data entered with is exactly what is preserved. It only coincides
            // with the query's spelling when the server compresses the owner into a
            // pointer at the QNAME (DNSServerOptions.UseCompression, off by default) —
            // see Mixed_Case_Name_Compresses_Against_Its_Lowercase_Twin.
            Assert.That(response.Answers[0].Name.Presentation, Is.EqualTo(mixedCase.TrimEnd('.')).IgnoreCase,
                        "the answer's owner name must be the same name as the question");

        });

    }

    #endregion

    #region Unknown_Name_Yields_NXDOMAIN()

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task Unknown_Name_Yields_NXDOMAIN()
    {

        var request   = RawDnsWriter.Query(0x0003, "nonexistent.conformance.test.", RawDnsType.A);
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.EqualTo(3), "NXDOMAIN = 3");
            Assert.That(response.Answers, Is.Empty);
        });

    }

    #endregion

    #region Known_Name_Unknown_Type_Yields_NODATA()

    [Test]
    [Property("RFC", "2308 §2.2")]
    public async Task Known_Name_Unknown_Type_Yields_NODATA()
    {

        // NODATA = NOERROR with an empty answer section for a name that exists.
        var request   = RawDnsWriter.Query(0x0004, ZoneFixtures.AName, RawDnsType.AAAA);
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.Zero, "NODATA is NOERROR, not NXDOMAIN");
            Assert.That(response.Answers, Is.Empty);
        });

    }

    #endregion

    #region Unsupported_Opcode_Yields_NOTIMP()

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task Unsupported_Opcode_Yields_NOTIMP()
    {

        // Opcode 2 = STATUS, not implemented by an authoritative server.
        var request  = new RawDnsWriter()
                           .Header(0x0005, RawDnsFlags.Opcode(2), 1, 0, 0, 0)
                           .Question(ZoneFixtures.AName, RawDnsType.A)
                           .ToArray();

        var raw      = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null, "an unsupported opcode must be answered, not ignored");

        var response = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(response.RCode,   Is.EqualTo(4), "NOTIMP = 4");
            Assert.That(response.Opcode,  Is.EqualTo(2), "opcode echoed");
            Assert.That(response.QR,      Is.True);
        });

    }

    #endregion

    #region A_Notimp_Response_Echoes_No_Flag_Of_The_Opcode_It_Rejected()

    [Test]
    [Property("RFC", "1035 §4.1.1, 6895 §2")]
    public async Task A_Notimp_Response_Echoes_No_Flag_Of_The_Opcode_It_Rejected()
    {

        // ISC's genreport calls this probe "opcodeflg": opcode 15 with every
        // flag bit set. RFC 1035 §4.1.1 does say RD "is copied into the
        // response", but the bit it defines is the one that "directs the name
        // server to pursue the query recursively" — a property of a QUERY. A
        // reply of NOTIMP has said it did not understand the request, so it
        // cannot meaningfully echo a bit belonging to the opcode it rejected.
        // RFC 6895 §2 leaves the combination open; BIND clears the bit, and
        // Hermod cleared every flag here except this one (finding 40).
        var allFlags  = (UInt16) (RawDnsFlags.Opcode(15) |
                                  RawDnsFlags.AA | RawDnsFlags.TC | RawDnsFlags.RD |
                                  RawDnsFlags.RA | RawDnsFlags.AD | RawDnsFlags.CD |
                                  0x0040);                                 // the Z bit

        var request   = new RawDnsWriter().Header(0x0F15, allFlags, 0, 0, 0, 0).ToArray();
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null, "an unknown opcode must be answered, not ignored");

        var response  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {

            Assert.That(response.RCode,  Is.EqualTo(4),  "NOTIMP = 4");
            Assert.That(response.Opcode, Is.EqualTo(15), "the opcode itself is echoed — it identifies what was refused");
            Assert.That(response.QR,     Is.True,        "and QR marks this a response");

            Assert.That(response.RD,     Is.False, "RD belongs to QUERY and must not be echoed here");
            Assert.That(response.AA,     Is.False, "AA");
            Assert.That(response.TC,     Is.False, "TC");
            Assert.That(response.RA,     Is.False, "RA");
            Assert.That(response.AD,     Is.False, "AD");
            Assert.That(response.CD,     Is.False, "CD");
            Assert.That(response.Z,      Is.Zero,  "Z MUST be zero");

        });

    }

    #endregion

    #region A_Query_Still_Has_Its_Recursion_Desired_Bit_Echoed()

    [Test]
    [Property("RFC", "1035 §4.1.1, 6891 §6.1.3")]
    public async Task A_Query_Still_Has_Its_Recursion_Desired_Bit_Echoed()
    {

        // The other half, and the one that stops "never echo RD" from passing as
        // the fix. It has to travel the *error* path to be worth anything: the
        // rule above lives where a refusal is built, and a query that simply
        // succeeds never goes near it. An EDNS version of 1 is refused with
        // BADVERS by RFC 6891 §6.1.3 while the opcode stays QUERY — so §4.1.1
        // applies untouched and the bit must come back.
        var request   = RawDnsWriter.Query(0x0F16,
                                           ZoneFixtures.AName,
                                           RawDnsType.A,
                                           recursionDesired: true,
                                           ednsPayloadSize:  4096,
                                           ednsVersion:      1);

        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(response.Opcode,        Is.Zero,        "still QUERY");
            Assert.That(response.CombinedRcode, Is.EqualTo(16), "BADVERS — so this really is the refusal path");
            Assert.That(response.RD,            Is.True,        "RD is copied into the response of a QUERY, refused or not");
        });

    }

    #endregion

    #region A_Successful_Query_Echoes_Recursion_Desired()

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task A_Successful_Query_Echoes_Recursion_Desired()
    {

        // And the ordinary path, which a client reads to see what it asked for.
        var request   = new RawDnsWriter().
                            Header(0x0F17, RawDnsFlags.RD, 1, 0, 0, 0).
                            Question(ZoneFixtures.AName, RawDnsType.A).
                            ToArray();

        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(response.RCode, Is.Zero, "NOERROR");
            Assert.That(response.RD,    Is.True, "RD echoed");
        });

    }

    #endregion

    #region Multiple_Answers_Are_All_Returned()

    [Test]
    public async Task Multiple_Answers_Are_All_Returned()
    {

        var request   = RawDnsWriter.Query(0x0006, ZoneFixtures.MultiName, RawDnsType.A);
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);
        var addresses = response.Answers.
                            Where (rr => rr.Type == RawDnsType.A).
                            Select(rr => String.Join('.', rr.Rdata)).
                            ToArray();

        Assert.That(addresses, Is.EquivalentTo(ZoneFixtures.MultiAddresses));

    }

    #endregion

    #region Mx_Answer_Rdata_Is_Wellformed()

    [Test]
    [Property("RFC", "1035 §3.3.9")]
    public async Task Mx_Answer_Rdata_Is_Wellformed()
    {

        var request   = RawDnsWriter.Query(0x0007, ZoneFixtures.MxName, RawDnsType.MX);
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);

        Assert.That(response.Answers, Has.Count.EqualTo(2));

        var exchanges = response.Answers.
                            Select(rr => {
                                var preference = (rr.Rdata[0] << 8) | rr.Rdata[1];
                                var exchange   = RawDnsReader.ReadNameAt(response.Wire, rr.RdataOffset + 2).Name.Canonical;
                                return (preference, exchange);
                            }).
                            ToArray();

        Assert.That(exchanges, Is.EquivalentTo(new[] {
            (10, ZoneFixtures.Mail1.TrimEnd('.')),
            (20, ZoneFixtures.Mail2.TrimEnd('.'))
        }));

    }

    #endregion

    #region Srv_Answer_Rdata_Is_Wellformed()

    [Test]
    [Property("RFC", "2782")]
    public async Task Srv_Answer_Rdata_Is_Wellformed()
    {

        var request   = RawDnsWriter.Query(0x0008, ZoneFixtures.SrvName, RawDnsType.SRV);
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);
        var rr        = response.Answers.Single();

        Assert.Multiple(() => {
            Assert.That((rr.Rdata[0] << 8) | rr.Rdata[1], Is.EqualTo(ZoneFixtures.SrvPriority));
            Assert.That((rr.Rdata[2] << 8) | rr.Rdata[3], Is.EqualTo(ZoneFixtures.SrvWeight));
            Assert.That((rr.Rdata[4] << 8) | rr.Rdata[5], Is.EqualTo(ZoneFixtures.SrvPort));
            Assert.That(RawDnsReader.ReadNameAt(response.Wire, rr.RdataOffset + 6).Name.Canonical,
                        Is.EqualTo(ZoneFixtures.NameServer.TrimEnd('.')));
        });

    }

    #endregion

    #region Response_Has_No_Trailing_Garbage()

    [Test]
    public async Task Response_Has_No_Trailing_Garbage()
    {

        var request   = RawDnsWriter.Query(0x0009, ZoneFixtures.AName, RawDnsType.A);
        var raw       = await RawDnsProbe.UdpAsync(server.UdpPort, request);

        Assert.That(raw, Is.Not.Null);

        var response  = RawDnsReader.Parse(raw!);

        Assert.That(response.ConsumedBytes, Is.EqualTo(raw!.Length),
                    () => $"{raw.Length - response.ConsumedBytes} unparsed bytes:\n{Bytes.Dump(raw)}");

    }

    #endregion

}

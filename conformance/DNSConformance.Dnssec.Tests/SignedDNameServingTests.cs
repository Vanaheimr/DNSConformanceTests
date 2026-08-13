using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 6672 §3.1 where it meets DNSSEC: what a server may sign in a DNAME
/// answer, and what it must not.
/// </summary>
/// <remarks>
/// <para>
/// The answer to a redirected query holds two records that look alike and are
/// not. The DNAME came out of the zone and was signed by whoever signed the
/// zone; the CNAME beside it was invented by the server while answering, which
/// is why RFC 6672 §3.1 says it "does not have to be signed" — nothing could
/// have signed it in advance, and a server that signed it on the fly would be
/// asserting with the zone's key something the zone never said.
/// </para>
/// <para>
/// So a validator authenticates the DNAME and re-derives the CNAME. That makes
/// the absence of a signature over the CNAME a requirement rather than an
/// omission, and it is the kind of requirement a test has to state, because a
/// server that simply forgot to sign a record would look identical.
/// </para>
/// <para>
/// The zone is signed by BIND's dnssec-signzone and served unchanged, so every
/// signature here was produced by an implementation that had no part in
/// answering the query.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "6672 §3.1")]
public class SignedDNameServingTests
{

    private const String Origin      = "dname.dnssec.test";
    private const String Owner       = "redirect.dname.dnssec.test.";
    private const String Queried     = "host.redirect.dname.dnssec.test.";
    private const String Resolved    = "host.target.dname.dnssec.test.";

    private SignedZoneFixture      fixture   = null!;
    private HermodServerFixture?   server;


    [OneTimeSetUp]
    public async Task StartServer()
    {

        if (!SignedZoneFixture.IsAvailableFor(Origin))
            return;

        fixture = SignedZoneFixture.Load(Origin);

        server  = await HermodServerFixture.StartAsync(
                      new HermodServerFixtureOptions {
                          Zone                      = fixture.ToZone(),
                          SharePortAcrossTransports = true
                      }
                  );

    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (server is not null)
            await server.DisposeAsync();
    }


    [SetUp]
    public void RequireTheFixture()
    {
        if (server is null)
            Assert.Ignore($"The signed fixture for {Origin} is missing — run fixtures/zones/resign.sh.");
    }


    /// <summary>Ask with the DO bit set, over TCP when the signed answer will not fit.</summary>
    private async Task<RawDnsMessage> AskWithDnssec(String name, UInt16 type)
    {

        var query     = RawDnsWriter.Query(0x6672, name, type, ednsPayloadSize: 1232, dnssecOk: true);
        var datagram  = await RawDnsProbe.UdpAsync(server!.UdpPort, query);

        Assert.That(datagram, Is.Not.Null, $"the server must answer a query for {name}");

        var response  = RawDnsReader.Parse(datagram!);

        if (!response.TC)
            return response;

        var stream = await RawDnsProbe.TcpAsync(server.TcpPort, query);

        Assert.That(stream, Is.Not.Null, "RFC 7766 §5: a truncated answer must be retrievable over TCP");

        return RawDnsReader.Parse(stream!);

    }

    private static IEnumerable<RawRecord> SignaturesOver(RawDnsMessage Response, UInt16 CoveredType)

        // The type covered is the first two octets of an RRSIG's RDATA
        // (RFC 4034 §3.1.1), read here rather than parsed, so nothing in the
        // suite has to agree with Hermod about the record's shape.
        => Response.Answers.Where(record => record.Type == RawDnsType.RRSIG &&
                                            record.Rdata.Length >= 2 &&
                                            ((record.Rdata[0] << 8) | record.Rdata[1]) == CoveredType);


    #region The_Dname_Travels_With_Its_Signature()

    [Test]
    [Property("RFC", "4035 §3.1.1")]
    public async Task The_Dname_Travels_With_Its_Signature()
    {

        var response  = await AskWithDnssec(Queried, RawDnsType.A);

        var dname     = response.Answers.SingleOrDefault(record => record.Type == RawDnsType.DNAME);
        var signature = SignaturesOver(response, RawDnsType.DNAME).ToArray();

        Assert.Multiple(() => {

            Assert.That(dname,     Is.Not.Null, "the DNAME is part of the answer (RFC 6672 §3.1)");
            Assert.That(signature, Has.Length.EqualTo(1),
                        "a DO querier gets the RRSIG covering it — it is the only record in this answer a " +
                        "validator can authenticate, and everything else in the redirection follows from it");

        });

        // And it must be the signature BIND wrote, not one produced here.
        var expected = fixture.SignatureFor(Owner, DNSResourceRecordTypes.DNAME);

        Assert.That(expected, Is.Not.Null, "the fixture zone must actually carry a signature over the DNAME");

        Assert.That(RRWireBytes(signature[0]), Is.EqualTo(RRWireBytes(expected!)),
                    "the served RRSIG must be byte-identical to the one in the zone");

    }

    #endregion

    #region The_Synthesized_Cname_Is_Not_Signed()

    [Test]
    public async Task The_Synthesized_Cname_Is_Not_Signed()
    {

        var response = await AskWithDnssec(Queried, RawDnsType.A);

        Assert.That(response.Answers.Any(record => record.Type == RawDnsType.CNAME), Is.True,
                    "the synthesized CNAME is still expected in the answer");

        Assert.That(SignaturesOver(response, RawDnsType.CNAME), Is.Empty,
                    "RFC 6672 §3.1: the synthesized CNAME does not have to be signed — and cannot honestly " +
                    "be, since the zone never contained it. A signature here would be the zone's key " +
                    "asserting a record the zone's owner never wrote.");

    }

    #endregion

    #region The_Data_At_The_Rewritten_Name_Is_Signed()

    [Test]
    [Property("RFC", "4035 §3.1.1")]
    public async Task The_Data_At_The_Rewritten_Name_Is_Signed()
    {

        // The redirection is only half the answer; the other half is ordinary
        // signed data at the name it led to.
        var response = await AskWithDnssec(Queried, RawDnsType.A);

        var a        = response.Answers.SingleOrDefault(record => record.Type == RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(a, Is.Not.Null);
            Assert.That(a!.Name.Canonical, Is.EqualTo(Resolved.TrimEnd('.')));

            Assert.That(SignaturesOver(response, RawDnsType.A).Count(), Is.EqualTo(1),
                        "the A at the rewritten name is zone data and carries its own RRSIG");

        });

    }

    #endregion

    #region Without_The_Do_Bit_No_Signatures_Are_Sent()

    [Test]
    [Property("RFC", "4035 §3.2.1")]
    public async Task Without_The_Do_Bit_No_Signatures_Are_Sent()
    {

        var datagram = await RawDnsProbe.UdpAsync(
                                 server!.UdpPort,
                                 RawDnsWriter.Query(0x6673, Queried, RawDnsType.A)
                             );

        Assert.That(datagram, Is.Not.Null);

        var response = RawDnsReader.Parse(datagram!);

        Assert.Multiple(() => {

            Assert.That(response.Answers.Any(record => record.Type == RawDnsType.DNAME), Is.True,
                        "the redirection happens for every querier");

            Assert.That(response.Answers.Any(record => record.Type == RawDnsType.RRSIG), Is.False,
                        "RFC 4035 §3.2.1: signatures go only to a querier that asked for them");

        });

    }

    #endregion


    #region (private static) RRWireBytes(...)

    /// <summary>The RDATA of a record as it sits on the wire.</summary>
    private static Byte[] RRWireBytes(RawRecord Record)
        => Record.Rdata;

    /// <summary>The RDATA a Hermod record serializes to, uncompressed.</summary>
    private static Byte[] RRWireBytes(IDNSResourceRecord Record)
    {

        var ms = new MemoryStream();
        ms.Write(new Byte[] { 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 });

        Record.Serialize(ms, UseCompression: false, CompressionOffsets: []);

        return RawDnsReader.Parse(ms.ToArray()).Answers.Single().Rdata;

    }

    #endregion

}

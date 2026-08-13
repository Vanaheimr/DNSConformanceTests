using System.Text;

using NUnit.Framework;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4035 §3.1, RFC 5155 §7 and RFC 7129 — the *server* side of DNSSEC:
/// what an authoritative server has to put in a response so that a validating
/// resolver can believe it, including when the answer is "no".
/// </summary>
/// <remarks>
/// <para>
/// The zone here is the BIND-signed fixture, loaded record for record into a
/// Hermod server, and every question is asked over a raw UDP socket. That gives
/// the assertions something solid to compare against: an RRSIG, NSEC or NSEC3
/// in the response must be byte-identical to one BIND put in the zone file. A
/// server can only select these records — if it produced one, it produced it
/// wrong, and the comparison says so without any need to trust Hermod's own
/// idea of what the record should look like.
/// </para>
/// <para>
/// Where a test has to reason about canonical order or a type bit map, it does
/// so with the small implementations at the bottom of this file rather than
/// with Hermod's, for the same reason.
/// </para>
/// </remarks>
[TestFixture]
public class SignedZoneServingTests
{

    private const String NsecZone  = "dnssec.test";
    private const String Nsec3Zone = "nsec3.dnssec.test";

    private SignedZoneFixture     nsecFixture   = null!;
    private SignedZoneFixture     nsec3Fixture  = null!;
    private HermodServerFixture   nsecServer    = null!;
    private HermodServerFixture   nsec3Server   = null!;


    [OneTimeSetUp]
    public async Task StartServers()
    {

        if (!SignedZoneFixture.IsAvailableFor(NsecZone) ||
            !SignedZoneFixture.IsAvailableFor(Nsec3Zone))
        {
            Assert.Ignore("The BIND-signed fixtures are missing — run fixtures/zones/resign.sh.");
        }

        nsecFixture   = SignedZoneFixture.Load(NsecZone);
        nsec3Fixture  = SignedZoneFixture.Load(Nsec3Zone);

        nsecServer    = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions { Zone = nsecFixture. ToZone() });
        nsec3Server   = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions { Zone = nsec3Fixture.ToZone() });

    }

    [OneTimeTearDown]
    public async Task StopServers()
    {

        if (nsecServer  is not null) await nsecServer. DisposeAsync();
        if (nsec3Server is not null) await nsec3Server.DisposeAsync();

    }


    /// <summary>
    /// Ask over UDP and, if the answer comes back truncated, ask again over TCP.
    /// </summary>
    /// <remarks>
    /// Not a workaround — this is the protocol. A signed negative answer is
    /// several RSA signatures of 256 octets each and routinely exceeds the 1232
    /// bytes DNS Flag Day recommends advertising, so RFC 1035 §4.2.1 has the
    /// server set TC and RFC 7766 §5 has the client come back over TCP. A test
    /// that only ever spoke UDP would be measuring the datagram size rather than
    /// the zone logic. See <see cref="Oversized_Signed_Answer_Truncates_And_Survives_Over_Tcp"/>,
    /// which asserts that behaviour rather than merely relying on it.
    /// </remarks>
    private static async Task<RawDnsMessage> Ask(HermodServerFixture  Server,
                                                 String               Name,
                                                 UInt16               Type,
                                                 Boolean              DnssecOK = true)
    {

        var query = RawDnsWriter.Query(
                        0x4035,
                        Name,
                        Type,
                        ednsPayloadSize: 4096,
                        dnssecOk:        DnssecOK
                    );

        var raw = await RawDnsProbe.UdpAsync(Server.UdpPort, query);

        Assert.That(raw, Is.Not.Null, $"the server must answer a query for {Name}");

        var response = RawDnsReader.Parse(raw!);

        if (!response.TC)
            return response;

        var overTcp = await RawDnsProbe.TcpAsync(Server.TcpPort, query);

        Assert.That(overTcp, Is.Not.Null, $"the server must answer the TCP retry for {Name}");

        return RawDnsReader.Parse(overTcp!);

    }


    /// <summary>The RDATA of every record of one type in a section, as it came off the wire.</summary>
    private static Byte[][] RdataOf(IEnumerable<RawRecord> Records, UInt16 Type)
        => [.. Records.Where(rr => rr.Type == Type).Select(rr => rr.Rdata)];


    /// <summary>The same record as the fixture holds it, serialized uncompressed.</summary>
    private static Byte[] FixtureRdata(org.GraphDefined.Vanaheimr.Hermod.DNS.IDNSResourceRecord Record)
    {

        using var stream = new MemoryStream();

        Record.Serialize(stream, UseCompression: false, CompressionOffsets: []);
        stream.Position = 0;

        // Skip owner name, TYPE, CLASS, TTL and RDLENGTH; what is left is RDATA.
        org.GraphDefined.Vanaheimr.Hermod.DNS.DNSTools.ExtractName(stream);
        stream.Position += 8;

        var rdLength = (stream.ReadByte() << 8) | stream.ReadByte();
        var rdata    = new Byte[rdLength];

        stream.ReadExactly(rdata);

        return rdata;

    }


    #region Answer_Carries_Its_Rrsig_When_The_DO_Bit_Is_Set()

    [Test]
    [Property("RFC", "4035 §3.1.1")]
    public async Task Answer_Carries_Its_Rrsig_When_The_DO_Bit_Is_Set()
    {

        var response   = await Ask(nsecServer, $"a.{NsecZone}.", RawDnsType.A);
        var signatures = response.Answers.Where(rr => rr.Type == RawDnsType.RRSIG).ToArray();

        var expected   = nsecFixture.SignatureFor($"a.{NsecZone}", org.GraphDefined.Vanaheimr.Hermod.DNS.DNSResourceRecordTypes.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.Zero);
            Assert.That(response.Answers.Any(rr => rr.Type == RawDnsType.A), Is.True, "the answer itself");

            Assert.That(signatures, Has.Length.EqualTo(1),
                        "§3.1.1: every RRset in the answer travels with the RRSIGs that cover it");

            Assert.That(expected, Is.Not.Null, "the fixture zone is signed");

            Assert.That(signatures[0].Rdata, Is.EqualTo(FixtureRdata(expected!)),
                        "byte for byte the signature BIND made — a server may select it, never rebuild it");

        });

    }

    #endregion

    #region Rrsigs_Are_Withheld_When_The_DO_Bit_Is_Clear()

    [Test]
    [Property("RFC", "4035 §3.2.1")]
    public async Task Rrsigs_Are_Withheld_When_The_DO_Bit_Is_Clear()
    {

        // §3.2.1 is a MUST NOT, and it is not a matter of taste: DNSSEC records
        // are large, and a server that ships them unasked inflates every answer
        // to every client that cannot use them — which was the whole reason the
        // DO bit was invented (RFC 3225 §3).
        var response = await Ask(nsecServer, $"a.{NsecZone}.", RawDnsType.A, DnssecOK: false);

        Assert.Multiple(() => {
            Assert.That(response.Answers.Any(rr => rr.Type == RawDnsType.A),     Is.True);
            Assert.That(response.Answers.Any(rr => rr.Type == RawDnsType.RRSIG), Is.False,
                        "no DO bit, no signatures");
        });

    }

    #endregion

    #region Nodata_Carries_The_Soa_The_Nsec_And_Both_Signatures()

    [Test]
    [Property("RFC", "4035 §3.1.3.1")]
    public async Task Nodata_Carries_The_Soa_The_Nsec_And_Both_Signatures()
    {

        // "a.dnssec.test." exists and holds an A. Asking for TXT is NODATA, and
        // §3.1.3.1 says the proof is the NSEC that *matches* the name: its type
        // bit map is the list of what the name really has, so a validator can
        // see for itself that TXT is not among them.
        var response = await Ask(nsecServer, $"a.{NsecZone}.", RawDnsType.TXT);
        var nsecs    = response.Authorities.Where(rr => rr.Type == RawDnsType.NSEC).ToArray();

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.Zero, "NODATA is NOERROR");
            Assert.That(response.Answers, Is.Empty);

            Assert.That(response.Authorities.Any(rr => rr.Type == RawDnsType.SOA), Is.True,
                        "RFC 2308 §3: the SOA bounds how long the 'no' may be cached");

            Assert.That(nsecs, Has.Length.EqualTo(1), "exactly the NSEC that matches the name");
            Assert.That(nsecs[0].Name.Canonical, Is.EqualTo($"a.{NsecZone}"));

            var types = TypesIn(nsecs[0].Rdata[NameLength(nsecs[0].Rdata)..]);

            Assert.That(types, Does.Contain(RawDnsType.A),   "the bitmap lists what the name has");
            Assert.That(types, Does.Not.Contain(RawDnsType.TXT),
                        "…and the absence of TXT is the proof");

            // Both the SOA and the NSEC are useless to a validator unsigned.
            var signedTypes = response.Authorities.Where(rr => rr.Type == RawDnsType.RRSIG).
                                                   Select(rr => (UInt16) ((rr.Rdata[0] << 8) | rr.Rdata[1])).
                                                   ToArray();

            Assert.That(signedTypes, Does.Contain(RawDnsType.SOA));
            Assert.That(signedTypes, Does.Contain(RawDnsType.NSEC));

        });

    }

    #endregion

    #region Nxdomain_Carries_An_Nsec_That_Covers_The_Name()

    [Test]
    [Property("RFC", "4035 §3.1.3.2")]
    public async Task Nxdomain_Carries_An_Nsec_That_Covers_The_Name()
    {

        // "zz.dnssec.test." is not in the zone, and no wildcard can reach it —
        // the zone's only wildcard is "*.wild.dnssec.test.", one level down.
        var qname    = $"zz.{NsecZone}.";
        var response = await Ask(nsecServer, qname, RawDnsType.A);
        var nsecs    = response.Authorities.Where(rr => rr.Type == RawDnsType.NSEC).ToArray();

        Assert.That(response.RCode, Is.EqualTo(3), "NXDOMAIN");
        Assert.That(nsecs,          Is.Not.Empty,  "an unproven NXDOMAIN is Bogus, not merely unsigned");

        // Every NSEC sent has to be one from the zone, not one made up for the
        // occasion.
        var fixtureNsecs = nsecFixture.Records.
                               Where(rr => rr.Type == org.GraphDefined.Vanaheimr.Hermod.DNS.DNSResourceRecordTypes.NSEC).
                               Select(FixtureRdata).
                               ToArray();

        foreach (var nsec in nsecs)
            Assert.That(fixtureNsecs.Any(known => known.SequenceEqual(nsec.Rdata)), Is.True,
                        $"the NSEC at {nsec.Name} is one of the zone's own records");

        // §3.1.3.2 wants two things proven, and the second is the one that gets
        // forgotten: that no wildcard could have answered either. Both may be
        // carried by a single record whose span happens to cover both names.
        var coversTheName     = nsecs.Any(nsec => Covers(nsec, qname));
        var coversAWildcard   = nsecs.Any(nsec => Covers(nsec, $"*.{NsecZone}.")) ||
                                nsecs.Any(nsec => nsec.Name.Canonical == $"*.{NsecZone}");

        Assert.Multiple(() => {
            Assert.That(coversTheName,   Is.True, "one NSEC must span the queried name");
            Assert.That(coversAWildcard, Is.True, "and one must span the wildcard at its closest encloser");
        });

    }

    #endregion

    #region Wildcard_Answer_Keeps_The_Labels_Field_Of_Its_Signature()

    [Test]
    [Property("RFC", "4035 §3.1.3.3")]
    public async Task Wildcard_Answer_Keeps_The_Labels_Field_Of_Its_Signature()
    {

        // The subtlest requirement in the whole of §3.1.3. A wildcard answer is
        // rewritten to carry the queried name — including the RRSIG's owner
        // name — but the RRSIG's *labels* field must keep counting the labels of
        // "*.wild.dnssec.test.", i.e. 3. That number is how a validator knows to
        // reconstruct the wildcard name before checking the signature, and a
        // server that "helpfully" updates it to match the queried name makes
        // every wildcard answer in the zone fail validation.
        var response  = await Ask(nsecServer, $"anything.wild.{NsecZone}.", RawDnsType.A);

        var answers   = response.Answers.Where(rr => rr.Type == RawDnsType.A).    ToArray();
        var signature = response.Answers.Where(rr => rr.Type == RawDnsType.RRSIG).ToArray();

        var expected  = nsecFixture.SignatureFor($"*.wild.{NsecZone}", org.GraphDefined.Vanaheimr.Hermod.DNS.DNSResourceRecordTypes.A);

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.Zero);
            Assert.That(answers,   Has.Length.EqualTo(1));
            Assert.That(signature, Has.Length.EqualTo(1));

            Assert.That(answers  [0].Name.Canonical, Is.EqualTo($"anything.wild.{NsecZone}"));
            Assert.That(signature[0].Name.Canonical, Is.EqualTo($"anything.wild.{NsecZone}"),
                        "the signature is rewritten to the queried name too");

            // RRSIG RDATA: type covered (2) | algorithm (1) | labels (1) | …
            Assert.That(signature[0].Rdata[3], Is.EqualTo((Byte) 3),
                        "labels still counts wild.dnssec.test. — the '*' and the root are not counted");

            Assert.That(expected, Is.Not.Null);
            Assert.That(signature[0].Rdata, Is.EqualTo(FixtureRdata(expected!)),
                        "and the RDATA is otherwise exactly the signature BIND made for the wildcard");

            // §3.1.3.3: without this the answer is indistinguishable from one an
            // attacker synthesized, because the signature validates under every
            // name the wildcard could have covered.
            Assert.That(response.Authorities.Any(rr => rr.Type == RawDnsType.NSEC), Is.True,
                        "a wildcard answer must prove that the queried name itself does not exist");

        });

    }

    #endregion

    #region Nsec3_Nxdomain_Carries_The_Three_Record_Closest_Encloser_Proof()

    [Test]
    [Property("RFC", "5155 §7.2.2")]
    public async Task Nsec3_Nxdomain_Carries_The_Three_Record_Closest_Encloser_Proof()
    {

        var response = await Ask(nsec3Server, $"zz.{Nsec3Zone}.", RawDnsType.A);
        var nsec3s   = response.Authorities.Where(rr => rr.Type == RawDnsType.NSEC3).ToArray();

        var known    = nsec3Fixture.Records.
                           Where(rr => rr.Type == org.GraphDefined.Vanaheimr.Hermod.DNS.DNSResourceRecordTypes.NSEC3).
                           Select(FixtureRdata).
                           ToArray();

        Assert.That(response.RCode, Is.EqualTo(3), "NXDOMAIN");
        Assert.That(nsec3s,         Is.Not.Empty,  "an unproven NXDOMAIN is Bogus, not merely unsigned");

        foreach (var nsec3 in nsec3s)
            Assert.That(known.Any(k => k.SequenceEqual(nsec3.Rdata)), Is.True,
                        $"the NSEC3 at {nsec3.Name} is one of the zone's own records");

        // §7.2.2 asks for three things to be proven: the closest encloser
        // matched, the next closer name covered, and the wildcard at the closest
        // encloser covered. Nothing existing between "zz" and the apex makes the
        // apex the closest encloser and "zz.nsec3.dnssec.test." itself the next
        // closer.
        //
        // Three *roles*, not necessarily three records: one NSEC3's span can
        // happen to contain two of the hashes, and a validator is perfectly
        // happy with that. Asserting a count of three would be asserting a
        // property of this fixture's hash values rather than of the protocol.
        var closestEncloser = $"{Nsec3Zone}.";
        var nextCloser      = $"zz.{Nsec3Zone}.";
        var wildcard        = $"*.{Nsec3Zone}.";

        Assert.Multiple(() => {

            Assert.That(nsec3s.Any(rr => Nsec3Matches(rr, closestEncloser)), Is.True,
                        "an NSEC3 must match the closest encloser");

            Assert.That(nsec3s.Any(rr => Nsec3Covers(rr, nextCloser)), Is.True,
                        "an NSEC3 must cover the next closer name");

            Assert.That(nsec3s.Any(rr => Nsec3Covers(rr, wildcard)), Is.True,
                        "an NSEC3 must cover the wildcard at the closest encloser — otherwise the name could still have been synthesized");

            Assert.That(nsec3s, Has.Length.LessThanOrEqualTo(3),
                        "and no more than the three §7.2.2 asks for: spare NSEC3 records are free zone-walking material");

            Assert.That(response.Authorities.Count(rr => rr.Type == RawDnsType.RRSIG),
                        Is.GreaterThanOrEqualTo(nsec3s.Length + 1),
                        "each NSEC3 and the SOA carry their own signature");

            Assert.That(response.Authorities.Any(rr => rr.Type == RawDnsType.NSEC), Is.False,
                        "RFC 5155 §7.1: a zone denies with NSEC3 or with NSEC, never with both");

        });

    }

    #endregion

    #region Nsec3_Proof_Below_An_Existing_Name_Needs_All_Three_Records()

    [Test]
    [Property("RFC", "5155 §7.2.2")]
    public async Task Nsec3_Proof_Below_An_Existing_Name_Needs_All_Three_Records()
    {

        // "a.nsec3.dnssec.test." exists, so it — not the apex — is the closest
        // encloser of "x.a.nsec3.dnssec.test.", and the wildcard that has to be
        // disproven is "*.a.nsec3.dnssec.test.". Three different hashes in three
        // different places in the chain, so unlike the apex case above this one
        // cannot be satisfied by a single lucky span.
        //
        // It is also the NSEC3 form of the wildcard question: the zone does have
        // a wildcard, at "*.wild.nsec3.dnssec.test.", and it is none of this
        // name's business.
        var qname    = $"x.a.{Nsec3Zone}.";
        var response = await Ask(nsec3Server, qname, RawDnsType.A);
        var nsec3s   = response.Authorities.Where(rr => rr.Type == RawDnsType.NSEC3).ToArray();

        Assert.That(response.RCode, Is.EqualTo(3), "NXDOMAIN");

        Assert.Multiple(() => {

            Assert.That(nsec3s, Has.Length.GreaterThanOrEqualTo(2),
                        "three roles that cannot all fall to one record here");

            Assert.That(nsec3s.Any(rr => Nsec3Matches(rr, $"a.{Nsec3Zone}.")), Is.True,
                        "the closest encloser is a.nsec3.dnssec.test., and it must be matched");

            Assert.That(nsec3s.Any(rr => Nsec3Covers(rr, qname)), Is.True,
                        "the next closer name must be covered");

            Assert.That(nsec3s.Any(rr => Nsec3Covers(rr, $"*.a.{Nsec3Zone}.")), Is.True,
                        "and so must the wildcard at the closest encloser");

            // The upper bound matters as much as the lower one. NSEC3 exists to
            // stop zone walking, and every NSEC3 handed out is one more hash an
            // attacker can grind offline — so a server that answers by dumping
            // the chain passes all three checks above while giving away exactly
            // what the zone paid for hashing to protect.
            Assert.That(nsec3s, Has.Length.LessThanOrEqualTo(3),
                        "§7.2.2 lists three records, and anything beyond them is free zone-walking material");

        });

    }

    #endregion

    #region Nsec3_Wildcard_Answer_Proves_The_Queried_Name_Absent()

    [Test]
    [Property("RFC", "5155 §7.2.5")]
    public async Task Nsec3_Wildcard_Answer_Proves_The_Queried_Name_Absent()
    {

        var qname    = $"anything.wild.{Nsec3Zone}.";
        var response = await Ask(nsec3Server, qname, RawDnsType.A);
        var nsec3s   = response.Authorities.Where(rr => rr.Type == RawDnsType.NSEC3).ToArray();

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.Zero);
            Assert.That(response.Answers.Any(rr => rr.Type == RawDnsType.A), Is.True,
                        "the wildcard answers");

            // §7.2.5 wants exactly one thing proven, and it is the thing that
            // makes the answer trustworthy: that the queried name does not exist
            // in its own right, so the wildcard really was entitled to answer.
            Assert.That(nsec3s.Any(rr => Nsec3Covers(rr, qname)), Is.True,
                        "an NSEC3 must cover the next closer name of the wildcard answer");

            Assert.That(nsec3s, Has.Length.EqualTo(1),
                        "and nothing else is required — the closest encloser is implied by the answer itself");

        });

    }

    #endregion

    #region Nsec3_Nodata_Carries_The_Nsec3_That_Matches_The_Name()

    [Test]
    [Property("RFC", "5155 §7.2.3")]
    public async Task Nsec3_Nodata_Carries_The_Nsec3_That_Matches_The_Name()
    {

        var response = await Ask(nsec3Server, $"a.{Nsec3Zone}.", RawDnsType.TXT);
        var nsec3s   = response.Authorities.Where(rr => rr.Type == RawDnsType.NSEC3).ToArray();

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.Zero, "the name exists — NODATA");
            Assert.That(response.Answers, Is.Empty);

            Assert.That(nsec3s, Has.Length.EqualTo(1),
                        "§7.2.3: one NSEC3, the one matching the name. No closest encloser proof is needed when the name is right there");

            // NSEC3 RDATA: alg (1) | flags (1) | iterations (2) | salt length (1)
            // | salt | hash length (1) | next hashed owner | type bit maps.
            var rdata     = nsec3s[0].Rdata;
            var saltLen   = rdata[4];
            var hashAt    = 5 + saltLen;
            var hashLen   = rdata[hashAt];
            var bitmapAt  = hashAt + 1 + hashLen;
            var types     = TypesIn(rdata[bitmapAt..]);

            Assert.That(types, Does.Contain(RawDnsType.A),       "the bitmap says what a.nsec3.dnssec.test. holds");
            Assert.That(types, Does.Not.Contain(RawDnsType.TXT), "…and the missing TXT bit is the whole proof");

        });

    }

    #endregion

    #region Nsec3_Zone_Publishes_The_Parameters_It_Was_Signed_With()

    [Test]
    [Property("RFC", "5155 §4")]
    public async Task Nsec3_Zone_Publishes_The_Parameters_It_Was_Signed_With()
    {

        var response = await Ask(nsec3Server, $"{Nsec3Zone}.", RawDnsType.NSEC3PARAM);
        var records  = response.Answers.Where(rr => rr.Type == RawDnsType.NSEC3PARAM).ToArray();

        Assert.Multiple(() => {

            Assert.That(records, Has.Length.EqualTo(1),
                        "§4.1: the apex carries NSEC3PARAM so a server knows which chain to walk");

            // fixtures/zones/resign.sh signs this zone with "-3 aabbccdd -H 12".
            var rdata = records[0].Rdata;

            Assert.That(rdata[0], Is.EqualTo((Byte) 1),  "hash algorithm 1 (SHA-1), the only one RFC 5155 defines");
            Assert.That(rdata[1], Is.Zero,               "§4.1.2: the NSEC3PARAM flags field is always zero, opt-out lives on the NSEC3 records");
            Assert.That((rdata[2] << 8) | rdata[3], Is.EqualTo(12), "12 extra iterations");
            Assert.That(rdata[4], Is.EqualTo((Byte) 4),  "a four-octet salt");
            Assert.That(rdata[5..9], Is.EqualTo(new Byte[] { 0xAA, 0xBB, 0xCC, 0xDD }));

        });

    }

    #endregion

    #region Denial_Records_Are_Withheld_When_The_DO_Bit_Is_Clear()

    [Test]
    [Property("RFC", "4035 §3.2.1")]
    public async Task Denial_Records_Are_Withheld_When_The_DO_Bit_Is_Clear()
    {

        var nsec  = await Ask(nsecServer,  $"zz.{NsecZone}.",  RawDnsType.A, DnssecOK: false);
        var nsec3 = await Ask(nsec3Server, $"zz.{Nsec3Zone}.", RawDnsType.A, DnssecOK: false);

        Assert.Multiple(() => {

            Assert.That(nsec. RCode, Is.EqualTo(3));
            Assert.That(nsec3.RCode, Is.EqualTo(3));

            Assert.That(nsec. Authorities.Any(rr => rr.Type == RawDnsType.NSEC),  Is.False);
            Assert.That(nsec3.Authorities.Any(rr => rr.Type == RawDnsType.NSEC3), Is.False);
            Assert.That(nsec. Authorities.Any(rr => rr.Type == RawDnsType.RRSIG), Is.False);

            // The SOA stays. It is not a DNSSEC record — RFC 2308 needs it for
            // negative caching whether or not anyone is validating.
            Assert.That(nsec. Authorities.Any(rr => rr.Type == RawDnsType.SOA),   Is.True);
            Assert.That(nsec3.Authorities.Any(rr => rr.Type == RawDnsType.SOA),   Is.True);

        });

    }

    #endregion

    #region Dnskey_Rrset_Is_Served_With_Its_Signature()

    [Test]
    [Property("RFC", "4035 §3.1.1")]
    public async Task Dnskey_Rrset_Is_Served_With_Its_Signature()
    {

        // The one query a validator always has to make, and the one RRset that
        // is signed by the key-signing key rather than the zone-signing key.
        var response = await Ask(nsecServer, $"{NsecZone}.", RawDnsType.DNSKEY);

        var keys       = response.Answers.Where(rr => rr.Type == RawDnsType.DNSKEY).ToArray();
        var signatures = response.Answers.Where(rr => rr.Type == RawDnsType.RRSIG). ToArray();

        Assert.Multiple(() => {
            Assert.That(keys,       Has.Length.EqualTo(2), "a KSK and a ZSK");
            Assert.That(signatures, Is.Not.Empty,          "and the RRSIG over the DNSKEY RRset");
            Assert.That(signatures.All(sig => ((sig.Rdata[0] << 8) | sig.Rdata[1]) == RawDnsType.DNSKEY), Is.True);
        });

    }

    #endregion


    #region Oversized_Signed_Answer_Truncates_And_Survives_Over_Tcp()

    [Test]
    [Property("RFC", "1035 §4.2.1, 7766 §5")]
    public async Task Oversized_Signed_Answer_Truncates_And_Survives_Over_Tcp()
    {

        // A signed NXDOMAIN below an existing name is three NSEC3 records plus a
        // signature each plus the SOA and its own — with 2048-bit RSA that is
        // well past the 1232 octets this server advertises, and past the 4096 a
        // client may claim it can reassemble but rarely can.
        //
        // The correct behaviour is not to send a partial proof. A truncated
        // answer says "come back over TCP", and a validator that acted on the
        // fragment would reject a perfectly good zone.
        var query   = RawDnsWriter.Query(0x7766, $"x.a.{Nsec3Zone}.", RawDnsType.A,
                                         ednsPayloadSize: 4096, dnssecOk: true);

        var raw     = await RawDnsProbe.UdpAsync(nsec3Server.UdpPort, query);
        var overUdp = RawDnsReader.Parse(raw!);

        Assert.Multiple(() => {
            Assert.That(overUdp.TC,          Is.True,  "the answer does not fit, so TC is set");
            Assert.That(overUdp.Authorities, Is.Empty, "and no fragment of the proof is sent");
            Assert.That(overUdp.RCode,       Is.EqualTo(3), "the RCODE still tells the truth");
        });

        var overTcp = RawDnsReader.Parse((await RawDnsProbe.TcpAsync(nsec3Server.TcpPort, query))!);

        Assert.Multiple(() => {

            Assert.That(overTcp.TC,    Is.False, "over TCP there is room");
            Assert.That(overTcp.RCode, Is.EqualTo(3));

            Assert.That(overTcp.Authorities.Count(rr => rr.Type == RawDnsType.NSEC3),
                        Is.GreaterThanOrEqualTo(2),
                        "…and the whole proof arrives");

            Assert.That(overTcp.Authorities.Any(rr => rr.Type == RawDnsType.SOA), Is.True);

        });

    }

    #endregion


    #region Small independent helpers

    /// <summary>
    /// Whether an NSEC record's span strictly contains a name, using the
    /// canonical ordering of RFC 4034 §6.1 as implemented below.
    /// </summary>
    private static Boolean Covers(RawRecord Nsec, String Name)
    {

        var owner = Nsec.Name.Canonical + ".";
        var next  = NextNameOf(Nsec.Rdata);

        var above = CompareCanonical(Name, owner) > 0;
        var below = CompareCanonical(Name, next)  < 0;

        // The last NSEC of a zone points back at the apex, so its span wraps.
        return CompareCanonical(owner, next) >= 0
                   ? above || below
                   : above && below;

    }


    /// <summary>
    /// RFC 4034 §6.1 — compare two names label by label from the rightmost, each
    /// label as a case-insensitive octet string.
    /// </summary>
    /// <remarks>
    /// Written here rather than borrowed from Hermod on purpose. This is the
    /// ordering the whole NSEC chain rests on, and a test that used the same
    /// comparison as the server would agree with the server's mistakes.
    /// </remarks>
    private static Int32 CompareCanonical(String Left, String Right)
    {

        var leftLabels  = Left. ToLowerInvariant().TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries);
        var rightLabels = Right.ToLowerInvariant().TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries);

        for (var i = 0; ; i++)
        {

            var l = leftLabels. Length - 1 - i;
            var r = rightLabels.Length - 1 - i;

            if (l < 0 && r < 0) return  0;
            if (l < 0)          return -1;
            if (r < 0)          return  1;

            var comparison = String.CompareOrdinal(leftLabels[l], rightLabels[r]);

            if (comparison != 0)
                return comparison < 0 ? -1 : 1;

        }

    }


    #region NSEC3: an independent hash, so the proofs can be checked from outside

    /// <summary>
    /// The NSEC3 hash of a name under the fixture's parameters (RFC 5155 §5):
    /// <c>IH(salt, x, 0) = H(x | salt)</c> and <c>IH(salt, x, k) = H(IH(salt, x, k-1) | salt)</c>,
    /// with <c>x</c> the name in canonical wire form.
    /// </summary>
    /// <remarks>
    /// Deliberately not Hermod's <c>NSEC3.ComputeHash</c>. A test that asked the
    /// server's own hash function which record ought to have been sent would be
    /// asking the defendant to write the verdict — and the iteration count is
    /// exactly the sort of off-by-one this suite exists to catch, since RFC 5155
    /// counts *extra* rounds on top of the first.
    /// </remarks>
    private static Byte[] Nsec3Hash(String Name, UInt16 Iterations, Byte[] Salt)
    {

        var input = new List<Byte>();

        foreach (var label in Name.ToLowerInvariant().TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            input.Add((Byte) bytes.Length);
            input.AddRange(bytes);
        }

        input.Add(0);   // the root label terminates the name

        var hash = System.Security.Cryptography.SHA1.HashData([.. input, .. Salt]);

        for (var i = 0; i < Iterations; i++)
            hash = System.Security.Cryptography.SHA1.HashData([.. hash, .. Salt]);

        return hash;

    }


    /// <summary>Base32hex (RFC 4648 §7) — the order-preserving alphabet NSEC3 owner names use.</summary>
    private static Byte[] Base32HexDecode(String Text)
    {

        const String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

        var result = new List<Byte>();
        var buffer = 0;
        var bits   = 0;

        foreach (var c in Text.ToUpperInvariant())
        {

            var value = alphabet.IndexOf(c);

            if (value < 0)
                throw new FormatException($"'{c}' is not a Base32hex character.");

            buffer  = (buffer << 5) | value;
            bits   += 5;

            if (bits >= 8)
            {
                bits -= 8;
                result.Add((Byte) ((buffer >> bits) & 0xFF));
            }

        }

        return [.. result];

    }


    private (UInt16 Iterations, Byte[] Salt, Byte[] NextHash) Nsec3FieldsOf(RawRecord Record)
    {

        var rdata      = Record.Rdata;
        var iterations = (UInt16) ((rdata[2] << 8) | rdata[3]);
        var saltLength = rdata[4];
        var salt       = rdata[5..(5 + saltLength)];
        var hashAt     = 5 + saltLength;
        var hashLength = rdata[hashAt];
        var nextHash   = rdata[(hashAt + 1)..(hashAt + 1 + hashLength)];

        return (iterations, salt, nextHash);

    }


    /// <summary>Whether an NSEC3's owner name is the hash of the given name (RFC 5155 §8.3, "matches").</summary>
    private Boolean Nsec3Matches(RawRecord Record, String Name)
    {

        var (iterations, salt, _) = Nsec3FieldsOf(Record);

        return Base32HexDecode(Record.Name.Presentation.Split('.')[0]).
                   SequenceEqual(Nsec3Hash(Name, iterations, salt));

    }


    /// <summary>Whether an NSEC3's hash span strictly contains the hash of the given name ("covers").</summary>
    private Boolean Nsec3Covers(RawRecord Record, String Name)
    {

        var (iterations, salt, nextHash) = Nsec3FieldsOf(Record);

        var owner = Base32HexDecode(Record.Name.Presentation.Split('.')[0]);
        var hash  = Nsec3Hash(Name, iterations, salt);

        var above = Compare(hash,  owner)    > 0;
        var below = Compare(hash,  nextHash) < 0;

        // The chain is a ring: its last record wraps from the highest hash back
        // to the lowest, and for that one record the span is either side.
        return Compare(owner, nextHash) >= 0
                   ? above || below
                   : above && below;


        static Int32 Compare(Byte[] Left, Byte[] Right)
        {

            for (var i = 0; i < Math.Min(Left.Length, Right.Length); i++)
                if (Left[i] != Right[i])
                    return Left[i] < Right[i] ? -1 : 1;

            return Left.Length.CompareTo(Right.Length);

        }

    }

    #endregion


    /// <summary>The length in octets of the uncompressed name at the start of some RDATA.</summary>
    private static Int32 NameLength(Byte[] Rdata)
    {

        var offset = 0;

        while (offset < Rdata.Length && Rdata[offset] != 0)
            offset += Rdata[offset] + 1;

        return offset + 1;

    }


    /// <summary>The next-domain-name field of an NSEC record, in presentation form.</summary>
    private static String NextNameOf(Byte[] Rdata)
    {

        var name   = new StringBuilder();
        var offset = 0;

        while (offset < Rdata.Length && Rdata[offset] != 0)
        {

            var length = Rdata[offset];

            name.Append(Encoding.ASCII.GetString(Rdata, offset + 1, length)).Append('.');
            offset += length + 1;

        }

        return name.Length == 0 ? "." : name.ToString();

    }


    /// <summary>
    /// The types a bit map asserts (RFC 4034 §4.1.2): a sequence of
    /// "window, length, bitmap" blocks, bit 0 being an octet's high bit.
    /// </summary>
    private static IReadOnlyList<UInt16> TypesIn(Byte[] BitMaps)
    {

        var types  = new List<UInt16>();
        var offset = 0;

        while (offset + 2 <= BitMaps.Length)
        {

            var window = BitMaps[offset];
            var length = BitMaps[offset + 1];

            offset += 2;

            for (var i = 0; i < length && offset + i < BitMaps.Length; i++)
                for (var bit = 0; bit < 8; bit++)
                    if ((BitMaps[offset + i] & (0x80 >> bit)) != 0)
                        types.Add((UInt16) (window * 256 + i * 8 + bit));

            offset += length;

        }

        return types;

    }

    #endregion

}

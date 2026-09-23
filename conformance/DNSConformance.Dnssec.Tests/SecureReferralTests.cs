using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4035 §3.1.4 — what a referral to a signed child has to carry.
/// </summary>
/// <remarks>
/// <para>
/// A referral is the one answer where the parent says nothing of its own: the
/// NS RRset belongs to the child, and §2.2 forbids the parent to sign it. The DS
/// is the single exception, and the whole chain of trust rests on it. §3.1.4
/// leaves no room: "the name server MUST return both the DS RRset and its
/// associated RRSIG RR(s) in the Authority section along with the NS RRset."
/// </para>
/// <para>
/// A referral that carries the DS and drops its signature looks entirely healthy
/// from the outside. The delegation works, the child answers, and every name
/// under it resolves — for anyone not validating. A resolver that *is* validating
/// has a DS it cannot believe, and the correct response to that is to call the
/// whole child Bogus. So the failure is invisible exactly until it matters.
/// </para>
/// <para>
/// The zone is written out record by record, signature included, rather than
/// handed to a signer. Nothing here verifies the signature — the server's job is
/// to select it and send it — and a fabricated one keeps the test independent of
/// whether the key material of the day happens to be present.
/// </para>
/// </remarks>
[TestFixture]
public class SecureReferralTests
{

    #region Data

    private const String Parent        = "referral.test";
    private const String SecureChild   = "secure.referral.test";
    private const String InsecureChild = "insecure.referral.test";

    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private HermodServerFixture server = null!;

    #endregion

    [OneTimeSetUp]
    public async Task StartServer()
    {
        server = await HermodServerFixture.StartAsync(
                           new HermodServerFixtureOptions { Zone = ZoneWithASignedDelegation() });
    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (server is not null)
            await server.DisposeAsync();
    }


    #region A_Referral_To_A_Signed_Child_Carries_The_Ds_And_Its_Signature()

    [Test]
    [Property("RFC", "4035 §3.1.4")]
    public async Task A_Referral_To_A_Signed_Child_Carries_The_Ds_And_Its_Signature()
    {

        var response = await Ask($"www.{SecureChild}.", RawDnsType.A);

        var ns    = response.Authorities.Where(rr => rr.Type == RawDnsType.NS).   ToArray();
        var ds    = response.Authorities.Where(rr => rr.Type == RawDnsType.DS).   ToArray();
        var rrsig = response.Authorities.Where(rr => rr.Type == RawDnsType.RRSIG).ToArray();

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.Zero,  "a referral is not an error");
            Assert.That(response.Answers, Is.Empty, "and the parent answers nothing itself");
            Assert.That(response.AA,      Is.False, "§2.2 — a referral is not authoritative data");

            Assert.That(ns, Is.Not.Empty, "the delegation's NS RRset");
            Assert.That(ds, Is.Not.Empty, "and the DS, which is the parent's own statement");

            // The point of the whole fixture. An unsigned DS is a link in the
            // chain that a validator has to reject, and the answer looks correct
            // to everyone who is not checking.
            Assert.That(rrsig.Any(rr => TypeCoveredOf(rr) == RawDnsType.DS), Is.True,
                        "and the RRSIG over it — §3.1.4 asks for both, not for whichever is handy");

            // §2.2 the other way round: the NS RRset of a delegation belongs to
            // the child and the parent must not sign it.
            Assert.That(rrsig.Any(rr => TypeCoveredOf(rr) == RawDnsType.NS), Is.False,
                        "§2.2 — a delegation's NS RRset is not the parent's to sign");

        });

    }

    #endregion

    #region A_Referral_To_A_Signed_Child_Carries_Nothing_Extra_Without_The_Do_Bit()

    [Test]
    [Property("RFC", "4035 §3.2.1")]
    public async Task A_Referral_To_A_Signed_Child_Carries_Nothing_Extra_Without_The_Do_Bit()
    {

        var response = await Ask($"www.{SecureChild}.", RawDnsType.A, DnssecOK: false);

        Assert.Multiple(() => {

            Assert.That(response.Authorities.Any(rr => rr.Type == RawDnsType.NS),    Is.True,
                        "the delegation itself is not DNSSEC and is still served");

            Assert.That(response.Authorities.Any(rr => rr.Type == RawDnsType.DS),    Is.False);
            Assert.That(response.Authorities.Any(rr => rr.Type == RawDnsType.RRSIG), Is.False);

        });

    }

    #endregion


    #region Zone

    /// <summary>
    /// A parent with two children: one it vouches for and one it does not.
    /// </summary>
    private static InMemoryDNSZone ZoneWithASignedDelegation()
    {

        var apex = DomainName.Parse($"{Parent}.");
        var zone = new InMemoryDNSZone();

        zone.Add(

            new SOA(
                apex,
                DNSQueryClasses.IN,
                Ttl,
                DomainName.Parse($"ns.{Parent}."),
                SimpleEMailAddress.Parse($"hostmaster@{Parent}"),
                2026092301,
                TimeSpan.FromHours(2),
                TimeSpan.FromHours(1),
                TimeSpan.FromDays(14),
                TimeSpan.FromMinutes(5)
            ),

            new NS(apex, DNSQueryClasses.IN, Ttl, DomainName.Parse($"ns.{Parent}.")),
            new A (DomainName.Parse($"ns.{Parent}."), DNSQueryClasses.IN, Ttl, IPv4Address.Parse("192.0.2.53")),

            // The secure delegation: the child's name servers, the parent's DS,
            // and the parent's signature over that DS.
            new NS(DomainName.Parse($"{SecureChild}."), DNSQueryClasses.IN, Ttl,
                   DomainName.Parse($"ns.{SecureChild}.")),

            ChildDelegationSigner(),
            SignatureOverTheDelegationSigner(),

            // …and one it says nothing about, so the DS branch is a choice the
            // server makes rather than the only path it has.
            new NS(DomainName.Parse($"{InsecureChild}."), DNSQueryClasses.IN, Ttl,
                   DomainName.Parse($"ns.{InsecureChild}."))

        );

        return zone;

    }

    /// <summary>
    /// RFC 4034 §5.1 — key tag, algorithm, digest type and the digest. The digest
    /// is twenty octets because SHA-1 is digest type 1; what it hashes does not
    /// matter to a server, which only ever carries it.
    /// </summary>
    private static DS ChildDelegationSigner()

        => new (DomainName.Parse($"{SecureChild}."),
                DNSQueryClasses.IN,
                Ttl,
                12345,
                8,                                  // RSASHA256
                1,                                  // SHA-1
                [.. Enumerable.Range(0, 20).Select(i => (Byte) i)]);

    /// <summary>
    /// RFC 4034 §3.1 — an RRSIG over the DS RRset, signed by the parent. The
    /// signature octets are made up on purpose: nothing in this test verifies
    /// them, and a server that refused to send a signature it cannot check would
    /// be the finding rather than the fixture.
    /// </summary>
    private static RRSIG SignatureOverTheDelegationSigner()

        => new (DomainName.Parse($"{SecureChild}."),
                DNSQueryClasses.IN,
                Ttl,
                DNSResourceRecordTypes.DS,
                8,                                  // RSASHA256
                3,                                  // "secure.referral.test." is three labels
                (UInt32) Ttl.TotalSeconds,
                4102444800,                         // 2100-01-01, comfortably ahead
                1735689600,                         // 2025-01-01
                54321,
                DomainName.Parse($"{Parent}."),
                [.. Enumerable.Range(0, 64).Select(i => (Byte) (i * 3))]);

    #endregion

    #region Small independent helpers

    /// <summary>
    /// The first two octets of an RRSIG's RDATA are the type it covers
    /// (RFC 4034 §3.1).
    /// </summary>
    private static UInt16 TypeCoveredOf(RawRecord Rrsig)

        => (UInt16) ((Rrsig.Rdata[0] << 8) | Rrsig.Rdata[1]);

    private async Task<RawDnsMessage> Ask(String   Name,
                                          UInt16   Type,
                                          Boolean  DnssecOK = true)
    {

        var query = RawDnsWriter.Query(
                        0x3104,
                        Name,
                        Type,
                        ednsPayloadSize: 4096,
                        dnssecOk:        DnssecOK
                    );

        var raw = await RawDnsProbe.UdpAsync(server.UdpPort, query);

        Assert.That(raw, Is.Not.Null, $"the server must answer a query for {Name}");

        return RawDnsReader.Parse(raw!);

    }

    #endregion

}

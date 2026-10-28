using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 5155 §7.2.2 at the root: a name error from a root zone signed with
/// NSEC3, where the closest encloser is the root and the wildcard to deny is
/// <c>*.</c>.
/// </summary>
/// <remarks>
/// <para>
/// "To prove the nonexistence of QNAME, a closest encloser proof and an NSEC3
/// RR covering the (nonexistent) wildcard RR at the closest encloser MUST be
/// included in the response." In every other zone the closest encloser is at
/// least the zone's own apex, and the wildcard has a name below it. In the root
/// zone the closest encloser of a top-level domain is the root, and its wildcard
/// is the asterisk label and nothing else.
/// </para>
/// <para>
/// The root zone is signed with NSEC today, so a resolver does not meet this on
/// the internet. A test bed or a private root signed with NSEC3 does, and
/// nothing in RFC 5155 sets the root apart.
/// </para>
/// <para>
/// The zone is written out record by record, NSEC3 chain included, as in
/// <see cref="ApexOnlyZoneDenialTests"/>: what is measured is the server's
/// selection of records, and not its signer — a root zone Hermod signs itself
/// is finding 77. It holds its apex and one delegation, <c>test.</c>, and that
/// is chosen rather than any name. The two hashes split the ring so that the
/// apex's record covers the hash of <c>zz.</c> and the delegation's record covers
/// the hash of <c>*.</c>: the wildcard's cover is a record of its own, which the
/// answer has or does not have.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "5155 §7.2.2")]
public class RootZoneDenialTests
{

    #region Data

    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private HermodServerFixture server = null!;

    #endregion

    #region Setup / teardown

    [OneTimeSetUp]
    public async Task StartServer()
    {
        server = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions { Zone = Nsec3Root() });
    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (server is not null)
            await server.DisposeAsync();
    }

    #endregion


    #region A_Top_Level_Domain_That_Does_Not_Exist_Is_Denied_With_The_Roots_Wildcard()

    /// <summary>
    /// Finding 76, the serving side. <c>zz.</c> does not exist. The apex's NSEC3
    /// matches the root and covers <c>zz.</c>; the NSEC3 of <c>test.</c> covers
    /// <c>*.</c>. Both are owed, and the answer has to hold both.
    /// </summary>
    /// <remarks>
    /// The server sent the first and not the second. It hashes the wildcard by
    /// parsing its name, the parser refused <c>*.</c>, and the server caught the
    /// refusal and went on without the record — so the name error went out one
    /// record short of RFC 5155 §8.4's proof, which a validator has to call Bogus.
    /// </remarks>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Top_Level_Domain_That_Does_Not_Exist_Is_Denied_With_The_Roots_Wildcard()
    {

        var response = await Ask("zz.");
        var owners   = response.Authorities.
                                Where (rr => rr.Type == RawDnsType.NSEC3).
                                Select(rr => rr.Name.Canonical).
                                ToList();

        Assert.Multiple(() => {

            Assert.That(response.RCode, Is.EqualTo(3), "NXDOMAIN");

            Assert.That(owners, Does.Contain(OwnerOf(".")),
                        "the root's NSEC3: the closest encloser, matched, and zz., covered");

            Assert.That(owners, Does.Contain(OwnerOf("test.")),
                        "test.'s NSEC3, which covers *., the wildcard at the closest encloser");

            Assert.That(owners, Has.Count.EqualTo(2),
                        "and nothing else");

        });

    }

    #endregion


    #region Zone

    /// <summary>
    /// The root zone: SOA and NS at the apex, an unsigned delegation of
    /// <c>test.</c>, and the NSEC3 chain over the two names — no salt, no extra
    /// iterations (RFC 9276 §3.1), no opt-out.
    /// </summary>
    private static InMemoryDNSZone Nsec3Root()
    {

        var apex   = DomainName.Parse(".");
        var test   = DomainName.Parse("test.");
        var root   = Nsec3HashOf(".");
        var below  = Nsec3HashOf("test.");

        var zone   = new InMemoryDNSZone();

        zone.Add(

            new SOA(apex,
                    DNSQueryClasses.IN,
                    Ttl,
                    DomainName.Parse("a.root-servers.test."),
                    SimpleEMailAddress.Parse("hostmaster@root-servers.test"),
                    2026102801,
                    TimeSpan.FromHours(2),
                    TimeSpan.FromHours(1),
                    TimeSpan.FromDays(14),
                    TimeSpan.FromMinutes(5)),

            new NS(apex, DNSQueryClasses.IN, Ttl, DomainName.Parse("a.root-servers.test.")),
            new NS(test, DNSQueryClasses.IN, Ttl, DomainName.Parse("ns.test.")),

            new NSEC3(DomainName.Parse($"{Base32Hex(root)}."),  DNSQueryClasses.IN, Ttl, 1, 0, 0, [], below, AtTheApex),
            new NSEC3(DomainName.Parse($"{Base32Hex(below)}."), DNSQueryClasses.IN, Ttl, 1, 0, 0, [], root,  AtADelegation)

        );

        return zone;

    }

    /// <summary>NS (2), SOA (6) and RRSIG (46): one window, six octets.</summary>
    private static Byte[] AtTheApex
        => [0x00, 0x06, 0x22, 0x00, 0x00, 0x00, 0x00, 0x02];

    /// <summary>NS (2) alone: a delegation without DS, where nothing is signed.</summary>
    private static Byte[] AtADelegation
        => [0x00, 0x01, 0x20];

    #endregion

    #region Small independent helpers

    /// <summary>
    /// RFC 5155 §5 with zero iterations and no salt: SHA-1 of the name in
    /// uncompressed, lowercased wire form. The root is the one name with no
    /// labels, and its wire form is the zero octet alone.
    /// </summary>
    private static Byte[] Nsec3HashOf(String Name)
    {

        var wire = new List<Byte>();

        foreach (var label in Name.ToLowerInvariant().TrimEnd('.').
                                   Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var octets = Encoding.ASCII.GetBytes(label);
            wire.Add((Byte) octets.Length);
            wire.AddRange(octets);
        }

        wire.Add(0);

        return SHA1.HashData(wire.ToArray());

    }

    /// <summary>
    /// The owner name of the NSEC3 of a name in the root zone, as the wire
    /// reader spells it: one label, lowercased, without the root's dot.
    /// </summary>
    private static String OwnerOf(String Name)
        => Base32Hex(Nsec3HashOf(Name)).ToLowerInvariant();

    /// <summary>RFC 4648 §7 — base32 with the extended hex alphabet.</summary>
    private static String Base32Hex(Byte[] Data)
    {

        const String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

        var text  = new StringBuilder();
        var bits  = 0;
        var value = 0;

        foreach (var octet in Data)
        {

            value = (value << 8) | octet;
            bits += 8;

            while (bits >= 5)
            {
                text.Append(alphabet[(value >> (bits - 5)) & 31]);
                bits -= 5;
            }

        }

        if (bits > 0)
            text.Append(alphabet[(value << (5 - bits)) & 31]);

        return text.ToString();

    }

    private async Task<RawDnsMessage> Ask(String Name)
    {

        var query = RawDnsWriter.Query(0x5155, Name, RawDnsType.A, ednsPayloadSize: 4096, dnssecOk: true);
        var raw   = await RawDnsProbe.UdpAsync(server.UdpPort, query);

        Assert.That(raw, Is.Not.Null, $"the server must answer a query for {Name}");

        return RawDnsReader.Parse(raw!);

    }

    #endregion

}

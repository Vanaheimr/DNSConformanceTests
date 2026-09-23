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
/// A signed zone that holds nothing but its own apex, and the denial chain that
/// wraps around to itself.
/// </summary>
/// <remarks>
/// <para>
/// RFC 4034 §4.1.1: "The value of the Next Domain Name field in the last NSEC
/// record in the zone is the name of the zone apex." A zone with one name has
/// one NSEC, which is therefore both the first and the last — so its next name
/// is its own owner, and the span it describes is the entire name space below
/// the apex rather than an interval inside it. RFC 5155 §7.1 puts the NSEC3
/// chain under the same rule, over hashes instead of names.
/// </para>
/// <para>
/// This is not a contrived shape. It is what a signer produces for an empty
/// zone — one served to hold a name away from the world, or one that has just
/// been created — and every other test in this suite works with chains of three
/// names or more, where owner and next are always different. A comparison that
/// reads "strictly after the owner AND strictly before the next" answers *no*
/// for every name in such a zone, and the NXDOMAIN it returns carries no proof
/// at all.
/// </para>
/// <para>
/// The zones here are written out record by record rather than signed, which is
/// deliberate twice over. The NSEC and NSEC3 records are stated by the test, so
/// what is measured is the server's selection of them and nothing else; and
/// with no RRSIG travelling alongside, a proof that needs one record for two
/// separate facts has nowhere to hide if it sends it twice.
/// </para>
/// </remarks>
[TestFixture]
public class ApexOnlyZoneDenialTests
{

    #region Data

    private const String NsecZone   = "empty-nsec.test";
    private const String Nsec3Zone  = "empty-nsec3.test";

    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private HermodServerFixture nsecServer   = null!;
    private HermodServerFixture nsec3Server  = null!;

    #endregion

    #region Setup / teardown

    [OneTimeSetUp]
    public async Task StartServers()
    {

        nsecServer   = await HermodServerFixture.StartAsync(
                                 new HermodServerFixtureOptions { Zone = ApexOnlyNsecZone()  });

        nsec3Server  = await HermodServerFixture.StartAsync(
                                 new HermodServerFixtureOptions { Zone = ApexOnlyNsec3Zone() });

    }

    [OneTimeTearDown]
    public async Task StopServers()
    {

        if (nsecServer  is not null) await nsecServer. DisposeAsync();
        if (nsec3Server is not null) await nsec3Server.DisposeAsync();

    }

    #endregion


    #region An_Nsec_Whose_Next_Name_Is_Its_Own_Owner_Covers_The_Whole_Zone()

    [Test]
    [Property("RFC", "4034 §4.1.1, 4035 §3.1.3.2")]
    public async Task An_Nsec_Whose_Next_Name_Is_Its_Own_Owner_Covers_The_Whole_Zone()
    {

        var response = await Ask(nsecServer, $"nothing.{NsecZone}.", RawDnsType.A);
        var nsecs    = response.Authorities.Where(rr => rr.Type == RawDnsType.NSEC).ToArray();

        Assert.That(response.RCode, Is.EqualTo(3), "NXDOMAIN");

        // The whole point. With owner and next equal the span wraps, and a name
        // that is neither before nor after both ends is still inside it — read
        // as a plain interval the apex NSEC covers nothing and the proof is
        // empty, which a validator has to treat as Bogus rather than as absent.
        Assert.That(nsecs, Is.Not.Empty,
                    "the one NSEC of a one-name zone spans everything below the apex");

        Assert.That(nsecs[0].Name.Canonical, Is.EqualTo(NsecZone),
                    "and it is the apex record, because there is no other");

        // RFC 4035 §3.1.3.2 asks for two things: that the name is absent, and
        // that no wildcard could have answered. Here one record proves both, and
        // proving something twice is a malformed answer rather than a stronger
        // one.
        Assert.That(nsecs, Has.Length.EqualTo(1),
                    "one record answers both halves of §3.1.3.2 and is sent once");

    }

    #endregion

    #region An_Nsec3_Whose_Next_Hash_Is_Its_Own_Owner_Hash_Covers_The_Whole_Zone()

    [Test]
    [Property("RFC", "5155 §7.1, §7.2.2")]
    public async Task An_Nsec3_Whose_Next_Hash_Is_Its_Own_Owner_Hash_Covers_The_Whole_Zone()
    {

        var response = await Ask(nsec3Server, $"nothing.{Nsec3Zone}.", RawDnsType.A);
        var nsec3s   = response.Authorities.Where(rr => rr.Type == RawDnsType.NSEC3).ToArray();

        Assert.That(response.RCode, Is.EqualTo(3), "NXDOMAIN");

        // Same shape as the NSEC case and one failure more. The hash comparison
        // walks the shorter of the two arrays; owner and next being the same
        // twenty octets is the one call where it runs to the end without
        // finding a difference, and a bound that is one too generous reads past
        // it rather than answering "equal".
        Assert.That(nsec3s, Is.Not.Empty,
                    "the one NSEC3 of a one-name zone spans every hash but its own");

        Assert.That(nsec3s, Has.Length.EqualTo(1),
                    "§7.2.2's three records collapse to one here, and it is sent once");

        Assert.That(nsec3s[0].Name.Canonical,
                    Is.EqualTo($"{Base32Hex(Nsec3HashOf($"{Nsec3Zone}."))}.{Nsec3Zone}".ToLowerInvariant()),
                    "and it is the record the zone actually holds");

    }

    #endregion

    #region A_Name_That_Exists_Is_Not_Denied()

    [Test]
    [Property("RFC", "4035 §3.1.3.1")]
    public async Task A_Name_That_Exists_Is_Not_Denied()
    {

        // The other side of the same span. The apex exists, so asking it for a
        // type it does not hold is NODATA — rcode 0 with an empty answer — and
        // the record that comes back has to be the NSEC *matching* the name.
        // A covering record here would be a zone claiming its own apex absent.
        var response = await Ask(nsecServer, $"{NsecZone}.", RawDnsType.MX);
        var nsecs    = response.Authorities.Where(rr => rr.Type == RawDnsType.NSEC).ToArray();

        Assert.Multiple(() => {

            Assert.That(response.RCode,   Is.Zero,      "NODATA, not NXDOMAIN");
            Assert.That(response.Answers, Is.Empty,     "and no MX was invented");
            Assert.That(nsecs,            Is.Not.Empty, "an unproven NODATA is Bogus too");

            Assert.That(nsecs[0].Name.Canonical, Is.EqualTo(NsecZone),
                        "the NSEC at the name itself, which is what proves the type absent");

        });

    }

    #endregion


    #region Zones

    /// <summary>
    /// SOA, NS, and one NSEC pointing at its own owner.
    /// </summary>
    private static InMemoryDNSZone ApexOnlyNsecZone()
    {

        var apex = DomainName.Parse($"{NsecZone}.");
        var zone = new InMemoryDNSZone();

        zone.Add(

            StartOfAuthority(apex),

            new NS(apex, DNSQueryClasses.IN, Ttl, DomainName.Parse($"ns.{NsecZone}.")),

            new NSEC(
                apex,
                DNSQueryClasses.IN,
                Ttl,
                apex,                       // RFC 4034 §4.1.1 — the last NSEC points at the apex,
                ApexTypeBitMap              // and here the last one is also the first one.
            )

        );

        return zone;

    }

    /// <summary>
    /// SOA, NS, and one NSEC3 whose next hashed owner is its own owner hash.
    /// </summary>
    private static InMemoryDNSZone ApexOnlyNsec3Zone()
    {

        var apex = DomainName.Parse($"{Nsec3Zone}.");
        var hash = Nsec3HashOf($"{Nsec3Zone}.");
        var zone = new InMemoryDNSZone();

        zone.Add(

            StartOfAuthority(apex),

            new NS(apex, DNSQueryClasses.IN, Ttl, DomainName.Parse($"ns.{Nsec3Zone}.")),

            new NSEC3(
                DomainName.Parse($"{Base32Hex(hash)}.{Nsec3Zone}."),
                DNSQueryClasses.IN,
                Ttl,
                1,                          // RFC 5155 §5 — SHA-1 is the only algorithm defined
                0,                          // no opt-out
                0,                          // no extra iterations, per RFC 9276 §3.1
                [],                         // and no salt, for the same reason
                hash,                       // pointing back at itself
                ApexTypeBitMap
            )

        );

        return zone;

    }

    private static SOA StartOfAuthority(DomainName Apex)

        => new (Apex,
                DNSQueryClasses.IN,
                Ttl,
                DomainName.Parse($"ns.{Apex.FullName}"),
                SimpleEMailAddress.Parse($"hostmaster@{Apex.FullName.TrimEnd('.')}"),
                2026092301,
                TimeSpan.FromHours(2),
                TimeSpan.FromHours(1),
                TimeSpan.FromDays(14),
                TimeSpan.FromMinutes(5));

    /// <summary>
    /// RFC 4034 §4.1.2 — the types present at the apex of these zones: NS (2),
    /// SOA (6) and the denial record itself. One window, six octets, bit <c>i</c>
    /// of the block standing for type <c>i</c> with bit 0 the most significant.
    /// </summary>
    private static Byte[] ApexTypeBitMap
        => [0x00, 0x06,                                   // window 0, six octets follow
            0x22, 0x00, 0x00, 0x00, 0x00, 0x03];          // NS|SOA … RRSIG|NSEC

    #endregion

    #region Small independent helpers

    /// <summary>
    /// RFC 5155 §5 with zero iterations and no salt: SHA-1 of the name in
    /// uncompressed, lowercased wire form.
    /// </summary>
    /// <remarks>
    /// Written here rather than asked of Hermod. The server looks a hash up in
    /// its own chain; a test that computed the hash the same way would agree
    /// with the server even where both are wrong.
    /// </remarks>
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
    /// RFC 4648 §7 — base32 with the extended hex alphabet, which is what an
    /// NSEC3 owner label is. Twenty octets are a hundred and sixty bits, so
    /// thirty-two characters come out exactly and no padding arises.
    /// </summary>
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

    private static async Task<RawDnsMessage> Ask(HermodServerFixture  Server,
                                                 String               Name,
                                                 UInt16               Type)
    {

        var query = RawDnsWriter.Query(
                        0x4034,
                        Name,
                        Type,
                        ednsPayloadSize: 4096,
                        dnssecOk:        true
                    );

        var raw = await RawDnsProbe.UdpAsync(Server.UdpPort, query);

        Assert.That(raw, Is.Not.Null, $"the server must answer a query for {Name}");

        return RawDnsReader.Parse(raw!);

    }

    #endregion

}

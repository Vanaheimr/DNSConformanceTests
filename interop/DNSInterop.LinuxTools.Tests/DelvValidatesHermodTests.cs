using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSInterop.LinuxTools.Tests;

/// <summary>
/// BIND's validating resolver, <c>delv</c>, judging a signed zone that Hermod
/// serves.
/// </summary>
/// <remarks>
/// <para>
/// This is the one test in the suite that asks an outside party whether Hermod's
/// DNSSEC *serving* is correct. Everything else measures the response against
/// the records BIND wrote — which catches an invented or mangled record, and
/// cannot catch a wrong reading of RFC 4035 §3.1 or RFC 5155 §7, because the
/// same reading produced both the server and the assertions. <c>delv</c> brings
/// its own, from the people who wrote the signer.
/// </para>
/// <para>
/// The trust anchor is the fixture zone's own KSK, handed to <c>delv</c> with
/// <c>+root=dnssec.test</c> so it treats that zone as the top of the world. No
/// real root, no network: the whole chain is the one zone.
/// </para>
/// </remarks>
[TestFixture]
[Category(TestCategories.Wsl)]
public class DelvValidatesHermodTests
{

    private const String NsecZone  = "dnssec.test";
    private const String Nsec3Zone = "nsec3.dnssec.test";

    private HermodServerFixture  nsecServer   = null!;
    private HermodServerFixture  nsec3Server  = null!;
    private String               hostAddress  = null!;
    private String               nsecAnchor   = null!;
    private String               nsec3Anchor  = null!;


    [OneTimeSetUp]
    public async Task StartServers()
    {

        TestEnvironment.RequireWsl("delv");

        if (!SignedZoneFixture.IsAvailableFor(NsecZone) ||
            !SignedZoneFixture.IsAvailableFor(Nsec3Zone))
        {
            Assert.Ignore("The BIND-signed fixtures are missing — run fixtures/zones/resign.sh.");
        }

        var nsecFixture  = SignedZoneFixture.Load(NsecZone);
        var nsec3Fixture = SignedZoneFixture.Load(Nsec3Zone);

        RequireUnexpiredSignatures(nsecFixture);
        RequireUnexpiredSignatures(nsec3Fixture);

        hostAddress  = Wsl.WindowsHostAddress
                           ?? throw new InvalidOperationException("Could not determine the Windows host address as seen from WSL!");

        nsecAnchor   = WriteTrustAnchor(nsecFixture);
        nsec3Anchor  = WriteTrustAnchor(nsec3Fixture);

        // Shared ports, because delv is a real client: the DNSKEY RRset of a
        // 2048-bit RSA zone does not fit in a datagram, and the TCP retry goes to
        // the same endpoint it just asked over UDP.
        nsecServer   = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
                                 Zone                       = nsecFixture. ToZone(),
                                 BindAllInterfaces          = true,
                                 SharePortAcrossTransports  = true
                             });

        nsec3Server  = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
                                 Zone                       = nsec3Fixture.ToZone(),
                                 BindAllInterfaces          = true,
                                 SharePortAcrossTransports  = true
                             });

    }

    [OneTimeTearDown]
    public async Task StopServers()
    {

        if (nsecServer  is not null) await nsecServer. DisposeAsync();
        if (nsec3Server is not null) await nsec3Server.DisposeAsync();

    }


    #region Trust anchors and preconditions

    /// <summary>
    /// A committed fixture carries real signatures, and real signatures expire a
    /// month after they were made. That is a fixture problem rather than a Hermod
    /// one, and <c>delv</c> would report it as "verify failed" — which points at
    /// entirely the wrong thing.
    /// </summary>
    private static void RequireUnexpiredSignatures(SignedZoneFixture Fixture)
    {

        var now      = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var earliest = Fixture.Signatures.Min(sig => (Int64) sig.SignatureExpiration);

        if (earliest < now)
            Assert.Ignore($"The {Fixture.Origin} fixture's signatures expired on " +
                          $"{DateTimeOffset.FromUnixTimeSeconds(earliest):u} — run fixtures/zones/resign.sh.");

    }


    /// <summary>
    /// Write the zone's key-signing key as a <c>bind.keys</c>-style trust anchor,
    /// which is what <c>delv -a</c> reads.
    /// </summary>
    /// <remarks>
    /// The key comes from the DNSKEY records of the signed zone rather than from
    /// the <c>.key</c> file beside them: same key, but taking it from the zone
    /// means the anchor and the data under test came out of the same signing run,
    /// so a re-signed fixture cannot leave the two disagreeing.
    /// </remarks>
    private static String WriteTrustAnchor(SignedZoneFixture Fixture)
    {

        var ksk  = Fixture.KeySigningKey
                       ?? throw new InvalidOperationException($"The {Fixture.Origin} fixture has no key-signing key!");

        var path = Path.Combine(Path.GetTempPath(), $"delv-anchor-{Fixture.Origin}.conf");

        // LF regardless of host: this is read by BIND's config parser inside WSL.
        var text = $"trust-anchors {{\n" +
                   $"    \"{Fixture.Origin}.\" static-key {ksk.Flags} {ksk.Protocol} {ksk.Algorithm} \"{Convert.ToBase64String(ksk.PublicKey)}\";\n" +
                   $"}};\n";

        File.WriteAllText(path, text, new UTF8Encoding(false));

        return Wsl.ToWslPath(path);

    }


    private String Delv(HermodServerFixture  Server,
                        String               Anchor,
                        String               Zone,
                        String               Name,
                        String               Type)
    {

        var result = Wsl.Run(
                         $"delv @{hostAddress} -p {Server.UdpPort} -a {Anchor} +root={Zone} {Name} {Type}",
                         TimeSpan.FromSeconds(30)
                     );

        TestContext.Out.WriteLine($"$ delv @{hostAddress} -p {Server.UdpPort} -a {Anchor} +root={Zone} {Name} {Type}");
        TestContext.Out.WriteLine(result.ToString());

        if (result.ExitCode == -1 ||
            result.StdErr.Contains("timed out",                 StringComparison.OrdinalIgnoreCase) ||
            result.StdErr.Contains("no servers could be reached", StringComparison.OrdinalIgnoreCase))
        {
            Assert.Ignore("WSL cannot reach the Hermod server — usually a Windows Firewall rule blocking the WSL subnet.");
        }

        return result.StdOut + result.StdErr;

    }

    #endregion


    #region Delv_Fully_Validates_A_Signed_Answer()

    [Test]
    [Property("RFC", "4035 §3.1.1")]
    public void Delv_Fully_Validates_A_Signed_Answer()
    {

        var output = Delv(nsecServer, nsecAnchor, NsecZone, $"a.{NsecZone}.", "A");

        Assert.Multiple(() => {

            // "; fully validated" is delv's verdict that it followed the chain
            // from the trust anchor to this RRset and every signature checked.
            Assert.That(output, Does.Contain("fully validated"),
                        "delv must validate the answer, not merely receive it");

            Assert.That(output, Does.Contain("192.0.2.1"));

            Assert.That(output, Does.Not.Contain("unsigned answer"),
                        "an unsigned verdict would mean the RRSIG never arrived");

        });

    }

    #endregion

    #region Delv_Fully_Validates_A_Wildcard_Answer()

    [Test]
    [Property("RFC", "4035 §3.1.3.3")]
    public void Delv_Fully_Validates_A_Wildcard_Answer()
    {

        // The answer that is hardest to serve correctly, and the one where an
        // outside judge earns its keep. Three things have to be right at once:
        // the owner name rewritten to the queried name, the RRSIG's `labels`
        // field still counting the wildcard's, and the NSEC proving the queried
        // name does not exist in its own right. Get any of them wrong and the
        // answer still *looks* fine — it is a validator that says otherwise.
        var output = Delv(nsecServer, nsecAnchor, NsecZone, $"anything.wild.{NsecZone}.", "A");

        Assert.Multiple(() => {
            Assert.That(output, Does.Contain("fully validated"));
            Assert.That(output, Does.Contain("192.0.2.77"), "the wildcard's address");
            Assert.That(output, Does.Contain($"anything.wild.{NsecZone}"),
                        "under the queried name, never the asterisk");
        });

    }

    #endregion

    #region Delv_Fully_Validates_An_Nsec_Denial()

    [Test]
    [Property("RFC", "4035 §3.1.3.2")]
    public void Delv_Fully_Validates_An_Nsec_Denial()
    {

        // A name with no wildcard above it, so this is a real NXDOMAIN and delv
        // has to be satisfied by the NSEC records alone.
        var output = Delv(nsecServer, nsecAnchor, NsecZone, $"zz.{NsecZone}.", "A");

        Assert.Multiple(() => {

            Assert.That(output, Does.Contain("fully validated"),
                        "delv must accept the denial as proven, not just as an RCODE");

            Assert.That(output, Does.Contain("NCACHE nxdomain").Or.Contain("negative response"),
                        "and read it as a name error");

        });

    }

    #endregion

    #region Delv_Fully_Validates_An_Nsec_Nodata()

    [Test]
    [Property("RFC", "4035 §3.1.3.1")]
    public void Delv_Fully_Validates_An_Nsec_Nodata()
    {

        // The name exists and holds an A; asking for TXT must produce a proven
        // NODATA, whose proof is the NSEC matching the name with the TXT bit
        // clear in its bitmap.
        var output = Delv(nsecServer, nsecAnchor, NsecZone, $"a.{NsecZone}.", "TXT");

        Assert.Multiple(() => {
            Assert.That(output, Does.Contain("fully validated"));
            Assert.That(output, Does.Contain("NCACHE nxrrset").Or.Contain("negative response"));
        });

    }

    #endregion

    #region Delv_Fully_Validates_An_Nsec3_Denial()

    [Test]
    [Property("RFC", "5155 §7.2.2")]
    public void Delv_Fully_Validates_An_Nsec3_Denial()
    {

        // The closest encloser proof, judged by someone else's implementation of
        // §8.4. The suite's own tests check that the three roles are filled;
        // this checks that a validator agrees they are filled *correctly*.
        var output = Delv(nsec3Server, nsec3Anchor, Nsec3Zone, $"x.a.{Nsec3Zone}.", "A");

        Assert.Multiple(() => {
            Assert.That(output, Does.Contain("fully validated"));
            Assert.That(output, Does.Contain("NCACHE nxdomain").Or.Contain("negative response"));
        });

    }

    #endregion

    #region Delv_Fully_Validates_The_Dnskey_Rrset()

    [Test]
    [Property("RFC", "4035 §3.1.1")]
    public void Delv_Fully_Validates_The_Dnskey_Rrset()
    {

        // The query every validator has to make first, and the one RRset signed
        // by the key-signing key rather than the zone-signing key. It is also the
        // biggest: two 2048-bit RSA keys plus their signature do not fit in a
        // datagram, so this only passes if the TCP retry reaches the same server.
        var output = Delv(nsecServer, nsecAnchor, NsecZone, $"{NsecZone}.", "DNSKEY");

        Assert.Multiple(() => {
            Assert.That(output, Does.Contain("fully validated"));
            Assert.That(output, Does.Contain("DNSKEY"));
        });

    }

    #endregion

    #region Delv_Refuses_The_Same_Answer_Under_A_Wrong_Trust_Anchor()

    [Test]
    [Property("RFC", "4035 §5")]
    public void Delv_Refuses_The_Same_Answer_Under_A_Wrong_Trust_Anchor()
    {

        // The control that makes every "fully validated" above mean something.
        //
        // A positive-only interop test cannot tell a validator that checked the
        // chain from one that says yes to whatever it is handed. So: publish a
        // trust anchor with the right *name* and the wrong *key* — the other
        // fixture zone's KSK, under dnssec.test. — and ask for the identical
        // record. delv must now refuse it. Same server, same answer, same
        // signatures; only the anchor differs.
        var nsec3Ksk = SignedZoneFixture.Load(Nsec3Zone).KeySigningKey!;
        var path     = Path.Combine(Path.GetTempPath(), "delv-anchor-wrong-key.conf");

        File.WriteAllText(
            path,
            $"trust-anchors {{\n" +
            $"    \"{NsecZone}.\" static-key {nsec3Ksk.Flags} {nsec3Ksk.Protocol} {nsec3Ksk.Algorithm} \"{Convert.ToBase64String(nsec3Ksk.PublicKey)}\";\n" +
            $"}};\n",
            new UTF8Encoding(false)
        );

        var result = Wsl.Run(
                         $"delv @{hostAddress} -p {nsecServer.UdpPort} -a {Wsl.ToWslPath(path)} +root={NsecZone} a.{NsecZone}. A",
                         TimeSpan.FromSeconds(30)
                     );

        TestContext.Out.WriteLine(result.ToString());

        Assert.Multiple(() => {

            Assert.That(result.StdOut, Does.Not.Contain("fully validated"),
                        "an answer that cannot be traced to the configured anchor must not be called validated");

            Assert.That(result.StdOut + result.StdErr,
                        Does.Contain("no valid").IgnoreCase.
                        Or.Contain("broken trust chain").IgnoreCase.
                        Or.Contain("resolution failed").IgnoreCase,
                        "…and delv must say why rather than falling silent");

        });

    }

    #endregion

    #region Delv_Reports_An_Unrelated_Zone_As_Unsigned()

    [Test]
    [Property("RFC", "4035 §5")]
    public void Delv_Reports_An_Unrelated_Zone_As_Unsigned()
    {

        // A control. Pointing delv at the *unsigned* fixture zone with the same
        // trust anchor must not produce "fully validated" — otherwise every
        // assertion above would be satisfied by a tool that says yes to
        // everything, which is the failure mode a positive-only interop test
        // cannot see.
        var result = Wsl.Run(
                         $"delv @{hostAddress} -p {nsecServer.UdpPort} -a {nsecAnchor} +root={NsecZone} " +
                         $"unrelated.example. A",
                         TimeSpan.FromSeconds(30)
                     );

        TestContext.Out.WriteLine(result.ToString());

        Assert.That(result.StdOut, Does.Not.Contain("fully validated"),
                    "a name outside the signed zone must not come back validated");

    }

    #endregion

}

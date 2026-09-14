using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSInterop.LinuxTools.Tests;

/// <summary>
/// <c>delv</c> judging a zone Hermod signed itself, seconds ago, in process.
/// </summary>
/// <remarks>
/// <para>
/// Every other DNSSEC test in this suite serves records BIND wrote. This one
/// has no fixture at all: the keys are generated at start-up, the zone is signed
/// by <see cref="InMemoryDNSZone.Sign"/>, and the trust anchor is built from the
/// public half of the key that did the signing. Nothing on the wire existed
/// before the test ran.
/// </para>
/// <para>
/// That removes the last place Hermod could be marking its own homework. The
/// signer is checked by <c>dnssec-verify</c> elsewhere, but a zone *file* is not
/// an answer: the labels field of a wildcard RRSIG, the opt-out flag, the choice
/// of which records travel with a denial — none of those exist in a file, and
/// all of them are how a validating resolver decides. <c>delv</c> brings BIND's
/// reading of RFC 4035 §3.1 and RFC 5155 §7 to records Hermod produced from
/// nothing but keys.
/// </para>
/// <para>
/// ECDSA P-256 rather than RSA on purpose: the DNSKEY RRset of a 2048-bit RSA
/// zone does not fit in a datagram, and while the fixture handles that by
/// sharing a port across transports, a signing test that also exercises TCP
/// fallback would be testing two things and reporting one.
/// </para>
/// </remarks>
[TestFixture]
[Category(TestCategories.Wsl)]
[Property("RFC", "4035 §2")]
public class DelvValidatesRuntimeSignedZoneTests
{

    #region Data

    private const String Zone = "runtime.test";

    /// <summary>RFC 8624 §3.1 lists ECDSA P-256 as recommended for signing.</summary>
    private const Byte ECDSAP256SHA256 = 13;

    private HermodServerFixture  nsecServer    = null!;
    private HermodServerFixture  nsec3Server   = null!;
    private String               hostAddress   = null!;
    private String               nsecAnchor    = null!;
    private String               nsec3Anchor   = null!;

    #endregion

    #region Setup

    [OneTimeSetUp]
    public async Task StartServers()
    {

        TestEnvironment.RequireWsl("delv");

        hostAddress = Wsl.WindowsHostAddress
                          ?? throw new InvalidOperationException("Could not determine the Windows host address as seen from WSL!");

        var nsecKeys  = KeysFor(Zone);
        var nsec3Keys = KeysFor(Zone);

        var nsecZone  = UnsignedZone().Sign(nsecKeys);
        var nsec3Zone = UnsignedZone().Sign(nsec3Keys, NSEC3: NSEC3Parameters.Recommended);

        nsecAnchor    = WriteTrustAnchor(nsecKeys,  "nsec");
        nsec3Anchor   = WriteTrustAnchor(nsec3Keys, "nsec3");

        nsecServer    = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
                                Zone                       = nsecZone,
                                BindAllInterfaces          = true,
                                SharePortAcrossTransports  = true
                            });

        nsec3Server   = await HermodServerFixture.StartAsync(new HermodServerFixtureOptions {
                                Zone                       = nsec3Zone,
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

    /// <summary>
    /// A key-signing key and a zone-signing key, which is the split RFC 4035 §2
    /// describes and the one <c>dnssec-verify</c> insists on.
    /// </summary>
    private static DNSSECSigningKey[] KeysFor(String Origin)
    {

        var apex = DomainName.Parse($"{Origin}.");

        return [
            DNSSECSigningKey.Generate(apex, ECDSAP256SHA256, KeySigningKey: true),
            DNSSECSigningKey.Generate(apex, ECDSAP256SHA256, KeySigningKey: false)
        ];

    }

    /// <summary>
    /// The zone before anything has signed it: an apex, a delegation, a wildcard
    /// and a gap between names that a denial has to cover.
    /// </summary>
    private static InMemoryDNSZone UnsignedZone()

        => new InMemoryDNSZone().
               AddZoneFile(
                   $"""
                    $ORIGIN {Zone}.
                    $TTL 3600
                    @        IN SOA  ns1.{Zone}. hostmaster.{Zone}. 1 7200 3600 1209600 3600
                    @        IN NS   ns1.{Zone}.
                    ns1      IN A    192.0.2.1
                    a        IN A    192.0.2.10
                    a        IN AAAA 2001:db8::10
                    m        IN MX   10 mail.{Zone}.
                    mail     IN A    192.0.2.20
                    *        IN A    192.0.2.99
                    """
               );

    /// <summary>
    /// The key-signing key as a <c>bind.keys</c>-style trust anchor, which is
    /// what <c>delv -a</c> reads.
    /// </summary>
    private static String WriteTrustAnchor(IEnumerable<DNSSECSigningKey>  Keys,
                                           String                         Which)
    {

        var ksk  = Keys.First(key => key.IsKeySigningKey).DNSKEY;
        var path = Path.Combine(Path.GetTempPath(), $"delv-runtime-{Which}.conf");

        var text = "trust-anchors {\n" +
                  $"    \"{Zone}.\" static-key {ksk.Flags} {ksk.Protocol} {ksk.Algorithm} \"{Convert.ToBase64String(ksk.PublicKey)}\";\n" +
                   "};\n";

        File.WriteAllText(path, text, new UTF8Encoding(false));

        return Wsl.ToWslPath(path);

    }

    private String Delv(HermodServerFixture  Server,
                        String               Anchor,
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
            result.StdErr.Contains("timed out",                   StringComparison.OrdinalIgnoreCase) ||
            result.StdErr.Contains("no servers could be reached", StringComparison.OrdinalIgnoreCase))
        {
            Assert.Ignore($"WSL could not reach the Hermod server at {hostAddress}:{Server.UdpPort} — " +
                          $"usually a Windows Firewall rule blocking the WSL subnet. delv said: {result.StdErr.Trim()}");
        }

        return result.StdOut + result.StdErr;

    }

    #endregion


    #region A signed answer

    [Test]
    [Property("RFC", "4035 §3.1.1")]
    [TestCase("nsec")]
    [TestCase("nsec3")]
    public void Delv_Fully_Validates_An_Answer_Hermod_Signed_Itself(String Denial)
    {

        var output = Delv(Server(Denial), Anchor(Denial), $"a.{Zone}.", "A");

        Assert.Multiple(() => {

            Assert.That(output, Does.Contain("fully validated"),
                        "delv must follow the chain from the anchor to this RRset and check every signature");

            Assert.That(output, Does.Contain("192.0.2.10"));

            Assert.That(output, Does.Not.Contain("unsigned answer"),
                        "an unsigned verdict would mean the RRSIG never arrived");

        });

    }

    #endregion

    #region A wildcard answer

    [Test]
    [Property("RFC", "4035 §3.1.3.3")]
    [TestCase("nsec")]
    [TestCase("nsec3")]
    public void Delv_Fully_Validates_A_Wildcard_Answer(String Denial)
    {

        // The answer where an outside judge earns its keep, and the one whose
        // two hard parts exist only in a response and never in a zone file: the
        // RRSIG's labels field has to count the wildcard rather than the name it
        // was expanded to, and the denial proving the queried name is absent has
        // to travel beside the answer. A mutation against the labels field
        // survived dnssec-verify for exactly this reason.
        var output = Delv(Server(Denial), Anchor(Denial), $"nothing-here.{Zone}.", "A");

        Assert.Multiple(() => {
            Assert.That(output, Does.Contain("fully validated"));
            Assert.That(output, Does.Contain("192.0.2.99"));
        });

    }

    #endregion

    #region A denial

    [Test]
    [Property("RFC", "4035 §3.1.3.2")]
    [TestCase("nsec")]
    [TestCase("nsec3")]
    public void Delv_Validates_A_Nodata_Denial(String Denial)
    {

        // "a" exists with A and AAAA but no TXT. The zone has to prove the type
        // is absent without proving the name is, which is the NODATA proof of
        // RFC 4035 §3.1.3.1 — and under NSEC3 it is a different record entirely
        // from the one an NXDOMAIN needs.
        var output = Delv(Server(Denial), Anchor(Denial), $"a.{Zone}.", "TXT");

        // "resolution failed: ncache nxrrset" is in this output and is not a
        // failure: it is delv saying there are no answer records to print, which
        // is what a NODATA is. The verdict is the line above it.
        var denialRecords = output.Split((Char) 10).
                                Select(line => line.TrimEnd((Char) 13)).
                                Where(line => line.Contains(" NSEC ") || line.Contains(" NSEC3 ")).
                                ToArray();

        Assert.Multiple(() => {

            Assert.That(output, Does.Contain("negative response, fully validated"),
                        "delv must validate the denial, not merely receive it");

            Assert.That(denialRecords, Is.Not.Empty,
                        "a NODATA must carry the denial record that proves it");

            // The proof itself, and the only part of it that can be wrong while
            // everything else looks right: the type bitmap of the record matching
            // the name has to list what the name does have and omit what it does
            // not. A bitmap that included TXT would be proving the opposite of
            // the answer it travels with.
            Assert.That(denialRecords.Any(line => line.Contains(" A ") && line.Contains(" AAAA ")),
                        Is.True,
                        $"the bitmap must list the types that do exist: {String.Join(" | ", denialRecords)}");

            Assert.That(denialRecords.Any(line => line.Contains(" TXT")),
                        Is.False,
                        $"and must not list TXT, which is the type being denied: {String.Join(" | ", denialRecords)}");

            Assert.That(output, Does.Not.Contain("; unsigned answer"));

        });

    }

    #endregion

    #region The DNSKEY RRset itself

    [Test]
    [Property("RFC", "4035 §2.2")]
    [TestCase("nsec")]
    [TestCase("nsec3")]
    public void Delv_Validates_The_Dnskey_Rrset(String Denial)
    {

        // The one RRset signed by the key-signing key rather than the zone
        // signing key. If Sign had published each key twice — which is what an
        // Add-rather-than-replace would do on a second run — this is where it
        // would show.
        var output = Delv(Server(Denial), Anchor(Denial), $"{Zone}.", "DNSKEY");

        Assert.Multiple(() => {
            Assert.That(output, Does.Contain("fully validated"));
            Assert.That(output, Does.Not.Contain("resolution failed"));
        });

    }

    #endregion

    #region Helpers

    private HermodServerFixture Server(String Denial)
        => Denial == "nsec" ? nsecServer : nsec3Server;

    private String Anchor(String Denial)
        => Denial == "nsec" ? nsecAnchor : nsec3Anchor;

    #endregion

}

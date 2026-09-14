using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSInterop.LinuxTools.Tests;

/// <summary>
/// BIND's <c>dnssec-verify</c> judging a zone Hermod signed.
/// </summary>
/// <remarks>
/// <para>
/// Every other DNSSEC test in this suite runs the other way: BIND signs, Hermod
/// validates. That direction is what makes the validator trustworthy, and it is
/// also why it cannot say anything about the signer — a signature checked by the
/// same canonicalisation that produced it proves only that the code agrees with
/// itself.
/// </para>
/// <para>
/// So the signer is measured by the one implementation in the room that has
/// never seen this code. <c>dnssec-verify</c> reads a whole signed zone and
/// checks it the way a secondary would: every authoritative RRset covered by a
/// signature that verifies under a published key, every name in the NSEC chain,
/// and the chain closed. It is a harsher reader than a resolver, because a
/// resolver only ever looks at the part of a zone it was asked about.
/// </para>
/// </remarks>
[TestFixture]
[Category(TestCategories.Wsl)]
public class BindVerifiesHermodSignaturesTests
{

    #region Data

    private const String Zone = "signed-by-hermod.test.";

    #endregion

    #region Setup

    [OneTimeSetUp]
    public void RequireBind()
    {

        if (!Wsl.IsAvailable)
            Assert.Ignore("No POSIX shell available — skipping.");

        if (!Wsl.Run("command -v dnssec-verify", TimeSpan.FromSeconds(20)).Success)
            Assert.Ignore("dnssec-verify is not installed. Needs: apt-get install bind9-utils");

    }

    #endregion

    #region (private static) The zone, and what BIND says about it

    /// <summary>
    /// A small zone with the shapes that make signing interesting: an RRset of
    /// more than one record, a wildcard, and a name that sorts after the
    /// wildcard so the NSEC chain has to order them.
    /// </summary>
    private static List<IDNSResourceRecord> UnsignedZone()

        => [
               new SOA  (DomainName.Parse(Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                         DomainName.Parse("ns1." + Zone),
                         SimpleEMailAddress.Parse("hostmaster@" + Zone.TrimEnd('.')),
                         2026091401, TimeSpan.FromHours(2), TimeSpan.FromHours(1),
                         TimeSpan.FromDays(14), TimeSpan.FromHours(1)),

               new NS   (DomainName.Parse(Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1),
                         DomainName.Parse("ns1." + Zone)),

               new A    (DomainName.Parse("ns1." + Zone),   DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.53")),
               new A    (DomainName.Parse("a."   + Zone),   DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.1")),

               // An RRset of three, which is where canonical ordering inside the
               // signature starts to matter.
               new A    (DomainName.Parse("multi." + Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.12")),
               new A    (DomainName.Parse("multi." + Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.10")),
               new A    (DomainName.Parse("multi." + Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.11")),

               new AAAA (DomainName.Parse("aaaa." + Zone),  DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv6Address.Parse("2001:db8::1")),
               new TXT  (DomainName.Parse("txt."  + Zone),  DNSQueryClasses.IN, TimeSpan.FromHours(1), "signed by Hermod"),
               new MX   (DomainName.Parse("mx."   + Zone),  DNSQueryClasses.IN, TimeSpan.FromHours(1), 10, DomainName.Parse("mail." + Zone)),

               // RFC 4034 §3.1.3's labels field earns its keep here: the RRSIG
               // over a wildcard counts one label fewer than the name has.
               new A    (DomainName.ParseLenient("*.wild." + Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.77"))
           ];

    /// <summary>
    /// Write a signed zone out and hand it to dnssec-verify.
    /// </summary>
    private static (Boolean Success, String Output) Verify(IEnumerable<IDNSResourceRecord> Signed)
    {

        var directory = Path.Combine(Path.GetTempPath(), "hermod-signed-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(directory);

        var file = Path.Combine(directory, Zone + "zone");

        File.WriteAllLines(
            file,
            Signed.Select(record => record.ToZoneFileString())
        );

        try
        {

            var result = Wsl.Run($"dnssec-verify -o {Zone.TrimEnd('.')} '{Wsl.ToWslPath(file)}' 2>&1",
                                 TimeSpan.FromSeconds(60));

            return (result.Success, result.StdOut + result.StdErr);

        }
        finally
        {
            try { Directory.Delete(directory, true); } catch { }
        }

    }

    #endregion

    /// <summary>
    /// The same zone with two things added that only matter once names are
    /// hashed: a name two labels deep whose parent owns nothing, and a
    /// delegation with no DS.
    /// </summary>
    private static List<IDNSResourceRecord> ZoneWithDepthAndDelegation()
    {

        var zone = UnsignedZone();

        // "sub." owns no records at all, and exists only because something lives
        // beneath it. NSEC would never notice; NSEC3 has to hash it (RFC 5155
        // §7.1).
        zone.Add(new A (DomainName.Parse("host.sub." + Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.30")));

        // A delegation and its glue: the NS RRset is the child's, not this
        // zone's, and neither it nor the glue is signed (RFC 4035 §2.2).
        zone.Add(new NS(DomainName.Parse("insecure." + Zone),     DNSQueryClasses.IN, TimeSpan.FromHours(1), DomainName.Parse("ns1.insecure." + Zone)));
        zone.Add(new A (DomainName.Parse("ns1.insecure." + Zone), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.90")));

        return zone;

    }

    #region Bind_Verifies_A_Zone_Hermod_Signed_With_Rsa()

    [Test]
    [Property("RFC", "4035 §2")]
    public void Bind_Verifies_A_Zone_Hermod_Signed_With_Rsa()
    {

        // Algorithm 8, RSA/SHA-256 — the one the IANA root KSK uses, so the same
        // code path as real-world validation.
        using var ksk = DNSSECSigningKey.Generate(DomainName.Parse(Zone), 8, KeySigningKey: true);
        using var zsk = DNSSECSigningKey.Generate(DomainName.Parse(Zone), 8);

        var signed = DNSSECZoneSigner.Sign(UnsignedZone(), DomainName.Parse(Zone), [ ksk, zsk ]);

        var (success, output) = Verify(signed);

        Assert.That(success, Is.True,
                    "dnssec-verify must accept a zone Hermod signed:" + Environment.NewLine + output);

    }

    #endregion

    #region Bind_Verifies_Every_Algorithm_This_Implementation_Signs_With()

    [Test]
    [Property("RFC", "8624 §3.1")]
    [TestCase((Byte)  8, TestName = "Bind_Verifies_RSASHA256")]
    [TestCase((Byte) 10, TestName = "Bind_Verifies_RSASHA512")]
    [TestCase((Byte) 13, TestName = "Bind_Verifies_ECDSAP256SHA256")]
    [TestCase((Byte) 14, TestName = "Bind_Verifies_ECDSAP384SHA384")]
    [TestCase((Byte) 15, TestName = "Bind_Verifies_Ed25519")]
    [TestCase((Byte) 16, TestName = "Bind_Verifies_Ed448")]
    public void Bind_Verifies_Every_Algorithm_This_Implementation_Signs_With(Byte Algorithm)
    {

        // RFC 8624 §3.1 lists what a signer may choose, and DNSSECSigning refuses
        // the two it says MUST NOT be used. Every one it does allow has its own
        // key encoding and its own signature encoding, and those encodings are
        // where implementations disagree — an r||s pair against an ASN.1
        // sequence, a raw Edwards key against a structured one.
        // A key signing key and a zone signing key, which is how a zone is
        // actually keyed — and what dnssec-verify insists on seeing: a key
        // without the Secure Entry Point flag for every algorithm in use, or it
        // calls the zone "not fully signed" however good the signatures are.
        using var ksk = DNSSECSigningKey.Generate(DomainName.Parse(Zone), Algorithm, KeySigningKey: true);
        using var zsk = DNSSECSigningKey.Generate(DomainName.Parse(Zone), Algorithm);

        var signed = DNSSECZoneSigner.Sign(UnsignedZone(), DomainName.Parse(Zone), [ ksk, zsk ]);

        var (success, output) = Verify(signed);

        Assert.That(success, Is.True,
                    $"dnssec-verify must accept algorithm {Algorithm}:" + Environment.NewLine + output);

    }

    #endregion

    #region Bind_Verifies_An_Nsec3_Zone()

    [Test]
    [Property("RFC", "5155 §7.1")]
    public void Bind_Verifies_An_Nsec3_Zone()
    {

        // The hashed chain, with the two shapes a signer gets wrong: an empty
        // non-terminal that has to be hashed although it owns nothing, and a
        // delegation whose NS RRset is not this zone's to sign.
        using var ksk = DNSSECSigningKey.Generate(DomainName.Parse(Zone), 13, KeySigningKey: true);
        using var zsk = DNSSECSigningKey.Generate(DomainName.Parse(Zone), 13);

        var signed = DNSSECZoneSigner.Sign(
                         ZoneWithDepthAndDelegation(),
                         DomainName.Parse(Zone),
                         [ ksk, zsk ],
                         NSEC3: new NSEC3Parameters([ 0xAA, 0xBB, 0xCC, 0xDD ], 12)
                     );

        var (success, output) = Verify(signed);

        Assert.That(success, Is.True,
                    "dnssec-verify must accept an NSEC3 zone Hermod signed:" + Environment.NewLine + output);

    }

    #endregion

    #region Bind_Verifies_An_Nsec3_Zone_With_Opt_Out()

    [Test]
    [Property("RFC", "5155 §6")]
    public void Bind_Verifies_An_Nsec3_Zone_With_Opt_Out()
    {

        // §6: with opt-out the insecure delegation is left out of the chain
        // entirely, and every NSEC3 carries the flag saying so. A verifier that
        // did not know about opt-out would call the zone incomplete, which is how
        // this test tells the two apart.
        using var ksk = DNSSECSigningKey.Generate(DomainName.Parse(Zone), 13, KeySigningKey: true);
        using var zsk = DNSSECSigningKey.Generate(DomainName.Parse(Zone), 13);

        var signed = DNSSECZoneSigner.Sign(
                         ZoneWithDepthAndDelegation(),
                         DomainName.Parse(Zone),
                         [ ksk, zsk ],
                         NSEC3: new NSEC3Parameters([ 0xAA, 0xBB, 0xCC, 0xDD ], 12, OptOut: true)
                     );

        var (success, output) = Verify(signed);

        Assert.That(success, Is.True,
                    "dnssec-verify must accept an opt-out NSEC3 zone:" + Environment.NewLine + output);

    }

    #endregion

    #region Bind_Verifies_Nsec3_With_The_Recommended_Parameters()

    [Test]
    [Property("RFC", "9276 §3.1")]
    public void Bind_Verifies_Nsec3_With_The_Recommended_Parameters()
    {

        // RFC 9276 §3.1 undid most of what NSEC3 was configured with for a
        // decade: no salt and zero extra iterations. An empty salt is the case a
        // signer is most likely to get wrong, because the field then has a length
        // of zero and a "-" in the presentation form.
        using var ksk = DNSSECSigningKey.Generate(DomainName.Parse(Zone), 13, KeySigningKey: true);
        using var zsk = DNSSECSigningKey.Generate(DomainName.Parse(Zone), 13);

        var signed = DNSSECZoneSigner.Sign(
                         ZoneWithDepthAndDelegation(),
                         DomainName.Parse(Zone),
                         [ ksk, zsk ],
                         NSEC3: NSEC3Parameters.Recommended
                     );

        var (success, output) = Verify(signed);

        Assert.That(success, Is.True,
                    "dnssec-verify must accept salt-free, iteration-free NSEC3:" + Environment.NewLine + output);

    }

    #endregion

    #region The_Delegation_Signer_Matches_What_Bind_Computes()

    [Test]
    [Property("RFC", "4034 §5.1.4")]
    public void The_Delegation_Signer_Matches_What_Bind_Computes()
    {

        // The DS is the one thing a parent publishes about a child, so getting it
        // wrong breaks the chain at exactly the point nobody can see. dnssec-verify
        // does not check it — a zone does not hold its own DS — so it is compared
        // against dnssec-dsfromkey, which is what a registrar would run.
        using var ksk = DNSSECSigningKey.Generate(DomainName.Parse(Zone), 8, KeySigningKey: true);

        var directory = Path.Combine(Path.GetTempPath(), "hermod-ds-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(directory);

        var keyFile = Path.Combine(directory, $"K{Zone}+008+{ksk.KeyTag:D5}.key");

        try
        {

            File.WriteAllText(keyFile, ksk.DNSKEY.ToZoneFileString() + "\n");

            var result = Wsl.Run($"dnssec-dsfromkey -2 '{Wsl.ToWslPath(keyFile)}' 2>&1",
                                 TimeSpan.FromSeconds(30));

            Assert.That(result.StdOut, Is.Not.Empty,
                        "dnssec-dsfromkey must read the key: " + result.StdOut + result.StdErr);

            // "<owner> IN DS <keytag> <algorithm> <digesttype> <digest>"
            var fields = result.StdOut.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            var theirs = fields[^1].Trim().ToUpperInvariant();
            var ours   = Convert.ToHexString(ksk.DelegationSigner(2).Digest);

            Assert.Multiple(() => {
                Assert.That(fields[3],  Is.EqualTo(ksk.KeyTag.ToString()), "the key tag agrees");
                Assert.That(ours,       Is.EqualTo(theirs),                "and so does the SHA-256 digest");
            });

        }
        finally
        {
            try { Directory.Delete(directory, true); } catch { }
        }

    }

    #endregion

}

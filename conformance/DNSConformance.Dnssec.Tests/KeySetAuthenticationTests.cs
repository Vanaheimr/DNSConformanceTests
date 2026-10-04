using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4035 §5.2 — a zone's keys are authenticated as one RRset, by the key the
/// anchor or the DS names having signed it.
///
/// <para>
/// A DS, or a trust anchor, names one key. Every other key of the zone — the
/// zone-signing key that signs the answers above all — is trusted only because
/// it stands in the apex DNSKEY RRset, and that RRset is trusted only because the
/// named key signed it. Take the signature over the DNSKEY RRset out of the
/// argument and the named key vouches for nothing but itself: any key published
/// beside it would do.
/// </para>
///
/// <para>
/// The zone below is the BIND-signed fixture, with its genuine key-signing key.
/// What is forged is one key next to it and one answer signed with that key —
/// which is all an attacker on the path needs, because neither the DS nor an
/// anchor says anything about a zone-signing key.
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "4035 §5.2")]
public class KeySetAuthenticationTests
{

    private SignedZoneFixture zone = null!;

    [OneTimeSetUp]
    public void LoadFixture()
    {

        if (!SignedZoneFixture.IsAvailable)
            Assert.Ignore("BIND-signed fixture zone missing — regenerate with: wsl -e sh fixtures/zones/resign.sh");

        zone = SignedZoneFixture.Load();

    }


    #region Helpers

    /// <summary>Where the trust anchor sits, relative to the zone that signed the answer.</summary>
    public enum AnchorAt
    {

        /// <summary>The zone's own DS is the anchor: the anchor names the key-signing key directly.</summary>
        TheZone,

        /// <summary>The anchor is a root two delegations up, and the zone's key is reached by its DS.</summary>
        TheRoot

    }

    private const Byte ECDSAP256SHA256 = 13;

    private static readonly DNSServerConfig Origin = new(IPv4Address.Localhost, IPPort.DNS);

    private static DNSInfo ResponseWith(params IDNSResourceRecord[] Answers)
        => new(Origin, 0, true, false, true, false, DNSResponseCodes.NoError,
               Answers, [], [], true, false, TimeSpan.FromSeconds(5), TimeSpan.Zero);

    private static RRSIG Sign(IEnumerable<IDNSResourceRecord> RRset, DNSSECSigningKey Key)
        => DNSSECZoneSigner.SignRRSet(RRset, Key, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(14));

    /// <summary>
    /// Validate an answer from <c>dnssec.test</c>, whose DNSKEY query is answered
    /// with the given records, under an anchor in the given place.
    /// </summary>
    /// <remarks>
    /// With the anchor at the root, <c>test.</c> and the root are generated here and
    /// every RRset of the chain above the fixture is signed for real: the fixture's
    /// own DS signed by <c>test.</c>, <c>test.</c>'s keys and DS, the root's keys. Only
    /// the zone under test is ever different between two calls.
    /// </remarks>
    private async Task<DNSSECValidationResult> Validate(AnchorAt                  Anchor,
                                                        IDNSResourceRecord[]      ZoneKeySet,
                                                        IDNSResourceRecord[]      Answer)
    {

        var resolver = new StubDnsClient().
                           Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, ZoneKeySet);

        if (Anchor == AnchorAt.TheZone)
            return await new DNSSECValidator(resolver, [ zone.DelegationSigner ]).
                             ValidateAsync(ResponseWith(Answer));

        using var rootKey  = DNSSECSigningKey.Generate(DomainName.Parse("."),    ECDSAP256SHA256, KeySigningKey: true);
        using var testKey  = DNSSECSigningKey.Generate(DomainName.Parse("test"), ECDSAP256SHA256, KeySigningKey: true);

        IDNSResourceRecord[] zoneDS    = [ zone.DelegationSigner ];
        IDNSResourceRecord[] testKeys  = [ testKey.DNSKEY ];
        IDNSResourceRecord[] testDS    = [ testKey.DelegationSigner() ];
        IDNSResourceRecord[] rootKeys  = [ rootKey.DNSKEY ];

        resolver.Answer("dnssec.test", DNSResourceRecordTypes.DS,     [ .. zoneDS,   Sign(zoneDS,   testKey) ]).
                 Answer("test",        DNSResourceRecordTypes.DNSKEY, [ .. testKeys, Sign(testKeys, testKey) ]).
                 Answer("test",        DNSResourceRecordTypes.DS,     [ .. testDS,   Sign(testDS,   rootKey) ]).
                 Answer(".",           DNSResourceRecordTypes.DNSKEY, [ .. rootKeys, Sign(rootKeys, rootKey) ]);

        return await new DNSSECValidator(resolver, [ rootKey.DelegationSigner() ]).
                         ValidateAsync(ResponseWith(Answer));

    }

    #endregion


    #region A_Forged_Zone_Signing_Key_Beside_The_Genuine_Key_Signing_Key_Is_Bogus(Anchor)

    /// <summary>
    /// RFC 4035 §5.2 lists what makes the step from a DS to a child zone's keys
    /// sound, and the third condition is the one that ties the zone-signing key to
    /// the key the DS is about:
    /// </summary>
    /// <remarks>
    /// <para>
    /// "The matching DNSKEY RR in the child zone has the Zone Flag bit set, the
    /// corresponding private key has signed the child zone's apex DNSKEY RRset, and
    /// the resulting RRSIG RR authenticates the child zone's apex DNSKEY RRset."
    /// </para>
    /// <para>
    /// The DNSKEY RRset served here is the fixture's genuine key-signing key and a
    /// zone-signing key generated a moment ago, under the same owner name. Beside
    /// them stand the two signatures an attacker can offer: the genuine RRSIG over
    /// the genuine RRset, replayed — it covered another set of keys, so it no
    /// longer verifies — and one made with the forged key over the forged set,
    /// which verifies and names a key no DS and no anchor names. The answer, an A
    /// record for <c>a.dnssec.test</c> with an address the zone never published, is
    /// signed with the forged key.
    /// </para>
    /// <para>
    /// The signature over the answer is good. The key-signing key is genuine, and
    /// its digest is the DS — or the anchor. A walk that checks the DS against
    /// "a key of the RRset" and never verifies the signature over the RRset has no
    /// reason to object, and calls the forged address Secure. For a DANE client
    /// that is the one verdict that may not be wrong: a forged TLSA RRset read as
    /// Secure is a certificate the client will accept for the server it believes
    /// it is talking to (RFC 7672 §2.2).
    /// </para>
    /// <para>
    /// Both places the anchor can sit are tried. At the zone, the anchor is
    /// compared with the zone's keys directly; at the root, two delegations up, the
    /// zone's DS is — and the chain above the fixture is signed for real, every
    /// RRset of it, so that the only thing wrong anywhere is the forged key. The
    /// genuine zone, with the same scaffolding, is the control: Secure in both
    /// places.
    /// </para>
    /// </remarks>
    [TestCase(AnchorAt.TheZone, TestName = "A_Forged_Zone_Signing_Key_Beside_The_Genuine_Key_Signing_Key_Is_Bogus(anchor at the zone)")]
    [TestCase(AnchorAt.TheRoot, TestName = "A_Forged_Zone_Signing_Key_Beside_The_Genuine_Key_Signing_Key_Is_Bogus(anchor at the root)")]
    [Property("RFC", "4035 §5.2, 7672 §2.2")]
    public async Task A_Forged_Zone_Signing_Key_Beside_The_Genuine_Key_Signing_Key_Is_Bogus(AnchorAt Anchor)
    {

        var genuineKSK        = zone.KeySigningKey!;
        var genuineKeySet     = zone.RRset("dnssec.test", DNSResourceRecordTypes.DNSKEY);
        var genuineSignature  = zone.SignatureFor("dnssec.test", DNSResourceRecordTypes.DNSKEY)!;

        var (genuineA, genuineASignature) = (zone.RRset("a.dnssec.test", DNSResourceRecordTypes.A),
                                             zone.SignatureFor("a.dnssec.test", DNSResourceRecordTypes.A)!);

        // The control: the zone as BIND signed it, through the same chain.
        Assert.That(await Validate(Anchor,
                                   [ .. genuineKeySet, genuineSignature ],
                                   [ .. genuineA,      genuineASignature ]),
                    Is.EqualTo(DNSSECValidationResult.Secure),
                    "the genuine zone validates through this chain, so the chain itself is sound");

        using var forgedZSK   = DNSSECSigningKey.Generate(DomainName.Parse("dnssec.test"), ECDSAP256SHA256);

        IDNSResourceRecord[] forgedKeySet  = [ forgedZSK.DNSKEY, genuineKSK ];
        IDNSResourceRecord[] forgedA       = [ new A(DomainName.Parse("a.dnssec.test"),
                                                     DNSQueryClasses.IN,
                                                     TimeSpan.FromSeconds(genuineASignature.OriginalTTL),
                                                     IPv4Address.Parse("192.0.2.66")) ];

        var result = await Validate(Anchor,
                                    [ .. forgedKeySet, genuineSignature, Sign(forgedKeySet, forgedZSK) ],
                                    [ .. forgedA,      Sign(forgedA, forgedZSK) ]);

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "no key the anchor or the DS names has signed the DNSKEY RRset that holds the key the answer was signed with");

    }

    #endregion

}

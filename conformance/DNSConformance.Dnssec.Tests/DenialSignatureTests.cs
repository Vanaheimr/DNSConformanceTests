using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4035 §5.4 — the signature half of a denial.
///
/// <para>
/// A denial of existence is two claims, and the records that carry them are
/// ordinary records of the zone: the NSEC or NSEC3 chain says the name is
/// absent, and an RRSIG over that chain says the zone is the one saying so.
/// §5.4 is explicit that the second is not optional — "the resolver MUST
/// authenticate the NSEC RRset" — because an unauthenticated proof is a proof an
/// attacker can write.
/// </para>
///
/// <para>
/// So the denial path repeats, on the authority section, every check the answer
/// path makes on the answer section: the validity window, the key the signature
/// names, the signature itself, and the chain up to a trust anchor. They are a
/// second implementation of the same four rules, and a mutation sweep could
/// change any of them without a test noticing. <see cref="DenialOfExistenceTests"/>
/// covers what the chain *proves*; this covers whether anyone had the right to
/// say it.
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "4035 §5.4")]
public class DenialSignatureTests
{

    private SignedZoneFixture? zone;

    [OneTimeSetUp]
    public void LoadZone()
    {
        if (SignedZoneFixture.IsAvailableFor("dnssec.test"))
            zone = SignedZoneFixture.Load("dnssec.test");
    }

    private SignedZoneFixture Zone
        => zone ?? throw new IgnoreException("dnssec.test is missing — run fixtures/zones/resign.sh (needs WSL + bind9utils).");


    #region Helpers

    /// <summary>
    /// A negative response: nothing in the answer section, the denial records in
    /// the authority section.
    /// </summary>
    private static DNSInfo DenialResponse(IEnumerable<IDNSResourceRecord>  Authorities,
                                          DNSResponseCodes                 ResponseCode = DNSResponseCodes.NameError)

        => new(new DNSServerConfig(IPv4Address.Localhost, IPPort.DNS),
               0,
               true, false, true, false,
               ResponseCode,
               [],
               [.. Authorities],
               [],
               true, false,
               TimeSpan.FromSeconds(5),
               TimeSpan.Zero);

    private static StubDnsClient ResolverServing(params IDNSResourceRecord[] Records)
        => new StubDnsClient().Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, Records);

    /// <summary>
    /// The given keys of <c>dnssec.test</c> beside a key-signing key, in one key set
    /// that key signs — the DNSKEY answer for a zone whose key set holds a key
    /// BIND never published, which the fixture's own key-signing key cannot sign.
    /// </summary>
    private static IDNSResourceRecord[] KeySetSignedBy(DNSSECSigningKey KeySigningKey, params DNSKEY[] Keys)
    {

        IDNSResourceRecord[] keySet = [.. Keys, KeySigningKey.DNSKEY];

        return [.. keySet,
                DNSSECZoneSigner.SignRRSet(keySet,
                                           KeySigningKey,
                                           DateTime.UtcNow.AddDays(-1),
                                           DateTime.UtcNow.AddDays(14))];

    }

    /// <summary>The same key material under different flags — same key, different tag.</summary>
    private static DNSKEY WithFlags(DNSKEY Key, UInt16 Flags)
        => new (DomainName.Parse(Key.DomainName.FullName.TrimEnd('.')),
                Key.Class,
                Key.TimeToLive,
                Flags,
                Key.Protocol,
                Key.Algorithm,
                Key.PublicKey);

    /// <summary>
    /// RFC 4034 §5.1.4's digest, computed here rather than asked of Hermod:
    /// SHA-256 over the canonical owner name followed by the DNSKEY RDATA.
    /// </summary>
    private static DS DelegationSignerFor(DNSKEY Key)
    {

        var rdata = new MemoryStream();

        foreach (var label in Key.DomainName.FullName.ToLowerInvariant().TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            rdata.WriteByte((Byte) bytes.Length);
            rdata.Write(bytes);
        }

        rdata.WriteByte(0x00);
        rdata.WriteByte((Byte) (Key.Flags >> 8));
        rdata.WriteByte((Byte) (Key.Flags & 0xFF));
        rdata.WriteByte(Key.Protocol);
        rdata.WriteByte(Key.Algorithm);
        rdata.Write(Key.PublicKey);

        return new DS(DomainName.Parse(Key.DomainName.FullName.TrimEnd('.')),
                      DNSQueryClasses.IN,
                      TimeSpan.FromDays(1),
                      DNSSECValidator.ComputeKeyTag(Key),
                      Key.Algorithm,
                      2,
                      SHA256.HashData(rdata.ToArray()));

    }

    /// <summary>The whole NSEC chain, which proves a name below the apex is absent.</summary>
    private (DNSInfo Response, (DomainName, DNSResourceRecordTypes) Question) ProvenDenial()
        => (DenialResponse(Zone.Records),
            (DomainName.Parse("nothing-here.dnssec.test."), DNSResourceRecordTypes.A));

    /// <summary>The RRSIG the denial path will check first.</summary>
    private RRSIG DenialSignature()
        => Zone.Records.OfType<RRSIG>().
                First(rrsig => rrsig.TypeCovered == DNSResourceRecordTypes.NSEC);

    #endregion


    #region The_Denial_Window_Includes_Both_Of_Its_Own_Seconds()

    /// <summary>
    /// RFC 4034 §3.1.5: "The RRSIG record is valid from the Signature Inception
    /// field's value until the Signature Expiration field's value". The denial
    /// path has its own copy of that comparison, on its own line, and the four
    /// ways to be wrong by one second are the same four.
    ///
    /// <para>
    /// This matters more here than on the answer side, not less. An expired
    /// denial is a replay of a "no such name" from before the name existed, and
    /// it is the one replay that costs nothing to obtain: every resolver on the
    /// internet has been handed one. The first two assertions are also the
    /// control for the three tests below — the same response, the same keys, and
    /// a verdict of Secure.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4034 §3.1.5")]
    public async Task The_Denial_Window_Includes_Both_Of_Its_Own_Seconds()
    {

        var (response, question) = ProvenDenial();

        var validator  = new DNSSECValidator(ResolverServing(Zone.KeySetAnswer),
                                             [Zone.DelegationSigner]);

        var signature  = DenialSignature();
        var inception  = DateTimeOffset.FromUnixTimeSeconds(signature.SignatureInception);
        var expiration = DateTimeOffset.FromUnixTimeSeconds(signature.SignatureExpiration);

        Assert.Multiple(async () => {

            Assert.That(await validator.ValidateAsync(response, question, inception),
                        Is.EqualTo(DNSSECValidationResult.Secure),
                        "the inception second is inside the window");

            Assert.That(await validator.ValidateAsync(response, question, expiration),
                        Is.EqualTo(DNSSECValidationResult.Secure),
                        "and so is the expiration second");

            Assert.That(await validator.ValidateAsync(response, question, inception.AddSeconds(-1)),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "the second before the inception is not");

            Assert.That(await validator.ValidateAsync(response, question, expiration.AddSeconds(1)),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "nor the second after the expiration — a denial does not outlive its signature");

        });

    }

    #endregion

    #region A_Denial_Is_Not_Validated_By_A_Key_It_Did_Not_Name()

    /// <summary>
    /// RFC 4035 §5.3.1, on this side of the house: the RRSIG names its key by
    /// algorithm *and* key tag, and a validator that settled for one of the two
    /// would be picking keys by a sixteen-bit checksum.
    ///
    /// <para>
    /// The construction is the one <see cref="KeyIdentityTests"/> uses, because
    /// it is the only one that separates "looked the key up properly" from
    /// "found something that worked": the tag covers the DNSKEY's flags, so the
    /// same key material under a different SEP bit is the same key with a
    /// different tag. The zone publishes that, beside a key-signing key of
    /// another algorithm that signs the key set and is the anchor — so nothing
    /// further up the chain is what refuses the denial, and a validator matching
    /// on algorithm alone would find the relabelled key, verify the signature
    /// over the NSEC chain, and call the denial Secure.
    /// </para>
    ///
    /// <para>
    /// The key set has to be signed for that to hold. Since finding 67 a key set
    /// nobody signed is refused on its own, and a test that served one would pass
    /// for that reason whatever the lookup did.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4035 §5.3.1")]
    public async Task A_Denial_Is_Not_Validated_By_A_Key_It_Did_Not_Name()
    {

        var (response, question) = ProvenDenial();

        var signing   = Zone.KeyFor(DenialSignature())!;
        var relabel   = WithFlags(signing, (UInt16) (signing.Flags ^ 0x0001));

        Assert.That(DNSSECValidator.ComputeKeyTag(relabel),
                    Is.Not.EqualTo(DenialSignature().KeyTag),
                    "the relabelled key is not the one the signature names");

        using var ksk = DNSSECSigningKey.Generate(DomainName.Parse("dnssec.test"), 13, KeySigningKey: true);

        Assert.That(ksk.Algorithm, Is.Not.EqualTo(DenialSignature().Algorithm),
                    "an algorithm-only lookup finds the relabelled key and nothing else");

        Assert.Multiple(async () => {

            Assert.That(await new DNSSECValidator(ResolverServing(KeySetSignedBy(ksk, signing)),
                                                  [DelegationSignerFor(ksk.DNSKEY)]).
                                  ValidateAsync(response, question),
                        Is.EqualTo(DNSSECValidationResult.Secure),
                        "the control: the key the signature names, in the same signed key set");

            Assert.That(await new DNSSECValidator(ResolverServing(KeySetSignedBy(ksk, relabel)),
                                                  [DelegationSignerFor(ksk.DNSKEY)]).
                                  ValidateAsync(response, question),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "the relabelled key would verify this signature, and it is not the one named");

        });

    }

    #endregion

    #region A_Signed_Denial_That_Proves_Nothing_Is_Bogus()

    /// <summary>
    /// The two checks are independent and neither is sufficient. Here the
    /// signature is genuine, the key is the right one and the chain reaches the
    /// anchor — and the records still do not deny what was asked.
    ///
    /// <para>
    /// One NSEC is offered, the one at <c>mx.dnssec.test</c>, whose span runs to
    /// <c>ns1</c>. The question is about <c>b.dnssec.test</c>, which is nowhere
    /// near it. That is the shape of an attacker replaying a denial the zone
    /// really did sign, for a name other than the one being asked about: every
    /// cryptographic check passes and the answer is still a lie.
    /// </para>
    /// </summary>
    [Test]
    public async Task A_Signed_Denial_That_Proves_Nothing_Is_Bogus()
    {

        var nsec      = Zone.RRset("mx.dnssec.test", DNSResourceRecordTypes.NSEC);
        var signature = Zone.SignatureFor("mx.dnssec.test", DNSResourceRecordTypes.NSEC)!;

        Assert.That(nsec, Is.Not.Empty, "the fixture has an NSEC at mx.dnssec.test");

        var validator = new DNSSECValidator(ResolverServing(Zone.KeySetAnswer),
                                            [Zone.DelegationSigner]);

        var result    = await validator.ValidateAsync(
                                  DenialResponse([.. nsec, signature]),
                                  (DomainName.Parse("b.dnssec.test."), DNSResourceRecordTypes.A)
                              );

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "authentic records that do not cover the name prove nothing about it");

    }

    #endregion

    #region A_Proven_Denial_Whose_Chain_Is_Broken_Is_Not_Secure()

    /// <summary>
    /// And the same independence from the other side: the records prove exactly
    /// what was asked, and the zone they came from cannot be traced to a trust
    /// anchor.
    ///
    /// <para>
    /// The anchor here names the right key by tag and algorithm and carries a
    /// digest that is not that key's, which is what a resolver holds after a
    /// rollover it did not follow — or what an attacker's zone looks like to a
    /// resolver that never had an anchor for it. A well-formed proof from a zone
    /// nobody vouches for must not come back Secure, or the chain of trust is
    /// decoration: anyone able to sign a zone could deny any name in it.
    /// </para>
    /// </summary>
    [Test]
    public async Task A_Proven_Denial_Whose_Chain_Is_Broken_Is_Not_Secure()
    {

        var (response, question) = ProvenDenial();

        var real      = Zone.DelegationSigner;

        var wrong     = new DS(DomainName.Parse("dnssec.test"),
                               DNSQueryClasses.IN,
                               TimeSpan.FromDays(1),
                               real.KeyTag,
                               real.Algorithm,
                               real.DigestType,
                               [.. real.Digest.Select(b => (Byte) (b ^ 0xFF))]);

        var validator = new DNSSECValidator(ResolverServing(Zone.KeySetAnswer), [wrong]);

        Assert.That(await validator.ValidateAsync(response, question),
                    Is.Not.EqualTo(DNSSECValidationResult.Secure),
                    "a proof is only worth the chain behind it");

    }

    #endregion

    #region An_Unsigned_NSEC_Beside_A_Signed_One_Proves_Nothing()

    /// <summary>
    /// Finding 70. A denial is read from the records whose signatures were checked,
    /// and from no others.
    ///
    /// <para>
    /// The authority section holds BIND's NSEC at <c>mx.dnssec.test</c> with its
    /// genuine signature — authentic, replayable, and about a span nowhere near the
    /// question — and an NSEC at <c>a.dnssec.test</c> that BIND never wrote: no
    /// signature, and a type bitmap that leaves out A. The question is the A
    /// record of <c>a.dnssec.test</c>, which exists. The signed record proves
    /// nothing about it; the record that would prove something is signed by
    /// nobody. §5.4: "security-aware resolvers MUST authenticate the NSEC RRsets
    /// that comprise the non-existence proof" — the ones the proof rests on.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4035 §5.4")]
    public async Task An_Unsigned_NSEC_Beside_A_Signed_One_Proves_Nothing()
    {

        var genuine   = Zone.RRset("mx.dnssec.test", DNSResourceRecordTypes.NSEC);
        var signature = Zone.SignatureFor("mx.dnssec.test", DNSResourceRecordTypes.NSEC)!;

        // RFC 4034 §4.1.2, written out: window 0, six octets of bitmap, TXT (16),
        // RRSIG (46) and NSEC (47) — and no A.
        var forged    = new NSEC(DomainName.Parse("a.dnssec.test"),
                                 DNSQueryClasses.IN,
                                 TimeSpan.FromHours(1),
                                 DomainName.Parse("aaaa.dnssec.test"),
                                 [0x00, 0x06, 0x00, 0x00, 0x80, 0x00, 0x00, 0x03]);

        var validator = new DNSSECValidator(ResolverServing(Zone.KeySetAnswer),
                                            [Zone.DelegationSigner]);

        var result    = await validator.ValidateAsync(
                                  DenialResponse([.. genuine, signature, forged], DNSResponseCodes.NoError),
                                  (DomainName.Parse("a.dnssec.test."), DNSResourceRecordTypes.A)
                              );

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "the only NSEC that denies the A record carries no signature");

    }

    #endregion

}

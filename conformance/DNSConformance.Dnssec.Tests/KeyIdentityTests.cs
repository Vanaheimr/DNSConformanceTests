using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4035 §5.3.1 and RFC 4034 §5.1 — which key a signature names, and which key
/// a trust anchor names.
///
/// <para>
/// The key tag is a checksum, not an identifier: RFC 4034 Appendix B computes it
/// by adding up the RDATA, and §5.1 says plainly that it "is not a unique
/// identifier". That is why every place in a validator that looks a key up does
/// so by tag *and* algorithm, and why a validator that settled for one of the two
/// would be picking keys by a sixteen-bit sum.
/// </para>
///
/// <para>
/// The trick these tests turn on is that the tag covers the DNSKEY's flags. The
/// same key material under a different SEP bit is the same key with a different
/// tag — so a signature can be offered a key that will verify it and is not the
/// one it named, which is the only way to tell "looked the key up properly" apart
/// from "found something that worked".
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "4035 §5.3.1")]
public class KeyIdentityTests
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

    private static readonly DNSServerConfig Origin = new(IPv4Address.Localhost, IPPort.DNS);

    private static DNSInfo ResponseWith(params IDNSResourceRecord[] Answers)
        => new(Origin, 0, true, false, true, false, DNSResponseCodes.NoError,
               Answers, [], [], true, false, TimeSpan.FromSeconds(5), TimeSpan.Zero);

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

    private StubDnsClient ResolverServing(params DNSKEY[] Keys)
        => new StubDnsClient().Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, [.. Keys]);

    private (List<IDNSResourceRecord> RRset, RRSIG Signature) SignedA()
        => (zone.RRset("a.dnssec.test", DNSResourceRecordTypes.A),
            zone.SignatureFor("a.dnssec.test", DNSResourceRecordTypes.A)!);

    #endregion


    #region The_Same_Key_Under_Different_Flags_Has_A_Different_Tag()

    /// <summary>
    /// The premise the two cases below rest on, asserted rather than assumed: the
    /// tag is a sum over the whole RDATA, flags included, so changing the SEP bit
    /// changes the tag while leaving the key that verifies signatures untouched.
    /// </summary>
    [Test]
    [Property("RFC", "4034 App. B")]
    public void The_Same_Key_Under_Different_Flags_Has_A_Different_Tag()
    {

        var signing = zone.KeyFor(SignedA().Signature)!;
        var relabel = WithFlags(signing, (UInt16) (signing.Flags ^ 0x0001));

        Assert.Multiple(() => {

            Assert.That(relabel.PublicKey, Is.EqualTo(signing.PublicKey),
                        "the key material is untouched");

            Assert.That(DNSSECValidator.ComputeKeyTag(relabel),
                        Is.Not.EqualTo(DNSSECValidator.ComputeKeyTag(signing)),
                        "and the tag is not, because Appendix B sums the flags too");

        });

    }

    #endregion

    #region A_Signature_Is_Not_Validated_By_A_Key_It_Did_Not_Name()

    /// <summary>
    /// RFC 4035 §5.3.1: the RRSIG's "Algorithm, and Key Tag fields MUST match the
    /// owner name, algorithm, and key tag for some DNSKEY RR in the zone's apex
    /// DNSKEY RRset".
    ///
    /// Here the zone publishes only the relabelled key. It will verify the
    /// signature — it is the same key material — and its tag is not the one the
    /// signature names. A validator that looked keys up by algorithm alone would
    /// find it, verify, and report Secure; one that reads §5.3.1 has no key to
    /// use and must say so.
    /// </summary>
    [Test]
    public async Task A_Signature_Is_Not_Validated_By_A_Key_It_Did_Not_Name()
    {

        var (rrset, signature) = SignedA();

        var signing   = zone.KeyFor(signature)!;
        var relabel   = WithFlags(signing, (UInt16) (signing.Flags ^ 0x0001));

        Assert.That(DNSSECValidator.ComputeKeyTag(relabel), Is.Not.EqualTo(signature.KeyTag));

        // The anchor is the relabelled key's own DS, so nothing further up the
        // chain is what refuses the answer.
        var validator = new DNSSECValidator(ResolverServing(relabel),
                                            [DelegationSignerFor(relabel)]);

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "the only published key would verify this signature, and it is not the one named");

    }

    #endregion

    #region A_Signature_Is_Validated_By_The_Key_It_Names()

    /// <summary>
    /// The control for the case above: the same construction with the key the
    /// signature actually names, which must come out Secure. Without it, the case
    /// above passes for a validator that refuses everything.
    /// </summary>
    [Test]
    public async Task A_Signature_Is_Validated_By_The_Key_It_Names()
    {

        var (rrset, signature) = SignedA();

        var signing   = zone.KeyFor(signature)!;

        var validator = new DNSSECValidator(ResolverServing(signing),
                                            [DelegationSignerFor(signing)]);

        var result    = await validator.ValidateAsync(ResponseWith([.. rrset, signature]));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure),
                    "named key, published key, and a trust anchor over it");

    }

    #endregion

    #region A_Trust_Anchor_Names_Its_Key_By_Tag_And_Algorithm()

    /// <summary>
    /// The same rule one level up. A DS identifies the key it delegates to by tag
    /// and algorithm (RFC 4034 §5.1), and a validator that matched on one of the
    /// two would pick an anchor by a sixteen-bit checksum — or by "any anchor of
    /// this algorithm", which for a zone with several is every anchor it has.
    ///
    /// The digest check behind it would catch a wrongly chosen anchor, so what
    /// these two decoys show is that the lookup does not *reach* the digest with
    /// the wrong anchor: each decoy carries the right digest for a key it does not
    /// name.
    /// </summary>
    [Test]
    [Property("RFC", "4034 §5.1")]
    public async Task A_Trust_Anchor_Names_Its_Key_By_Tag_And_Algorithm()
    {

        var (rrset, signature) = SignedA();

        var signing  = zone.KeyFor(signature)!;
        var correct  = DelegationSignerFor(signing);

        // Right digest, right algorithm, a tag that is one off.
        var wrongTag = new DS(DomainName.Parse("dnssec.test"), DNSQueryClasses.IN, TimeSpan.FromDays(1),
                              (UInt16) (correct.KeyTag + 1), correct.Algorithm, correct.DigestType, correct.Digest);

        // Right digest, right tag, an algorithm that is not the key's.
        var wrongAlg = new DS(DomainName.Parse("dnssec.test"), DNSQueryClasses.IN, TimeSpan.FromDays(1),
                              correct.KeyTag, (Byte) (correct.Algorithm + 1), correct.DigestType, correct.Digest);

        Assert.Multiple(async () => {

            Assert.That(await new DNSSECValidator(ResolverServing(signing), [correct]).
                                  ValidateAsync(ResponseWith([.. rrset, signature])),
                        Is.EqualTo(DNSSECValidationResult.Secure),
                        "the anchor that names the key");

            Assert.That(await new DNSSECValidator(ResolverServing(signing), [wrongTag]).
                                  ValidateAsync(ResponseWith([.. rrset, signature])),
                        Is.Not.EqualTo(DNSSECValidationResult.Secure),
                        "an anchor whose tag is not the key's does not anchor it");

            Assert.That(await new DNSSECValidator(ResolverServing(signing), [wrongAlg]).
                                  ValidateAsync(ResponseWith([.. rrset, signature])),
                        Is.Not.EqualTo(DNSSECValidationResult.Secure),
                        "nor does one whose algorithm is not the key's");

        });

    }

    #endregion

}

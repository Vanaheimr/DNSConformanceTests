using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4035 §5.2 — the step up from one zone to the next.
///
/// <para>
/// A chain of trust is a repeated move: the DS in the parent authenticates the
/// child's key, and the parent's own key then has to be authenticated the same
/// way one level further up, until a key is reached that the resolver was
/// configured to believe. Every test elsewhere in this suite anchors the fixture
/// zone with its own DS, which is the shortest possible chain — the very first
/// check inside the walk succeeds and the step is never taken.
/// </para>
///
/// <para>
/// So the step itself was unwatched. These tests anchor one level *above* the
/// fixture, at a parent zone invented for the purpose, which forces the walk to
/// fetch the DS, cross into the parent, and decide which of the parent's keys to
/// carry up. The child half is genuine — BIND's signature over BIND's zone,
/// verified before the walk is reached — and only the zones above it are
/// constructed.
/// </para>
///
/// <para>
/// Constructed, and signed for real: the DS RRset each parent publishes for its
/// child and each parent's DNSKEY RRset carry signatures made here with keys
/// generated here. They used to be filler octets, on the reasoning that the walk
/// read the RRSIG over a parent's DNSKEY RRset only for the key tag it named and
/// that the next DS check up asserted everything a real signature would. That
/// reasoning described the validator rather than RFC 4035 §5.2, and it was
/// finding 67: a key set whose signature nobody checks is a key set anyone can
/// add a key to.
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "4035 §5.2")]
public class ChainWalkTests
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

    private const Byte ECDSAP256SHA256 = 13;

    private static readonly DNSServerConfig Origin = new(IPv4Address.Localhost, IPPort.DNS);

    private static DNSInfo ResponseWith(params IDNSResourceRecord[] Answers)
        => new(Origin, 0, true, false, true, false, DNSResponseCodes.NoError,
               Answers, [], [], true, false, TimeSpan.FromSeconds(5), TimeSpan.Zero);

    /// <summary>A key-signing key of the parent zone <c>test.</c>.</summary>
    private static DNSSECSigningKey ParentKey()
        => DNSSECSigningKey.Generate(DomainName.Parse("test"), ECDSAP256SHA256, KeySigningKey: true);

    /// <summary>A key-signing key of the root zone, for the step above the parent.</summary>
    private static DNSSECSigningKey RootKey()
        => DNSSECSigningKey.Generate(DomainName.Parse("."), ECDSAP256SHA256, KeySigningKey: true);

    private static RRSIG Sign(IEnumerable<IDNSResourceRecord> RRset, DNSSECSigningKey Key)
        => DNSSECZoneSigner.SignRRSet(RRset, Key, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(14));

    /// <summary>
    /// A zone's answer to its DNSKEY query: the keys, in the order given, and the
    /// signature one of them made over all of them.
    /// </summary>
    private static IDNSResourceRecord[] KeySet(DNSSECSigningKey Signer, params DNSSECSigningKey[] Keys)
    {
        IDNSResourceRecord[] keys = [.. Keys.Select(key => key.DNSKEY)];
        return [.. keys, Sign(keys, Signer)];
    }

    /// <summary>A DS RRset with the signature of the parent that publishes it.</summary>
    private static IDNSResourceRecord[] SignedDS(DNSSECSigningKey Parent, params DS[] DelegationSigners)
    {
        IDNSResourceRecord[] ds = [.. DelegationSigners];
        return [.. ds, Sign(ds, Parent)];
    }

    /// <summary>
    /// RFC 4034 §5.1.4's digest, computed here rather than asked of Hermod:
    /// SHA-256 over the canonical owner name followed by the DNSKEY RDATA.
    /// </summary>
    private static DS DelegationSignerFor(DNSKEY Key)
    {

        var rdata = new MemoryStream();

        // The root has no labels, only the terminator written below.
        foreach (var label in Key.DomainName.FullName.ToLowerInvariant().TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
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

        return new DS(DomainName.ParseLenient(Key.DomainName.FullName),
                      DNSQueryClasses.IN,
                      TimeSpan.FromDays(1),
                      DNSSECValidator.ComputeKeyTag(Key),
                      Key.Algorithm,
                      2,
                      SHA256.HashData(rdata.ToArray()));

    }

    /// <summary>
    /// A resolver serving the fixture zone's keys, the fixture zone's own DS —
    /// which is what the walk asks the parent for — signed by the given key of
    /// the parent, and whatever the parent publishes under its DNSKEY.
    /// </summary>
    private StubDnsClient ResolverWithParent(DNSSECSigningKey DSSigner, params IDNSResourceRecord[] ParentDnskeyAnswer)
        => new StubDnsClient().
               Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, zone.KeySetAnswer).
               Answer("dnssec.test", DNSResourceRecordTypes.DS,     SignedDS(DSSigner, zone.DelegationSigner)).
               Answer("test",        DNSResourceRecordTypes.DNSKEY, ParentDnskeyAnswer);

    private (List<IDNSResourceRecord> RRset, RRSIG Signature) SignedA()
        => (zone.RRset("a.dnssec.test", DNSResourceRecordTypes.A),
            zone.SignatureFor("a.dnssec.test", DNSResourceRecordTypes.A)!);

    private async Task<DNSSECValidationResult> Validate(StubDnsClient Resolver, params DS[] Anchors)
    {

        var (rrset, signature) = SignedA();

        return await new DNSSECValidator(Resolver, [.. Anchors]).
                         ValidateAsync(ResponseWith([.. rrset, signature]));

    }

    #endregion


    #region The_Root_Has_No_Parent_To_Step_Into()

    /// <summary>
    /// The walk stops when it runs out of zones. Every step asks the parent for
    /// the current zone's DS, and above the root there is no parent to ask — so
    /// a chain that climbs all the way up without meeting a configured anchor has
    /// ended, and ended in failure.
    ///
    /// <para>
    /// Reading the root as its own parent does not loop forever, which is why the
    /// depth limit is not what catches it. It asks the root for the root's own DS,
    /// gets no answer, and reports the delegation unsigned — turning "this chain
    /// reaches no anchor I hold" into "this zone is not signed", which is the
    /// difference between refusing an answer and accepting it.
    /// </para>
    ///
    /// <para>
    /// Three zones are needed to get there, because the walk has to take the step
    /// twice: out of the fixture into its parent, and out of the parent into the
    /// root. Every RRset on the way is signed, so the walk does reach the root —
    /// the queries say so — and the verdict is the root's and not some broken
    /// step's below it.
    /// </para>
    /// </summary>
    [Test]
    public async Task The_Root_Has_No_Parent_To_Step_Into()
    {

        using var parent  = ParentKey();
        using var root    = RootKey();

        var resolver      = new StubDnsClient().
                                Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, zone.KeySetAnswer).
                                Answer("dnssec.test", DNSResourceRecordTypes.DS,     SignedDS(parent, zone.DelegationSigner)).
                                Answer("test",        DNSResourceRecordTypes.DNSKEY, KeySet(parent, parent)).
                                Answer("test",        DNSResourceRecordTypes.DS,     SignedDS(root, DelegationSignerFor(parent.DNSKEY))).
                                Answer(".",           DNSResourceRecordTypes.DNSKEY, KeySet(root, root));

        // No anchor anywhere: the chain is signed the whole way up and reaches
        // nothing this resolver was configured to believe.
        var result        = await Validate(resolver);

        Assert.Multiple(() => {

            Assert.That(resolver.Queries, Does.Contain(("", DNSResourceRecordTypes.DNSKEY)),
                        "the walk reached the root");

            Assert.That(resolver.Queries, Does.Not.Contain(("", DNSResourceRecordTypes.DS)),
                        "and did not ask the root for a delegation of its own");

            Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                        "the walk ran out of zones rather than asking the root for its own delegation");

        });

    }

    #endregion

    #region The_Walk_Crosses_Into_The_Parent_And_Anchors_There()

    /// <summary>
    /// The step, taken once. The anchor is not the fixture zone's DS but the
    /// parent's key, so reaching Secure requires fetching the child's DS from the
    /// parent, verifying the child's KSK against it, moving up, and authenticating
    /// the parent's key set by the key the anchor names.
    ///
    /// <para>
    /// The parent also publishes a signature over something that is not its
    /// DNSKEY RRset, naming a key nobody published. RFC 4035 §5.2 is about "the
    /// DNSKEY RRset" specifically, and a walk that took whichever RRSIG came to
    /// hand would look for a key that does not exist. It is here so that the test
    /// says which signature the step reads rather than merely that it reads one.
    /// </para>
    /// </summary>
    [Test]
    public async Task The_Walk_Crosses_Into_The_Parent_And_Anchors_There()
    {

        using var parent    = ParentKey();
        using var stranger  = ParentKey();

        var unrelated       = Sign([ zone.RRset("a.dnssec.test", DNSResourceRecordTypes.A)[0] ], stranger);

        var result          = await Validate(
                                        ResolverWithParent(parent,
                                                           [ .. KeySet(parent, parent), unrelated ]),
                                        DelegationSignerFor(parent.DNSKEY)
                                    );

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure),
                    "the chain reaches an anchor one zone above the signer");

    }

    #endregion

    #region The_Anchor_Has_To_Name_The_Key_That_Signed_The_Key_Set()

    /// <summary>
    /// RFC 4034 §5.1 again, at the top of the step: a key is named by tag *and*
    /// algorithm, and the tag alone is a checksum — and since finding 67, RFC 4035
    /// §5.2 on top of it: the key the anchor names has to be one that signed the
    /// key set it stands in.
    ///
    /// <para>
    /// The parent publishes two keys of the same algorithm, both with the SEP bit,
    /// and the signature over its DNSKEY RRset is made by the second. Anchored on
    /// the second, the chain holds. Anchored on the first — a key the parent does
    /// publish, and never signed its key set with — it does not: that key vouches
    /// for nothing but itself, and a walk that accepted it would accept any key set
    /// the anchored key merely appears in.
    /// </para>
    ///
    /// <para>
    /// This test used to be about which key the walk carried up, and its decoy
    /// carried the SEP bit because a fallback to "the first SEP key of this
    /// algorithm" repaired a decoy without it — written that way the test passed
    /// and proved nothing, which the mutation run said and the test could not.
    /// Finding 65 removed the fallback, and the walk stopped carrying any key up;
    /// finding 67 gave the decoy something to be wrong about again. The SEP bit
    /// stays, so that the flag is not what tells the two keys apart.
    /// </para>
    ///
    /// <para>
    /// The second assertion is finding 67 one step up, and was red until it was
    /// fixed: the walk compared an anchor with every key of the key set, signer or
    /// not.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4034 §5.1, 4035 §5.2")]
    public async Task The_Anchor_Has_To_Name_The_Key_That_Signed_The_Key_Set()
    {

        using var decoy   = ParentKey();                 // same algorithm and flags, published first, never signs
        using var parent  = ParentKey();

        Assert.That(DNSSECValidator.ComputeKeyTag(decoy.DNSKEY),
                    Is.Not.EqualTo(DNSSECValidator.ComputeKeyTag(parent.DNSKEY)),
                    "the two parent keys are distinct, which is what the test rests on");

        var keySet = KeySet(parent, decoy, parent);

        Assert.Multiple(async () => {

            Assert.That(await Validate(ResolverWithParent(parent, keySet), DelegationSignerFor(parent.DNSKEY)),
                        Is.EqualTo(DNSSECValidationResult.Secure),
                        "the anchor names the key that signed the parent's key set");

            Assert.That(await Validate(ResolverWithParent(parent, keySet), DelegationSignerFor(decoy.DNSKEY)),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "the anchor names a key the parent publishes and never signed its key set with");

        });

    }

    #endregion

    #region A_Zone_With_Two_Key_Signing_Keys_Is_Followed_Through_The_One_Its_DS_Names()

    /// <summary>
    /// A zone in the middle of the chain that publishes two keys with the SEP bit,
    /// as every zone does for the length of a KSK rollover — and as <c>org.</c> does
    /// today: keys 725 and 26974, both flagged 257, the DNSKEY RRset signed by 26974,
    /// and the root's DS for <c>org.</c> naming 26974.
    ///
    /// <para>
    /// The walk picked "the" key-signing key as the first published key with the SEP
    /// bit and an algorithm equal to the one it carried up, and checked the DS
    /// against that key alone. With the standby key listed first, the check failed
    /// and the verdict was Bogus — for every name under the zone, for as long as the
    /// rollover lasts. RFC 4034 §2.1.1 rules the flag out as a basis for anything a
    /// validator decides:
    /// </para>
    /// <para>
    /// "This flag is only intended to be a hint to zone signing or debugging
    /// software as to the intended use of this DNSKEY record; validators MUST NOT
    /// alter their behavior during the signature validation process in any way
    /// based on the setting of this bit."
    /// </para>
    /// <para>
    /// RFC 4035 §5.2 says which key the DS has to match: "a DNSKEY RR in the child
    /// zone's apex DNSKEY RRset" — any of them, chosen by key tag, algorithm and
    /// digest, and not by its flags — one whose private key "has signed the child
    /// zone's apex DNSKEY RRset".
    /// </para>
    /// <para>
    /// The anchor sits at the root, two steps above the fixture, so that the middle
    /// zone's key is reached by a DS and not by an anchor. That was finding 65.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4034 §2.1.1, 4035 §5.2")]
    public async Task A_Zone_With_Two_Key_Signing_Keys_Is_Followed_Through_The_One_Its_DS_Names()
    {

        using var standby  = ParentKey();                // SEP, same algorithm, published first
        using var active   = ParentKey();                // SEP, signs the RRset, named by the DS
        using var root     = RootKey();

        Assert.That(DNSSECValidator.ComputeKeyTag(standby.DNSKEY),
                    Is.Not.EqualTo(DNSSECValidator.ComputeKeyTag(active.DNSKEY)),
                    "the two key-signing keys are distinct, which is what the test rests on");

        var resolver  = ResolverWithParent(active, KeySet(active, standby, active)).
                            Answer("test", DNSResourceRecordTypes.DS,     SignedDS(root, DelegationSignerFor(active.DNSKEY))).
                            Answer(".",    DNSResourceRecordTypes.DNSKEY, KeySet(root, root));

        var result    = await Validate(resolver, DelegationSignerFor(root.DNSKEY));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure),
                    "the DS names the key that signs the RRset; that a standby key is listed first changes nothing");

    }

    #endregion

    #region A_Parent_That_Does_Not_Sign_Its_DNSKEY_RRset_Is_Bogus()

    /// <summary>
    /// RFC 4035 §4.3 distinguishes Bogus from Insecure, and the difference is
    /// whether a name resolves. Insecure is a statement the validator can stand
    /// behind — "an RRset for which the security-aware resolver knows that it has
    /// no chain of signed DNSKEY and DS RRs" — and Bogus is the rest: "an RRset for
    /// which the resolver believes that it ought to be able to establish a chain
    /// of trust but for which it is unable to do so".
    ///
    /// <para>
    /// The parent here is anchored, publishes a signed DS for the fixture, and
    /// serves its key set without the signature over it. The anchor says the
    /// parent signs; the missing signature is not a fact about the parent but
    /// about the answer, and stripping it is the cheapest thing an attacker on the
    /// path can do. It is Bogus.
    /// </para>
    ///
    /// <para>
    /// This test used to say Insecure, on the reasoning that a parent without a
    /// signature "has not been caught lying either". That was the validator's
    /// behavior — it looked for the RRSIG over the parent's key set, answered
    /// Insecure when there was none, and read only its key tag when there was —
    /// written down as the rule. It is finding 67 seen from one step up, and was
    /// red until the walk verified the signatures it relies on.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4035 §4.3, §5.2")]
    public async Task A_Parent_That_Does_Not_Sign_Its_DNSKEY_RRset_Is_Bogus()
    {

        using var parent = ParentKey();

        var result = await Validate(ResolverWithParent(parent, parent.DNSKEY),
                                    DelegationSignerFor(parent.DNSKEY));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "an anchored parent's key set without its signature is a stripped answer, not an unsigned zone");

    }

    #endregion

}

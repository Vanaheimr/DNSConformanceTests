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
/// verified before the walk is reached — and only the parent above it is
/// constructed.
/// </para>
///
/// <para>
/// Every zone above the fixture is signed for real, by keys the suite makes and
/// signs with itself (<see cref="ConstructedKey"/>): the parent's DNSKEY RRset
/// by the parent's key, the fixture's DS by the parent, the parent's DS by the
/// root. Every one of those signatures is a link of the chain, and RFC 4035 §5.2
/// requires each to verify.
/// </para>
///
/// <para>
/// This summary used to say the opposite — that the parent's RRSIG "is never
/// verified by the walk and is not made to verify here", because building one
/// "would assert nothing the next DS check does not already assert". It asserts
/// that the parent signed what the chain says it signed, which no DS check can.
/// The validator did not check it either, and that was finding 67; the filler
/// signatures this file was built on are kept only where a forgery is the point.
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

    private const  Byte   RSASHA256  = 8;
    private const UInt16  ZoneKey    = 0x0100;
    private const UInt16  SEP        = 0x0001;

    private static readonly DNSServerConfig Origin = new(IPv4Address.Localhost, IPPort.DNS);

    private static DNSInfo ResponseWith(params IDNSResourceRecord[] Answers)
        => new(Origin, 0, true, false, true, false, DNSResponseCodes.NoError,
               Answers, [], [], true, false, TimeSpan.FromSeconds(5), TimeSpan.Zero);

    /// <summary>
    /// A key of the parent zone made of filler octets: nothing can sign with it,
    /// which is what a forgery needs. Real parents are a <see cref="ConstructedKey"/>.
    /// </summary>
    private static DNSKEY ParentKey(Byte Filler, UInt16 Flags = (UInt16) (ZoneKey | SEP))
        => new (DomainName.Parse("test"),
                DNSQueryClasses.IN,
                TimeSpan.FromDays(1),
                Flags,
                3,
                RSASHA256,
                [.. Enumerable.Repeat(Filler, 64)]);

    /// <summary>
    /// An RRSIG naming the given key, over the given type, whose signature octets
    /// are filler: a signature nobody made.
    /// </summary>
    private static RRSIG SignatureNaming(DNSKEY Key, DNSResourceRecordTypes TypeCovered)
        => new (DomainName.Parse("test"),
                DNSQueryClasses.IN,
                TimeSpan.FromDays(1),
                TypeCovered,
                Key.Algorithm,
                1,
                86400,
                (UInt32) DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds(),
                (UInt32) DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds(),
                DNSSECValidator.ComputeKeyTag(Key),
                DomainName.Parse("test"),
                [.. Enumerable.Repeat((Byte) 0x5A, 64)]);

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
    /// A resolver serving the fixture zone's keys with BIND's signature over them,
    /// the fixture zone's own DS — which is what the walk asks the parent for —
    /// signed by the parent key given, and whatever the parent publishes under its
    /// DNSKEY.
    /// </summary>
    private StubDnsClient ResolverWithParent(ConstructedKey DsSigner, params IDNSResourceRecord[] ParentDnskeyAnswer)
        => new StubDnsClient().
               Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, [.. zone.DnsKeyAnswer]).
               Answer("dnssec.test", DNSResourceRecordTypes.DS,     DsSigner.Signed(zone.DelegationSigner)).
               Answer("test",        DNSResourceRecordTypes.DNSKEY, ParentDnskeyAnswer);

    /// <summary>A key of the root zone made of filler octets, for forgeries above the parent.</summary>
    private static DNSKEY RootKey(Byte Filler)
        => new (DomainName.ParseLenient("."),
                DNSQueryClasses.IN,
                TimeSpan.FromDays(1),
                (UInt16) (ZoneKey | SEP),
                3,
                RSASHA256,
                [.. Enumerable.Repeat(Filler, 64)]);

    /// <summary>A filler signature over the root's DNSKEY RRset, naming the given key.</summary>
    private static RRSIG RootSignatureNaming(DNSKEY Key)
        => new (DomainName.ParseLenient("."),
                DNSQueryClasses.IN,
                TimeSpan.FromDays(1),
                DNSResourceRecordTypes.DNSKEY,
                Key.Algorithm,
                0,
                86400,
                (UInt32) DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds(),
                (UInt32) DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds(),
                DNSSECValidator.ComputeKeyTag(Key),
                DomainName.ParseLenient("."),
                [.. Enumerable.Repeat((Byte) 0x5A, 64)]);

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
    /// root.
    /// </para>
    ///
    /// <para>
    /// Every link is signed for real, so that the walk does reach the root: with
    /// filler signatures, as this test was first written, it now stops at the
    /// first DS and the verdict says nothing about the root. The control puts an
    /// anchor over the root key and the same chain is Secure — what makes the
    /// other answer Bogus is the missing anchor and nothing else.
    /// </para>
    /// </summary>
    [Test]
    public async Task The_Root_Has_No_Parent_To_Step_Into()
    {

        using var parent = new ConstructedKey("test");
        using var root   = new ConstructedKey(".");

        var resolver  = ResolverWithParent(parent, parent.Signed(parent.DNSKEY)).
                            Answer("test", DNSResourceRecordTypes.DS,     root.Signed(DelegationSignerFor(parent.DNSKEY))).
                            Answer(".",    DNSResourceRecordTypes.DNSKEY, root.Signed(root.DNSKEY));

        // No anchor anywhere: the chain is signed the whole way up and reaches
        // nothing this resolver was configured to believe.
        var unanchored = await Validate(resolver);
        var anchored   = await Validate(resolver, DelegationSignerFor(root.DNSKEY));

        Assert.Multiple(() => {

            Assert.That(anchored,   Is.EqualTo(DNSSECValidationResult.Secure),
                        "the control: the same chain under an anchor over the root key");

            Assert.That(unanchored, Is.EqualTo(DNSSECValidationResult.Bogus),
                        "the walk ran out of zones rather than asking the root for its own delegation");

        });

    }

    #endregion

    #region The_Walk_Crosses_Into_The_Parent_And_Anchors_There()

    /// <summary>
    /// The step, taken once. The anchor is not the fixture zone's DS but the
    /// parent's key, so reaching Secure requires fetching the child's DS from the
    /// parent, verifying the parent's signature over it, matching the child's KSK
    /// against it, and verifying the parent's own signature over its DNSKEY RRset
    /// with the key the anchor names.
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

        using var parent = new ConstructedKey("test");
        var unrelated    = SignatureNaming(ParentKey(0x99), DNSResourceRecordTypes.A);

        var result    = await Validate(
                                  ResolverWithParent(parent,
                                                     parent.DNSKEY,
                                                     parent.Sign([parent.DNSKEY]),
                                                     unrelated),
                                  DelegationSignerFor(parent.DNSKEY)
                              );

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure),
                    "the chain reaches an anchor one zone above the signer");

    }

    #endregion

    #region The_Key_Carried_Up_Is_The_One_The_Signature_Names()

    /// <summary>
    /// RFC 4034 §5.1 again, at the top of the step: a key is named by tag *and*
    /// algorithm, and the tag alone is a checksum.
    ///
    /// <para>
    /// The parent publishes two keys of the same algorithm and the signature over
    /// its DNSKEY RRset names the second. A walk that matched on either half
    /// would take the first and carry it up — and the first is not the key the
    /// anchor is over, so the chain would end nowhere. Publishing the decoy first
    /// is the whole construction: with the right key first, both readings pick
    /// the same key and the test says nothing.
    /// </para>
    ///
    /// <para>
    /// The decoy carries the SEP bit as well, and that is not decoration. One
    /// line below the lookup the walk falls back to "whichever published key is a
    /// SEP of this algorithm", which is the ordinary way a zone's signing key is
    /// found from its zone-signing one. A decoy without the bit is repaired by
    /// that fallback — the wrong key is carried up and the right one is picked out
    /// again immediately, and the verdict never moves. Written that way this test
    /// passed and proved nothing, which the mutation run said and the test itself
    /// could not.
    /// </para>
    ///
    /// <para>
    /// That fallback was finding 65, and it is gone: the walk now compares anchors
    /// and DS records with every key of the RRset and carries no key up at all. The
    /// verdict here is unchanged, but what it pins is less than this note describes —
    /// the decoy can no longer be picked, because nothing is picked.
    /// </para>
    ///
    /// <para>
    /// Since finding 67 the signature is verified, which gives the test back some
    /// of what it lost: the decoy is published first and cannot verify it, so a
    /// walk that took the first key of the right algorithm would now fail, and
    /// one that tries the key the signature names — by tag and algorithm — does
    /// not.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4034 §5.1")]
    public async Task The_Key_Carried_Up_Is_The_One_The_Signature_Names()
    {

        using var decoy  = new ConstructedKey("test");    // same algorithm and flags, other tag
        using var parent = new ConstructedKey("test");

        Assert.That(decoy.KeyTag,
                    Is.Not.EqualTo(parent.KeyTag),
                    "the two parent keys are distinct, which is what the test rests on");

        var result = await Validate(
                               ResolverWithParent(parent,
                                                  decoy.DNSKEY,
                                                  parent.DNSKEY,
                                                  parent.Sign([decoy.DNSKEY, parent.DNSKEY])),
                               DelegationSignerFor(parent.DNSKEY)
                           );

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure),
                    "the signature names the second key, so the second key is the one carried up");

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
    /// The walk picks "the" key-signing key as the first published key with the SEP
    /// bit and an algorithm equal to the one it carried up, and checks the DS
    /// against that key alone. With the standby key listed first, the check fails
    /// and the verdict is Bogus — for every name under the zone, for as long as the
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
    /// digest, and not by its flags.
    /// </para>
    /// <para>
    /// The anchor sits at the root, two steps above the fixture, so that the middle
    /// zone's key is reached by a DS and not by an anchor. One level lower, as in
    /// <see cref="The_Key_Carried_Up_Is_The_One_The_Signature_Names"/>, the key the
    /// parent's signature names is compared with the anchor before the flag is ever
    /// consulted, and the same zone validates.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4034 §2.1.1, 4035 §5.2")]
    public async Task A_Zone_With_Two_Key_Signing_Keys_Is_Followed_Through_The_One_Its_DS_Names()
    {

        using var standby = new ConstructedKey("test");  // SEP, same algorithm, published first
        using var active  = new ConstructedKey("test");  // SEP, signs the RRset, named by the DS
        using var root    = new ConstructedKey(".");

        Assert.That(standby.KeyTag,
                    Is.Not.EqualTo(active.KeyTag),
                    "the two key-signing keys are distinct, which is what the test rests on");

        var resolver  = ResolverWithParent(active,
                                           standby.DNSKEY,
                                           active.DNSKEY,
                                           active.Sign([standby.DNSKEY, active.DNSKEY])).
                            Answer("test", DNSResourceRecordTypes.DS,     root.Signed(DelegationSignerFor(active.DNSKEY))).
                            Answer(".",    DNSResourceRecordTypes.DNSKEY, root.Signed(root.DNSKEY));

        var result    = await Validate(resolver, DelegationSignerFor(root.DNSKEY));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure),
                    "the DS names the key that signs the RRset; that a standby key is listed first changes nothing");

    }

    #endregion

    #region A_Parent_That_Does_Not_Sign_Its_DNSKEY_RRset_Breaks_The_Chain()

    /// <summary>
    /// RFC 4035 §4.3 distinguishes Bogus from Insecure, and the difference is
    /// whether a name resolves — which is why it has to be drawn where §4.3 draws
    /// it. Insecure is "an RRset for which the resolver knows that it has no chain
    /// of signed DNSKEY and DS RRs from any trusted starting point"; Bogus is one
    /// "for which the resolver believes that it ought to be able to establish a
    /// chain of trust but for which it is unable to do so".
    ///
    /// <para>
    /// The anchor here is over the parent's key. The resolver was configured to
    /// believe that <c>test.</c> is signed, the parent signed the fixture's DS, and
    /// its DNSKEY RRset arrives without a signature. Nothing proves the parent
    /// unsigned — the anchor says the opposite — so it is the second case. An
    /// unsigned key set under an anchor is exactly what stripping the RRSIGs
    /// produces, and finding 64's cache produced it by accident.
    /// </para>
    ///
    /// <para>
    /// This test was <c>A_Parent_That_Does_Not_Sign_Its_DNSKEY_RRset_Is_Insecure</c>
    /// and asserted the other verdict, reasoning that such a parent "has not been
    /// caught lying either". It pinned the one place where the walk read an RRSIG
    /// above the answer, and the reading it pinned was the gap of finding 67.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4035 §4.3, §5.2")]
    public async Task A_Parent_That_Does_Not_Sign_Its_DNSKEY_RRset_Breaks_The_Chain()
    {

        using var parent = new ConstructedKey("test");

        var result = await Validate(ResolverWithParent(parent, parent.DNSKEY),
                                    DelegationSignerFor(parent.DNSKEY));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "under an anchor that says the parent is signed, its unsigned keys are a broken chain");

    }

    #endregion

    #region A_Chain_Of_Signatures_Nobody_Made_Is_Not_Secure()

    /// <summary>
    /// Finding 67. The shape of <see cref="The_Root_Has_No_Parent_To_Step_Into"/>
    /// made of filler instead of signatures, under an anchor over the filler root
    /// key.
    ///
    /// <para>
    /// Every key above the fixture zone is filler, every signature over a DNSKEY
    /// RRset is 64 octets of 0x5A, neither DS RRset is signed at all, and BIND's
    /// signature over the fixture's own DNSKEY RRset is left out. The one genuine
    /// signature is BIND's over the A record. RFC 4035 §5.2 makes a DNSKEY RRset
    /// authentic only through an RRSIG made by a key that an authenticated DS — or
    /// the anchor — names, and a DS RRset authentic only through the parent's
    /// signature. Nothing above the answer here is authentic, so the answer may
    /// not be Secure.
    /// </para>
    ///
    /// <para>
    /// Against the real root the attack needs no made-up root key: the root's
    /// DNSKEY response is public, signature and all, and can be replayed whole.
    /// The filler key stands in for it because the suite holds no anchor for the
    /// real root.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4035 §5.2, 4033 §5")]
    public async Task A_Chain_Of_Signatures_Nobody_Made_Is_Not_Secure()
    {

        var parent    = ParentKey(0x77);
        var root      = RootKey(0x88);

        var resolver  = new StubDnsClient().
                            Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, [.. zone.DnsKeys]).
                            Answer("dnssec.test", DNSResourceRecordTypes.DS,     zone.DelegationSigner).
                            Answer("test",        DNSResourceRecordTypes.DNSKEY, parent,
                                                                                 SignatureNaming(parent, DNSResourceRecordTypes.DNSKEY)).
                            Answer("test",        DNSResourceRecordTypes.DS,     DelegationSignerFor(parent)).
                            Answer(".",           DNSResourceRecordTypes.DNSKEY, root,
                                                                                 RootSignatureNaming(root));

        var result    = await Validate(resolver, DelegationSignerFor(root));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "no signature above the answer verifies, and the DS records are signed by nobody");

    }

    #endregion

}

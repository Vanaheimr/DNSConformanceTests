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
/// The parent's own RRSIG is never verified by the walk and is not made to
/// verify here: it is read for the key tag and algorithm it names, and the key
/// it points at is authenticated by the DS one level further up. Building a
/// signature that verifies would assert nothing the next DS check does not
/// already assert.
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

    /// <summary>A key of the parent zone. The octets are filler: nothing signs with it.</summary>
    private static DNSKEY ParentKey(Byte Filler, UInt16 Flags = (UInt16) (ZoneKey | SEP))
        => new (DomainName.Parse("test"),
                DNSQueryClasses.IN,
                TimeSpan.FromDays(1),
                Flags,
                3,
                RSASHA256,
                [.. Enumerable.Repeat(Filler, 64)]);

    /// <summary>
    /// An RRSIG naming the given key, over the given type. The signature octets
    /// are filler — see the note on the fixture.
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

    /// <summary>
    /// A resolver serving the fixture zone's keys, the fixture zone's own DS
    /// — which is what the walk asks the parent for — and whatever the parent
    /// publishes under its DNSKEY.
    /// </summary>
    private StubDnsClient ResolverWithParent(params IDNSResourceRecord[] ParentDnskeyAnswer)
        => new StubDnsClient().
               Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, [.. zone.DnsKeys]).
               Answer("dnssec.test", DNSResourceRecordTypes.DS,     zone.DelegationSigner).
               Answer("test",        DNSResourceRecordTypes.DNSKEY, ParentDnskeyAnswer);

    /// <summary>A key of the root zone, for the step above the parent.</summary>
    private static DNSKEY RootKey(Byte Filler)
        => new (DomainName.ParseLenient("."),
                DNSQueryClasses.IN,
                TimeSpan.FromDays(1),
                (UInt16) (ZoneKey | SEP),
                3,
                RSASHA256,
                [.. Enumerable.Repeat(Filler, 64)]);

    /// <summary>The root's signature over its own DNSKEY RRset.</summary>
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
    /// </summary>
    [Test]
    public async Task The_Root_Has_No_Parent_To_Step_Into()
    {

        var parent    = ParentKey(0x55);
        var root      = RootKey(0x66);

        var resolver  = new StubDnsClient().
                            Answer("dnssec.test", DNSResourceRecordTypes.DNSKEY, [.. zone.DnsKeys]).
                            Answer("dnssec.test", DNSResourceRecordTypes.DS,     zone.DelegationSigner).
                            Answer("test",        DNSResourceRecordTypes.DNSKEY, parent,
                                                                                 SignatureNaming(parent, DNSResourceRecordTypes.DNSKEY)).
                            Answer("test",        DNSResourceRecordTypes.DS,     DelegationSignerFor(parent)).
                            Answer(".",           DNSResourceRecordTypes.DNSKEY, root,
                                                                                 RootSignatureNaming(root));

        // No anchor anywhere: the chain is signed the whole way up and reaches
        // nothing this resolver was configured to believe.
        var result    = await Validate(resolver);

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Bogus),
                    "the walk ran out of zones rather than asking the root for its own delegation");

    }

    #endregion

    #region The_Walk_Crosses_Into_The_Parent_And_Anchors_There()

    /// <summary>
    /// The step, taken once. The anchor is not the fixture zone's DS but the
    /// parent's key, so reaching Secure requires fetching the child's DS from the
    /// parent, verifying the child's KSK against it, moving up, and picking the
    /// parent key the parent's DNSKEY signature names.
    ///
    /// <para>
    /// The parent also publishes a signature over something that is not its
    /// DNSKEY RRset, naming a key nobody published. RFC 4035 §5.2 is about "the
    /// DNSKEY RRset" specifically, and a walk that took whichever RRSIG came to
    /// hand would carry up a key that does not exist. It is here so that the test
    /// says which signature the step reads rather than merely that it reads one.
    /// </para>
    /// </summary>
    [Test]
    public async Task The_Walk_Crosses_Into_The_Parent_And_Anchors_There()
    {

        var parent    = ParentKey(0x11);
        var unrelated = SignatureNaming(ParentKey(0x99), DNSResourceRecordTypes.A);

        var result    = await Validate(
                                  ResolverWithParent(parent,
                                                     SignatureNaming(parent, DNSResourceRecordTypes.DNSKEY),
                                                     unrelated),
                                  DelegationSignerFor(parent)
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
    /// </summary>
    [Test]
    [Property("RFC", "4034 §5.1")]
    public async Task The_Key_Carried_Up_Is_The_One_The_Signature_Names()
    {

        var decoy  = ParentKey(0x22);                    // same algorithm and flags, other tag
        var parent = ParentKey(0x33);

        Assert.That(DNSSECValidator.ComputeKeyTag(decoy),
                    Is.Not.EqualTo(DNSSECValidator.ComputeKeyTag(parent)),
                    "the two parent keys are distinct, which is what the test rests on");

        var result = await Validate(
                               ResolverWithParent(decoy,
                                                  parent,
                                                  SignatureNaming(parent, DNSResourceRecordTypes.DNSKEY)),
                               DelegationSignerFor(parent)
                           );

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Secure),
                    "the signature names the second key, so the second key is the one carried up");

    }

    #endregion

    #region A_Parent_That_Does_Not_Sign_Its_DNSKEY_RRset_Is_Insecure()

    /// <summary>
    /// RFC 4035 §4.3 distinguishes Bogus from Insecure, and the difference is
    /// whether a name resolves. A parent whose DNSKEY RRset carries no signature
    /// offers nothing to continue the chain with — but it has not been caught
    /// lying either, and answering Bogus would take the name off the internet
    /// rather than leaving it unvalidated.
    ///
    /// <para>
    /// This is the same reasoning the file already applies to a DS RRset with no
    /// usable algorithm, one branch further down, and it is worth pinning because
    /// the two verdicts are one comparison apart.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4035 §4.3")]
    public async Task A_Parent_That_Does_Not_Sign_Its_DNSKEY_RRset_Is_Insecure()
    {

        var parent = ParentKey(0x44);

        var result = await Validate(ResolverWithParent(parent),
                                    DelegationSignerFor(parent));

        Assert.That(result, Is.EqualTo(DNSSECValidationResult.Insecure),
                    "an unsigned step is an unvalidated chain, not a broken one");

    }

    #endregion

}

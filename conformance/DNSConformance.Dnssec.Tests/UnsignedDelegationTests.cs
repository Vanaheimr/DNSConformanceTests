using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4035 §5.2: an unsigned delegation, and what may prove one — whose
/// records, signed by whom, and found from which end of the chain.
/// </summary>
/// <remarks>
/// <para>
/// An unsigned delegation is the one place a chain of trust is allowed to stop
/// short of an answer without the answer being Bogus. That makes it the claim
/// an attacker wants a validator to believe: every signed RRset that can be made
/// to look as though it lies below one may be stripped of its signatures and
/// still be accepted as Insecure. §5.2 lets the claim stand only on a proof —
/// "If the validator authenticates an NSEC RRset that proves that no DS RRset is
/// present for this zone, then there is no authentication path leading from the
/// parent to the child" — and the findings 72 and 73 tests say what that proof
/// is for. These say what it has to be.
/// </para>
/// <para>
/// The validator meets the claim from two directions. A <b>signed</b> answer is
/// walked up from its signer, and a missing DS on the way is the question
/// (<c>WalkChainOfTrust</c>). An <b>unsigned</b> answer is walked down from the
/// closest anchor, one label at a time, until a proven unsigned delegation is
/// found or the owner is reached inside signed zones (<c>ProveUnsigned</c>).
/// Both read the proof the same way, and both have their own ways to go wrong.
/// </para>
/// <para>
/// Every zone here is made in the test: <c>p.test.</c> is anchored with a key
/// generated for it, and everything below it is generated, signed and answered
/// by a stub resolver. Each forgery comes with the genuine answer beside it, so
/// that what decides the verdict is the one thing that differs.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "4035 §5.2")]
public class UnsignedDelegationTests
{

    #region Helpers

    private const Byte ECDSAP256SHA256 = 13;

    private static readonly DNSServerConfig Origin = new(IPv4Address.Localhost, IPPort.DNS);

    private static DNSInfo ResponseWith(params IDNSResourceRecord[] Answers)
        => new(Origin, 0, true, false, true, false, DNSResponseCodes.NoError,
               Answers, [], [], true, false, TimeSpan.FromSeconds(5), TimeSpan.Zero);

    private static DNSSECSigningKey KeyFor(String Zone)
        => DNSSECSigningKey.Generate(DomainName.Parse(Zone), ECDSAP256SHA256, KeySigningKey: true);

    private static RRSIG Sign(IEnumerable<IDNSResourceRecord> RRset, DNSSECSigningKey Key)
        => DNSSECZoneSigner.SignRRSet(RRset, Key, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(14));

    /// <summary>An RRset and its signature, made with the given key.</summary>
    private static IDNSResourceRecord[] Signed(DNSSECSigningKey Key, params IDNSResourceRecord[] RRset)
        => [ .. RRset, Sign(RRset, Key) ];

    /// <summary>A zone's DNSKEY RRset, signed by its own key.</summary>
    private static IDNSResourceRecord[] KeySet(DNSSECSigningKey Zone)
        => Signed(Zone, Zone.DNSKEY);

    private static A Address(String Name)
        => new(DomainName.Parse(Name), DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Parse("192.0.2.80"));

    /// <summary>
    /// RFC 4034 §4.1.2: a type bitmap of window 0, bit <c>i</c> of the block
    /// standing for type <c>i</c>, the most significant bit first. Built here
    /// from the type numbers rather than asked of Hermod's encoder.
    /// </summary>
    private static Byte[] Types(params Int32[] Codes)
    {

        var octets = new Byte[Codes.Max() / 8 + 1];

        foreach (var code in Codes)
            octets[code / 8] |= (Byte) (0x80 >> (code % 8));

        return [ 0x00, (Byte) octets.Length, .. octets ];

    }

    /// <summary>NS, RRSIG and NSEC: the parent's record at a delegation without DS.</summary>
    private static readonly Byte[] AtADelegation = Types(2, 46, 47);

    /// <summary>A, RRSIG and NSEC: an ordinary name of the zone, which is no zone cut.</summary>
    private static readonly Byte[] AtAnAddress   = Types(1, 46, 47);

    private static NSEC Nsec(String Owner, String Next, Byte[] TypeBitMap)
        => new(DomainName.Parse(Owner), DNSQueryClasses.IN, TimeSpan.FromHours(1), DomainName.Parse(Next), TypeBitMap);

    #endregion


    #region A_Proof_Of_No_Ds_Counts_Only_Once_The_Parents_Keys_Are_Authenticated()

    /// <summary>
    /// The walk up. <c>c.p.test.</c> is signed and its answer verifies; the
    /// answer to its DS query is empty, with an NSEC at <c>c.p.test.</c> that
    /// shows a delegation and no DS. Signed by <c>p.test.</c>'s genuine key, that
    /// is Insecure. Signed by a key made up for <c>p.test.</c> and handed to the
    /// validator as <c>p.test.</c>'s key set, it is Bogus.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The proof verifies in both cases — against the key set it came with. §5.2
    /// asks for more: the validator has to have <i>authenticated</i> the NSEC
    /// RRset, and a key set is authenticated only by the step above it. So the
    /// proof is accepted on the terms a DS would be, conditionally on the parent's
    /// keys, and the walk goes on to the anchor to settle them. Taken at its word
    /// instead, it would let anyone able to answer two queries — the DS and the
    /// parent's DNSKEY — call any signed zone below an anchor unsigned.
    /// </para>
    /// <para>
    /// <see cref="ChainValidationTests.An_Unfollowable_Ds_Counts_Only_Once_The_Parents_Keys_Are_Authenticated"/>
    /// is the same rule for the other way a DS step ends Insecure.
    /// </para>
    /// </remarks>
    [Test]
    public async Task A_Proof_Of_No_Ds_Counts_Only_Once_The_Parents_Keys_Are_Authenticated()
    {

        using var parent = KeyFor("p.test");
        using var forged = KeyFor("p.test");
        using var child  = KeyFor("c.p.test");

        var response = ResponseWith(Signed(child, Address("www.c.p.test")));

        StubDnsClient ParentSaysNoDs(DNSSECSigningKey ParentKey)
            => new StubDnsClient().
                   Answer   ("c.p.test", DNSResourceRecordTypes.DNSKEY, KeySet(child)).
                   Answer   ("p.test",   DNSResourceRecordTypes.DNSKEY, KeySet(ParentKey)).
                   Authority("c.p.test", DNSResourceRecordTypes.DS,     Signed(ParentKey, Nsec("c.p.test", "d.p.test", AtADelegation)));

        var anchors  = new[] { parent.DelegationSigner() };

        Assert.Multiple(async () => {

            Assert.That(await new DNSSECValidator(ParentSaysNoDs(parent), anchors).ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Insecure),
                        "the control: the anchored parent proves the delegation has no DS");

            Assert.That(await new DNSSECValidator(ParentSaysNoDs(forged), anchors).ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "the same proof under a key set the anchor does not name proves nothing");

        });

    }

    #endregion

    #region A_Ds_Rrset_Signed_By_Any_Zone_But_A_Parent_Is_Bogus()

    /// <summary>
    /// The walk up again, with a DS this time: §5.2's first condition is that
    /// "the DS RR has been authenticated using some DNSKEY RR in the parent's
    /// apex DNSKEY RRset". Signed by <c>p.test.</c>, the DS leads to the anchor
    /// and the answer is Secure. Signed by <c>o.example.</c>, a zone with no say
    /// over <c>c.p.test.</c>, or by <c>c.p.test.</c> itself, it is Bogus.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The walk learns the parent's name from the DS RRset's signature, which
    /// also finds the parent where a label is not a zone cut — and which is
    /// exactly why it must refuse a signer that is not strictly above the child.
    /// Followed to <c>o.example.</c>, the walk climbs into a zone no anchor covers,
    /// whose own DS is missing, and comes back Insecure: anybody's key in front of
    /// any DS would then downgrade the zone below it.
    /// </para>
    /// <para>
    /// Followed to the child itself, it climbs nowhere. The child's DS, signed by
    /// the child's key, leads back to the child, round and round until the depth
    /// limit gives up with Indeterminate — which is why the assertion asks for
    /// Bogus rather than for anything but Secure.
    /// </para>
    /// </remarks>
    [Test]
    public async Task A_Ds_Rrset_Signed_By_Any_Zone_But_A_Parent_Is_Bogus()
    {

        using var parent = KeyFor("p.test");
        using var child  = KeyFor("c.p.test");
        using var other  = KeyFor("o.example");

        var response = ResponseWith(Signed(child, Address("www.c.p.test")));

        StubDnsClient DsSignedBy(DNSSECSigningKey Signer)
            => new StubDnsClient().
                   Answer("c.p.test",  DNSResourceRecordTypes.DNSKEY, KeySet(child)).
                   Answer("p.test",    DNSResourceRecordTypes.DNSKEY, KeySet(parent)).
                   Answer("o.example", DNSResourceRecordTypes.DNSKEY, KeySet(other)).
                   Answer("c.p.test",  DNSResourceRecordTypes.DS,     Signed(Signer, child.DelegationSigner()));

        var anchors  = new[] { parent.DelegationSigner() };

        Assert.Multiple(async () => {

            Assert.That(await new DNSSECValidator(DsSignedBy(parent), anchors).ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Secure),
                        "the control: the parent signed the DS, and the parent is anchored");

            Assert.That(await new DNSSECValidator(DsSignedBy(other),  anchors).ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "o.example. is not above c.p.test., and its word on c.p.test.'s keys is nobody's");

            Assert.That(await new DNSSECValidator(DsSignedBy(child),  anchors).ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "and a zone does not vouch for its own keys");

        });

    }

    #endregion

    #region A_Child_Cannot_Prove_Its_Own_Delegation_Unsigned()

    /// <summary>
    /// RFC 4035 §5.2: "A security-aware resolver MUST use the parent NSEC RR when
    /// attempting to prove that a DS RRset does not exist." The NSEC at
    /// <c>c.p.test.</c> shows a delegation and no DS either way; signed by
    /// <c>p.test.</c> it is the parent's and proves the delegation unsigned, signed
    /// by <c>c.p.test.</c>'s own key it is Bogus.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The child's real apex NSEC would never pass for the parent's, because its
    /// SOA bit is set (§5.2 again: "the SOA bit will be set in the child NSEC RR
    /// and clear in the parent NSEC RR"). This one is made to pass: NS, RRSIG and
    /// NSEC, exactly the parent's shape, signed by whoever holds the child's key.
    /// What is left to refuse it is the name on its signature.
    /// </para>
    /// <para>
    /// Accepted, it would make the child's key the parent of its own delegation,
    /// and the walk would step from the child to the child until its depth limit
    /// ran out — Indeterminate, which is why the assertion asks for Bogus.
    /// </para>
    /// </remarks>
    [Test]
    public async Task A_Child_Cannot_Prove_Its_Own_Delegation_Unsigned()
    {

        using var parent = KeyFor("p.test");
        using var child  = KeyFor("c.p.test");

        var response = ResponseWith(Signed(child, Address("www.c.p.test")));

        StubDnsClient NoDsProvenBy(DNSSECSigningKey Signer)
            => new StubDnsClient().
                   Answer   ("c.p.test", DNSResourceRecordTypes.DNSKEY, KeySet(child)).
                   Answer   ("p.test",   DNSResourceRecordTypes.DNSKEY, KeySet(parent)).
                   Authority("c.p.test", DNSResourceRecordTypes.DS,     Signed(Signer, Nsec("c.p.test", "d.p.test", AtADelegation)));

        var anchors  = new[] { parent.DelegationSigner() };

        Assert.Multiple(async () => {

            Assert.That(await new DNSSECValidator(NoDsProvenBy(parent), anchors).ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Insecure),
                        "the control: the parent's NSEC proves its delegation unsigned");

            Assert.That(await new DNSSECValidator(NoDsProvenBy(child),  anchors).ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "the child's signature on the same record makes it the child's word, and that is not a proof");

        });

    }

    #endregion


    #region An_Unsigned_Answer_At_The_Delegation_Itself_Is_Insecure()

    /// <summary>
    /// The walk down. <c>p.test.</c> proves <c>u.p.test.</c> an unsigned
    /// delegation, and an unsigned A record at <c>u.p.test.</c> — the apex of the
    /// unsigned child — is Insecure.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The walk asks about every name between the anchor and the owner, one label
    /// at a time, and the last name it asks about is the owner itself. That is
    /// the step a walk one short leaves out, and the one this answer needs: the
    /// delegation is the owner. <see cref="ChainValidationTests.An_Unsigned_Answer_Below_A_Proven_Unsigned_Delegation_Is_Insecure"/>
    /// asks about <c>www.u.p.test.</c>, one label further down, where a walk that
    /// stops before the owner still finds the delegation on its way.
    /// </para>
    /// <para>
    /// An apex is not a corner case. Every zone has one, and a name like
    /// <c>example.com.</c> is asked for far more often than any name below it.
    /// </para>
    /// </remarks>
    [Test]
    [Property("RFC", "4035 §4.3")]
    public async Task An_Unsigned_Answer_At_The_Delegation_Itself_Is_Insecure()
    {

        using var parent = KeyFor("p.test");

        var resolver  = new StubDnsClient().
                            Answer   ("p.test",   DNSResourceRecordTypes.DNSKEY, KeySet(parent)).
                            Authority("u.p.test", DNSResourceRecordTypes.DS,     Signed(parent, Nsec("u.p.test", "v.p.test", AtADelegation)));

        var validator = new DNSSECValidator(resolver, [ parent.DelegationSigner() ]);

        Assert.That(await validator.ValidateAsync(ResponseWith(Address("u.p.test"))),
                    Is.EqualTo(DNSSECValidationResult.Insecure),
                    "the apex of a child its parent proves unsigned is unsigned");

    }

    #endregion

    #region The_Walk_Down_Crosses_A_Signed_Zone_Cut()

    /// <summary>
    /// The walk down, through a signed child. <c>p.test.</c> delegates
    /// <c>s.p.test.</c> with a signed DS, <c>s.p.test.</c> delegates
    /// <c>u.s.p.test.</c> without one and proves it, and an unsigned answer at
    /// <c>www.u.s.p.test.</c> is Insecure. The same unsigned answer at
    /// <c>www.s.p.test.</c>, inside the signed child, is Bogus.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A walk that never meets a DS proves nothing about how it takes one. Here
    /// it has to: find the DS at <c>s.p.test.</c>, check that <c>p.test.</c>
    /// signed it, fetch the child's keys and check that a key the DS names signed
    /// them — §5.2's three conditions for a child's key set, in order — and then
    /// read the next proof with the child's keys rather than the parent's. Only
    /// <c>s.p.test.</c> can prove anything about <c>u.s.p.test.</c>.
    /// </para>
    /// <para>
    /// Every test before this one has the unsigned delegation directly below
    /// the anchor. On the internet it almost never is: under the root's anchor,
    /// an unsigned zone is found below a signed TLD.
    /// </para>
    /// </remarks>
    [Test]
    public async Task The_Walk_Down_Crosses_A_Signed_Zone_Cut()
    {

        using var parent = KeyFor("p.test");
        using var signed = KeyFor("s.p.test");

        var resolver  = new StubDnsClient().
                            Answer   ("p.test",     DNSResourceRecordTypes.DNSKEY, KeySet(parent)).
                            Answer   ("s.p.test",   DNSResourceRecordTypes.DS,     Signed(parent, signed.DelegationSigner())).
                            Answer   ("s.p.test",   DNSResourceRecordTypes.DNSKEY, KeySet(signed)).
                            Authority("u.s.p.test", DNSResourceRecordTypes.DS,     Signed(signed, Nsec("u.s.p.test", "v.s.p.test", AtADelegation)));

        var validator = new DNSSECValidator(resolver, [ parent.DelegationSigner() ]);

        Assert.Multiple(async () => {

            Assert.That(await validator.ValidateAsync(ResponseWith(Address("www.u.s.p.test"))),
                        Is.EqualTo(DNSSECValidationResult.Insecure),
                        "below a delegation the signed child proves unsigned");

            Assert.That(await validator.ValidateAsync(ResponseWith(Address("www.s.p.test"))),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "and inside the signed child itself, where the signature was owed");

        });

    }

    #endregion

    #region A_Ds_On_The_Way_Down_That_Its_Zone_Did_Not_Sign_Is_Bogus()

    /// <summary>
    /// The same walk with the DS forged. Someone wants an answer under
    /// <c>p.test.</c> stripped of its signatures and accepted, so they invent a
    /// zone cut at <c>s.p.test.</c> with keys of their own, publish a DS for those
    /// keys signed with yet another key under <c>p.test.</c>'s name, and prove a
    /// delegation below their invented zone unsigned. That is Bogus.
    /// </summary>
    /// <remarks>
    /// Everything below the DS is consistent, because the forger made all of it:
    /// the child's keys sign themselves, and they sign the proof. The one record
    /// they cannot make is a DS signature that <c>p.test.</c>'s authenticated keys
    /// verify, and a signature whose signer's name is right is not yet one that
    /// verifies.
    /// </remarks>
    [Test]
    public async Task A_Ds_On_The_Way_Down_That_Its_Zone_Did_Not_Sign_Is_Bogus()
    {

        using var parent = KeyFor("p.test");
        using var forged = KeyFor("p.test");
        using var signed = KeyFor("s.p.test");

        var resolver  = new StubDnsClient().
                            Answer   ("p.test",     DNSResourceRecordTypes.DNSKEY, KeySet(parent)).
                            Answer   ("s.p.test",   DNSResourceRecordTypes.DS,     Signed(forged, signed.DelegationSigner())).
                            Answer   ("s.p.test",   DNSResourceRecordTypes.DNSKEY, KeySet(signed)).
                            Authority("u.s.p.test", DNSResourceRecordTypes.DS,     Signed(signed, Nsec("u.s.p.test", "v.s.p.test", AtADelegation)));

        var validator = new DNSSECValidator(resolver, [ parent.DelegationSigner() ]);

        Assert.That(await validator.ValidateAsync(ResponseWith(Address("www.u.s.p.test"))),
                    Is.EqualTo(DNSSECValidationResult.Bogus),
                    "a DS signed in p.test.'s name by a key p.test. does not hold leads nowhere");

    }

    #endregion

    #region The_Walk_Down_Goes_On_Through_A_Name_That_Is_No_Zone_Cut()

    /// <summary>
    /// The walk down, past names of the zone that are not delegations. An
    /// unsigned delegation two labels below <c>p.test.</c> is Insecure, whether
    /// the label between is an ordinary name or an empty non-terminal.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The walk asks for the DS of every name on the way, and at the name between
    /// it gets no DS and a proof that is not a delegation: the NSEC of
    /// <c>x.p.test.</c>, which holds an A record, or — for <c>e.p.test.</c>, which
    /// holds nothing and exists only because <c>u.e.p.test.</c> does — the NSEC
    /// whose span holds it and whose next name is that descendant. Either says the
    /// name exists, holds no DS, and is no zone cut, so the zone goes on below it
    /// and the walk with it. A walk that took either for the end of the road would
    /// make every unsigned delegation more than one label down Bogus.
    /// </para>
    /// <para>
    /// The second is the common one. <c>_tcp</c> labels, and the second level of
    /// any registry that delegates at the third, are empty non-terminals.
    /// </para>
    /// </remarks>
    [Test]
    public async Task The_Walk_Down_Goes_On_Through_A_Name_That_Is_No_Zone_Cut()
    {

        using var parent = KeyFor("p.test");

        var resolver  = new StubDnsClient().
                            Answer   ("p.test",     DNSResourceRecordTypes.DNSKEY, KeySet(parent)).
                            Authority("x.p.test",   DNSResourceRecordTypes.DS,     Signed(parent, Nsec("x.p.test",   "u.x.p.test", AtAnAddress))).
                            Authority("u.x.p.test", DNSResourceRecordTypes.DS,     Signed(parent, Nsec("u.x.p.test", "y.p.test",   AtADelegation))).
                            Authority("e.p.test",   DNSResourceRecordTypes.DS,     Signed(parent, Nsec("d.p.test",   "u.e.p.test", AtAnAddress))).
                            Authority("u.e.p.test", DNSResourceRecordTypes.DS,     Signed(parent, Nsec("u.e.p.test", "f.p.test",   AtADelegation)));

        var validator = new DNSSECValidator(resolver, [ parent.DelegationSigner() ]);

        Assert.Multiple(async () => {

            Assert.That(await validator.ValidateAsync(ResponseWith(Address("www.u.x.p.test"))),
                        Is.EqualTo(DNSSECValidationResult.Insecure),
                        "x.p.test. holds an address and no zone cut, and the delegation is below it");

            Assert.That(await validator.ValidateAsync(ResponseWith(Address("www.u.e.p.test"))),
                        Is.EqualTo(DNSSECValidationResult.Insecure),
                        "e.p.test. holds nothing at all, and the delegation is below it too");

        });

    }

    #endregion


    #region An_Nsec_At_A_Name_That_Is_No_Delegation_Proves_No_Unsigned_Delegation()

    /// <summary>
    /// RFC 6840 §4.4: the validator "MUST check for the presence of the NS bit in
    /// the matching NSEC (or NSEC3) RR (proving that there is, indeed, a
    /// delegation)". An unsigned A record at <c>www.p.test.</c>, with the genuine
    /// NSEC of <c>www.p.test.</c> as the answer to its DS query, is Bogus.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The section names this attack itself: "an attacker could reuse an NSEC or
    /// NSEC3 RR matching a non-delegation name to spoof an unsigned delegation at
    /// that name. This would claim that an existing signed RRset ... is below an
    /// unsigned delegation, thus not signed". The NSEC is real, signed by
    /// <c>p.test.</c>, and it does say that <c>www.p.test.</c> holds no DS. It
    /// says so because <c>www.p.test.</c> holds an A record and no zone cut, which
    /// is what its missing NS bit means — and its SOA bit is clear too, so a
    /// validator that read either bit alone would not tell this record from a
    /// delegation's.
    /// </para>
    /// <para>
    /// The A record is what <c>p.test.</c> would have signed. Without its
    /// signature it is missing data, and Bogus.
    /// </para>
    /// </remarks>
    [Test]
    [Property("RFC", "6840 §4.4")]
    public async Task An_Nsec_At_A_Name_That_Is_No_Delegation_Proves_No_Unsigned_Delegation()
    {

        using var parent = KeyFor("p.test");

        var resolver  = new StubDnsClient().
                            Answer   ("p.test",     DNSResourceRecordTypes.DNSKEY, KeySet(parent)).
                            Authority("www.p.test", DNSResourceRecordTypes.DS,     Signed(parent, Nsec("www.p.test", "x.p.test", AtAnAddress)));

        var validator = new DNSSECValidator(resolver, [ parent.DelegationSigner() ]);

        Assert.That(await validator.ValidateAsync(ResponseWith(Address("www.p.test"))),
                    Is.EqualTo(DNSSECValidationResult.Bogus),
                    "an NSEC without the NS bit proves a name, not a delegation");

    }

    #endregion

    #region A_Proof_Whose_Signature_Does_Not_Verify_Proves_Nothing()

    /// <summary>
    /// RFC 4035 §5.2 ends the authentication path on an NSEC RRset the validator
    /// "authenticates". The NSEC at <c>u.p.test.</c> shows a delegation without DS;
    /// signed by <c>p.test.</c>'s key, an unsigned answer below it is Insecure, and
    /// signed by any other key under <c>p.test.</c>'s name it is Bogus.
    /// </summary>
    /// <remarks>
    /// Finding 70 was this rule for a negative answer: a denial read from NSEC
    /// records whose signatures did not verify. The proof of an unsigned
    /// delegation is read by other code, and a signature whose signer's name and
    /// validity window are both right is not yet a signature that verifies.
    /// </remarks>
    [Test]
    public async Task A_Proof_Whose_Signature_Does_Not_Verify_Proves_Nothing()
    {

        using var parent = KeyFor("p.test");
        using var forged = KeyFor("p.test");

        StubDnsClient ProofSignedBy(DNSSECSigningKey Signer)
            => new StubDnsClient().
                   Answer   ("p.test",   DNSResourceRecordTypes.DNSKEY, KeySet(parent)).
                   Authority("u.p.test", DNSResourceRecordTypes.DS,     Signed(Signer, Nsec("u.p.test", "v.p.test", AtADelegation)));

        var anchors  = new[] { parent.DelegationSigner() };
        var response = ResponseWith(Address("www.u.p.test"));

        Assert.Multiple(async () => {

            Assert.That(await new DNSSECValidator(ProofSignedBy(parent), anchors).ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Insecure),
                        "the control: p.test.'s signature over its NSEC");

            Assert.That(await new DNSSECValidator(ProofSignedBy(forged), anchors).ValidateAsync(response),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "the same NSEC under a signature p.test.'s keys do not verify");

        });

    }

    #endregion

    #region A_Proof_Signed_In_Another_Zones_Name_Is_Not_The_Zones_Own()

    /// <summary>
    /// RFC 4035 §5.3.1: an RRSIG authenticates an RRset only if "the RRSIG RR's
    /// Signer's Name, Algorithm, and Key Tag fields MUST match the owner name,
    /// algorithm, and key tag for some DNSKEY RR in the zone's apex DNSKEY RRset."
    /// The NSEC at <c>u.p.test.</c> is signed with <c>p.test.</c>'s own key, and
    /// its signature verifies under that key — and the signature names
    /// <c>u.p.test.</c> as its signer. It is not <c>p.test.</c>'s proof, and the
    /// unsigned answer below it is Bogus.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A key verifies a signature; the signer's name says whose word it is. The
    /// two come apart wherever one key signs more than one zone, which operators
    /// do. Here the name on the signature is the child's — a zone that, by the
    /// record's own account, is unsigned and has no keys to sign with — and the
    /// key that verifies it belongs to a DNSKEY RR whose owner is
    /// <c>p.test.</c>. The §5.3.1 condition fails on the name.
    /// </para>
    /// <para>
    /// The signature is made by hand for that reason: the zone signer writes the
    /// key's own zone into the field, and this record exists to have another.
    /// </para>
    /// </remarks>
    [Test]
    [Property("RFC", "4035 §5.3.1")]
    public async Task A_Proof_Signed_In_Another_Zones_Name_Is_Not_The_Zones_Own()
    {

        using var parent = KeyFor("p.test");

        var nsec     = Nsec("u.p.test", "v.p.test", AtADelegation);

        var template = new RRSIG(DomainName.Parse("u.p.test"),
                                 DNSQueryClasses.IN,
                                 TimeSpan.FromHours(1),
                                 DNSResourceRecordTypes.NSEC,
                                 parent.Algorithm,
                                 3,
                                 3600,
                                 (UInt32) DateTimeOffset.UtcNow.AddDays(14).ToUnixTimeSeconds(),
                                 (UInt32) DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds(),
                                 parent.KeyTag,
                                 DomainName.Parse("u.p.test"),
                                 []);

        var signature = new RRSIG(DomainName.Parse("u.p.test"),
                                  template.Class,
                                  template.TimeToLive,
                                  template.TypeCovered,
                                  template.Algorithm,
                                  template.Labels,
                                  template.OriginalTTL,
                                  template.SignatureExpiration,
                                  template.SignatureInception,
                                  template.KeyTag,
                                  template.SignerName,
                                  parent.Sign(DNSSECCanonical.SignedData([ nsec ], template)));

        var resolver  = new StubDnsClient().
                            Answer   ("p.test",   DNSResourceRecordTypes.DNSKEY, KeySet(parent)).
                            Authority("u.p.test", DNSResourceRecordTypes.DS,     nsec, signature);

        var validator = new DNSSECValidator(resolver, [ parent.DelegationSigner() ]);

        Assert.That(await validator.ValidateAsync(ResponseWith(Address("www.u.p.test"))),
                    Is.EqualTo(DNSSECValidationResult.Bogus),
                    "a signature in u.p.test.'s name is u.p.test.'s, whichever key made it");

    }

    #endregion

}

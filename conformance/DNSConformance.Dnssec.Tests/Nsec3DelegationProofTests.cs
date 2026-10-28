using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 5155 §8.6 and RFC 6840 §4.4 — the NSEC3 records that prove a delegation
/// unsigned, read by <see cref="DenialOfExistenceValidator.VerifyNoDelegationSigner"/>.
/// </summary>
/// <remarks>
/// <para>
/// A DS query answered with NSEC3 proves an unsigned delegation in one of two
/// ways. Either an NSEC3 matches the child's name, holds NS and neither DS nor
/// SOA — the same shape as the NSEC that
/// <see cref="UnsignedDelegationTests"/> reads — or the child's name lies in an
/// opt-out span, whose zone declined to say whether unsigned delegations are
/// there. Both are read twice: once for what the records deny, and once more for
/// the type bitmap that says whether the denial is about a delegation at all.
/// It is that second reading these tests are about.
/// </para>
/// <para>
/// The records are built by hand and the hashes computed from RFC 5155 §5 —
/// H(owner name in canonical wire form, then the salt), no extra iterations —
/// rather than asked of Hermod. Nothing here is signed:
/// <c>VerifyNoDelegationSigner</c> is handed records whose signatures were
/// already checked, and what it decides is what they say.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "5155 §8.6")]
[Property("RFC", "6840 §4.4")]
public class Nsec3DelegationProofTests
{

    #region Data

    private const  Byte    SHA1Algorithm = 1;
    private const  Byte    OptOut        = 0x01;
    private static readonly Byte[] Salt  = Convert.FromHexString("aabbccdd");
    private static readonly Byte[] Other = Convert.FromHexString("11223344");

    /// <summary>
    /// RFC 4034 §6.2's canonical wire form of a name, lowercased. The root is the
    /// one name with no labels: a single zero octet.
    /// </summary>
    private static Byte[] CanonicalWire(String Name)
    {

        var stream = new MemoryStream();

        foreach (var label in Name.ToLowerInvariant().TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((Byte) bytes.Length);
            stream.Write(bytes);
        }

        stream.WriteByte(0x00);

        return stream.ToArray();

    }

    /// <summary>RFC 5155 §5: H(name || salt), with no extra iterations.</summary>
    private static Byte[] Hash(String Name, Byte[]? WithSalt = null)
        => SHA1.HashData([ .. CanonicalWire(Name), .. WithSalt ?? Salt ]);

    private static Byte[] Step(Byte[] Hash, Int32 By)
    {

        var copy  = (Byte[]) Hash.Clone();
        var carry = By;

        for (var i = copy.Length - 1; i >= 0 && carry != 0; i--)
        {
            var sum = copy[i] + carry;
            copy[i] = (Byte) (sum & 0xFF);
            carry   = sum < 0 ? -1 : sum >> 8;
        }

        return copy;

    }

    /// <summary>
    /// RFC 4034 §4.1.2: a type bitmap of window 0, bit <c>i</c> of the block
    /// standing for type <c>i</c>. NS is 2, SOA 6, DS 43, RRSIG 46, DNSKEY 48,
    /// NSEC3PARAM 51, A 1.
    /// </summary>
    private static Byte[] Types(params Int32[] Codes)
    {

        var octets = new Byte[Codes.Max() / 8 + 1];

        foreach (var code in Codes)
            octets[code / 8] |= (Byte) (0x80 >> (code % 8));

        return [ 0x00, (Byte) octets.Length, .. octets ];

    }

    private static readonly Byte[] AtAnApex           = Types(2, 6, 46, 48, 51);
    private static readonly Byte[] AtADelegation      = Types(2);
    private static readonly Byte[] AtASignedDelegation = Types(2, 43, 46);
    private static readonly Byte[] AtAnAddress        = Types(1, 46);

    private static NSEC3 Nsec3(String Zone, Byte[] OwnerHash, Byte[] NextHash, Byte[] TypeBitMap, Byte Flags = 0, Byte[]? WithSalt = null)
        => new (DomainName.Parse($"{NSEC3.Base32HexEncode(OwnerHash)}.{Zone.TrimStart('.')}"),
                DNSQueryClasses.IN,
                TimeSpan.FromHours(1),
                SHA1Algorithm,
                Flags,
                0,
                WithSalt ?? Salt,
                NextHash,
                TypeBitMap);

    /// <summary>The NSEC3 matching a name, with a span that holds nothing else.</summary>
    private static NSEC3 Matching(String Zone, String Name, Byte[] TypeBitMap, Byte[]? WithSalt = null)
        => Nsec3(Zone, Hash(Name), Step(Hash(Name), 1), TypeBitMap, WithSalt: WithSalt);

    /// <summary>An NSEC3 whose span holds the name's hash and nothing else.</summary>
    private static NSEC3 Covering(String Zone, String Name, Byte Flags = 0)
        => Nsec3(Zone, Step(Hash(Name), -1), Step(Hash(Name), 1), Types(46), Flags);

    private static DenialOfExistence NoDs(String Child, params IDNSResourceRecord[] Records)
        => DenialOfExistenceValidator.VerifyNoDelegationSigner(DomainName.ParseLenient(Child), Records);

    #endregion


    #region An_Nsec3_Matching_A_Delegation_Proves_It_Unsigned()

    /// <summary>
    /// RFC 5155 §8.6, the first way: an NSEC3 that matches the child's name, with
    /// NS in its bitmap and DS absent, proves the delegation unsigned. The same
    /// record with DS in its bitmap proves the opposite.
    /// </summary>
    /// <remarks>
    /// It is the shape every unsigned delegation of an NSEC3 zone without opt-out
    /// is proven by, and no test had asked for it: the walk tests prove their
    /// delegations with NSEC.
    /// </remarks>
    [Test]
    public void An_Nsec3_Matching_A_Delegation_Proves_It_Unsigned()
    {

        Assert.Multiple(() => {

            Assert.That(NoDs("d.example.", Matching("example.", "d.example.", AtADelegation)),
                        Is.EqualTo(DenialOfExistence.NoDataForType),
                        "a delegation, and no DS for it");

            Assert.That(NoDs("d.example.", Matching("example.", "d.example.", AtASignedDelegation)),
                        Is.EqualTo(DenialOfExistence.NotProven),
                        "a delegation whose DS the record itself lists");

        });

    }

    #endregion

    #region Records_Of_Another_Chain_Do_Not_Make_A_Name_A_Delegation()

    /// <summary>
    /// RFC 5155 §8.2: the records of a proof share one hash algorithm, iteration
    /// count and salt. <c>www.example.</c> is an ordinary name, and its NSEC3 —
    /// A and RRSIG, no NS — proves it no delegation. A second record at the same
    /// owner name, of another chain, says NS. It is not part of this proof.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="DenialProofTests.Records_Of_Another_Chain_Are_Not_Part_Of_This_Proof"/>
    /// holds the denial to this, and the denial gets it right: it finds the
    /// genuine record and reads NODATA. The question whether the name is a
    /// delegation is a second look at the records, and it has to make the same
    /// choice of records as the first.
    /// </para>
    /// <para>
    /// The decoy is built the way that one is: its owner name is the hash of
    /// <c>www.example.</c> under the reference salt, so it looks like a match, and
    /// its own salt field says it was hashed under another. It shares the
    /// reference's algorithm and iteration count, so a comparison that dropped
    /// either conjunction would let it in — and it comes first, as anyone placing
    /// it would put it.
    /// </para>
    /// </remarks>
    [Test]
    [Property("RFC", "5155 §8.2")]
    public void Records_Of_Another_Chain_Do_Not_Make_A_Name_A_Delegation()
    {

        var apex    = Matching("example.", "example.",     AtAnApex);
        var decoy   = Matching("example.", "www.example.", AtADelegation, WithSalt: Other);
        var genuine = Matching("example.", "www.example.", AtAnAddress);

        Assert.That(NoDs("www.example.", apex, decoy, genuine),
                    Is.EqualTo(DenialOfExistence.NotProven),
                    "only the record of the reference chain speaks for www.example., and it holds no NS");

    }

    #endregion

    #region An_Opt_Out_Span_Below_An_Ordinary_Closest_Encloser_Proves_An_Unsigned_Delegation()

    /// <summary>
    /// RFC 5155 §8.6, the second way: the closest encloser of <c>d.example.</c> is
    /// the apex, and an opt-out NSEC3 covers the next closer name. The delegation
    /// may be there and unsigned, which is all a DS query needs to hear.
    /// </summary>
    /// <remarks>
    /// Opt-out is how most of the large delegation-only zones are signed — it is
    /// what lets a registry leave unsigned delegations out of its chain — so this
    /// is the proof a validator sees for nearly every unsigned zone below them.
    /// </remarks>
    [Test]
    [Property("RFC", "5155 §6")]
    public void An_Opt_Out_Span_Below_An_Ordinary_Closest_Encloser_Proves_An_Unsigned_Delegation()
    {

        Assert.That(NoDs("d.example.",
                         Matching("example.", "example.",   AtAnApex),
                         Covering("example.", "d.example.", OptOut)),
                    Is.EqualTo(DenialOfExistence.OptedOut),
                    "the apex is the closest encloser, and the next closer name is in an opt-out span");

    }

    #endregion

    #region An_Opt_Out_Span_Below_A_Delegation_Proves_Nothing()

    /// <summary>
    /// RFC 6840 §4.1: an NSEC3 with NS set and SOA clear is an "ancestor
    /// delegation" record, and "MUST NOT be used to assume nonexistence of any
    /// RRs below that zone cut". The DS query is for <c>x.d.example.</c>; the
    /// closest encloser found is <c>d.example.</c>, a delegation; an opt-out span
    /// of <c>example.</c> covers the next closer name. That proves nothing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>x.d.example.</c> is not in <c>example.</c> at all. It is in the child
    /// zone <c>d.example.</c> — here a signed one, its DS in the bitmap — and
    /// what <c>example.</c>'s opt-out spans say about hashes is said about its own
    /// names. Taken as a proof, the parent's records would make every name of a
    /// signed child look like an unsigned delegation, and every answer under it
    /// could be stripped of its signatures and still be Insecure.
    /// </para>
    /// <para>
    /// The control is the test above: the same proof with the apex as the
    /// closest encloser is an opt-out.
    /// </para>
    /// </remarks>
    [Test]
    [Property("RFC", "6840 §4.1")]
    public void An_Opt_Out_Span_Below_A_Delegation_Proves_Nothing()
    {

        Assert.That(NoDs("x.d.example.",
                         Matching("example.", "d.example.",   AtASignedDelegation),
                         Covering("example.", "x.d.example.", OptOut)),
                    Is.EqualTo(DenialOfExistence.NotProven),
                    "an opt-out of example. says nothing about the names below its zone cut at d.example.");

    }

    #endregion

    #region An_Nsec3_Signed_Root_Is_The_Closest_Encloser_Of_A_Top_Level_Domain()

    /// <summary>
    /// RFC 5155 §8.3: the closest encloser is the longest existing ancestor of
    /// the name, and for a top-level domain the only ancestor is the root. In a
    /// root zone signed with NSEC3 and opt-out, a TLD whose hash an opt-out span
    /// covers is an unsigned delegation, and its only closest encloser is the
    /// root's own record.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both searches for the closest encloser — the one that reads the denial,
    /// and the one that then reads its bitmap — walk up from the name one label
    /// at a time, and for a one-label name the root is the first ancestor and the
    /// last. A walk that stopped one short would never try it.
    /// </para>
    /// <para>
    /// The root is signed with NSEC today, so no resolver meets this on the
    /// internet. It is still the boundary of the walk, and the only name a walk
    /// one short leaves out. The NSEC twin is
    /// <see cref="DenialProofTests.A_Top_Level_Domain_That_Does_Not_Exist_Is_Denied_By_The_Root"/>.
    /// </para>
    /// </remarks>
    [Test]
    [Property("RFC", "5155 §8.3")]
    public void An_Nsec3_Signed_Root_Is_The_Closest_Encloser_Of_A_Top_Level_Domain()
    {

        Assert.That(NoDs("tld.",
                         Matching(".", ".",    AtAnApex),
                         Covering(".", "tld.", OptOut)),
                    Is.EqualTo(DenialOfExistence.OptedOut),
                    "the root matches, and tld. lies in one of its opt-out spans");

    }

    #endregion

    #region A_Top_Level_Domain_That_Does_Not_Exist_Is_Denied_By_An_Nsec3_Root()

    /// <summary>
    /// RFC 5155 §8.4, at the same boundary: <c>zz.</c> does not exist in a root
    /// zone signed with NSEC3. The root's own record is the closest encloser, one
    /// record covers <c>zz.</c>, and another covers the wildcard <c>*.</c> that
    /// could have synthesised it.
    /// </summary>
    /// <remarks>
    /// This is the denial alone, through <see cref="DenialOfExistenceValidator.Verify"/>,
    /// with the question an A record rather than a DS — the root's NXDOMAIN, the
    /// most-answered negative response there is, if the root were signed this
    /// way.
    /// </remarks>
    [Test]
    [Property("RFC", "5155 §8.4")]
    [Category(TestCategories.KnownIssue)]
    public void A_Top_Level_Domain_That_Does_Not_Exist_Is_Denied_By_An_Nsec3_Root()
    {

        Assert.That(DenialOfExistenceValidator.Verify(DomainName.ParseLenient("zz."),
                                                      DNSResourceRecordTypes.A,
                                                      [ Matching(".", ".",   AtAnApex),
                                                        Covering(".", "zz."),
                                                        Covering(".", "*.") ]),
                    Is.EqualTo(DenialOfExistence.NameDoesNotExist),
                    "the root encloses zz., and neither zz. nor *. exists");

    }

    #endregion

}

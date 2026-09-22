using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// Which records a denial may be built from, and which names it has to deny.
///
/// <para>
/// <see cref="NsecCoverageTests"/> and <see cref="Nsec3CoverageTests"/> pin the
/// arithmetic of a single record's span. What is left over is the reasoning
/// around it: a proof assembled from records that do not belong together, and a
/// proof that stops one name short of what RFC 4035 §5.4 asks for. Both produce
/// a verdict of "this name does not exist" from evidence that does not say so,
/// which is the only direction in which a denial can be wrong and still look
/// right.
/// </para>
///
/// <para>
/// The records here are built by hand and the hashes computed from RFC 5155 §5's
/// definition rather than read back from Hermod. A signer produces none of these
/// shapes — that is the point of them.
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "4035 §5.4")]
[Property("RFC", "5155 §8.2")]
public class DenialProofTests
{

    #region Data

    private const  Byte    SHA1Algorithm  = 1;
    private static readonly Byte[] Salt   = Convert.FromHexString("aabbccdd");
    private static readonly Byte[] Other  = Convert.FromHexString("11223344");

    /// <summary>RFC 4034 §6.2's canonical wire form of a name, lowercased.</summary>
    private static Byte[] CanonicalWire(String Name)
    {

        var stream = new MemoryStream();

        foreach (var label in Name.ToLowerInvariant().TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((Byte) bytes.Length);
            stream.Write(bytes);
        }

        stream.WriteByte(0x00);

        return stream.ToArray();

    }

    /// <summary>RFC 5155 §5: H(name) with no extra iterations, under the given salt.</summary>
    private static Byte[] Hash(String Name, Byte[] WithSalt)
        => SHA1.HashData([.. CanonicalWire(Name), .. WithSalt]);

    /// <summary>The next hash up, so that a record can be given a span that holds nothing.</summary>
    private static Byte[] PlusOne(Byte[] Hash)
    {

        var copy = (Byte[]) Hash.Clone();

        for (var i = copy.Length - 1; i >= 0; i--)
        {
            if (copy[i] != 0xFF)
            {
                copy[i]++;
                return copy;
            }
            copy[i] = 0x00;
        }

        throw new ArgumentException("a hash of nothing but 0xFF has no successor", nameof(Hash));

    }

    private static NSEC3 Nsec3(Byte[] OwnerHash, Byte[] NextHash, Byte[]? WithSalt = null)
        => new (DomainName.Parse($"{NSEC3.Base32HexEncode(OwnerHash)}.example."),
                DNSQueryClasses.IN,
                TimeSpan.FromHours(1),
                SHA1Algorithm,
                0,
                0,
                WithSalt ?? Salt,
                NextHash,
                []);

    /// <summary>An NSEC with an empty type bitmap — only its span is of interest here.</summary>
    private static NSEC Nsec(String Owner, String Next)
        => new (DomainName.Parse(Owner),
                DNSQueryClasses.IN,
                TimeSpan.FromHours(1),
                DomainName.Parse(Next),
                []);

    private static DenialOfExistence Verify(String QName, params IDNSResourceRecord[] Records)
        => DenialOfExistenceValidator.Verify(DomainName.ParseLenient(QName),
                                             DNSResourceRecordTypes.A,
                                             Records);

    /// <summary>
    /// An NSEC3 that matches the apex, with a span holding nothing. It is what
    /// makes the closest-encloser proof get as far as looking for a cover, so
    /// that what is or is not admitted as a cover decides the verdict.
    /// </summary>
    private static NSEC3 ApexMatch()
    {
        var apex = Hash("example.", Salt);
        return Nsec3(apex, PlusOne(apex));
    }

    #endregion


    #region Records_Of_Another_Chain_Are_Not_Part_Of_This_Proof()

    /// <summary>
    /// RFC 5155 §8.2: "the validator MUST ignore NSEC3 RRs with ... different
    /// values" for hash algorithm, iterations or salt. A zone being re-signed
    /// publishes two chains at once, and a record of the old one says nothing
    /// about the new one — its hashes are of a different function.
    ///
    /// <para>
    /// The decoy here is the shape that matters: its owner name is the hash of
    /// the queried name <b>under the reference record's salt</b>, so it looks
    /// like a match, while its own salt field says it was computed under another.
    /// A validator that compared only part of the parameter set would find it,
    /// read its empty type bitmap, and answer NODATA for a name nothing in this
    /// chain says anything about.
    /// </para>
    ///
    /// <para>
    /// One decoy covers both halves of the comparison: it shares the reference's
    /// hash algorithm and iteration count and differs only in the salt, so
    /// dropping either conjunction admits it.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "5155 §8.2")]
    public void Records_Of_Another_Chain_Are_Not_Part_Of_This_Proof()
    {

        var decoy = Nsec3(Hash("q.example.", Salt),          // looks like a match…
                          PlusOne(Hash("q.example.", Salt)),
                          WithSalt: Other);                   // …under a salt that is not this chain's

        Assert.That(decoy.Salt, Is.Not.EqualTo(Salt).AsCollection,
                    "the decoy belongs to another chain, which is the whole construction");

        Assert.That(Verify("q.example.", ApexMatch(), decoy),
                    Is.EqualTo(DenialOfExistence.NotProven),
                    "a record of another chain proves nothing about this one");

    }

    #endregion

    #region An_Nsec3_Whose_Owner_Is_Not_A_Hash_Is_Not_In_The_Chain()

    /// <summary>
    /// RFC 5155 §3: an NSEC3's owner name is the base32hex of a hash, prefixed
    /// to the zone name. A record whose leftmost label is not there at all
    /// carries no hash, and a hash it does not have cannot be an end of a span.
    ///
    /// <para>
    /// Read as an empty hash rather than as no hash, it becomes the lowest value
    /// there is, and a record reaching from it to the highest covers the entire
    /// hash space — one record proving the absence of every name in the zone.
    /// That is the failure this guards against, and it is why "no hash" has to be
    /// different from "the empty hash".
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "5155 §3")]
    public void An_Nsec3_Whose_Owner_Is_Not_A_Hash_Is_Not_In_The_Chain()
    {

        var everything = new NSEC3(DomainName.ParseLenient("."),
                                   DNSQueryClasses.IN,
                                   TimeSpan.FromHours(1),
                                   SHA1Algorithm,
                                   0,
                                   0,
                                   Salt,
                                   [.. Enumerable.Repeat((Byte) 0xFF, 20)],
                                   []);

        Assert.That(Verify("q.example.", ApexMatch(), everything),
                    Is.EqualTo(DenialOfExistence.NotProven),
                    "a record with no hashed owner name is not a cover, however wide its next hash reaches");

    }

    #endregion

    #region A_Covered_Name_Is_Not_Denied_Until_Its_Wildcard_Is()

    /// <summary>
    /// RFC 4035 §5.4: an NXDOMAIN proof is two statements, not one. The first
    /// NSEC says the name itself is not in the zone; the second says no wildcard
    /// could have synthesised it. Without the second the name may well be
    /// answerable, and a resolver that stopped after the first would refuse an
    /// answer the zone is willing to give.
    ///
    /// <para>
    /// The chain here is missing the record that would deny <c>*.example.</c> —
    /// the apex's own, since <c>*</c> is 0x2A and sorts below every letter. What
    /// is left covers the queried name and nothing else, which is exactly half a
    /// proof.
    /// </para>
    /// </summary>
    [Test]
    public void A_Covered_Name_Is_Not_Denied_Until_Its_Wildcard_Is()
    {

        Assert.That(Verify("c.example.", Nsec("b.example.", "d.example.")),
                    Is.EqualTo(DenialOfExistence.NotProven),
                    "the name is covered and the wildcard is not denied, which proves nothing");

    }

    #endregion

    #region A_Top_Level_Domain_That_Does_Not_Exist_Is_Denied_By_The_Root()

    /// <summary>
    /// The walk up to the wildcard has to reach the root, and a one-label query
    /// is where that shows: for <c>zz.</c> the only wildcard that could have
    /// synthesised an answer is the root's own <c>*.</c>, so the very first step
    /// of the walk is also its last.
    ///
    /// <para>
    /// A walk that stopped one short would never prove any TLD absent — the root
    /// zone's NXDOMAIN, which is the most-answered negative response there is.
    /// The chain below is the root's: the apex record spans from the root up to
    /// the first TLD, which is what denies <c>*.</c>, and the last record wraps.
    /// </para>
    /// </summary>
    [Test]
    public void A_Top_Level_Domain_That_Does_Not_Exist_Is_Denied_By_The_Root()
    {

        var root = new[] {
                       Nsec(".",    "com."),
                       Nsec("com.", "org."),
                       Nsec("org.", ".")
                   };

        Assert.That(Verify("zz.", root),
                    Is.EqualTo(DenialOfExistence.NameDoesNotExist),
                    "the wrapping record covers zz., and the root's own record denies *.");

    }

    #endregion

}

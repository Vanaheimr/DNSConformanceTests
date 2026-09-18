using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 5155 §7.2 and §8.3 — the span an NSEC3 record covers, in the hash domain.
///
/// <para>
/// The arithmetic is the same as <see cref="NsecCoverageTests"/>'s and written a
/// second time in the same file, against hashes instead of names: strictly above
/// the owner, strictly below the next, and the last record of the chain wrapping
/// past the highest hash back to the lowest. Both ends are open for the same
/// reason — the hashes at them belong to names that exist.
/// </para>
///
/// <para>
/// The hashes here are computed by this suite from RFC 5155 §5's definition, not
/// read back from Hermod, so a record can be given a span that ends exactly on
/// the hash of the name being asked about. A signer produces no such chain, which
/// is why <see cref="DenialOfExistenceTests"/> — which uses BIND's output — cannot
/// reach these cases.
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "5155 §7.2")]
public class Nsec3CoverageTests
{

    #region Data

    private const  Byte    SHA1Algorithm = 1;
    private static readonly Byte[] Salt  = Convert.FromHexString("aabbccdd");

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

    /// <summary>RFC 5155 §5: H(name) with no extra iterations.</summary>
    private static Byte[] Hash(String Name)
        => SHA1.HashData([.. CanonicalWire(Name), .. Salt]);

    /// <summary>
    /// An NSEC3 whose owner label is the given hash and whose span ends at the
    /// given one. The type bitmap is empty: only the span matters here.
    /// </summary>
    private static NSEC3 Nsec3(Byte[] OwnerHash, Byte[] NextHash, Byte Flags = 0)
        => new (DomainName.Parse($"{NSEC3.Base32HexEncode(OwnerHash)}.example."),
                DNSQueryClasses.IN,
                TimeSpan.FromHours(1),
                SHA1Algorithm,
                Flags,
                0,
                Salt,
                NextHash,
                []);

    /// <summary>
    /// The same hash with one added to its last octet, and one taken away.
    ///
    /// The bounds check is not ceremony: an octet of 0xFF or 0x00 would wrap, and
    /// a wrapped octet reverses the ordering of the chain silently — every test
    /// here would go on passing while proving the opposite of what it says. SHA-1
    /// of a fixed name is a fixed value, so this either always holds or never
    /// does, and it should say which.
    /// </summary>
    private static Byte[] Above(Byte[] H)
    {
        Assert.That(H[^1], Is.LessThan(0xFE), "the last octet would wrap; pick another name");
        var c = (Byte[]) H.Clone();
        c[^1]++;
        return c;
    }

    private static Byte[] Below(Byte[] H)
    {
        Assert.That(H[^1], Is.GreaterThan(0x01), "the last octet would wrap; pick another name");
        var c = (Byte[]) H.Clone();
        c[^1]--;
        return c;
    }

    private static DenialOfExistence Verify(String QName, params NSEC3[] Records)
        => DenialOfExistenceValidator.Verify(
               DomainName.Parse(QName),
               DNSResourceRecordTypes.A,
               Records
           );

    /// <summary>
    /// The three records an NXDOMAIN proof needs for "c.example.": one matching
    /// the closest encloser, one covering the next closer name, and one covering
    /// the wildcard. The two spans are supplied by the caller so each test can
    /// put its own boundary on them.
    /// </summary>
    private static NSEC3[] Proof(NSEC3 CoveringNextCloser, NSEC3 CoveringWildcard)
        => [
               Nsec3(Hash("example."), Above(Hash("example."))),   // the apex matches itself
               CoveringNextCloser,
               CoveringWildcard
           ];

    private static NSEC3 SpanAround(String Name)
        => Nsec3(Below(Hash(Name)), Above(Hash(Name)));

    #endregion


    #region A_Hash_Inside_A_Span_Is_Denied()

    /// <summary>
    /// The control, and the shape every case below varies: RFC 5155 §8.4 wants
    /// the next closer name covered and the wildcard covered before it will call
    /// a name absent.
    /// </summary>
    [Test]
    [Property("RFC", "5155 §8.4")]
    public void A_Hash_Inside_A_Span_Is_Denied()
    {

        Assert.That(Verify("c.example.",
                           Proof(SpanAround("c.example."), SpanAround("*.example."))),
                    Is.EqualTo(DenialOfExistence.NameDoesNotExist));

    }

    #endregion

    #region An_Nsec3_Does_Not_Deny_The_Hash_Its_Span_Ends_At()

    /// <summary>
    /// The next hashed owner name is the next owner in the chain: some name
    /// hashes to it, and that name exists. A span reaching its own end would
    /// prove that name absent.
    /// </summary>
    [Test]
    public void An_Nsec3_Does_Not_Deny_The_Hash_Its_Span_Ends_At()
    {

        // The span stops exactly at the next closer name's hash.
        var endsAtIt = Nsec3(Below(Hash("c.example.")), Hash("c.example."));

        Assert.That(Verify("c.example.", Proof(endsAtIt, SpanAround("*.example."))),
                    Is.EqualTo(DenialOfExistence.NotProven),
                    "the span stops short of the hash it points at");

    }

    #endregion

    #region An_Nsec3_Does_Not_Deny_A_Hash_Past_Its_Span()

    /// <summary>
    /// Both ends have to hold at once, for a span that does not wrap.
    /// </summary>
    [Test]
    public void An_Nsec3_Does_Not_Deny_A_Hash_Past_Its_Span()
    {

        // A span that sits entirely below the hash being asked about.
        var wellBelow = Nsec3(Below(Below(Hash("c.example."))), Below(Hash("c.example.")));

        Assert.That(Verify("c.example.", Proof(wellBelow, SpanAround("*.example."))),
                    Is.EqualTo(DenialOfExistence.NotProven),
                    "a hash above both ends of the span is outside it");

    }

    #endregion

    #region The_Last_Nsec3_Of_A_Chain_Wraps_Past_The_Highest_Hash()

    /// <summary>
    /// RFC 5155 §7.2: the chain is a ring. Its last record's next hashed owner
    /// name is the lowest hash in the zone, so its span runs off the top of the
    /// ordering and back to the bottom — and for that record alone a hash
    /// qualifies by being above the owner *or* below the next.
    ///
    /// Without that, a zone cannot deny anything hashing above its highest name,
    /// which is a fixed fraction of the namespace an attacker can aim at.
    /// </summary>
    [Test]
    [Property("RFC", "5155 §7.2")]
    public void The_Last_Nsec3_Of_A_Chain_Wraps_Past_The_Highest_Hash()
    {

        var target  = Hash("c.example.");

        // The ring's last record, with the target above its owner: the span runs
        // off the top of the ordering and the target is in the part above.
        var wrapping = Nsec3(Below(target), Below(Below(target)));

        Assert.That(Verify("c.example.", Proof(wrapping, SpanAround("*.example."))),
                    Is.EqualTo(DenialOfExistence.NameDoesNotExist),
                    "a hash past the chain's highest owner is denied by the wrapping record");

        // The same wrapping shape with the target in the gap the span does not
        // reach — below the owner and above the next — is not denied by it. A
        // ring is not a record that covers everything.
        var missesIt = Nsec3(Above(target), Below(target));

        Assert.That(Verify("c.example.", Proof(missesIt, SpanAround("*.example."))),
                    Is.EqualTo(DenialOfExistence.NotProven),
                    "wrapping does not mean covering everything");

    }

    #endregion

    #region A_Chain_Of_One_Record_Wraps_Onto_Itself()

    /// <summary>
    /// A record whose next hashed owner name is its own owner hash spans
    /// everything except the one name that hashes to it. Reading that equality as
    /// "no wrap" leaves the span empty and denies nothing.
    /// </summary>
    [Test]
    [Property("RFC", "5155 §7.2")]
    public void A_Chain_Of_One_Record_Wraps_Onto_Itself()
    {

        var apex  = Hash("example.");

        // The apex matches itself and its span wraps the whole ring.
        var alone = Nsec3(apex, apex);

        Assert.That(Verify("c.example.", [alone]),
                    Is.EqualTo(DenialOfExistence.NameDoesNotExist),
                    "one record whose span ends where it starts covers everything else");

    }

    #endregion

}

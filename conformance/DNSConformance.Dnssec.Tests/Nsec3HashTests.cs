using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 5155 — the NSEC3 hash.
///
/// <para>
/// The primary evidence is Appendix A of RFC 5155, which publishes a fully
/// worked example zone: algorithm 1, 12 iterations, salt <c>aabbccdd</c>, and
/// the hashed owner name for every name in the zone. Those are somebody else's
/// numbers, computed by the people who wrote the specification, which is what
/// makes them worth asserting against.
/// </para>
///
/// <para>
/// The remaining tests pin the two details of §5 that an implementation can get
/// wrong while still passing a single-round check: that the salt is appended on
/// every iteration rather than only the first, and that the iteration count is a
/// count of *extra* rounds, so zero still hashes once. Both are checked against
/// the formula applied by hand with <c>SHA1</c>, not against Hermod's own
/// output.
/// </para>
/// </summary>
[TestFixture]
public class Nsec3HashTests
{

    private static readonly Byte[] Rfc5155Salt        = Convert.FromHexString("aabbccdd");
    private const           UInt16 Rfc5155Iterations  = 12;


    #region Rfc5155_Appendix_A_Hash_Vectors(Name, ExpectedHash)

    // RFC 5155 Appendix A, the "example." zone: algorithm 1, 12 iterations,
    // salt aabbccdd. Every hashed owner name the appendix publishes.
    [Test]
    [Property("RFC", "5155 App. A")]
    [TestCase("example.",                                   "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom")]
    [TestCase("a.example.",                                 "35mthgpgcu1qg68fab165klnsnk3dpvl")]
    [TestCase("ai.example.",                                "gjeqe526plbf1g8mklp59enfd789njgi")]
    [TestCase("ns1.example.",                               "2t7b4g4vsa5smi47k61mv5bv1a22bojr")]
    [TestCase("ns2.example.",                               "q04jkcevqvmu85r014c7dkba38o0ji5r")]
    [TestCase("w.example.",                                 "k8udemvp1j2f7eg6jebps17vp3n8i58h")]
    [TestCase("*.w.example.",                               "r53bq7cc2uvmubfu5ocmm6pers9tk9en")]
    [TestCase("x.w.example.",                               "b4um86eghhds6nea196smvmlo4ors995")]
    [TestCase("y.w.example.",                               "ji6neoaepv8b5o6k4ev33abha8ht9fgc")]
    [TestCase("x.y.w.example.",                             "2vptu5timamqttgl4luu9kg21e0aor3s")]
    [TestCase("xx.example.",                                "t644ebqk9bibcna874givr6joj62mlhv")]
    [TestCase("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.",  "kohar7mbb8dc2ce8a9qvl8hon4k53uhi")]
    public void Rfc5155_Appendix_A_Hash_Vectors(String Name, String ExpectedHash)
    {

        // ParseLenient, not Parse: "*.w.example." is a wildcard owner name, and
        // the strict hostname parser refuses those by design.
        var hash     = NSEC3.ComputeHash(DomainName.ParseLenient(Name), Rfc5155Iterations, Rfc5155Salt);
        var encoded  = NSEC3.Base32HexEncode(hash);

        Assert.Multiple(() => {

            Assert.That(hash,                     Has.Length.EqualTo(20),
                        "SHA-1 produces 160 bits, and RFC 5155 §5 hashes with nothing else");

            Assert.That(encoded.ToLowerInvariant(), Is.EqualTo(ExpectedHash),
                        $"RFC 5155 Appendix A publishes the hash of {Name} as {ExpectedHash}");

        });

    }

    #endregion

    #region Iteration_Count_Is_Extra_Rounds_So_Zero_Still_Hashes_Once()

    [Test]
    [Property("RFC", "5155 §5")]
    public void Iteration_Count_Is_Extra_Rounds_So_Zero_Still_Hashes_Once()
    {

        // RFC 5155 §5: H(name) = IH(salt, name, iterations), and IH(salt, x, 0)
        // is already one hash. An implementation that reads "iterations" as the
        // number of rounds performs none at all here and returns the bare name.
        var name      = DomainName.Parse("a.example.");
        var salt      = Convert.FromHexString("aabbccdd");

        var expected  = SHA1.HashData([.. CanonicalWire(name), .. salt]);

        Assert.That(NSEC3.ComputeHash(name, 0, salt), Is.EqualTo(expected),
                    "zero iterations means one hash of (name || salt), not zero hashes");

    }

    #endregion

    #region Salt_Is_Appended_On_Every_Iteration()

    [Test]
    [Property("RFC", "5155 §5")]
    public void Salt_Is_Appended_On_Every_Iteration()
    {

        // The recurrence is IH(salt, x, k) = H(IH(salt, x, k-1) || salt) — the
        // salt goes in again on each round. Salting only the first round is the
        // natural misreading, and it agrees with the correct implementation for
        // iterations = 0, so it survives any test that does not go past one round.
        var name     = DomainName.Parse("a.example.");
        var salt     = Convert.FromHexString("aabbccdd");

        var correct  = SHA1.HashData([.. SHA1.HashData([.. CanonicalWire(name), .. salt]), .. salt]);
        var salted0  = SHA1.HashData(SHA1.HashData([.. CanonicalWire(name), .. salt]));

        Assert.Multiple(() => {

            Assert.That(NSEC3.ComputeHash(name, 1, salt), Is.EqualTo(correct),
                        "round two hashes the previous digest with the salt appended again");

            Assert.That(NSEC3.ComputeHash(name, 1, salt), Is.Not.EqualTo(salted0),
                        "a salt applied only to the first round would produce this instead — " +
                        "the premise of the test, asserted so a future regression cannot look like a test bug");

        });

    }

    #endregion

    #region Empty_Salt_Is_Not_The_Same_As_No_Hashing()

    [Test]
    [Property("RFC", "5155 §5")]
    public void Empty_Salt_Is_Not_The_Same_As_No_Hashing()
    {

        var name = DomainName.Parse("a.example.");

        Assert.That(NSEC3.ComputeHash(name, 0, []),
                    Is.EqualTo(SHA1.HashData(CanonicalWire(name))),
                    "an empty salt appends nothing, but the name is still hashed");

    }

    #endregion

    #region Hash_Is_Of_The_Canonical_Wire_Form_Not_The_Presentation_Text()

    [Test]
    [Property("RFC", "5155 §5")]
    public void Hash_Is_Of_The_Canonical_Wire_Form_Not_The_Presentation_Text()
    {

        var name = DomainName.Parse("A.ExAmPlE.");

        Assert.Multiple(() => {

            // Length-prefixed labels, not the dotted string: hashing the text
            // would be a different value entirely.
            Assert.That(NSEC3.ComputeHash(name, 0, []),
                        Is.Not.EqualTo(SHA1.HashData(Encoding.ASCII.GetBytes("a.example."))),
                        "the input is wire format, not presentation format");

            // RFC 4034 §6.2 lowercases the canonical form, so case cannot change
            // which NSEC3 record covers a name.
            Assert.That(NSEC3.ComputeHash(name,                              Rfc5155Iterations, Rfc5155Salt),
                        Is.EqualTo(NSEC3.ComputeHash(DomainName.Parse("a.example."), Rfc5155Iterations, Rfc5155Salt)),
                        "names differing only in case must hash alike");

        });

    }

    #endregion

    #region Hashed_Owner_Name_Is_The_Hash_Label_Under_The_Zone()

    [Test]
    [Property("RFC", "5155 §1.3")]
    public void Hashed_Owner_Name_Is_The_Hash_Label_Under_The_Zone()
    {

        var owner = NSEC3.ComputeHashedOwnerName(DomainName.Parse("a.example."),
                                                 DomainName.Parse("example."),
                                                 Rfc5155Iterations,
                                                 Rfc5155Salt);

        Assert.That(owner.FullName.ToLowerInvariant().TrimEnd('.'),
                    Is.EqualTo("35mthgpgcu1qg68fab165klnsnk3dpvl.example"),
                    "the hash becomes a single leftmost label, and the zone follows it");

    }

    #endregion

    #region Base32Hex_Preserves_The_Ordering_Of_The_Bytes_It_Encodes()

    [Test]
    [Property("RFC", "5155 §1.3")]
    public void Base32Hex_Preserves_The_Ordering_Of_The_Bytes_It_Encodes()
    {

        // This is why RFC 5155 §1.3 specifies Base32hex rather than ordinary
        // Base32: the NSEC3 chain is ordered by hash, and the proof of
        // non-existence is "your hash sorts between these two owner names".
        // An alphabet that did not preserve order would break that argument.
        var lower = new Byte[] { 0x00, 0x11, 0x22 };
        var upper = new Byte[] { 0x00, 0x11, 0x23 };

        Assert.That(String.CompareOrdinal(NSEC3.Base32HexEncode(lower),
                                          NSEC3.Base32HexEncode(upper)), Is.LessThan(0),
                    "byte order and encoded order must agree");

    }

    #endregion

    #region Base32Hex_Round_Trips()

    [Test]
    public void Base32Hex_Round_Trips()
    {

        var hash = NSEC3.ComputeHash(DomainName.Parse("a.example."), Rfc5155Iterations, Rfc5155Salt);

        Assert.Multiple(() => {

            Assert.That(NSEC3.Base32HexDecode(NSEC3.Base32HexEncode(hash)), Is.EqualTo(hash));

            // A hashed owner name arrives as a domain label, and RFC 4343 makes
            // those case-insensitive, so decoding must not depend on the case.
            Assert.That(NSEC3.Base32HexDecode(NSEC3.Base32HexEncode(hash).ToLowerInvariant()),
                        Is.EqualTo(hash));

            Assert.That(NSEC3.Base32HexEncode(hash), Has.Length.EqualTo(32),
                        "160 bits divide into exactly 32 base-32 characters, so no padding is ever needed");

        });

    }

    #endregion

    #region Only_Sha1_Is_Accepted()

    [Test]
    [Property("RFC", "5155 §5")]
    public void Only_Sha1_Is_Accepted()
    {

        // IANA's "DNSSEC NSEC3 Hash Algorithms" registry has exactly one entry.
        // Guessing at an unassigned number would be worse than refusing: it
        // would produce hashes that no signer agrees with.
        Assert.That(() => NSEC3.ComputeHash(DomainName.Parse("a.example."), 0, [], HashAlgorithm: 2),
                    Throws.TypeOf<NotSupportedException>());

    }

    #endregion


    #region (private static) Helpers

    /// <summary>
    /// The canonical wire form of a name, built here rather than taken from
    /// Hermod, so the expected values in this fixture do not come from the code
    /// under test.
    /// </summary>
    private static Byte[] CanonicalWire(DomainName Name)
    {

        var stream = new MemoryStream();

        foreach (var label in Name.FullName.ToLowerInvariant().TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((Byte) bytes.Length);
            stream.Write(bytes);
        }

        stream.WriteByte(0x00);

        return stream.ToArray();

    }

    #endregion

}

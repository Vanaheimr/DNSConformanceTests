using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4034 §6 — the two helpers that put a signature's inputs in order.
///
/// <para>
/// Both are public, both are pure, and neither had a test of its own: they are
/// reached only through a signature that verifies or does not, which says nothing
/// about *why*. The cases below are the ones a signer never produces and a
/// round trip therefore never exercises.
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "4034 §6")]
public class CanonicalFormTests
{

    #region The_Root_Apex_And_The_Roots_Wildcard_Both_Carry_Labels_Zero()

    /// <summary>
    /// RFC 4034 §3.1.3 counts the labels of the original owner name "not counting
    /// the null label for the root and not counting any leading asterisk label",
    /// and RFC 4035 §5.3.2 reconstructs the signed name from that count. Two
    /// different names come out of the count as **zero**, and they must not be
    /// reconstructed the same way:
    ///
    /// <list type="bullet">
    ///   <item>the root apex itself, whose owner name has no labels to count</item>
    ///   <item>
    ///     a name synthesised from the root zone's own wildcard <c>*.</c>, whose
    ///     asterisk is the one label there was and is not counted
    ///   </item>
    /// </list>
    ///
    /// <para>
    /// The first is signed under its own name; the second under <c>*.</c>. A
    /// reconstruction that took the root apex for a wildcard expansion, or a
    /// one-label name for the root, would hand the verifier octets the signer
    /// never hashed — and would do it only for the root zone, which is the one
    /// zone every validator has an anchor for.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4035 §5.3.2")]
    public void The_Root_Apex_And_The_Roots_Wildcard_Both_Carry_Labels_Zero()
    {

        Assert.Multiple(() => {

            Assert.That(DNSSECCanonical.SignedOwnerName(".", 0),
                        Is.EqualTo("."),
                        "the root apex has no labels to count and is not a wildcard expansion");

            Assert.That(DNSSECCanonical.SignedOwnerName("com.", 0),
                        Is.EqualTo("*."),
                        "a one-label name with a count of zero was synthesised from the root's wildcard");

        });

    }

    #endregion

    #region A_Prefix_Sorts_Before_What_Extends_It()

    /// <summary>
    /// RFC 4034 §6.3 orders an RRset by its RDATA, "treating the RDATA as a
    /// left-justified unsigned octet sequence" — so where one RDATA is a prefix
    /// of another, the shorter comes first, and two identical ones are equal.
    ///
    /// <para>
    /// Those are exactly the two inputs on which the comparison runs out of
    /// octets to look at rather than returning early, and they are the two a
    /// signer's own output rarely contains: RRsets of records that differ
    /// somewhere in the middle return long before the end. A comparison whose
    /// loop ran one step past the shorter length would read off the end of the
    /// array on precisely these, and nowhere else.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4034 §6.3")]
    public void A_Prefix_Sorts_Before_What_Extends_It()
    {

        Assert.Multiple(() => {

            Assert.That(DNSSECCanonical.Compare([1, 2, 3], [1, 2, 3, 4]), Is.LessThan(0),
                        "the shorter of two, where one is a prefix of the other");

            Assert.That(DNSSECCanonical.Compare([1, 2, 3, 4], [1, 2, 3]), Is.GreaterThan(0),
                        "and the same the other way round");

            Assert.That(DNSSECCanonical.Compare([1, 2, 3], [1, 2, 3]), Is.Zero,
                        "two identical sequences are equal, and getting there means reading them whole");

            Assert.That(DNSSECCanonical.Compare([], []), Is.Zero,
                        "including when there is nothing to read at all");

        });

    }

    #endregion

}

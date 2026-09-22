using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// The set of trust anchors a validator was configured with: how it is managed,
/// and what it is taken to cover.
///
/// <para>
/// Everything else about anchors in this suite goes through
/// <see cref="DNSSECValidator.ProbeForTrustAnchorUpdatesAsync"/>, which is RFC
/// 5011's automatic half. The manual half is two lines of public API and one
/// private predicate, and between them they decide whether a name is inside the
/// island of trust at all.
/// </para>
///
/// <para>
/// That decision is what turns a missing signature into a verdict. RFC 4035 §4.3
/// separates Bogus from Insecure, and the separation is not about the answer: it
/// is about whether the resolver had grounds to expect a signature. An answer
/// with no proof from a zone under an anchor is what stripping the records looks
/// like; the same answer from outside every anchor is an unsigned zone going
/// about its business.
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "4035 §4.3")]
public class TrustAnchorSetTests
{

    #region Data

    private const Byte RSASHA256 = 8;

    private static readonly DNSServerConfig Origin = new(IPv4Address.Localhost, IPPort.DNS);

    private static DS Anchor(String Owner, UInt16 KeyTag, Byte Algorithm = RSASHA256)
        => new (DomainName.ParseLenient(Owner),
                DNSQueryClasses.IN,
                TimeSpan.FromDays(1),
                KeyTag,
                Algorithm,
                2,
                new Byte[32]);

    /// <summary>
    /// An answer carrying nothing at all: no records, no signatures, no proof.
    /// It is the shape a stripped negative answer arrives in, and the shape an
    /// unsigned zone's negative answer arrives in — the two are the same message
    /// and only the anchor set tells them apart.
    /// </summary>
    private static DNSInfo NothingAtAll()
        => new (Origin, 0, true, false, true, false, DNSResponseCodes.NameError,
                [], [], [], true, false, TimeSpan.FromSeconds(5), TimeSpan.Zero);

    private static async Task<DNSSECValidationResult> VerdictFor(String QName, params DS[] Anchors)
        => await new DNSSECValidator(new StubDnsClient(), [.. Anchors]).
                     ValidateAsync(NothingAtAll(),
                                   (DomainName.ParseLenient(QName), DNSResourceRecordTypes.A));

    #endregion


    #region An_Anchor_Is_Removed_By_Tag_And_Algorithm_Together()

    /// <summary>
    /// RFC 4034 §5.1 says the key tag "is not a unique identifier", which is why
    /// every lookup in this library matches on tag *and* algorithm. The public
    /// removal API is the one place a caller can ask for that match by hand, and
    /// it has to mean the same thing there.
    ///
    /// <para>
    /// Two anchors of the same algorithm, distinguished only by their tags: a
    /// removal that matched on either half would take both, which for a resolver
    /// holding the root's current and incoming keys is the whole trust store gone
    /// on one call meant to retire one key.
    /// </para>
    /// </summary>
    [Test]
    [Property("RFC", "4034 §5.1")]
    public void An_Anchor_Is_Removed_By_Tag_And_Algorithm_Together()
    {

        var validator = new DNSSECValidator(new StubDnsClient());

        validator.AddTrustAnchor(Anchor(".", 111));
        validator.AddTrustAnchor(Anchor(".", 222));

        Assert.Multiple(() => {

            Assert.That(validator.RemoveTrustAnchor(111, RSASHA256), Is.True,
                        "the anchor was there and is gone");

            Assert.That(validator.TrustAnchors.Select(anchor => anchor.KeyTag),
                        Is.EqualTo(new UInt16[] { 222 }).AsCollection,
                        "and the one that shares its algorithm is untouched");

        });

    }

    #endregion

    #region Removing_An_Anchor_That_Is_Not_There_Says_So()

    /// <summary>
    /// The return value is the whole of what the call tells a caller, and a
    /// caller writing its trust store out when told something changed needs it to
    /// be true. Reporting success for a removal that matched nothing is the same
    /// error as the probe reporting a change it did not make, one API along.
    /// </summary>
    [Test]
    public void Removing_An_Anchor_That_Is_Not_There_Says_So()
    {

        var validator = new DNSSECValidator(new StubDnsClient());

        validator.AddTrustAnchor(Anchor(".", 111));

        Assert.Multiple(() => {

            Assert.That(validator.RemoveTrustAnchor(999, RSASHA256), Is.False,
                        "no anchor carries that tag");

            Assert.That(validator.RemoveTrustAnchor(111, 13), Is.False,
                        "and none carries that algorithm");

            Assert.That(validator.TrustAnchors, Has.Count.EqualTo(1),
                        "so nothing was removed either time");

        });

    }

    #endregion

    #region Whether_A_Missing_Proof_Is_A_Forgery_Depends_On_The_Anchors()

    /// <summary>
    /// The same empty answer, three anchor sets, and the verdict RFC 4035 §4.3
    /// asks for in each.
    ///
    /// <list type="bullet">
    ///   <item>
    ///     A <b>root anchor</b> covers everything there is, which is the case
    ///     that matters most: it is the anchor a resolver actually ships with.
    ///     An empty name is not a name that fails to match — it is the one that
    ///     matches all of them.
    ///   </item>
    ///   <item>
    ///     An anchor <b>at the queried name itself</b> covers it. "At or above"
    ///     includes "at", and a validator that only looked for a strict suffix
    ///     would stop trusting the very zone it was given an anchor for.
    ///   </item>
    ///   <item>
    ///     An anchor <b>somewhere else entirely</b> covers nothing here, and the
    ///     answer is an unsigned zone rather than a stripped one.
    ///   </item>
    /// </list>
    /// </summary>
    [Test]
    public async Task Whether_A_Missing_Proof_Is_A_Forgery_Depends_On_The_Anchors()
    {

        Assert.Multiple(async () => {

            Assert.That(await VerdictFor("q.example.", Anchor(".", 1)),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "the root anchor covers every name, so a proof was owed");

            Assert.That(await VerdictFor("q.example.", Anchor("q.example.", 2)),
                        Is.EqualTo(DNSSECValidationResult.Bogus),
                        "an anchor at the name itself covers it — at or above, not only above");

            Assert.That(await VerdictFor("q.example.", Anchor("elsewhere.test.", 3)),
                        Is.EqualTo(DNSSECValidationResult.Insecure),
                        "and an anchor over some other zone says nothing about this one");

        });

    }

    #endregion

}

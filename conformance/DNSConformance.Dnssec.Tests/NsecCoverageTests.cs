using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 4034 §4.1.3 and RFC 4035 §5.4 — the span an NSEC record covers, and what
/// sits at each end of it.
///
/// <para>
/// An NSEC says "between my owner name and my next name there is nothing". The
/// two names at the ends of that sentence are the part worth testing: they both
/// exist — they are owner names in the chain — so the span is *open*, and a
/// validator that closed either end would accept a proof that a name is absent
/// when the zone said it is present. RFC 4035 §5.4 turns that into an NXDOMAIN a
/// resolver caches.
/// </para>
///
/// <para>
/// The chains here are built by hand rather than taken from a signed zone,
/// because a signer will never produce the shapes that matter: a span whose ends
/// are the interesting ones, a chain of one record, and a query landing exactly
/// on a boundary. <see cref="DenialOfExistenceTests"/> covers the ordinary case
/// against BIND's own output; this covers the edges of the arithmetic.
/// </para>
/// </summary>
[TestFixture]
[Property("RFC", "4034 §4.1.3")]
public class NsecCoverageTests
{

    #region Data

    /// <summary>An NSEC with an empty type bitmap — only its span is of interest here.</summary>
    private static NSEC Nsec(String Owner, String Next)
        => new (DomainName.Parse(Owner),
                DNSQueryClasses.IN,
                TimeSpan.FromHours(1),
                DomainName.Parse(Next),
                []);

    /// <summary>
    /// A three-name zone: the apex, "b" and "d". In canonical order (RFC 4034
    /// §6.1) that is example. &lt; b.example. &lt; d.example., and the last record
    /// wraps back to the apex.
    ///
    /// The apex record is what denies the wildcard: "*" is 0x2A, which sorts
    /// below every letter, so *.example. falls inside the apex's span.
    /// </summary>
    private static NSEC[] Chain()
        => [
               Nsec("example.",   "b.example."),
               Nsec("b.example.", "d.example."),
               Nsec("d.example.", "example.")
           ];

    private static DenialOfExistence Verify(String QName, params NSEC[] Records)
        => DenialOfExistenceValidator.Verify(
               DomainName.Parse(QName),
               DNSResourceRecordTypes.A,
               Records
           );

    #endregion


    #region A_Name_Inside_A_Span_Is_Denied()

    /// <summary>
    /// The control. "c" falls between "b" and "d", the wildcard falls inside the
    /// apex's span, and RFC 4035 §5.4 wants both before it will call a name
    /// absent.
    /// </summary>
    [Test]
    [Property("RFC", "4035 §5.4")]
    public void A_Name_Inside_A_Span_Is_Denied()
    {

        Assert.That(Verify("c.example.", Chain()),
                    Is.EqualTo(DenialOfExistence.NameDoesNotExist));

    }

    #endregion

    #region An_Nsec_Does_Not_Deny_Its_Own_Next_Name()

    /// <summary>
    /// The next name is the next owner in the chain: it exists, by construction.
    /// An NSEC whose span reached it would be proof that a name the zone lists is
    /// missing — which is exactly the proof an attacker wants for a name they
    /// want removed from the answer.
    ///
    /// The record owning "d" is left out of the set, so nothing here says "d
    /// exists" except the record pointing at it.
    /// </summary>
    [Test]
    public void An_Nsec_Does_Not_Deny_Its_Own_Next_Name()
    {

        var withoutD = new[] { Nsec("example.", "b.example."),
                               Nsec("b.example.", "d.example.") };

        Assert.That(Verify("d.example.", withoutD),
                    Is.EqualTo(DenialOfExistence.NotProven),
                    "the span stops short of the name it points at");

    }

    #endregion

    #region An_Nsec_Does_Not_Deny_A_Name_Past_Its_Span()

    /// <summary>
    /// Both ends have to hold at once. A name above the owner *and* above the
    /// next is outside the span, and a validator that wanted only one of the two
    /// would let the first record of a zone deny everything after it.
    /// </summary>
    [Test]
    public void An_Nsec_Does_Not_Deny_A_Name_Past_Its_Span()
    {

        var noWrap = new[] { Nsec("example.",   "b.example."),
                             Nsec("b.example.", "d.example.") };

        Assert.That(Verify("z.example.", noWrap),
                    Is.EqualTo(DenialOfExistence.NotProven),
                    "z is above both ends of every span here, so no span contains it");

    }

    #endregion

    #region The_Last_Nsec_Of_A_Zone_Wraps_Past_The_End()

    /// <summary>
    /// RFC 4034 §4.1.3: "The value of the Next Domain Name field in the last NSEC
    /// record in the zone is the name of the zone apex." That record's span runs
    /// off the end of the ordering and back to the beginning, so for it — and only
    /// for it — a name qualifies by being above the owner *or* below the next.
    ///
    /// Treating that one record like the others is how a zone stops being able to
    /// deny anything sorting after its last name.
    /// </summary>
    [Test]
    [Property("RFC", "4034 §4.1.3")]
    public void The_Last_Nsec_Of_A_Zone_Wraps_Past_The_End()
    {

        Assert.That(Verify("z.example.", Chain()),
                    Is.EqualTo(DenialOfExistence.NameDoesNotExist),
                    "z sorts after the zone's last name, which is what the wrapping record is for");

    }

    #endregion

    #region A_Chain_Of_One_Record_Wraps_Onto_Itself()

    /// <summary>
    /// A zone with nothing in it but its apex has one NSEC, and that record's
    /// next name is its own owner. Owner and next being equal is still a wrap —
    /// the span is the whole ordering minus the single name that exists — and a
    /// validator that read equality as "no wrap" would find the span empty and
    /// deny nothing at all.
    /// </summary>
    [Test]
    [Property("RFC", "4034 §4.1.3")]
    public void A_Chain_Of_One_Record_Wraps_Onto_Itself()
    {

        var alone = new[] { Nsec("example.", "example.") };

        Assert.That(Verify("anything.example.", alone),
                    Is.EqualTo(DenialOfExistence.NameDoesNotExist),
                    "one record whose next name is its own owner covers everything else");

    }

    #endregion

}

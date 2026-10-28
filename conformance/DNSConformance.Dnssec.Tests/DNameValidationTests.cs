using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.Dnssec.Tests;

/// <summary>
/// RFC 6672 §5.3.1 from the validator's side: a CNAME that comes with no
/// signature of its own, and the signed DNAME that has to account for it.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="SignedDNameServingTests"/> holds the server to sending the
/// synthesized CNAME unsigned. This is the other half: a validator handed that
/// answer has to accept the CNAME without a signature, and has to accept it for
/// no other reason than that the DNAME beside it produces it. §5.3.1: "For a
/// DNSSEC validator, verification of the DNAME RR and then that the CNAME was
/// properly synthesized is sufficient proof."
/// </para>
/// <para>
/// Both halves of that sentence are checks, and a validator that drops the
/// second one has handed every attacker a way through. The CNAME is the record
/// an attacker would rewrite, because it is the only one nothing signed —
/// §5.3.4's own example alters it to point at <c>bla.bla.example</c> — and the
/// signed DNAME it leans on is in every answer from the zone, free for anyone
/// to copy into a forged one.
/// </para>
/// <para>
/// The zone is BIND's <c>dname.dnssec.test</c>, whose
/// <c>redirect.dname.dnssec.test. DNAME target.dname.dnssec.test.</c> and
/// <c>host.target.dname.dnssec.test. A</c> are signed by dnssec-signzone. Every
/// CNAME here is written out by hand, because a synthesized CNAME is never
/// signed and a forged one is the point.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "6672 §5.3.1")]
public class DNameValidationTests
{

    private const String Origin    = "dname.dnssec.test";
    private const String Owner     = "redirect.dname.dnssec.test";
    private const String Target    = "target.dname.dnssec.test";

    private SignedZoneFixture zone = null!;


    [OneTimeSetUp]
    public void LoadFixture()
    {

        if (!SignedZoneFixture.IsAvailableFor(Origin))
            Assert.Ignore($"The signed fixture for {Origin} is missing — regenerate with: wsl -e sh fixtures/zones/resign.sh");

        zone = SignedZoneFixture.Load(Origin);

    }


    #region Helpers

    private static readonly DNSServerConfig Server = new(IPv4Address.Localhost, IPPort.DNS);

    /// <summary>
    /// A response carrying the given records in its answer section.
    /// </summary>
    private static DNSInfo ResponseWith(params IDNSResourceRecord[] Answers)

        => new(
               Server,
               0,
               true, false, true, false,
               DNSResponseCodes.NoError,
               Answers,
               [],
               [],
               true,
               false,
               TimeSpan.FromSeconds(5),
               TimeSpan.Zero
           );


    /// <summary>
    /// A validator anchored at the fixture zone, with a resolver that serves the
    /// zone's key set and the signatures over it — and nothing else. Every
    /// signature in these answers is the zone's own, so the anchor is all the
    /// chain there is, and the DNAME and the CNAME are all a verdict can turn on.
    /// </summary>
    private DNSSECValidator Validator()

        => new(new StubDnsClient().Answer(Origin, DNSResourceRecordTypes.DNSKEY, zone.KeySetAnswer),
               [ zone.DelegationSigner ]);


    /// <summary>
    /// The signed RRset of the fixture zone at the given owner, with its RRSIG.
    /// </summary>
    private IDNSResourceRecord[] Signed(String Owner, DNSResourceRecordTypes Type)
    {

        var rrset     = zone.RRset(Owner, Type);
        var signature = zone.SignatureFor(Owner, Type);

        Assert.That(rrset,     Is.Not.Empty, $"{Owner} {Type} is in the fixture");
        Assert.That(signature, Is.Not.Null,  $"and signed");

        return [ .. rrset, signature! ];

    }


    /// <summary>
    /// The signed DNAME at <c>redirect.dname.dnssec.test.</c>, exactly as the
    /// zone holds it — what an attacker can copy from any answer the zone gives.
    /// </summary>
    private IDNSResourceRecord[] SignedDName
        => Signed(Owner, DNSResourceRecordTypes.DNAME);


    /// <summary>
    /// An unsigned CNAME, with the DNAME's TTL as RFC 6672 §3.1 gives it.
    /// </summary>
    private static CNAME CName(String Owner, String Target)
        => new(DomainName.Parse(Owner), DNSQueryClasses.IN, TimeSpan.FromHours(1), DomainName.Parse(Target));

    #endregion


    #region A_Cname_Synthesized_From_A_Signed_Dname_Needs_No_Signature()

    /// <summary>
    /// RFC 6672 §5.3.1, the answer a server gives for
    /// <c>host.redirect.dname.dnssec.test. A</c>: the signed DNAME, the CNAME it
    /// produces, and the signed A RRset at the CNAME's target. The CNAME "will
    /// never be signed", and the answer is Secure all the same.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The substitution is RFC 6672 §2.2's: the labels of the name that match the
    /// DNAME's owner are replaced by its target, so <c>host</c> in front of
    /// <c>redirect.dname.dnssec.test</c> becomes <c>host</c> in front of
    /// <c>target.dname.dnssec.test</c>. A validator that computes anything else
    /// — that keeps the owner's labels, or drops the leading ones, or never
    /// looks — finds the CNAME unexplained, and a CNAME without a signature in a
    /// signed zone is a stripped one.
    /// </para>
    /// <para>
    /// Without this answer a validator could refuse every DNAME redirection
    /// there is, and every test below would still pass.
    /// </para>
    /// </remarks>
    [Test]
    public async Task A_Cname_Synthesized_From_A_Signed_Dname_Needs_No_Signature()
    {

        var response = ResponseWith([ .. SignedDName,
                                      CName("host." + Owner, "host." + Target),
                                      .. Signed("host." + Target, DNSResourceRecordTypes.A) ]);

        Assert.That(await Validator().ValidateAsync(response),
                    Is.EqualTo(DNSSECValidationResult.Secure),
                    "the DNAME verifies, and the CNAME is the one it produces");

    }

    #endregion

    #region A_Cname_The_Dname_Does_Not_Produce_Is_Bogus()

    /// <summary>
    /// RFC 6672 §5.3.4's own attack: the same answer with the CNAME rewritten
    /// to point elsewhere. "It could be altered by an attacker to be
    /// foo.bar.example.com CNAME bla.bla.example."
    /// </summary>
    /// <remarks>
    /// The DNAME is untouched and still verifies. What it no longer does is
    /// explain the CNAME beside it, and an unsigned CNAME at a name of a signed
    /// zone that nothing explains is one whose signature is missing.
    /// </remarks>
    [Test]
    [Property("RFC", "6672 §5.3.4")]
    public async Task A_Cname_The_Dname_Does_Not_Produce_Is_Bogus()
    {

        var response = ResponseWith([ .. SignedDName,
                                      CName("host." + Owner, "bla.bla.example") ]);

        Assert.That(await Validator().ValidateAsync(response),
                    Is.EqualTo(DNSSECValidationResult.Bogus),
                    "a genuine DNAME does not vouch for a CNAME it would not have produced");

    }

    #endregion

    #region A_Cname_At_The_Dnames_Own_Name_Is_Not_Synthesized()

    /// <summary>
    /// RFC 6672 §2.3: a DNAME "redirects DNS names subordinate to its owner
    /// name; the owner name of a DNAME is not redirected itself." Table 1 of
    /// §2.2 has the row: QNAME <c>example.com.</c>, DNAME owner
    /// <c>example.com.</c>, no match. So a CNAME at
    /// <c>redirect.dname.dnssec.test.</c> cannot have come from the DNAME there,
    /// and is Bogus however much it looks like it did.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The CNAME points at the DNAME's target, which is what a substitution
    /// would yield if it took the whole owner name as the part to replace. That
    /// is the one target a careless check is most likely to accept, and the
    /// same section leaves no doubt that the record is wrong whatever it points
    /// at: the owner of a DNAME may hold other types, "except DNAMEs, CNAMEs, or
    /// other types that have restrictions on what they can coexist with."
    /// </para>
    /// <para>
    /// It is also the place where the substitution, run anyway, has no labels
    /// left to keep. A validator that gets that far has to answer Bogus rather
    /// than fail on its own arithmetic.
    /// </para>
    /// </remarks>
    [Test]
    [Property("RFC", "6672 §2.3")]
    public async Task A_Cname_At_The_Dnames_Own_Name_Is_Not_Synthesized()
    {

        var response = ResponseWith([ .. SignedDName,
                                      CName(Owner, Target) ]);

        Assert.That(await Validator().ValidateAsync(response),
                    Is.EqualTo(DNSSECValidationResult.Bogus),
                    "a DNAME produces no CNAME at its own owner name");

    }

    #endregion

    #region A_Cname_Across_A_Label_Boundary_Is_Not_Synthesized()

    /// <summary>
    /// RFC 6672 §2.2: "Only whole labels are replaced." Table 1 has the row:
    /// QNAME <c>ab.example.com.</c>, DNAME owner <c>b.example.com.</c>, no
    /// match. <c>abredirect.dname.dnssec.test.</c> ends in the characters of
    /// the DNAME's owner name and is not below it.
    /// </summary>
    /// <remarks>
    /// The forged CNAME points at <c>a.target.dname.dnssec.test.</c> — the name a
    /// validator arrives at when it cuts the owner's length off the end of the
    /// string and takes the character in front of it to be the dot between two
    /// labels. Pointing anywhere else, the forgery would fail the comparison of
    /// targets and say nothing about whether the boundary was checked.
    /// </remarks>
    [Test]
    [Property("RFC", "6672 §2.2")]
    public async Task A_Cname_Across_A_Label_Boundary_Is_Not_Synthesized()
    {

        var response = ResponseWith([ .. SignedDName,
                                      CName("ab" + Owner, "a." + Target) ]);

        Assert.That(await Validator().ValidateAsync(response),
                    Is.EqualTo(DNSSECValidationResult.Bogus),
                    "abredirect is not a name below redirect");

    }

    #endregion

}

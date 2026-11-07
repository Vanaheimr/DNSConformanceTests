using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Client.Tests;

/// <summary>
/// What the cache hands out for one name and one type: the RRset asked for, its
/// signatures, and the aliases that lead to it - and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="CachedAnswerTests"/> asks this through the wire, with a name that
/// owns its records. A name reached through an alias is the other half of the
/// same rule, and it is where the cache has to decide what belongs to the
/// answer: RFC 1034 §3.6.2 has a name server include the CNAME record in the
/// response and restart "the query at the domain name specified in the data
/// field of the CNAME record", so the answer for an alias is the CNAME, then the
/// RRset at its target. RFC 4035 §3.1.1 puts a signed RRset's RRSIGs beside it
/// in the same section, and RFC 6672 §5.3.1 says a CNAME synthesized from a
/// DNAME "will never be signed": the DNAME and its RRSIG are what a validator
/// checks it by.
/// </para>
/// <para>
/// So the cache is driven directly here, as in <see cref="CacheBoundaryTests"/>,
/// with responses the test builds: a validator reads what comes back, and the
/// RRSIG of a link it is not given is a link it cannot verify, while a DNAME it
/// is given that leads somewhere else is a redirection nobody sent for this name.
/// </para>
/// </remarks>
[TestFixture]
public class CachedAliasChainTests
{

    #region Data

    private static readonly TimeSpan Hour = TimeSpan.FromHours(1);

    private static DNSCache UnsweptCache()
        => new (CleanUpEvery: TimeSpan.FromHours(1));


    private static DNSInfo Response(params IDNSResourceRecord[] Answers)

        => new (Origin:                 new DNSServerConfig(IPv4Address.Localhost, IPPort.DNS),
                QueryId:                0,
                IsAuthoritativeAnswer:  false,
                IsTruncated:            false,
                RecursionDesired:       true,
                RecursionAvailable:     true,
                ResponseCode:           DNSResponseCodes.NoError,
                Answers:                Answers,
                Authorities:            [],
                AdditionalRecords:      [],
                IsValid:                true,
                IsTimeout:              false,
                Timeout:                TimeSpan.Zero,
                Runtime:                TimeSpan.Zero);


    private static A Address(String Owner, String IPv4, TimeSpan? TimeToLive = null)
        => new (DomainName.Parse(Owner), DNSQueryClasses.IN, TimeToLive ?? Hour, IPv4Address.Parse(IPv4));

    private static CNAME Cname(String Owner, String Target, TimeSpan? TimeToLive = null)
        => new (DomainName.Parse(Owner), DNSQueryClasses.IN, TimeToLive ?? Hour, DomainName.Parse(Target));

    private static DNAME Dname(String Owner, String Target)
        => new (DomainName.Parse(Owner), DNSQueryClasses.IN, Hour, DomainName.Parse(Target));


    /// <summary>
    /// A signature over the given type at the given owner. Nothing here verifies
    /// it; what matters is which RRset it says it covers (RFC 4034 §3.1.1).
    /// </summary>
    private static RRSIG Signature(String Owner, DNSResourceRecordTypes Covered, String Signer)

        => new (DomainName.Parse(Owner),
                DNSQueryClasses.IN,
                Hour,
                Covered,
                13,                                     // ECDSAP256SHA256
                (Byte) DomainName.Parse(Owner).FullName.TrimEnd('.').Split('.').Length,
                3600,
                1893456000,                             // 2030-01-01
                1577836800,                             // 2020-01-01
                12345,
                DomainName.Parse(Signer),
                [ 0xde, 0xad, 0xbe, 0xef ]);


    private static readonly DNSServiceName Alias = DNSServiceName.Parse("www.alias.test.");

    #endregion


    #region Through a CNAME

    [Test]
    [Property("RFC", "1034 §3.6.2, 4035 §3.1.1")]
    public void An_Answer_Reached_Through_A_Cname_Holds_The_Cname_And_The_Rrset_With_Their_Signatures()
    {

        // The answer for www.alias.test A, as a signed zone gives it: the CNAME and
        // its RRSIG at the alias, the A RRset and its RRSIG at the canonical name.
        // Both RRSIGs are needed - one for each RRset - and nothing else is at
        // either name. A cache that finds no A at the alias and does not follow the
        // CNAME has nothing to say; one that keeps the CNAME but not its signature
        // hands a validator an alias it cannot verify.
        var cname     = Cname    ("www.alias.test.",  "host.target.test.");
        var cnameSig  = Signature("www.alias.test.",  DNSResourceRecordTypes.CNAME, "alias.test.");
        var a         = Address  ("host.target.test.", "192.0.2.31");
        var aSig      = Signature("host.target.test.", DNSResourceRecordTypes.A,     "target.test.");

        var cache     = UnsweptCache();
        cache.Add(Alias, Response(cname, cnameSig, a, aSig));

        Assert.That(cache.TryGetAnswer(Alias, DNSResourceRecordTypes.A, out var served), Is.True,
                    "§3.6.2: the CNAME at the name stands in for the A asked for, and the A is at its target");

        Assert.That(served!.Answers, Is.EquivalentTo(new IDNSResourceRecord[] { cname, cnameSig, a, aSig }),
                    "the alias and the address, each with the RRSIG that covers it (RFC 4035 §3.1.1)");

    }

    #endregion

    #region Through a DNAME

    [Test]
    [Property("RFC", "6672 §3.1, §5.3.1")]
    public void An_Answer_Reached_Through_A_Dname_Holds_The_Dname_And_Its_Signature()
    {

        // RFC 6672 §3.1: a name under the owner of a DNAME is answered with the
        // DNAME and a CNAME synthesized from it, from www.alias.test. to
        // www.target.test. here. §5.3.1: the synthesized CNAME "will never be
        // signed" - a validator checks it against the DNAME, whose RRSIG it
        // verifies instead. So the DNAME and that RRSIG belong to the answer as
        // much as the CNAME does, although neither is at the name asked for.
        var dname     = Dname    ("alias.test.",      "target.test.");
        var dnameSig  = Signature("alias.test.",      DNSResourceRecordTypes.DNAME, "alias.test.");
        var cname     = Cname    ("www.alias.test.",  "www.target.test.");
        var a         = Address  ("www.target.test.", "192.0.2.32");
        var aSig      = Signature("www.target.test.", DNSResourceRecordTypes.A,     "target.test.");

        var cache     = UnsweptCache();
        cache.Add(Alias, Response(dname, dnameSig, cname, a, aSig));

        Assert.That(cache.TryGetAnswer(Alias, DNSResourceRecordTypes.A, out var served), Is.True,
                    "the synthesized CNAME leads to the A as any other would");

        Assert.That(served!.Answers, Is.EquivalentTo(new IDNSResourceRecord[] { dname, dnameSig, cname, a, aSig }),
                    "§5.3.1: the unsigned CNAME together with the DNAME it was synthesized from and that DNAME's RRSIG");

    }


    [Test]
    [Property("RFC", "6672 §2.4, §3.1")]
    public void A_Dname_That_Does_Not_Lead_To_The_Cnames_Target_Is_Not_Part_Of_The_Answer()
    {

        // The control for the test above, from the other side. The response holds a
        // second DNAME, at alias.test.'s parent, which would rewrite the name to
        // somewhere else entirely, and a DNAME at an unrelated owner. No server that
        // keeps RFC 6672 §2.4 sends the first - "Resource records MUST NOT exist at
        // any subdomain of the owner of a DNAME RR", and alias.test. is one of
        // test.'s - but a response is not the zone, and what the cache does with a record
        // it was handed is the cache's own decision. Only the DNAME the CNAME was
        // synthesized from leads to the answer. Handed out beside it, the other two
        // are a second redirection of the same name for whatever reads the answer
        // next, and nothing in the answer says which one to believe.
        var dname     = Dname    ("alias.test.",      "target.test.");
        var dnameSig  = Signature("alias.test.",      DNSResourceRecordTypes.DNAME, "alias.test.");
        var cname     = Cname    ("www.alias.test.",  "www.target.test.");
        var a         = Address  ("www.target.test.", "192.0.2.33");

        var elsewhere = Dname    ("test.",            "elsewhere.example.");
        var unrelated = Dname    ("other.example.",   "target.test.");

        var cache     = UnsweptCache();
        cache.Add(Alias, Response(dname, dnameSig, elsewhere, unrelated, cname, a));

        Assert.That(cache.TryGetAnswer(Alias, DNSResourceRecordTypes.A, out var served), Is.True);

        Assert.Multiple(() => {

            Assert.That(served!.Answers, Does.Not.Contain(elsewhere),
                        "a DNAME that rewrites the name to somewhere other than the CNAME's target did not lead here");

            Assert.That(served.Answers,  Does.Not.Contain(unrelated),
                        "nor does a DNAME whose owner the name is not under");

            Assert.That(served.Answers,  Is.EquivalentTo(new IDNSResourceRecord[] { dname, dnameSig, cname, a }),
                        "what is left is the chain that was followed");

        });

    }

    #endregion

    #region What is a miss

    [Test]
    [Property("RFC", "4035 §4.5")]
    public void An_Alias_Chain_With_An_Expired_Link_Is_A_Miss()
    {

        // RFC 4035 §4.5: the resolver "SHOULD discard the entire atomic entry when
        // any of the RRs contained in it expire". The A behind the alias has an
        // hour left; the CNAME in front of it had none. The address alone, without
        // the alias that leads to it, is not the answer for this name - the next
        // query has to ask again. CachedAnswerTests and the test above are the
        // control: the same chain with time on every link is served.
        var cache = UnsweptCache();

        cache.Add(Alias, Response(Cname("www.alias.test.",  "host.target.test.", TimeSpan.Zero),
                                  Address("host.target.test.", "192.0.2.34")));

        Assert.Multiple(() => {

            Assert.That(cache.TryGetAnswer(Alias, DNSResourceRecordTypes.A, out var served), Is.False,
                        "a chain whose CNAME has run out is not served");

            Assert.That(served, Is.Null);

        });

    }


    [Test]
    [Property("RFC", "1034 §3.6.2, §5.2.2")]
    public void An_Alias_Loop_Is_A_Miss()
    {

        // Two CNAMEs that point at each other, put into the cache record by record.
        // RFC 1034 §3.6.2 has "CNAME loops signalled as an error", and §5.2.2 says
        // "Alias loops and aliases which point to non-existent names should be
        // caught and an error condition passed back to the client". Following them
        // never reaches an A, so there is nothing to serve. Coming back round to a
        // name already visited ends the walk; what it may not do is end it with a
        // hit that has no answer in it.
        var cache = UnsweptCache();

        cache.Add(Alias,
                  Cname("www.alias.test.",  "loop.alias.test."),
                  Cname("loop.alias.test.", "www.alias.test."));

        Assert.Multiple(() => {

            Assert.That(cache.TryGetAnswer(Alias, DNSResourceRecordTypes.A, out var served), Is.False,
                        "a loop is no answer");

            Assert.That(served, Is.Null);

        });

    }


    [Test]
    [Property("RFC", "1035 §7.4")]
    public void A_Name_Nothing_Was_Cached_For_Is_A_Miss()
    {

        // The plainest miss there is, and still one with two halves: no hit, and no
        // answer handed out with it. A hit whose answer is null is worse than either
        // reading, because the caller has been told to stop asking and given nothing.
        //
        // Not asked here: whether ANY may be answered from the cache. Hermod declines
        // to, because a cache holding some RRsets of a name cannot know it holds all
        // of them. RFC 8482 §5 leaves that to the initiator - it "MAY instead respond
        // to such queries with the contents of the local cache in the usual way" - so
        // either choice conforms, and this suite holds Hermod to neither.
        var cache = UnsweptCache();
        var name  = DNSServiceName.Parse("cached.alias.test.");

        cache.Add(name, Response(Address("cached.alias.test.", "192.0.2.35")));

        Assert.Multiple(() => {

            Assert.That(cache.TryGetAnswer(name, DNSResourceRecordTypes.A, out var hit), Is.True,
                        "the control: what was cached is served");

            Assert.That(hit, Is.Not.Null);

            Assert.That(cache.TryGetAnswer(DNSServiceName.Parse("never.alias.test."), DNSResourceRecordTypes.A, out var none), Is.False,
                        "a name nothing was cached for is a miss");

            Assert.That(none, Is.Null, "and a miss hands out no answer");

        });

    }


    [Test]
    [Property("RFC", "1035 §7.4")]
    public void Records_Put_Into_The_Cache_One_By_One_Answer_For_Their_Type()
    {

        // The other way into the cache: records added by hand, with no response
        // around them - the hosts file, a preseeded name. They are their own
        // response, and the type asked for is found among them.
        var cache = UnsweptCache();
        var name  = DNSServiceName.Parse("byhand.alias.test.");
        var a     = Address("byhand.alias.test.", "192.0.2.36");

        cache.Add(name, a);

        Assert.Multiple(() => {

            Assert.That(cache.TryGetAnswer(name, DNSResourceRecordTypes.A, out var served), Is.True,
                        "an A put in by hand is the answer for A");

            Assert.That(served?.Answers, Is.EquivalentTo(new IDNSResourceRecord[] { a }));

            Assert.That(cache.TryGetAnswer(name, DNSResourceRecordTypes.MX, out _), Is.False,
                        "and not for a type nobody put in");

        });

    }

    #endregion

}

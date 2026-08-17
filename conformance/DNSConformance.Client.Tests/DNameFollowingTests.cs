using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 6672 §2.2 as a resolver has to apply it: which names a DNAME in a
/// response is allowed to rewrite.
/// </summary>
/// <remarks>
/// <para>
/// A resolver that receives a DNAME performs the substitution itself — the
/// synthesized CNAME beside it is a courtesy for resolvers that do not, and
/// cannot be signed, so a validating resolver has to re-derive the name from
/// the DNAME anyway.
/// </para>
/// <para>
/// Deriving it means matching <i>labels</i>. The substitution is defined on the
/// label sequence (§2.2: "replacing the suffix labels of the name being sought
/// matching the owner name"), and a resolver that compares the two names as
/// strings will find suffixes that are not label boundaries at all — which
/// hands a DNAME the power to rewrite names it has no relationship to.
/// </para>
/// <para>
/// The server here is scripted, so it can send exactly the answer a hostile or
/// merely broken authoritative server would, and the assertions are about what
/// the client asks for next.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "6672 §2.2")]
public class DNameFollowingTests
{

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromSeconds(10);


    #region (private) DNameOnlyServer(Owner, Target)

    /// <summary>
    /// A server that answers every query with one DNAME and nothing else — no
    /// synthesized CNAME, so the client has to do the substitution itself.
    /// </summary>
    private static ScriptedUdpServer DNameOnlyServer(String Owner, String Target)

        => new(request => RawDnsResponder.Answer(
                              request,
                              (Owner, RawDnsType.DNAME, 3600, RawDnsWriter.NameBytes(Target))
                          ));

    /// <summary>
    /// The names the client went on to ask about, in order.
    /// </summary>
    private static String[] NamesAsked(ScriptedUdpServer Server)

        => [.. Server.Requests.
                   Select(request => RawDnsReader.Parse(request).Questions[0].Name.Canonical)];

    #endregion


    #region A_Dname_Rewrites_A_Name_Below_Its_Owner()

    [Test]
    public async Task A_Dname_Rewrites_A_Name_Below_Its_Owner()
    {

        // The case that must work, so that the ones below mean something.
        await using var server = DNameOnlyServer("old.example.", "new.example.");

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  false
                           );

        _ = await client.Query(DNSServiceName.Parse("host.old.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);

        Assert.That(NamesAsked(server), Does.Contain("host.new.example"),
                    "host.old.example → host.new.example: the labels above the owner carry over");

    }

    #endregion

    #region A_Dname_Does_Not_Rewrite_A_Name_That_Merely_Ends_With_Its_Owner()

    [Test]
    public async Task A_Dname_Does_Not_Rewrite_A_Name_That_Merely_Ends_With_Its_Owner()
    {

        // "notold.example." ends with the characters of "old.example." but is not
        // subordinate to it — the boundary falls inside a label. RFC 6672 §2.2
        // substitutes "suffix labels", and there is no label suffix here to
        // substitute.
        //
        // A string comparison says otherwise, and the name it then builds is not
        // even well formed: strip "old.example." from "notold.example." and the
        // remainder is "not", which concatenated with the target gives
        // "notnew.example." — a name in somebody else's zone, reached by a
        // redirection that never authorized it.
        await using var server = DNameOnlyServer("old.example.", "new.example.");

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  false
                           );

        _ = await client.Query(DNSServiceName.Parse("notold.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);

        var asked = NamesAsked(server);

        Assert.That(asked, Does.Not.Contain("notnew.example"),
                    "a DNAME at old.example. has no say over notold.example. — the shared suffix " +
                    "is a coincidence of spelling, not a position in the tree.");

        Assert.That(asked, Has.Length.EqualTo(1),
                    () => "nothing should have been chased at all, but the client asked for: " +
                          String.Join(", ", asked));

    }

    #endregion

    #region A_Dname_Does_Not_Rewrite_Its_Own_Owner_Name()

    [Test]
    [Property("RFC", "6672 §2.3")]
    public async Task A_Dname_Does_Not_Rewrite_Its_Own_Owner_Name()
    {

        // §2.3: "the owner name of a DNAME is not redirected itself." A suffix
        // comparison makes the owner match itself with an empty prefix, and the
        // rewritten name comes out as the bare target — so the one name the RFC
        // singles out as exempt is the one that gets redirected most cleanly.
        await using var server = DNameOnlyServer("old.example.", "new.example.");

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  false
                           );

        _ = await client.Query(DNSServiceName.Parse("old.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);

        Assert.That(NamesAsked(server), Does.Not.Contain("new.example"),
                    "the DNAME's own name is not subordinate to itself");

    }

    #endregion

    #region A_Dname_Does_Not_Rewrite_A_Name_Above_Its_Owner()

    [Test]
    [Property("RFC", "6672 §2.3")]
    public async Task A_Dname_Does_Not_Rewrite_A_Name_Above_Its_Owner()
    {

        await using var server = DNameOnlyServer("sub.old.example.", "new.example.");

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  false
                           );

        _ = await client.Query(DNSServiceName.Parse("old.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);

        Assert.That(NamesAsked(server), Has.Length.EqualTo(1),
                    "a DNAME below the queried name redirects nothing");

    }

    #endregion

    #region An_Oversized_Substitution_Is_Not_Followed()

    [Test]
    [Property("RFC", "6672 §2.2")]
    [Property("RFC", "1035 §2.3.4")]
    public async Task An_Oversized_Substitution_Is_Not_Followed()
    {

        // The target is 245 octets on the wire, so a 20-character prefix label
        // takes the rewritten name past 255. RFC 6672 §2.2 has a server answer
        // YXDOMAIN rather than build it; a resolver equally has no name to ask
        // about, and must not try — nor fall over trying.
        var longTarget = new String('a', 60) + "." + new String('b', 60) + "." +
                         new String('c', 60) + "." + new String('d', 60) + ".";

        await using var server = DNameOnlyServer("old.example.", longTarget);

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  false
                           );

        Assert.That(
            async () => await client.Query(
                                  DNSServiceName.Parse(new String('x', 20) + ".old.example."),
                                  [ DNSResourceRecordTypes.A ],
                                  ShortTimeout
                              ),
            Throws.Nothing,
            "a name that cannot exist is not a reason to fail the query"
        );

        Assert.That(NamesAsked(server), Has.Length.EqualTo(1),
                    "there is no name over 255 octets to ask about");

    }

    #endregion

}

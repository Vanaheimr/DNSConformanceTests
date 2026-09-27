using System.Net.NetworkInformation;
using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// What a client is, and what it asks for, when the caller says nothing.
/// </summary>
/// <remarks>
/// <para>
/// Every default here is written twice: once as the parameter's own default on
/// the declaration, and once as the fallback the body reaches for when the
/// parameter arrives as null. The second one is unreachable while the first is a
/// non-null literal, so the only way to ask what it decides is to pass null
/// deliberately — which is why several tests below do exactly that and would
/// otherwise look like they were testing the same thing twice.
/// </para>
/// <para>
/// The rest of the suite constructs its clients with everything spelled out,
/// `UseQueryCache: false` most of all, because a test about the wire wants no
/// cache in the way. That is the right thing for those tests and it is why the
/// defaults themselves went unwatched: a default nobody takes is a default
/// nobody checks.
/// </para>
/// </remarks>
[TestFixture]
public class ClientDefaultsTests
{

    #region Data

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromMilliseconds(800);

    /// <summary>
    /// A port with nothing on it. Constructing a client makes no connection, so
    /// the tests that only read properties never need a server.
    /// </summary>
    private static readonly IPPort UnusedPort = IPPort.Parse((UInt16) 53999);


    /// <summary>
    /// A server that answers whatever it is asked with one A record at that same
    /// name, and stays silent for a query carrying no question at all — which is
    /// what one of the mutants below produces, and which would otherwise take the
    /// scripted responder down with it rather than failing an assertion.
    /// </summary>
    private static ScriptedUdpServer AnswerWhateverIsAsked()

        => new (request => {

               var questions = RawDnsReader.Parse(request).Questions;

               if (questions.Count != 1)
                   return null;

               return RawDnsResponder.Answer(
                          request,
                          ($"{questions[0].Name.Canonical}.", RawDnsType.A, 300, [192, 0, 2, 1])
                      );

           });


    /// <summary>The questions the server was asked, as "name/type" in arrival order.</summary>
    private static String[] QuestionsAsked(ScriptedUdpServer Server)
        => [.. Server.Requests.
                   Select (request  => RawDnsReader.Parse(request)).
                   Select (message  => message.Questions.Count == 1
                                           ? $"{message.Questions[0].Name.Canonical}/{message.Questions[0].Type}"
                                           : $"<{message.Questions.Count} questions>")];

    /// <summary>Whether the RD bit was set in each query the server received.</summary>
    private static Boolean[] RecursionAsked(ScriptedUdpServer Server)
        => [.. Server.Requests.Select(request => RawDnsReader.Parse(request).RD)];

    #endregion


    #region The cache is on unless it is switched off

    [Test]
    public async Task A_Client_Given_No_Opinion_Caches()
    {

        // Two identical questions, one datagram. Nothing in the DNS obliges a
        // stub resolver to keep a cache — RFC 1035 §7.4 permits one and says what
        // may go in it — so this is not a conformance rule but a promise this
        // library makes in the name of the parameter: UseQueryCache defaults to
        // true, and a caller who never mentions it gets a cache.
        //
        // It is pinned because it is the kind of default that changes by accident.
        // Every other test in this project passes `UseQueryCache: false`, so the
        // suite would have carried on green with the cache silently off.
        await using var server = AnswerWhateverIsAsked();

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:  ShortTimeout
                           );

        await client.Query(DNSServiceName.Parse("cached.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);
        await client.Query(DNSServiceName.Parse("cached.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);

        var asked = QuestionsAsked(server);

        Assert.Multiple(() => {

            Assert.That(client.UseCache, Is.True,
                        "a client that was told nothing has a cache");

            Assert.That(asked, Has.Length.EqualTo(1),
                        "and the second identical question is answered out of it");

        });

    }


    [Test]
    public async Task A_Client_Handed_A_Null_Opinion_Caches_Too()
    {

        // `UseQueryCache: null` is the only way to reach the `?? true` behind the
        // parameter. Passing it is not a thing callers do on purpose; it is what
        // happens when the value is forwarded from somewhere that had nothing to
        // say, and the answer has to be the same as saying nothing at all.
        await using var server = AnswerWhateverIsAsked();

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  null
                           );

        await client.Query(DNSServiceName.Parse("nulled.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);
        await client.Query(DNSServiceName.Parse("nulled.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);

        var asked = QuestionsAsked(server);

        Assert.Multiple(() => {
            Assert.That(client.UseCache, Is.True,  "null is not an opinion, so the default stands");
            Assert.That(asked,           Has.Length.EqualTo(1));
        });

    }


    [Test]
    public void All_Four_Constructors_Start_With_The_Cache_On()
    {

        // The same default, written out four times, one per constructor. They are
        // checked together because the failure to guard against is one of them
        // drifting away from the other three: four constructors of one class that
        // disagree about whether there is a cache is worse than any single answer.
        //
        // Read off the property rather than from behaviour, because two of these
        // constructors take no server to point at a test one could observe.
        using var oneServer     = new DNSClient(
                                      IPv4Address.Localhost,
                                      UnusedPort
                                  );

        using var manyServers   = new DNSClient(
                                      DNSServers:  new IIPAddress[] { IPv4Address.Localhost },
                                      Port:        UnusedPort
                                  );

        using var discovering   = new DNSClient(
                                      QueryTimeout:             ShortTimeout,
                                      SearchForIPv4DNSServers:  false,
                                      SearchForIPv6DNSServers:  false
                                  );

        using var manual        = new DNSClient(
                                      ManualDNSServers:  [ new DNSServerConfig(IPv4Address.Localhost, UnusedPort) ],
                                      QueryTimeout:      ShortTimeout
                                  );

        Assert.Multiple(() => {
            Assert.That(oneServer.  UseCache, Is.True, "DNSClient(address, port, ...)");
            Assert.That(manyServers.UseCache, Is.True, "DNSClient(addresses, port, ...)");
            Assert.That(discovering.UseCache, Is.True, "DNSClient(timeout, search..., ...)");
            Assert.That(manual.     UseCache, Is.True, "DNSClient(manual servers, ...)");
        });

    }

    [Test]
    public async Task Only_Force_Update_Goes_Past_The_Cache()
    {

        // ForceUpdate is the caller's way of saying "ask anyway", and the default
        // has to be the other one: a client whose every call bypassed its own
        // cache has a cache in name only, and every caller that never heard of
        // the parameter pays for it in queries somebody else's server answers.
        //
        // Five calls, and the count after each is the assertion. The fourth is the
        // interesting one: passing null explicitly is the only way to reach the
        // `?? false` behind the parameter, and it has to mean the same as leaving
        // the parameter out — a forwarded nothing is not a request to ask again.
        await using var server = AnswerWhateverIsAsked();

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  true
                           );

        var name = DNSServiceName.Parse("forced.example.");

        await client.Query(name, [ DNSResourceRecordTypes.A ], ShortTimeout);
        var afterFirst   = QuestionsAsked(server).Length;

        await client.Query(name, [ DNSResourceRecordTypes.A ], ShortTimeout);
        var afterSecond  = QuestionsAsked(server).Length;

        await client.Query(DomainName.Parse("forced.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);
        var afterByName  = QuestionsAsked(server).Length;

        await client.Query(name, [ DNSResourceRecordTypes.A ], ShortTimeout, ForceUpdate: null);
        var afterNull    = QuestionsAsked(server).Length;

        await client.Query(name, [ DNSResourceRecordTypes.A ], ShortTimeout, ForceUpdate: true);
        var afterForced  = QuestionsAsked(server).Length;

        Assert.Multiple(() => {

            Assert.That(afterFirst,  Is.EqualTo(1), "nothing was cached yet");
            Assert.That(afterSecond, Is.EqualTo(1), "the second identical question came out of the cache");
            Assert.That(afterByName, Is.EqualTo(1), "and so did the same question asked through the DomainName overload");
            Assert.That(afterNull,   Is.EqualTo(1), "ForceUpdate: null is not ForceUpdate: true");
            Assert.That(afterForced, Is.EqualTo(2), "ForceUpdate: true asks anyway, which is what makes the rest of this test mean something");

        });

    }

    #endregion


    #region Which servers a client ends up with

    [Test]
    public void A_Client_Given_Servers_Queries_Only_Those()
    {

        // A client handed an explicit list must not add the machine's own
        // resolvers to it. The point is not tidiness: the list is usually
        // explicit because the caller cares where the query goes — a test rig, a
        // split-horizon view, a resolver that is trusted for this name — and a
        // second server quietly appended is a query leaving for somewhere the
        // caller did not choose, racing the one it did.
        //
        // The two search parameters therefore default to false on this
        // constructor and to true on the one that has no list to be explicit
        // with. That contrast is the rule, and it is the reason the same two
        // parameters are checked twice in this file with opposite expectations.
        //
        // On a machine with no DNS server configured at all this test still
        // passes and proves less, since there would be nothing to append. It is
        // not wrong there, only quiet.
        using var client = new DNSClient(
                               ManualDNSServers:  [ new DNSServerConfig(IPv4Address.Localhost, UnusedPort) ],
                               QueryTimeout:      ShortTimeout
                           );

        Assert.Multiple(() => {

            Assert.That(client.DNSServers,                   Has.Count.EqualTo(1),
                        "one server was named, so one server is configured");

            Assert.That(client.DNSServers.First().IPAddress, Is.EqualTo(IPv4Address.Localhost));

        });

    }


    [Test]
    public void A_Client_Given_No_Servers_Looks_Them_Up()
    {

        // The other half of the contrast: the constructor with no list to be
        // explicit with searches the machine's network configuration, per address
        // family, and only on interfaces that are up.
        //
        // This is the one test here that can only be answered by the machine it
        // runs on, so it says out loud what it needs, family by family, and
        // declines to judge what this machine cannot settle. Two questions are
        // being asked and they need different things:
        //
        //   "does the search run?" needs one DNS server of that family on an
        //   interface that is up. Switched off, nothing of that family is found,
        //   whatever the down interfaces hold.
        //
        //   "are only up interfaces read?" needs that family to have *no* DNS
        //   server on a down interface. Otherwise "up" and "not up" both find one,
        //   and the client could be reading the wrong interfaces and still look
        //   right.
        //
        // The second is the stricter, and on Windows it is routinely unmeetable for
        // IPv6: fec0:0:0:ffff::1 through ::3 are the legacy site-local defaults and
        // they sit on nearly every adapter, disconnected VPN tunnels included, while
        // IPv4 servers only appear where one was actually configured.
        //
        // The preconditions apply the same filter the implementation does, which
        // would be circular if they were the expectation. They are not: they decide
        // which questions this machine can answer, and the expectation is what the
        // client found.
        var interfaces  = NetworkInterface.GetAllNetworkInterfaces();

        IEnumerable<System.Net.IPAddress> DnsOn(Boolean Up, AddressFamily Family)
            => interfaces.
                   Where     (networkInterface => (networkInterface.OperationalStatus == OperationalStatus.Up) == Up).
                   SelectMany(networkInterface => networkInterface.GetIPProperties().DnsAddresses).
                   Where     (address          => address.AddressFamily == Family);

        var upIPv4      = DnsOn(true,  AddressFamily.InterNetwork).  Any();
        var upIPv6      = DnsOn(true,  AddressFamily.InterNetworkV6).Any();
        var downIPv4    = DnsOn(false, AddressFamily.InterNetwork).  Any();
        var downIPv6    = DnsOn(false, AddressFamily.InterNetworkV6).Any();

        if (!upIPv4 && !upIPv6)
            Assert.Ignore("no DNS server is configured on an interface that is up, so there is nothing for discovery to find");

        using var searching  = new DNSClient(QueryTimeout: ShortTimeout);

        using var told       = new DNSClient(
                                   QueryTimeout:             ShortTimeout,
                                   SearchForIPv4DNSServers:  false,
                                   SearchForIPv6DNSServers:  false
                               );

        // Null rather than omitted, because omitting it takes the parameter's own
        // default and never reaches the `?? true` in the body.
        using var nulled     = new DNSClient(
                                   QueryTimeout:             ShortTimeout,
                                   SearchForIPv4DNSServers:  null,
                                   SearchForIPv6DNSServers:  null
                               );

        Assert.Multiple(() => {

            if (upIPv4)
            {
                Assert.That(searching.DNSServers.Any(server => server.IPAddress is IPv4Address), Is.True,
                            downIPv4
                                ? "searching by default finds an IPv4 resolver of this machine"
                                : "searching by default finds an IPv4 resolver, and only up interfaces hold one here");

                Assert.That(nulled.   DNSServers.Any(server => server.IPAddress is IPv4Address), Is.True,
                            "and so does searching when the parameter arrives as null");
            }

            if (upIPv6)
            {
                Assert.That(searching.DNSServers.Any(server => server.IPAddress is IPv6Address), Is.True,
                            downIPv6
                                ? "searching by default finds an IPv6 resolver, though this machine cannot say which interfaces were read"
                                : "searching by default finds an IPv6 resolver, and only up interfaces hold one here");

                Assert.That(nulled.   DNSServers.Any(server => server.IPAddress is IPv6Address), Is.True,
                            "null again means search");
            }

            Assert.That(told.DNSServers, Is.Empty,
                        "and a client told not to search has no servers at all");

        });

        // Not a failure and not silence: which of the two questions this run could
        // answer belongs in the record, because "passed" alone does not say.
        TestContext.Out.WriteLine(
            $"judged here — IPv4: search {(upIPv4 ? "yes" : "no")}, up-only {(upIPv4 && !downIPv4 ? "yes" : "no")}; " +
            $"IPv6: search {(upIPv6 ? "yes" : "no")}, up-only {(upIPv6 && !downIPv6 ? "yes" : "no")}"
        );

    }

    #endregion


    #region The recursion bit the client asks for

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public void A_Clients_Own_Recursion_Setting_Starts_Out_Asking_For_It()
    {

        // RFC 1035 §4.1.1 makes RD a request the querier makes and the responder
        // copies back. Which of the two kinds of resolver is asking is the whole
        // content of the bit: a stub has no delegation chain to walk and needs the
        // server to walk it, while something walking the chain itself must leave the
        // bit clear or be answered out of a cache instead of referred downwards.
        //
        // This class is a stub, so the field is set in the constructor and not from
        // a parameter — there is no constructor argument for it at all.
        //
        // The property only. What reaches the wire is a separate question with a
        // separate answer, and the test below it is where that answer lives.
        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               UnusedPort,
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  false
                           );

        Assert.That(client.RecursionDesired, Is.True,
                    "a stub asks for recursion unless it is told otherwise");

    }


    /// <summary>
    /// Red: the recursion setting of a <c>DNSClient</c> does not reach the wire.
    /// </summary>
    /// <remarks>
    /// Left failing on purpose. Three places in <c>DNSClient</c> decide RD — the
    /// property, the <c>Query</c> parameter, and the <c>?? true</c> behind it — and
    /// the value they produce is handed to a transport client that resolves the
    /// question again from its own field, which its own constructor has already
    /// defaulted to true. So the transport's default wins over everything the caller
    /// said, on every transport.
    /// <para>
    /// This is why the three mutants on those defaults survive any test that reads
    /// the wire: there is nothing downstream that could tell them apart.
    /// </para>
    /// </remarks>
    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "1035 §4.1.1, 1034 §5.3.3")]
    public async Task A_Client_Told_Not_To_Ask_For_Recursion_Does_Not_Ask()
    {

        // The control first, in the same test, because the two together are the
        // finding: a default client asks for recursion, and a client told not to
        // asks anyway.
        //
        // Both ways of telling it are exercised. The property is the client-wide
        // setting; the parameter is per query, and it is reached only with the
        // property put back to null, since a non-null property takes precedence over
        // it. Neither changes the bit.
        await using var server = AnswerWhateverIsAsked();

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  false
                           );

        await client.Query(DNSServiceName.Parse("default.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);

        client.RecursionDesired = false;
        await client.Query(DNSServiceName.Parse("byproperty.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);

        client.RecursionDesired = null;
        await client.Query(DNSServiceName.Parse("bycall.example."), [ DNSResourceRecordTypes.A ], ShortTimeout, RecursionDesired: false);

        var asked = RecursionAsked(server);

        Assert.That(asked, Has.Length.EqualTo(3), "three queries went out");

        Assert.Multiple(() => {

            Assert.That(asked[0], Is.True,  "a client told nothing asks for recursion");
            Assert.That(asked[1], Is.False, "a client whose RecursionDesired is false does not");
            Assert.That(asked[2], Is.False, "and neither does one told so per query");

        });

    }

    #endregion


    #region What is asked for when no type is named

    [Test]
    [Property("RFC", "1035 §3.2.3, §4.1.2")]
    public async Task Asking_For_No_Type_Asks_For_Every_Type()
    {

        // RFC 1035 §3.2.3 defines QTYPE 255 as "A request for all records", and
        // §4.1.2 gives every question exactly one QTYPE. A caller who names no
        // type has still asked a question, so one QTYPE has to be chosen, and 255
        // is the only one that does not narrow what was asked.
        //
        // The other direction is the half worth guarding: a client that reached
        // for ANY when types *were* named would answer the caller's question out
        // of a larger answer, and over UDP that larger answer is what truncation
        // is made of.
        await using var server = AnswerWhateverIsAsked();

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  false
                           );

        await client.Query(DNSServiceName.Parse("typeless.example."), [], ShortTimeout);
        await client.Query(DNSServiceName.Parse("typed.example."),    [ DNSResourceRecordTypes.A ], ShortTimeout);

        // As one comparison rather than three, because a query with no question in
        // it never reaches the wire at all: the mutant that skips the substitution
        // leaves the list empty, and the datagram is never sent. So the count is
        // part of what is asserted and indexing into it is not safe.
        Assert.That(
            QuestionsAsked(server),
            Is.EqualTo(new[] {
                $"typeless.example/{RawDnsType.ANY}",   // no type named: all of them
                $"typed.example/{RawDnsType.A}"         // a type named: that one, and not all
            })
        );

    }

    #endregion

}

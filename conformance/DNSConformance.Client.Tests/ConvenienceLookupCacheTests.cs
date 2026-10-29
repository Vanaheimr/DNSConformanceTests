using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// Every convenience lookup asks the cache first, unless it is told not to.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ClientDefaultsTests"/> pins the cache of <c>DNSClient.Query</c>
/// itself. Most callers never reach that method directly: they ask for "the IPv4
/// addresses of", "the SRV records of", "this type, mapped to that" — sixteen
/// extension methods and two interface methods, and each of them declares its
/// own <c>ForceUpdate = false</c> and passes it on. The value that reaches the
/// cache is whichever one the method the caller named declared, so each of
/// those sixteen defaults decides on its own whether its callers get a cache.
/// </para>
/// <para>
/// This is not a conformance rule — RFC 1035 §7.4 permits a cache rather than
/// requiring one — but the promise the parameter's name makes, and the kind of
/// default that changes by accident in one overload of many. Hence one case per
/// overload rather than one test that happens to take some of them.
/// </para>
/// </remarks>
[TestFixture]
public class ConvenienceLookupCacheTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);


    /// <summary>
    /// A server answering the type it was asked for — an A for A, an AAAA for
    /// AAAA, an SRV for SRV — because a cache keeps the RRset that was asked about
    /// and nothing beside it, so an answer of the wrong type would never be found
    /// there however the default was set.
    /// </summary>
    private static ScriptedUdpServer AnswerTheTypeAsked()

        => new (request => {

               var questions = RawDnsReader.Parse(request).Questions;

               if (questions.Count != 1)
                   return null;

               var name = $"{questions[0].Name.Canonical}.";

               return questions[0].Type switch {
                   RawDnsType.A     => RawDnsResponder.Answer(request, (name, RawDnsType.A,    300, [192, 0, 2, 21])),
                   RawDnsType.AAAA  => RawDnsResponder.Answer(request, (name, RawDnsType.AAAA, 300, [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x21])),
                   RawDnsType.SRV   => RawDnsResponder.Answer(request, (name, RawDnsType.SRV,  300, [0, 10, 0, 5, 0x13, 0xc4,
                                                                                                     3, (Byte) 's', (Byte) 'i', (Byte) 'p',
                                                                                                     7, (Byte) 'e', (Byte) 'x', (Byte) 'a', (Byte) 'm', (Byte) 'p', (Byte) 'l', (Byte) 'e',
                                                                                                     0])),
                   _                => RawDnsResponder.Answer(request)
               };

           });


    private static readonly DomainName      Name     = DomainName.    Parse("convenience.example.");
    private static readonly DNSServiceName  Service  = DNSServiceName.Parse("convenience.example.");
    private static readonly DNSServiceName  SRVName  = DNSServiceName.Parse("_sip._udp.convenience.example.");
    private static readonly URL             Address  = URL.           Parse("https://convenience.example/");


    /// <summary>
    /// Each overload once, with nothing but what a caller who never heard of
    /// ForceUpdate would pass, and the number of questions one call asks.
    /// </summary>
    private static IEnumerable<TestCaseData> Overloads()
    {

        TestCaseData Case(String Label, Int32 Questions, Func<IDNSClient, Task> Call)
            => new TestCaseData(Call, Questions).SetArgDisplayNames(Label);

        yield return Case("Query<T>(DomainName)",                    1, client => client.Query<A>(Name,    Timeout));
        yield return Case("Query<T>(DNSServiceName)",                1, client => client.Query<A>(Service, Timeout));
        yield return Case("Query<T1, T2>(DomainName, Mapper)",       1, client => client.Query<A, IPv4Address>(Name,    record => record.IPv4Address, Timeout));
        yield return Case("Query<T1, T2>(DNSServiceName, Mapper)",   1, client => client.Query<A, IPv4Address>(Service, record => record.IPv4Address, Timeout));

        yield return Case("Query_IPv4Addresses(DomainName)",         1, client => client.Query_IPv4Addresses(Name,    Timeout));
        yield return Case("Query_IPv4Addresses(DNSServiceName)",     1, client => client.Query_IPv4Addresses(Service, Timeout));
        yield return Case("Query_IPv4Addresses(URL)",                1, client => client.Query_IPv4Addresses(Address, Timeout));

        yield return Case("Query_IPv6Addresses(DomainName)",         1, client => client.Query_IPv6Addresses(Name,    Timeout));
        yield return Case("Query_IPv6Addresses(DNSServiceName)",     1, client => client.Query_IPv6Addresses(Service, Timeout));
        yield return Case("Query_IPv6Addresses(URL)",                1, client => client.Query_IPv6Addresses(Address, Timeout));

        // Two questions per call, A and AAAA: the defaults being asked about are
        // the ones these three declare and hand to the two lookups above.
        yield return Case("Query_IPAddresses(DomainName)",           2, client => client.Query_IPAddresses(Name,    Timeout));
        yield return Case("Query_IPAddresses(DNSServiceName)",       2, client => client.Query_IPAddresses(Service, Timeout));
        yield return Case("Query_IPAddresses(URL)",                  2, client => client.Query_IPAddresses(Address, Timeout));

        yield return Case("Query_DNSService(DomainName, SRV_Spec)",  1, client => client.Query_DNSService(Name, SRV_Spec.UDP("sip"), Timeout));
        yield return Case("Query_DNSService(DNSServiceName)",        1, client => client.Query_DNSService(SRVName, Timeout));

        // The interface's own two methods, reached through the interface type —
        // which is where their declared defaults apply rather than DNSClient's.
        yield return Case("IDNSClient.Query(DomainName, Types)",     1, client => client.Query(Name,    [ DNSResourceRecordTypes.A ], Timeout));
        yield return Case("IDNSClient.Query(DNSServiceName, Types)", 1, client => client.Query(Service, [ DNSResourceRecordTypes.A ], Timeout));

    }

    #endregion


    [TestCaseSource(nameof(Overloads))]
    [Property("RFC", "1035 §7.4")]
    public async Task A_Second_Identical_Lookup_Is_Answered_From_The_Cache(Func<IDNSClient, Task> Lookup, Int32 QuestionsPerLookup)
    {

        // Twice the same lookup through the same client. The first one asks the
        // server; the second finds every answer it needs in the cache, so the
        // server is asked nothing new. A default of "always ask" would double the
        // count and leave the answers just as right, which is why the count, and
        // not the answer, is what is asserted.
        await using var server = AnswerTheTypeAsked();

        using var client = new DNSClient(IPv4Address.Localhost,
                                         IPPort.Parse((UInt16) server.Port),
                                         QueryTimeout: Timeout);

        IDNSClient asInterface = client;

        await Lookup(asInterface);
        var afterFirst  = server.Requests.Count;

        await Lookup(asInterface);
        var afterSecond = server.Requests.Count;

        Assert.Multiple(() => {
            Assert.That(afterFirst,  Is.EqualTo(QuestionsPerLookup), "the first lookup asked the server");
            Assert.That(afterSecond, Is.EqualTo(QuestionsPerLookup), "and the second one was answered out of the cache");
        });

    }

}

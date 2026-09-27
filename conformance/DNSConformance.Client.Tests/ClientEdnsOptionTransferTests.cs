using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// The EDNS options a query leaves with, once the per-server cookie has been
/// added to whatever the caller configured.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="CookieProtocolTests"/> covers the cookie itself — how it is
/// derived, when it is accepted, what a BADCOOKIE costs. What nothing covered is
/// the list it lands in. A cookie is per server and per query, while everything
/// else on <c>DNSClient.EDNSOptions</c> is configured once and meant for every
/// query, so the two have to be merged, and merging is where options go missing
/// and where they arrive twice.
/// </para>
/// <para>
/// The merge happens twice over, in two different ways. The list is first built
/// for the query, and then transferred onto the transport client that will
/// actually write it — appended for UDP, where a fresh client is made per query,
/// and replaced by option code for TCP, TLS and HTTPS, where one client is
/// pooled and reused. The second path is the one that can accumulate, so it is
/// tested over TCP with two queries rather than one.
/// </para>
/// </remarks>
[TestFixture]
public class ClientEdnsOptionTransferTests
{

    #region Data

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromSeconds(3);


    private static Byte[] PlainAnswer(Byte[] Request)
    {

        var questions = RawDnsReader.Parse(Request, RawDnsReaderOptions.Lenient).Questions;

        return RawDnsResponder.Answer(
                   Request,
                   ($"{questions[0].Name.Canonical}.", RawDnsType.A, 300, [192, 0, 2, 9])
               );

    }


    /// <summary>The EDNS option codes of a query the scripted peer received, in order.</summary>
    private static UInt16[] OptionCodesOf(Byte[] Request)

        => [.. RawDnsReader.Parse(Request, RawDnsReaderOptions.Lenient).
                   Edns?.
                   Options.
                   Select(option => option.Code) ?? []];

    #endregion


    #region What travels beside the cookie (RFC 6891 §6.1.2, RFC 7873 §5.1)

    [Test]
    [Property("RFC", "6891 §6.1.2, 7873 §5.1")]
    public async Task An_Option_The_Client_Was_Configured_With_Survives_The_Cookie()
    {

        // RFC 7873 §5.1 has a client always offer a cookie, so every query gains
        // an option it was not configured with, and the configured ones have to
        // survive that. NSID is the plainest case: RFC 5001 §2.1 — "The resolver
        // MUST NOT include any NSID payload data in the query message" — makes it
        // an option code and nothing else, so it changes nothing about the query,
        // and a client that drops it simply is not asking what the caller set up.
        //
        // The failure this guards against is the natural way to write the merge —
        // filter the list down to the cookie rather than filter the old cookie out
        // of the list. Both are one comparison, and both leave a query that
        // carries a cookie and works.
        await using var server = new ScriptedUdpServer(PlainAnswer);

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  false
                           );

        client.EDNSOptions.Add(new EDNSOption(EDNSOptionCode.NSID, []));

        await client.Query(DNSServiceName.Parse("nsid.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the query reached the server");

        var codes = OptionCodesOf(request!);

        Assert.Multiple(() => {

            Assert.That(codes, Does.Contain((UInt16) EDNSOptionCode.NSID),
                        "the option the caller configured is still there");

            Assert.That(codes, Does.Contain((UInt16) EDNSOptionCode.Cookie),
                        "and the cookie the client always offers is there beside it");

        });

    }


    [Test]
    [Property("RFC", "7871 §6, §7.1.2, 6891 §6.1.2, 7873 §5.1")]
    public async Task A_Configured_Client_Subnet_Does_Not_Displace_The_Cookie()
    {

        // Client Subnet (RFC 7871 §6, sent by a stub per §7.1.2) is handled apart
        // from the rest, because the configured one has to win over any left over
        // from before: RFC 7871 states no limit on how many a query may carry, and
        // RFC 6891 §6.1.2 leaves the order of option tuples undefined, so two of
        // them is a query whose subnet a responder picks rather than reads.
        // Removing the old one is right; removing everything that is not one takes
        // the cookie with it, and the two are one comparison apart.
        //
        // What that costs is not the cookie itself but what the cookie is for: a
        // client that stops offering one as soon as a subnet is configured is a
        // client that cannot complete an exchange with a server requiring cookies
        // (RFC 7873 §5.2.3) — and it stops for a reason that has nothing to do
        // with either feature.
        await using var server = new ScriptedUdpServer(PlainAnswer);

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  false
                           );

        client.ClientSubnet = new EDNSClientSubnetOption(
                                  System.Net.IPAddress.Parse("192.0.2.0"),
                                  24
                              );

        await client.Query(DNSServiceName.Parse("subnet.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the query reached the server");

        var codes = OptionCodesOf(request!);

        Assert.Multiple(() => {

            Assert.That(codes, Does.Contain((UInt16) EDNSOptionCode.ClientSubnet),
                        "the configured subnet is sent");

            Assert.That(codes, Does.Contain((UInt16) EDNSOptionCode.Cookie),
                        "and it did not take the cookie with it");

            Assert.That(codes.Count(code => code == (UInt16) EDNSOptionCode.ClientSubnet), Is.EqualTo(1),
                        "and there is one of it, not two");

        });

    }

    #endregion


    #region One of each, on a connection that is reused (RFC 6891 §6.1.2)

    [Test]
    [Property("RFC", "6891 §6.1.2, 7873 §5.2")]
    public async Task A_Reused_Connection_Still_Carries_One_Cookie_Per_Query()
    {

        // UDP clients are built per query and start with an empty option list, so
        // appending to it is harmless there. TCP, TLS and HTTPS clients are pooled
        // and reused, and appending to those accumulates: the second query carries
        // the option twice, the third three times.
        //
        // RFC 6891 §6.1.2 is why that is not merely untidy — "The order of
        // appearance of option tuples is not defined", so a query carrying two
        // COOKIE options has no answer to which one a responder reads. One of them
        // is the cookie this exchange has established; the other is whatever was
        // left from last time, and a server that reads it rejects the query or
        // issues a new cookie for a client half it was not asked about.
        //
        // Two queries, because the first cannot tell the difference: an empty list
        // appended to and an empty list replaced into look the same.
        //
        // And two configured options rather than one, which is not padding of the
        // test. With the cookie there are then three codes in play, and three is
        // where "replace the option with this code" and "replace an option without
        // it" stop agreeing. With two they agree: a search for the wrong code finds
        // the only other entry, each assignment writes over the other's slot, and
        // the list ends up holding one of each in the opposite order — which RFC
        // 6891 §6.1.2 makes indistinguishable, since it defines no order. Three
        // codes and the same mutation loses one option and duplicates another.
        await using var server = new ScriptedTcpServer(PlainAnswer);

        using var client = new DNSClient(
                               ManualDNSServers:  [
                                                      new DNSServerConfig(
                                                          IPv4Address.Localhost,
                                                          IPPort.Parse((UInt16) server.Port),
                                                          DNSTransport.TCP
                                                      )
                                                  ],
                               QueryTimeout:      ShortTimeout
                           );

        client.EDNSOptions.Add(new EDNSOption      (EDNSOptionCode.NSID, []));
        client.EDNSOptions.Add(new EDNSPaddingOption(16));

        await client.Query(DNSServiceName.Parse("first.example."),  [ DNSResourceRecordTypes.A ], ShortTimeout);
        await client.Query(DNSServiceName.Parse("second.example."), [ DNSResourceRecordTypes.A ], ShortTimeout);

        var requests = server.Requests.ToArray();

        Assert.That(requests, Has.Length.EqualTo(2), "two queries, two datagrams inside the frames");

        var second = OptionCodesOf(requests[1]);

        Assert.Multiple(() => {

            Assert.That(second.Count(code => code == (UInt16) EDNSOptionCode.Cookie),  Is.EqualTo(1),
                        "the second query over the same connection carries one cookie");

            Assert.That(second.Count(code => code == (UInt16) EDNSOptionCode.NSID),    Is.EqualTo(1),
                        "and one NSID");

            Assert.That(second.Count(code => code == (UInt16) EDNSOptionCode.Padding), Is.EqualTo(1),
                        "and one padding option, which is the one a wrong replacement drops");

        });

    }

    #endregion

}

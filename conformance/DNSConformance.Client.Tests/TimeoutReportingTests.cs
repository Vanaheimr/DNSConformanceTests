using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// One event, four transports, one answer: a query that runs out of its own
/// time says so.
///
/// No RFC writes this down — it is an API property rather than a wire property,
/// which is why it went unnoticed. It still decides behaviour: "no answer yet"
/// and "this resolver is broken" call for different next moves, and a caller
/// that picks between them by <c>IsTimeout</c> got a different answer from DoH
/// than from everything else. DoH's deadline never surfaced as an exception —
/// the HTTP layer turned it into a statusless response first — so the timeout
/// path was unreachable and every slow DoH resolver looked like a failing one.
///
/// Each case asserts the runtime as well, because <c>IsTimeout</c> on a query
/// that returned in a millisecond would be a different bug wearing the same
/// answer.
/// </summary>
[TestFixture]
public class TimeoutReportingTests
{

    #region Data

    private static readonly TimeSpan  Timeout  = TimeSpan.FromMilliseconds(600);

    private static void AssertTimedOut(DNSInfo<A> Response, String Transport)
        => Assert.Multiple(() => {

               Assert.That(Response.IsTimeout, Is.True,
                           $"{Transport}: a query that ran out of its own time is a timeout, not an unexplained failure");

               Assert.That(Response.FilteredAnswers, Is.Empty,
                           $"{Transport}: and it carries no answers");

               Assert.That(Response.Runtime, Is.GreaterThan(TimeSpan.FromMilliseconds(300)),
                           $"{Transport}: it waited for the deadline rather than reporting one it never reached");

           });

    #endregion


    #region A_Udp_Query_That_Runs_Out_Of_Time_Says_So()

    [Test]
    public async Task A_Udp_Query_That_Runs_Out_Of_Time_Says_So()
    {

        await using var server = ScriptedUdpServer.Silent();

        await using var client = new DNSUDPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout: Timeout
                                 );

        AssertTimedOut(await client.Query<A>(DomainName.Parse("silent.example."), Timeout: Timeout), "UDP");

    }

    #endregion

    #region A_Tcp_Query_That_Runs_Out_Of_Time_Says_So()

    [Test]
    public async Task A_Tcp_Query_That_Runs_Out_Of_Time_Says_So()
    {

        await using var server = new ScriptedTcpServer(_ => (Byte[]?) null);

        await using var client = new DNSTCPClient(
                                     IPv4Address.Localhost,
                                     Port:          IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:  Timeout
                                 );

        AssertTimedOut(await client.Query<A>(DomainName.Parse("silent.example."), Timeout: Timeout), "TCP");

    }

    #endregion

    #region A_Dot_Query_That_Runs_Out_Of_Time_Says_So()

    [Test]
    public async Task A_Dot_Query_That_Runs_Out_Of_Time_Says_So()
    {

        await using var server = new ScriptedTlsServer(_ => (Byte[]?) null);

        await using var client = new DNSTLSClient(
                                     IPv4Address.Localhost,
                                     TCPPort:                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout:                Timeout,
                                     RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success()
                                 );

        AssertTimedOut(await client.Query<A>(DomainName.Parse("silent.example."), Timeout: Timeout), "DoT");

    }

    #endregion

    #region A_Doh_Query_That_Runs_Out_Of_Time_Says_So()

    [Test]
    public async Task A_Doh_Query_That_Runs_Out_Of_Time_Says_So()
    {

        // The one that was wrong. The others are here so that the assertion is
        // about a property all four share rather than about DoH alone — if a
        // future change makes one of them disagree again, this says which.
        await using var server = new ScriptedDoHServer(
            _ => {
                Thread.Sleep(TimeSpan.FromSeconds(3));
                return null;
            }
        );

        await using var client = new DNSHTTPSClient(
                                     URL.Parse(server.Url),
                                     Mode:          DNSHTTPSMode.POST,
                                     QueryTimeout:  Timeout
                                 );

        AssertTimedOut(await client.Query<A>(DomainName.Parse("silent.example."), Timeout: Timeout), "DoH");

    }

    #endregion


    #region One deadline for a query of two types

    [TestCaseSource(typeof(TransportPeers), nameof(TransportPeers.Transports))]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Query_For_Two_Types_Runs_Out_Of_Time_Once(String Transport)
    {

        // RFC 9619 §4 makes a query for two types two queries, and over a stream
        // the two share one connection, one at a time. The deadline is still the
        // caller's, and one: the second half must not be given a fresh one when
        // the first is done with the connection. Over TCP and DoT it was, because
        // the deadline began only once the connection was free - 2.0 s and 2.2 s
        // for a 1 s query to a server that never answered.
        var deadline = TimeSpan.FromSeconds(1);

        await using var peer = TransportPeers.Silent(Transport, deadline);

        var clock = System.Diagnostics.Stopwatch.StartNew();
        var info  = await peer.Client.Query(DNSServiceName.Parse("silent.example."),
                                            [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ],
                                            deadline);
        clock.Stop();

        Assert.Multiple(() => {
            Assert.That(info.IsTimeout, Is.True,                                         "neither type was answered");
            Assert.That(clock.Elapsed,  Is.LessThan(deadline + TimeSpan.FromSeconds(0.5)), "and that was known once, at the deadline");
        });

    }

    #endregion

    #region A failure says how long it took

    [TestCaseSource(typeof(TransportPeers), nameof(TransportPeers.Transports))]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Failure_Reports_The_Time_It_Took(String Transport)
    {

        // A refused connection is known long before any deadline: at once for a
        // UDP port, after about two seconds of SYN retries for a TCP one on
        // Windows. Its runtime was the timeout all the same - every failure's
        // was - so a caller reading Runtime, or a test asking how long something
        // took, was told a number the query had nothing to do with.
        var deadline = TimeSpan.FromSeconds(6);

        await using var client = TransportPeers.Refused(Transport, deadline);

        var clock = System.Diagnostics.Stopwatch.StartNew();
        var info  = await client.Query(DNSServiceName.Parse("refused.example."), [ DNSResourceRecordTypes.A ], deadline);
        clock.Stop();

        Assert.Multiple(() => {
            Assert.That(info.IsTimeout, Is.False,                       "a refusal is not a timeout");
            Assert.That(info.Runtime,   Is.LessThan(deadline),          "its runtime is not its timeout");
            Assert.That(info.Runtime,   Is.LessThanOrEqualTo(clock.Elapsed), "and no longer than the caller waited");
            Assert.That(clock.Elapsed - info.Runtime, Is.LessThan(TimeSpan.FromMilliseconds(500)),
                        "but the time it took, give or take what the call costs around it");
        });

    }

    #endregion

}

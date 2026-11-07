using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.RawDns;
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

    #region A_Udp_Query_Whose_Tcp_Fallback_Runs_Out_Of_Time_Says_So()

    [Test]
    [Property("RFC", "7766 §5")]
    public async Task A_Udp_Query_Whose_Tcp_Fallback_Runs_Out_Of_Time_Says_So()
    {

        // The UDP answer is truncated, so RFC 7766 §5 sends the query again over TCP
        // to the same server - and the TCP side takes it in and never answers. The
        // query has one deadline, and it runs out during the fallback: that is still
        // a query that ran out of its own time. Nothing about the second leg makes it
        // the caller's cancellation or a failure of the server.
        var (udpServer, tcpServer) = await ScriptedServerPair.CreateAsync(
            UdpResponder: request => RawDnsResponder.Truncated(request),
            TcpResponder: _       => null
        );

        await using var udp = udpServer;
        await using var tcp = tcpServer;

        await using var client = new DNSUDPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) udp.Port),
                                     QueryTimeout: Timeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("fallback.example."), Timeout: Timeout);

        Assert.That(tcp.Requests, Is.Not.Empty,
                    "the positive control: the truncated answer sent the query on to TCP, where it went unanswered");

        AssertTimedOut(response, "UDP falling back to TCP");

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

    #region A DoH request the server hangs up on

    /// <summary>
    /// A loopback HTTP server that takes each request in and closes the connection
    /// without a word, and counts the requests it took in.
    /// </summary>
    private sealed class HangingUpServer : IAsyncDisposable
    {

        private readonly System.Net.Sockets.TcpListener  listener  = new (System.Net.IPAddress.Loopback, 0);
        private readonly CancellationTokenSource         stop      = new ();
        private readonly Task                            loop;
        private          Int32                           requests;

        public Int32  Port      => ((System.Net.IPEndPoint) listener.LocalEndpoint).Port;
        public Int32  Requests  => Volatile.Read(ref requests);

        public HangingUpServer()
        {
            listener.Start();
            loop = Task.Run(Serve);
        }

        private async Task Serve()
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {

                    using var peer   = await listener.AcceptSocketAsync(stop.Token);
                    var       buffer = new Byte[4096];
                    var       seen   = new System.Text.StringBuilder();

                    // Up to the end of the request head, which is all it takes to
                    // know a request arrived: the client has sent and is waiting.
                    using var patience = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
                    patience.CancelAfter(TimeSpan.FromSeconds(2));

                    try
                    {
                        while (!seen.ToString().Contains("\r\n\r\n"))
                        {
                            var read = await peer.ReceiveAsync(buffer, System.Net.Sockets.SocketFlags.None, patience.Token);
                            if (read == 0)
                                break;
                            seen.Append(System.Text.Encoding.ASCII.GetString(buffer, 0, read));
                        }
                    }
                    catch (OperationCanceledException) when (!stop.IsCancellationRequested) { }

                    if (seen.ToString().Contains("HTTP/1.1"))
                        Interlocked.Increment(ref requests);

                    // And then nothing: the connection ends, the request unanswered.
                    peer.Shutdown(System.Net.Sockets.SocketShutdown.Both);

                }
            }
            catch (OperationCanceledException)                 { }
            catch (ObjectDisposedException)                    { }
            catch (System.Net.Sockets.SocketException)         { }
        }

        public async ValueTask DisposeAsync()
        {
            await stop.CancelAsync();
            listener.Stop();
            try { await loop.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
            stop.Dispose();
        }

    }


    [Test]
    public async Task A_Doh_Request_The_Server_Hangs_Up_On_Is_A_Failure_Not_A_Timeout()
    {

        // The other side of the DoH timeout above. Its deadline reaches the DoH
        // client as a response with no status, and that is why the client asks
        // whether its own deadline ran out before calling one a timeout. A request
        // the server takes in and hangs up on comes back the same way, statusless,
        // once the HTTP layer has tried as often as it may - and long before any
        // deadline. That is a resolver that failed, and a caller deciding whether to
        // try again is owed the difference.
        var deadline = TimeSpan.FromSeconds(10);

        await using var server = new HangingUpServer();

        await using var client = new DNSHTTPSClient(
                                     URL.Parse($"http://127.0.0.1:{server.Port}/dns-query"),
                                     Mode:          DNSHTTPSMode.POST,
                                     QueryTimeout:  deadline
                                 );

        var clock = System.Diagnostics.Stopwatch.StartNew();
        var info  = await client.Query<A>(DomainName.Parse("hungup.example."), Timeout: deadline);
        clock.Stop();

        TestContext.Out.WriteLine($"{server.Requests} request(s) taken in, answer after {clock.Elapsed.TotalMilliseconds:F0} ms");

        Assert.Multiple(() => {

            Assert.That(server.Requests,  Is.GreaterThan(0),
                        "the positive control: the request reached the server, which then hung up on it");

            Assert.That(info.IsTimeout,   Is.False,
                        "a hang-up is not a timeout");

            Assert.That(info.FilteredAnswers, Is.Empty,
                        "and it carries no answers");

            Assert.That(clock.Elapsed,    Is.LessThan(deadline / 2),
                        "it was known well before the deadline");

        });

    }

    #endregion

}

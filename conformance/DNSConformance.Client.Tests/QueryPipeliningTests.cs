using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Client.Tests;

/// <summary>
/// A client with two queries for one server sends the second without waiting
/// for the answer to the first.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7766 §6.2.1.1: "In order to achieve performance on par with UDP, DNS
/// clients SHOULD pipeline their queries. When a DNS client sends multiple
/// queries to a server, it SHOULD NOT wait for an outstanding reply before
/// sending the next query." RFC 7858 §3.3 says the same of a TLS session and
/// cites the paragraph.
/// </para>
/// <para>
/// Since RFC 9619 a query for two types is two queries, and Hermod's transport
/// clients send them at once. The server here reads every query the moment it
/// arrives and answers none of them until it has seen both, or until a second
/// has passed. Then it answers everything it holds. A client that pipelines has
/// both queries on the wire before the first answer; a client that waits sends
/// the second only after the first answer, and the server says when that was.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "7766 §6.2.1.1")]
public class QueryPipeliningTests
{

    #region Data

    private static readonly TimeSpan Hold    = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(4);

    private static readonly DNSResourceRecordTypes[] TwoTypes = [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ];


    /// <summary>
    /// Reads every query on every connection as it arrives, and holds the
    /// answers until <c>Expected</c> queries have arrived or <c>Window</c> has
    /// passed since the first. Records how many it had seen when it let go.
    /// </summary>
    /// <remarks>
    /// The scripted servers answer a query before they read the next one, so a
    /// pipelined query would wait unread behind a held answer and look exactly
    /// like one that was never sent. This one keeps reading.
    /// </remarks>
    private sealed class HoldingServer : IAsyncDisposable
    {

        private readonly TcpListener                listener;
        private readonly X509Certificate2?          certificate;
        private readonly Int32                      expected;
        private readonly TimeSpan                   window;
        private readonly CancellationTokenSource    cts         = new();
        private readonly Lock                       sync        = new();
        private readonly List<(Stream Stream, SemaphoreSlim Write, Byte[] Query)> held = [];
        private readonly TaskCompletionSource       firstSeen   = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource       enoughSeen  = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private          Int32                      queriesSeen;
        private          Int32                      seenWhenReleased = -1;
        private          Boolean                    released;

        public Int32 Port               { get; }
        public Int32 QueriesSeen        => Volatile.Read(ref queriesSeen);
        public Int32 SeenWhenReleased   => Volatile.Read(ref seenWhenReleased);


        public HoldingServer(Int32              Expected,
                             TimeSpan           Window,
                             X509Certificate2?  Certificate = null)
        {

            expected     = Expected;
            window       = Window;
            certificate  = Certificate;

            listener     = new TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            Port         = ((IPEndPoint) listener.LocalEndpoint).Port;

            _ = AcceptLoop();
            _ = ReleaseWhenDue();

        }


        private async Task AcceptLoop()
        {
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    var client = await listener.AcceptTcpClientAsync(cts.Token);
                    _ = Task.Run(() => HandleConnection(client));
                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException)    { }
            catch (SocketException)            { }
        }


        private async Task HandleConnection(TcpClient client)
        {

            try
            {

                using var _      = client;
                Stream    stream = client.GetStream();

                if (certificate is not null)
                {
                    var tls = new SslStream(stream, leaveInnerStreamOpen: false);
                    await tls.AuthenticateAsServerAsync(
                              new SslServerAuthenticationOptions {
                                  ServerCertificate          = certificate,
                                  EnabledSslProtocols        = SslProtocols.Tls12 | SslProtocols.Tls13,
                                  ClientCertificateRequired  = false
                              },
                              cts.Token
                          );
                    stream = tls;
                }

                await using var __    = stream;
                using var       write = new SemaphoreSlim(1, 1);

                while (!cts.IsCancellationRequested)
                {

                    var length = new Byte[2];
                    if (!await ReadExactly(stream, length))
                        return;

                    var query = new Byte[(length[0] << 8) | length[1]];
                    if (!await ReadExactly(stream, query))
                        return;

                    Boolean answerNow;

                    lock (sync)
                    {
                        var seen = ++queriesSeen;
                        answerNow = released;
                        if (!answerNow)
                            held.Add((stream, write, query));
                        if (seen == 1)
                            firstSeen.TrySetResult();
                        if (seen >= expected)
                            enoughSeen.TrySetResult();
                    }

                    if (answerNow)
                        await Answer(stream, write, query);

                }

            }
            catch (OperationCanceledException) { }
            catch (IOException)                { }
            catch (AuthenticationException)    { }
            catch (ObjectDisposedException)    { }

        }


        private async Task ReleaseWhenDue()
        {

            try
            {

                await firstSeen.Task.WaitAsync(cts.Token);
                await Task.WhenAny(enoughSeen.Task, Task.Delay(window, cts.Token));

                List<(Stream Stream, SemaphoreSlim Write, Byte[] Query)> due;

                lock (sync)
                {
                    seenWhenReleased = queriesSeen;
                    released         = true;
                    due              = [.. held];
                    held.Clear();
                }

                foreach (var (stream, write, query) in due)
                    await Answer(stream, write, query);

            }
            catch (OperationCanceledException) { }
            catch (IOException)                { }
            catch (ObjectDisposedException)    { }

        }


        private async Task Answer(Stream Stream, SemaphoreSlim Write, Byte[] Query)
        {

            var response = RawDnsResponder.Answer(Query);
            var framed   = new Byte[response.Length + 2];
            framed[0]    = (Byte) (response.Length >> 8);
            framed[1]    = (Byte) (response.Length & 0xFF);
            response.CopyTo(framed, 2);

            await Write.WaitAsync(cts.Token);

            try
            {
                await Stream.WriteAsync(framed, cts.Token);
                await Stream.FlushAsync(cts.Token);
            }
            finally
            {
                Write.Release();
            }

        }


        private async Task<Boolean> ReadExactly(Stream Stream, Byte[] Buffer)
        {

            var read = 0;

            while (read < Buffer.Length)
            {
                var n = await Stream.ReadAsync(Buffer.AsMemory(read), cts.Token);
                if (n == 0)
                    return false;
                read += n;
            }

            return true;

        }


        public async ValueTask DisposeAsync()
        {
            cts.Cancel();
            listener.Stop();
            await Task.Delay(50);
            cts.Dispose();
        }

    }


    private static void AssertPipelined(HoldingServer Server, String Transport)
        => Assert.Multiple(() => {

               Assert.That(Server.QueriesSeen, Is.EqualTo(2),
                           $"{Transport}: both queries reached the server - without this the next line measures nothing");

               Assert.That(Server.SeenWhenReleased, Is.EqualTo(2),
                           $"{Transport}: the second query was on the wire while the first was still unanswered");

           });


    /// <summary>
    /// Two framed queries written back to back, then both answers read - what a
    /// pipelining client does, without a client library in the way.
    /// </summary>
    private static async Task PipelineTwoQueries(Stream Stream)
    {

        foreach (var (id, type) in new[] { ((UInt16) 1, RawDnsType.A), ((UInt16) 2, RawDnsType.AAAA) })
        {
            var query  = RawDnsWriter.Query(id, "two.example.", type);
            var framed = new Byte[query.Length + 2];
            framed[0]  = (Byte) (query.Length >> 8);
            framed[1]  = (Byte) (query.Length & 0xFF);
            query.CopyTo(framed, 2);
            await Stream.WriteAsync(framed);
        }

        await Stream.FlushAsync();

        var length = new Byte[2];

        for (var answers = 0; answers < 2; answers++)
        {
            await Stream.ReadExactlyAsync(length);
            await Stream.ReadExactlyAsync(new Byte[(length[0] << 8) | length[1]]);
        }

    }

    #endregion


    #region The server tells a pipelining client apart

    // Without these the trackers below could be red for a reason of the
    // server's own: a held answer that blocked the read, say, would make every
    // client look like one that waits.

    [Test]
    public async Task The_Holding_Server_Sees_Two_Queries_Sent_Back_To_Back_Over_Tcp()
    {

        await using var server = new HoldingServer(Expected: 2, Window: Hold);

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(System.Net.IPAddress.Loopback, server.Port);

        await PipelineTwoQueries(tcp.GetStream()).WaitAsync(Timeout);

        AssertPipelined(server, "raw TCP");

    }

    [Test]
    public async Task The_Holding_Server_Sees_Two_Queries_Sent_Back_To_Back_Over_Tls()
    {

        await using var server = new HoldingServer(Expected: 2, Window: Hold, Certificate: TestCertificate.CreateServerCertificate());

        using var       tcp = new TcpClient();
        await tcp.ConnectAsync(System.Net.IPAddress.Loopback, server.Port);

        await using var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                                                TargetHost           = "localhost",
                                                EnabledSslProtocols  = SslProtocols.Tls12 | SslProtocols.Tls13
                                            });

        await PipelineTwoQueries(tls).WaitAsync(Timeout);

        AssertPipelined(server, "raw TLS");

    }

    #endregion


    /// <summary>
    /// Finding 87, over TCP.
    /// </summary>
    [Test]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Tcp_Client_Sends_Its_Second_Query_Before_The_First_Is_Answered()
    {

        await using var server = new HoldingServer(Expected: 2, Window: Hold);
        await using var client = new DNSTCPClient(IPv4Address.Localhost,
                                                  Port:          IPPort.Parse((UInt16) server.Port),
                                                  QueryTimeout:  Timeout);

        await client.Query(DNSServiceName.Parse("two.example."), TwoTypes, Timeout);

        AssertPipelined(server, "TCP");

    }


    /// <summary>
    /// Finding 87, over TLS. RFC 7858 §3.3: "In order to minimize latency,
    /// clients SHOULD pipeline multiple queries over a TLS session."
    /// </summary>
    [Test]
    [Property("RFC", "7858 §3.3")]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Dot_Client_Sends_Its_Second_Query_Before_The_First_Is_Answered()
    {

        await using var server = new HoldingServer(Expected: 2, Window: Hold, Certificate: TestCertificate.CreateServerCertificate());
        await using var client = new DNSTLSClient(IPv4Address.Localhost,
                                                  TCPPort:                     IPPort.Parse((UInt16) server.Port),
                                                  QueryTimeout:                Timeout,
                                                  RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success());

        await client.Query(DNSServiceName.Parse("two.example."), TwoTypes, Timeout);

        AssertPipelined(server, "DoT");

    }

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// What a client holds between queries, and that it lets go of it.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7766 §6.2.3 is the reason this is more than tidiness: "To mitigate the
/// risk of unintentional server overload, DNS clients MUST take care to minimise
/// the idle time of established DNS-over-TCP sessions made to any individual
/// server." A client that has been disposed will never send on its connections
/// again, so every one it still holds is idle for good — and the server at the
/// other end keeps a socket for a conversation nobody will finish.
/// </para>
/// <para>
/// None of this is reachable through the wire format; it is what the API does
/// with what it opened. The server here counts the connections its peer ended,
/// so "the client let go" is something the test observes rather than infers.
/// </para>
/// </remarks>
[TestFixture]
public class ClientLifecycleTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);


    private static Byte[] OneAddress(Byte[] Request)
        => RawDnsResponder.Answer(Request, ($"{RawDnsReader.Parse(Request).Questions[0].Name.Canonical}.", RawDnsType.A, 60, [192, 0, 2, 9]));


    private static DNSClient TcpClientFor(ScriptedTcpServer Server)
        => new (ManualDNSServers:  [
                                       new DNSServerConfig(
                                           IPv4Address.Localhost,
                                           IPPort.Parse((UInt16) Server.Port),
                                           DNSTransport.TCP
                                       )
                                   ],
                QueryTimeout:      Timeout,
                UseQueryCache:     false);


    /// <summary>Whether the server saw its peer end a connection within the deadline.</summary>
    private static async Task<Boolean> PeerClosedWithin(ScriptedTcpServer Server, TimeSpan Deadline)
    {

        var until = DateTime.UtcNow + Deadline;

        while (DateTime.UtcNow < until)
        {
            if (Server.ClosedByPeer > 0)
                return true;
            await Task.Delay(20);
        }

        return Server.ClosedByPeer > 0;

    }

    #endregion


    #region A disposed client closes the connections it pooled

    [Test]
    [Property("RFC", "7766 §6.2.3")]
    public async Task A_Disposed_Client_Closes_The_Connection_It_Kept()
    {

        // The control comes first and is what makes the rest mean anything: after
        // the query the connection is still open, because the client keeps it for
        // the next one. Only then is the client disposed, and the connection has
        // to end with it.
        await using var server = new ScriptedTcpServer(OneAddress);

        var client = TcpClientFor(server);

        await client.Query(DNSServiceName.Parse("pooled.example."), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.That(server.ClosedByPeer, Is.Zero, "the connection is kept for the next query");

        client.Dispose();

        Assert.That(await PeerClosedWithin(server, Timeout), Is.True,
                    "and disposing the client ends it");

    }


    [Test]
    [Property("RFC", "7766 §6.2.3")]
    public async Task An_Asynchronously_Disposed_Client_Closes_The_Connection_It_Kept()
    {

        // DisposeAsync is a second entry point with its own call into the same
        // cleanup, so it is a second chance for the cleanup to be skipped. An
        // `await using` reaches this one and not the other.
        await using var server = new ScriptedTcpServer(OneAddress);

        var client = TcpClientFor(server);

        await client.Query(DNSServiceName.Parse("pooledasync.example."), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.That(server.ClosedByPeer, Is.Zero, "the connection is kept for the next query");

        await client.DisposeAsync();

        Assert.That(await PeerClosedWithin(server, Timeout), Is.True,
                    "and disposing the client asynchronously ends it as well");

    }

    #endregion


    #region Disposing twice is disposing once

    [Test]
    public async Task Disposing_A_Stream_Client_Twice_Is_Harmless()
    {

        // The IDisposable contract: a second call is to be ignored. It matters
        // more for these two than for most, because a DNSClient disposes the
        // transports it pooled while their creator may dispose them too — two
        // owners, two calls, and the second must not throw out of a cleanup
        // path where nothing is left to catch it.
        await using var tcpServer = new ScriptedTcpServer(OneAddress);
        await using var tlsServer = new ScriptedTlsServer(OneAddress);

        var tcp = new DNSTCPClient(IPv4Address.Localhost,
                                   Port:          IPPort.Parse((UInt16) tcpServer.Port),
                                   QueryTimeout:  Timeout);

        var tls = new DNSTLSClient(IPv4Address.Localhost,
                                   TCPPort:                     IPPort.Parse((UInt16) tlsServer.Port),
                                   QueryTimeout:                Timeout,
                                   RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success());

        // A query first, so that each client has a connection and a keepalive
        // timer to clean up rather than nothing at all.
        await tcp.Query(DNSServiceName.Parse("twice.example."), [ DNSResourceRecordTypes.A ], Timeout);
        await tls.Query(DNSServiceName.Parse("twice.example."), [ DNSResourceRecordTypes.A ], Timeout);

        await tcp.DisposeAsync();
        await tls.DisposeAsync();

        Assert.Multiple(() => {
            Assert.That(async () => await tcp.DisposeAsync(), Throws.Nothing, "DNSTCPClient");
            Assert.That(async () => await tls.DisposeAsync(), Throws.Nothing, "DNSTLSClient");
        });

    }

    #endregion


    #region A datagram client has no connection to report

    [Test]
    [Property("RFC", "768")]
    public async Task A_Udp_Client_Never_Claims_A_Connection()
    {

        // UDP has no connection, and this client opens a fresh socket for each
        // query and closes it with the answer. A caller reading IsConnected to
        // decide whether to reconnect, or whether a query is in flight, would be
        // told something no socket of this client ever was.
        await using var server = new ScriptedUdpServer(OneAddress);

        await using var client = new DNSUDPClient(IPv4Address.Localhost,
                                                  IPPort.Parse((UInt16) server.Port),
                                                  QueryTimeout: Timeout);

        var before = client.IsConnected;

        var info   = await client.Query(DNSServiceName.Parse("datagram.example."), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.Multiple(() => {
            Assert.That(info.Answers.Count(), Is.EqualTo(1),  "the query was answered");
            Assert.That(before,               Is.False,       "not connected before it");
            Assert.That(client.IsConnected,   Is.False,       "and not connected after it either");
        });

    }

    #endregion

}

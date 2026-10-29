using System.Net;
using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// One client per transport, for the tests that ask the same thing of all four.
/// </summary>
internal static class TransportPeers
{

    /// <summary>The four transports, by the names the test cases carry.</summary>
    public static readonly String[] Transports = [ "UDP", "TCP", "DoT", "DoH" ];


    /// <summary>
    /// A server that takes every query and answers none, and a client asking it.
    /// </summary>
    public static SilentPeer Silent(String Transport, TimeSpan QueryTimeout)
    {

        switch (Transport)
        {

            case "UDP":
            {
                var server = ScriptedUdpServer.Silent();
                return new SilentPeer(server,
                                      new DNSUDPClient(IPv4Address.Localhost,
                                                       IPPort.Parse((UInt16) server.Port),
                                                       QueryTimeout: QueryTimeout),
                                      () => server.Requests.Count);
            }

            case "TCP":
            {
                var server = new ScriptedTcpServer(_ => (Byte[]?) null);
                return new SilentPeer(server,
                                      new DNSTCPClient(IPv4Address.Localhost,
                                                       Port:          IPPort.Parse((UInt16) server.Port),
                                                       QueryTimeout:  QueryTimeout),
                                      () => server.Requests.Count);
            }

            case "DoT":
            {
                var server = new ScriptedTlsServer(_ => (Byte[]?) null);
                return new SilentPeer(server,
                                      new DNSTLSClient(IPv4Address.Localhost,
                                                       TCPPort:                     IPPort.Parse((UInt16) server.Port),
                                                       QueryTimeout:                QueryTimeout,
                                                       RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success()),
                                      () => server.Requests.Count);
            }

            case "DoH":
            {

                // HTTP has no silence of its own: a request is answered, if only
                // with an error. So the answer is held back until the test is over,
                // which is what a resolver that never gets round to it looks like.
                var held   = new ManualResetEventSlim();
                var server = new ScriptedDoHServer(_ => {
                                 held.Wait(TimeSpan.FromSeconds(30));
                                 return null;
                             });

                return new SilentPeer(server,
                                      new DNSHTTPSClient(URL.Parse(server.Url),
                                                         QueryTimeout: QueryTimeout),
                                      () => server.Exchanges.Count,
                                      held);

            }

            default:
                throw new ArgumentException($"No such transport: {Transport}", nameof(Transport));

        }

    }


    /// <summary>
    /// A client asking a loopback port nothing listens on.
    /// </summary>
    public static IDNSClient Refused(String Transport, TimeSpan QueryTimeout)

        => Transport switch {

               "UDP"  => new DNSUDPClient  (IPv4Address.Localhost,
                                            IPPort.Parse((UInt16) ClosedUdpPort()),
                                            QueryTimeout: QueryTimeout),

               "TCP"  => new DNSTCPClient  (IPv4Address.Localhost,
                                            Port:          IPPort.Parse((UInt16) ClosedTcpPort()),
                                            QueryTimeout:  QueryTimeout),

               "DoT"  => new DNSTLSClient  (IPv4Address.Localhost,
                                            TCPPort:                     IPPort.Parse((UInt16) ClosedTcpPort()),
                                            QueryTimeout:                QueryTimeout,
                                            RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success()),

               "DoH"  => new DNSHTTPSClient(URL.Parse($"http://127.0.0.1:{ClosedTcpPort()}/dns-query"),
                                            QueryTimeout: QueryTimeout),

               _      => throw new ArgumentException($"No such transport: {Transport}", nameof(Transport))

           };


    /// <summary>A loopback TCP port nothing listens on, found by binding one and letting it go.</summary>
    private static Int32 ClosedTcpPort()
    {
        var probe = new TcpListener(System.Net.IPAddress.Loopback, 0);
        probe.Start();
        var port  = ((IPEndPoint) probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    /// <summary>A loopback UDP port nothing listens on, found the same way.</summary>
    private static Int32 ClosedUdpPort()
    {
        using var probe = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));
        return ((IPEndPoint) probe.Client.LocalEndPoint!).Port;
    }

}


/// <summary>
/// A server that never answers, and the client asking it.
/// </summary>
internal sealed class SilentPeer(IAsyncDisposable       Server,
                                 IDNSClient             Client,
                                 Func<Int32>            QueriesSeen,
                                 ManualResetEventSlim?  Held = null) : IAsyncDisposable
{

    public IDNSClient Client { get; } = Client;


    /// <summary>
    /// Whether the server has the question in hand within the deadline - so that
    /// what a test does next happens to a query in flight rather than to one that
    /// has not left yet.
    /// </summary>
    public async Task<Boolean> SawAQueryWithin(TimeSpan Deadline)
    {

        var until = DateTime.UtcNow + Deadline;

        while (DateTime.UtcNow < until)
        {

            if (QueriesSeen() > 0)
                return true;

            await Task.Delay(20);

        }

        return QueriesSeen() > 0;

    }


    public async ValueTask DisposeAsync()
    {
        Held?.Set();
        await Client.DisposeAsync();
        await Server.DisposeAsync();
        Held?.Dispose();
    }

}

using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.SecureTransports.Tests;

/// <summary>
/// What a DoH server holds after it was disposed.
/// </summary>
/// <remarks>
/// <para>
/// None of this is a requirement of RFC 8484, and none of it is reachable through
/// a DNS message. It is what the API does with what it opened. A server that was
/// disposed and still listens keeps its port for as long as the process runs,
/// and goes on answering for an owner that has let go of it.
/// </para>
/// <para>
/// The test watches the port rather than the object: a connection is accepted
/// while the server runs, which proves the port is the right one, and is not
/// accepted once the server has been disposed.
/// </para>
/// </remarks>
[TestFixture]
public class DohServerLifecycleTests
{

    #region (private static) AcceptsAsync(Port)

    /// <summary>Whether a TCP connection to the loopback port is accepted within a few seconds.</summary>
    private static async Task<Boolean> AcceptsAsync(UInt16 Port)
    {

        using var tcp = new TcpClient();

        try
        {
            await tcp.ConnectAsync(System.Net.IPAddress.Loopback, Port).
                      WaitAsync(TimeSpan.FromSeconds(5));
            return tcp.Connected;
        }
        catch (SocketException)
        {
            return false;
        }
        catch (TimeoutException)
        {
            return false;
        }

    }

    #endregion


    #region A_Disposed_Http2_Server_Accepts_No_Connection()

    [Test]
    public async Task A_Disposed_Http2_Server_Accepts_No_Connection()
    {

        // DisposeAsync() stops the listener and then lets go of what Stop() keeps
        // for a later start. It guards against running twice, and a guard that
        // reads the flag the wrong way round returns at once from the first call,
        // so nothing is stopped and nothing is let go of.
        var server = await DNSOverHTTP2Server.StartNew(IPAddress: IPv4Address.Localhost,
                                                       TCPPort:   IPPort.Zero);

        var port   = server.TCPPort.ToUInt16();

        Assert.That(await AcceptsAsync(port), Is.True,
                    "the positive control: the running server accepts on the port it reports");

        await server.DisposeAsync();

        Assert.That(await AcceptsAsync(port), Is.False,
                    "a disposed server holds no listening port");

    }

    #endregion

}

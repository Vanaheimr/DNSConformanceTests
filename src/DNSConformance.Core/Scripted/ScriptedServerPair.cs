using System.Net.Sockets;

namespace DNSConformance.Core.Scripted;

/// <summary>
/// A UDP and a TCP responder sharing one port number.
/// </summary>
/// <remarks>
/// <para>
/// What an RFC 7766 §5 fallback test needs: the client is told about one server
/// endpoint, gets TC=1 over UDP, and retries <em>that same endpoint</em> over
/// TCP. Two independently allocated ports would not exercise the fallback at
/// all — the retry would go somewhere else.
/// </para>
/// <para>
/// Sharing a number is not free, because UDP and TCP have separate port spaces
/// on every platform: the ephemeral port the TCP listener is handed may already
/// belong to somebody else's UDP socket, and asking for it then throws. It is a
/// rare collision when one test runs alone and a routine one when a whole
/// solution's worth of loopback servers is starting in parallel — which is
/// exactly when a flake is most expensive to diagnose. So: pick again.
/// </para>
/// </remarks>
public static class ScriptedServerPair
{

    /// <summary>
    /// Start a UDP and a TCP responder on the same port, retrying until a port
    /// number is free for both.
    /// </summary>
    /// <param name="UdpResponder">What the UDP side answers.</param>
    /// <param name="TcpResponder">What the TCP side answers.</param>
    /// <param name="Options">Framing options for the TCP side.</param>
    /// <param name="Attempts">How many port numbers to try before giving up.</param>
    public static async Task<(ScriptedUdpServer Udp, ScriptedTcpServer Tcp)> CreateAsync(
        Func<Byte[], Byte[]?>  UdpResponder,
        Func<Byte[], Byte[]?>  TcpResponder,
        ScriptedTcpOptions?    Options    = null,
        Int32                  Attempts   = 25)
    {

        for (var attempt = 1; ; attempt++)
        {

            var tcp = new ScriptedTcpServer(TcpResponder, Options);

            try
            {
                return (new ScriptedUdpServer(UdpResponder, FixedPort: tcp.Port), tcp);
            }
            catch (SocketException) when (attempt < Attempts)
            {
                // The TCP listener got a port whose UDP twin is taken. Drop it and
                // let the OS hand out a different one.
                await tcp.DisposeAsync();
            }
            catch
            {
                await tcp.DisposeAsync();
                throw;
            }

        }

    }

}

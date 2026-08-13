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
/// Sharing a number is not free, because UDP and TCP have separate port spaces:
/// the ephemeral port one listener is handed may be unavailable to the other,
/// and asking for it then throws. Rare when a test runs alone, routine when a
/// whole solution's worth of loopback servers starts in parallel — which is
/// exactly when a flake costs the most to diagnose. So: pick again.
/// </para>
/// <para>
/// UDP goes first, and on Windows that matters rather than being a coin flip.
/// Hyper-V and WSL reserve large blocks of the ephemeral range, and a UDP bind
/// into one of them fails with <c>WSAEACCES</c> — not "in use", but "not yours",
/// which no amount of retrying inside that block will fix. Letting the OS choose
/// the UDP port means it chooses one it is willing to grant; TCP is then asked
/// to follow, which it almost always can.
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

        SocketException? lastFailure = null;

        for (var attempt = 0; attempt < Attempts; attempt++)
        {

            // The first attempt lets the OS choose, which is the right thing
            // where nothing is reserved. After that the candidates are drawn at
            // random from a wide span instead: consecutive ephemeral ports come
            // from one narrow window, so if that window sits inside a reservation
            // then every retry lands in the same one and twenty-five attempts
            // fail as reliably as one.
            var candidate = attempt == 0
                                ? 0
                                : Random.Shared.Next(20000, 60000);

            ScriptedUdpServer udp;

            try
            {
                udp = new ScriptedUdpServer(UdpResponder, FixedPort: candidate);
            }
            catch (SocketException e)
            {
                lastFailure = e;
                continue;
            }

            try
            {
                return (udp, new ScriptedTcpServer(TcpResponder, Options, FixedPort: udp.Port));
            }
            catch (SocketException e)
            {
                lastFailure = e;
                await udp.DisposeAsync();
            }
            catch
            {
                await udp.DisposeAsync();
                throw;
            }

        }

        throw new InvalidOperationException(
                  $"No port number was free for both UDP and TCP after {Attempts} attempts.",
                  lastFailure
              );

    }

}

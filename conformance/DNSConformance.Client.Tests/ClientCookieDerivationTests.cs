using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 7873 §4.1 — where a client cookie comes from.
/// </summary>
/// <remarks>
/// <para>
/// §4.1 asks for "a pseudorandom function of the Client IP Address, the Server
/// IP Address, and a secret quantity known only to the client", and each input
/// buys something different. The secret makes the value unguessable, which is
/// the entire mechanism. The server address satisfies the MUST in the same
/// paragraph — "a client MUST send Client Cookies that will usually be different
/// for any two servers at different IP addresses" — so one server cannot learn
/// what another sees.
/// </para>
/// <para>
/// The client address is the one that is easy to leave out, and the one this
/// fixture spends the most effort on. It is not there for correctness: §4.1 puts
/// it in so that the cookie "cannot be used to track a client if the Client IP
/// Address changes due to privacy mechanisms", and so that a device "formerly on
/// path but ... no longer on path" cannot impersonate the client afterwards.
/// </para>
/// <para>
/// That is also why the cookie is <i>derived</i> rather than remembered. A stored
/// random value would be equally stable and equally unguessable — and would
/// follow the client across every change of address for as long as the process
/// lived, which is the thing the client address is in the input to prevent.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "7873 §4.1")]
public class ClientCookieDerivationTests
{

    private static readonly Byte[] Secret = Convert.FromHexString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");

    private static readonly IPAddress ServerA = IPAddress.Parse("192.0.2.1");
    private static readonly IPAddress ServerB = IPAddress.Parse("192.0.2.2");


    #region The_Derivation_Is_The_One_Section_Four_One_Describes()

    [Test]
    public void The_Derivation_Is_The_One_Section_Four_One_Describes()
    {

        // The strongest form available here: recompute the cookie from §4.1's
        // three inputs, independently, and compare. A test that only checked
        // "stable and eight octets" would pass against a derivation that had
        // quietly dropped the client address — which is exactly the input whose
        // absence has no visible effect until somebody's address changes.
        var cookies  = new DNSClientCookies(Secret);

        Byte[] input = [.. LocalAddressFor(ServerA)?.GetAddressBytes() ?? [],
                        .. ServerA.GetAddressBytes()];

        var expected = HMACSHA256.HashData(Secret, input)[..8];

        Assert.That(cookies.For(ServerA), Is.EqualTo(expected));

    }

    /// <summary>
    /// The local address this host would use to reach that server, worked out the
    /// same way the implementation does: a connected UDP socket sends nothing and
    /// makes the kernel fill in the local endpoint from its routing table.
    /// </summary>
    private static IPAddress? LocalAddressFor(IPAddress ServerAddress)
    {

        try
        {

            using var socket = new Socket(ServerAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

            socket.Connect(ServerAddress, 53);

            return (socket.LocalEndPoint as IPEndPoint)?.Address;

        }
        catch (SocketException)
        {
            return null;
        }

    }

    #endregion

    #region The_Same_Server_Always_Gets_The_Same_Cookie()

    [Test]
    public void The_Same_Server_Always_Gets_The_Same_Cookie()
    {

        // Stability is what makes a server cookie worth keeping: a server cookie
        // is bound to the client cookie it was issued for, so a client cookie
        // that changed per query would throw the server's answer away with every
        // question and start the handshake over.
        var cookies = new DNSClientCookies(Secret);

        var first   = cookies.For(ServerA);

        Assert.Multiple(() => {

            for (var i = 0; i < 5; i++)
                Assert.That(cookies.For(ServerA), Is.EqualTo(first));

        });

    }

    #endregion

    #region Two_Servers_Get_Different_Cookies()

    [Test]
    public void Two_Servers_Get_Different_Cookies()
    {

        // §4.1: "In order to provide minimal authentication, a client MUST send
        // Client Cookies that will usually be different for any two servers at
        // different IP addresses." One server learning the value another sees
        // could replay it — which would make the cookie evidence of nothing.
        var cookies = new DNSClientCookies(Secret);

        Assert.That(cookies.For(ServerA), Is.Not.EqualTo(cookies.For(ServerB)));

    }

    #endregion

    #region Two_Clients_Get_Different_Cookies()

    [Test]
    public void Two_Clients_Get_Different_Cookies()
    {

        // The secret is what makes the value unguessable. Two clients on the same
        // host, talking to the same server, must not produce the same cookie —
        // otherwise anyone able to run a resolver could predict everybody else's.
        Assert.That(new DNSClientCookies().For(ServerA),
                    Is.Not.EqualTo(new DNSClientCookies().For(ServerA)));

    }

    #endregion

    #region A_Cookie_Is_Eight_Octets_And_Not_Constant()

    [Test]
    public void A_Cookie_Is_Eight_Octets_And_Not_Constant()
    {

        var cookie = new DNSClientCookies().For(ServerA);

        Assert.Multiple(() => {

            Assert.That(cookie, Has.Length.EqualTo(8), "RFC 7873 §4.1: the client cookie is 8 octets");
            Assert.That(cookie, Is.Not.EqualTo(new Byte[8]));

        });

    }

    #endregion

    #region A_Secret_Below_Sixty_Four_Bits_Is_Refused()

    [Test]
    public void A_Secret_Below_Sixty_Four_Bits_Is_Refused()
    {

        // §4.1: "This Client Secret SHOULD have at least 64 bits of entropy". A
        // shorter one makes the cookie guessable, and a guessable cookie is a
        // cookie that proves nothing when it comes back — the mechanism is still
        // there, still costing a round trip, and no longer buying anything.
        Assert.Multiple(() => {

            Assert.That(() => new DNSClientCookies(new Byte[7]), Throws.InstanceOf<ArgumentException>());
            Assert.That(() => new DNSClientCookies(new Byte[8]), Throws.Nothing);

        });

    }

    #endregion

    #region The_Option_Carries_The_Server_Half_When_There_Is_One()

    [Test]
    [Property("RFC", "7873 §5.1")]
    public void The_Option_Carries_The_Server_Half_When_There_Is_One()
    {

        var cookies      = new DNSClientCookies(Secret);
        var serverCookie = new Byte[16];
        Array.Fill(serverCookie, (Byte) 0x7B);

        var first        = cookies.OptionFor(ServerA);
        var later        = cookies.OptionFor(ServerA, serverCookie);

        Assert.Multiple(() => {

            Assert.That(first.HasServerCookie, Is.False, "the first query to a server has none to present");
            Assert.That(later.ServerCookie,    Is.EqualTo(serverCookie));

            Assert.That(later.ClientCookie,    Is.EqualTo(first.ClientCookie),
                        "and acquiring a server cookie does not change the client half — " +
                        "the server cookie is bound to it, so changing it would discard what was just learned");

        });

    }

    #endregion

}

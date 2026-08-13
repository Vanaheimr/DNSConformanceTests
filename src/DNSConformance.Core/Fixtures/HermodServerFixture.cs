using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.Core.Fixtures;

public sealed class HermodServerFixtureOptions
{

    public Boolean            EnableUdp           { get; init; } = true;

    public Boolean            EnableTcp           { get; init; } = true;

    public Boolean            EnableTls           { get; init; } = false;

    /// <summary>Bind 0.0.0.0 instead of 127.0.0.1 (required for WSL-based tools to reach the server).</summary>
    public Boolean            BindAllInterfaces   { get; init; } = false;

    /// <summary>Enable RFC 1035 §4.1.4 name compression in server responses.</summary>
    public Boolean            UseCompression      { get; init; } = false;

    public IDNSZoneStore?     Zone                { get; init; }

    public X509Certificate2?  Certificate         { get; init; }

    /// <summary>TSIG keys the server accepts (RFC 8945). Empty leaves TSIG inactive.</summary>
    public IEnumerable<TSIGKey>  TSIGKeys         { get; init; } = [];

    /// <summary>KEY records whose SIG(0) signatures the server accepts (RFC 2931). Empty leaves SIG(0) inactive.</summary>
    public IEnumerable<KEY>      SIG0Keys         { get; init; } = [];

    /// <summary>
    /// Bind UDP and TCP to one port number instead of two ephemeral ones.
    /// </summary>
    /// <remarks>
    /// What a real resolver assumes. A client that gets TC=1 retries the *same*
    /// endpoint over TCP (RFC 7766 §5) — it has one server address and one port,
    /// not a pair — so any tool driven from outside needs this the moment an
    /// answer stops fitting in a datagram. Which, for a signed zone, is most of
    /// them.
    /// </remarks>
    public Boolean               SharePortAcrossTransports { get; init; } = false;

    /// <summary>The key the server signs replies to SIG(0)-signed requests with. Null leaves them unsigned.</summary>
    public SIG0Key?              SIG0ResponseKey  { get; init; }

    /// <summary>The secret the server issues DNS Cookies with (RFC 7873). Null leaves cookies off.</summary>
    public Byte[]?               DNSCookieSecret  { get; init; }

    /// <summary>Whether a query must return a valid server cookie to be answered (RFC 7873 §5.2.3).</summary>
    public Boolean               RequireDNSCookies { get; init; }

}


/// <summary>
/// Starts a real Hermod <see cref="DNSServer"/> with the standard fixture zone
/// on ephemeral loopback ports (UDP / TCP / optionally TLS-DoT).
/// </summary>
public sealed class HermodServerFixture : IAsyncDisposable
{

    public DNSServer          Server        { get; }

    public IDNSZoneStore      Zone          { get; }

    public X509Certificate2?  Certificate   { get; }

    public UInt16             UdpPort       => Server.ActiveUDPUnicastSocket?.Port.ToUInt16() ?? 0;

    public UInt16             TcpPort       => Server.ActiveTCPUnicastSocket?.Port.ToUInt16() ?? 0;

    public UInt16             TlsPort       => Server.ActiveTLSUnicastSocket?.Port.ToUInt16() ?? 0;


    private HermodServerFixture(DNSServer Server, IDNSZoneStore Zone, X509Certificate2? Certificate)
    {
        this.Server       = Server;
        this.Zone         = Zone;
        this.Certificate  = Certificate;
    }


    public static async Task<HermodServerFixture> StartAsync(HermodServerFixtureOptions? Options = null)
    {

        Options ??= new HermodServerFixtureOptions();

        var zone         = Options.Zone ?? ZoneFixtures.CreateStandardZone();

        var bindAddress  = Options.BindAllInterfaces
                               ? IPv4Address.Any
                               : IPv4Address.Localhost;

        var certificate  = Options.EnableTls
                               ? Options.Certificate ?? TestCertificate.CreateServerCertificate()
                               : null;

        // With a shared port the same number has to be free in two port spaces at
        // once, so the first candidate may simply not be available — and on
        // Windows a Hyper-V reservation refuses a whole block rather than one
        // port, which is why the retries are spread rather than sequential.
        const Int32 attempts = 25;

        for (var attempt = 0; ; attempt++)
        {

            // Probe the candidate before handing it over. A shared port has to be
            // free in two port spaces at once, and on Windows large blocks of the
            // range are reserved by Hyper-V — a bind there fails with WSAEACCES,
            // "not yours" rather than "in use". Finding that out from a throwaway
            // socket costs microseconds; finding it out from DNSServer costs the
            // listener-startup deadline, because Start() reports a failed bind
            // only by never publishing an endpoint.
            var port = Options.SharePortAcrossTransports
                           ? IPPort.Parse((UInt16) FreeSharedPort())
                           : IPPort.Zero;

            var server = new DNSServer(

                             new AuthoritativeDNSRequestHandler(
                                 zone,
                                 DNSCookieSecret:    Options.DNSCookieSecret,
                                 RequireDNSCookies:  Options.RequireDNSCookies
                             ),

                             new DNSServerOptions {

                                 EnableUDPUnicast      = Options.EnableUdp,
                                 UDPUnicastSocket      = new IPSocket(bindAddress, port),

                                 EnableUDPMulticast    = false,

                                 EnableTCPUnicast      = Options.EnableTcp,
                                 TCPUnicastSocket      = new IPSocket(bindAddress, port),

                                 EnableTLSUnicast      = Options.EnableTls,
                                 TLSUnicastSocket      = new IPSocket(bindAddress, IPPort.Zero),
                                 TLSServerCertificate  = certificate,

                                 UseCompression        = Options.UseCompression,

                                 TSIGKeys              = Options.TSIGKeys,

                                 SIG0Keys              = Options.SIG0Keys,
                                 SIG0ResponseKey       = Options.SIG0ResponseKey

                             }

                         );

            try
            {
                await server.Start();
            }
            catch (SocketException) when (Options.SharePortAcrossTransports && attempt < attempts - 1)
            {
                await StopQuietly(server);
                continue;
            }

            // Start() does not report a failed bind synchronously: it kicks off a
            // listener task per transport, and each task binds its socket and
            // publishes the endpoint from inside. So "no exception" means only
            // that the tasks were started, and a port that could not be taken
            // leaves the socket unset and the port reading as 0 — an external
            // tool then gets "-p 0", times out, and the test blames the firewall.
            //
            // Waiting rather than checking once is what separates "not yet" from
            // "never": the endpoints appear a moment after Start() returns, and a
            // check without a deadline reports every server as broken.
            var bound = await WaitForListeners(server, Options, TimeSpan.FromSeconds(5));

            if (!bound && attempt < attempts - 1)
            {
                await StopQuietly(server);
                continue;
            }

            if (!bound)
                throw new InvalidOperationException(
                          $"The DNS server did not bind its listeners after {attempts} attempts" +
                          (Options.SharePortAcrossTransports
                               ? " — UDP and TCP were asked to share one port number."
                               : ".")
                      );

            return new HermodServerFixture(server, zone, certificate);

        }

    }


    /// <summary>
    /// A port number a UDP and a TCP socket could both take a moment ago.
    /// </summary>
    /// <remarks>
    /// The candidates are drawn at random rather than sequentially: consecutive
    /// ephemeral ports come from one narrow window, so a window that sits inside
    /// a reservation makes every retry fail identically.
    /// </remarks>
    private static Int32 FreeSharedPort(Int32 Attempts = 200)
    {

        for (var attempt = 0; attempt < Attempts; attempt++)
        {

            var candidate = Random.Shared.Next(20000, 60000);

            try
            {

                using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram,  ProtocolType.Udp);
                using var tcp = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                udp.Bind(new IPEndPoint(System.Net.IPAddress.Any, candidate));
                tcp.Bind(new IPEndPoint(System.Net.IPAddress.Any, candidate));

                return candidate;

            }
            catch (SocketException)
            {
                // Taken, or reserved. Try elsewhere in the range.
            }

        }

        throw new InvalidOperationException(
                  $"No port number was free for both UDP and TCP after {Attempts} probes."
              );

    }


    /// <summary>
    /// Stop a server that may never have started properly.
    /// </summary>
    /// <remarks>
    /// <c>Stop()</c> awaits the listener tasks, and a listener whose bind failed
    /// is a faulted task — so stopping a half-started server rethrows the very
    /// exception that made it half-started, out of the cleanup path, replacing
    /// whatever the caller was doing about it. Which is how a retry loop ends up
    /// propagating the failure it exists to retry.
    /// </remarks>
    private static async Task StopQuietly(DNSServer Server)
    {
        try
        {
            await Server.Stop();
        }
        catch (Exception)
        { }
    }


    /// <summary>
    /// Wait until every enabled listener has published its endpoint, or the
    /// deadline passes.
    /// </summary>
    private static async Task<Boolean> WaitForListeners(DNSServer                   Server,
                                                        HermodServerFixtureOptions  Options,
                                                        TimeSpan                    Deadline)
    {

        var until = DateTimeOffset.UtcNow + Deadline;

        while (true)
        {

            if ((!Options.EnableUdp || Server.ActiveUDPUnicastSocket is not null) &&
                (!Options.EnableTcp || Server.ActiveTCPUnicastSocket is not null) &&
                (!Options.EnableTls || Server.ActiveTLSUnicastSocket is not null))
            {
                return true;
            }

            if (DateTimeOffset.UtcNow >= until)
                return false;

            await Task.Delay(20);

        }

    }


    public async ValueTask DisposeAsync()
    {
        await Server.Stop();
        Certificate?.Dispose();
    }

}

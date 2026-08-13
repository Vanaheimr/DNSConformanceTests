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

    /// <summary>The key the server signs replies to SIG(0)-signed requests with. Null leaves them unsigned.</summary>
    public SIG0Key?              SIG0ResponseKey  { get; init; }

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

        var server = new DNSServer(

                         new AuthoritativeDNSRequestHandler(zone),

                         new DNSServerOptions {

                             EnableUDPUnicast      = Options.EnableUdp,
                             UDPUnicastSocket      = new IPSocket(bindAddress, IPPort.Zero),

                             EnableUDPMulticast    = false,

                             EnableTCPUnicast      = Options.EnableTcp,
                             TCPUnicastSocket      = new IPSocket(bindAddress, IPPort.Zero),

                             EnableTLSUnicast      = Options.EnableTls,
                             TLSUnicastSocket      = new IPSocket(bindAddress, IPPort.Zero),
                             TLSServerCertificate  = certificate,

                             UseCompression        = Options.UseCompression,

                             TSIGKeys              = Options.TSIGKeys,

                             SIG0Keys              = Options.SIG0Keys,
                             SIG0ResponseKey       = Options.SIG0ResponseKey

                         }

                     );

        await server.Start();

        return new HermodServerFixture(server, zone, certificate);

    }


    public async ValueTask DisposeAsync()
    {
        await Server.Stop();
        Certificate?.Dispose();
    }

}

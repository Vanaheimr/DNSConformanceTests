using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

namespace DNSConformance.Core.Fixtures;

public sealed class HermodDoHFixtureOptions
{

    /// <summary>
    /// Serve over TLS through a <see cref="DNSServer"/>, the shape RFC 8484 §5
    /// requires of a deployment: "This protocol MUST be used with the https URI
    /// scheme."
    /// </summary>
    /// <remarks>
    /// False by default, which starts the same endpoint on cleartext HTTP. That
    /// is deliberate and mirrors <c>ScriptedDoHServer</c> on the client side: the
    /// requirements under test here are HTTP-layer ones — methods, media types,
    /// status codes, cache metadata — and running them through TLS would only
    /// put a handshake between the assertion and the thing asserted. One test
    /// sets this to true, so that the deployed shape is covered too.
    /// </remarks>
    public Boolean            Secured      { get; init; }

    public IDNSZoneStore?     Zone         { get; init; }

    /// <summary>
    /// The path to answer on. Null takes Hermod's default, <c>/dns-query</c>.
    /// </summary>
    public HTTPPath?          Path         { get; init; }

    /// <summary>
    /// TSIG keys the server accepts (RFC 8945). Empty leaves TSIG inactive.
    /// </summary>
    public IEnumerable<TSIGKey>  TSIGKeys  { get; init; } = [];

}


/// <summary>
/// Starts Hermod's RFC 8484 endpoint on an ephemeral loopback port — either
/// standalone in cleartext, or over TLS as a listener of a real
/// <see cref="DNSServer"/>.
/// </summary>
public sealed class HermodDoHFixture : IAsyncDisposable
{

    private readonly DNSServer?           dnsServer;
    private readonly DNSOverHTTPSServer?  dohServer;

    /// <summary>
    /// The zone being served.
    /// </summary>
    public IDNSZoneStore      Zone         { get; }

    public X509Certificate2?  Certificate  { get; }

    /// <summary>
    /// The port the endpoint bound.
    /// </summary>
    public UInt16             Port         { get; }

    /// <summary>
    /// The RFC 8484 endpoint, ready to be handed to <see cref="RawDoHProbe"/>.
    /// </summary>
    public String             Url          { get; }

    /// <summary>
    /// The origin, for the tests that ask for a path this server does not serve.
    /// </summary>
    public String             Origin       { get; }


    private HermodDoHFixture(DNSServer?           DNSServer,
                             DNSOverHTTPSServer?  DoHServer,
                             IDNSZoneStore        Zone,
                             X509Certificate2?    Certificate,
                             UInt16               Port,
                             HTTPPath             Path,
                             Boolean              Secured)
    {

        this.dnsServer    = DNSServer;
        this.dohServer    = DoHServer;
        this.Zone         = Zone;
        this.Certificate  = Certificate;
        this.Port         = Port;
        this.Origin       = $"{(Secured ? "https" : "http")}://127.0.0.1:{Port}";
        this.Url          = $"{Origin}{Path}";

    }


    public static async Task<HermodDoHFixture> StartAsync(HermodDoHFixtureOptions? Options = null)
    {

        Options ??= new HermodDoHFixtureOptions();

        var zone         = Options.Zone ?? ZoneFixtures.CreateStandardZone();
        var path         = Options.Path ?? DNSOverHTTPSServer.DefaultDNSQueryPath;
        var handler      = new AuthoritativeDNSRequestHandler(zone);

        var certificate  = Options.Secured
                               ? TestCertificate.CreateServerCertificate()
                               : null;

        if (Options.Secured)
        {

            var dnsServer = new DNSServer(
                                handler,
                                new DNSServerOptions {
                                    EnableUDPUnicast      = false,
                                    EnableUDPMulticast    = false,
                                    EnableTCPUnicast      = false,
                                    EnableTLSUnicast      = false,
                                    EnableHTTPSUnicast    = true,
                                    HTTPSUnicastSocket    = new IPSocket(IPv4Address.Localhost, IPPort.Zero),
                                    HTTPSPath             = path,
                                    TLSServerCertificate  = certificate,
                                    TSIGKeys              = Options.TSIGKeys
                                }
                            );

            await dnsServer.Start();

            var socket = dnsServer.ActiveHTTPSUnicastSocket
                             ?? throw new InvalidOperationException("The DoH listener did not publish an endpoint.");

            return new HermodDoHFixture(
                       dnsServer,
                       null,
                       zone,
                       certificate,
                       socket.Port.ToUInt16(),
                       path,
                       Secured: true
                   );

        }

        var dohServer = await DNSOverHTTPSServer.StartNew(
                                  handler,
                                  new DNSServerOptions {
                                      TSIGKeys = Options.TSIGKeys
                                  },
                                  IPv4Address.Localhost,
                                  IPPort.Zero,
                                  path
                              );

        return new HermodDoHFixture(
                   null,
                   dohServer,
                   zone,
                   null,
                   dohServer.TCPPort.ToUInt16(),
                   path,
                   Secured: false
               );

    }


    public async ValueTask DisposeAsync()
    {

        if (dnsServer is not null)
            await dnsServer.Stop();

        if (dohServer is not null)
            await dohServer.Stop();

        Certificate?.Dispose();

    }

}

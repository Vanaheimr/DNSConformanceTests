using System.Net;
using System.Net.Http;
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

    /// <summary>
    /// Serve over HTTP/2 instead of HTTP/1.1 — the version RFC 8484 §5.2 calls
    /// "the minimum RECOMMENDED version of HTTP for use with DoH".
    /// </summary>
    /// <remarks>
    /// Combined with <see cref="Secured"/> this is h2 with ALPN; on its own it
    /// is cleartext h2c with prior knowledge (RFC 9113 §3.3), which is what lets
    /// the RFC 8484 assertions run over both versions without a handshake in the
    /// way of either.
    /// </remarks>
    public Boolean            HTTP2        { get; init; }

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
    private readonly DNSOverHTTP2Server?  doh2Server;

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

    /// <summary>
    /// The HTTP version this endpoint speaks.
    /// </summary>
    public Version            HTTPVersion  { get; }

    /// <summary>
    /// A client pinned to this endpoint's HTTP version.
    /// </summary>
    /// <remarks>
    /// Pinned with <c>RequestVersionExact</c> rather than left to negotiate: a
    /// test aimed at the HTTP/2 listener that quietly fell back to HTTP/1.1
    /// would still pass, and would be measuring the wrong server. Hand this to
    /// <see cref="RawDoHProbe"/> and a fall back becomes an exception instead.
    /// </remarks>
    public HttpClient         Http         { get; }


    private HermodDoHFixture(DNSServer?           DNSServer,
                             DNSOverHTTPSServer?  DoHServer,
                             DNSOverHTTP2Server?  DoH2Server,
                             IDNSZoneStore        Zone,
                             X509Certificate2?    Certificate,
                             UInt16               Port,
                             HTTPPath             Path,
                             Boolean              Secured,
                             Boolean              HTTP2)
    {

        this.dnsServer    = DNSServer;
        this.dohServer    = DoHServer;
        this.doh2Server   = DoH2Server;
        this.Zone         = Zone;
        this.Certificate  = Certificate;
        this.Port         = Port;
        this.Origin       = $"{(Secured ? "https" : "http")}://127.0.0.1:{Port}";
        this.Url          = $"{Origin}{Path}";
        this.HTTPVersion  = HTTP2 ? System.Net.HttpVersion.Version20 : System.Net.HttpVersion.Version11;

        this.Http         = new HttpClient(
                                new HttpClientHandler {
                                    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
                                }
                            ) {
                                DefaultRequestVersion  = HTTPVersion,
                                DefaultVersionPolicy   = HttpVersionPolicy.RequestVersionExact,
                                Timeout                = TimeSpan.FromSeconds(10)
                            };

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
                                    EnableHTTPSUnicast    = !Options.HTTP2,
                                    HTTPSUnicastSocket    = new IPSocket(IPv4Address.Localhost, IPPort.Zero),
                                    EnableHTTP2Unicast    =  Options.HTTP2,
                                    HTTP2UnicastSocket    = new IPSocket(IPv4Address.Localhost, IPPort.Zero),
                                    HTTPSPath             = path,
                                    TLSServerCertificate  = certificate,
                                    TSIGKeys              = Options.TSIGKeys
                                }
                            );

            await dnsServer.Start();

            var socket = (Options.HTTP2
                              ? dnsServer.ActiveHTTP2UnicastSocket
                              : dnsServer.ActiveHTTPSUnicastSocket)
                             ?? throw new InvalidOperationException("The DoH listener did not publish an endpoint.");

            return new HermodDoHFixture(
                       dnsServer,
                       null,
                       null,
                       zone,
                       certificate,
                       socket.Port.ToUInt16(),
                       path,
                       Secured: true,
                       HTTP2:   Options.HTTP2
                   );

        }

        var dnsOptions = new DNSServerOptions {
                             TSIGKeys = Options.TSIGKeys
                         };

        if (Options.HTTP2)
        {

            var doh2Server = await DNSOverHTTP2Server.StartNew(
                                       handler,
                                       dnsOptions,
                                       IPv4Address.Localhost,
                                       IPPort.Zero,
                                       path
                                   );

            return new HermodDoHFixture(
                       null,
                       null,
                       doh2Server,
                       zone,
                       null,
                       doh2Server.TCPPort.ToUInt16(),
                       path,
                       Secured: false,
                       HTTP2:   true
                   );

        }

        var dohServer = await DNSOverHTTPSServer.StartNew(
                                  handler,
                                  dnsOptions,
                                  IPv4Address.Localhost,
                                  IPPort.Zero,
                                  path
                              );

        return new HermodDoHFixture(
                   null,
                   dohServer,
                   null,
                   zone,
                   null,
                   dohServer.TCPPort.ToUInt16(),
                   path,
                   Secured: false,
                   HTTP2:   false
               );

    }


    public async ValueTask DisposeAsync()
    {

        if (dnsServer is not null)
            await dnsServer.Stop();

        if (dohServer is not null)
            await dohServer.Stop();

        if (doh2Server is not null)
            await doh2Server.Stop();

        Http.Dispose();
        Certificate?.Dispose();

    }

}

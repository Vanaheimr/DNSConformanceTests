using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// What the constructors of the two encrypted clients promise before a single
/// query is asked: that the transport is encrypted, and that recursion is asked
/// for unless the caller says otherwise.
/// </summary>
/// <remarks>
/// <para>
/// Each of these clients has more than one constructor, and each constructor
/// writes its own defaults rather than delegating to another. The suite built
/// its DoH clients from a URL and its DoT clients from an address, so the
/// defaults of the other constructors were defaults nobody took.
/// </para>
/// <para>
/// Encryption is the one that matters. RFC 8484 §5: "This protocol MUST be used
/// with the https URI scheme". A DoH client built from an address has no URI to
/// say so, which is exactly why it has to say it itself — and RFC 8310 §5's
/// Strict Privacy profile, under which "A hard failure occurs if this is not
/// available", is the only behaviour a client offering no profile choice can
/// have: a privacy transport that quietly speaks clear text is worse than none,
/// because its caller believes otherwise.
/// </para>
/// </remarks>
[TestFixture]
public class EncryptedClientConstructionTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(3);


    private static Byte[] OneAddress(Byte[] Request)
        => RawDnsResponder.Answer(Request, ($"{RawDnsReader.Parse(Request).Questions[0].Name.Canonical}.", RawDnsType.A, 60, [192, 0, 2, 7]));

    #endregion


    #region DoH: never in the clear (RFC 8484 §5)

    [Test]
    [Property("RFC", "8484 §5, 8310 §5")]
    public async Task A_Doh_Client_Built_From_An_Address_Never_Asks_In_The_Clear()
    {

        // A plain-HTTP DoH endpoint, which answers anything it is sent in clear
        // text. A client honouring RFC 8484 §5 opens TLS towards it, the
        // handshake meets an HTTP server, and no question is ever read. A client
        // that did not would be answered — that answer is the failure.
        await using var peer   = new ScriptedDoHServer(OneAddress);

        await using var client = new DNSHTTPSClient(IPv4Address.Localhost,
                                                    IPPort.Parse((UInt16) peer.Port),
                                                    QueryTimeout:    Timeout,
                                                    ConnectTimeout:  Timeout);

        var info = await client.Query(DNSServiceName.Parse("clear.example."), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.Multiple(() => {
            Assert.That(peer.Exchanges, Is.Empty,
                        "the question never reached the server in clear text");
            Assert.That(info.Answers,   Is.Empty,
                        "so there is no answer to report");
        });

    }


    [Test]
    [Property("RFC", "8484 §5, 8310 §5")]
    public async Task A_Doh_Client_Built_From_A_Port_Alone_Never_Asks_In_The_Clear()
    {

        // The same promise from the constructor that takes only a port and talks
        // to this machine. Loopback is no exemption: RFC 8484 §5 makes no
        // exception for it, and a local forwarder is still a different process
        // that a caller chose to reach over TLS.
        await using var peer   = new ScriptedDoHServer(OneAddress);

        await using var client = new DNSHTTPSClient(IPPort.Parse((UInt16) peer.Port),
                                                    QueryTimeout:    Timeout,
                                                    ConnectTimeout:  Timeout);

        var info = await client.Query(DNSServiceName.Parse("loopback.example."), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.Multiple(() => {
            Assert.That(peer.Exchanges, Is.Empty, "no question in clear text, to this machine either");
            Assert.That(info.Answers,   Is.Empty);
        });

    }

    #endregion

    #region DoT: TLS whatever the URL says (RFC 7858 §3.1, 8310 §5)

    [Test]
    [Property("RFC", "7858 §3.1, 8310 §5")]
    public async Task A_Dot_Client_Speaks_Tls_Whatever_Its_Url_Scheme_Says()
    {

        // A URL whose scheme says nothing about TLS. RFC 7858 §3.1 does not leave
        // that to the scheme: "The first data exchange on this TCP connection
        // MUST be the client and server initiating a TLS handshake". The client is
        // a DNS-over-TLS client, so the handshake is its first act whatever the
        // URL says — and against a TLS server, a client that does it is answered
        // and one that does not is not.
        await using var server = new ScriptedTlsServer(OneAddress);

        await using var client = new DNSTLSClient(URL.Parse($"tcp://127.0.0.1:{server.Port}"),
                                                  QueryTimeout:                Timeout,
                                                  RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success());

        var info = await client.Query(DNSServiceName.Parse("tcpscheme.example."), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.Multiple(() => {
            Assert.That(server.HandshakeCount, Is.GreaterThanOrEqualTo(1), "a TLS handshake took place");
            Assert.That(info.Answers.Count(),  Is.EqualTo(1),              "and the question was answered over it");
        });

    }

    #endregion


    #region Recursion is asked for unless the caller says otherwise (RFC 1035 §4.1.1)

    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public void Every_Encrypted_Client_Constructor_Starts_Out_Asking_For_Recursion()
    {

        // Five constructors, five copies of the same `?? true`. Read off the
        // property, because three of them could only be watched on the wire
        // through a TLS endpoint this file does not need to build: the test below
        // takes the wire for the two that can be reached in clear.
        using var dohByPort     = new DNSHTTPSClient(IPPort.Parse((UInt16) 1));
        using var dohByAddress  = new DNSHTTPSClient(IPv4Address.Localhost, IPPort.Parse((UInt16) 1));
        using var dohByURL      = new DNSHTTPSClient(URL.Parse("https://127.0.0.1:1/dns-query"));
        using var dotByAddress  = new DNSTLSClient  (IPv4Address.Localhost, IPPort.Parse((UInt16) 1));
        using var dotByURL      = new DNSTLSClient  (URL.Parse("tls://127.0.0.1:1"));

        Assert.Multiple(() => {
            Assert.That(dohByPort.   RecursionDesired, Is.True, "DNSHTTPSClient(port, ...)");
            Assert.That(dohByAddress.RecursionDesired, Is.True, "DNSHTTPSClient(address, ...)");
            Assert.That(dohByURL.    RecursionDesired, Is.True, "DNSHTTPSClient(URL, ...)");
            Assert.That(dotByAddress.RecursionDesired, Is.True, "DNSTLSClient(address, ...)");
            Assert.That(dotByURL.    RecursionDesired, Is.True, "DNSTLSClient(URL, ...)");
        });

    }


    [Test]
    [Property("RFC", "1035 §4.1.1")]
    public async Task A_Client_Built_From_A_URL_Asks_For_Recursion_On_The_Wire()
    {

        // The two URL constructors, watched where the bit actually goes: RD set
        // in the query each one sends, with nothing said about recursion anywhere
        // — not to the constructor, not to the query.
        await using var doh      = new ScriptedDoHServer(OneAddress);
        await using var dot      = new ScriptedTlsServer(OneAddress);

        await using var dohClient = new DNSHTTPSClient(URL.Parse(doh.Url), QueryTimeout: Timeout);
        await using var dotClient = new DNSTLSClient  (URL.Parse($"tls://127.0.0.1:{dot.Port}"),
                                                       QueryTimeout:                Timeout,
                                                       RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success());

        await dohClient.Query(DNSServiceName.Parse("dohurl.example."), [ DNSResourceRecordTypes.A ], Timeout);
        await dotClient.Query(DNSServiceName.Parse("doturl.example."), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.That(doh.Exchanges, Has.Count.EqualTo(1), "the DoH query arrived");
        Assert.That(dot.Requests,  Has.Count.EqualTo(1), "and so did the DoT query");

        Assert.Multiple(() => {
            Assert.That(RawDnsReader.Parse(doh.Exchanges.Single().DnsMessage).RD, Is.True, "DoH: RD set");
            Assert.That(RawDnsReader.Parse(dot.Requests. Single()).           RD, Is.True, "DoT: RD set");
        });

    }

    #endregion

}

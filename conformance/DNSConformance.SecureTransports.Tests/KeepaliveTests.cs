using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.SecureTransports.Tests;

/// <summary>
/// RFC 7828 — the edns-tcp-keepalive EDNS(0) option — measured on the wire
/// rather than in the type that models it.
/// </summary>
/// <remarks>
/// <para>
/// The option's *encoding* is already pinned by
/// <c>DNSConformance.Edns.Tests.EdnsOptionPolicyTests</c>. What that file cannot
/// answer is whether any client ever puts one on the wire, or could ever read
/// one back — and both Hermod clients that expose a
/// <c>ServerKeepaliveTimeout</c> property fill it in from a response option
/// nothing in the client ever asks for.
/// </para>
/// <para>
/// RFC 7828 does not make asking a precondition. §3.2.1 offers the query option
/// as a MAY, and §3.3.2 lets a server volunteer the timeout to any TCP query
/// carrying an OPT RR. So the question is not "does the client ask" but "does
/// the client emit an OPT RR at all", which is what these tests measure — with
/// the suite's own reader, never with Hermod's.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "7828")]
public class KeepaliveTests
{

    #region Data

    /// <summary>RFC 7828 §3.1: "OPTION-CODE: the EDNS0 option code assigned to edns-tcp-keepalive, 11".</summary>
    private const UInt16 KeepaliveOptionCode = 11;

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    #endregion

    #region (private) KeepaliveOption(Timeout100ms)

    /// <summary>
    /// An EDNS option blob carrying one edns-tcp-keepalive option, in the
    /// response form: RFC 7828 §3.1 gives OPTION-LENGTH "the value 2" when the
    /// TIMEOUT is present, "specified in units of 100 milliseconds, encoded in
    /// network byte order".
    /// </summary>
    private static Byte[] KeepaliveOption(UInt16 Timeout100ms)

        => [
               0x00, 0x0B,                              // OPTION-CODE  = 11
               0x00, 0x02,                              // OPTION-LENGTH = 2
               (Byte) (Timeout100ms >> 8),
               (Byte) (Timeout100ms & 0xFF)
           ];

    #endregion

    #region (private) AnswerWithKeepalive(Request, Timeout100ms)

    /// <summary>
    /// An ordinary answer whose OPT record carries an edns-tcp-keepalive option
    /// the client never asked for — which is precisely what RFC 7828 §3.3.2
    /// permits a server to send.
    /// </summary>
    private static Byte[] AnswerWithKeepalive(Byte[]  Request,
                                              UInt16  Timeout100ms)
    {

        var query          = RawDnsReader.Parse(Request, RawDnsReaderOptions.Lenient);
        var question       = query.Questions[0];
        var questionBytes  = Request[12..(12 + question.Name.WireLength + 4)];

        return new RawDnsWriter().
                   Header(query.Id,
                          RawDnsFlags.QR | RawDnsFlags.RD | RawDnsFlags.RA,
                          1, 1, 0, 1).
                   Bytes(questionBytes).
                   RR("keepalive.example.", RawDnsType.A, RawDnsClass.IN, 300, RawDnsWriter.IPv4("192.0.2.28")).
                   Opt(1232, options: KeepaliveOption(Timeout100ms)).
                   ToArray();

    }

    #endregion

    #region (private) OptOf(Message)

    /// <summary>The OPT record of a message, as the suite's own reader sees it.</summary>
    private static RawEdns? OptOf(Byte[] Message)
    {

        var opt = RawDnsReader.Parse(Message, RawDnsReaderOptions.Lenient).
                      Additionals.
                      FirstOrDefault(rr => rr.IsOpt);

        return opt is null
                   ? null
                   : RawEdns.From(opt);

    }

    #endregion

    #region (private) NewDoTClient(Port)

    private static DNSTLSClient NewDoTClient(Int32 Port)

        => new (IPv4Address.Localhost,
                TCPPort:                     IPPort.Parse((UInt16) Port),
                QueryTimeout:                Timeout,
                RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success());

    #endregion


    #region A_DoT_Query_Carries_An_Opt_Record_But_No_Keepalive_Option()

    [Test]
    [Property("RFC", "7828 §3.2.1, §3.3.2")]
    public async Task A_DoT_Query_Carries_An_Opt_Record_But_No_Keepalive_Option()
    {

        // Not asking is conformant. RFC 7828 §3.2.1: "DNS clients MAY include
        //  the edns-tcp-keepalive option in the first query sent to a server
        //  using TCP transport to signal their desire to keep the connection
        //  open when idle." A MAY, so silence deviates from nothing.
        //
        // What the server's freedom actually rests on is the OPT record, not the
        // option. RFC 7828 §3.3.2: "A DNS server that receives a query sent
        //  using TCP transport that includes an OPT RR (with or without the
        //  edns-tcp-keepalive option) MAY include the edns-tcp-keepalive option
        //  in the response to signal the expected idle timeout on a connection."
        //
        // So this one assertion decides whether ServerKeepaliveTimeout is
        // reachable at all on this transport.
        await using var server = new ScriptedTlsServer(
            request => RawDnsResponder.Answer(request, ("keepalive.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.28")))
        );

        await using var client = NewDoTClient(server.Port);

        await client.Query<A>(DomainName.Parse("keepalive.example."), Timeout: Timeout);

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the DoT listener received a query");

        var edns = OptOf(request!);

        Assert.Multiple(() => {

            Assert.That(edns,                                                    Is.Not.Null,
                        "RFC 7828 §3.3.2: an OPT RR in the query is what lets the server volunteer a timeout");

            Assert.That(edns!.Options.Any(option => option.Code == KeepaliveOptionCode), Is.False,
                        "and the client does not ask for one — §3.2.1 makes that a MAY");

        });

    }

    #endregion

    #region A_DoT_Client_Reads_A_Keepalive_Timeout_It_Never_Asked_For()

    [Test]
    [Property("RFC", "7828 §3.3.2")]
    public async Task A_DoT_Client_Reads_A_Keepalive_Timeout_It_Never_Asked_For()
    {

        // The other half of §3.3.2, from the client's side: a timeout arrives
        // unsolicited, and the property that models it is filled in. Together
        // with the test above this settles the "dead code?" question for DoT —
        // the value is reachable against a server doing nothing unusual.
        //
        // 300 * 100 ms = 30 s. RFC 7828 §3.1: TIMEOUT is "an idle timeout value
        //  for the TCP connection, specified in units of 100 milliseconds,
        //  encoded in network byte order."
        await using var server = new ScriptedTlsServer(
            request => AnswerWithKeepalive(request, 300)
        );

        await using var client = NewDoTClient(server.Port);

        await client.Query<A>(DomainName.Parse("keepalive.example."), Timeout: Timeout);

        Assert.That(client.ServerKeepaliveTimeout, Is.EqualTo(TimeSpan.FromSeconds(30)),
                    "the server's advertised idle timeout reaches the caller");

    }

    #endregion

    #region A_DoT_Client_Stops_Using_A_Connection_The_Server_Asked_It_To_Close()

    [Test]
    [Property("RFC", "7828 §3.2.2")]
    public async Task A_DoT_Client_Stops_Using_A_Connection_The_Server_Asked_It_To_Close()
    {

        // RFC 7828 §3.2.2: "A DNS client that receives a response that includes
        //  the edns-tcp-keepalive option with a TIMEOUT value of 0 SHOULD send
        //  no more queries on that connection and initiate closing the
        //  connection as soon as it has received all outstanding responses."
        //
        // A timeout of 0 is the server's way of saying it is out of room — RFC
        // 7828 §3.3.2: "The DNS server SHOULD send an edns-tcp-keepalive option
        //  with a timeout of 0 if it deems its local resources are too low to
        //  service more TCP keepalive sessions or if it wants clients to close
        //  currently open connections."
        //
        // DNSTLSClient holds one TLS session and reuses it across queries, so
        // the handshake count is what tells the two behaviours apart: a client
        // that honoured the 0 has to handshake again for the second query.
        await using var server = new ScriptedTlsServer(
            request => AnswerWithKeepalive(request, 0)
        );

        await using var client = NewDoTClient(server.Port);

        await client.Query<A>(DomainName.Parse("keepalive.example."), Timeout: Timeout);

        Assert.That(client.ServerKeepaliveTimeout, Is.EqualTo(TimeSpan.Zero),
                    "the client read the 0 the server sent");

        await client.Query<A>(DomainName.Parse("keepalive.example."), Timeout: Timeout);

        TestContext.Out.WriteLine($"{server.HandshakeCount} TLS handshake(s) for two queries");

        Assert.That(server.HandshakeCount, Is.EqualTo(2),
                    "the second query may not travel on the connection the server asked the client to close");

    }

    #endregion

    #region A_TCP_Query_Carries_An_Opt_Record()

    [Test]
    [Property("RFC", "7828 §3.3.2, 3225 §3")]
    public async Task A_TCP_Query_Carries_An_Opt_Record()
    {

        // DNSTCPClient exposes ServerKeepaliveTimeout, an EDNSOptions list
        // documented as "included in every DNS query", and a DnssecOK flag.
        // None of the three can reach the wire while the query carries no OPT
        // record — and for the keepalive property that is terminal, because RFC
        // 7828 §3.3.2 conditions the server's licence on the query having one:
        // "A DNS server that receives a query sent using TCP transport that
        //  includes an OPT RR (with or without the edns-tcp-keepalive option)
        //  MAY include the edns-tcp-keepalive option in the response".
        //
        // The client is set up here to ask for everything at once, so a failure
        // names the cause rather than one symptom of it.
        await using var server = new ScriptedTcpServer(
            request => RawDnsResponder.Answer(request, ("keepalive.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.28")))
        );

        await using var client = new DNSTCPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) server.Port),
                                     QueryTimeout: Timeout
                                 );

        client.DnssecOK = true;
        client.EDNSOptions.Add(EDNSKeepaliveOption.CreateQuery());

        await client.Query<A>(DomainName.Parse("keepalive.example."), Timeout: Timeout);

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the TCP listener received a query");

        var edns = OptOf(request!);

        Assert.Multiple(() => {

            Assert.That(edns,                                                     Is.Not.Null,
                        "a client with DnssecOK and an EDNS option set has to send an OPT record to carry them");

            Assert.That(edns?.Do,                                                 Is.True,
                        "RFC 3225 §3: DnssecOK = true is the most significant bit of the OPT flags");

            Assert.That(edns?.Options.Any(option => option.Code == KeepaliveOptionCode), Is.True,
                        "RFC 7828 §3.2.1: a keepalive option the caller supplied belongs on a TCP query");

        });

    }

    #endregion

    #region A_Resolver_Routing_Over_TCP_Still_Asks_For_DNSSEC()

    [Test]
    [Property("RFC", "3225 §3, 6891 §6.2.2")]
    public async Task A_Resolver_Routing_Over_TCP_Still_Asks_For_DNSSEC()
    {

        // The test above sets the properties on the transport client by hand,
        // which invites the reply "no caller does that". This one comes in
        // through the front door: DNSClient copies its own DnssecOK onto
        // whichever transport client it picked, and pushes the DNS Cookie it
        // manages into that client's EDNSOptions. Both land in a client that
        // sends no OPT record, and both are lost without a word.
        //
        // The bit has exactly one home. RFC 3225 §3: "The mechanism chosen for
        //  the explicit notification of the ability of the client to accept (if
        //  not understand) DNSSEC security RRs is using the most significant bit
        //  of the Z field on the EDNS0 OPT header in the query." No OPT header,
        //  no bit — and RFC 6891 §6.2.2 spells out that there is no way around
        //  it: "if DNSSEC or any future option using EDNS is required, no
        //  fallback should be performed, as these options are only signaled
        //  through EDNS."
        //
        // What a query without the bit asks for is the opposite of what this
        // caller wants. RFC 3225 §3: "The DO bit cleared (set to zero) indicates
        //  the resolver is unprepared to handle DNSSEC security RRs and those
        //  RRs MUST NOT be returned in the response (unless DNSSEC security RRs
        //  are explicitly queried for)."
        await using var server = new ScriptedTcpServer(
            request => RawDnsResponder.Answer(request, ("keepalive.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.28")))
        );

        // Disposed: DNSClient pools its TCP transport client and holds the
        // connection open, so letting it fall out of scope leaves a live socket
        // on a listener the next test may reuse the port of.
        using var client = new DNSClient(
                               [ new DNSServerConfig(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) server.Port),
                                     DNSTransport.TCP
                                 ) ],
                               QueryTimeout:   Timeout,
                               UseQueryCache:  false
                           ) {
                               DnssecOK = true
                           };

        await client.Query(DNSServiceName.Parse("keepalive.example."), [ DNSResourceRecordTypes.A ], Timeout);

        Assert.That(server.Requests.TryDequeue(out var request), Is.True, "the TCP listener received a query");

        var edns = OptOf(request!);

        Assert.Multiple(() => {

            Assert.That(edns,      Is.Not.Null,
                        "a resolver that asked for DNSSEC has to put an OPT record on the wire to say so");

            Assert.That(edns?.Do,  Is.True,
                        "RFC 3225 §3: the DO bit is how the request is made");

        });

    }

    #endregion

    #region A_DoH_Query_Carries_An_Opt_Record()

    [Test]
    [Property("RFC", "8484 §6, §10, 3225 §3")]
    public async Task A_DoH_Query_Carries_An_Opt_Record()
    {

        // Keepalive itself does not belong here. RFC 8484 §10: "Many extensions
        //  to DNS, using [RFC6891], have been defined over the years.
        //  Extensions that are specific to the choice of transport, such as
        //  [RFC7828], are not applicable to DoH." DNSHTTPSClient having no
        //  ServerKeepaliveTimeout is therefore right rather than an omission.
        //
        // The OPT record itself very much does belong. RFC 8484 §6: "DoH clients
        //  using this media type MAY have one or more Extension Mechanisms for
        //  DNS (EDNS) options [RFC6891] in the request." And the DO bit has no
        //  other home: RFC 3225 §3 puts it in the OPT record's flags, so a
        //  DoH client that emits no OPT cannot ask for DNSSEC at all.
        await using var server = new ScriptedDoHServer(
            request => RawDnsResponder.Answer(request, ("keepalive.example.", RawDnsType.A, 300, RawDnsWriter.IPv4("192.0.2.28")))
        );

        await using var client = new DNSHTTPSClient(
                                     URL.Parse(server.Url),
                                     Mode:          DNSHTTPSMode.POST,
                                     QueryTimeout:  Timeout
                                 );

        client.DnssecOK = true;

        await client.Query<A>(DomainName.Parse("keepalive.example."), Timeout: Timeout);

        Assert.That(server.Exchanges.TryDequeue(out var exchange), Is.True, "the DoH endpoint received a request");

        var edns = OptOf(exchange!.DnsMessage);

        Assert.Multiple(() => {

            Assert.That(edns,      Is.Not.Null,
                        "RFC 8484 §6: a DoH request is an ordinary DNS message and may carry EDNS options");

            Assert.That(edns?.Do,  Is.True,
                        "RFC 3225 §3: DnssecOK = true has nowhere to go but the OPT record's flags");

        });

    }

    #endregion

    #region The_TCP_Retry_Of_A_Truncated_UDP_Query_Carries_Its_Opt_Record()

    [Test]
    [Property("RFC", "7828 §3.2.2, §3.3.2")]
    public async Task The_TCP_Retry_Of_A_Truncated_UDP_Query_Carries_Its_Opt_Record()
    {

        // DNSUDPClient's TCP fallback re-sends the message that was built for
        // the datagram, OPT record and all, so the retry meets §3.3.2's
        // condition and a server may answer it with a keepalive option. The
        // client models no such property and ignores what arrives, which §3.2.2
        // allows — the option only ever grants a client permission: "A DNS
        // client that receives a response using TCP transport that includes the
        // edns-tcp-keepalive option MAY keep the existing TCP session open when
        // it is idle."
        //
        // It has nothing to keep open in any case: the fallback socket is opened
        // for one exchange and closed after it. So the ignored option costs
        // nothing here, and this test says so rather than leaving the transport
        // unmeasured.
        var (udpServer, tcpServer) = await ScriptedServerPair.CreateAsync(
            UdpResponder: request => RawDnsResponder.Truncated(request),
            TcpResponder: request => AnswerWithKeepalive(request, 300)
        );

        await using var udp = udpServer;
        await using var tcp = tcpServer;

        await using var client = new DNSUDPClient(
                                     IPv4Address.Localhost,
                                     IPPort.Parse((UInt16) udp.Port),
                                     QueryTimeout: Timeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("keepalive.example."), Timeout: Timeout);

        Assert.That(tcp.Requests.TryDequeue(out var retry), Is.True, "the truncated answer was retried over TCP");

        Assert.Multiple(() => {

            Assert.That(OptOf(retry!),            Is.Not.Null,
                        "RFC 7828 §3.3.2: the retry carries the OPT record the datagram carried");

            Assert.That(response.Answers.Count(), Is.EqualTo(1),
                        "and a keepalive option in the reply does not disturb the answer it rode in on");

        });

    }

    #endregion


}

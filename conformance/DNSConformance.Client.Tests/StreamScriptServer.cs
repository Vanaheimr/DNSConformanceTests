using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;
using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// A TCP, DoT or DNS over SSH server that does nothing on its own. Every query
/// it reads, on every connection, goes to the test together with the connection
/// it came on, and answering it, holding it, cutting the answer off, closing the
/// connection or resetting it is the test's move.
/// </summary>
/// <remarks>
/// <para>
/// Over SSH a "connection" here is a channel of the subsystem
/// "dns@open.charging.cloud". Section 3.6 of the white paper "DNS over SSH" maps
/// the one onto the other - what a TLS session is to DNS over TLS, the channel is
/// over SSH - and sections 3.3 to 3.5 carry the rules of RFC 7766 and RFC 7828
/// over with "channel" where they say "connection": the idle timeout is the
/// channel's, the queries left unanswered on a closed channel are asked again on
/// a new one. So the tests that count connections count channels, and a
/// connection that is closed is a channel the server ended with exit-status 0,
/// EOF and CLOSE while the SSH connection stays. Only a reset has no channel to
/// happen to: it is the SSH connection's TCP connection that is reset, and the
/// channel goes with it. The server underneath is a
/// <see cref="ScriptedSshServer"/>, which says what of it is Hermod's and what is
/// not.
/// </para>
/// <para>
/// The scripted servers answer a query before they read the next one and treat
/// every connection alike. What the tests here need is the opposite on both
/// counts: queries read the moment they arrive, so that a pipelined one is seen
/// while an earlier answer is held, and connections told apart, so that "the
/// second query went out on a new connection" is something the server counts
/// rather than something inferred.
/// </para>
/// <para>
/// The handler is not awaited by the reader. A test that holds an answer does so
/// in its handler, and the connection keeps reading behind it.
/// </para>
/// </remarks>
internal sealed class StreamScriptServer : IAsyncDisposable
{

    #region (class) Connection

    /// <summary>
    /// One connection the server accepted, and what the test may do to it.
    /// </summary>
    internal sealed class Connection
    {

        private readonly TcpClient?             client;
        private readonly ScriptedSshChannel?    channel;
        private readonly SemaphoreSlim          write   = new(1, 1);
        private readonly ConcurrentQueue<String> names  = new();

        internal Stream Stream { get; set; } = Stream.Null;

        internal Connection(Int32 Number, TcpClient Client)
        {
            this.Number  = Number;
            this.client  = Client;
        }

        internal Connection(Int32 Number, ScriptedSshChannel Channel)
        {
            this.Number   = Number;
            this.channel  = Channel;
        }

        /// <summary>The connection's place in the order they were accepted, from 1.</summary>
        public Int32                  Number   { get; }

        /// <summary>The names of the queries that arrived on this connection, in order.</summary>
        public IReadOnlyList<String>  Names    => [.. names];

        internal void Saw(String Name)
            => names.Enqueue(Name);


        /// <summary>
        /// Answer the query, with an edns-tcp-keepalive option of the given
        /// timeout when there is one - RFC 7828 §3.1: "specified in units of 100
        /// milliseconds".
        /// </summary>
        public Task Answer(Byte[] Query, UInt16? Keepalive = null)
            => Send(Framed(Response(Query, Keepalive)));

        /// <summary>
        /// Send the length of the answer and the first half of its octets, and
        /// close the connection there: a server that went away in the middle of
        /// an answer.
        /// </summary>
        public async Task CutOff(Byte[] Query)
        {
            var framed = Framed(Response(Query, null));
            await Send(framed[..(2 + (framed.Length - 2) / 2)]);
            Close();
        }

        /// <summary>Close the connection: a FIN, and nothing more is read or written.</summary>
        /// <remarks>
        /// Over SSH the channel is ended, as section 3.5 of the white paper has a
        /// server end it - exit-status 0, EOF, CLOSE - and the SSH connection stays.
        /// </remarks>
        public void Close()
        {

            if (channel is not null)
            {
                channel.EndAsync(0).GetAwaiter().GetResult();
                return;
            }

            try { client!.Client.Shutdown(SocketShutdown.Both); } catch { }
            client!.Close();

        }

        /// <summary>Reset the connection: a RST rather than a FIN.</summary>
        /// <remarks>
        /// The socket is closed, not the TcpClient. TcpClient.Close shuts the
        /// socket down first, and the shutdown sends a FIN. The peer takes that
        /// for an orderly close: its next read returns 0 and its next write goes
        /// through, and only the RST sent back for that write fails the one
        /// after it.
        /// <para>
        /// Over SSH it is the TCP connection of the SSH connection that is reset.
        /// A channel cannot be: it ends with a CLOSE or with its connection.
        /// </para>
        /// </remarks>
        public void Reset()
        {

            if (channel is not null)
            {
                channel.ResetConnection();
                return;
            }

            try { client!.Client.Close(0); } catch { }
            client!.Close();

        }

        private async Task Send(Byte[] Octets)
        {
            if (channel is not null)
            {

                // One channel write for all of it; the channel keeps its own
                // writers apart. Whatever a channel that ended throws is the
                // IOException of a socket that closed.
                try
                {
                    await channel.WriteAsync(Octets);
                }
                catch (Exception)
                { }

                return;

            }

            await write.WaitAsync();
            try
            {
                await Stream.WriteAsync(Octets);
                await Stream.FlushAsync();
            }
            catch (IOException)             { }
            catch (ObjectDisposedException) { }
            finally
            {
                write.Release();
            }
        }

    }

    #endregion


    #region Data

    /// <summary>The three transports, by the names the test cases carry.</summary>
    public static readonly String[] Transports = [ "TCP", "DoT", "SSH" ];

    private readonly Func<Connection, Byte[], Task>  onQuery;
    private readonly X509Certificate2?               certificate;
    private readonly TcpListener?                    listener;
    private readonly ScriptedSshServer?              ssh;
    private readonly CancellationTokenSource         cts          = new();
    private readonly ConcurrentQueue<Connection>     connections  = new();

    private          Int32                           accepted;

    public String                      Transport         { get; }

    public Int32                       Port              { get; }

    /// <summary>Every connection accepted so far, in the order it was accepted.</summary>
    public IReadOnlyList<Connection>   Connections       => [.. connections.OrderBy(connection => connection.Number)];

    public Int32                       ConnectionCount   => Volatile.Read(ref accepted);

    #endregion

    #region Constructor(s)

    /// <param name="Transport">"TCP", "DoT" for TLS on every connection (RFC 7858), or "SSH" for a channel of the subsystem "dns@open.charging.cloud" as every connection.</param>
    /// <param name="OnQuery">What to do with a query, given the connection it came on. Not awaited by the reader.</param>
    /// <param name="Port">The port to listen on, or 0 for one the system picks.</param>
    public StreamScriptServer(String                          Transport,
                              Func<Connection, Byte[], Task>  OnQuery,
                              Int32                           Port = 0)
    {

        this.Transport  = Transport;
        onQuery         = OnQuery;
        certificate     = Transport switch {
                              "TCP"  => null,
                              "DoT"  => TestCertificate.CreateServerCertificate(),
                              "SSH"  => null,
                              _      => throw new ArgumentException($"No such stream transport: {Transport}", nameof(Transport))
                          };

        if (Transport == "SSH")
        {
            ssh        = new ScriptedSshServer(ServeChannel, FixedPort: Port);
            this.Port  = ssh.Port;
            return;
        }

        listener     = new TcpListener(System.Net.IPAddress.Loopback, Port);
        listener.Start();
        this.Port    = ((IPEndPoint) listener.LocalEndpoint).Port;

        _ = AcceptLoop();

    }

    #endregion


    #region NewClient(QueryTimeout) / (static) NewClient(Transport, Port, QueryTimeout)

    /// <summary>A client of this server's transport, pointed at it.</summary>
    public IDNSClient NewClient(TimeSpan QueryTimeout)
        => NewClient(Transport, Port, QueryTimeout);

    /// <summary>A client of the given transport, pointed at a port on the loopback address - whether anything listens there or not.</summary>
    public static IDNSClient NewClient(String Transport, Int32 Port, TimeSpan QueryTimeout)

        => Transport switch {

               "TCP"  => new DNSTCPClient(IPv4Address.Localhost,
                                          Port:                        IPPort.Parse((UInt16) Port),
                                          QueryTimeout:                QueryTimeout),

               "DoT"  => new DNSTLSClient(IPv4Address.Localhost,
                                          TCPPort:                     IPPort.Parse((UInt16) Port),
                                          QueryTimeout:                QueryTimeout,
                                          RemoteCertificateValidator:  (_, _, _, _, _) => TLSValidationResult.Success()),

               // An SSH connection of the client's own, with the key every
               // scripted SSH server accepts, and its host key pinned.
               "SSH"  => ScriptedSshServer.NewClient(Port, QueryTimeout),

               _      => throw new ArgumentException($"No such stream transport: {Transport}", nameof(Transport))

           };

    #endregion


    #region (static) Response / Framed / NameOf

    private static Byte[] Response(Byte[] Query, UInt16? Keepalive)
    {

        var query          = RawDnsReader.Parse(Query, RawDnsReaderOptions.Lenient);
        var question       = query.Questions[0];
        var questionBytes  = Query[12..(12 + question.Name.WireLength + 4)];

        var writer         = new RawDnsWriter().
                                 Header(query.Id, RawDnsResponder.DefaultFlags, 1, 1, 0, (UInt16) (Keepalive is null ? 0 : 1)).
                                 Bytes(questionBytes).
                                 RR($"{question.Name.Canonical}.", RawDnsType.A, RawDnsClass.IN, 60, RawDnsWriter.IPv4("192.0.2.53"));

        if (Keepalive is UInt16 units)
            writer.Opt(1232, options: [ 0x00, 0x0B, 0x00, 0x02, (Byte) (units >> 8), (Byte) (units & 0xFF) ]);

        return writer.ToArray();

    }

    private static Byte[] Framed(Byte[] Message)
    {
        var framed = new Byte[Message.Length + 2];
        framed[0]  = (Byte) (Message.Length >> 8);
        framed[1]  = (Byte) (Message.Length & 0xFF);
        Message.CopyTo(framed, 2);
        return framed;
    }

    /// <summary>The name a query asks about, as the server's own reader sees it.</summary>
    public static String NameOf(Byte[] Query)
        => $"{RawDnsReader.Parse(Query, RawDnsReaderOptions.Lenient).Questions[0].Name.Canonical}.";

    #endregion

    #region (private) AcceptLoop() / Serve(Client) / ServeChannel(Channel, CancellationToken)

    /// <summary>
    /// What <see cref="Serve"/> does with a connection, for a channel of the DNS
    /// subsystem: counted when it is opened, read as the queries arrive.
    /// </summary>
    private async Task ServeChannel(ScriptedSshChannel Channel, CancellationToken CancellationToken)
    {

        var connection = new Connection(Interlocked.Increment(ref accepted), Channel);
        connections.Enqueue(connection);

        while (await Channel.ReadMessageAsync(CancellationToken) is Byte[] query)
        {

            connection.Saw(NameOf(query));

            _ = Handle(connection, query);

        }

    }

    private async Task AcceptLoop()
    {
        try
        {
            while (!cts.IsCancellationRequested)
            {
                var client = await listener!.AcceptTcpClientAsync(cts.Token);
                _ = Task.Run(() => Serve(client));
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException)    { }
        catch (SocketException)            { }
    }

    private async Task Serve(TcpClient Client)
    {

        try
        {

            using var held   = Client;
            Stream    stream = Client.GetStream();

            if (certificate is not null)
            {
                var tls = new SslStream(stream, leaveInnerStreamOpen: false);
                await tls.AuthenticateAsServerAsync(
                          new SslServerAuthenticationOptions {
                              ServerCertificate          = certificate,
                              EnabledSslProtocols        = SslProtocols.Tls12 | SslProtocols.Tls13,
                              ClientCertificateRequired  = false
                          },
                          cts.Token
                      );
                stream = tls;
            }

            // Counted once it can carry a query: for DoT that is after the
            // handshake, which is what makes it the same count as a TCP accept.
            var connection = new Connection(Interlocked.Increment(ref accepted), Client) { Stream = stream };
            connections.Enqueue(connection);

            await using var __ = stream;

            while (!cts.IsCancellationRequested)
            {

                var length = new Byte[2];
                if (!await ReadExactly(stream, length))
                    return;

                var query = new Byte[(length[0] << 8) | length[1]];
                if (!await ReadExactly(stream, query))
                    return;

                connection.Saw(NameOf(query));

                _ = Handle(connection, query);

            }

        }
        catch (OperationCanceledException) { }
        catch (IOException)                { }
        catch (AuthenticationException)    { }
        catch (ObjectDisposedException)    { }
        catch (SocketException)            { }

    }

    private async Task Handle(Connection Connection, Byte[] Query)
    {
        try
        {
            await onQuery(Connection, Query);
        }
        catch (OperationCanceledException) { }
        catch (IOException)                { }
        catch (ObjectDisposedException)    { }
        catch (SocketException)            { }
    }

    private async Task<Boolean> ReadExactly(Stream Stream, Byte[] Buffer)
    {

        var read = 0;

        while (read < Buffer.Length)
        {
            var n = await Stream.ReadAsync(Buffer.AsMemory(read), cts.Token);
            if (n == 0)
                return false;
            read += n;
        }

        return true;

    }

    #endregion


    public async ValueTask DisposeAsync()
    {

        cts.Cancel();

        if (ssh is not null)
        {
            await ssh.DisposeAsync();
            cts.Dispose();
            return;
        }

        listener!.Stop();

        foreach (var connection in connections)
            connection.Close();

        await Task.Delay(50);
        cts.Dispose();

    }

}

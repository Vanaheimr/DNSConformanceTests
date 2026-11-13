using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

namespace DNSConformance.Core.Scripted;

public sealed class ScriptedSshOptions
{

    /// <summary>
    /// Write responses in chunks of this many bytes, each a channel write of its own (0 = single write). Exercises the reassembly of section 3.2 of the white paper, which is RFC 7766 §8's.
    /// </summary>
    public Int32     WriteChunkSize       { get; init; } = 0;

    /// <summary>
    /// Delay between chunked writes.
    /// </summary>
    public TimeSpan  WriteChunkDelay      { get; init; } = TimeSpan.FromMilliseconds(5);

    /// <summary>
    /// Send the 2-byte length prefix and the payload in separate writes.
    /// </summary>
    public Boolean   SplitLengthPrefix    { get; init; } = false;

    /// <summary>
    /// End the channel once this many responses were written on it (0 = never):
    /// exit-status, EOF and CLOSE of that channel, and the SSH connection stays.
    /// </summary>
    public Int32     EndChannelAfter      { get; init; } = 0;

    /// <summary>
    /// The exit-status a channel is ended with (RFC 4254 §6.10): 0 for an idle
    /// timeout, 1 after a protocol error (section 3.5 of the white paper).
    /// </summary>
    public UInt32    ExitStatus           { get; init; } = 0;

    /// <summary>
    /// Where <see cref="EndChannelAfter"/> is reached, close the whole SSH
    /// connection instead of the channel: what section 3.5 says a server does
    /// not do, and a network does.
    /// </summary>
    public Boolean   CloseTheConnection   { get; init; } = false;

    /// <summary>
    /// Answer the subsystem request with SSH_MSG_CHANNEL_FAILURE: a login the
    /// server knows, and does not offer DNS to.
    /// </summary>
    public Boolean   RefuseSubsystem      { get; init; } = false;

}


/// <summary>
/// One channel of the subsystem "dns@open.charging.cloud", and what a script may
/// do to it.
/// </summary>
public sealed class ScriptedSshChannel
{

    private readonly SshMuxChannel                  channel;
    private readonly ScriptedSshServer.Link?        link;
    private readonly ConcurrentQueue<Byte[]>        seen;
    private readonly SemaphoreSlim                  write    = new(1, 1);
    private readonly ConcurrentQueue<Int32>         reads    = new();
    private readonly Byte[]                         buffer   = new Byte[128 * 1024];
    private          Int32                          buffered;
    private          Int32                          ended;

    internal ScriptedSshChannel(Int32                     Number,
                                String                    Login,
                                SshMuxChannel             Channel,
                                ScriptedSshServer.Link?   Link,
                                ConcurrentQueue<Byte[]>   Seen)
    {
        this.Number  = Number;
        this.Login   = Login;
        channel      = Channel;
        link         = Link;
        seen         = Seen;
    }

    /// <summary>The channel's place in the order the subsystem was opened, from 1.</summary>
    public Int32                    Number             { get; }

    /// <summary>The SSH connection the channel is on, in the order they were accepted, from 1; 0 where it could not be told.</summary>
    public Int32                    ConnectionNumber   => link?.Number ?? 0;

    /// <summary>Who signed in on that connection.</summary>
    public String                   Login              { get; }

    /// <summary>The messages read from this channel, without their lengths, in order.</summary>
    public ConcurrentQueue<Byte[]>  Requests           { get; } = new();

    /// <summary>
    /// How many octets each read of the channel returned, in order. A length
    /// and its message written to the channel in one write are there together
    /// when the first of them is: the first read is then at least as long as
    /// the two. A read of two octets is a length that travelled alone.
    /// </summary>
    public IReadOnlyList<Int32>     ReadSizes          => [.. reads];

    /// <summary>Whether the channel is over: the server ended it, the client did, or its connection went.</summary>
    public Boolean                  Ended              => Volatile.Read(ref ended) != 0 || channel.Closed.IsCompleted;


    /// <summary>
    /// The next message of the channel, without its length; null where the
    /// client ended the channel, or the channel ended inside a message.
    /// </summary>
    public async Task<Byte[]?> ReadMessageAsync(CancellationToken CancellationToken = default)
    {

        while (true)
        {

            if (buffered >= 2)
            {

                var length = (buffer[0] << 8) | buffer[1];

                if (buffered >= 2 + length)
                {

                    var message = buffer[2..(2 + length)];

                    Buffer.BlockCopy(buffer, 2 + length, buffer, 0, buffered - 2 - length);
                    buffered -= 2 + length;

                    Requests.Enqueue(message);
                    seen.    Enqueue(message);

                    return message;

                }

            }

            Int32 read;

            try
            {
                read = await channel.Input.ReadAsync(buffer.AsMemory(buffered), CancellationToken);
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // The connection went under the channel.
                return null;
            }

            if (read == 0)
                return null;

            reads.Enqueue(read);
            buffered += read;

        }

    }

    /// <summary>
    /// Write these octets to the channel as they are, in one write: whatever
    /// part of a length or a message they hold.
    /// </summary>
    public async Task WriteAsync(ReadOnlyMemory<Byte> Octets, CancellationToken CancellationToken = default)
    {

        await write.WaitAsync(CancellationToken);

        try
        {
            await channel.SendDataAsync(Octets, CancellationToken);
        }
        finally
        {
            write.Release();
        }

    }

    /// <summary>
    /// Write a message behind its two-octet length, both in one write.
    /// </summary>
    public Task WriteMessageAsync(Byte[] Message, CancellationToken CancellationToken = default)
        => WriteAsync(ScriptedSshServer.Framed(Message), CancellationToken);

    /// <summary>
    /// End the channel as section 3.5 of the white paper has a server end it:
    /// the channel request exit-status (RFC 4254 §6.10), then EOF and CLOSE.
    /// The SSH connection stays.
    /// </summary>
    public async Task EndAsync(UInt32 ExitStatus = 0)
    {

        if (Interlocked.Exchange(ref ended, 1) != 0)
            return;

        await write.WaitAsync();

        try
        {
            await channel.SendExitStatusAsync(ExitStatus);
            await channel.CloseAsync();
        }
        catch (Exception)
        {
            // Closed already, or gone with its connection.
        }
        finally
        {
            write.Release();
        }

    }

    /// <summary>Close the SSH connection this channel is on: a FIN, with every channel on it.</summary>
    public void CloseConnection()
        => link?.Close();

    /// <summary>Reset the SSH connection this channel is on: a RST rather than a FIN.</summary>
    public void ResetConnection()
        => link?.Reset();

}


/// <summary>
/// A loopback SSH server whose subsystem "dns@open.charging.cloud" runs a
/// script over the byte stream of DNS over TCP (white paper "DNS over SSH",
/// section 3.2): RFC 7766 two-byte framing in a session channel.
/// </summary>
/// <remarks>
/// <para>
/// The SSH underneath is Hermod's own <see cref="SshServer"/>. There is no other
/// SSH implementation to run in-process, so the transport of the offline lane is
/// Hermod on both sides - the interop lane has OpenSSH for that. What the suite
/// keeps to itself is everything the conformance judgments are made from: the
/// subsystem is served by the script given here, never by
/// <c>DNSServer.ServeSSHSubsystemAsync</c>, the framing is read and written
/// here, and the messages are whatever octets the responder returns.
/// </para>
/// <para>
/// The port clients dial is a relay of this class in front of the SSH server.
/// It counts TCP connections where nothing of Hermod's is asked - a client that
/// turned away at the host key was still there - and it can end one connection,
/// by a FIN or by a RST, which the SSH server offers no way to do.
/// </para>
/// </remarks>
public sealed class ScriptedSshServer : IAsyncDisposable
{

    #region (class) Link

    /// <summary>
    /// One TCP connection the relay accepted, and its other half to the SSH server.
    /// </summary>
    public sealed class Link
    {

        private readonly TcpClient client;
        private readonly TcpClient upstream;

        internal Link(Int32 Number, TcpClient Client, TcpClient Upstream)
        {
            this.Number  = Number;
            client       = Client;
            upstream     = Upstream;
        }

        /// <summary>The connection's place in the order they were accepted, from 1.</summary>
        public Int32 Number { get; }

        /// <summary>Close the connection: a FIN to the client.</summary>
        public void Close()
        {
            try { client.Client.Shutdown(SocketShutdown.Both); } catch { }
            client.Close();
            upstream.Close();
        }

        /// <summary>
        /// Reset the connection: a RST to the client. The socket is closed and
        /// not the TcpClient, whose Close sends a FIN first.
        /// </summary>
        public void Reset()
        {
            try { client.Client.Close(0); } catch { }
            client.Close();
            upstream.Close();
        }

    }

    #endregion

    #region Data

    /// <summary>The name of the subsystem, as section 3.1 of the white paper spells it.</summary>
    public const String SubsystemName = "dns@open.charging.cloud";

    /// <summary>The login the clients made here sign in with; any login with the right key is accepted.</summary>
    public const String DefaultLogin  = "cs001";

    private static readonly Lazy<ISshHostKey>  sharedHostKey    = new (SshHostKey.GenerateEd25519);
    private static readonly Lazy<ISshHostKey>  sharedClientKey  = new (SshHostKey.GenerateEd25519);

    /// <summary>The host key of every server that was not given one of its own.</summary>
    public static ISshHostKey SharedHostKey    => sharedHostKey.Value;

    /// <summary>The key every server accepts that was not told another.</summary>
    public static ISshHostKey SharedClientKey  => sharedClientKey.Value;


    private readonly Func<ScriptedSshServer, ScriptedSshChannel, CancellationToken, Task>  script;
    private readonly ScriptedSshOptions                                                    options;
    private readonly SshServer                                                             ssh;
    private readonly Int32                                                                 sshPort;
    private readonly TcpListener                                                           listener;
    private readonly CancellationTokenSource                                               cts        = new();
    private readonly Task                                                                  acceptLoop;
    private readonly ConcurrentDictionary<Int32, Link>                                     links      = new();
    private readonly ConcurrentQueue<ScriptedSshChannel>                                   channels   = new();
    private readonly CollectingAuditSink                                                   audit      = new();

    #endregion

    #region Properties

    /// <summary>The host key the server shows. A test pins it, or pins another.</summary>
    public ISshHostKey              HostKey                 { get; }

    /// <summary>The key the server accepts, for whatever login it is shown with.</summary>
    public ISshHostKey              ClientKey               { get; }

    /// <summary>Every message read in the subsystem, on whatever channel, without its length.</summary>
    public ConcurrentQueue<Byte[]>  Requests                { get; } = new();

    public Int32                    Port                    { get; }

    /// <summary>TCP connections accepted, whatever became of them.</summary>
    public Int32                    ConnectionCount         => connectionCount;
    private Int32                   connectionCount;

    /// <summary>How often a key was shown to sign in with, accepted or not.</summary>
    public Int32                    LoginAttempts           => loginAttempts;
    private Int32                   loginAttempts;

    /// <summary>Logins that succeeded: one for each SSH connection that got as far as opening channels.</summary>
    public Int32                    AuthenticationCount     => audit.Events.OfType<AuthenticationSucceededEvent>().Count();

    /// <summary>How often the subsystem was asked for, served or refused.</summary>
    public Int32                    SubsystemRequests       => subsystemRequests;
    private Int32                   subsystemRequests;

    /// <summary>How often it was refused with SSH_MSG_CHANNEL_FAILURE.</summary>
    public Int32                    SubsystemsRefused       => subsystemsRefused;
    private Int32                   subsystemsRefused;

    /// <summary>Channels the subsystem was served on.</summary>
    public Int32                    ChannelsOpened          => channelsOpened;
    private Int32                   channelsOpened;

    /// <summary>How many of them ended: the client closed its channel, the server did, or the connection went.</summary>
    public Int32                    ChannelsEnded           => channelsEnded;
    private Int32                   channelsEnded;

    /// <summary>Every channel the subsystem was served on, in the order it was opened.</summary>
    public IReadOnlyList<ScriptedSshChannel>  Channels      => [.. channels.OrderBy(channel => channel.Number)];

    /// <summary>
    /// Messages this server has finished writing. A test that depends on a
    /// response already being on the wire can check that rather than trust a
    /// sleep.
    /// </summary>
    public Int32                    ResponsesWritten        => responsesWritten;
    private Int32                   responsesWritten;

    #endregion

    #region Constructor(s)

    private ScriptedSshServer(Func<ScriptedSshServer, ScriptedSshChannel, CancellationToken, Task>  Script,
                              ScriptedSshOptions?                                                    Options,
                              Int32                                                                  FixedPort,
                              ISshHostKey?                                                           HostKey,
                              ISshHostKey?                                                           ClientKey)
    {

        script          = Script;
        options         = Options   ?? new ScriptedSshOptions();
        this.HostKey    = HostKey   ?? SharedHostKey;
        this.ClientKey  = ClientKey ?? SharedClientKey;

        var accepted    = this.ClientKey.PublicKeyBlob;

        ssh             = new SshServer(new SshServerOptions {

                              HostKeys             = [ this.HostKey ],

                              Authenticator        = new SshUserAuthenticator((request, _) => {
                                                         Interlocked.Increment(ref loginAttempts);
                                                         return ValueTask.FromResult(accepted.AsSpan().SequenceEqual(request.PublicKeyBlob));
                                                     }),

                              AuditSink            = audit,
                              ShutdownGracePeriod  = TimeSpan.FromMilliseconds(200),

                              Subsystems           = (session, name, _) => {

                                                         if (name != SubsystemName)
                                                             return ValueTask.FromResult<SshSubsystemHandler?>(null);

                                                         Interlocked.Increment(ref subsystemRequests);

                                                         if (options.RefuseSubsystem)
                                                         {
                                                             Interlocked.Increment(ref subsystemsRefused);
                                                             return ValueTask.FromResult<SshSubsystemHandler?>(null);
                                                         }

                                                         return ValueTask.FromResult<SshSubsystemHandler?>(Serve);

                                                     }

                          });

        ssh.StartAsync(new IPSocket(IPv4Address.Localhost, IPPort.Auto)).AsTask().GetAwaiter().GetResult();

        sshPort         = ssh.LocalEndPoint.Port.ToInt32();

        listener        = new TcpListener(System.Net.IPAddress.Loopback, FixedPort);
        listener.Start();
        Port            = ((IPEndPoint) listener.LocalEndpoint).Port;
        acceptLoop      = Task.Run(AcceptLoop);

    }

    /// <param name="Script">Serves one channel of the subsystem. The channel is ended with exit-status 0 when it returns, unless the script ended it itself.</param>
    /// <param name="Options">Whether the subsystem is refused; the framing options are the responder's and mean nothing to a script.</param>
    /// <param name="FixedPort">Bind this specific port instead of an ephemeral one.</param>
    /// <param name="HostKey">The host key to show; the shared one by default.</param>
    /// <param name="ClientKey">The key to accept; the shared one by default.</param>
    public ScriptedSshServer(Func<ScriptedSshChannel, CancellationToken, Task>  Script,
                             ScriptedSshOptions?                                Options     = null,
                             Int32                                              FixedPort   = 0,
                             ISshHostKey?                                       HostKey     = null,
                             ISshHostKey?                                       ClientKey   = null)

        : this((_, channel, token) => Script(channel, token),
               Options,
               FixedPort,
               HostKey,
               ClientKey)

    { }

    /// <param name="Responder">The scripted response logic: the answers to write for a message read, none, one or several, in the order they are to be written.</param>
    /// <param name="Options">Framing options, and how and when a channel is ended.</param>
    /// <param name="FixedPort">Bind this specific port instead of an ephemeral one.</param>
    /// <param name="HostKey">The host key to show; the shared one by default.</param>
    /// <param name="ClientKey">The key to accept; the shared one by default.</param>
    public ScriptedSshServer(Func<Byte[], IEnumerable<Byte[]>>  Responder,
                             ScriptedSshOptions?                Options     = null,
                             Int32                              FixedPort   = 0,
                             ISshHostKey?                       HostKey     = null,
                             ISshHostKey?                       ClientKey   = null)

        : this((server, channel, token) => server.Respond(channel, Responder, token),
               Options,
               FixedPort,
               HostKey,
               ClientKey)

    { }

    public ScriptedSshServer(Func<Byte[], Byte[]?>  Responder,
                             ScriptedSshOptions?    Options     = null,
                             Int32                  FixedPort   = 0,
                             ISshHostKey?           HostKey     = null,
                             ISshHostKey?           ClientKey   = null)

        : this(request => Responder(request) is { } response ? [response] : Array.Empty<Byte[]>(),
               Options,
               FixedPort,
               HostKey,
               ClientKey)

    { }

    #endregion


    #region ClientOptions(Login = DefaultLogin, PinnedHostKey = null) / NewClient(QueryTimeout)

    /// <summary>
    /// The SSH login of a client of this server: its key, and the host key held
    /// to the given one - this server's, unless told otherwise.
    /// </summary>
    public SshClientOptions ClientOptions(String        Login           = DefaultLogin,
                                          ISshHostKey?  PinnedHostKey   = null)

        => ClientOptions(PinnedHostKey ?? HostKey, ClientKey, Login);

    /// <summary>
    /// An SSH login with the given key, for a server whose host key is the given one and no other.
    /// </summary>
    public static SshClientOptions ClientOptions(ISshHostKey  PinnedHostKey,
                                                 ISshHostKey  ClientKey,
                                                 String       Login   = DefaultLogin)
    {

        var pinned = PinnedHostKey.PublicKeyBlob;

        return new SshClientOptions {
                   Username       = Login,
                   VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(pinned),
                   Credentials    = [ ClientKey ]
               };

    }

    /// <summary>A client with an SSH connection of its own, pointed at this server and pinning its host key.</summary>
    public DNSSSHClient NewClient(TimeSpan QueryTimeout)

        => new ("127.0.0.1",
                ClientOptions(),
                IPPort.Parse((UInt16) Port),
                QueryTimeout: QueryTimeout);

    /// <summary>
    /// A client for a server with the shared keys on the given loopback port - whether anything listens there or not.
    /// </summary>
    public static DNSSSHClient NewClient(Int32 Port, TimeSpan QueryTimeout)

        => new ("127.0.0.1",
                ClientOptions(SharedHostKey, SharedClientKey),
                IPPort.Parse((UInt16) Port),
                QueryTimeout: QueryTimeout);

    #endregion

    #region (static) Framed(Message)

    /// <summary>A message behind its two-octet length (RFC 1035 §4.2.2).</summary>
    public static Byte[] Framed(Byte[] Message)
    {
        var framed = new Byte[Message.Length + 2];
        framed[0]  = (Byte) (Message.Length >> 8);
        framed[1]  = (Byte) (Message.Length & 0xFF);
        Message.CopyTo(framed, 2);
        return framed;
    }

    #endregion


    #region (private) Serve(Context, CancellationToken)

    private async ValueTask Serve(SshSubsystemContext Context, CancellationToken CancellationToken)
    {

        Link? link = null;

        if (Context.Session.Peer is IPSocket peer)
            links.TryGetValue(peer.Port.ToInt32(), out link);

        var channel = new ScriptedSshChannel(Interlocked.Increment(ref channelsOpened),
                                             Context.Session.Username,
                                             Context.Channel,
                                             link,
                                             Requests);

        channels.Enqueue(channel);

        using var ending = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, cts.Token);

        try
        {
            await script(this, channel, ending.Token);
        }
        catch (OperationCanceledException)
        { }
        finally
        {

            // The script is done: exit-status 0, EOF and CLOSE, unless it said
            // otherwise before. Hermod's server would send the same; sent here so
            // that what a channel ends with is this file's to say.
            await channel.EndAsync(0);

            Interlocked.Increment(ref channelsEnded);

        }

    }

    #endregion

    #region (private) Respond(Channel, Responder, CancellationToken) / WriteChunked(Channel, Octets, CancellationToken)

    /// <summary>
    /// What a <see cref="ScriptedTcpServer"/> does with a connection, for a
    /// channel: a message is read, and what the responder returns for it is
    /// written before the next one is read.
    /// </summary>
    private async Task Respond(ScriptedSshChannel                 Channel,
                               Func<Byte[], IEnumerable<Byte[]>>  Responder,
                               CancellationToken                  CancellationToken)
    {

        var written = 0;

        while (await Channel.ReadMessageAsync(CancellationToken) is Byte[] message)
        {

            foreach (var response in Responder(message))
            {

                var framed = Framed(response);

                if (options.SplitLengthPrefix)
                {
                    await Channel.WriteAsync(framed.AsMemory(0, 1), CancellationToken);
                    await Task.Delay(options.WriteChunkDelay, CancellationToken);
                    await Channel.WriteAsync(framed.AsMemory(1, 1), CancellationToken);
                    await Task.Delay(options.WriteChunkDelay, CancellationToken);
                    await WriteChunked(Channel, framed.AsMemory(2), CancellationToken);
                }
                else if (options.WriteChunkSize > 0)
                    await WriteChunked(Channel, framed, CancellationToken);
                else
                    await Channel.WriteAsync(framed, CancellationToken);

                Interlocked.Increment(ref responsesWritten);

                if (options.EndChannelAfter > 0 && ++written >= options.EndChannelAfter)
                {

                    if (options.CloseTheConnection)
                        Channel.CloseConnection();

                    else
                        await Channel.EndAsync(options.ExitStatus);

                    return;

                }

            }

        }

    }

    private async Task WriteChunked(ScriptedSshChannel Channel, ReadOnlyMemory<Byte> Octets, CancellationToken CancellationToken)
    {

        var chunkSize = Math.Max(1, options.WriteChunkSize);

        for (var offset = 0; offset < Octets.Length; offset += chunkSize)
        {
            await Channel.WriteAsync(Octets.Slice(offset, Math.Min(chunkSize, Octets.Length - offset)), CancellationToken);
            await Task.Delay(options.WriteChunkDelay, CancellationToken);
        }

    }

    #endregion

    #region (private) AcceptLoop() / Relay(Number, Client)

    private async Task AcceptLoop()
    {

        try
        {
            while (!cts.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(cts.Token);
                var number = Interlocked.Increment(ref connectionCount);
                _ = Task.Run(() => Relay(number, client));
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException)    { }
        catch (SocketException)            { }

    }

    private async Task Relay(Int32 Number, TcpClient Client)
    {

        var upstream = new TcpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0)) { NoDelay = true };

        try
        {

            Client.NoDelay = true;

            // Bound before it connects, so that the SSH server's session is
            // known by its port from its first octet on.
            var link = new Link(Number, Client, upstream);
            links[((IPEndPoint) upstream.Client.LocalEndPoint!).Port] = link;

            await upstream.ConnectAsync(System.Net.IPAddress.Loopback, sshPort, cts.Token);

            var down  = Client.  GetStream();
            var up    = upstream.GetStream();

            await Task.WhenAny(
                      down.CopyToAsync(up,   cts.Token),
                      up.  CopyToAsync(down, cts.Token)
                  );

        }
        catch (OperationCanceledException) { }
        catch (IOException)                { }
        catch (SocketException)            { }
        catch (ObjectDisposedException)    { }
        finally
        {
            try { Client.  Close(); } catch { }
            try { upstream.Close(); } catch { }
        }

    }

    #endregion


    public async ValueTask DisposeAsync()
    {

        await cts.CancelAsync();
        listener.Stop();

        foreach (var link in links.Values)
            link.Close();

        try
        {
            await acceptLoop.WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch { }

        try
        {
            await ssh.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch { }

        cts.Dispose();

    }

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH;

using DNSConformance.Core;
using DNSConformance.Core.Fixtures;

namespace DNSInterop.ExternalServers.Tests;

/// <summary>
/// DNS over SSH against a server that has nothing of Hermod in it: OpenSSH's
/// <c>sshd</c> with a <c>Subsystem dns@open.charging.cloud</c> line, <c>socat</c>
/// behind it, and ISC BIND behind that - appendix B of the white paper "DNS over
/// SSH". Hermod's <see cref="DNSSSHClient"/> is the client.
/// </summary>
/// <remarks>
/// <para>
/// The conformance tests of the client run against a scripted subsystem on
/// Hermod's own SSH server, because no other SSH implementation runs
/// in-process. That leaves one question they cannot answer: whether the client
/// speaks SSH, and the subsystem request of RFC 4254 §6.5, to anybody but its
/// sibling. Here the key exchange, the host key, the login, the channel and the
/// subsystem are OpenSSH's, the byte stream is relayed by a program that knows
/// nothing of DNS, and every answer is BIND's.
/// </para>
/// <para>
/// Section 6.5 of the paper calls this deployment "OpenSSH in front of an
/// existing resolver", and it is the one a second, independent implementation
/// of the subsystem exists for today.
/// </para>
/// </remarks>
[TestFixture]
[Category(TestCategories.Wsl)]
[Property("Paper", "DNS over SSH, appendix B")]
public class OpenSshSubsystemInteropTests
{

    private OpenSshDnsFixture ssh = null!;

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);


    [OneTimeSetUp]
    public async Task StartSshdAndBind()
    {

        TestEnvironment.RequireWsl("named", "dig", "sshd", "socat", "ssh-keygen");

        try
        {
            ssh = await OpenSshDnsFixture.StartAsync();
        }
        catch (Exception e)
        {
            Assert.Ignore($"Could not start sshd in front of BIND inside WSL: {e.Message}");
        }

    }

    [OneTimeTearDown]
    public async Task StopSshdAndBind()
    {
        if (ssh is not null)
            await ssh.DisposeAsync();
    }


    private DNSSSHClient SshClient(String? Subsystem = null, Byte[]? PinnedHostKeyBlob = null)
        => new (ssh.Address,
                ssh.ClientOptions(PinnedHostKeyBlob),
                IPPort.Parse(ssh.Port),
                Subsystem:     Subsystem,
                QueryTimeout:  Timeout);

    private DNSTCPClient TcpClient()
        => new (IPv4Address.Parse(ssh.Bind.Address), Port: IPPort.Parse(ssh.Bind.Port), QueryTimeout: Timeout);


    #region Hermod_Resolves_A_Name_Through_OpenSsh_Socat_And_Bind()

    /// <summary>
    /// T1: "A query over the channel. The same answer as over TCP from the same
    /// server."
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH T1, B.1")]
    public async Task Hermod_Resolves_A_Name_Through_OpenSsh_Socat_And_Bind()
    {

        await using var overSsh = SshClient();
        await using var overTcp = TcpClient();

        var throughTheChannel = await overSsh.Query<A>(DomainName.Parse("a.interop.test"), Timeout);
        var direct            = await overTcp.Query<A>(DomainName.Parse("a.interop.test"), Timeout);

        Assert.Multiple(() => {

            Assert.That(throughTheChannel.ResponseCode,  Is.EqualTo(DNSResponseCodes.NoError),
                        $"sshd said:\n{(throughTheChannel.IsValid ? "" : ssh.LogTail())}\nthe client said: {overSsh.LastConnectionError}");

            Assert.That(throughTheChannel.FilteredAnswers.Select(a => a.IPv4Address.ToString()),
                                                         Is.EqualTo(new[] { "192.0.2.1" }),
                        "BIND's answer, through socat and sshd");

            Assert.That(throughTheChannel.FilteredAnswers.Select(a => a.IPv4Address.ToString()),
                                                         Is.EqualTo(direct.FilteredAnswers.Select(a => a.IPv4Address.ToString())),
                        "T1: the same answer as over TCP from the same server");

            Assert.That(throughTheChannel.Origin.Transport,  Is.EqualTo(DNSTransport.SSH));
            Assert.That(overSsh.ChannelsOpened,              Is.EqualTo(1));
            Assert.That(overSsh.ConnectionsMade,             Is.EqualTo(1));

        });

    }

    #endregion

    #region Hermod_Pipelines_Several_Queries_Through_One_OpenSsh_Channel()

    /// <summary>
    /// Appendix B.3: "three queries in one write to ssh -s [...] three answers,
    /// matched by ID" - here six at once, of five kinds, on one channel.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.3, T2, B.3")]
    [Property("RFC",   "7766 §6.2.1.1, 7858 §3.3")]
    public async Task Hermod_Pipelines_Several_Queries_Through_One_OpenSsh_Channel()
    {

        // Asked together, so that they are on the channel together: the first
        // opens the connection and the channel, the others are written behind it
        // while its answer is still out. BIND answers a TCP connection's queries
        // as it pleases; whichever order that is, each caller has to get the
        // answer to what it asked.
        await using var client = SshClient();

        var a      = client.Query<A>   (DomainName.Parse("a.interop.test"),      Timeout);
        var multi  = client.Query<A>   (DomainName.Parse("multi.interop.test"),  Timeout);
        var aaaa   = client.Query<AAAA>(DomainName.Parse("aaaa.interop.test"),   Timeout);
        var mx     = client.Query<MX>  (DomainName.Parse("mx.interop.test"),     Timeout);
        var txt    = client.Query<TXT> (DomainName.Parse("txt.interop.test"),    Timeout);
        var none   = client.Query<A>   (DomainName.Parse("nosuch.interop.test"), Timeout);

        await Task.WhenAll(a, multi, aaaa, mx, txt, none);

        Assert.Multiple(() => {

            Assert.That(a.Result.FilteredAnswers.Select(record => record.IPv4Address.ToString()),
                        Is.EqualTo(new[] { "192.0.2.1" }),
                        $"sshd said:\n{(a.Result.IsValid ? "" : ssh.LogTail())}");

            Assert.That(multi.Result.FilteredAnswers.Select(record => record.IPv4Address.ToString()).Order(),
                        Is.EqualTo(new[] { "192.0.2.10", "192.0.2.11", "192.0.2.12" }));

            Assert.That(aaaa.Result.FilteredAnswers.Select(record => System.Net.IPAddress.Parse(record.IPv6Address.ToString())),
                        Is.EqualTo(new[] { System.Net.IPAddress.Parse("2001:db8::1") }));

            Assert.That(mx.Result.FilteredAnswers.Select(record => record.Preference).Order(),
                        Is.EqualTo(new UInt16[] { 10, 20 }));

            Assert.That(txt.Result.FilteredAnswers.Count(),  Is.EqualTo(1));

            Assert.That(none.Result.ResponseCode,            Is.EqualTo(DNSResponseCodes.NameError),
                        "and the name that does not exist is the one that got the NXDOMAIN");

            Assert.That(client.ChannelsOpened,               Is.EqualTo(1),  "section 3.3: one channel for all of them");
            Assert.That(client.ConnectionsMade,              Is.EqualTo(1),  "of one SSH connection");

        });

    }

    #endregion

    #region A_Subsystem_OpenSsh_Was_Not_Configured_With_Is_Refused()

    /// <summary>
    /// Appendix B.1: "A subsystem not configured is refused by sshd" - and
    /// Hermod's client takes OpenSSH's refusal for what it is.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.1, T11, B.3")]
    [Property("RFC",   "4254 §6.5")]
    public async Task A_Subsystem_OpenSsh_Was_Not_Configured_With_Is_Refused()
    {

        await using var client = SshClient(Subsystem: "foo@open.charging.cloud");

        var info = await client.Query<A>(DomainName.Parse("a.interop.test"), Timeout);

        Assert.Multiple(() => {

            Assert.That(info.IsValid,    Is.False,  "no answer");
            Assert.That(info.IsTimeout,  Is.False,  "and no timeout: sshd answered the request, with SSH_MSG_CHANNEL_FAILURE");

            Assert.That(client.LastConnectionError,  Is.InstanceOf<SshSubsystemRefusedException>(),
                        $"the client knows it was the subsystem that was refused; sshd said:\n{ssh.LogTail()}");

        });

        // The control: the login and the host key were good, so the refusal was
        // of that name and nothing else.
        await using var served = SshClient();

        Assert.That((await served.Query<A>(DomainName.Parse("a.interop.test"), Timeout)).IsValid,
                    Is.True,
                    "the same login is served the subsystem sshd does know");

    }

    #endregion

    #region A_Host_Key_That_Is_Not_OpenSshs_Is_Not_Used()

    /// <summary>
    /// Appendix B.3: "a host key that is not in known_hosts: Host key
    /// verification failed [...] nothing sent".
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §4.1, T5, B.3")]
    public async Task A_Host_Key_That_Is_Not_OpenSshs_Is_Not_Used()
    {

        // Whether anybody signed in is sshd's to say, and it says it in its log:
        // one line "Accepted publickey for ..." for each login.
        const String Accepted = "Accepted publickey";

        var other         = SshHostKey.GenerateEd25519().PublicKeyBlob;
        var loginsBefore  = ssh.LogCount(Accepted);

        await using var mistaken = SshClient(PinnedHostKeyBlob: other);

        var info          = await mistaken.Query<A>(DomainName.Parse("a.interop.test"), Timeout);

        var loginsAfter   = ssh.LogCount(Accepted);

        Assert.Multiple(() => {
            Assert.That(info.IsValid,                  Is.False,  "no answer from a server whose key is not the pinned one");
            Assert.That(info.IsTimeout,                Is.False,  "and not for want of time");
            Assert.That(mistaken.ChannelsOpened,       Is.Zero,   "no channel was opened to it");
            Assert.That(mistaken.LastConnectionError,  Is.Not.Null.And.Not.InstanceOf<SshSubsystemRefusedException>());
            Assert.That(loginsAfter,                   Is.EqualTo(loginsBefore),
                        "and sshd saw nobody sign in");
        });

        // The control, for both absences: the same server answers a client
        // that pins its key, and its log does count that client's login.
        await using var pinned = SshClient();

        var answered = await pinned.Query<A>(DomainName.Parse("a.interop.test"), Timeout);

        Assert.Multiple(() => {
            Assert.That(answered.IsValid,              Is.True,                        "control: a client that pins sshd's key is answered");
            Assert.That(ssh.LogCount(Accepted),        Is.EqualTo(loginsBefore + 1),   "control: and its login is one sshd's log counts");
        });

    }

    #endregion

}

using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Client.Tests;

/// <summary>
/// The addresses to connect to, asked for in both families at once, with the
/// Resolution Delay of RFC 8305 §3 ("Happy Eyeballs Version 2").
/// </summary>
/// <remarks>
/// <para>
/// RFC 8305 §3: "Implementations SHOULD NOT wait for both families of answers
/// to return before attempting connection establishment." Once one family has
/// answered positively, the other is waited for a short while - "The
/// recommended value for the Resolution Delay is 50 milliseconds" - and no
/// longer. A negative answer, or none, is no reason to stop waiting: there is
/// nothing yet to connect to.
/// </para>
/// <para>
/// Hermod's <c>Query_IPAddressesToConnect</c> returns once rather than
/// streaming addresses as they arrive, and waits the Resolution Delay for the
/// other family whichever one answers first. Its documentation says so, and
/// these tests hold it to what both readings share: a positive answer does not
/// make the caller wait out the other family's whole timeout, a negative one
/// does not end the wait early, and the other family's addresses are taken
/// when they arrive within the delay. IPv6 addresses come first, which is
/// RFC 8305 §4's preference without its interleaving.
/// </para>
/// <para>
/// Every delay here is generous on purpose. What is asserted is which side of a
/// wait an answer lands on, and the margins are chosen so that a loaded machine
/// moves nothing across it.
/// </para>
/// </remarks>
[TestFixture]
public class ResolutionDelayTests
{

    #region Data

    private static readonly DNSServiceName Name   = DNSServiceName.Parse("dual.happy.test.");

    private static readonly Byte[]         IPv4   = [ 192, 0, 2, 41 ];
    private static readonly Byte[]         IPv6   = [ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x41 ];


    /// <summary>
    /// When and with what a scripted server answers one question type: after the
    /// given delay with the given response, or - for null - never.
    /// </summary>
    private sealed record Reply(TimeSpan Delay, Func<Byte[], Byte[]> Response);


    private static Reply Address(TimeSpan Delay)
        => new (Delay, request => {
                           var question = RawDnsReader.Parse(request).Questions[0];
                           return question.Type == RawDnsType.AAAA
                                      ? RawDnsResponder.Answer(request, ($"{question.Name.Canonical}.", RawDnsType.AAAA, 300, IPv6))
                                      : RawDnsResponder.Answer(request, ($"{question.Name.Canonical}.", RawDnsType.A,    300, IPv4));
                       });

    /// <summary>NOERROR with no answer and the zone's SOA: RFC 2308 §2.2's NODATA, the negative answer RFC 8305 §3 names.</summary>
    private static Reply NoData(TimeSpan Delay)
        => new (Delay, request => RawDnsResponder.Negative(request, 0, "happy.test."));


    /// <summary>
    /// A loopback UDP name server that answers each question type on its own
    /// schedule, so that one family can be made to arrive before, after or never
    /// against the other. ScriptedUdpServer answers inside its receive loop, and a
    /// delay there would hold back the next question as well.
    /// </summary>
    private sealed class PerTypeServer : IAsyncDisposable
    {

        private readonly UdpClient                udp     = new (new IPEndPoint(System.Net.IPAddress.Loopback, 0));
        private readonly CancellationTokenSource  stop    = new ();
        private readonly Dictionary<UInt16, Reply?> replies;
        private readonly Task                     loop;

        public Int32 Port
            => ((IPEndPoint) udp.Client.LocalEndPoint!).Port;

        public PerTypeServer(Reply? AAAA, Reply? A)
        {

            replies = new () { [RawDnsType.AAAA] = AAAA, [RawDnsType.A] = A };

            // A reply sent to a client that has already closed its socket earns an
            // ICMP port unreachable, which Windows reports on this socket's next
            // receive as a reset. Not an error of this server's; told to ignore it.
            if (OperatingSystem.IsWindows())
                udp.Client.IOControl(-1744830452 /* SIO_UDP_CONNRESET */, [ 0 ], null);

            loop = Task.Run(Serve);

        }

        private async Task Serve()
        {
            try
            {
                while (!stop.IsCancellationRequested)
                {

                    var received = await udp.ReceiveAsync(stop.Token);
                    var type     = RawDnsReader.Parse(received.Buffer).Questions[0].Type;

                    if (replies.GetValueOrDefault(type) is not Reply reply)
                        continue;

                    _ = Task.Run(async () => {
                        try
                        {
                            await Task.Delay(reply.Delay, stop.Token);
                            await udp.SendAsync(reply.Response(received.Buffer), received.RemoteEndPoint, stop.Token);
                        }
                        catch (OperationCanceledException) { }
                        catch (ObjectDisposedException)    { }
                        catch (SocketException)            { }
                    });

                }
            }
            catch (OperationCanceledException) { }
            catch (ObjectDisposedException)    { }
            catch (SocketException)            { }
        }

        public async ValueTask DisposeAsync()
        {
            await stop.CancelAsync();
            udp.Dispose();
            try { await loop.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
            stop.Dispose();
        }

    }


    private static DNSUDPClient ClientFor(PerTypeServer Server, TimeSpan QueryTimeout)
        => new (IPv4Address.Localhost,
                IPPort.Parse((UInt16) Server.Port),
                QueryTimeout: QueryTimeout);


    private static String[] Shown(IEnumerable<IIPAddress> Addresses)
        => [ .. Addresses.Select(address => address.ToString()) ];

    private static readonly String ExpectedIPv4 = IPv4Address.Parse("192.0.2.41").ToString();
    private static readonly String ExpectedIPv6 = IPv6Address.Parse("2001:db8::41").ToString();

    #endregion


    #region A positive answer first

    [Test]
    [Property("RFC", "8305 §3, §4")]
    public async Task The_Other_Family_Answering_Within_The_Resolution_Delay_Is_Taken_Too()
    {

        // The A answer at once, the AAAA answer 300 ms later, with five seconds of
        // Resolution Delay. The A answer is positive and first, so the AAAA is
        // waited for - "it is common for the AAAA response to follow the A response
        // by a few milliseconds" - and it arrives in time. Both families come back,
        // IPv6 first. Returning with the A answer alone would have dropped the
        // family RFC 8305 prefers, for want of waiting at all.
        await using var server = new PerTypeServer(AAAA: Address(TimeSpan.FromMilliseconds(300)),
                                                   A:    Address(TimeSpan.Zero));

        await using var client = ClientFor(server, TimeSpan.FromSeconds(20));

        var addresses = await client.Query_IPAddressesToConnect(Name, ResolutionDelay: TimeSpan.FromSeconds(5));

        Assert.That(Shown(addresses), Is.EqualTo(new[] { ExpectedIPv6, ExpectedIPv4 }),
                    "the AAAA answer arrived within the Resolution Delay, so both families, IPv6 first");

    }


    [Test]
    [Property("RFC", "8305 §3")]
    public async Task The_Other_Family_Is_Not_Waited_For_Past_The_Resolution_Delay()
    {

        // The A answer at once, the AAAA question never answered, a query timeout of
        // twenty seconds and a Resolution Delay of 200 ms. "If one query fails to
        // return or takes significantly longer to return, waiting for the second
        // address family can significantly delay the connection establishment of
        // the first one": the IPv4 address is what there is, and it is returned
        // when the delay is over, not when the AAAA query gives up.
        var timeout = TimeSpan.FromSeconds(20);

        await using var server = new PerTypeServer(AAAA: null,
                                                   A:    Address(TimeSpan.Zero));

        await using var client = ClientFor(server, timeout);

        var clock     = Stopwatch.StartNew();
        var addresses = await client.Query_IPAddressesToConnect(Name, ResolutionDelay: TimeSpan.FromMilliseconds(200), Timeout: timeout);
        clock.Stop();

        TestContext.Out.WriteLine($"returned after {clock.Elapsed.TotalMilliseconds:F0} ms");

        Assert.Multiple(() => {

            Assert.That(Shown(addresses), Is.EqualTo(new[] { ExpectedIPv4 }),
                        "the positive control: the A answer is what came back");

            Assert.That(clock.Elapsed, Is.LessThan(timeout / 4),
                        "§3: once the A answer was in, the silent AAAA query was waited for the Resolution Delay, not its timeout");

        });

    }

    #endregion

    #region A negative answer first

    [Test]
    [Property("RFC", "8305 §3, 2308 §2.2")]
    public async Task A_Negative_Answer_First_Does_Not_End_The_Wait_For_The_Other_Family()
    {

        // The AAAA question answered at once with NODATA - "a negative AAAA response
        // (no error, no data)" - and the A answer 400 ms later, eight times the
        // default Resolution Delay. Nothing has been found to connect to when the
        // NODATA arrives, so the delay has not started: the A answer is waited for
        // as long as it takes, and it is the answer.
        await using var server = new PerTypeServer(AAAA: NoData (TimeSpan.Zero),
                                                   A:    Address(TimeSpan.FromMilliseconds(400)));

        await using var client = ClientFor(server, TimeSpan.FromSeconds(20));

        var addresses = await client.Query_IPAddressesToConnect(Name);

        Assert.That(Shown(addresses), Is.EqualTo(new[] { ExpectedIPv4 }),
                    "the AAAA answer had no addresses, so the A answer was waited for past the Resolution Delay");

    }

    #endregion

}

using System.Diagnostics;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// DNS over SSH, the client: what is the transport's own, beside what it shares
/// with DNS over TCP and TLS.
/// </summary>
/// <remarks>
/// <para>
/// The specification is the white paper "DNS over SSH": the SSH subsystem
/// "dns@open.charging.cloud" on a session channel carries, in both directions,
/// "what a TCP connection carries for DNS" (section 3.2) - a two-octet length
/// and one message - and takes its rules from RFC 7766 and, "where they say
/// 'TLS session'", from RFC 7858 §3.3 "for the channel". Chapter 11 of the paper
/// numbers its test criteria; the tests here name the ones they are (T2, T3,
/// T19, T22) and the sections the others come from.
/// </para>
/// <para>
/// What the stream clients are asked alike - a channel that ends under a query,
/// TIMEOUT 0, an answer out of order, a deadline, a client that is disposed of -
/// runs over SSH in the tests that ask it: <see cref="ConnectionTeardownTests"/>,
/// <see cref="PipelinedKeepaliveTests"/>, <see cref="AnswerHandoverTests"/>,
/// <see cref="TimeoutReportingTests"/>, <see cref="ClientLifecycleTests"/> and
/// <see cref="FramedTransportQueryTests"/>. Here is what only SSH has: the
/// channel that ends while the connection stays, the login, the host key, the
/// subsystem that is refused, a connection the client is handed.
/// </para>
/// <para>
/// The server is a <see cref="ScriptedSshServer"/>: Hermod's SSH underneath, as
/// there is no other to run in-process, and the suite's own script in the
/// subsystem - its framing, its messages, its counts.
/// </para>
/// </remarks>
[TestFixture]
[Property("Paper", "DNS over SSH")]
public class DnsOverSshTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(6);

    private static readonly DNSResourceRecordTypes[] TypeA = [ DNSResourceRecordTypes.A ];

    /// <summary>The EDNS(0) option code of Padding (RFC 7830 §3: "The OPTION-CODE for the "Padding" option is 12").</summary>
    private const UInt16 PaddingOption = 12;

    /// <summary>The last octet of the address each name is answered with, so that an answer handed to the wrong query shows.</summary>
    private static readonly Dictionary<String, Byte> Hosts = new() {
                                                                 ["one.example."]    = 1,
                                                                 ["two.example."]    = 2,
                                                                 ["three.example."]  = 3
                                                             };

    /// <summary>The address no name is answered with by an honest answer.</summary>
    private const String Forged = "203.0.113.66";


    private static String NameOf(Byte[] Query)
        => $"{RawDnsReader.Parse(Query, RawDnsReaderOptions.Lenient).Questions[0].Name.Canonical}.";

    /// <summary>One A record for the name asked: 192.0.2.x, where x tells the names apart.</summary>
    private static Byte[] Answer(Byte[] Query)
    {
        var name = NameOf(Query);
        return RawDnsResponder.Answer(Query, (name, RawDnsType.A, 300, [ 192, 0, 2, Hosts.GetValueOrDefault(name, (Byte) 53) ]));
    }

    /// <summary>
    /// The same answer with an edns-tcp-keepalive option of the given timeout -
    /// RFC 7828 §3.1: "specified in units of 100 milliseconds".
    /// </summary>
    private static Byte[] AnswerWithKeepalive(Byte[] Query, UInt16 Timeout)
    {

        var name      = NameOf(Query);
        var query     = RawDnsReader.Parse(Query, RawDnsReaderOptions.Lenient);
        var question  = Query[12..(12 + query.Questions[0].Name.WireLength + 4)];

        return new RawDnsWriter().
                   Header(query.Id, RawDnsResponder.DefaultFlags, 1, 1, 0, 1).
                   Bytes (question).
                   RR    (name, RawDnsType.A, RawDnsClass.IN, 300, [ 192, 0, 2, Hosts.GetValueOrDefault(name, (Byte) 53) ]).
                   Opt   (1232, options: [ 0x00, 0x0B, 0x00, 0x02, (Byte) (Timeout >> 8), (Byte) (Timeout & 0xFF) ]).
                   ToArray();

    }

    /// <summary>An answer to the query that no honest server gave.</summary>
    private static Byte[] ForgedAnswer(Byte[] Query)
        => RawDnsResponder.Answer(Query, (NameOf(Query), RawDnsType.A, 300, [ 203, 0, 113, 66 ]));

    private static String[] AddressesOf(DNSInfo Info)
        => [.. Info.Answers.OfType<A>().Select(a => a.IPv4Address.ToString())];

    private static async Task Eventually(Func<Boolean> Holds, String What)
    {

        var since = Stopwatch.GetTimestamp();

        while (!Holds())
        {

            if (Stopwatch.GetElapsedTime(since) > TimeSpan.FromSeconds(10))
                Assert.Fail($"{What} did not happen within 10 s.");

            await Task.Delay(20);

        }

    }

    /// <summary>
    /// A server that answers every query of every channel but those of the
    /// first, which <paramref name="OnFirst"/> is given instead.
    /// </summary>
    private static ScriptedSshServer FirstChannelThen(Func<ScriptedSshChannel, Byte[], Task> OnFirst)

        => new (async (channel, token) => {

               while (await channel.ReadMessageAsync(token) is Byte[] query)
               {

                   if (channel.Number == 1)
                       await OnFirst(channel, query);

                   else
                       await channel.WriteMessageAsync(Answer(query), token);

               }

           });

    #endregion


    #region The byte stream (section 3.2, appendix A)

    /// <summary>
    /// Section 3.2: "The client writes first. There is nothing to wait for; the
    /// first two octets of the channel are the length of the first query."
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.1, §3.2, A.1, A.4")]
    [Property("RFC",   "4254 §6.5, 1035 §4.2.2")]
    public async Task The_Client_Writes_First_And_The_Channel_Begins_With_The_Length_Of_Its_Query()
    {

        // The server says nothing before it has read: a client that waited for a
        // greeting would wait out its deadline. What the server reads is taken
        // apart by the suite's own framing, so "the first two octets are the
        // length" is: the octets behind them, that many, are one DNS message
        // that RawDns reads to its last octet - the query that was asked.
        await using var server = new ScriptedSshServer(Answer);

        await using var client = server.NewClient(Timeout);

        // Appendix A.1 advertises a UDP size of 1232; the client's default is its
        // own. Told A.1's, it has every octet of A.1 to write but the ID.
        client.UDPPayloadSize = 1232;

        var info = await client.Query(DNSServiceName.Parse("csms.example.org."), TypeA, Timeout);

        Assert.That(info.IsValid,     Is.True,             "the query was answered: the client wrote without being spoken to");
        Assert.That(server.Requests,  Has.Count.EqualTo(1), "one message was read from the channel");

        var request = server.Requests.Single();
        var query   = RawDnsReader.Parse(request);

        // Appendix A.1, without its two octets of length and its two of ID.
        var a1      = Convert.FromHexString(
                          "0100" + "0001" + "0000" + "0000" + "0001" +
                          "0463736d73076578616d706c65036f726700" + "0001" + "0001" +
                          "00" + "0029" + "04d0" + "00000000" + "0053" +
                          "000c" + "004f" + new String('0', 2 * 79)
                      );

        Assert.Multiple(() => {

            Assert.That(query.ConsumedBytes,          Is.EqualTo(request.Length),
                        "the two octets in front of it were its length: the message ends where they said");

            Assert.That(query.QR,                     Is.False,  "and it is a query");
            Assert.That(query.Questions,              Has.Count.EqualTo(1));
            Assert.That(query.Questions[0].Name.Canonical,
                                                      Is.EqualTo("csms.example.org"));
            Assert.That(query.Questions[0].Type,      Is.EqualTo(RawDnsType.A));

            Assert.That(request.Length,               Is.EqualTo(128),
                        "appendix A.1: \"130 octets: the length 0x0080, then the 128 octets of the message\"");

            Assert.That(Convert.ToHexString(request[2..]),
                                                      Is.EqualTo(Convert.ToHexString(a1)),
                        "appendix A.1, octet for octet behind the ID");

            // Appendix A.4 and RFC 4254 §6.5: string "subsystem", string
            // "dns@open.charging.cloud". The server serves that name and no
            // other, so a query that arrived was asked for under it.
            Assert.That(DNSSSHClient.DefaultSubsystem, Is.EqualTo("dns@open.charging.cloud"), "section 3.1: the name");
            Assert.That(client.Subsystem,              Is.EqualTo("dns@open.charging.cloud"));
            Assert.That(server.SubsystemRequests,      Is.EqualTo(1), "asked for once, by that name");

        });

    }


    /// <summary>
    /// Section 3.2: "Length and message should go to the channel in one write,
    /// as RFC 7766, section 8 asks for TCP."
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.2")]
    [Property("RFC",   "7766 §8")]
    public async Task The_Length_And_The_Message_Of_A_Query_Go_To_The_Channel_In_One_Write()
    {

        // RFC 7766 §8: "DNS clients and servers SHOULD pass the two-octet length
        // field, and the message described by that length field, to the TCP
        // layer at the same time (e.g., in a single "write" system call)". On a
        // channel a write is an SSH_MSG_CHANNEL_DATA, and what one of them
        // carries is there together when the server reads: a read that returns
        // two octets is a length that travelled alone. Three queries one after
        // another, so that no read can hold more than one of them, and each read
        // has to be a whole one.
        await using var server = new ScriptedSshServer(Answer);

        await using var client = server.NewClient(Timeout);

        await client.Query(DNSServiceName.Parse("one.example."),   TypeA, Timeout);
        await client.Query(DNSServiceName.Parse("two.example."),   TypeA, Timeout);
        await client.Query(DNSServiceName.Parse("three.example."), TypeA, Timeout);

        Assert.That(server.Channels, Has.Count.EqualTo(1), "one channel for the three");

        var lengths = server.Requests.Select(request => 2 + request.Length).ToArray();

        Assert.That(server.Channels[0].ReadSizes, Is.EqualTo(lengths),
                    "every read of the channel returned one query whole, its length in front: " +
                    "length and message were one write");

    }

    #endregion

    #region Pipelining and answers out of order (section 3.3, T2)

    /// <summary>
    /// T2: three queries outstanding at once on one channel, the answers in
    /// another order.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.3, T2")]
    [Property("RFC",   "7766 §6.2.1.1, 7766 §7, 7858 §3.3")]
    public async Task Three_Queries_Outstanding_On_One_Channel_Each_Get_Their_Own_Answer_In_Whatever_Order()
    {

        // RFC 7766 §6.2.1.1: "When a DNS client sends multiple queries to a
        // server, it SHOULD NOT wait for an outstanding reply before sending the
        // next query." The server answers nothing until it holds three queries,
        // or a second has passed, and says how many it held: a client that waits
        // for an answer before it asks again never gets to three.
        //
        // RFC 7858 §3.3, which section 3.3 of the paper carries over to the
        // channel: "Since pipelined responses can arrive out of order, clients
        // MUST match responses to outstanding queries on the same TLS connection
        // using the Message ID." The answers leave third, first, second.
        var held = 0;

        await using var server = new ScriptedSshServer(async (channel, token) => {

                                     var queries = new List<Byte[]>();

                                     using var window = CancellationTokenSource.CreateLinkedTokenSource(token);
                                     window.CancelAfter(TimeSpan.FromSeconds(1));

                                     try
                                     {
                                         while (queries.Count < 3 && await channel.ReadMessageAsync(window.Token) is Byte[] query)
                                             queries.Add(query);
                                     }
                                     catch (OperationCanceledException) when (!token.IsCancellationRequested)
                                     { }

                                     Volatile.Write(ref held, queries.Count);

                                     foreach (var name in new[] { "three.example.", "one.example.", "two.example." })
                                         if (queries.FirstOrDefault(query => NameOf(query) == name) is Byte[] asked)
                                             await channel.WriteMessageAsync(Answer(asked), token);

                                     while (await channel.ReadMessageAsync(token) is not null)
                                     { }

                                 });

        await using var client = server.NewClient(Timeout);

        var one   = client.Query(DNSServiceName.Parse("one.example."),   TypeA, Timeout);
        var two   = client.Query(DNSServiceName.Parse("two.example."),   TypeA, Timeout);
        var three = client.Query(DNSServiceName.Parse("three.example."), TypeA, Timeout);

        await Task.WhenAll(one, two, three);

        Assert.Multiple(() => {

            Assert.That(held,                       Is.EqualTo(3),
                        "RFC 7766 §6.2.1.1: all three queries were on the channel before the first answer left");

            Assert.That(AddressesOf(one.Result),    Is.EqualTo(new[] { "192.0.2.1" }),  "the first query has its own answer, which came second");
            Assert.That(AddressesOf(two.Result),    Is.EqualTo(new[] { "192.0.2.2" }),  "the second its own, which came last");
            Assert.That(AddressesOf(three.Result),  Is.EqualTo(new[] { "192.0.2.3" }),  "and the third its own, which came first");

            Assert.That(server.ChannelsOpened,      Is.EqualTo(1),  "section 3.3: one channel is enough");
            Assert.That(server.ConnectionCount,     Is.EqualTo(1),  "on one connection");

        });

    }


    /// <summary>
    /// A message with the ID of one outstanding query and the question of
    /// another is the answer to neither.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.3")]
    [Property("RFC",   "7858 §3.3, 7766 §7")]
    public async Task A_Message_With_The_Id_Of_One_Query_And_The_Question_Of_Another_Answers_Neither()
    {

        // RFC 7858 §3.3, after the Message ID: "If the response contains a
        // Question Section, the client MUST match the QNAME, QCLASS, and QTYPE
        // fields." Two queries are outstanding. What the server writes first has
        // the ID of each and the question - and a forged address - of the other;
        // the honest answers follow. A client that matched by ID alone would
        // hand each query the other's forgery.
        await using var server = new ScriptedSshServer(async (channel, token) => {

                                     var first   = await channel.ReadMessageAsync(token);
                                     var second  = await channel.ReadMessageAsync(token);

                                     if (first is null || second is null)
                                         return;

                                     var crossed  = ForgedAnswer(second);
                                     crossed[0]   = first[0];
                                     crossed[1]   = first[1];

                                     var crossedBack  = ForgedAnswer(first);
                                     crossedBack[0]   = second[0];
                                     crossedBack[1]   = second[1];

                                     await channel.WriteMessageAsync(crossed,        token);
                                     await channel.WriteMessageAsync(crossedBack,    token);
                                     await channel.WriteMessageAsync(Answer(second), token);
                                     await channel.WriteMessageAsync(Answer(first),  token);

                                     while (await channel.ReadMessageAsync(token) is not null)
                                     { }

                                 });

        await using var client = server.NewClient(Timeout);

        var one = client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);
        var two = client.Query(DNSServiceName.Parse("two.example."), TypeA, Timeout);

        await Task.WhenAll(one, two);

        Assert.Multiple(() => {
            Assert.That(AddressesOf(one.Result), Is.EqualTo(new[] { "192.0.2.1" }), "the first query: its own answer, not the message that carried its ID");
            Assert.That(AddressesOf(two.Result), Is.EqualTo(new[] { "192.0.2.2" }), "and the second likewise");
        });

    }

    #endregion

    #region SSH packets do not delimit messages (section 3.2, T3)

    /// <summary>
    /// T3: "an answer of 60,000 octets" arrives whole, however many
    /// SSH_MSG_CHANNEL_DATA it took.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.2, T3")]
    [Property("RFC",   "7766 §8")]
    public async Task An_Answer_Of_Sixty_Thousand_Octets_In_Many_Small_Channel_Writes_Arrives_Whole()
    {

        // Section 3.2: "SSH packets do not delimit messages. [...] A reader reads
        // lengths and messages from the stream and never assumes one message per
        // packet." 2221 address records behind the question make a message of
        // just under 60,000 octets. Its length goes out an octet at a time and
        // the rest in writes of 997, a number that divides nothing here.
        const Int32 records = 2221;

        Byte[] big(Byte[] query)
            => RawDnsResponder.Answer(query,
                                      [.. Enumerable.Range(0, records).
                                                     Select(i => (NameOf(query), RawDnsType.A, (UInt32) 300, new Byte[] { 10, (Byte) (i >> 8), (Byte) (i & 0xFF), 1 }))]);

        await using var server = new ScriptedSshServer(big,
                                                       new ScriptedSshOptions {
                                                           SplitLengthPrefix  = true,
                                                           WriteChunkSize     = 997,
                                                           WriteChunkDelay    = TimeSpan.FromMilliseconds(1)
                                                       });

        await using var client = server.NewClient(Timeout);

        var info      = await client.Query(DNSServiceName.Parse("big.example."), TypeA, Timeout);
        var addresses = AddressesOf(info);

        var sent      = big(server.Requests.Single()).Length;

        Assert.Multiple(() => {

            Assert.That(sent,                   Is.InRange(59_900, 60_100),          "the answer the server wrote was the 60,000 octets of T3");
            Assert.That(info.IsValid,           Is.True,                              "it arrived");
            Assert.That(addresses,              Has.Length.EqualTo(records),          "whole: every record of it");
            Assert.That(addresses.First(),      Is.EqualTo("10.0.0.1"),               "from the first");
            Assert.That(addresses.Last(),       Is.EqualTo("10.8.172.1"),             "to the last");
            Assert.That(server.ChannelsOpened,  Is.EqualTo(1),                        "on the channel it was asked on");

        });

    }


    /// <summary>
    /// Section 3.2: "one of them may hold the end of a message and the start of
    /// the next".
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.2, T3")]
    [Property("RFC",   "7766 §8")]
    public async Task The_End_Of_One_Answer_And_The_Start_Of_The_Next_In_One_Channel_Write_Arrive_Whole()
    {

        // Two queries outstanding, two answers, three writes: the first half of
        // the first answer; its second half with the length and the first five
        // octets of the second answer behind it; the rest of the second. No
        // write is a message, and the middle one is parts of two.
        await using var server = new ScriptedSshServer(async (channel, token) => {

                                     var first   = await channel.ReadMessageAsync(token);
                                     var second  = await channel.ReadMessageAsync(token);

                                     if (first is null || second is null)
                                         return;

                                     var one     = ScriptedSshServer.Framed(Answer(first));
                                     var two     = ScriptedSshServer.Framed(Answer(second));
                                     var half    = one.Length / 2;

                                     await channel.WriteAsync(one.AsMemory(0, half), token);
                                     await Task.Delay(50, token);
                                     await channel.WriteAsync((Byte[]) [ .. one[half..], .. two[..7] ], token);
                                     await Task.Delay(50, token);
                                     await channel.WriteAsync(two.AsMemory(7), token);

                                     while (await channel.ReadMessageAsync(token) is not null)
                                     { }

                                 });

        await using var client = server.NewClient(Timeout);

        var one = client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);
        var two = client.Query(DNSServiceName.Parse("two.example."), TypeA, Timeout);

        await Task.WhenAll(one, two);

        Assert.Multiple(() => {
            Assert.That(AddressesOf(one.Result),  Is.EqualTo(new[] { "192.0.2.1" }),  "the answer that ended in the middle of a write");
            Assert.That(AddressesOf(two.Result),  Is.EqualTo(new[] { "192.0.2.2" }),  "and the one that began there");
            Assert.That(server.ChannelsOpened,    Is.EqualTo(1),                      "read from the one channel, which was never given up");
        });

    }

    #endregion

    #region A channel ends, the connection stays (sections 3.3 and 3.5, T19)

    /// <summary>
    /// T19: "The server closes an idle DNS channel on a shared connection. [...]
    /// the connection [...] go[es] on; the next query opens a new channel."
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.3, §3.5, T19")]
    [Property("RFC",   "4254 §6.10, 7766 §6.2.3, 7858 §3.4")]
    public async Task After_The_Server_Ended_The_Idle_Channel_The_Next_Query_Opens_A_New_One_On_The_Same_Connection()
    {

        // Section 3.5: "A channel ends, the connection stays. Neither side ends
        // the SSH connection because a DNS channel ended. A client opens a new
        // channel at its next query." The server ends the channel as section 3.5
        // has it: exit-status 0 (RFC 4254 §6.10), EOF, CLOSE. What the handshake
        // and the login cost is paid once - section 3.7 - so the server counts
        // them: one TCP connection, one authentication, two channels.
        await using var server = new ScriptedSshServer(Answer);

        await using var client = server.NewClient(Timeout);

        var first      = await client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);
        var connection = client.Connection;

        await server.Channels[0].EndAsync(0);

        // Idle: the end of the channel reaches the client with nothing asked.
        await Task.Delay(TimeSpan.FromMilliseconds(250));

        var second     = await client.Query(DNSServiceName.Parse("two.example."), TypeA, Timeout);

        Assert.Multiple(() => {

            Assert.That(AddressesOf(first),            Is.EqualTo(new[] { "192.0.2.1" }),  "the first query was answered");
            Assert.That(AddressesOf(second),           Is.EqualTo(new[] { "192.0.2.2" }),  "and the one asked after the channel ended");

            Assert.That(server.ChannelsOpened,         Is.EqualTo(2),  "on a new channel");
            Assert.That(server.ConnectionCount,        Is.EqualTo(1),  "of the same SSH connection: no second TCP connection was made");
            Assert.That(server.AuthenticationCount,    Is.EqualTo(1),  "and nobody signed in again");

            Assert.That(server.Channels.Select(channel => channel.ConnectionNumber),
                                                       Is.EqualTo(new[] { 1, 1 }),
                        "both channels were channels of the first connection");

            Assert.That(server.Channels[1].Requests.Select(NameOf),
                                                       Is.EqualTo(new[] { "two.example." }),
                        "the second query went out once, on the second channel");

            Assert.That(client.ChannelsOpened,         Is.EqualTo(2),  "which is what the client counts, too");
            Assert.That(client.ConnectionsMade,        Is.EqualTo(1));
            Assert.That(client.Connection,             Is.SameAs(connection).And.Not.Null,
                        "its SSH connection is the one it had");

        });

    }


    /// <summary>
    /// Section 3.3: "a client re-sends the queries left unanswered on a closed
    /// channel over a new one" - whichever exit-status the channel ended with.
    /// </summary>
    [TestCase(0u)]
    [TestCase(1u)]
    [Property("Paper", "DNS over SSH §3.3, §3.5, T19")]
    [Property("RFC",   "7766 §6.2.4, 4254 §6.10")]
    public async Task A_Query_In_Flight_When_Its_Channel_Ends_Is_Asked_Again_Once_On_A_New_Channel(UInt32 ExitStatus)
    {

        // RFC 7766 §6.2.4: "DNS clients SHOULD retry unanswered queries if the
        // connection closes before receiving all outstanding responses." The
        // first channel is ended the moment the query is read from it - with 0,
        // the server's idle timeout or its stopping, or with 1, its word for a
        // protocol error (section 3.5). RFC 4254 §6.10: "The client MAY ignore
        // these messages", and for what the client does next it makes no
        // difference: the query was not answered.
        await using var server = FirstChannelThen((channel, _) => channel.EndAsync(ExitStatus));

        await using var client = server.NewClient(Timeout);

        var info = await client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);

        Assert.Multiple(() => {

            Assert.That(AddressesOf(info),             Is.EqualTo(new[] { "192.0.2.1" }),  "the query was answered after all");

            Assert.That(server.Channels,               Has.Count.EqualTo(2),               "on a second channel");

            Assert.That(server.Requests.Select(NameOf),
                                                       Is.EqualTo(new[] { "one.example.", "one.example." }),
                        "asked once on the channel that ended, and once more on the new one");

            Assert.That(server.ConnectionCount,        Is.EqualTo(1),  "section 3.5: the channel ended, the connection stayed");
            Assert.That(server.AuthenticationCount,    Is.EqualTo(1),  "one login for both channels");
            Assert.That(client.ConnectionsMade,        Is.EqualTo(1));

        });

    }


    /// <summary>
    /// The bound of asking again: once, and on the connection that is there.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.3, §3.5")]
    [Property("RFC",   "7766 §6.2.4, 7858 §7")]
    public async Task A_Server_That_Ends_Every_Channel_Gets_The_Query_Twice_On_One_Connection()
    {

        // ConnectionTeardownTests has the count of channels and the failure that
        // is not a timeout, over SSH as over TCP and DoT. What it cannot see is
        // what the two channels were channels of. A client that answered a
        // channel's end by dialling again would pay a key exchange and a login
        // for a retry that costs three round trips (section 3.7) - and, on a
        // connection it shares, would have ended OCPP for a DNS channel.
        await using var server = new ScriptedSshServer(async (channel, token) => {
                                     if (await channel.ReadMessageAsync(token) is not null)
                                         await channel.EndAsync(0);
                                 });

        await using var client = server.NewClient(Timeout);

        var clock = Stopwatch.StartNew();
        var info  = await client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);
        clock.Stop();

        Assert.Multiple(() => {

            Assert.That(info.IsValid,                  Is.False,                  "no answer");
            Assert.That(info.IsTimeout,                Is.False,                  "and no timeout: the server ended the channels, the deadline did not pass");
            Assert.That(clock.Elapsed,                 Is.LessThan(Timeout / 2));

            Assert.That(server.ChannelsOpened,         Is.EqualTo(2),             "the query and one retry");
            Assert.That(server.ConnectionCount,        Is.EqualTo(1),             "both on the one SSH connection");
            Assert.That(server.AuthenticationCount,    Is.EqualTo(1));

        });

    }

    #endregion

    #region The idle timeout is the channel's (section 3.4)

    /// <summary>
    /// Section 3.4: "edns-tcp-keepalive (RFC 7828) is used as over TCP, and its
    /// timeout applies to the channel."
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.4")]
    [Property("RFC",   "7828 §3.2.2")]
    public async Task An_Advertised_Idle_Timeout_Ends_The_Channel_Before_It_Expires_And_Not_The_Connection()
    {

        // RFC 7828 §3.2.2, of a client that was sent the option: "It SHOULD
        // honour the timeout received in that response (overriding any previous
        // timeout) and initiate close of the connection before the timeout
        // expires." Over SSH what has the timeout is the channel, and section
        // 3.4 goes on: "A server that announces it keeps the channel, not the
        // SSH connection, open for that long." So the channel has to end within
        // the two seconds the server announced, by the client's doing - the
        // server here ends nothing - and the connection has to be there for the
        // query that comes after.
        var advertised = TimeSpan.FromSeconds(2);

        await using var server = new ScriptedSshServer(request => AnswerWithKeepalive(request, 20));

        await using var client = server.NewClient(Timeout);

        var first      = await client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);
        var answered   = Stopwatch.GetTimestamp();
        var connection = client.Connection;
        var heard      = client.ServerKeepaliveTimeout;
        var endedAtOnce = server.ChannelsEnded;

        while (server.ChannelsEnded == 0 && Stopwatch.GetElapsedTime(answered) < advertised + TimeSpan.FromSeconds(3))
            await Task.Delay(20);

        var endedAfter = Stopwatch.GetElapsedTime(answered);

        var second     = await client.Query(DNSServiceName.Parse("two.example."), TypeA, Timeout);

        Assert.Multiple(() => {

            Assert.That(AddressesOf(first),            Is.EqualTo(new[] { "192.0.2.1" }),  "the first query was answered");
            Assert.That(heard,                         Is.EqualTo(advertised),             "and the client read the timeout the answer carried");
            Assert.That(endedAtOnce,                   Is.Zero,                            "control: the channel was open when the answer arrived");

            Assert.That(server.Channels[0].Ended,      Is.True,                            "the client ended the channel");
            Assert.That(endedAfter,                    Is.LessThan(advertised),            "RFC 7828 §3.2.2: before the timeout expired");

            Assert.That(AddressesOf(second),           Is.EqualTo(new[] { "192.0.2.2" }),  "the next query was answered");
            Assert.That(server.ChannelsOpened,         Is.EqualTo(2),                      "on a new channel");
            Assert.That(server.ConnectionCount,        Is.EqualTo(1),                      "section 3.4: of the SSH connection, which the timeout was not about");
            Assert.That(server.AuthenticationCount,    Is.EqualTo(1));
            Assert.That(client.Connection,             Is.SameAs(connection).And.Not.Null);

        });

    }

    #endregion

    #region Padding (section 3.4, T22)

    /// <summary>
    /// T22: "Queries padded to a multiple of 128 octets".
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.4, T22")]
    [Property("RFC",   "8467 §4.1, 7830 §3")]
    public async Task Queries_Are_Padded_To_A_Multiple_Of_128_Octets_And_The_Padding_Option_Is_What_Makes_The_Length()
    {

        // Section 3.4: "SSH hides the content of a message, not its length.
        // Clients pad their queries to a multiple of 128 octets". RFC 8467 §4.1:
        // "Clients SHOULD pad queries to the closest multiple of 128 octets."
        // Three names of three lengths, the last one too long for one block, so
        // that "a multiple" is seen to be more than "128". The same three from a
        // client told not to pad are the control: they are of no such length,
        // and carry no such option.
        var names = new[] {
                        "a.example.",
                        "csms.example.org.",
                        $"{new String('a', 60)}.{new String('b', 60)}.{new String('c', 60)}.example."
                    };

        await using var server = new ScriptedSshServer(Answer);

        await using var padding = server.NewClient(Timeout);

        foreach (var name in names)
            await padding.Query(DNSServiceName.Parse(name), TypeA, Timeout);

        var padded   = server.Requests.ToArray();

        await using var plain = server.NewClient(Timeout);
        plain.PaddingBlockSize = 0;

        foreach (var name in names)
            await plain.Query(DNSServiceName.Parse(name), TypeA, Timeout);

        var unpadded = server.Requests.Skip(padded.Length).ToArray();

        Assert.That(padded,   Has.Length.EqualTo(3), "the three padded queries arrived");
        Assert.That(unpadded, Has.Length.EqualTo(3), "and the three of the control");

        Assert.Multiple(() => {

            Assert.That(padded.Select(query => query.Length),
                                              Is.EqualTo(new[] { 128, 128, 256 }),
                        "every query is a multiple of 128 octets long, the nearest that holds it");

            foreach (var query in padded)
            {

                var options = RawDnsReader.Parse(query).Edns?.Options ?? [];
                var pad     = options.Where(option => option.Code == PaddingOption).ToArray();

                Assert.That(pad,              Has.Length.EqualTo(1),
                            "RFC 7830 §3: the length is made by one Padding option in the OPT record");

                if (pad.Length != 1)
                    continue;

                Assert.That(pad[0].Data,      Is.All.EqualTo((Byte) 0),
                            "RFC 7830 §3: \"The PADDING octets SHOULD be set to 0x00\"");

                // Without the option's octets the message ends short of the
                // block; with its four octets of header alone it still fits
                // into the block it was padded to.
                var without = query.Length - 4 - pad[0].Data.Length;

                Assert.That(without % 128,    Is.Not.Zero,
                            "the message without the option is of no such length");

                Assert.That(without + 4,      Is.GreaterThan(query.Length - 128).And.LessThanOrEqualTo(query.Length),
                            "RFC 8467 §4.1: the closest multiple - not a block more than the query needs");

            }

            foreach (var query in unpadded)
            {

                Assert.That(query.Length % 128,  Is.Not.Zero,
                            "the control: unpadded, these queries are no multiple of 128 octets long");

                Assert.That((RawDnsReader.Parse(query).Edns?.Options ?? []).Any(option => option.Code == PaddingOption),
                                                 Is.False,
                            "and carry no Padding option");

            }

        });

    }

    #endregion

    #region A subsystem that is refused (section 3.1, T11)

    /// <summary>
    /// T11: "SSH_MSG_CHANNEL_FAILURE" for a login the server does not offer DNS
    /// to - a failure of its own, told apart from a timeout, and no query sent.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.1, T11")]
    [Property("RFC",   "4254 §6.5")]
    public async Task A_Refused_Subsystem_Is_Told_Apart_From_A_Timeout_And_No_Query_Is_Sent()
    {

        // Section 3.1: the client "sends a subsystem request with the name, with
        // want reply set, and waits for the answer before it writes. A server
        // that does not offer the subsystem to this login answers
        // SSH_MSG_CHANNEL_FAILURE." RFC 4254 §6.5: "It is RECOMMENDED that the
        // reply to these messages be requested and checked."
        //
        // The positive control is the server's own account: it was reached, the
        // login was good, the subsystem was asked for. Without it "no query
        // arrived" would also be true of a client that never left.
        await using var server = new ScriptedSshServer(Answer, new ScriptedSshOptions { RefuseSubsystem = true });

        await using var client = server.NewClient(Timeout);

        var clock = Stopwatch.StartNew();
        var info  = await client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);
        clock.Stop();

        var error = client.LastConnectionError;

        Assert.Multiple(() => {

            Assert.That(server.ConnectionCount,        Is.EqualTo(1),  "control: the server was reached");
            Assert.That(server.AuthenticationCount,    Is.EqualTo(1),  "control: the login was accepted");
            Assert.That(server.SubsystemsRefused,      Is.EqualTo(1),  "control: the subsystem was asked for and refused - once, as asking again would not change it");

            Assert.That(info.IsValid,                  Is.False,       "no answer");
            Assert.That(info.IsTimeout,                Is.False,       "and not a timeout: the server answered, with a refusal");
            Assert.That(clock.Elapsed,                 Is.LessThan(Timeout / 2),
                        "known when the refusal arrived, not at the deadline");

            Assert.That(error,                         Is.InstanceOf<SshSubsystemRefusedException>(),
                        "LastConnectionError says which failure it was");

            Assert.That((error as SshSubsystemRefusedException)?.Subsystem,
                                                       Is.EqualTo("dns@open.charging.cloud"));

            Assert.That(server.ChannelsOpened,         Is.Zero,        "the subsystem never ran");
            Assert.That(server.Requests,               Is.Empty,       "and not an octet of a query was read by anybody");

        });

        // The same failure for whoever asks before it queries, and the SSH
        // connection is not what was refused: the second attempt finds it open.
        Assert.That(async () => await client.ConnectAsync(),
                    Throws.InstanceOf<SshSubsystemRefusedException>(),
                    "ConnectAsync throws what a query keeps");

        Assert.Multiple(() => {
            Assert.That(server.SubsystemsRefused,      Is.EqualTo(2),  "asked for again");
            Assert.That(server.ConnectionCount,        Is.EqualTo(1),  "on the connection that was there: a refusal is the channel's, not the connection's");
            Assert.That(server.AuthenticationCount,    Is.EqualTo(1));
        });

    }


    /// <summary>
    /// The other side of the distinction: a server that serves the subsystem
    /// and does not answer is a timeout, and leaves no connection error.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.1")]
    public async Task A_Served_Subsystem_That_Does_Not_Answer_Is_A_Timeout_With_No_Connection_Error()
    {

        var deadline = TimeSpan.FromSeconds(1.5);

        await using var server = new ScriptedSshServer(_ => (Byte[]?) null);

        await using var client = server.NewClient(deadline);

        var info = await client.Query(DNSServiceName.Parse("one.example."), TypeA, deadline);

        Assert.Multiple(() => {
            Assert.That(server.Requests,             Has.Count.EqualTo(1),  "the query arrived");
            Assert.That(info.IsTimeout,              Is.True,               "and was not answered in time");
            Assert.That(client.LastConnectionError,  Is.Null,               "the channel was opened: there is no connection error to tell");
        });

    }

    #endregion

    #region A host key that is not the pinned one (section 4.1, T5)

    /// <summary>
    /// T5: "A host key that is not pinned. Not used".
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §4.1, T5")]
    public async Task A_Host_Key_That_Is_Not_The_Pinned_One_Gets_No_Login_No_Channel_And_No_Query()
    {

        // The client holds the server to a key the server does not have. The
        // key exchange shows it the server's, and that is where it stops:
        // before the login - a login is what a false server is after - before
        // any channel, before any query. Appendix B.3 has OpenSSH do the same:
        // "Host key verification failed [...] nothing sent".
        //
        // Two positive controls, since every assertion below is an absence. The
        // relay in front of the server counted a TCP connection, so the client
        // was there. And a second client that pins the right key is answered by
        // the same server, so there was something to be had.
        await using var server = new ScriptedSshServer(Answer);

        var other = SshHostKey.GenerateEd25519();

        await using var mistaken = new DNSSSHClient("127.0.0.1",
                                                    server.ClientOptions(PinnedHostKey: other),
                                                    IPPort.Parse((UInt16) server.Port),
                                                    QueryTimeout: Timeout);

        var clock = Stopwatch.StartNew();
        var info  = await mistaken.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);
        clock.Stop();

        Assert.Multiple(() => {

            Assert.That(server.ConnectionCount,        Is.GreaterThanOrEqualTo(1),  "control: the server was reached");

            Assert.That(info.IsValid,                  Is.False,   "no answer");
            Assert.That(info.IsTimeout,                Is.False,   "and not for want of time");
            Assert.That(clock.Elapsed,                 Is.LessThan(Timeout / 2));

            Assert.That(mistaken.LastConnectionError,  Is.Not.Null.And.Not.InstanceOf<SshSubsystemRefusedException>(),
                        "the client knows why, and it was not a refusal of the subsystem");

            Assert.That(server.LoginAttempts,          Is.Zero,    "no key was shown to sign in with");
            Assert.That(server.AuthenticationCount,    Is.Zero,    "nobody signed in");
            Assert.That(server.SubsystemRequests,      Is.Zero,    "no subsystem was asked for");
            Assert.That(server.ChannelsOpened,         Is.Zero,    "no channel of it opened");
            Assert.That(server.Requests,               Is.Empty,   "and no query was sent");

            Assert.That(mistaken.ChannelsOpened,       Is.Zero);

        });

        await using var pinned = server.NewClient(Timeout);

        var answered = await pinned.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);

        Assert.Multiple(() => {
            Assert.That(AddressesOf(answered),         Is.EqualTo(new[] { "192.0.2.1" }),  "control: the same server answers a client that pins its key");
            Assert.That(server.LoginAttempts,          Is.GreaterThan(0),                  "control: and a login is something this server counts");
        });

    }

    #endregion

    #region Whose connection it is (sections 3.5 and 6.3, T12)

    /// <summary>
    /// T12: "the connection and OCPP go on after the DNS channel ends" - a
    /// connection the client was handed is not closed when the client is
    /// disposed of, and carries another channel afterwards.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.5, §6.3, T12")]
    public async Task A_Connection_The_Client_Was_Handed_Is_Not_Closed_With_The_Client_And_Carries_Another_Channel()
    {

        // The SSH connection is made here, by the test, as a station makes the
        // one to its Local Controller, and handed to a DNS client. The client is
        // asked something and disposed of. Section 3.5: "Neither side ends the
        // SSH connection because a DNS channel ended." Then a second client is
        // handed the same connection, and what it asks is the proof that the
        // connection is not merely open but usable.
        await using var server = new ScriptedSshServer(Answer);

        await using var ssh    = await SshClient.ConnectAsync("127.0.0.1", (UInt16) server.Port, server.ClientOptions());

        var first  = new DNSSSHClient(_ => ValueTask.FromResult(ssh), QueryTimeout: Timeout);

        var before = await first.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);

        await first.DisposeAsync();

        // The client's own channel does end with it.
        await Eventually(() => server.ChannelsEnded == 1, "The end of the disposed client's channel");

        // And time for a close of the connection to show, were there one.
        await Task.Delay(TimeSpan.FromMilliseconds(250));

        var openAfterDispose = !ssh.Closed.IsCompleted;

        await using var second = new DNSSSHClient(_ => ValueTask.FromResult(ssh), QueryTimeout: Timeout);

        var after  = await second.Query(DNSServiceName.Parse("two.example."), TypeA, Timeout);

        Assert.Multiple(() => {

            Assert.That(first.OwnsConnection,          Is.False,                            "a connection that was handed is not the client's own");
            Assert.That(AddressesOf(before),           Is.EqualTo(new[] { "192.0.2.1" }),   "the first client was answered over it");

            Assert.That(openAfterDispose,              Is.True,                             "disposing the client did not close the connection");
            Assert.That(AddressesOf(after),            Is.EqualTo(new[] { "192.0.2.2" }),   "and another channel on it still works");

            Assert.That(server.ChannelsOpened,         Is.EqualTo(2),                       "two channels");
            Assert.That(server.ConnectionCount,        Is.EqualTo(1),                       "of the one connection the test made");
            Assert.That(server.AuthenticationCount,    Is.EqualTo(1),                       "T12: one SSH authentication for both");

        });

    }


    /// <summary>
    /// The contrast: a connection the client dialled itself goes with it.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.5")]
    public async Task A_Connection_Of_The_Clients_Own_Is_Closed_With_The_Client()
    {

        // Without this the test above could pass for a client that closes
        // nothing at all - and a station would keep a connection to every name
        // server it was ever configured with.
        await using var server = new ScriptedSshServer(Answer);

        var client = server.NewClient(Timeout);

        await client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);

        var own = client.Connection;

        Assert.That(own,                     Is.Not.Null,  "the client has a connection after its query");
        Assert.That(client.OwnsConnection,   Is.True,      "and it is its own");
        Assert.That(own!.Closed.IsCompleted, Is.False,     "kept open for the next query");

        await client.DisposeAsync();

        var closed = await Task.WhenAny(own.Closed, Task.Delay(TimeSpan.FromSeconds(5))) == own.Closed;

        // Whatever it ended with is not this test's to judge.
        _ = own.Closed.Exception;

        Assert.Multiple(() => {
            Assert.That(closed,                Is.True,        "disposing the client closed the connection it had dialled");
            Assert.That(client.Connection,     Is.Null,        "and it has none any more");
            Assert.That(server.ChannelsEnded,  Is.EqualTo(1),  "its channel ended with it");
        });

    }

    #endregion

    #region A server over SSH among the servers of a DNSClient

    /// <summary>
    /// A server over SSH beside a UDP server that says nothing: the answer is
    /// the SSH server's.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §7.1")]
    public async Task A_Server_Over_Ssh_Answers_Beside_A_Udp_Server_That_Does_Not()
    {

        await using var udp = ScriptedUdpServer.Silent();
        await using var ssh = new ScriptedSshServer(Answer);

        using var client = new DNSClient(
                               [
                                   new DNSServerConfig(IPv4Address.Localhost, IPPort.Parse((UInt16) udp.Port), DNSTransport.UDP),
                                   DNSServerConfig.OverSSH(IPv4Address.Localhost, ssh.ClientOptions(), IPPort.Parse((UInt16) ssh.Port))
                               ],
                               QueryTimeout:             Timeout,
                               SearchForIPv4DNSServers:  false,
                               SearchForIPv6DNSServers:  false,
                               UseQueryCache:            false
                           );

        var info = await client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);

        Assert.Multiple(() => {

            Assert.That(client.DNSServers.Select(dnsServer => dnsServer.Transport),
                                                 Is.EquivalentTo(new[] { DNSTransport.UDP, DNSTransport.SSH }),
                        "both are servers of the client");

            Assert.That(AddressesOf(info),       Is.EqualTo(new[] { "192.0.2.1" }),   "the answer is the one the SSH server gives");
            Assert.That(info.Origin.Transport,   Is.EqualTo(DNSTransport.SSH),        "and says where it came from");
            Assert.That(ssh.Requests,            Has.Count.EqualTo(1),                "the SSH server was asked once");
            Assert.That(udp.Requests,            Is.Not.Empty,                        "control: the UDP server was asked too, and kept silent");

        });

    }


    /// <summary>
    /// The other way round: the UDP server answers, the SSH server does not.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §7.1")]
    public async Task A_Udp_Server_Answers_Beside_A_Server_Over_Ssh_That_Does_Not()
    {

        await using var udp = new ScriptedUdpServer(request => RawDnsResponder.Answer(request, (NameOf(request), RawDnsType.A, 300, [ 198, 51, 100, 7 ])));
        await using var ssh = new ScriptedSshServer(_ => (Byte[]?) null);

        using var client = new DNSClient(
                               [
                                   new DNSServerConfig(IPv4Address.Localhost, IPPort.Parse((UInt16) udp.Port), DNSTransport.UDP),
                                   DNSServerConfig.OverSSH(IPv4Address.Localhost, ssh.ClientOptions(), IPPort.Parse((UInt16) ssh.Port))
                               ],
                               QueryTimeout:             Timeout,
                               SearchForIPv4DNSServers:  false,
                               SearchForIPv6DNSServers:  false,
                               UseQueryCache:            false
                           );

        var clock = Stopwatch.StartNew();
        var info  = await client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);
        clock.Stop();

        Assert.Multiple(() => {
            Assert.That(AddressesOf(info),       Is.EqualTo(new[] { "198.51.100.7" }),  "the answer is the UDP server's");
            Assert.That(info.Origin.Transport,   Is.EqualTo(DNSTransport.UDP),          "and says so");
            Assert.That(clock.Elapsed,           Is.LessThan(Timeout / 2),              "without waiting for the server over SSH to run out of time");
        });

    }


    /// <summary>
    /// A server named for SSH without a word on how its connection is had is
    /// refused when the servers are named, not when the first query fails.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §4.1, T14")]
    public void A_Server_Named_For_Ssh_Without_Its_Ssh_Settings_Is_Refused_When_The_Servers_Are_Named()
    {

        // Section 4.1: there is no default for what the host key is held to. An
        // address, a port and the word "SSH" make no connection - there is no
        // login in them and no pin - and a client that took them would have a
        // name server it can only fail to reach, or one it reaches unverified.
        // T14 has the Device Model reject such an entry; this is the same rule
        // one layer down.
        var bare = new DNSServerConfig(IPv4Address.Localhost, IPPort.Parse((UInt16) 22), DNSTransport.SSH);
        var udp  = new DNSServerConfig(IPv4Address.Localhost, IPPort.Parse((UInt16) 53), DNSTransport.UDP);

        Assert.That(() => new DNSClient([ udp, bare ],
                                        SearchForIPv4DNSServers:  false,
                                        SearchForIPv6DNSServers:  false),
                    Throws.InstanceOf<NotSupportedException>(),
                    "the constructor refuses it");

        using var client = new DNSClient([ udp ],
                                         SearchForIPv4DNSServers:  false,
                                         SearchForIPv6DNSServers:  false);

        Assert.That(() => client.SetDNSServers([ udp, bare ]),
                    Throws.InstanceOf<NotSupportedException>(),
                    "and so does SetDNSServers");

        Assert.That(client.DNSServers.Select(dnsServer => dnsServer.Transport),
                    Is.EqualTo(new[] { DNSTransport.UDP }),
                    "which leaves the servers as they were");

    }

    #endregion

    #region What the server must not get away with (sections 3.3 and 3.5)

    /// <summary>
    /// A message with an ID nobody is waiting for is not an answer, and the
    /// answer behind it is.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.3")]
    [Property("RFC",   "7858 §3.3, 7766 §7")]
    public async Task An_Answer_With_Another_Id_Is_Skipped_And_The_Answer_Behind_It_Taken()
    {

        // RFC 7766 §7: "clients MUST match responses to outstanding queries on
        // the same TCP connection using the Message ID." The forgery has the
        // right question and another ID, and arrives first.
        await using var server = new ScriptedSshServer(request => new[] {
                                                                      RawDnsResponder.WithWrongId(ForgedAnswer(request)),
                                                                      Answer(request)
                                                                  });

        await using var client = server.NewClient(Timeout);

        var info = await client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);

        Assert.Multiple(() => {
            Assert.That(AddressesOf(info),        Is.EqualTo(new[] { "192.0.2.1" }),  "the answer with the query's ID, not the message in front of it");
            Assert.That(server.ChannelsOpened,    Is.EqualTo(1),                      "read from the channel the query was asked on");
        });

    }


    /// <summary>
    /// And with nothing behind it, the query runs out of time rather than
    /// taking what it was given.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.3")]
    [Property("RFC",   "7858 §3.3, 7766 §7")]
    public async Task An_Answer_With_Another_Id_And_Nothing_Behind_It_Is_A_Timeout()
    {

        var deadline = TimeSpan.FromSeconds(1.5);

        await using var server = new ScriptedSshServer(request => RawDnsResponder.WithWrongId(ForgedAnswer(request)));

        await using var client = server.NewClient(deadline);

        var info = await client.Query(DNSServiceName.Parse("one.example."), TypeA, deadline);

        Assert.Multiple(() => {
            Assert.That(server.ResponsesWritten,  Is.EqualTo(1),   "control: the forgery was written");
            Assert.That(AddressesOf(info),        Is.Empty,        "its address reached nobody");
            Assert.That(info.IsValid,             Is.False);
            Assert.That(info.IsTimeout,           Is.True,         "the query waited for its answer until its time was up");
        });

    }


    /// <summary>
    /// A length of 0, and a message too short for a header, in front of the
    /// answer: the stream stays aligned and the answer is read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Section 3.5 of the paper: "Protocol errors end the channel: a length of 0,
    /// or a message too short to hold the 12 octets of a DNS header. A message
    /// whose header can be read but whose rest cannot is answered with FORMERR,
    /// as over TCP." The sentence stands under "The server ends a channel [...]
    /// after a protocol error", and its second half - answering with FORMERR -
    /// is a server's. It is read here as the server's rule for what a client
    /// sends, and not as a rule for a client that is sent such a thing.
    /// </para>
    /// <para>
    /// For the client the rule that is written down is RFC 7766 §7's, which the
    /// paper carries over: match by ID and question. What matches no outstanding
    /// query is not an answer, and <see cref="OutOfOrderResponseTests"/> holds
    /// the TCP client to consuming such a message rather than stranding the
    /// stream on it. The SSH client does the same: the length said how many
    /// octets to skip, they were skipped, and the next two octets are a length
    /// again. This test asserts that, and that the channel was kept - which is
    /// the reading. A client that ended the channel and asked again would also
    /// be within section 3.3; the paper does not say which it wants.
    /// </para>
    /// </remarks>
    [TestCase(0)]
    [TestCase(5)]
    [TestCase(11)]
    [Property("Paper", "DNS over SSH §3.5, §3.3")]
    [Property("RFC",   "7766 §7, 1035 §4.2.2")]
    public async Task A_Message_Of_No_Length_Or_Too_Short_For_A_Header_Does_Not_Desynchronise_The_Channel(Int32 Length)
    {

        await using var server = new ScriptedSshServer(request => NameOf(request) == "one.example."
                                                                      ? new[] { new Byte[Length], Answer(request) }
                                                                      : new[] { Answer(request) });

        await using var client = server.NewClient(Timeout);

        var one = await client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);
        var two = await client.Query(DNSServiceName.Parse("two.example."), TypeA, Timeout);

        Assert.Multiple(() => {

            Assert.That(AddressesOf(one),         Is.EqualTo(new[] { "192.0.2.1" }),
                        "the answer behind the short message was read as an answer: the stream was still aligned");

            Assert.That(AddressesOf(two),         Is.EqualTo(new[] { "192.0.2.2" }),
                        "and so was the next one");

            Assert.That(server.Requests,          Has.Count.EqualTo(2),  "each query was asked once");
            Assert.That(server.ChannelsOpened,    Is.EqualTo(1),         "on the one channel, which the client kept");

        });

    }


    /// <summary>
    /// An answer cut off in its middle, and the channel ended behind it with
    /// exit-status 1: the query is asked again, once, on a new channel of the
    /// same connection.
    /// </summary>
    [Test]
    [Property("Paper", "DNS over SSH §3.3, §3.5")]
    [Property("RFC",   "7766 §6.2.4, 4254 §6.10")]
    public async Task A_Truncated_Answer_Followed_By_The_End_Of_The_Channel_Has_The_Query_Asked_Again()
    {

        // The length promises the whole answer, half of it follows, and the
        // channel ends. More octets of an answer arrived than for a channel that
        // ended at once, and no answer did: section 3.3's "queries left
        // unanswered on a closed channel", RFC 7766 §6.2.4's "connection closes
        // before receiving all outstanding responses". What must not happen is
        // the other thing a reader could do with half a message - take the next
        // channel's first octets for the rest of it.
        await using var server = FirstChannelThen(async (channel, query) => {
                                     var framed = ScriptedSshServer.Framed(Answer(query));
                                     await channel.WriteAsync(framed.AsMemory(0, 2 + (framed.Length - 2) / 2));
                                     await channel.EndAsync(1);
                                 });

        await using var client = server.NewClient(Timeout);

        var one = await client.Query(DNSServiceName.Parse("one.example."), TypeA, Timeout);
        var two = await client.Query(DNSServiceName.Parse("two.example."), TypeA, Timeout);

        Assert.Multiple(() => {

            Assert.That(AddressesOf(one),              Is.EqualTo(new[] { "192.0.2.1" }),  "the query whose answer was cut off was answered on the next channel");
            Assert.That(AddressesOf(two),              Is.EqualTo(new[] { "192.0.2.2" }),  "which is read from its first octet: the next query's answer is its own");

            Assert.That(server.Requests.Select(NameOf),
                                                       Is.EqualTo(new[] { "one.example.", "one.example.", "two.example." }),
                        "asked again once");

            Assert.That(server.ChannelsOpened,         Is.EqualTo(2),  "two channels");
            Assert.That(server.ConnectionCount,        Is.EqualTo(1),  "of one connection");
            Assert.That(server.AuthenticationCount,    Is.EqualTo(1));

        });

    }

    #endregion

}

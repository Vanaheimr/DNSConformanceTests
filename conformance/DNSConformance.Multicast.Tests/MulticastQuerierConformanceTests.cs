using System.Diagnostics;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Multicast.Tests;

/// <summary>
/// RFC 6762 querier conformance: what Hermod's Multicast DNS client sends, what it
/// believes, and what it keeps.
/// </summary>
/// <remarks>
/// Every other test in this project is about the responder, and none of them built a
/// <see cref="MulticastDNSClient"/>: the first mutation sweep of this block killed none
/// of its 107 mutants, and none of the browser's 85. Here the client is the one under
/// test, and the other host on the link is the suite itself — every answer it hears
/// is built with <see cref="RawDnsWriter"/>, and every query it sends is read back
/// with <see cref="RawDnsReader"/>.
/// </remarks>
[TestFixture]
public sealed class MulticastQuerierConformanceTests
{

    #region Harness

    private sealed record CapturedDatagram(InMemoryMulticastDNSTransport  Sender,
                                           IPSocket?                      Destination,
                                           Byte[]                         Wire,
                                           TimeSpan                       SentAt);

    private sealed class PacketCapture
    {

        private readonly List<CapturedDatagram>  packets  = [];
        private readonly Stopwatch               clock    = Stopwatch.StartNew();

        public PacketCapture(InMemoryMulticastDNSNetwork network)
        {
            network.OnDatagramSent += (_, sender, payload, destination) => {
                lock (packets)
                    packets.Add(new CapturedDatagram(sender, destination, payload.ToArray(), clock.Elapsed));
                return Task.CompletedTask;
            };
        }

        public CapturedDatagram[] QueriesFrom(InMemoryMulticastDNSTransport sender)
        {
            lock (packets)
                return [.. packets.Where(packet => ReferenceEquals(packet.Sender, sender) &&
                                                   !RawDnsReader.Parse(packet.Wire).QR)];
        }

    }


    /// <summary>
    /// A clock the test moves by hand. Only GetUtcNow is overridden — the cache reads
    /// nothing else — so timers keep running in real time.
    /// </summary>
    /// <remarks>
    /// Hermod ships a FakeTimeProvider in its own test project. Borrowing it would let
    /// Hermod supply both the implementation and the instrument that judges it.
    /// </remarks>
    private sealed class SteppedClock : TimeProvider
    {

        private DateTimeOffset now = new (2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow()
            => now;

        public void Advance(TimeSpan by)
            => now = now.Add(by);

    }


    /// <summary>
    /// The client under test and one other host on the same link, which is where every
    /// answer comes from.
    /// </summary>
    private sealed class Link : IAsyncDisposable
    {

        public required InMemoryMulticastDNSNetwork    Network   { get; init; }
        public required InMemoryMulticastDNSTransport  Querier   { get; init; }
        public required InMemoryMulticastDNSTransport  Peer      { get; init; }
        public required MulticastDNSClient             Client    { get; init; }
        public required PacketCapture                  Capture   { get; init; }

        public static async Task<Link> Start(MulticastDNSClientOptions?  Options  = null,
                                             TimeProvider?               Clock    = null)
        {

            var network  = new InMemoryMulticastDNSNetwork();
            var querier  = network.CreateTransport();
            var peer     = network.CreateTransport();
            var capture  = new PacketCapture(network);
            var client   = new MulticastDNSClient(querier, Options, Clock);

            await peer.StartAsync();
            await client.StartAsync();

            return new Link {
                       Network  = network,
                       Querier  = querier,
                       Peer     = peer,
                       Client   = client,
                       Capture  = capture
                   };

        }

        /// <summary>The other host multicasts this message from port 5353.</summary>
        public Task Multicast(Byte[] Wire)
            => Peer.SendAsync(Wire);

        /// <summary>The other host sends this message to the querier's own address.</summary>
        public Task Unicast(Byte[] Wire, Boolean SourceIsOnLocalLink = true)
            => Querier.InjectAsync(Wire,
                                   new IPSocket(Peer.Address, MulticastDNS.Port),
                                   default,
                                   Querier.Address,
                                   SourceIsOnLocalLink);

        /// <summary>A multicast message that came from a port other than 5353.</summary>
        public Task MulticastFromPort(Byte[] Wire, UInt16 Port)
            => Querier.InjectAsync(Wire, new IPSocket(Peer.Address, IPPort.Parse(Port)));

        public CapturedDatagram[] Queries
            => Capture.QueriesFrom(Querier);

        public async ValueTask DisposeAsync()
        {
            await Client.DisposeAsync();
            await Peer.DisposeAsync();
            await Querier.DisposeAsync();
        }

    }


    private static readonly DNSServiceName  Host      = DNSServiceName.Parse("querier-host.local.");
    private static readonly String          HostName  = "querier-host.local.";


    private sealed record Rr(String   Name,
                             UInt16   Type,
                             UInt32   Ttl,
                             Byte[]   Rdata,
                             Boolean  CacheFlush = false);


    private static Rr Address(String Dotted, UInt32 Ttl = 120, Boolean CacheFlush = false, String Name = "querier-host.local.")
        => new (Name, RawDnsType.A, Ttl, RawDnsWriter.IPv4(Dotted), CacheFlush);


    /// <summary>
    /// The restricted NSEC form of RFC 6762 §6.1: window 0, the listed types set, and
    /// the record's own name as the next name unless the test says otherwise.
    /// </summary>
    private static Rr Nsec(String           Name,
                           UInt16[]         Types,
                           String?          NextName  = null,
                           UInt32           Ttl       = 120)
    {

        var bitmap = new Byte[Types.Max() / 8 + 1];

        foreach (var type in Types)
            bitmap[type / 8] |= (Byte) (0x80 >> (type % 8));

        return new (Name,
                    RawDnsType.NSEC,
                    Ttl,
                    [.. RawDnsWriter.NameBytes(NextName ?? Name), 0, (Byte) bitmap.Length, .. bitmap],
                    true);

    }


    /// <summary>An NSEC record with RDATA the test writes byte by byte after the next name.</summary>
    private static Rr NsecWithBitmaps(String Name, params Byte[] Bitmaps)
        => new (Name, RawDnsType.NSEC, 120, [.. RawDnsWriter.NameBytes(Name), .. Bitmaps], true);


    private static Byte[] Response(IEnumerable<Rr>   Answers,
                                   IEnumerable<Rr>?  Additionals  = null,
                                   UInt16            Flags        = 0x8400,
                                   UInt16            Id           = 0,
                                   String?           Question     = null)
    {

        var answers      = Answers.ToArray();
        var additionals  = Additionals?.ToArray() ?? [];

        var writer = new RawDnsWriter().
                         Header(Id,
                                Flags,
                                (UInt16) (Question is null ? 0 : 1),
                                (UInt16) answers.Length,
                                0,
                                (UInt16) additionals.Length);

        if (Question is not null)
            writer.Question(Question, RawDnsType.A);

        foreach (var rr in answers.Concat(additionals))
            writer.RR(rr.Name,
                      rr.Type,
                      (UInt16) (rr.CacheFlush ? RawDnsClass.IN | 0x8000 : RawDnsClass.IN),
                      rr.Ttl,
                      rr.Rdata);

        return writer.ToArray();

    }


    private static IPv4Address[] CachedAddresses(MulticastDNSClient Client, DNSServiceName? Name = null)

        => [.. Client.CachedRecords(Name ?? Host, DNSResourceRecordTypes.A).
                      Select (entry => entry.Record).
                      OfType<A>().
                      Select (a => a.IPv4Address)];


    private static async Task WaitUntil(Func<Boolean>  Condition,
                                        String         What,
                                        Int32          TimeoutMilliseconds = 5000)
    {

        var deadline = DateTime.UtcNow.AddMilliseconds(TimeoutMilliseconds);

        while (DateTime.UtcNow < deadline)
        {
            if (Condition())
                return;
            await Task.Delay(5);
        }

        Assert.Fail($"timed out after {TimeoutMilliseconds} ms waiting for {What}");

    }


    /// <summary>
    /// Start a one-shot query, wait until it is on the wire, let the other host answer
    /// with the given message, and return what the query resolved to.
    /// </summary>
    private static async Task<(DNSInfo Info, TimeSpan Took)> Answered(Link                     Link,
                                                                     DNSResourceRecordTypes   Type,
                                                                     Byte[]                   Answer,
                                                                     TimeSpan                 Timeout)
    {

        var stopwatch  = Stopwatch.StartNew();
        var pending    = Link.Client.Query(Host, [ Type ], Timeout);

        await WaitUntil(() => Link.Queries.Length > 0, "the client's query");
        await Link.Multicast(Answer);

        var info = await pending;

        return (info, stopwatch.Elapsed);

    }

    #endregion


    #region What a query looks like on the wire (RFC 6762 §5.3, §18)

    /// <summary>
    /// §18 gives every header field of a multicast query a value on transmission: the
    /// ID "SHOULD be set to zero" (§18.1), QR "MUST be zero" (§18.2), and OPCODE, AA,
    /// RA, Z, AD, CD and RCODE MUST all be zero, with RD a SHOULD (§18.3 to §18.11).
    /// TC is the one bit with a meaning, and a query without known answers has none to
    /// announce (§18.5).
    /// </summary>
    [Test]
    [Property("RFC", "6762 §18.1, §18.2, §18.3, §18.4, §18.5, §18.6, §18.7, §18.8, §18.9, §18.10, §18.11")]
    public async Task A_Query_Goes_Out_With_Every_Header_Field_Zero()
    {

        await using var link = await Link.Start();

        await link.Client.Query(Host, [ DNSResourceRecordTypes.A ], TimeSpan.FromMilliseconds(200));

        var query = RawDnsReader.Parse(link.Queries.First().Wire);

        Assert.Multiple(() => {
            Assert.That(query.Id,     Is.EqualTo(0),      "§18.1: the Query Identifier SHOULD be set to zero on transmission");
            Assert.That(query.Flags,  Is.EqualTo(0x0000), "§18.2 to §18.11: no header bit of a query without known answers is set");
            Assert.That(query.Answers, Is.Empty,          "nothing was cached, so there is nothing to list as known");
        });

    }


    /// <summary>
    /// §5.3: "The semantics of a Multicast DNS query message containing multiple
    /// questions is identical to a series of individual DNS query messages containing
    /// one question each." Two types asked for are two questions, and no type at all is
    /// the one question that covers every type.
    /// </summary>
    [TestCase(new[] { DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA }, new UInt16[] { RawDnsType.A, RawDnsType.AAAA })]
    [TestCase(new DNSResourceRecordTypes[0],                                  new UInt16[] { RawDnsType.ANY })]
    [Property("RFC", "6762 §5.3")]
    public async Task Every_Queried_Type_Is_A_Question_Of_Its_Own(DNSResourceRecordTypes[] Types, UInt16[] Expected)
    {

        await using var link = await Link.Start();

        await link.Client.Query(Host, Types, TimeSpan.FromMilliseconds(200));

        var query = RawDnsReader.Parse(link.Queries.First().Wire);

        Assert.Multiple(() => {
            Assert.That(query.Questions.Select(question => question.Type), Is.EquivalentTo(Expected));
            Assert.That(query.Questions.All(question => question.Name.Canonical == "querier-host.local"), Is.True);
            Assert.That(query.Questions.All(question => (question.Class & 0x7FFF) == RawDnsClass.IN), Is.True);
        });

    }

    #endregion

    #region Retransmission (RFC 6762 §5.2, §5.4)

    /// <summary>
    /// Finding 78. §5.4: "When a question is retransmitted (as described in Section
    /// 5.2), the unicast-response bit SHOULD NOT be set in subsequent retransmissions of
    /// that question. Subsequent retransmissions SHOULD be usual "QM" questions."
    /// </summary>
    /// <remarks>
    /// Whether the first question asks for a unicast reply is an option of the client,
    /// and Hermod sets it by default so that an answer is not held back by the
    /// responder's one-per-second multicast limit. That is a reason, which a SHOULD
    /// NOT allows for. Repeating the bit is not covered by it: the first answer that
    /// went out by unicast is the reason the question is being asked again.
    /// </remarks>
    [Test]
    [Property("RFC", "6762 §5.4")]
    public async Task Only_The_First_Transmission_Of_A_Question_Asks_For_A_Unicast_Reply()
    {

        await using var link = await Link.Start();

        await link.Client.Query(Host, [ DNSResourceRecordTypes.A ], TimeSpan.FromMilliseconds(3500));

        var classes = link.Queries.Select(packet => RawDnsReader.Parse(packet.Wire).Questions.Single().Class).ToArray();

        Assert.Multiple(() => {

            Assert.That(classes, Has.Length.GreaterThanOrEqualTo(2),
                        "an unanswered query is asked again");

            Assert.That(classes[0] & 0x8000, Is.EqualTo(0x8000),
                        "the client asks for a unicast reply the first time (its default)");

            Assert.That(classes.Skip(1).Select(qclass => qclass & 0x8000), Is.All.EqualTo(0),
                        "§5.4: the unicast-response bit SHOULD NOT be set in subsequent retransmissions");

        });

    }


    /// <summary>
    /// Finding 79. §5.2: "when retransmitting Multicast DNS queries to implement this
    /// kind of continuous monitoring, the interval between the first two queries MUST
    /// be at least one second, the intervals between successive queries MUST increase
    /// by at least a factor of two".
    /// </summary>
    /// <remarks>
    /// The sentence sits in the section about continuous querying, and a lookup that
    /// ends with its first answer is not obviously that. It is all the RFC says about
    /// retransmission, though, and §5.4 refers back to it in those words: "When a
    /// question is retransmitted (as described in Section 5.2)". §5.2 also names
    /// "looking up the IPv4 and IPv6 addresses of another host" as an operation of its
    /// kind. And the one-shot querier of §5.1 that it does not govern is the one that
    /// "MUST NOT be sent using UDP source port 5353", where Hermod's client sends from.
    /// </remarks>
    [Test]
    [Property("RFC", "6762 §5.2")]
    public async Task Retransmissions_Start_A_Second_Apart_And_At_Least_Double()
    {

        await using var link = await Link.Start();

        await link.Client.Query(Host, [ DNSResourceRecordTypes.A ], TimeSpan.FromMilliseconds(3500));

        var sent  = link.Queries.Select(packet => packet.SentAt).ToArray();
        var gaps  = sent.Zip(sent.Skip(1), (first, second) => second - first).ToArray();

        // Timers fire a little early or late. 50 ms of that is allowed on each interval,
        // and three times as much where an interval measured late is doubled into the
        // next comparison — either way far from hiding a 500 ms interval.
        var tolerance = TimeSpan.FromMilliseconds(50);

        Assert.Multiple(() => {

            Assert.That(gaps, Is.Not.Empty, "an unanswered query is asked again");

            Assert.That(gaps.FirstOrDefault(), Is.GreaterThanOrEqualTo(TimeSpan.FromSeconds(1) - tolerance),
                        "§5.2: the interval between the first two queries MUST be at least one second");

            for (var i = 1; i < gaps.Length; i++)
                Assert.That(gaps[i], Is.GreaterThanOrEqualTo(gaps[i - 1] * 2 - tolerance * 3),
                            $"§5.2: interval {i + 1} MUST be at least twice interval {i}");

        });

    }

    #endregion

    #region What a querier accepts (RFC 6762 §6, §11, §18)

    [Test]
    [Property("RFC", "6762 §5.1, §6")]
    public async Task A_Multicast_Response_Answers_A_Pending_Query()
    {

        await using var link = await Link.Start();

        var (info, took) = await Answered(link,
                                          DNSResourceRecordTypes.A,
                                          Response([ Address("192.0.2.7") ]),
                                          TimeSpan.FromSeconds(3));

        Assert.Multiple(() => {
            Assert.That(info.IsTimeout, Is.False);
            Assert.That(info.Answers.OfType<A>().Select(a => a.IPv4Address.ToString()), Is.EqualTo(new[] { "192.0.2.7" }));
            Assert.That(took, Is.LessThan(TimeSpan.FromSeconds(2)), "an answer ends the wait; the timeout is for when none comes");
        });

    }


    /// <summary>
    /// §6: "Multicast DNS implementations MUST silently ignore any Multicast DNS
    /// responses they receive where the source UDP port is not 5353."
    /// </summary>
    [Test]
    [Property("RFC", "6762 §6")]
    public async Task A_Response_From_Another_Port_Than_5353_Is_Ignored()
    {

        await using var link = await Link.Start();

        await link.MulticastFromPort(Response([ Address("192.0.2.7") ]), 5354);

        Assert.That(CachedAddresses(link.Client), Is.Empty);

        // The same message from the right port is accepted, so the one above was not
        // refused for some other reason.
        await link.Multicast(Response([ Address("192.0.2.7") ]));

        Assert.That(CachedAddresses(link.Client).Select(address => address.ToString()), Is.EqualTo(new[] { "192.0.2.7" }));

    }


    public enum UnicastCase
    {
        Unsolicited,
        AfterAMulticastOnlyQuestion,
        ForAnotherName,
        ForAnotherType,
        LongAfterTheQuestion,
        FromOffTheLink
    }

    /// <summary>
    /// §6: "A Multicast DNS querier MUST only accept unicast responses if they answer a
    /// recently sent query (e.g., sent within the last two seconds) that explicitly
    /// requested unicast responses. A Multicast DNS querier MUST silently ignore all
    /// other unicast responses." §11 adds that a querier "MUST only accept responses to
    /// that query that originate from the local link".
    /// </summary>
    [TestCase(UnicastCase.Unsolicited)]
    [TestCase(UnicastCase.AfterAMulticastOnlyQuestion)]
    [TestCase(UnicastCase.ForAnotherName)]
    [TestCase(UnicastCase.ForAnotherType)]
    [TestCase(UnicastCase.LongAfterTheQuestion)]
    [TestCase(UnicastCase.FromOffTheLink)]
    [Property("RFC", "6762 §6, §11")]
    public async Task A_Unicast_Response_Nobody_Asked_For_Is_Ignored(UnicastCase Case)
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(Clock: clock);

        if (Case != UnicastCase.Unsolicited)
            await link.Client.SendQueryAsync([
                      new MulticastDNSQuestion(Case == UnicastCase.ForAnotherName ? DNSServiceName.Parse("someone-else.local.") : Host,
                                               Case == UnicastCase.ForAnotherType ? DNSResourceRecordTypes.TXT                   : DNSResourceRecordTypes.A,
                                               Case != UnicastCase.AfterAMulticastOnlyQuestion)
                  ]);

        if (Case == UnicastCase.LongAfterTheQuestion)
            clock.Advance(TimeSpan.FromSeconds(10));

        await link.Unicast(Response([ Address("192.0.2.7") ]),
                           SourceIsOnLocalLink: Case != UnicastCase.FromOffTheLink);

        Assert.That(CachedAddresses(link.Client), Is.Empty,
                    "§6: a querier MUST silently ignore all other unicast responses");

    }


    [Test]
    [Property("RFC", "6762 §5.4, §6")]
    public async Task A_Unicast_Response_To_A_Question_That_Asked_For_One_Is_Accepted()
    {

        await using var link = await Link.Start(Clock: new SteppedClock());

        await link.Client.SendQueryAsync([ new MulticastDNSQuestion(Host, DNSResourceRecordTypes.A, true) ]);
        await link.Unicast(Response([ Address("192.0.2.7") ]));

        Assert.That(CachedAddresses(link.Client).Select(address => address.ToString()), Is.EqualTo(new[] { "192.0.2.7" }));

    }


    /// <summary>
    /// §18.3: "Multicast DNS messages received with an OPCODE other than zero MUST be
    /// silently ignored." §18.11: "Multicast DNS messages received with non-zero
    /// Response Codes MUST be silently ignored."
    /// </summary>
    [TestCase((UInt16) (0x8400 | 4 << 11), TestName = "Opcode NOTIFY")]
    [TestCase((UInt16) (0x8400 | 5 << 11), TestName = "Opcode UPDATE")]
    [TestCase((UInt16) (0x8400 | 2),       TestName = "Rcode SERVFAIL")]
    [TestCase((UInt16) (0x8400 | 3),       TestName = "Rcode NXDOMAIN")]
    [Property("RFC", "6762 §18.3, §18.11")]
    public async Task A_Response_With_A_Nonzero_Opcode_Or_Rcode_Is_Ignored(UInt16 Flags)
    {

        await using var link = await Link.Start();

        await link.Multicast(Response([ Address("192.0.2.7") ], Flags: Flags));

        Assert.That(CachedAddresses(link.Client), Is.Empty);

    }


    /// <summary>
    /// §18.4 to §18.10: the AA, TC, RD, RA, Z, AD and CD bits of a response each "MUST
    /// be ignored on reception". So does the ID (§18.1: examine every response "without
    /// regard to the contents of the ID field or the Question Section").
    /// </summary>
    [TestCase((UInt16) 0x8000, (UInt16) 0,      TestName = "AA clear")]
    [TestCase((UInt16) 0x8600, (UInt16) 0,      TestName = "TC set")]
    [TestCase((UInt16) 0x8500, (UInt16) 0,      TestName = "RD set")]
    [TestCase((UInt16) 0x8480, (UInt16) 0,      TestName = "RA set")]
    [TestCase((UInt16) 0x8440, (UInt16) 0,      TestName = "Z set")]
    [TestCase((UInt16) 0x8420, (UInt16) 0,      TestName = "AD set")]
    [TestCase((UInt16) 0x8410, (UInt16) 0,      TestName = "CD set")]
    [TestCase((UInt16) 0x8400, (UInt16) 0x1234, TestName = "Nonzero ID")]
    [Property("RFC", "6762 §18.1, §18.4, §18.5, §18.6, §18.7, §18.8, §18.9, §18.10")]
    public async Task Header_Bits_A_Response_Should_Not_Carry_Do_Not_Cost_Its_Answers(UInt16 Flags, UInt16 Id)
    {

        await using var link = await Link.Start();

        await link.Multicast(Response([ Address("192.0.2.7") ], Flags: Flags, Id: Id));

        Assert.That(CachedAddresses(link.Client).Select(address => address.ToString()), Is.EqualTo(new[] { "192.0.2.7" }));

    }


    /// <summary>
    /// §6: "Any questions in the Question Section of a received Multicast DNS response
    /// MUST be silently ignored." Ignored means the answers still count, whatever the
    /// question asked.
    /// </summary>
    [Test]
    [Property("RFC", "6762 §6")]
    public async Task A_Question_In_A_Response_Does_Not_Cost_Its_Answers()
    {

        await using var link = await Link.Start();

        await link.Multicast(Response([ Address("192.0.2.7") ], Question: "someone-else.local."));

        Assert.That(CachedAddresses(link.Client).Select(address => address.ToString()), Is.EqualTo(new[] { "192.0.2.7" }));

    }


    /// <summary>
    /// §7.1: "A Multicast DNS querier MUST NOT cache resource records observed in the
    /// Known-Answer Section of other Multicast DNS queries."
    /// </summary>
    [Test]
    [Property("RFC", "6762 §7.1")]
    public async Task Known_Answers_In_Another_Hosts_Query_Are_Not_Cached()
    {

        await using var link = await Link.Start();

        await link.Multicast(new RawDnsWriter().
                                 Header(0, 0x0000, 1, 1, 0, 0).
                                 Question(HostName, RawDnsType.A).
                                 RR(HostName, RawDnsType.A, RawDnsClass.IN, 120, RawDnsWriter.IPv4("192.0.2.7")).
                                 ToArray());

        Assert.That(link.Client.CacheSize, Is.EqualTo(0),
                    "§7.1: the Answer Section of Multicast DNS queries is not authoritative");

    }

    #endregion

    #region Negative answers (RFC 6762 §6.1)

    [Test]
    [Property("RFC", "6762 §6.1")]
    public async Task An_Nsec_Without_The_Queried_Type_Ends_The_Query_With_No_Answer()
    {

        await using var link = await Link.Start();

        var (info, took) = await Answered(link,
                                          DNSResourceRecordTypes.AAAA,
                                          Response([ Nsec(HostName, [ RawDnsType.A, RawDnsType.NSEC ]) ]),
                                          TimeSpan.FromSeconds(3));

        Assert.Multiple(() => {
            Assert.That(info.IsTimeout, Is.False, "the NSEC record is the answer: there is no AAAA");
            Assert.That(info.Answers.OfType<AAAA>(), Is.Empty);
            Assert.That(took, Is.LessThan(TimeSpan.FromSeconds(2)),
                        "§6.1: an explicit negative response is preferable to the querier having to retransmit its query " +
                        "multiple times, and eventually give up with a timeout");
        });

    }


    [Test]
    [Property("RFC", "6762 §6.1")]
    public async Task An_Nsec_That_Lists_The_Queried_Type_Denies_Nothing()
    {

        await using var link = await Link.Start();

        var (info, _) = await Answered(link,
                                       DNSResourceRecordTypes.AAAA,
                                       Response([ Nsec(HostName, [ RawDnsType.A, RawDnsType.AAAA, RawDnsType.NSEC ]) ]),
                                       TimeSpan.FromMilliseconds(800));

        Assert.That(info.IsTimeout, Is.True,
                    "an NSEC that lists AAAA says it exists, so the query keeps waiting for it");

    }


    /// <summary>
    /// §6.1: "a Multicast DNS implementation MUST NOT reject or ignore an NSEC record it
    /// receives just because it finds an unexpected value in the 'Next Domain Name'
    /// field."
    /// </summary>
    [Test]
    [Property("RFC", "6762 §6.1")]
    public async Task An_Nsec_With_A_Foreign_Next_Name_Is_Still_A_Denial()
    {

        await using var link = await Link.Start();

        var (info, took) = await Answered(link,
                                          DNSResourceRecordTypes.AAAA,
                                          Response([ Nsec(HostName, [ RawDnsType.A, RawDnsType.NSEC ], NextName: "zz-next.local.") ]),
                                          TimeSpan.FromSeconds(3));

        Assert.Multiple(() => {
            Assert.That(info.IsTimeout, Is.False);
            Assert.That(took, Is.LessThan(TimeSpan.FromSeconds(2)));
        });

    }


    /// <summary>
    /// §6.1: a querier MAY ignore an NSEC record with "more than one Type Bit Map, or
    /// where the Type Bit Map block number is not zero, or where the block length is not
    /// in the range 1-32", but "MUST NOT ignore an entire message just because that
    /// message contains one or more NSEC record(s) that the Multicast DNS
    /// implementation cannot parse."
    /// </summary>
    [TestCase(new Byte[] { 1, 1, 0x40 },                TestName = "Block number one")]
    [TestCase(new Byte[] { 0, 1, 0x40, 1, 1, 0x40 },    TestName = "Two type bit maps")]
    [TestCase(new Byte[] { 0, 0 },                      TestName = "Block length zero")]
    [TestCase(new Byte[] { 0, 33, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
                                                        TestName = "Block length thirty-three")]
    [Property("RFC", "6762 §6.1")]
    public async Task An_Nsec_The_Querier_Cannot_Use_Does_Not_Cost_The_Rest_Of_The_Message(Byte[] Bitmaps)
    {

        await using var link = await Link.Start();

        await link.Multicast(Response([ Address("192.0.2.7") ],
                                      [ NsecWithBitmaps(HostName, Bitmaps) ]));

        Assert.That(CachedAddresses(link.Client).Select(address => address.ToString()), Is.EqualTo(new[] { "192.0.2.7" }),
                    "§6.1: a querier MUST NOT ignore an entire message because of an NSEC record it cannot parse");

    }

    #endregion

    #region The cache (RFC 6762 §5.2, §10)

    [Test]
    [Property("RFC", "6762 §5.2")]
    public async Task A_Record_Leaves_The_Cache_When_Its_Ttl_Runs_Out()
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(Clock: clock);

        await link.Multicast(Response([ Address("192.0.2.7", Ttl: 10) ]));

        clock.Advance(TimeSpan.FromSeconds(9.9));
        Assert.That(CachedAddresses(link.Client), Has.Length.EqualTo(1), "still inside its ten seconds");

        clock.Advance(TimeSpan.FromSeconds(0.2));
        Assert.That(CachedAddresses(link.Client), Is.Empty,
                    "§5.2: after this interval has passed, the answer will no longer be valid and SHOULD be deleted from the cache");

    }


    /// <summary>
    /// §5.2: "If an answer is received, then the remaining TTL is reset to the value
    /// given in the answer".
    /// </summary>
    [Test]
    [Property("RFC", "6762 §5.2")]
    public async Task A_Record_Heard_Again_Lives_On_From_Its_New_Ttl()
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(Clock: clock);

        await link.Multicast(Response([ Address("192.0.2.7", Ttl: 10) ]));
        clock.Advance(TimeSpan.FromSeconds(8));
        await link.Multicast(Response([ Address("192.0.2.7", Ttl: 10) ]));
        clock.Advance(TimeSpan.FromSeconds(5));

        Assert.That(CachedAddresses(link.Client), Has.Length.EqualTo(1),
                    "thirteen seconds after the first copy, five after the second");

        Assert.That(link.Client.CacheSize, Is.EqualTo(1), "the same record heard twice is one cache entry");

    }


    /// <summary>
    /// §10.1: "Queriers receiving a Multicast DNS response with a TTL of zero SHOULD NOT
    /// immediately delete the record from the cache, but instead record a TTL of 1 and
    /// then delete the record one second later."
    /// </summary>
    [Test]
    [Property("RFC", "6762 §10.1")]
    public async Task A_Goodbye_Leaves_The_Record_One_More_Second()
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(Clock: clock);

        await link.Multicast(Response([ Address("192.0.2.7", Ttl: 120) ]));
        await link.Multicast(Response([ Address("192.0.2.7", Ttl: 0) ]));

        Assert.That(CachedAddresses(link.Client), Has.Length.EqualTo(1), "§10.1: SHOULD NOT immediately delete the record");

        clock.Advance(TimeSpan.FromSeconds(0.9));
        Assert.That(CachedAddresses(link.Client), Has.Length.EqualTo(1), "within the one second it is given");

        clock.Advance(TimeSpan.FromSeconds(0.2));
        Assert.That(CachedAddresses(link.Client), Is.Empty, "§10.1: and then delete the record one second later");

    }


    [Test]
    [Property("RFC", "6762 §10.1")]
    public async Task A_Goodbye_For_A_Record_Never_Heard_Caches_Nothing()
    {

        await using var link = await Link.Start(Clock: new SteppedClock());

        await link.Multicast(Response([ Address("192.0.2.7", Ttl: 0) ]));

        Assert.That(link.Client.CacheSize, Is.EqualTo(0), "a TTL of zero is a withdrawal, not an assertion");

    }


    /// <summary>
    /// §10.2: "all old records with that name, rrtype, and rrclass that were received
    /// more than one second ago are declared invalid, and marked to expire from the
    /// cache in one second."
    /// </summary>
    [Test]
    [Property("RFC", "6762 §10.2")]
    public async Task Cache_Flush_Expires_Older_Members_Of_The_RRSet_One_Second_Later()
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(Clock: clock);

        await link.Multicast(Response([ Address("192.0.2.1") ]));
        clock.Advance(TimeSpan.FromSeconds(5));
        await link.Multicast(Response([ Address("192.0.2.2", CacheFlush: true) ]));

        clock.Advance(TimeSpan.FromSeconds(0.9));
        Assert.That(CachedAddresses(link.Client).Select(address => address.ToString()),
                    Is.EquivalentTo(new[] { "192.0.2.1", "192.0.2.2" }),
                    "marked to expire in one second, not removed at once");

        clock.Advance(TimeSpan.FromSeconds(0.2));
        Assert.That(CachedAddresses(link.Client).Select(address => address.ToString()),
                    Is.EqualTo(new[] { "192.0.2.2" }),
                    "§10.2: the older record is no longer true");

    }


    /// <summary>
    /// §10.2: "only cache records that are more than one second old are flushed. This
    /// allows the announcing host to generate a quick burst of packets back-to-back on
    /// the wire containing all the members of the RRSet."
    /// </summary>
    [Test]
    [Property("RFC", "6762 §10.2")]
    public async Task Cache_Flush_Spares_What_Arrived_Within_The_Last_Second()
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(Clock: clock);

        await link.Multicast(Response([ Address("192.0.2.1", CacheFlush: true) ]));
        clock.Advance(TimeSpan.FromSeconds(0.5));
        await link.Multicast(Response([ Address("192.0.2.2", CacheFlush: true) ]));
        clock.Advance(TimeSpan.FromSeconds(3));

        Assert.That(CachedAddresses(link.Client).Select(address => address.ToString()),
                    Is.EquivalentTo(new[] { "192.0.2.1", "192.0.2.2" }),
                    "two halves of one RRSet, half a second apart");

    }


    [Test]
    [Property("RFC", "6762 §10.2")]
    public async Task Cache_Flush_Touches_Only_Its_Own_Name_And_Type()
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(Clock: clock);

        var other = DNSServiceName.Parse("other-host.local.");

        await link.Multicast(Response([
                                 Address("192.0.2.1"),
                                 Address("192.0.2.9", Name: "other-host.local."),
                                 new Rr(HostName, RawDnsType.TXT, 120, [ 5, .. "hello"u8 ])
                             ]));

        clock.Advance(TimeSpan.FromSeconds(5));
        await link.Multicast(Response([ Address("192.0.2.2", CacheFlush: true) ]));
        clock.Advance(TimeSpan.FromSeconds(2));

        Assert.Multiple(() => {
            Assert.That(CachedAddresses(link.Client).Select(address => address.ToString()), Is.EqualTo(new[] { "192.0.2.2" }));
            Assert.That(CachedAddresses(link.Client, other), Has.Length.EqualTo(1), "another name");
            Assert.That(link.Client.CachedRecords(Host, DNSResourceRecordTypes.TXT), Has.Count.EqualTo(1), "another type");
        });

    }


    /// <summary>
    /// §10.2: "There is no Multicast DNS resource record class 0x8001. The value 0x8001
    /// in the rrclass field of a resource record in a Multicast DNS response message
    /// indicates a resource record with class 1, with the cache-flush bit set."
    /// </summary>
    [Test]
    [Property("RFC", "6762 §10.2, §18.13")]
    public async Task The_Cache_Flush_Bit_Is_Not_Part_Of_The_Class()
    {

        await using var link = await Link.Start();

        await link.Multicast(Response([ Address("192.0.2.7", CacheFlush: true) ]));

        Assert.That(link.Client.CachedRecords(Host, DNSResourceRecordTypes.A).Single().Record.Class,
                    Is.EqualTo(DNSQueryClasses.IN));

    }


    /// <summary>
    /// §10.2: "Since pseudo-RRs should never go into the Multicast DNS cache, the concept
    /// of a cache-flush bit for these types is not applicable."
    /// </summary>
    [Test]
    [Property("RFC", "6762 §10.2")]
    public async Task An_Opt_Record_Never_Goes_Into_The_Cache()
    {

        await using var link = await Link.Start();

        await link.Multicast(new RawDnsWriter().
                                 Header(0, 0x8400, 0, 1, 0, 1).
                                 RR(HostName, RawDnsType.A, RawDnsClass.IN, 120, RawDnsWriter.IPv4("192.0.2.7")).
                                 Opt(1440).
                                 ToArray());

        Assert.Multiple(() => {
            Assert.That(link.Client.CacheSize, Is.EqualTo(1), "the address and nothing else");
            Assert.That(CachedAddresses(link.Client), Has.Length.EqualTo(1));
        });

    }

    #endregion

}

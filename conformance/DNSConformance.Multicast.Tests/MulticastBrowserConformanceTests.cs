using System.Diagnostics;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Multicast.Tests;

/// <summary>
/// RFC 6762 continuous querying and RFC 6763 browsing, judged on Hermod's
/// <see cref="MulticastDNSBrowser"/>: when it asks, what it says it already knows, and
/// what it makes of the answers.
/// </summary>
/// <remarks>
/// <see cref="MulticastQuerierConformanceTests"/> covers the one-shot query and the
/// cache underneath both. A browser is the querier §5.2 is written about — it keeps
/// asking for as long as anyone is interested — so the rules that only bite on the
/// second, third and hundredth query are tested here. The other host on the link is
/// the suite: answers are built with <see cref="RawDnsWriter"/>, queries read back
/// with <see cref="RawDnsReader"/>.
/// </remarks>
[TestFixture]
public sealed class MulticastBrowserConformanceTests
{

    #region Harness

    private sealed record CapturedDatagram(InMemoryMulticastDNSTransport  Sender,
                                           Byte[]                         Wire,
                                           TimeSpan                       SentAt);

    private sealed class PacketCapture
    {

        private readonly List<CapturedDatagram>  packets  = [];
        private readonly Stopwatch               clock    = Stopwatch.StartNew();
        private readonly ManualClock?            manual;

        /// <summary>The time on the test's clock, if it moves one, or else on the wall.</summary>
        public TimeSpan Now
            => manual?.Elapsed ?? clock.Elapsed;

        public PacketCapture(InMemoryMulticastDNSNetwork network, ManualClock? Manual = null)
        {
            manual = Manual;
            network.OnDatagramSent += (_, sender, payload, _) => {
                lock (packets)
                    packets.Add(new CapturedDatagram(sender, payload.ToArray(), Now));
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
    /// A clock the test moves by hand. Only GetUtcNow is overridden, so timers — the
    /// browser's query loop and its maintenance tick among them — keep real time.
    /// </summary>
    private sealed class SteppedClock : TimeProvider
    {

        private DateTimeOffset now = new (2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow()
            => now;

        public void Advance(TimeSpan by)
            => now = now.Add(by);

    }


    private sealed class Events
    {

        private readonly List<(String Kind, MulticastDNSServiceInstance Instance, TimeSpan At)>  seen  = [];
        private readonly Stopwatch                                                              clock = Stopwatch.StartNew();

        public Events(MulticastDNSBrowser Browser)
        {
            Browser.OnInstanceAdded    += (_, _, instance, _) => Record("added",   instance);
            Browser.OnInstanceUpdated  += (_, _, instance, _) => Record("updated", instance);
            Browser.OnInstanceRemoved  += (_, _, instance, _) => Record("removed", instance);
        }

        private Task Record(String Kind, MulticastDNSServiceInstance Instance)
        {
            lock (seen)
                seen.Add((Kind, Instance, clock.Elapsed));
            return Task.CompletedTask;
        }

        public TimeSpan Now
            => clock.Elapsed;

        public (MulticastDNSServiceInstance Instance, TimeSpan At)[] Of(String Kind)
        {
            lock (seen)
                return [.. seen.Where(e => e.Kind == Kind).Select(e => (e.Instance, e.At))];
        }

    }


    private sealed class Link : IAsyncDisposable
    {

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
            var capture  = new PacketCapture(network, Clock as ManualClock);
            var client   = new MulticastDNSClient(querier, Options, Clock);

            await peer.StartAsync();
            await client.StartAsync();

            return new Link { Querier = querier, Peer = peer, Client = client, Capture = capture };

        }

        public Task Multicast(Byte[] Wire)
            => Peer.SendAsync(Wire);

        public CapturedDatagram[] Queries
            => Capture.QueriesFrom(Querier);

        /// <summary>The browser's queries that ask for the service type.</summary>
        public CapturedDatagram[] BrowseQueries
            => [.. Queries.Where(packet => RawDnsReader.Parse(packet.Wire).Questions.Any(question => question.Type == RawDnsType.PTR &&
                                                                                                      question.Name.Canonical == ServiceTypeName.TrimEnd('.')))];

        public Boolean Asked(String Name, UInt16 Type)
            => Queries.Any(packet => RawDnsReader.Parse(packet.Wire).Questions.Any(question => question.Type == Type &&
                                                                                               question.Name.Canonical == Name.TrimEnd('.').ToLowerInvariant()));

        public async ValueTask DisposeAsync()
        {
            await Client.DisposeAsync();
            await Peer.DisposeAsync();
            await Querier.DisposeAsync();
        }

    }


    private const String ServiceTypeName  = "_qtest._tcp.local.";
    private const String InstanceName     = "Kitchen._qtest._tcp.local.";
    private const String HostName         = "kitchen-host.local.";

    private static readonly DNSServiceName  ServiceType  = DNSServiceName.Parse(ServiceTypeName);


    private sealed record Rr(String   Name,
                             UInt16   Type,
                             UInt32   Ttl,
                             Byte[]   Rdata,
                             Boolean  CacheFlush = false);


    private static Rr Pointer(String Target = InstanceName, UInt32 Ttl = 4500, Boolean CacheFlush = false)
        => new (ServiceTypeName, RawDnsType.PTR, Ttl, RawDnsWriter.NameBytes(Target), CacheFlush);

    private static Rr Service(String Target = HostName, UInt16 Port = 8080, UInt16 Priority = 0, UInt16 Weight = 0, UInt32 Ttl = 120, String Name = InstanceName)
        => new (Name,
                RawDnsType.SRV,
                Ttl,
                [ (Byte) (Priority >> 8), (Byte) Priority,
                  (Byte) (Weight   >> 8), (Byte) Weight,
                  (Byte) (Port     >> 8), (Byte) Port,
                  .. RawDnsWriter.NameBytes(Target) ],
                true);

    private static Rr Text(params String[] Strings)
        => new (InstanceName,
                RawDnsType.TXT,
                4500,
                [.. Strings.SelectMany(text => (Byte[]) [ (Byte) text.Length, .. System.Text.Encoding.ASCII.GetBytes(text) ])],
                true);

    private static Rr TextRdata(params Byte[] Rdata)
        => new (InstanceName, RawDnsType.TXT, 4500, Rdata, true);

    private static Rr Address(String Dotted = "192.0.2.80", String Name = HostName, UInt32 Ttl = 120, Boolean CacheFlush = true)
        => new (Name, RawDnsType.A, Ttl, RawDnsWriter.IPv4(Dotted), CacheFlush);

    private static Rr Address6(String Address = "2001:db8::80", String Name = HostName, UInt32 Ttl = 120, Boolean CacheFlush = true)
        => new (Name, RawDnsType.AAAA, Ttl, RawDnsWriter.IPv6(Address), CacheFlush);


    private static Byte[] Response(params Rr[] Answers)
    {

        var writer = new RawDnsWriter().Header(0, 0x8400, 0, (UInt16) Answers.Length, 0, 0);

        foreach (var rr in Answers)
            writer.RR(rr.Name,
                      rr.Type,
                      (UInt16) (rr.CacheFlush ? RawDnsClass.IN | 0x8000 : RawDnsClass.IN),
                      rr.Ttl,
                      rr.Rdata);

        return writer.ToArray();

    }


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
    /// Browse queries a test does not ask for, moved an hour away. A test that counts
    /// the packets it caused would otherwise count the browser's own next query when
    /// the two happen to fall into the same moment.
    /// </summary>
    private static MulticastDNSClientOptions Quiet()

        => new () {
               InitialBrowseInterval  = TimeSpan.FromHours(1),
               MaxBrowseInterval      = TimeSpan.FromHours(1)
           };


    /// <summary>
    /// <see cref="Quiet"/>, and with the cache swept and the instances looked after every
    /// 50 ms, so that a move of the test's clock is taken in at once.
    /// </summary>
    private static MulticastDNSClientOptions QuietAndQuick()

        => new () {
               InitialBrowseInterval      = TimeSpan.FromHours(1),
               MaxBrowseInterval          = TimeSpan.FromHours(1),
               CacheSweepInterval         = TimeSpan.FromMilliseconds(50),
               BrowseMaintenanceInterval  = TimeSpan.FromMilliseconds(50)
           };


    /// <summary>Whether a query sent after the first <paramref name="Before"/> asks the name for the type.</summary>
    private static Boolean AskedSince(Link Link, Int32 Before, String Name, UInt16 Type)

        => Link.Queries.Skip(Before).
                Any(packet => RawDnsReader.Parse(packet.Wire).Questions.Any(question => question.Type == Type &&
                                                                                        question.Name.Canonical == Name.TrimEnd('.').ToLowerInvariant()));


    /// <summary>
    /// A browser that has seen the whole service in one response and reported it.
    /// The report comes while the response is still being read, so the questions the
    /// browser asks about the instance may still be on their way; a short pause lets
    /// them pass before the test starts counting.
    /// </summary>
    private static async Task<(MulticastDNSBrowser Browser, Events Events)> Resolved(Link Link, params Rr[] Records)
    {

        var browser = await Link.Client.BrowseAsync(ServiceType);
        var events  = new Events(browser);

        await Link.Multicast(Response(Records.Length > 0
                                          ? Records
                                          : [ Pointer(), Service(), Text("path=/"), Address() ]));

        await WaitUntil(() => events.Of("added").Length == 1, "the instance to be reported");
        await Task.Delay(200);

        return (browser, events);

    }

    #endregion


    #region When a browser asks (RFC 6762 §5.2, §5.4, §7.3)

    /// <summary>
    /// RFC 6763 §4.1: browsing is a PTR query for the service type. §5.4: questions a
    /// local client creates once the host is up "should be treated as normal "QM"
    /// questions and SHOULD NOT have the unicast-response bit set on the first question
    /// of the series."
    /// </summary>
    [Test]
    [Property("RFC", "6763 §4.1, 6762 §5.4")]
    public async Task A_Browser_Asks_For_The_Service_Type_With_A_Multicast_Pointer_Question()
    {

        await using var link = await Link.Start();
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        await WaitUntil(() => link.BrowseQueries.Length > 0, "the first browse query");

        var question = RawDnsReader.Parse(link.BrowseQueries[0].Wire).Questions.Single();

        Assert.That(question.Class, Is.EqualTo(RawDnsClass.IN),
                    "a QM question: class IN without the unicast-response bit");

    }


    /// <summary>
    /// §5.2: "the interval between the first two queries MUST be at least one second,
    /// the intervals between successive queries MUST increase by at least a factor of
    /// two".
    /// </summary>
    /// <remarks>
    /// On the test's clock (<see cref="ManualClock"/>), so each interval is the one the
    /// browser asked for, and compared with no tolerance: the wall clock's made a late
    /// first interval look like a second one that did not double.
    /// </remarks>
    [Test]
    [Property("RFC", "6762 §5.2")]
    public async Task Browse_Queries_Start_A_Second_Apart_And_At_Least_Double()
    {

        var clock = new ManualClock();

        await using var link = await Link.Start(Clock: clock);
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        for (var queries = 1; queries <= 4; queries++)
        {
            await clock.RunOutNextWait();
            await WaitUntil(() => link.BrowseQueries.Length >= queries, $"browse query {queries}");
        }

        var sent  = link.BrowseQueries.Select(packet => packet.SentAt).ToArray();
        var gaps  = sent.Zip(sent.Skip(1), (first, second) => second - first).ToArray();

        Assert.Multiple(() => {

            Assert.That(gaps[0], Is.GreaterThanOrEqualTo(TimeSpan.FromSeconds(1)),
                        "§5.2: the interval between the first two queries MUST be at least one second");

            for (var i = 1; i < gaps.Length; i++)
                Assert.That(gaps[i], Is.GreaterThanOrEqualTo(gaps[i - 1] * 2),
                            $"§5.2: interval {i + 1} MUST be at least twice interval {i}");

        });

    }


    /// <summary>
    /// Finding 80. §5.2: "To avoid accidental synchronization when, for some reason,
    /// multiple clients begin querying at exactly the same moment (e.g., because of some
    /// common external trigger event), a Multicast DNS querier SHOULD also delay the
    /// first query of the series by a randomly chosen amount in the range 20-120 ms."
    /// </summary>
    /// <remarks>
    /// On the test's clock (<see cref="ManualClock"/>), which stands at zero when the
    /// browse begins. A query sent at once would be sent at zero, whichever wait came
    /// after it.
    /// </remarks>
    [Test]
    [Property("RFC", "6762 §5.2")]
    public async Task The_First_Browse_Query_Waits_Twenty_To_A_Hundred_And_Twenty_Milliseconds()
    {

        var clock = new ManualClock();

        await using var link = await Link.Start(Clock: clock);
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        await clock.RunOutNextWait();
        await WaitUntil(() => link.BrowseQueries.Length > 0, "the first browse query");

        Assert.That(link.BrowseQueries[0].SentAt, Is.InRange(TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(120)),
                    "§5.2: SHOULD delay the first query of the series by 20-120 ms");

    }


    /// <summary>
    /// Finding 81. §7.3: "If a host is planning to transmit (or retransmit) a query, and
    /// it sees another host on the network send a query containing the same "QM"
    /// question, and the Known-Answer Section of that query does not contain any records
    /// that this host would not also put in its own Known-Answer Section, then this host
    /// SHOULD treat its own query as having been sent."
    /// </summary>
    /// <remarks>
    /// On the test's clock (<see cref="ManualClock"/>). The other host's query has been
    /// read by the time <c>Multicast</c> returns, so the clock moves on only after it.
    /// </remarks>
    [Test]
    [Property("RFC", "6762 §7.3")]
    public async Task A_Question_Another_Host_Just_Asked_Is_Not_Asked_Again()
    {

        var clock = new ManualClock();

        await using var link = await Link.Start(Clock: clock);
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        // The first query, after whatever wait comes before it. The browser starts its
        // next wait only once a query is out, so the wait pending then is the second's.
        // A browser that sends nothing still waits, and would be waited for forever on
        // this clock: ten waits are nine more than the first query needs.
        var due = (await clock.NextWait())!.Value;

        for (var waits = 0; link.BrowseQueries.Length == 0 && waits < 10; waits++)
        {
            clock.AdvanceTo(due);
            due = (await clock.NextWait())!.Value;
        }

        Assert.That(link.BrowseQueries, Is.Not.Empty, "the first browse query");

        // Half a second before the browser's second query is due, the other host asks the
        // same question with no known answers, which is exactly what this browser would
        // put in its own.
        clock.AdvanceTo(due - TimeSpan.FromMilliseconds(500));

        await link.Multicast(new RawDnsWriter().Header(0, 0, 1, 0, 0, 0).Question(ServiceTypeName, RawDnsType.PTR).ToArray());

        clock.AdvanceTo(due);

        // And the series goes on: the query after the one treated as sent is sent when
        // it is due, which is also what shows the clock still drives the browser.
        var next = await clock.RunOutNextWait();
        await clock.NextWait();

        Assert.Multiple(() => {

            Assert.That(link.BrowseQueries.Select(packet => packet.SentAt), Has.None.EqualTo(due),
                        "§7.3: the browser SHOULD treat its own query, due half a second later, as having been sent");

            Assert.That(link.BrowseQueries[^1].SentAt, Is.EqualTo(next),
                        "the series goes on after the query treated as sent");

        });

    }


    public enum OtherQuery
    {
        Truncated,
        UnicastResponse,
        AnotherType,
        AnotherClass,
        AnotherName
    }

    /// <summary>
    /// §7.3 lets a browser treat its own query as sent only when another host asked "the
    /// same "QM" question", and only when "the Known-Answer Section of that query does
    /// not contain any records that this host would not also put in its own". A QU
    /// question, or one of another type, class or name, is not that question. A query
    /// with the TC bit set has more known answers on their way (§7.2), and they may be
    /// ones this browser does not have.
    /// </summary>
    /// <remarks>
    /// The same course as the test above, on the test's clock: the other host asks half
    /// a second before the browser's second query is due, and the browser sends that
    /// query when it is due.
    /// </remarks>
    [TestCase(OtherQuery.Truncated,        TestName = "A truncated query does not stand in for the browser's own")]
    [TestCase(OtherQuery.UnicastResponse,  TestName = "A QU question does not stand in for the browser's own")]
    [TestCase(OtherQuery.AnotherType,      TestName = "A question of another type does not stand in for the browser's own")]
    [TestCase(OtherQuery.AnotherClass,     TestName = "A question of another class does not stand in for the browser's own")]
    [TestCase(OtherQuery.AnotherName,      TestName = "A question for another name does not stand in for the browser's own")]
    [Property("RFC", "6762 §7.2, §7.3")]
    public async Task Only_The_Same_Qm_Question_Stands_In_For_The_Browsers_Own(OtherQuery Other)
    {

        var clock = new ManualClock();

        await using var link = await Link.Start(Clock: clock);
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        var due = (await clock.NextWait())!.Value;

        for (var waits = 0; link.BrowseQueries.Length == 0 && waits < 10; waits++)
        {
            clock.AdvanceTo(due);
            due = (await clock.NextWait())!.Value;
        }

        Assert.That(link.BrowseQueries, Is.Not.Empty, "the first browse query");

        clock.AdvanceTo(due - TimeSpan.FromMilliseconds(500));

        await link.Multicast(new RawDnsWriter().
                                 Header(0, Other == OtherQuery.Truncated ? RawDnsFlags.TC : (UInt16) 0, 1, 0, 0, 0).
                                 Question(Other == OtherQuery.AnotherName ? "_other._tcp.local."  : ServiceTypeName,
                                          Other == OtherQuery.AnotherType ? RawDnsType.SRV        : RawDnsType.PTR,
                                          Other switch {
                                              OtherQuery.UnicastResponse  => (UInt16) (RawDnsClass.IN | 0x8000),
                                              OtherQuery.AnotherClass     => RawDnsClass.CH,
                                              _                           => RawDnsClass.IN
                                          }).
                                 ToArray());

        clock.AdvanceTo(due);
        await clock.NextWait();

        Assert.That(link.BrowseQueries.Select(packet => packet.SentAt), Has.Some.EqualTo(due),
                    "§7.3: not the same QM question, so the browser's own query goes out when it is due");

    }


    public enum Repeated
    {
        Pointer,
        Service,
        Text
    }

    /// <summary>
    /// A browser asks about an instance for what it lacks: RFC 6763 §5's SRV and TXT
    /// records, and the addresses of the host the SRV record names. An instance it knows
    /// in full leaves nothing to ask about, and a record of it heard again does not
    /// change that. Asking anyway would answer every repetition with a query, and every
    /// answer to that query with the next one.
    /// </summary>
    [TestCase(Repeated.Pointer, TestName = "A pointer heard again for an instance known in full draws no query")]
    [TestCase(Repeated.Service, TestName = "An SRV record heard again for an instance known in full draws no query")]
    [TestCase(Repeated.Text,    TestName = "A TXT record heard again for an instance known in full draws no query")]
    [Property("RFC", "6762 §5.2, 6763 §5")]
    public async Task A_Record_Heard_Again_For_An_Instance_Known_In_Full_Draws_No_Query(Repeated Record)
    {

        await using var link = await Link.Start(Quiet());

        var (browser, _) = await Resolved(link, Pointer(), Service(), Text("path=/"), Address());

        await using var _ = browser;

        var before = link.Queries.Length;

        await link.Multicast(Response(Record switch {
                                          Repeated.Pointer  => Pointer(),
                                          Repeated.Service  => Service(),
                                          _                 => Text("path=/")
                                      }));

        await Task.Delay(300);

        Assert.That(link.Queries.Skip(before), Is.Empty, "nothing about the instance is missing");

    }


    /// <summary>
    /// An instance that still lacks something is asked about again when its pointer is
    /// heard again: for the addresses of its host, or for its TXT record, which RFC 6763
    /// §6 gives every service, so that one not yet heard is one still to come.
    /// </summary>
    [TestCase(false, TestName = "An instance without an address is asked about again when its pointer is heard")]
    [TestCase(true,  TestName = "An instance without a TXT record is asked about again when its pointer is heard")]
    [Property("RFC", "6763 §5, §6")]
    public async Task An_Instance_Heard_Again_Is_Asked_About_What_It_Still_Lacks(Boolean LacksText)
    {

        await using var link = await Link.Start(Quiet());

        var (browser, _) = LacksText
                               ? await Resolved(link, Pointer(), Service(), Address())
                               : await Resolved(link, Pointer(), Service(), Text("path=/"));

        await using var _ = browser;

        var before = link.Queries.Length;

        await link.Multicast(Response(Pointer()));

        if (LacksText)
            await WaitUntil(() => AskedSince(link, before, InstanceName, RawDnsType.TXT), "the question for the TXT record");
        else
            await WaitUntil(() => AskedSince(link, before, HostName,     RawDnsType.A),   "the question for the address");

    }

    #endregion

    #region What a browser says it already knows (RFC 6762 §7.1, §7.2, §10.2, §17)

    /// <summary>
    /// §7.1: "When a Multicast DNS querier sends a query to which it already knows some
    /// answers, it populates the Answer Section of the DNS query message with those
    /// answers." §10.2: "The cache-flush bit MUST NOT be set in any resource records in
    /// the Known-Answer list of any query message." That holds even when the answer
    /// arrived with the bit set.
    /// </summary>
    [Test]
    [Property("RFC", "6762 §7.1, §10.2")]
    public async Task A_Known_Pointer_Is_Listed_With_Its_Remaining_Ttl_And_No_Cache_Flush_Bit()
    {

        await using var link = await Link.Start(Quiet());

        var (browser, _) = await Resolved(link, Pointer(Ttl: 4500, CacheFlush: true), Service(), Text("path=/"), Address());

        await using var _ = browser;

        var before = link.BrowseQueries.Length;

        await browser.QueryNowAsync();

        var known = RawDnsReader.Parse(link.BrowseQueries.Skip(before).Single().Wire).Answers.Single();

        Assert.Multiple(() => {
            Assert.That(known.Type,  Is.EqualTo(RawDnsType.PTR));
            Assert.That(known.Name.Canonical, Is.EqualTo(ServiceTypeName.TrimEnd('.')));
            Assert.That(known.Class, Is.EqualTo(RawDnsClass.IN), "§10.2: no cache-flush bit in a known answer");
            Assert.That(known.Ttl,   Is.InRange(4490u, 4500u), "the remaining TTL, not a fresh one");
        });

    }


    /// <summary>
    /// Finding 82. §7.1: "a Multicast DNS querier SHOULD NOT include records in the
    /// Known-Answer list whose remaining TTL is less than half of their original TTL.
    /// Doing so would simply consume space in the message without achieving the goal of
    /// suppressing responses".
    /// </summary>
    [Test]
    [Property("RFC", "6762 §7.1")]
    public async Task A_Pointer_Below_Half_Its_Ttl_Is_No_Known_Answer()
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(Quiet(), clock);

        var (browser, _) = await Resolved(link, Pointer(Ttl: 100), Service(Ttl: 1000), Text("path=/"), Address(Ttl: 1000));

        await using var _ = browser;

        clock.Advance(TimeSpan.FromSeconds(40));

        var before = link.BrowseQueries.Length;
        await browser.QueryNowAsync();
        var atSixty = RawDnsReader.Parse(link.BrowseQueries.Skip(before).Single().Wire).Answers;

        clock.Advance(TimeSpan.FromSeconds(20));

        before = link.BrowseQueries.Length;
        await browser.QueryNowAsync();
        var atForty = RawDnsReader.Parse(link.BrowseQueries.Skip(before).Single().Wire).Answers;

        Assert.Multiple(() => {
            Assert.That(atSixty, Has.Count.EqualTo(1), "sixty of a hundred seconds left: still worth suppressing");
            Assert.That(atForty, Is.Empty,             "§7.1: forty of a hundred left SHOULD NOT be listed");
        });

    }


    /// <summary>
    /// Finding 83. §7.2: a querier with too many known answers for one packet "should
    /// issue a Multicast DNS query containing a question and as many Known-Answer
    /// records as will fit. It MUST then set the TC (Truncated) bit in the header before
    /// sending the query. It MUST immediately follow the packet with another query
    /// packet containing no questions and as many more Known-Answer records as will
    /// fit." §17: a packet larger than the interface MTU "MUST NOT contain more than one
    /// resource record", and none, fragments included, "MUST NOT exceed 9000 bytes".
    /// </summary>
    /// <remarks>
    /// "Will fit" is measured against an Ethernet MTU of 1500 bytes, less 28 for the IPv4
    /// and UDP headers — which is the size Hermod's own responder keeps its answers to.
    /// </remarks>
    [Test]
    [Property("RFC", "6762 §7.2, §17")]
    public async Task Known_Answers_That_Do_Not_Fit_One_Packet_Continue_In_Truncated_Packets()
    {

        await using var link = await Link.Start(Quiet());
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        // The first query of the series waits 20-120 ms (§5.2), and goes out with every
        // pointer cached by then. Sent after the count below has begun, it is counted
        // beside the query this test asks for, and every known answer twice.
        await WaitUntil(() => link.BrowseQueries.Length > 0, "the first browse query");

        var names = Enumerable.Range(1, 250).
                               Select(n => $"Instance {n:D3} with a name long enough to matter._qtest._tcp.local.").
                               ToArray();

        await link.Multicast(Response([.. names.Select(name => Pointer(name))]));

        await WaitUntil(() => link.Client.CachedRecords(ServiceType, DNSResourceRecordTypes.PTR).Count == names.Length,
                        "all pointers to be cached");

        var before = link.Queries.Length;
        await browser.QueryNowAsync();
        var packets = link.Queries.Skip(before).Select(packet => RawDnsReader.Parse(packet.Wire)).ToArray();

        Assert.Multiple(() => {

            Assert.That(packets.Select(packet => packet.Wire.Length), Is.All.LessThanOrEqualTo(9000 - 28),
                        "§17: a Multicast DNS packet, including IP and UDP headers, MUST NOT exceed 9000 bytes");

            Assert.That(packets.Where(packet => packet.Answers.Count > 1).Select(packet => packet.Wire.Length),
                        Is.All.LessThanOrEqualTo(1472),
                        "§17: a packet larger than the MTU MUST NOT contain more than one resource record");

            Assert.That(packets.SkipLast(1).Select(packet => packet.TC), Is.All.True,
                        "§7.2: every packet but the last MUST set the TC bit");

            Assert.That(packets.Skip(1).Select(packet => packet.Questions.Count), Is.All.EqualTo(0),
                        "§7.2: the packets that follow contain no questions");

            Assert.That(packets.SelectMany(packet => packet.Answers).Count(), Is.EqualTo(names.Length),
                        "every known answer is sent, in one packet or another");

        });

    }

    #endregion

    #region What a browser makes of the answers (RFC 6763 §5, §6)

    /// <summary>
    /// RFC 6763 §5: a client resolving an instance "queries for the SRV and TXT records
    /// of that name", and the SRV record names the host whose addresses come next.
    /// </summary>
    [Test]
    [Property("RFC", "6763 §4.1, §5")]
    public async Task A_Pointer_Leads_To_Srv_And_Txt_And_The_Srv_To_The_Address()
    {

        await using var link = await Link.Start();
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        var events = new Events(browser);

        await link.Multicast(Response(Pointer()));

        await WaitUntil(() => link.Asked(InstanceName, RawDnsType.SRV) && link.Asked(InstanceName, RawDnsType.TXT),
                        "the SRV and TXT questions for the instance");

        Assert.That(link.Asked(HostName, RawDnsType.A), Is.False, "the host is not known before the SRV record is");

        await link.Multicast(Response(Service(Port: 8443), Text("path=/kitchen")));

        await WaitUntil(() => link.Asked(HostName, RawDnsType.A), "the address question for the SRV target");

        await link.Multicast(Response(Address("192.0.2.80")));

        await WaitUntil(() => browser.Instances.SingleOrDefault()?.Addresses.Count == 1, "the address to arrive");

        var instance = browser.Instances.Single();

        Assert.Multiple(() => {
            Assert.That(instance.InstanceName.FullName.TrimEnd('.'), Is.EqualTo(InstanceName.TrimEnd('.')));
            Assert.That(instance.HostName?.FullName.TrimEnd('.'),    Is.EqualTo(HostName.TrimEnd('.')));
            Assert.That(instance.Port?.ToUInt16(),                   Is.EqualTo((UInt16) 8443));
            Assert.That(instance.TXT?.Strings,                       Is.EqualTo(new[] { "path=/kitchen" }));
            Assert.That(instance.Addresses.Select(address => address.ToString()), Is.EqualTo(new[] { "192.0.2.80" }));
            Assert.That(events.Of("added"), Has.Length.EqualTo(1), "reported once");
        });

    }


    /// <summary>
    /// RFC 6763 §6.1: "DNS-SD clients MUST treat the following as equivalent", listing a
    /// TXT record holding one empty string, an empty TXT record, and "No TXT record". A
    /// service without one is still a service.
    /// </summary>
    [Test]
    [Property("RFC", "6763 §6.1")]
    public async Task An_Instance_Without_A_Txt_Record_Is_Still_Reported()
    {

        await using var link = await Link.Start();

        var (browser, events) = await Resolved(link, Pointer(), Service(), Address());

        await using var _ = browser;

        Assert.That(events.Of("added").Single().Instance.IsResolved, Is.True);

    }


    /// <summary>
    /// Finding 84. RFC 6763 §6.1: no TXT record, one holding a single empty string, and
    /// a zero-length one are equivalent, so learning that the TXT record is the empty
    /// string changes nothing about an instance first seen without one.
    /// </summary>
    [TestCase(new Byte[] { 0 }, TestName = "A single empty string")]
    [TestCase(new Byte[0],      TestName = "A zero-length TXT record")]
    [Property("RFC", "6763 §6.1")]
    public async Task An_Empty_Txt_Record_Is_No_Change_To_An_Instance_That_Had_None(Byte[] Rdata)
    {

        await using var link = await Link.Start();

        var (browser, events) = await Resolved(link, Pointer(), Service(), Address());

        await using var _ = browser;

        await link.Multicast(Response(TextRdata(Rdata)));

        await Task.Delay(300);

        Assert.That(events.Of("updated"), Is.Empty,
                    "§6.1: DNS-SD clients MUST treat no TXT record and an empty one as equivalent");

    }


    /// <summary>
    /// A zero-length TXT record "is not strictly legal, but should one be received, it
    /// should be interpreted as the same as a single empty string" (RFC 6763 §6.1). It
    /// must at least not cost the records it arrived with.
    /// </summary>
    [Test]
    [Property("RFC", "6763 §6.1")]
    public async Task A_Zero_Length_Txt_Record_Does_Not_Cost_Its_Instance()
    {

        await using var link = await Link.Start();

        var (browser, events) = await Resolved(link, Pointer(), Service(), TextRdata(), Address());

        await using var _ = browser;

        Assert.That(events.Of("added"), Has.Length.EqualTo(1));

    }


    /// <summary>
    /// Finding 85. RFC 6763 §5: "In the event that more than one SRV is returned,
    /// clients MUST correctly interpret the priority and weight fields -- i.e.,
    /// lower-numbered priority servers should be used in preference to higher-numbered
    /// priority servers". An instance described by two SRV records is reported with the
    /// one a client should use, whichever order they came in.
    /// </summary>
    [TestCase(true,  TestName = "Preferred record first")]
    [TestCase(false, TestName = "Preferred record last")]
    [Property("RFC", "6763 §5")]
    public async Task The_Preferred_Srv_Record_Describes_The_Instance(Boolean PreferredFirst)
    {

        await using var link = await Link.Start();

        var preferred  = Service(Target: "first-choice.local.",  Port: 1000, Priority: 0);
        var fallback   = Service(Target: "second-choice.local.", Port: 2000, Priority: 10);

        var (browser, _) = await Resolved(link,
                                          [ Pointer(),
                                            .. PreferredFirst ? new[] { preferred, fallback } : [ fallback, preferred ],
                                            Text("path=/") ]);

        await using var _ = browser;

        await Task.Delay(200);

        var instance = browser.Instances.Single();

        Assert.Multiple(() => {
            Assert.That(instance.Priority,                        Is.EqualTo((UInt16) 0), "§5: lower-numbered priority servers should be used in preference");
            Assert.That(instance.HostName?.FullName.TrimEnd('.'), Is.EqualTo("first-choice.local"));
            Assert.That(instance.Port?.ToUInt16(),                Is.EqualTo((UInt16) 1000));
        });

    }


    [Test]
    [Property("RFC", "6763 §6")]
    public async Task A_Changed_Txt_Record_Is_Reported_As_An_Update()
    {

        await using var link = await Link.Start();

        var (browser, events) = await Resolved(link, Pointer(), Service(), Text("v=1"), Address());

        await using var _ = browser;

        await link.Multicast(Response(Text("v=2")));

        await WaitUntil(() => events.Of("updated").Length > 0, "the update");

        Assert.That(browser.Instances.Single().TXT?.Strings, Is.EqualTo(new[] { "v=2" }));

    }


    /// <summary>
    /// RFC 6763 §6.1 makes no TXT record and an empty one equivalent, and nothing else. A
    /// TXT record that empties has lost what it said, and one that arrives for an instance
    /// first seen without one brings something to say: either is a change to the
    /// instance. <see cref="An_Empty_Txt_Record_Is_No_Change_To_An_Instance_That_Had_None"/>
    /// is the case §6.1 does make equivalent.
    /// </summary>
    [TestCase(true,  TestName = "A TXT record that empties is reported as an update")]
    [TestCase(false, TestName = "A TXT record for an instance that had none is reported as an update")]
    [Property("RFC", "6763 §6, §6.1")]
    public async Task A_Txt_Record_That_Empties_Or_Fills_Is_Reported_As_An_Update(Boolean Empties)
    {

        await using var link = await Link.Start();

        var (browser, events) = Empties
                                    ? await Resolved(link, Pointer(), Service(), Text("v=1"), Address())
                                    : await Resolved(link, Pointer(), Service(),              Address());

        await using var _ = browser;

        await link.Multicast(Response(Empties ? TextRdata(0) : Text("v=1")));

        await WaitUntil(() => events.Of("updated").Length > 0, "the update");

        Assert.That(browser.Instances.Single().TXT?.Strings, Is.EqualTo(Empties ? new[] { "" } : [ "v=1" ]));

    }


    [Test]
    [Property("RFC", "6763 §5")]
    public async Task A_Changed_Port_Is_Reported_As_An_Update()
    {

        await using var link = await Link.Start();

        var (browser, events) = await Resolved(link, Pointer(), Service(Port: 8080), Text("path=/"), Address());

        await using var _ = browser;

        await link.Multicast(Response(Service(Port: 9090)));

        await WaitUntil(() => events.Of("updated").Length > 0, "the update");

        Assert.That(browser.Instances.Single().Port?.ToUInt16(), Is.EqualTo((UInt16) 9090));

    }


    /// <summary>
    /// RFC 6763 §5: of several SRV records, "lower-numbered priority servers should be
    /// used in preference to higher-numbered priority servers". When one of them expires,
    /// the instance changes only if it was the one in use, and then the next one takes
    /// over. One that was not in use leaves the instance as it was.
    /// </summary>
    /// <remarks>
    /// The cache is swept every 50 ms, so the expiry is taken in soon after the clock has
    /// passed it; the test waits for the client to report it.
    /// </remarks>
    [TestCase(true,  TestName = "When the SRV record in use expires, the next one takes over")]
    [TestCase(false, TestName = "When an SRV record not in use expires, the instance is unchanged")]
    [Property("RFC", "6763 §5")]
    public async Task An_Srv_Record_That_Expires_Changes_The_Instance_Only_If_It_Was_In_Use(Boolean InUse)
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(new MulticastDNSClientOptions {
                                                    InitialBrowseInterval  = TimeSpan.FromHours(1),
                                                    MaxBrowseInterval      = TimeSpan.FromHours(1),
                                                    CacheSweepInterval     = TimeSpan.FromMilliseconds(50)
                                                },
                                                clock);

        var expired = 0;

        link.Client.OnRecordExpired += (_, _, entry, _) => {
            if (entry.Record is SRV)
                Interlocked.Increment(ref expired);
            return Task.CompletedTask;
        };

        var (browser, events) = await Resolved(link,
                                               Pointer(Ttl: 1000),
                                               Service(Target: "first-choice.local.",  Port: 1000, Priority: 0,  Ttl: InUse ? 10u : 1000u),
                                               Service(Target: "second-choice.local.", Port: 2000, Priority: 10, Ttl: InUse ? 1000u : 10u),
                                               Text("path=/"),
                                               Address("192.0.2.1", Name: "first-choice.local.",  Ttl: 1000),
                                               Address("192.0.2.2", Name: "second-choice.local.", Ttl: 1000));

        await using var _ = browser;

        clock.Advance(TimeSpan.FromSeconds(11));

        await WaitUntil(() => Volatile.Read(ref expired) == 1, "the SRV record to expire");
        await Task.Delay(300);

        Assert.Multiple(() => {

            Assert.That(browser.Instances.Single().Port?.ToUInt16(), Is.EqualTo(InUse ? 2000 : 1000),
                        "§5: the SRV record in use is the preferred one of those still cached");

            Assert.That(events.Of("updated"), InUse ? (NUnit.Framework.Constraints.IResolveConstraint) Is.Not.Empty : Is.Empty,
                        InUse ? "the next SRV record took over, which is a change"
                              : "the SRV record the instance uses is still there, so nothing about it changed");

        });

    }


    /// <summary>
    /// An SRV record naming another host makes the addresses of the old one irrelevant:
    /// they say where the service was, not where it is.
    /// </summary>
    [Test]
    [Property("RFC", "6763 §5")]
    public async Task A_New_Srv_Target_Leaves_The_Old_Hosts_Addresses_Behind()
    {

        await using var link = await Link.Start();

        var (browser, _) = await Resolved(link, Pointer(), Service(Target: HostName), Text("path=/"), Address("192.0.2.80"));

        await using var _ = browser;

        await link.Multicast(Response(Service(Target: "new-host.local.")));
        await WaitUntil(() => link.Asked("new-host.local.", RawDnsType.A), "the question for the new host's address");

        Assert.That(browser.Instances.Single().Addresses, Is.Empty, "192.0.2.80 belongs to the old host");

        await link.Multicast(Response(Address("192.0.2.81", Name: "new-host.local.")));
        await WaitUntil(() => browser.Instances.Single().Addresses.Count == 1, "the new host's address");

        Assert.That(browser.Instances.Single().Addresses.Select(address => address.ToString()), Is.EqualTo(new[] { "192.0.2.81" }));

    }


    /// <summary>
    /// RFC 6762 §16: "The simple rules for case-insensitivity in Unicast DNS [RFC1034]
    /// [RFC1035] also apply in Multicast DNS".
    /// </summary>
    [Test]
    [Property("RFC", "6762 §16")]
    public async Task Instance_Names_Match_Without_Regard_To_Case()
    {

        await using var link = await Link.Start();

        var (browser, _) = await Resolved(link,
                                          Pointer("Kitchen._qtest._tcp.local."),
                                          Service(Name: "KITCHEN._QTEST._TCP.LOCAL."),
                                          Address());

        await using var _ = browser;

        Assert.That(browser.AllInstances, Has.Count.EqualTo(1), "one instance, whatever the case of its name");

    }


    /// <summary>
    /// Finding 93. RFC 6762 §16 ends the rule above at ASCII: "No other automatic
    /// equivalences should be assumed. In particular, all UTF-8 multibyte characters
    /// (codes 0x80 and higher) are compared by simple binary comparison of the raw byte
    /// values." And RFC 6763 §4.1.1 lets an instance name hold "arbitrary Net-Unicode
    /// text", accented characters by name. Two services whose names differ only in the
    /// case of an É are two services, each with its own host and port.
    /// </summary>
    [Test]
    [Property("RFC", "6762 §16, 6763 §4.1.1")]
    public async Task Instance_Names_That_Differ_Above_Ascii_Are_Two_Instances()
    {

        await using var link = await Link.Start();
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        var events = new Events(browser);

        await link.Multicast(Response(Pointer("Café._qtest._tcp.local."),
                                      Pointer("CafÉ._qtest._tcp.local."),
                                      Service(Name: "Café._qtest._tcp.local.", Target: "cafe-one.local.", Port: 1000),
                                      Service(Name: "CafÉ._qtest._tcp.local.", Target: "cafe-two.local.", Port: 2000),
                                      Address("192.0.2.1", Name: "cafe-one.local."),
                                      Address("192.0.2.2", Name: "cafe-two.local.")));

        await WaitUntil(() => events.Of("added").Length > 0, "an instance to be reported");
        await Task.Delay(300);

        Assert.That(browser.AllInstances.Select(instance => (instance.InstanceName.FullName.TrimEnd('.'), instance.Port?.ToUInt16())),
                    Is.EquivalentTo(new (String, UInt16?)[] { ("Café._qtest._tcp.local", 1000),
                                                             ("CafÉ._qtest._tcp.local", 2000) }),
                    "§16: É and é are different octets, so these are two names");

    }


    public enum HeardAgain
    {
        Pointer,
        Address,
        Ipv6Address
    }

    /// <summary>
    /// A record heard again says what the instance already holds. Responders repeat
    /// themselves: RFC 6762 §8.3 announces at least twice, and every answer to a browse
    /// query says the same as the last. A browser that took a repetition for a change
    /// would report one where there is none.
    /// </summary>
    [TestCase(HeardAgain.Pointer,     TestName = "A pointer heard again is no update")]
    [TestCase(HeardAgain.Address,     TestName = "An address heard again is no update")]
    [TestCase(HeardAgain.Ipv6Address, TestName = "An IPv6 address heard again is no update")]
    [Property("RFC", "6762 §8.3")]
    public async Task A_Record_Heard_Again_Is_No_Update(HeardAgain Record)
    {

        await using var link = await Link.Start(Quiet());

        var (browser, events) = await Resolved(link, Pointer(), Service(), Text("path=/"), Address(), Address6());

        await using var _ = browser;

        await link.Multicast(Response(Record switch {
                                          HeardAgain.Pointer  => Pointer(),
                                          HeardAgain.Address  => Address(),
                                          _                   => Address6()
                                      }));

        await Task.Delay(300);

        Assert.That(events.Of("updated"), Is.Empty, "the instance is what it was");

    }


    /// <summary>
    /// A new address of a reported instance is a new place to reach the service at: an
    /// update, for an IPv4 address as for an IPv6 one.
    /// </summary>
    [TestCase(false, TestName = "A new address of a reported instance is an update")]
    [TestCase(true,  TestName = "A new IPv6 address of a reported instance is an update")]
    [Property("RFC", "6763 §5")]
    public async Task A_New_Address_Of_A_Reported_Instance_Is_An_Update(Boolean Ipv6)
    {

        await using var link = await Link.Start(Quiet());

        var (browser, events) = await Resolved(link, Pointer(), Service(), Text("path=/"), Address("192.0.2.80"));

        await using var _ = browser;

        // Without the cache-flush bit: the first address stays true beside the second.
        await link.Multicast(Response(Ipv6 ? Address6("2001:db8::81", CacheFlush: false)
                                           : Address ("192.0.2.81",   CacheFlush: false)));

        await WaitUntil(() => events.Of("updated").Length > 0, "the update");

        Assert.That(browser.Instances.Single().Addresses, Has.Count.EqualTo(2), "the address it had, and the new one");

    }


    /// <summary>
    /// Two services on the link, one of them still waiting for its SRV record. An address
    /// of the other one's host reaches the other one.
    /// </summary>
    [Test]
    [Property("RFC", "6763 §5")]
    public async Task An_Address_Reaches_Its_Instance_While_Another_Is_Still_Unresolved()
    {

        await using var link = await Link.Start(Quiet());
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        var events = new Events(browser);

        await link.Multicast(Response(Pointer("Pending._qtest._tcp.local.")));
        await WaitUntil(() => browser.AllInstances.Count == 1, "the instance without an SRV record to be seen");

        await link.Multicast(Response(Pointer(), Service(), Text("path=/")));
        await WaitUntil(() => events.Of("added").Length == 1, "the other instance to be reported");

        await link.Multicast(Response(Address("192.0.2.80")));
        await WaitUntil(() => browser.Instances.Single().Addresses.Count == 1, "the address to reach its instance");

    }

    #endregion

    #region When an instance goes (RFC 6762 §5.2, §10.1)

    /// <summary>
    /// §10.1: a goodbye is the record "with a TTL of zero", and queriers "record a TTL of
    /// 1 and then delete the record one second later".
    /// </summary>
    [Test]
    [Property("RFC", "6762 §10.1")]
    public async Task A_Goodbye_For_The_Pointer_Removes_The_Instance_A_Second_Later()
    {

        await using var link = await Link.Start();

        var (browser, events) = await Resolved(link);

        await using var _ = browser;

        var goodbye = events.Now;

        await link.Multicast(Response(Pointer(Ttl: 0)));

        await WaitUntil(() => events.Of("removed").Length == 1, "the instance to be removed");

        Assert.That(events.Of("removed")[0].At - goodbye, Is.GreaterThanOrEqualTo(TimeSpan.FromMilliseconds(900)),
                    "§10.1: one second to be rescued by another responder");

    }


    [Test]
    [Property("RFC", "6762 §5.2")]
    public async Task An_Instance_Whose_Pointer_Expires_Is_Removed()
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(Clock: clock);

        var (browser, events) = await Resolved(link, Pointer(Ttl: 10), Service(Ttl: 1000), Text("path=/"), Address(Ttl: 1000));

        await using var _ = browser;

        clock.Advance(TimeSpan.FromSeconds(11));

        await WaitUntil(() => events.Of("removed").Length == 1, "the instance to be removed");

        Assert.That(browser.AllInstances, Is.Empty);

    }


    [Test]
    [Property("RFC", "6762 §5.2")]
    public async Task An_Address_That_Expires_Leaves_The_Instance_And_Is_Asked_For_Again()
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(Clock: clock);

        var (browser, events) = await Resolved(link, Pointer(Ttl: 1000), Service(Ttl: 1000), Text("path=/"), Address(Ttl: 10));

        await using var _ = browser;

        var before = link.Queries.Length;

        clock.Advance(TimeSpan.FromSeconds(11));

        await WaitUntil(() => events.Of("updated").Length > 0, "the update");

        Assert.Multiple(() => {
            Assert.That(browser.Instances.Single().Addresses, Is.Empty, "the address is no longer valid");
            Assert.That(link.Queries.Skip(before).Any(packet => RawDnsReader.Parse(packet.Wire).Questions.Any(question => question.Type == RawDnsType.A)),
                        Is.True, "and the browser asks for it again");
        });

    }


    /// <summary>
    /// §5.2: "Before the record expiry time is reached, a Multicast DNS querier that has
    /// local clients with an active interest in the state of that record (e.g., a
    /// network browsing window displaying a list of discovered services to the user)
    /// SHOULD reissue its query to determine whether the record is still valid." The
    /// RFC recommends doing so at 80 % of the lifetime.
    /// </summary>
    [Test]
    [Property("RFC", "6762 §5.2")]
    public async Task A_Pointer_Is_Asked_For_Again_At_Eighty_Percent_Of_Its_Lifetime()
    {

        var clock = new SteppedClock();

        // The repeating browse queries are moved out of the way, so the only query left
        // to look for is the one that refreshes the record.
        await using var link = await Link.Start(Quiet(), clock);

        var (browser, _) = await Resolved(link, Pointer(Ttl: 100), Service(Ttl: 1000), Text("path=/"), Address(Ttl: 1000));

        await using var _ = browser;

        var before = link.Queries.Length;

        clock.Advance(TimeSpan.FromSeconds(75));
        await Task.Delay(TimeSpan.FromMilliseconds(1500));

        Assert.That(link.Queries.Skip(before), Is.Empty, "three quarters of the lifetime is not yet the time to ask");

        clock.Advance(TimeSpan.FromSeconds(6));

        await WaitUntil(() => link.Queries.Skip(before).Any(packet => RawDnsReader.Parse(packet.Wire).Questions.Any(question => question.Type == RawDnsType.PTR)),
                        "the refresh query", 3000);

    }


    /// <summary>
    /// §5.2 plans the queries that keep a record alive at 80, 85, 90 and 95 % of its
    /// lifetime, each with "a random variation of 2% of the record TTL". The one at 80 %
    /// is one query, and is not sent again on every tick until the record is heard.
    /// </summary>
    [Test]
    [Property("RFC", "6762 §5.2")]
    public async Task The_Query_At_Eighty_Percent_Is_Not_Repeated_Before_Eighty_Five()
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(QuietAndQuick(), clock);

        var (browser, _) = await Resolved(link, Pointer(Ttl: 100), Service(Ttl: 1000), Text("path=/"), Address(Ttl: 1000));

        await using var _ = browser;

        var before = link.BrowseQueries.Length;

        clock.Advance(TimeSpan.FromSeconds(83));

        await WaitUntil(() => link.BrowseQueries.Length > before, "the query at 80 %");
        await Task.Delay(500);

        Assert.That(link.BrowseQueries.Length - before, Is.EqualTo(1), "ten maintenance ticks at 83 %, and one query");

    }


    /// <summary>
    /// An address that expires is the address of one host. The instances on that host
    /// lose it, and are updated and asked about again. An instance on another host is
    /// neither.
    /// </summary>
    [TestCase(false, TestName = "An address that expires changes only the instances on its host")]
    [TestCase(true,  TestName = "An IPv6 address that expires changes only the instances on its host")]
    [Property("RFC", "6762 §5.2, 6763 §5")]
    public async Task An_Address_That_Expires_Changes_Only_The_Instances_On_Its_Host(Boolean Ipv6)
    {

        const String Garden      = "Garden._qtest._tcp.local.";
        const String GardenHost  = "garden-host.local.";

        var clock = new SteppedClock();

        await using var link = await Link.Start(QuietAndQuick(), clock);
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        var events = new Events(browser);

        await link.Multicast(Response(Pointer(Ttl: 1000),
                                      Service(Ttl: 1000),
                                      Text("path=/"),
                                      Ipv6 ? Address6(Ttl: 10) : Address(Ttl: 10),
                                      Pointer(Garden, Ttl: 1000),
                                      Service(Name: Garden, Target: GardenHost, Ttl: 1000),
                                      new Rr(Garden, RawDnsType.TXT, 4500, [ 6, .. "path=/"u8 ], true),
                                      Ipv6 ? Address6("2001:db8::90", Name: GardenHost, Ttl: 1000)
                                           : Address ("192.0.2.90",   Name: GardenHost, Ttl: 1000)));

        await WaitUntil(() => events.Of("added").Length == 2, "both instances to be reported");
        await Task.Delay(200);

        var before = link.Queries.Length;
        var type   = Ipv6 ? RawDnsType.AAAA : RawDnsType.A;

        clock.Advance(TimeSpan.FromSeconds(11));

        await WaitUntil(() => events.Of("updated").Length > 0, "the update");
        await Task.Delay(300);

        Assert.Multiple(() => {
            Assert.That(events.Of("updated").Select(update => update.Instance.InstanceName.FullName.TrimEnd('.')),
                        Is.EqualTo(new[] { InstanceName.TrimEnd('.') }), "the instance on the host whose address expired, and no other");
            Assert.That(AskedSince(link, before, HostName,   type), Is.True,  "its host is asked about again");
            Assert.That(AskedSince(link, before, GardenHost, type), Is.False, "the other host is not");
        });

    }


    /// <summary>
    /// An instance whose SRV record never came was never reported. When its pointer
    /// expires it goes as it came, without a report: a removal is the counterpart of an
    /// addition the browser reported.
    /// </summary>
    [Test]
    [Property("RFC", "6762 §5.2")]
    public async Task An_Instance_That_Was_Never_Reported_Goes_Without_A_Report()
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(QuietAndQuick(), clock);
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        var events = new Events(browser);

        await link.Multicast(Response(Pointer(Ttl: 10)));
        await WaitUntil(() => browser.AllInstances.Count == 1, "the instance to be seen");

        clock.Advance(TimeSpan.FromSeconds(11));

        await WaitUntil(() => browser.AllInstances.Count == 0, "the instance to go");
        await Task.Delay(300);

        Assert.That(events.Of("added").Concat(events.Of("removed")), Is.Empty, "neither its coming nor its going was reported");

    }


    /// <summary>
    /// An instance whose pointer has left the cache without expiring, because the cache
    /// was cleared, cannot go with its expiry. It goes once no pointer heard when it was
    /// last seen could still be alive: the longest TTL §10 recommends is 75 minutes. It
    /// goes with a report, and with nothing asked, since nothing is left to keep alive.
    /// </summary>
    [Test]
    [Property("RFC", "6762 §10")]
    public async Task An_Instance_Whose_Pointer_Was_Cleared_From_The_Cache_Goes_After_Seventy_Five_Minutes()
    {

        var clock = new SteppedClock();

        await using var link = await Link.Start(QuietAndQuick(), clock);

        var (browser, events) = await Resolved(link);

        await using var _ = browser;

        link.Client.ClearCache();

        var before = link.Queries.Length;

        clock.Advance(TimeSpan.FromMinutes(75) + TimeSpan.FromSeconds(1));

        await WaitUntil(() => events.Of("removed").Length == 1, "the instance to be reported gone");
        await Task.Delay(300);

        Assert.Multiple(() => {
            Assert.That(browser.AllInstances,      Is.Empty);
            Assert.That(link.Queries.Skip(before), Is.Empty, "nothing is left to keep alive");
        });

    }

    #endregion

}

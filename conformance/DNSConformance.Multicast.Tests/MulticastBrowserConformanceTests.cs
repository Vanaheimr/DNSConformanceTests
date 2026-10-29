using System.Diagnostics;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
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

        public TimeSpan Now
            => clock.Elapsed;

        public PacketCapture(InMemoryMulticastDNSNetwork network)
        {
            network.OnDatagramSent += (_, sender, payload, _) => {
                lock (packets)
                    packets.Add(new CapturedDatagram(sender, payload.ToArray(), clock.Elapsed));
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
            var capture  = new PacketCapture(network);
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

    private static Rr Address(String Dotted = "192.0.2.80", String Name = HostName, UInt32 Ttl = 120)
        => new (Name, RawDnsType.A, Ttl, RawDnsWriter.IPv4(Dotted), true);


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
    [Test]
    [Property("RFC", "6762 §5.2")]
    public async Task Browse_Queries_Start_A_Second_Apart_And_At_Least_Double()
    {

        await using var link = await Link.Start();
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        await Task.Delay(TimeSpan.FromMilliseconds(3500));

        var sent       = link.BrowseQueries.Select(packet => packet.SentAt).ToArray();
        var gaps       = sent.Zip(sent.Skip(1), (first, second) => second - first).ToArray();

        // Timers fire a little early or late. 50 ms of that is allowed on each interval,
        // and an interval measured late is doubled into the next comparison, so that one
        // allows three times as much: still far from the 1 s a non-doubling interval
        // would fall short by.
        var tolerance  = TimeSpan.FromMilliseconds(50);

        Assert.Multiple(() => {

            Assert.That(gaps, Has.Length.GreaterThanOrEqualTo(2), "three queries in three and a half seconds");

            Assert.That(gaps.FirstOrDefault(), Is.GreaterThanOrEqualTo(TimeSpan.FromSeconds(1) - tolerance),
                        "§5.2: the interval between the first two queries MUST be at least one second");

            for (var i = 1; i < gaps.Length; i++)
                Assert.That(gaps[i], Is.GreaterThanOrEqualTo(gaps[i - 1] * 2 - tolerance * 3),
                            $"§5.2: interval {i + 1} MUST be at least twice interval {i}");

        });

    }


    /// <summary>
    /// Finding 80. §5.2: "To avoid accidental synchronization when, for some reason,
    /// multiple clients begin querying at exactly the same moment (e.g., because of some
    /// common external trigger event), a Multicast DNS querier SHOULD also delay the
    /// first query of the series by a randomly chosen amount in the range 20-120 ms."
    /// </summary>
    [Test]
    [Property("RFC", "6762 §5.2")]
    [Category(TestCategories.KnownIssue)]
    public async Task The_First_Browse_Query_Waits_Twenty_To_A_Hundred_And_Twenty_Milliseconds()
    {

        await using var link = await Link.Start();

        var started = link.Capture.Now;

        await using var browser = await link.Client.BrowseAsync(ServiceType);

        await WaitUntil(() => link.BrowseQueries.Length > 0, "the first browse query");

        var delay = link.BrowseQueries[0].SentAt - started;

        Assert.That(delay, Is.InRange(TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(150)),
                    "§5.2: SHOULD delay the first query of the series by 20-120 ms " +
                    "(the upper bound leaves 30 ms for the test's own scheduling)");

    }


    /// <summary>
    /// Finding 81. §7.3: "If a host is planning to transmit (or retransmit) a query, and
    /// it sees another host on the network send a query containing the same "QM"
    /// question, and the Known-Answer Section of that query does not contain any records
    /// that this host would not also put in its own Known-Answer Section, then this host
    /// SHOULD treat its own query as having been sent."
    /// </summary>
    [Test]
    [Property("RFC", "6762 §7.3")]
    [Category(TestCategories.KnownIssue)]
    public async Task A_Question_Another_Host_Just_Asked_Is_Not_Asked_Again()
    {

        await using var link = await Link.Start();
        await using var browser = await link.Client.BrowseAsync(ServiceType);

        await WaitUntil(() => link.BrowseQueries.Length > 0, "the first browse query");

        // Half a second in, the other host asks the same question with no known answers,
        // which is exactly what this browser would put in its own second query.
        var first = link.BrowseQueries[0].SentAt;

        var wait = first + TimeSpan.FromMilliseconds(500) - link.Capture.Now;
        if (wait > TimeSpan.Zero)
            await Task.Delay(wait);

        var asked = link.Capture.Now;

        await link.Multicast(new RawDnsWriter().Header(0, 0, 1, 0, 0, 0).Question(ServiceTypeName, RawDnsType.PTR).ToArray());

        await Task.Delay(TimeSpan.FromMilliseconds(1000));

        Assert.That(link.BrowseQueries.Where(packet => packet.SentAt > asked), Is.Empty,
                    "§7.3: the browser SHOULD treat its own query, due half a second later, as having been sent");

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
    [Category(TestCategories.KnownIssue)]
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
    [Category(TestCategories.KnownIssue)]
    public async Task Known_Answers_That_Do_Not_Fit_One_Packet_Continue_In_Truncated_Packets()
    {

        await using var link = await Link.Start(Quiet());
        await using var browser = await link.Client.BrowseAsync(ServiceType);

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
    [Category(TestCategories.KnownIssue)]
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
    [Category(TestCategories.KnownIssue)]
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

    #endregion

}

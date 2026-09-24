using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

namespace DNSConformance.Multicast.Tests;

/// <summary>
/// RFC 6762 responder conformance, judged from the wire with the suite's own decoder.
/// </summary>
/// <remarks>
/// The four tests in <see cref="MulticastWireConformanceTests"/> cover the shapes a
/// responder emits on its own initiative — probing, announcing, withdrawal, and the
/// legacy unicast reply. These cover what it does when it is asked: known-answer
/// suppression, negative answers, wildcards, the multicast rate limit, and the edges
/// of each.
/// </remarks>
[TestFixture]
public sealed class MulticastResponderConformanceTests
{

    #region Harness

    private sealed record CapturedDatagram(InMemoryMulticastDNSTransport  Sender,
                                           IPSocket?                      Destination,
                                           Byte[]                         Wire);

    private sealed class PacketCapture
    {

        private readonly List<CapturedDatagram> packets = [];

        public PacketCapture(InMemoryMulticastDNSNetwork network)
        {
            network.OnDatagramSent += (_, sender, payload, destination) => {
                lock (packets)
                    packets.Add(new CapturedDatagram(sender, destination, payload.ToArray()));
                return Task.CompletedTask;
            };
        }

        public CapturedDatagram[] From(InMemoryMulticastDNSTransport sender)
        {
            lock (packets)
                return [.. packets.Where(packet => ReferenceEquals(packet.Sender, sender))];
        }

        public RawDnsMessage[] ResponsesFrom(InMemoryMulticastDNSTransport sender)
            => [.. From(sender).Select(packet => RawDnsReader.Parse(packet.Wire)).
                               Where (message => message.QR)];

        public void Clear()
        {
            lock (packets)
                packets.Clear();
        }

    }


    /// <summary>
    /// A clock the test moves by hand.
    /// </summary>
    /// <remarks>
    /// Only GetUtcNow is overridden, which is exactly what the responder's rate limit
    /// reads. Timers keep the base implementation and therefore real time, so probing
    /// and announcing still finish on their own: the test controls what the responder
    /// believes the time is, not how long it actually waits.
    ///
    /// Hermod ships a FakeTimeProvider in its own test project. Borrowing it would let
    /// Hermod supply both the implementation and the instrument that judges it, which
    /// is the one thing this suite does not do.
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
    /// Every delay removed, so a test observes ordering instead of waiting for it.
    /// </summary>
    /// <param name="MinRecordMulticastInterval">
    /// Left at zero unless a test is about the rate limit itself. The options type is a
    /// sealed class rather than a record, so there is no `with` to reach for.
    /// </param>
    private static MulticastDNSResponderOptions FastOptions(TimeSpan? MinRecordMulticastInterval = null)

        => new () {
               ProbeInterval               = TimeSpan.FromMilliseconds(5),
               MaxInitialProbeDelay        = TimeSpan.Zero,
               AnnouncementInterval        = TimeSpan.FromMilliseconds(5),
               MinSharedResponseDelay      = TimeSpan.Zero,
               MaxSharedResponseDelay      = TimeSpan.Zero,
               MinTruncatedQueryDelay      = TimeSpan.Zero,
               MaxTruncatedQueryDelay      = TimeSpan.Zero,
               MinRecordMulticastInterval  = MinRecordMulticastInterval ?? TimeSpan.Zero
           };


    private static readonly DomainName  Host         = DomainName.Parse("wire-host.local.");

    private static readonly Byte[]      HostAddress  = RawDnsWriter.IPv4("192.0.2.53");


    private static IDNSResourceRecord[] HostRecords()

        => [
            new A(Host, DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv4Address.Parse("192.0.2.53"))
        ];


    private static Byte[] Query(String   Name,
                                UInt16   Type,
                                Boolean  UnicastResponse = false)

        => new RawDnsWriter().
               Header(0, 0, 1, 0, 0, 0).
               Question(Name, Type, (UInt16) (UnicastResponse ? RawDnsClass.IN | 0x8000 : RawDnsClass.IN)).
               ToArray();


    /// <summary>A query that already carries the answer it would provoke (RFC 6762 §7.1).</summary>
    private static Byte[] QueryKnowing(String  Name,
                                       UInt16  Type,
                                       UInt32  KnownTimeToLive,
                                       Byte[]  KnownRdata)

        => new RawDnsWriter().
               Header(0, 0, 1, 1, 0, 0).
               Question(Name, Type).
               RR(Name, Type, RawDnsClass.IN, KnownTimeToLive, KnownRdata).
               ToArray();


    /// <summary>A probe: one ANY question, the proposed record in the authority section (RFC 6762 §8.1).</summary>
    private static Byte[] ProbeFor(String   Name,
                                   Byte[]   ProposedAddress,
                                   Boolean  UnicastResponse)

        => new RawDnsWriter().
               Header(0, 0, 1, 0, 1, 0).
               Question(Name, RawDnsType.ANY, (UInt16) (UnicastResponse ? RawDnsClass.IN | 0x8000 : RawDnsClass.IN)).
               RR(Name, RawDnsType.A, RawDnsClass.IN, 120, ProposedAddress).
               ToArray();


    /// <summary>
    /// Decode an NSEC type bit map (RFC 4034 §4.1.2) without asking Hermod to do it.
    /// </summary>
    private static UInt16[] DecodeTypeBitmap(Byte[]  Wire,
                                             Int32   Offset,
                                             Int32   End)
    {

        var types = new List<UInt16>();

        while (Offset + 2 <= End)
        {

            var window  = Wire[Offset++];
            var length  = Wire[Offset++];

            for (var i = 0; i < length && Offset + i < End; i++)
                for (var bit = 0; bit < 8; bit++)
                    if ((Wire[Offset + i] & (0x80 >> bit)) != 0)
                        types.Add((UInt16) ((window << 8) | (i * 8 + bit)));

            Offset += length;

        }

        return [.. types];

    }


    private static UInt16[] TypesInNsec(RawDnsMessage  Response,
                                        RawRecord      Nsec)
    {

        var (_, nameLength) = RawDnsReader.ReadNameAt(Response.Wire, Nsec.RdataOffset);

        return DecodeTypeBitmap(
                   Response.Wire,
                   Nsec.RdataOffset + nameLength,
                   Nsec.RdataOffset + Nsec.Rdata.Length
               );

    }


    /// <summary>Publish the host record, then ask one question and collect what comes back.</summary>
    private static async Task<RawDnsMessage[]> AnswersTo(Byte[] QueryWire)
    {

        var network            = new InMemoryMulticastDNSNetwork();
        var responderTransport = network.CreateTransport();
        var querierTransport   = network.CreateTransport();
        var capture            = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(responderTransport, FastOptions());
        await responder.StartAsync();
        await querierTransport.StartAsync();
        await responder.PublishAsync(HostRecords(), Probe: false);
        capture.Clear();

        await querierTransport.SendAsync(QueryWire);

        return capture.ResponsesFrom(responderTransport);

    }

    #endregion


    #region The defaults carry the constants the RFC names

    [Test]
    [Property("RFC", "6762 §6, §6.3, §7.2, §8.1, §8.3")]
    public void The_Default_Timings_Are_The_Ones_The_Rfc_Names()
    {

        // The expected values are literals on purpose. Comparing the options against
        // Hermod's own MulticastDNS constants would compare the implementation with
        // itself, and agree no matter what either of them said.
        var options = new MulticastDNSResponderOptions();

        Assert.Multiple(() => {

            Assert.That(options.ProbeCount,                 Is.EqualTo(3),
                        "§8.1: a first query, a second 250 ms later, then a third");
            Assert.That(options.ProbeInterval,              Is.EqualTo(TimeSpan.FromMilliseconds(250)),
                        "§8.1: 250 ms after the first query, the host should send a second");
            Assert.That(options.MaxInitialProbeDelay,       Is.EqualTo(TimeSpan.FromMilliseconds(250)),
                        "§8.1: a short random delay, uniformly distributed in the range 0-250 ms");

            Assert.That(options.AnnouncementCount,          Is.EqualTo(2),
                        "§8.3: at least two unsolicited responses");
            Assert.That(options.AnnouncementInterval,       Is.EqualTo(TimeSpan.FromSeconds(1)),
                        "§8.3: one second apart");

            Assert.That(options.MinSharedResponseDelay,     Is.EqualTo(TimeSpan.FromMilliseconds(20)),
                        "§6.3: randomly delayed in the range 20-120 ms");
            Assert.That(options.MaxSharedResponseDelay,     Is.EqualTo(TimeSpan.FromMilliseconds(120)),
                        "§6.3: randomly delayed in the range 20-120 ms");

            Assert.That(options.MinTruncatedQueryDelay,     Is.EqualTo(TimeSpan.FromMilliseconds(400)),
                        "§7.2: defers its response for a time randomly selected in the interval 400-500 ms");
            Assert.That(options.MaxTruncatedQueryDelay,     Is.EqualTo(TimeSpan.FromMilliseconds(500)),
                        "§7.2: defers its response for a time randomly selected in the interval 400-500 ms");

            Assert.That(options.MinRecordMulticastInterval, Is.EqualTo(TimeSpan.FromSeconds(1)),
                        "§6: until at least one second has elapsed since the last time that record was multicast");

        });

    }

    #endregion


    #region Known-answer suppression (RFC 6762 §7.1)

    [Test]
    [Property("RFC", "6762 §7.1")]
    public async Task An_Answer_Already_Known_At_Its_Full_Ttl_Is_Not_Repeated()
    {

        var responses = await AnswersTo(QueryKnowing("wire-host.local.", RawDnsType.A, 120, HostAddress));

        Assert.That(responses, Is.Empty,
                    "§7.1: a responder MUST NOT answer if the answer it would give is already " +
                    "included in the Answer Section with an RR TTL at least half the correct value");

    }


    [Test]
    [Property("RFC", "6762 §7.1")]
    public async Task An_Answer_Known_At_Less_Than_Half_Its_Ttl_Is_Sent_Again()
    {

        var responses = await AnswersTo(QueryKnowing("wire-host.local.", RawDnsType.A, 59, HostAddress));

        Assert.Multiple(() => {

            Assert.That(responses, Has.Length.EqualTo(1),
                        "§7.1: if the TTL given is less than half the true TTL, the responder MUST " +
                        "send an answer so as to update the querier's cache");

            Assert.That(responses[0].Answers.Any(record => record.Type == RawDnsType.A), Is.True);

        });

    }


    [Test]
    [Property("RFC", "6762 §7.1")]
    public async Task The_Known_Answer_Boundary_Is_Exactly_Half_The_Ttl()
    {

        // 60 of 120 is "at least half", so this one is suppressed while 59 is not. The
        // pair is what separates >= from >; neither test alone says which one the code
        // is using.
        var responses = await AnswersTo(QueryKnowing("wire-host.local.", RawDnsType.A, 60, HostAddress));

        Assert.That(responses, Is.Empty,
                    "§7.1: exactly half the correct value is still 'at least half'");

    }

    #endregion


    #region Negative responses (RFC 6762 §6.1)

    [Test]
    [Property("RFC", "6762 §6.1")]
    public async Task A_Missing_Type_At_An_Owned_Name_Is_Answered_With_Nsec()
    {

        var responses = await AnswersTo(Query("wire-host.local.", RawDnsType.AAAA));

        Assert.That(responses, Has.Length.EqualTo(1),
                    "§6.1: the responder MUST respond asserting the nonexistence of that record");

        var nsec = responses[0].Answers.Single(record => record.Type == RawDnsType.NSEC);

        Assert.Multiple(() => {

            Assert.That(nsec.Name.Canonical,                     Is.EqualTo("wire-host.local"));
            Assert.That(TypesInNsec(responses[0], nsec),         Does.Contain(RawDnsType.A),
                        "the bit map names the types that do exist at that name");
            Assert.That(TypesInNsec(responses[0], nsec),         Does.Not.Contain(RawDnsType.AAAA),
                        "the type that was asked for is precisely the one that does not");

        });

    }


    [Test]
    [Property("RFC", "6762 §6.1")]
    public async Task The_Synthesized_Nsec_Does_Not_Claim_The_Nsec_Type_Itself()
    {

        var responses  = await AnswersTo(Query("wire-host.local.", RawDnsType.AAAA));
        var response   = responses.Single();
        var nsec       = response.Answers.Single(record => record.Type == RawDnsType.NSEC);

        Assert.That(TypesInNsec(response, nsec), Does.Not.Contain(RawDnsType.NSEC),
                    "§6.1: the synthesized Multicast DNS NSEC records MUST NOT have the NSEC bit " +
                    "set in the Type Bit Map");

    }


    [Test]
    [Property("RFC", "6762 §6.1, §10.2")]
    public async Task A_Negative_Answer_Carries_The_Cache_Flush_Bit()
    {

        var response  = (await AnswersTo(Query("wire-host.local.", RawDnsType.AAAA))).Single();
        var nsec      = response.Answers.Single(record => record.Type == RawDnsType.NSEC);

        Assert.That(nsec.Class, Is.EqualTo((UInt16) (RawDnsClass.IN | 0x8000)),
                    "the denial is as unique to this responder as the records it denies");

    }


    [Test]
    [Property("RFC", "6762 §6, §6.1")]
    public async Task A_Name_The_Responder_Does_Not_Own_Draws_No_Answer_At_All()
    {

        var responses = await AnswersTo(Query("somebody-else.local.", RawDnsType.A));

        Assert.That(responses, Is.Empty,
                    "§6: a responder MUST only respond when it has a positive, non-null response to " +
                    "send, or it authoritatively knows that a particular record does not exist");

    }

    #endregion


    #region Wildcards and multiple questions (RFC 6762 §6.3, §6.4, §6.5)

    private static async Task<(PacketCapture Capture, InMemoryMulticastDNSTransport Responder, InMemoryMulticastDNSTransport Querier, MulticastDNSResponder Instance)>
        DualStackHost()
    {

        var network            = new InMemoryMulticastDNSNetwork();
        var responderTransport = network.CreateTransport();
        var querierTransport   = network.CreateTransport();
        var capture            = new PacketCapture(network);

        var responder = new MulticastDNSResponder(responderTransport, FastOptions());
        await responder.StartAsync();
        await querierTransport.StartAsync();

        await responder.PublishAsync([
            new A   (Host, DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv4Address.Parse("192.0.2.53")),
            new AAAA(Host, DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv6Address.Parse("2001:db8::53"))
        ], Probe: false);

        capture.Clear();

        return (capture, responderTransport, querierTransport, responder);

    }


    [Test]
    [Property("RFC", "6762 §6.5")]
    public async Task An_Any_Query_Returns_Every_Record_At_The_Name()
    {

        var (capture, responderTransport, querierTransport, responder) = await DualStackHost();

        await using (responder)
        {

            await querierTransport.SendAsync(Query("wire-host.local.", RawDnsType.ANY));

            var response = capture.ResponsesFrom(responderTransport).Single();

            Assert.Multiple(() => {

                Assert.That(response.Answers.Select(record => record.Type),
                            Is.EquivalentTo(new UInt16[] { RawDnsType.A, RawDnsType.AAAA }),
                            "§6.5: a responder MUST respond with *ALL* of its records that match the query");

                Assert.That(response.Answers.Any(record => record.Type == RawDnsType.NSEC), Is.False,
                            "a wildcard query is answered with what exists, not with a denial");

            });

        }

    }


    [Test]
    [Property("RFC", "6762 §6.3, §6.4")]
    public async Task A_Query_With_Two_Questions_Answers_Both_In_One_Message()
    {

        var (capture, responderTransport, querierTransport, responder) = await DualStackHost();

        await using (responder)
        {

            await querierTransport.SendAsync(
                      new RawDnsWriter().
                          Header(0, 0, 2, 0, 0, 0).
                          Question("wire-host.local.", RawDnsType.A).
                          Question("wire-host.local.", RawDnsType.AAAA).
                          ToArray()
                  );

            var responses = capture.ResponsesFrom(responderTransport);

            Assert.Multiple(() => {

                Assert.That(responses, Has.Length.EqualTo(1),
                            "§6.4: a responder SHOULD aggregate as many responses as possible into a " +
                            "single Multicast DNS response message");

                Assert.That(responses[0].Answers.Select(record => record.Type),
                            Is.EquivalentTo(new UInt16[] { RawDnsType.A, RawDnsType.AAAA }),
                            "§6.3: responders MUST correctly handle query messages containing more " +
                            "than one question, by answering any or all of the questions");

            });

        }

    }

    #endregion


    #region The edges of the legacy unicast rule (RFC 6762 §6.7)

    [Test]
    [Property("RFC", "6762 §6.7")]
    public async Task A_Ttl_Below_The_Legacy_Cap_Is_Not_Raised_To_It()
    {

        var network    = new InMemoryMulticastDNSNetwork();
        var transport  = network.CreateTransport();
        var capture    = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(transport, FastOptions());
        await responder.StartAsync();

        await responder.PublishAsync([
            new A(Host, DNSQueryClasses.IN, TimeSpan.FromSeconds(5), IPv4Address.Parse("192.0.2.53"))
        ], Probe: false);

        capture.Clear();

        await transport.InjectAsync(
                  Query("wire-host.local.", RawDnsType.A),
                  new IPSocket(IPv4Address.Parse("10.53.0.99"), IPPort.Parse(49152))
              );

        var answer = RawDnsReader.Parse(capture.From(transport).Single().Wire).Answers.Single();

        Assert.That(answer.Ttl, Is.EqualTo(5),
                    "§6.7 caps the TTL of a legacy answer at ten seconds; it does not raise a " +
                    "shorter one up to ten");

    }


    [Test]
    [Property("RFC", "6762 §6.7, §10.2, §18.1")]
    public async Task A_Query_From_The_Mdns_Port_Is_Not_A_Legacy_Query()
    {

        var network    = new InMemoryMulticastDNSNetwork();
        var transport  = network.CreateTransport();
        var capture    = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(transport, FastOptions());
        await responder.StartAsync();
        await responder.PublishAsync(HostRecords(), Probe: false);
        capture.Clear();

        // The same query, injected the same way; only the source port differs. Port 5353
        // is what tells a peer responder from a stub resolver, and everything §6.7 asks
        // for hangs off that one comparison.
        await transport.InjectAsync(
                  Query("wire-host.local.", RawDnsType.A),
                  new IPSocket(IPv4Address.Parse("10.53.0.99"), IPPort.Parse(5353))
              );

        var packet    = capture.From(transport).Single();
        var response  = RawDnsReader.Parse(packet.Wire);

        Assert.Multiple(() => {

            Assert.That(packet.Destination, Is.Null,
                        "a query from the mDNS port is answered by multicast, not back to the sender");

            Assert.That(response.Id, Is.EqualTo(0),
                        "§18.1: in multicast responses the ID is zero");

            Assert.That(response.Questions, Is.Empty,
                        "§6.7 repeats the question only in a legacy unicast response");

            Assert.That(response.Answers.Single().Class, Is.EqualTo((UInt16) (RawDnsClass.IN | 0x8000)),
                        "§10.2: the cache-flush bit is set in records sent to UDP port 5353");

            Assert.That(response.Answers.Single().Ttl, Is.EqualTo(120),
                        "the ten-second cap belongs to legacy responses alone");

        });

    }

    #endregion


    #region Complete RRsets (RFC 6762 §10.2)

    [Test]
    [Property("RFC", "6762 §10.2")]
    public async Task Every_Member_Of_A_Unique_Rrset_Is_Sent_Together()
    {

        var network            = new InMemoryMulticastDNSNetwork();
        var responderTransport = network.CreateTransport();
        var querierTransport   = network.CreateTransport();
        var capture            = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(responderTransport, FastOptions());
        await responder.StartAsync();
        await querierTransport.StartAsync();

        await responder.PublishAsync([
            new A(Host, DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv4Address.Parse("192.0.2.53")),
            new A(Host, DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv4Address.Parse("192.0.2.54"))
        ], Probe: false);

        capture.Clear();

        await querierTransport.SendAsync(Query("wire-host.local.", RawDnsType.A));

        var answers = capture.ResponsesFrom(responderTransport).Single().Answers;

        Assert.Multiple(() => {

            Assert.That(answers, Has.Count.EqualTo(2),
                        "§10.2: any time a host sends a response packet containing some members of a " +
                        "unique RRSet, it MUST send the entire RRSet");

            Assert.That(answers.All(record => record.Class == (RawDnsClass.IN | 0x8000)), Is.True,
                        "§10.2: the host MUST set the cache-flush bit on all members of the unique RRSet");

        });

    }

    #endregion


    #region The multicast rate limit (RFC 6762 §6)

    [Test]
    [Property("RFC", "6762 §6")]
    public async Task The_Same_Record_Is_Not_Multicast_Twice_Within_One_Second()
    {

        var clock              = new SteppedClock();
        var network            = new InMemoryMulticastDNSNetwork();
        var responderTransport = network.CreateTransport();
        var querierTransport   = network.CreateTransport();
        var capture            = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(
                                        responderTransport,
                                        FastOptions(TimeSpan.FromSeconds(1)),
                                        clock
                                    );

        await responder.StartAsync();
        await querierTransport.StartAsync();
        await responder.PublishAsync(HostRecords(), Probe: false);
        capture.Clear();

        await querierTransport.SendAsync(Query("wire-host.local.", RawDnsType.A));
        var afterFirst = capture.ResponsesFrom(responderTransport).Length;

        clock.Advance(TimeSpan.FromMilliseconds(999));
        await querierTransport.SendAsync(Query("wire-host.local.", RawDnsType.A));
        var afterSecond = capture.ResponsesFrom(responderTransport).Length;

        clock.Advance(TimeSpan.FromMilliseconds(2));
        await querierTransport.SendAsync(Query("wire-host.local.", RawDnsType.A));
        var afterThird = capture.ResponsesFrom(responderTransport).Length;

        Assert.Multiple(() => {

            Assert.That(afterSecond, Is.EqualTo(afterFirst),
                        "§6: a responder MUST NOT multicast a record on a given interface until at " +
                        "least one second has elapsed since the last time that record was multicast");

            Assert.That(afterThird, Is.EqualTo(afterFirst + 1),
                        "and once that second has elapsed it answers again");

        });

    }


    [Test]
    [Property("RFC", "6762 §5.4, §6")]
    public async Task A_Unicast_Answer_Is_Not_Held_Back_By_The_Multicast_Rate_Limit()
    {

        var clock              = new SteppedClock();
        var network            = new InMemoryMulticastDNSNetwork();
        var responderTransport = network.CreateTransport();
        var querierTransport   = network.CreateTransport();
        var capture            = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(
                                        responderTransport,
                                        FastOptions(TimeSpan.FromSeconds(1)),
                                        clock
                                    );

        await responder.StartAsync();
        await querierTransport.StartAsync();
        await responder.PublishAsync(HostRecords(), Probe: false);
        capture.Clear();

        // The clock never moves, so both of these are well inside the interval that stops
        // a multicast. The limit counts multicasts, and neither of these is one.
        await querierTransport.SendAsync(Query("wire-host.local.", RawDnsType.A, UnicastResponse: true));
        await querierTransport.SendAsync(Query("wire-host.local.", RawDnsType.A, UnicastResponse: true));

        Assert.That(capture.ResponsesFrom(responderTransport), Has.Length.EqualTo(2),
                    "§6 limits how often a record is multicast; a unicast reply costs the link nothing");

    }

    #endregion


    #region Defending a name against a probe (RFC 6762 §6, §8.1)

    private static async Task<CapturedDatagram[]> DefenceAgainstProbe(Boolean UnicastResponse)
    {

        var network            = new InMemoryMulticastDNSNetwork();
        var responderTransport = network.CreateTransport();
        var proberTransport    = network.CreateTransport();
        var capture            = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(
                                        responderTransport,
                                        FastOptions(TimeSpan.FromSeconds(1))
                                    );

        await responder.StartAsync();
        await proberTransport.StartAsync();

        // Publishing announces, and announcing multicasts the record, which starts the
        // one-second clock on it. The second right after an announcement is precisely
        // when a neighbour is most likely to probe for the same name.
        await responder.PublishAsync(HostRecords(), Probe: false);
        capture.Clear();

        await proberTransport.SendAsync(
                  ProbeFor("wire-host.local.", RawDnsWriter.IPv4("192.0.2.99"), UnicastResponse)
              );

        return capture.From(responderTransport);

    }


    /// <summary>
    /// Red for finding 59: the rate limit swallows the defence of a name.
    /// </summary>
    /// <remarks>
    /// Left failing on purpose, the way PLAN.md §9 asks: the test is the tracking signal,
    /// and turning it green by weakening it would hide the thing it found. Its control
    /// below passes, so the defence itself works — what is missing is the exemption §6
    /// names.
    /// </remarks>
    [Test]
    [Category(TestCategories.KnownIssue)]
    [Property("RFC", "6762 §6, §8.1")]
    public async Task A_Probe_Without_The_Unicast_Bit_Is_Still_Defended()
    {

        var packets = await DefenceAgainstProbe(UnicastResponse: false);

        Assert.That(packets, Is.Not.Empty,
                    "§6 exempts probes from the rate limit by name: a responder MUST NOT multicast a " +
                    "record within one second 'except in the one special case of answering probe " +
                    "queries'. §8.1 says why the exception is there — the QU bit exists to let a " +
                    "defender answer 'instead of potentially having to wait before replying via " +
                    "multicast' — and §8.1 makes QU a SHOULD, not a MUST. A probe arriving without it " +
                    "must still be answered, or the prober takes a name that is already in use.");

    }


    [Test]
    [Property("RFC", "6762 §5.4, §8.1")]
    public async Task A_Probe_With_The_Unicast_Bit_Is_Defended_By_Unicast()
    {

        // The control for the test above: the defence itself works, so what the other one
        // fails on is the missing exemption rather than the mechanism.
        var packets = await DefenceAgainstProbe(UnicastResponse: true);

        Assert.Multiple(() => {

            Assert.That(packets, Is.Not.Empty,
                        "§8.1: a device receiving a probe for a name it is currently using SHOULD " +
                        "generate its response to defend that name immediately");

            Assert.That(packets.Any(packet => packet.Destination is not null), Is.True,
                        "§5.4: the unicast-response bit asks for the reply to come straight back");

        });

    }

    #endregion

}

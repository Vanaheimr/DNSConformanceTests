using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Multicast.Tests;

/// <summary>
/// RFC 6762/6763 assertions made with the suite's independent wire decoder.
/// Hermod supplies the implementation under test, but not the verdict.
/// </summary>
[TestFixture]
public sealed class MulticastWireConformanceTests
{

    private sealed record CapturedDatagram(InMemoryMulticastDNSTransport Sender,
                                           IPSocket?                     Destination,
                                           Byte[]                        Wire);

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

        public void Clear()
        {
            lock (packets)
                packets.Clear();
        }
    }


    private static MulticastDNSResponderOptions FastOptions()
        => new() {
               ProbeInterval               = TimeSpan.FromMilliseconds(5),
               MaxInitialProbeDelay        = TimeSpan.Zero,
               AnnouncementInterval        = TimeSpan.FromMilliseconds(5),
               MinSharedResponseDelay      = TimeSpan.Zero,
               MaxSharedResponseDelay      = TimeSpan.Zero,
               MinTruncatedQueryDelay      = TimeSpan.Zero,
               MaxTruncatedQueryDelay      = TimeSpan.Zero,
               MinRecordMulticastInterval  = TimeSpan.Zero
           };


    private static IDNSResourceRecord[] ServiceRecords()
    {
        var host        = DomainName.Parse("wire-host.local.");
        var serviceType = DNSServiceName.Parse("_wiretest._tcp.local.");
        var instance    = DNSServiceName.Parse("Independent._wiretest._tcp.local.");

        return [
            new A  (host,        DNSQueryClasses.IN, TimeSpan.FromSeconds(120),  IPv4Address.Parse("192.0.2.53")),
            new SRV(instance,    DNSQueryClasses.IN, TimeSpan.FromSeconds(120),  0, 0, IPPort.Parse(8053), host),
            new TXT(instance,    DNSQueryClasses.IN, TimeSpan.FromSeconds(4500), [ "txtvers=1", "path=/dns" ]),
            new PTR(serviceType, DNSQueryClasses.IN, TimeSpan.FromSeconds(4500), instance)
        ];
    }


    private static Byte[] Query(UInt16 id, String name, UInt16 type, UInt16 queryClass = RawDnsClass.IN)
    {
        using var stream = new MemoryStream();

        WriteUInt16(stream, id);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, 1);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, 0);

        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte((Byte) bytes.Length);
            stream.Write(bytes);
        }

        stream.WriteByte(0);
        WriteUInt16(stream, type);
        WriteUInt16(stream, queryClass);

        return stream.ToArray();
    }

    private static void WriteUInt16(Stream stream, UInt16 value)
    {
        stream.WriteByte((Byte) (value >> 8));
        stream.WriteByte((Byte) value);
    }


    [Test]
    [Property("RFC", "6762 §8.1, §8.3, §10.2, §18.1, §18.5")]
    public async Task Probing_And_Announcements_Have_The_Required_Wire_Shape()
    {
        var network    = new InMemoryMulticastDNSNetwork();
        var transport  = network.CreateTransport();
        var capture    = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(transport, FastOptions());
        await responder.StartAsync();

        var publication = await responder.PublishAsync([
            new A(DomainName.Parse("wire-probe.local."),
                  DNSQueryClasses.IN,
                  TimeSpan.FromSeconds(120),
                  IPv4Address.Parse("192.0.2.54"))
        ]);

        var messages       = capture.From(transport).Select(packet => RawDnsReader.Parse(packet.Wire)).ToArray();
        var probes         = messages.Where(message => !message.QR).ToArray();
        var announcements  = messages.Where(message =>  message.QR).ToArray();

        Assert.Multiple(() => {
            Assert.That(publication.State, Is.EqualTo(MulticastDNSPublicationState.Published));
            Assert.That(probes, Has.Length.EqualTo(3), "a new unique name is probed three times");
            Assert.That(announcements, Has.Length.EqualTo(2), "a successful probe is announced twice");

            Assert.That(probes.All(message => message.Id == 0 && !message.RD && message.Questions.Count == 1),
                        Is.True, "multicast probes use ID zero, RD clear and one question");
            Assert.That(probes.All(message => message.Questions[0].Type == RawDnsType.ANY),
                        Is.True, "a probe asks ANY for the proposed unique name");
            Assert.That(probes.All(message => message.Questions[0].Class == (RawDnsClass.IN | 0x8000)),
                        Is.True, "probe questions request a unicast response (QU)");
            Assert.That(probes.All(message => message.Authorities.Count == 1),
                        Is.True, "the proposed record is in the authority section");
            Assert.That(probes.All(message => message.Authorities.Single().Class == RawDnsClass.IN),
                        Is.True, "§10.2: the cache-flush bit is only set in records in the Resource Record Sections " +
                                 "of Multicast DNS responses, and a probe is a query");
            Assert.That(probes.All(message => message.Answers.Count == 0 && !message.TC),
                        Is.True, "§18.5: a probe lists no known answers, so no TC bit says more of them are following");

            Assert.That(announcements.All(message => message.Id == 0 && message.AA && !message.RD),
                        Is.True, "multicast announcements use ID zero, AA set and RD clear");
            Assert.That(announcements.All(message => !message.TC),
                        Is.True, "§18.5: in multicast response messages, the TC bit MUST be zero on transmission");
            Assert.That(announcements.All(message => message.Answers.Single().Class == (RawDnsClass.IN | 0x8000)),
                        Is.True, "unique announcement records carry the cache-flush bit");
        });
    }


    [Test]
    [Property("RFC", "6763 §4, §12")]
    public async Task A_DnsSd_Ptr_Answer_Carries_Srv_Txt_And_Address_Additionals()
    {
        var network           = new InMemoryMulticastDNSNetwork();
        var responderTransport = network.CreateTransport();
        var querierTransport   = network.CreateTransport();
        var capture            = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(responderTransport, FastOptions());
        await responder.StartAsync();
        await querierTransport.StartAsync();
        await responder.PublishAsync(ServiceRecords(), Probe: false);
        capture.Clear();

        await querierTransport.SendAsync(Query(0, "_wiretest._tcp.local.", RawDnsType.PTR));

        var response = capture.From(responderTransport).
                               Select(packet => RawDnsReader.Parse(packet.Wire)).
                               Single(message => message.QR);

        var ptr = response.Answers.Single(record => record.Type == RawDnsType.PTR);

        Assert.Multiple(() => {
            Assert.That(ptr.Name.Canonical, Is.EqualTo("_wiretest._tcp.local"));
            Assert.That(ptr.Class, Is.EqualTo(RawDnsClass.IN), "shared PTR records do not carry cache-flush");
            Assert.That(RawDnsReader.ReadNameAt(response.Wire, ptr.RdataOffset).Name.Canonical,
                        Is.EqualTo("independent._wiretest._tcp.local"));

            Assert.That(response.Additionals.Select(record => record.Type),
                        Is.EquivalentTo(new UInt16[] { RawDnsType.SRV, RawDnsType.TXT, RawDnsType.A }));
            Assert.That(response.Additionals.All(record => (record.Class & 0x8000) != 0),
                        Is.True, "the unique SRV, TXT and address records carry cache-flush");
        });
    }


    [Test]
    [Property("RFC", "6762 §10.1, §10.2")]
    public async Task Withdrawal_Sends_Ttl_Zero_Without_Changing_Shared_And_Unique_Bits()
    {
        var network    = new InMemoryMulticastDNSNetwork();
        var transport  = network.CreateTransport();
        var capture    = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(transport, FastOptions());
        await responder.StartAsync();
        var publication = await responder.PublishAsync(ServiceRecords(), Probe: false);
        capture.Clear();

        await publication.WithdrawAsync();

        var goodbye = capture.From(transport).
                              Select(packet => RawDnsReader.Parse(packet.Wire)).
                              Single(message => message.QR);

        Assert.Multiple(() => {
            Assert.That(goodbye.Answers, Has.Count.EqualTo(4));
            Assert.That(goodbye.Answers.All(record => record.Ttl == 0), Is.True);
            Assert.That(goodbye.Answers.Single(record => record.Type == RawDnsType.PTR).Class,
                        Is.EqualTo(RawDnsClass.IN), "shared PTR goodbye has no cache-flush bit");
            Assert.That(goodbye.Answers.Where(record => record.Type != RawDnsType.PTR).
                                        All(record => record.Class == (RawDnsClass.IN | 0x8000)),
                        Is.True, "unique goodbyes retain cache-flush");
        });
    }


    [Test]
    [Property("RFC", "6762 §6.7")]
    public async Task Legacy_Unicast_Response_Copies_Id_And_Question_And_Caps_Ttl()
    {
        var network    = new InMemoryMulticastDNSNetwork();
        var transport  = network.CreateTransport();
        var capture    = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(transport, FastOptions());
        await responder.StartAsync();
        await responder.PublishAsync(ServiceRecords(), Probe: false);
        capture.Clear();

        await transport.InjectAsync(
                  Query(0xBEEF, "wire-host.local.", RawDnsType.A),
                  new IPSocket(IPv4Address.Parse("10.53.0.99"), IPPort.Parse(49152))
              );

        var packet    = capture.From(transport).Single();
        var response  = RawDnsReader.Parse(packet.Wire);
        var answer    = response.Answers.Single();

        Assert.Multiple(() => {
            Assert.That(packet.Destination, Is.Not.Null, "legacy answer is sent by unicast");
            Assert.That(response.Id, Is.EqualTo(0xBEEF));
            Assert.That(response.Questions, Has.Count.EqualTo(1));
            Assert.That(response.Questions[0].Name.Canonical, Is.EqualTo("wire-host.local"));
            Assert.That(answer.Ttl, Is.LessThanOrEqualTo(10));
            Assert.That(answer.Class, Is.EqualTo(RawDnsClass.IN),
                        "cache-flush is not set in a legacy unicast response");
        });
    }


    private static readonly DNSServiceName WireServiceType = DNSServiceName.Parse("_wiretest._tcp.local.");

    private static PTR Pointer(String Instance)
        => new (WireServiceType, DNSQueryClasses.IN, TimeSpan.FromSeconds(4500), DNSServiceName.Parse($"{Instance}._wiretest._tcp.local."));

    /// <summary>The instance a PTR record names, read with the suite's decoder.</summary>
    private static String PointerTarget(RawDnsMessage Message, RawRecord Record)
        => RawDnsReader.ReadNameAt(Message.Wire, Record.RdataOffset).Name.Canonical;

    private static RawDnsMessage[] Responses(PacketCapture Capture, InMemoryMulticastDNSTransport Transport)
        => [.. Capture.From(Transport).Select(packet => RawDnsReader.Parse(packet.Wire)).Where(message => message.QR)];


    /// <summary>
    /// §8.1: "for all those resource records that a Multicast DNS responder desires to be
    /// unique on the local link, it MUST send a Multicast DNS query asking for those
    /// resource records, to see if any of them are already in use". A publication of
    /// shared records only has nothing to probe for, and goes on to announce them.
    /// </summary>
    [Test]
    [Property("RFC", "6762 §8.1, §8.3")]
    public async Task A_Publication_Of_Shared_Records_Only_Is_Not_Probed()
    {
        var network    = new InMemoryMulticastDNSNetwork();
        var transport  = network.CreateTransport();
        var capture    = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(transport, FastOptions());
        await responder.StartAsync();

        var publication  = await responder.PublishAsync([ Pointer("Shared") ]);
        var messages     = capture.From(transport).Select(packet => RawDnsReader.Parse(packet.Wire)).ToArray();

        Assert.Multiple(() => {
            Assert.That(publication.State, Is.EqualTo(MulticastDNSPublicationState.Published));
            Assert.That(messages.Where(message => !message.QR), Is.Empty,
                        "§8.1: probing is for the records that are to be unique");
            Assert.That(messages.Count(message => message.QR), Is.EqualTo(2),
                        "§8.3: the shared record is announced");
        });
    }


    /// <summary>
    /// §10.1: a goodbye is for "resource record data [that] is about to become invalid",
    /// and gives "the same resource record name, rrtype, rrclass, and rdata, but an RR TTL
    /// of zero". Records still being probed for were never announced, and may be another
    /// host's as well, rdata and all: a goodbye for them would delete that host's records
    /// from every cache on the link.
    /// </summary>
    /// <remarks>
    /// On the test's clock, with the delay before the first probe fixed at 100 ms.
    /// </remarks>
    [Test]
    [Property("RFC", "6762 §10.1")]
    public async Task A_Publication_Withdrawn_While_Probing_Says_No_Goodbye()
    {
        var clock      = new ManualClock();
        var network    = new InMemoryMulticastDNSNetwork();
        var transport  = network.CreateTransport();
        var capture    = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(transport,
                                                              new MulticastDNSResponderOptions {
                                                                  MinInitialProbeDelay  = TimeSpan.FromMilliseconds(100),
                                                                  MaxInitialProbeDelay  = TimeSpan.FromMilliseconds(100)
                                                              },
                                                              clock);
        await responder.StartAsync();

        var publishing = responder.PublishAsync(ServiceRecords());

        clock.AdvanceTo((await clock.NextWait(Until: publishing))!.Value);
        await clock.NextWait(Until: publishing);

        Assert.That(capture.From(transport), Has.Length.EqualTo(1), "the first probe is out");

        await responder.WithdrawAsync(responder.Publications.Single());

        while (await clock.NextWait(Until: publishing) is TimeSpan due)
            clock.AdvanceTo(due);

        var publication = await publishing;

        Assert.Multiple(() => {
            Assert.That(publication.State, Is.EqualTo(MulticastDNSPublicationState.Withdrawn));
            Assert.That(Responses(capture, transport), Is.Empty,
                        "§10.1: nothing was announced, so there is nothing to say goodbye to");
        });
    }


    /// <summary>
    /// §8.4: "if the rdata of any of a host's Multicast DNS records changes, the host MUST
    /// repeat the Announcing step described above to update neighboring caches". And "In
    /// the case of unique records, a host SHOULD omit the "goodbye" announcement, since
    /// the cache-flush bit on the newly announced records will cause old rdata to be
    /// flushed from peer caches anyway."
    /// </summary>
    [Test]
    [Property("RFC", "6762 §8.3, §8.4")]
    public async Task A_Changed_Address_Is_Announced_As_Often_As_The_First_And_Without_A_Goodbye()
    {
        var network    = new InMemoryMulticastDNSNetwork();
        var transport  = network.CreateTransport();
        var capture    = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(transport, FastOptions());
        await responder.StartAsync();

        var host         = DomainName.Parse("wire-host.local.");
        var publication  = await responder.PublishAsync([ new A(host, DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv4Address.Parse("192.0.2.53")) ],
                                                        Probe: false);
        var announced    = Responses(capture, transport).Length;

        capture.Clear();

        await responder.UpdateAsync(publication, [ new A(host, DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv4Address.Parse("192.0.2.54")) ]);

        var updates = Responses(capture, transport);

        Assert.Multiple(() => {

            Assert.That(updates, Has.Length.EqualTo(announced),
                        "§8.4: the host MUST repeat the Announcing step");

            Assert.That(updates.SelectMany(update => update.Answers).
                                Select(record => (record.Type, record.Class, record.Ttl, String.Join(".", record.Rdata))),
                        Is.All.EqualTo((RawDnsType.A, (UInt16) (RawDnsClass.IN | 0x8000), 120u, "192.0.2.54")),
                        "§8.4: the new address with the cache-flush bit, and no goodbye for the old one");

        });
    }


    /// <summary>
    /// §8.4: "In the case of shared records, a host MUST send a "goodbye" announcement with
    /// RR TTL zero (see Section 10.1, "Goodbye Packets") for the old rdata, to cause it to
    /// be deleted from peer caches, before announcing the new rdata." A shared record has
    /// no cache-flush bit to do that, even when another record of its set stays.
    /// </summary>
    [Test]
    [Property("RFC", "6762 §8.4, §10.1")]
    public async Task A_Shared_Record_Taken_Out_Gets_A_Goodbye_Before_The_Rest_Is_Announced()
    {
        var network    = new InMemoryMulticastDNSNetwork();
        var transport  = network.CreateTransport();
        var capture    = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(transport, FastOptions());
        await responder.StartAsync();

        var publication = await responder.PublishAsync([ Pointer("One"), Pointer("Two") ], Probe: false);

        capture.Clear();

        await responder.UpdateAsync(publication, [ Pointer("Two") ]);

        var sent = Responses(capture, transport).
                       Select(message => message.Answers.Select(record => (PointerTarget(message, record), record.Ttl)).ToArray()).
                       ToArray();

        Assert.Multiple(() => {

            Assert.That(sent.FirstOrDefault(), Is.EqualTo(new[] { ("one._wiretest._tcp.local", 0u) }),
                        "§8.4: first a goodbye for the old rdata");

            Assert.That(sent.Skip(1), Is.Not.Empty.And.All.EqualTo(new[] { ("two._wiretest._tcp.local", 4500u) }),
                        "§8.4: then the announcements of what is left");

        });
    }


    public enum WholeSetGone
    {
        AnotherTypeStaysAtTheName,
        TheTypeStaysAtAnotherName
    }

    /// <summary>
    /// §10.1: a host that "knows that certain resource record data is about to become
    /// invalid" SHOULD send it again "but with a TTL of zero". A unique record whose whole
    /// RRSet is taken out has no cache-flush announcement to replace it, so it gets that
    /// goodbye: also when another type stays at its name, and when its type stays at
    /// another name. Neither is the same name, rrtype and rrclass.
    /// </summary>
    [TestCase(WholeSetGone.AnotherTypeStaysAtTheName, TestName = "An IPv6 address taken out gets a goodbye while the IPv4 address stays")]
    [TestCase(WholeSetGone.TheTypeStaysAtAnotherName, TestName = "The address of a host taken out gets a goodbye while another host's stays")]
    [Property("RFC", "6762 §8.4, §10.1")]
    public async Task A_Unique_Record_Taken_Out_With_Its_Whole_Set_Gets_A_Goodbye(WholeSetGone Case)
    {
        var network    = new InMemoryMulticastDNSNetwork();
        var transport  = network.CreateTransport();
        var capture    = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(transport, FastOptions());
        await responder.StartAsync();

        var leaving   = DomainName.Parse("leaving.local.");
        var staying   = DomainName.Parse("staying.local.");
        var address   = new A   (leaving, DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv4Address.Parse("192.0.2.60"));
        var ipv6      = new AAAA(leaving, DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv6Address.Parse("2001:db8::60"));
        var another   = new A   (staying, DNSQueryClasses.IN, TimeSpan.FromSeconds(120), IPv4Address.Parse("192.0.2.61"));

        IDNSResourceRecord[] before  = Case == WholeSetGone.AnotherTypeStaysAtTheName ? [ address, ipv6 ] : [ address, another ];
        IDNSResourceRecord[] after   = Case == WholeSetGone.AnotherTypeStaysAtTheName ? [ address ]       : [ another ];
        var                  gone    = Case == WholeSetGone.AnotherTypeStaysAtTheName ? RawDnsType.AAAA   : RawDnsType.A;

        var publication = await responder.PublishAsync(before, Probe: false);

        capture.Clear();

        await responder.UpdateAsync(publication, after);

        var goodbyes = Responses(capture, transport).
                           SelectMany(message => message.Answers).
                           Where     (record  => record.Ttl == 0).
                           Select    (record  => (record.Name.Canonical, record.Type)).
                           ToArray();

        Assert.That(goodbyes, Is.EqualTo(new[] { ("leaving.local", gone) }),
                    "§10.1: the record taken out, with a TTL of zero, and nothing that stays");
    }


    /// <summary>
    /// §17: "A Multicast DNS packet larger than the interface MTU, which is sent using
    /// fragments, MUST NOT contain more than one resource record." Forty pointers do not
    /// fit one packet of an Ethernet MTU, so their announcement goes out in several.
    /// </summary>
    [Test]
    [Property("RFC", "6762 §8.3, §17")]
    public async Task Records_Too_Many_For_One_Packet_Are_Announced_In_Several()
    {
        var network    = new InMemoryMulticastDNSNetwork();
        var transport  = network.CreateTransport();
        var capture    = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(transport, FastOptions());
        await responder.StartAsync();

        var names = Enumerable.Range(1, 40).Select(n => $"Instance {n:D2} with a name long enough to fill a packet soon").ToArray();

        await responder.PublishAsync([.. names.Select(Pointer)], Probe: false);

        var responses = Responses(capture, transport);

        Assert.Multiple(() => {

            Assert.That(responses.Where(response => response.Answers.Count > 1).Select(response => response.Wire.Length),
                        Is.All.LessThanOrEqualTo(1472),
                        "§17: a packet larger than the MTU MUST NOT contain more than one resource record");

            Assert.That(responses.SelectMany(response => response.Answers).Count(), Is.EqualTo(2 * names.Length),
                        "every record is announced, twice");

        });
    }


    /// <summary>
    /// §17 again, for one record larger than the MTU: it goes in a packet of its own, as
    /// the only record there, and nothing else goes with it, not even a packet without
    /// any record.
    /// </summary>
    [Test]
    [Property("RFC", "6762 §8.3, §17")]
    public async Task A_Record_Too_Large_For_A_Packet_Is_Announced_Alone()
    {
        var network    = new InMemoryMulticastDNSNetwork();
        var transport  = network.CreateTransport();
        var capture    = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(transport, FastOptions());
        await responder.StartAsync();

        await responder.PublishAsync([ new TXT(DNSServiceName.Parse("Large._wiretest._tcp.local."),
                                               DNSQueryClasses.IN,
                                               TimeSpan.FromSeconds(4500),
                                               new String('x', 1600)) ],
                                     Probe: false);

        Assert.That(Responses(capture, transport).Select(response => response.Answers.Count), Is.EqualTo(new[] { 1, 1 }),
                    "§8.3: two announcements, each a packet holding the one record");
    }

}

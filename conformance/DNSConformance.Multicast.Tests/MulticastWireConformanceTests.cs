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
    [Property("RFC", "6762 §8.1, §8.3, §18.1")]
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

            Assert.That(announcements.All(message => message.Id == 0 && message.AA && !message.RD),
                        Is.True, "multicast announcements use ID zero, AA set and RD clear");
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

}

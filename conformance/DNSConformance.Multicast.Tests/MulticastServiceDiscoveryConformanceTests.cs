using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Multicast.Tests;

/// <summary>
/// RFC 6763 conformance: the additional records a responder is asked to volunteer, and
/// the one thing DNS-SD forbids a TXT record to be.
/// </summary>
/// <remarks>
/// <see cref="MulticastWireConformanceTests"/> covers the PTR case of §12 — the service
/// enumeration answer that drags SRV, TXT and the address records along. §12 has two
/// more cases, and they say different things: an SRV answer brings addresses, a TXT
/// answer brings nothing at all. The second is as much a requirement as the first.
/// </remarks>
[TestFixture]
public sealed class MulticastServiceDiscoveryConformanceTests
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

        public RawDnsMessage[] ResponsesFrom(InMemoryMulticastDNSTransport sender)
        {
            lock (packets)
                return [.. packets.Where (packet  => ReferenceEquals(packet.Sender, sender)).
                                   Select(packet  => RawDnsReader.Parse(packet.Wire)).
                                   Where (message => message.QR)];
        }

        public void Clear()
        {
            lock (packets)
                packets.Clear();
        }

    }


    private static MulticastDNSResponderOptions FastOptions()

        => new () {
               ProbeInterval               = TimeSpan.FromMilliseconds(5),
               MaxInitialProbeDelay        = TimeSpan.Zero,
               AnnouncementInterval        = TimeSpan.FromMilliseconds(5),
               MinSharedResponseDelay      = TimeSpan.Zero,
               MaxSharedResponseDelay      = TimeSpan.Zero,
               MinTruncatedQueryDelay      = TimeSpan.Zero,
               MaxTruncatedQueryDelay      = TimeSpan.Zero,
               MinRecordMulticastInterval  = TimeSpan.Zero
           };


    private static readonly DomainName      Host         = DomainName.Parse    ("sd-host.local.");
    private static readonly DNSServiceName  ServiceType  = DNSServiceName.Parse("_sdtest._tcp.local.");
    private static readonly DNSServiceName  Instance     = DNSServiceName.Parse("Independent._sdtest._tcp.local.");


    private static Byte[] Query(String Name, UInt16 Type)

        => new RawDnsWriter().
               Header(0, 0, 1, 0, 0, 0).
               Question(Name, Type).
               ToArray();


    /// <summary>Publish the given records, then ask one question and read what came back.</summary>
    private static async Task<RawDnsMessage> AnswerTo(IDNSResourceRecord[]  Records,
                                                      String                Name,
                                                      UInt16                Type)
    {

        var network            = new InMemoryMulticastDNSNetwork();
        var responderTransport = network.CreateTransport();
        var querierTransport   = network.CreateTransport();
        var capture            = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(responderTransport, FastOptions());
        await responder.StartAsync();
        await querierTransport.StartAsync();
        await responder.PublishAsync(Records, Probe: false);
        capture.Clear();

        await querierTransport.SendAsync(Query(Name, Type));

        return capture.ResponsesFrom(responderTransport).Single();

    }


    private static IDNSResourceRecord[] FullService()

        => [
            new A   (Host,         DNSQueryClasses.IN, TimeSpan.FromSeconds(120),  IPv4Address.Parse("192.0.2.60")),
            new AAAA(Host,         DNSQueryClasses.IN, TimeSpan.FromSeconds(120),  IPv6Address.Parse("2001:db8::60")),
            new SRV (Instance,     DNSQueryClasses.IN, TimeSpan.FromSeconds(120),  0, 0, IPPort.Parse(8053), Host),
            new TXT (Instance,     DNSQueryClasses.IN, TimeSpan.FromSeconds(4500), [ "txtvers=1", "path=/dns" ]),
            new PTR (ServiceType,  DNSQueryClasses.IN, TimeSpan.FromSeconds(4500), Instance)
        ];

    #endregion


    #region Additional record generation (RFC 6763 §12, RFC 6762 §6.2)

    [Test]
    [Property("RFC", "6763 §12.2")]
    public async Task An_Srv_Answer_Brings_The_Address_Records_Of_Its_Target()
    {

        var response = await AnswerTo(FullService(), "Independent._sdtest._tcp.local.", RawDnsType.SRV);

        Assert.Multiple(() => {

            Assert.That(response.Answers.Select(record => record.Type),
                        Is.EquivalentTo(new UInt16[] { RawDnsType.SRV }));

            Assert.That(response.Additionals.Select(record => record.Type),
                        Is.EquivalentTo(new UInt16[] { RawDnsType.A, RawDnsType.AAAA }),
                        "§12.2: when including an SRV record, the responder SHOULD include all " +
                        "address records (type A and AAAA) named in the SRV rdata");

            Assert.That(response.Additionals.All(record => record.Name.Canonical == "sd-host.local"),
                        Is.True,
                        "the addresses that come along are the ones the SRV points at");

        });

    }


    [Test]
    [Property("RFC", "6763 §12.3")]
    public async Task A_Txt_Answer_Brings_No_Additional_Records()
    {

        var response = await AnswerTo(FullService(), "Independent._sdtest._tcp.local.", RawDnsType.TXT);

        Assert.Multiple(() => {

            Assert.That(response.Answers.Select(record => record.Type),
                        Is.EquivalentTo(new UInt16[] { RawDnsType.TXT }));

            // The SRV shares the instance name and its target has two addresses, so a
            // responder that volunteered "everything nearby" would attach three records
            // here. §12.3 is the case that says which of the neighbours are relevant, and
            // the answer is none of them.
            Assert.That(response.Additionals, Is.Empty,
                        "§12.3: when including a TXT record in a response packet, no additional " +
                        "records are required");

        });

    }


    [Test]
    [Property("RFC", "6762 §6.2")]
    public async Task An_Address_Answer_Brings_The_Other_Address_Family()
    {

        var response = await AnswerTo(FullService(), "sd-host.local.", RawDnsType.A);

        Assert.Multiple(() => {

            Assert.That(response.Answers.Select(record => record.Type),
                        Is.EquivalentTo(new UInt16[] { RawDnsType.A }));

            Assert.That(response.Additionals.Select(record => record.Type),
                        Is.EquivalentTo(new UInt16[] { RawDnsType.AAAA }),
                        "§6.2: when placing an A or AAAA record into a response, a responder SHOULD " +
                        "also place any records of the other address type with the same name into " +
                        "the additional section");

        });

    }

    #endregion


    #region The one shape a TXT record may not have (RFC 6763 §6.1)

    [Test]
    [Property("RFC", "6763 §6.1")]
    public async Task A_Txt_Record_Without_Attributes_Is_Not_Emitted_Empty()
    {

        // RFC 6763 §6.1 draws a line that looks like a technicality and is not: a TXT
        // record carrying no attributes is one zero-length string, rdlength 1, not
        // rdlength 0. Clients must treat "one zero byte", "zero-length record" and "no
        // record at all" as the same thing when reading — but a responder does not get
        // to pick among them when writing.
        var response = await AnswerTo(
                           [
                               new A  (Host,      DNSQueryClasses.IN, TimeSpan.FromSeconds(120),  IPv4Address.Parse("192.0.2.60")),
                               new SRV(Instance,  DNSQueryClasses.IN, TimeSpan.FromSeconds(120),  0, 0, IPPort.Parse(8053), Host),
                               new TXT(Instance,  DNSQueryClasses.IN, TimeSpan.FromSeconds(4500), Array.Empty<String>())
                           ],
                           "Independent._sdtest._tcp.local.",
                           RawDnsType.TXT
                       );

        var txt = response.Answers.Single(record => record.Type == RawDnsType.TXT);

        Assert.Multiple(() => {

            Assert.That(txt.Rdata, Is.Not.Empty,
                        "§6.1: an empty TXT record containing zero strings is not allowed; " +
                        "DNS-SD implementations MUST NOT emit empty TXT records");

            Assert.That(txt.Rdata[0], Is.EqualTo(0),
                        "§6.1: the representation of 'no attributes' is a single zero-length string");

            Assert.That(txt.Rdata, Has.Length.EqualTo(1),
                        "and nothing beyond it");

        });

    }

    #endregion

}

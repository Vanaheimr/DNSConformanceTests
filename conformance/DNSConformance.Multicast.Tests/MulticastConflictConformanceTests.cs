using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.Multicast.Tests;

/// <summary>
/// RFC 6762 §8.2 and §9: who wins a simultaneous probe, and what counts as a conflict
/// once a name has been taken.
/// </summary>
/// <remarks>
/// This is the only part of the responder that decides something by comparing raw bytes
/// as unsigned values, and the only part where being wrong costs a name rather than a
/// packet. The tests come in pairs on purpose: one where the responder must yield and
/// one where it must not, because a comparison that always answers the same way passes
/// either test alone.
/// </remarks>
[TestFixture]
public sealed class MulticastConflictConformanceTests
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

        public RawDnsMessage[] From(InMemoryMulticastDNSTransport sender)
        {
            lock (packets)
                return [.. packets.Where (packet => ReferenceEquals(packet.Sender, sender)).
                                   Select(packet => RawDnsReader.Parse(packet.Wire))];
        }

    }


    /// <summary>
    /// Probing kept slow enough to reach into, everything else instant.
    /// </summary>
    /// <remarks>
    /// The other fixtures shorten the probe interval to five milliseconds because they
    /// only want publishing to be over. Here the probing state is the thing under test,
    /// so it has to last long enough for a competing probe to arrive inside it — which
    /// is exactly the situation §8.2 is written for.
    /// </remarks>
    private static MulticastDNSResponderOptions ProbingOptions()

        => new () {
               ProbeInterval               = TimeSpan.FromMilliseconds(250),
               MaxInitialProbeDelay        = TimeSpan.Zero,
               AnnouncementInterval        = TimeSpan.FromMilliseconds(5),
               MinSharedResponseDelay      = TimeSpan.Zero,
               MaxSharedResponseDelay      = TimeSpan.Zero,
               MinTruncatedQueryDelay      = TimeSpan.Zero,
               MaxTruncatedQueryDelay      = TimeSpan.Zero,
               MinRecordMulticastInterval  = TimeSpan.Zero
           };


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


    private static readonly DomainName  Contested  = DomainName.Parse("contested.local.");

    /// <summary>The address this responder proposes: 192.0.2.10, or C0 00 02 0A on the wire.</summary>
    private static readonly IPv4Address OurAddress = IPv4Address.Parse("192.0.2.10");


    private static IDNSResourceRecord[] OurRecords()

        => [
            new A(Contested, DNSQueryClasses.IN, TimeSpan.FromSeconds(120), OurAddress)
        ];


    /// <summary>A probe: one ANY question and the proposed record in the authority section.</summary>
    private static Byte[] ProbeProposing(String Address)

        => new RawDnsWriter().
               Header(0, 0, 1, 0, 1, 0).
               Question("contested.local.", RawDnsType.ANY).
               RR("contested.local.", RawDnsType.A, RawDnsClass.IN, 120, RawDnsWriter.IPv4(Address)).
               ToArray();


    /// <summary>An unsolicited response asserting an address for the contested name.</summary>
    private static Byte[] ResponseAsserting(String Address, UInt32 TimeToLive = 120)

        => new RawDnsWriter().
               Header(0, (UInt16) (RawDnsFlags.QR | RawDnsFlags.AA), 0, 1, 0, 0).
               RR("contested.local.",
                  RawDnsType.A,
                  (UInt16) (RawDnsClass.IN | 0x8000),
                  TimeToLive,
                  RawDnsWriter.IPv4(Address)).
               ToArray();


    /// <summary>
    /// What a publication looked like while its responder was still alive.
    /// </summary>
    /// <remarks>
    /// Read inside the helper rather than returned as a live publication: disposing the
    /// responder withdraws everything it published, so a state read after the helper
    /// returns is Withdrawn no matter what the test was about. Six tests said so at once,
    /// which is the only reason the mistake was obvious.
    /// </remarks>
    private sealed record Outcome(MulticastDNSPublicationState  State,
                                  Boolean                       IsActive,
                                  IDNSResourceRecord?           OwnConflictedRecord,
                                  IDNSResourceRecord?           ConflictingRecord,
                                  IPSocket?                     ConflictSource)
    {

        public static Outcome Of(MulticastDNSPublication Publication)

            => new (Publication.State,
                    Publication.IsActive,
                    Publication.OwnConflictedRecord,
                    Publication.ConflictingRecord,
                    Publication.ConflictSource);

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

    #endregion


    #region Simultaneous probe tie-breaking (RFC 6762 §8.2)

    /// <summary>
    /// Start probing the contested name, wait until the first probe is actually on the
    /// wire, then let a competitor probe for the same name with the given address.
    /// </summary>
    private static async Task<Outcome> ProbeAgainst(String TheirAddress)
    {

        var network            = new InMemoryMulticastDNSNetwork();
        var responderTransport = network.CreateTransport();
        var rivalTransport     = network.CreateTransport();
        var capture            = new PacketCapture(network);

        await using var responder = new MulticastDNSResponder(responderTransport, ProbingOptions());
        await responder.StartAsync();
        await rivalTransport.StartAsync();

        // Deliberately not awaited: the publication has to be reachable while it is still
        // in the probing state, which is the only state §8.2 says anything about.
        var publishing = responder.PublishAsync(OurRecords());

        await WaitUntil(() => capture.From(responderTransport).Any(message => !message.QR),
                        "the responder to send its first probe");

        await rivalTransport.SendAsync(ProbeProposing(TheirAddress));

        var finished = await Task.WhenAny(publishing, Task.Delay(10000));

        Assert.That(ReferenceEquals(finished, publishing), Is.True,
                    "the publication never settled");

        return Outcome.Of(await publishing);

    }


    [Test]
    [Property("RFC", "6762 §8.2")]
    public async Task A_Rival_Probe_With_Later_Data_Takes_The_Name()
    {

        // C0 00 02 14 against our C0 00 02 0A: byte four decides, and 0x14 is the larger
        // unsigned value.
        var publication = await ProbeAgainst("192.0.2.20");

        Assert.That(publication.State, Is.EqualTo(MulticastDNSPublicationState.Conflict),
                    "§8.2: the two records are compared and the lexicographically later data wins; " +
                    "a host that finds its own data is lexicographically earlier defers to the winner");

    }


    [Test]
    [Property("RFC", "6762 §8.2")]
    public async Task A_Rival_Probe_With_Earlier_Data_Does_Not_Take_The_Name()
    {

        // C0 00 02 01 against our C0 00 02 0A. The pair matters: a comparison stuck on one
        // answer would satisfy either test by itself, and only the two together say which
        // direction the code actually reads.
        var publication = await ProbeAgainst("192.0.2.1");

        Assert.That(publication.State, Is.EqualTo(MulticastDNSPublicationState.Published),
                    "§8.2: the lexicographically later data wins, and here that is ours");

    }


    [Test]
    [Property("RFC", "6762 §8.2")]
    public async Task A_Rival_Probe_Proposing_The_Same_Data_Is_Not_A_Conflict()
    {

        // Our own probe looping back off the link, or a second instance of the same host.
        // §9 defines a conflict by inconsistent rdata, and identical data is not that.
        var publication = await ProbeAgainst("192.0.2.10");

        Assert.That(publication.State, Is.EqualTo(MulticastDNSPublicationState.Published),
                    "identical proposals are not a conflict, whichever way they compare");

    }

    #endregion


    #region Conflicts after the name has been taken (RFC 6762 §9)

    /// <summary>Publish the contested name without probing, then let somebody else assert something.</summary>
    private static async Task<Outcome> PublishedThenHears(Byte[] Wire)
    {

        var network            = new InMemoryMulticastDNSNetwork();
        var responderTransport = network.CreateTransport();
        var otherTransport     = network.CreateTransport();

        await using var responder = new MulticastDNSResponder(responderTransport, FastOptions());
        await responder.StartAsync();
        await otherTransport.StartAsync();

        var publication = await responder.PublishAsync(OurRecords(), Probe: false);

        Assert.That(publication.State, Is.EqualTo(MulticastDNSPublicationState.Published),
                    "the name has to be held before anything can conflict with holding it");

        await otherTransport.SendAsync(Wire);

        // Delivery on this link is synchronous, but the conflict is raised through event
        // handlers; give it a moment rather than assuming the whole chain is inline.
        await Task.Delay(50);

        return Outcome.Of(publication);

    }


    [Test]
    [Property("RFC", "6762 §9")]
    public async Task A_Response_With_Inconsistent_Rdata_Is_A_Conflict()
    {

        var publication = await PublishedThenHears(ResponseAsserting("192.0.2.99"));

        Assert.Multiple(() => {

            // §9 says the responder "MUST immediately reset its conflicted unique record to
            // probing state". Hermod stops at Conflict and reports it, leaving the choice of
            // a new name to the caller — a library cannot invent one, and §9's own recipe
            // ("programmatically change the resource record name", "display a message to the
            // user or operator") describes a complete host rather than a component of one.
            // What is asserted here is that the responder stops claiming the name and says
            // why. Whether stopping at Conflict discharges the MUST is a question for the
            // API's owner, and it is written down rather than quietly answered.
            Assert.That(publication.State, Is.EqualTo(MulticastDNSPublicationState.Conflict),
                        "§9: a conflict occurs when a responder has a unique record for which it " +
                        "is currently authoritative and receives a response containing a record " +
                        "with the same name, rrtype and rrclass, but inconsistent rdata");

            Assert.That(publication.IsActive, Is.False,
                        "a conflicted name is no longer being asserted");

            Assert.That(publication.OwnConflictedRecord, Is.Not.Null,
                        "the report names the record of ours that lost");

            Assert.That(publication.ConflictingRecord,   Is.Not.Null,
                        "and the record that took it");

            Assert.That(publication.ConflictSource,      Is.Not.Null,
                        "and where it came from");

        });

    }


    [Test]
    [Property("RFC", "6762 §9")]
    public async Task A_Response_Repeating_Our_Own_Record_Is_Not_A_Conflict()
    {

        // Our own announcement coming back off the link, or a cooperating responder for the
        // same name. §9 turns on "inconsistent rdata", and this rdata is ours exactly.
        var publication = await PublishedThenHears(ResponseAsserting("192.0.2.10"));

        Assert.That(publication.State, Is.EqualTo(MulticastDNSPublicationState.Published),
                    "§9 defines the conflict by inconsistent rdata, so consistent rdata is none");

    }


    [Test]
    [Property("RFC", "6762 §9, §10.1")]
    public async Task A_Goodbye_For_Our_Name_Is_Not_A_Conflict()
    {

        // A record with TTL zero withdraws data; it asserts nothing about who owns the
        // name, so there is nothing for it to be inconsistent with. Reading it as a claim
        // would let any departing host push a live one off its own name.
        var publication = await PublishedThenHears(ResponseAsserting("192.0.2.99", TimeToLive: 0));

        Assert.That(publication.State, Is.EqualTo(MulticastDNSPublicationState.Published),
                    "§10.1: a TTL of zero says a record is going away, not that somebody else has " +
                    "the name");

    }

    #endregion

}

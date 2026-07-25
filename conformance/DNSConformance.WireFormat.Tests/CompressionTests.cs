using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

namespace DNSConformance.WireFormat.Tests;

/// <summary>
/// RFC 1035 §4.1.4 — message compression. Decoding uses Hermod's
/// DNSTools.ExtractName on RawDns-crafted messages; encoding uses Hermod's
/// serializer with UseCompression=true, decoded by the strict RawDns reader.
/// </summary>
[TestFixture]
[Property("RFC", "1035 §4.1.4")]
public class CompressionTests
{

    #region Hermod_Decodes_The_RFC1035_Compression_Example()

    [Test]
    public void Hermod_Decodes_The_RFC1035_Compression_Example()
    {

        // RFC 1035 §4.1.4 example layout:
        //   offset 20: F.ISI.ARPA
        //   offset 40: FOO + pointer to 20
        //   offset 64: pointer to 26 (ARPA)
        //   offset 92: root
        var writer = new RawDnsWriter();

        writer.Bytes(new Byte[20]);                       // padding to offset 20

        writer.RawLabel("F").RawLabel("ISI").RawLabel("ARPA").EndName();   // 20..31

        writer.Bytes(new Byte[40 - writer.Position]);     // pad to 40
        writer.RawLabel("FOO").Pointer(20);               // FOO.F.ISI.ARPA

        writer.Bytes(new Byte[64 - writer.Position]);     // pad to 64
        writer.Pointer(26);                               // ARPA

        writer.Bytes(new Byte[92 - writer.Position]);     // pad to 92
        writer.EndName();                                 // root

        var wire = writer.ToArray();

        Assert.Multiple(() => {

            var stream = new MemoryStream(wire);

            stream.Position = 20;
            Assert.That(DNSTools.ExtractName(stream), Is.EqualTo("F.ISI.ARPA"));

            stream.Position = 40;
            Assert.That(DNSTools.ExtractName(stream), Is.EqualTo("FOO.F.ISI.ARPA"));

            stream.Position = 64;
            Assert.That(DNSTools.ExtractName(stream), Is.EqualTo("ARPA"));

            stream.Position = 92;
            Assert.That(DNSTools.ExtractName(stream), Is.EqualTo("."));

        });

    }

    #endregion

    #region Hermod_Rejects_Compression_Pointer_Loops()

    [Test]
    public void Hermod_Rejects_Compression_Pointer_Loops()
    {

        // Two pointers referencing each other.
        var wire = new RawDnsWriter()
                       .Bytes(new Byte[12])
                       .Pointer(14)      // at offset 12 → 14
                       .Pointer(12)      // at offset 14 → 12
                       .ToArray();

        var stream = new MemoryStream(wire) { Position = 12 };

        Assert.That(
            () => DNSTools.ExtractName(stream),
            Throws.InstanceOf<Exception>(),
            "cyclic compression pointers must be detected"
        );

    }

    #endregion

    #region Hermod_Rejects_SelfReferencing_Pointer()

    [Test]
    public void Hermod_Rejects_SelfReferencing_Pointer()
    {

        var wire = new RawDnsWriter()
                       .Bytes(new Byte[12])
                       .Pointer(12)
                       .ToArray();

        var stream = new MemoryStream(wire) { Position = 12 };

        Assert.That(
            () => DNSTools.ExtractName(stream),
            Throws.InstanceOf<Exception>()
        );

    }

    #endregion

    #region Hermod_Rejects_Pointer_Beyond_Message_End()

    [Test]
    public void Hermod_Rejects_Pointer_Beyond_Message_End()
    {

        var wire = new RawDnsWriter()
                       .Pointer(0x2FFF)
                       .ToArray();

        Assert.That(
            () => DNSTools.ExtractName(new MemoryStream(wire)),
            Throws.InstanceOf<Exception>()
        );

    }

    #endregion

    #region Forward_Pointers_Are_Not_Prior_Locations()

    [Test]
    [Property("Note", "RFC 1035 §4.1.4 defines pointers as referring to a PRIOR occurrence; accepting forward pointers is lenient parsing.")]
    public void Forward_Pointers_Are_Not_Prior_Locations()
    {

        // Name at offset 0 points FORWARD to offset 4.
        var wire = new RawDnsWriter()
                       .Pointer(4)                     // 0..1
                       .Bytes(0x00, 0x00)              // 2..3 padding
                       .RawLabel("fwd").EndName()      // 4..
                       .ToArray();

        // The independent strict reader refuses forward pointers:
        Assert.That(
            () => RawDnsReader.ReadNameAt(wire, 0),
            Throws.InstanceOf<RawDnsFormatException>()
        );

        // Document Hermod's behavior (leniency is a robustness trade-off, not
        // a MUST violation — recorded here so behavior changes are noticed):
        var hermodResult = DNSTools.ExtractName(new MemoryStream(wire));

        Assert.That(hermodResult, Is.EqualTo("fwd"), "Hermod currently accepts forward pointers (lenient)");

    }

    #endregion


    #region Compressed_Server_Response_Is_Decodable_And_Equivalent()

    [Test]
    public void Compressed_Server_Response_Is_Decodable_And_Equivalent()
    {

        // A response whose owner names share suffixes — prime compression bait:
        //   question: www.conformance.test A
        //   answer:   www.conformance.test CNAME a.conformance.test
        //   answer:   a.conformance.test   A     192.0.2.1
        var question  = new DNSQuestion(
                            DNSServiceName.Parse("www.conformance.test."),
                            DNSResourceRecordTypes.A,
                            DNSQueryClasses.IN
                        );

        var cname     = new CNAME(
                            DomainName.Parse("www.conformance.test."),
                            DNSQueryClasses.IN,
                            TimeSpan.FromMinutes(5),
                            DomainName.Parse("a.conformance.test.")
                        );

        var a         = new A(
                            DomainName.Parse("a.conformance.test."),
                            DNSQueryClasses.IN,
                            TimeSpan.FromMinutes(5),
                            IPv4Address.Parse("192.0.2.1")
                        );

        DNSPacket Build()
            => new (
                   0x7777,
                   DNSQueryResponse.Response,
                   0, true, false, true, true,
                   DNSResponseCodes.NoError,
                   [ question ],
                   [ cname, a ],
                   [],
                   []
               );

        // Reference: uncompressed serialization.
        var uncompressed = Build().ToByteArray();
        var reference    = RawDnsReader.Parse(uncompressed);

        // Under test: compressed serialization of the identical packet.
        var ms = new MemoryStream();
        Build().Serialize(ms, UseCompression: true, CompressionOffsets: []);
        var compressed = ms.ToArray();

        Assert.That(compressed, Has.Length.LessThanOrEqualTo(uncompressed.Length),
                    "compression must never grow the message");

        // The strict reader enforces RFC 1035 §4.1.4 (pointers to PRIOR
        // locations only) and validates every label:
        RawDnsMessage decoded = null!;

        Assert.That(
            () => decoded = RawDnsReader.Parse(compressed),
            Throws.Nothing,
            () => "compressed message is structurally invalid:\n" + Bytes.Dump(compressed)
        );

        Assert.Multiple(() => {

            Assert.That(decoded.Questions.Single().Name.Canonical,
                        Is.EqualTo(reference.Questions.Single().Name.Canonical));

            Assert.That(decoded.Answers, Has.Count.EqualTo(2));

            Assert.That(decoded.Answers[0].Name.Canonical,
                        Is.EqualTo("www.conformance.test"));

            // CNAME RDATA contains a (possibly compressed) name:
            var cnameTarget = RawDnsReader.ReadNameAt(decoded.Wire, decoded.Answers[0].RdataOffset).Name;
            Assert.That(cnameTarget.Canonical, Is.EqualTo("a.conformance.test"));

            Assert.That(decoded.Answers[1].Name.Canonical,
                        Is.EqualTo("a.conformance.test"));

            Assert.That(decoded.Answers[1].Rdata,
                        Is.EqualTo(new Byte[] { 192, 0, 2, 1 }));

        });

    }

    #endregion

    #region Compressed_Response_With_Many_Shared_Suffix_Names_Stays_Valid()

    [Test]
    public void Compressed_Response_With_Many_Shared_Suffix_Names_Stays_Valid()
    {

        // Multiple MX records whose exchanges share the suffix of the owner —
        // exercises suffix-offset bookkeeping across several RRs.
        var owner = DomainName.Parse("mx.deep.sub.conformance.test.");

        DNSPacket Build()
            => new (
                   0x2ADD,
                   DNSQueryResponse.Response,
                   0, true, false, true, true,
                   DNSResponseCodes.NoError,
                   [ new DNSQuestion(DNSServiceName.Parse("mx.deep.sub.conformance.test."), DNSResourceRecordTypes.MX, DNSQueryClasses.IN) ],
                   [
                       new MX(owner, DNSQueryClasses.IN, TimeSpan.FromMinutes(5), 10, DomainName.Parse("mail1.deep.sub.conformance.test.")),
                       new MX(owner, DNSQueryClasses.IN, TimeSpan.FromMinutes(5), 20, DomainName.Parse("mail2.deep.sub.conformance.test.")),
                       new MX(owner, DNSQueryClasses.IN, TimeSpan.FromMinutes(5), 30, DomainName.Parse("mail3.other.example."))
                   ],
                   [],
                   []
               );

        var ms = new MemoryStream();
        Build().Serialize(ms, UseCompression: true, CompressionOffsets: []);
        var compressed = ms.ToArray();

        RawDnsMessage decoded = null!;

        Assert.That(
            () => decoded = RawDnsReader.Parse(compressed),
            Throws.Nothing,
            () => "compressed message is structurally invalid:\n" + Bytes.Dump(compressed)
        );

        var exchanges = decoded.Answers.
                            Select(rr => RawDnsReader.ReadNameAt(decoded.Wire, rr.RdataOffset + 2).Name.Canonical).
                            ToArray();

        Assert.That(exchanges, Is.EquivalentTo(new[] {
            "mail1.deep.sub.conformance.test",
            "mail2.deep.sub.conformance.test",
            "mail3.other.example"
        }));

    }

    #endregion

    #region Uncompressed_Serialization_Contains_No_Pointers()

    [Test]
    public void Uncompressed_Serialization_Contains_No_Pointers()
    {

        var packet = new DNSPacket(
                         0x0001,
                         DNSQueryResponse.Response,
                         0, true, false, false, false,
                         DNSResponseCodes.NoError,
                         [ new DNSQuestion(DNSServiceName.Parse("plain.conformance.test."), DNSResourceRecordTypes.A, DNSQueryClasses.IN) ],
                         [ new A(DomainName.Parse("plain.conformance.test."), DNSQueryClasses.IN, TimeSpan.FromMinutes(1), IPv4Address.Parse("192.0.2.99")) ],
                         [],
                         []
                     );

        var decoded = RawDnsReader.Parse(packet.ToByteArray());

        Assert.Multiple(() => {
            Assert.That(decoded.Questions.Single().Name.Compressed, Is.False);
            Assert.That(decoded.Answers.Single().Name.Compressed,   Is.False);
        });

    }

    #endregion

}

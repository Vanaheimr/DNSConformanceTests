using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

namespace DNSConformance.WireFormat.Tests;

/// <summary>
/// RFC 3597 §4 — which resource records may carry a compression pointer inside
/// their RDATA, and which may not.
/// </summary>
/// <remarks>
/// <para>
/// The rule is one sentence and a definition. Names embedded in RDATA may be
/// compressed only for well-known types, and RFC 3597 §4 settles the term that
/// RFC 1123 left open: well-known means the types defined in RFC 1035, and
/// nothing later. Every type that came afterwards therefore writes its embedded
/// names out in full.
/// </para>
/// <para>
/// The reason is the rest of the RFC. A receiver with no parser for a type
/// handles its RDATA as octets (§2), which leaves it no way to find a pointer
/// inside, let alone expand one — and if it stores those octets and sends them
/// on later, the pointer now indexes into a message that no longer exists. The
/// damage is silent and it lands on the record's contents, not on the parse.
/// </para>
/// <para>
/// Each case here builds the RDATA by hand, reads it back through Hermod, checks
/// that the hand-built layout survived a lossless round trip — so a wrong layout
/// fails as a wrong layout rather than as a compression verdict — and only then
/// asks whether the embedded name was compressed. The name is placed where
/// compression is genuinely on offer: it is also the question name, sitting at
/// offset 12.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "3597 §4")]
public class RdataCompressionTests
{

    /// <summary>The name that appears both as the question name and inside the RDATA.</summary>
    private const String EmbeddedName = "target.example.";

    private static Byte[] Name
        => RawDnsWriter.NameBytes(EmbeddedName);


    #region (private static) RdataFor(Type)

    /// <summary>
    /// Hand-built RDATA for the given type, always containing <see cref="EmbeddedName"/>.
    /// </summary>
    private static Byte[] RdataFor(UInt16 Type)

        => Type switch {

               // RFC 1035 §3.3 — the well-known types, which MAY compress.
               RawDnsType.NS     => Name,
               RawDnsType.CNAME  => Name,
               RawDnsType.PTR    => Name,
               RawDnsType.MX     => new RawDnsWriter().U16(10).Bytes(Name).ToArray(),
               RawDnsType.SOA    => new RawDnsWriter().Bytes(Name).Name("hostmaster.example.").
                                        U32(1).U32(7200).U32(3600).U32(1209600).U32(3600).ToArray(),

               // RFC 1183 — later than RFC 1035, so no compression.
               RawDnsType.AFSDB  => new RawDnsWriter().U16(1).Bytes(Name).ToArray(),
               RawDnsType.RP     => new RawDnsWriter().Bytes(Name).Name("txt.example.").ToArray(),

               // RFC 2782 §"Target": "No name compression is to be used for this field."
               RawDnsType.SRV    => new RawDnsWriter().U16(0).U16(0).U16(5060).Bytes(Name).ToArray(),

               // RFC 3403 §4.1 — NAPTR's replacement.
               RawDnsType.NAPTR  => new RawDnsWriter().U16(100).U16(10).
                                        CharacterString("U").
                                        CharacterString("E2U+sip").
                                        CharacterString("!^.*$!sip:x@example.!").
                                        Bytes(Name).ToArray(),

               // RFC 6672 — DNAME's target.
               RawDnsType.DNAME  => Name,

               // RFC 4034 §3.1.7 — the RRSIG signer's name. The one that fires in
               // practice: the signer is the zone apex, which is already on the
               // wire as the question name of almost every signed answer.
               RawDnsType.RRSIG  => new RawDnsWriter().U16(RawDnsType.A).U8(8).U8(2).
                                        U32(3600).U32(1893456000).U32(1735689600).U16(12345).
                                        Bytes(Name).Hex("0badc0ffee").ToArray(),

               // RFC 4034 §4.1.1 — NSEC's next domain name. Bitmap asserts A.
               RawDnsType.NSEC   => new RawDnsWriter().Bytes(Name).Hex("000140").ToArray(),

               // RFC 9460 §2.2 — SVCB/HTTPS TargetName, here with no parameters.
               RawDnsType.SVCB   => new RawDnsWriter().U16(1).Bytes(Name).ToArray(),
               RawDnsType.HTTPS  => new RawDnsWriter().U16(1).Bytes(Name).ToArray(),

               // RFC 2930 §2 — TKEY's algorithm name.
               RawDnsType.TKEY   => new RawDnsWriter().Bytes(Name).
                                        U32(1735689600).U32(1893456000).U16(3).U16(0).
                                        U16(4).Hex("01020304").U16(0).ToArray(),

               // RFC 8945 §4.2 — TSIG's algorithm name.
               RawDnsType.TSIG   => new RawDnsWriter().Bytes(Name).
                                        U16(0).U32(1735689600).U16(300).
                                        U16(4).Hex("01020304").
                                        U16(0x1234).U16(0).U16(0).ToArray(),

               _ => throw new ArgumentException($"No hand-built RDATA for TYPE{Type}!", nameof(Type))

           };

    #endregion

    #region (private static) RdataAsSerializedInto(Type, Message)

    /// <summary>
    /// Build a record of the given type from hand-written RDATA, put it into a
    /// message whose question name is <see cref="EmbeddedName"/>, and return the
    /// RDATA Hermod wrote — read back by the independent RawDns reader.
    /// </summary>
    private static Byte[] RdataAsSerializedInto(UInt16 Type, Boolean UseCompression)
    {

        var handBuilt = RdataFor(Type);

        // Read the record through Hermod, from a wire image built here.
        var single    = new RawDnsWriter().
                            RR("owner.example.", Type, RawDnsClass.IN, 300, handBuilt).
                            ToArray();

        var record    = DNSInfo.ReadResourceRecord(new MemoryStream(single));

        Assert.That(record, Is.Not.Null, $"Hermod could not read the hand-built TYPE{Type} record");

        // Self-check before the real question: serialising it straight back out,
        // with compression off, must reproduce the hand-built octets exactly.
        // Without this, a mistake in the layout above would surface further down
        // as "this type does not compress" — a pass, for the wrong reason.
        var plain = new MemoryStream();
        record!.Serialize(plain, UseCompression: false, CompressionOffsets: []);

        Assert.That(
            RawDnsReader.Parse([.. new Byte[] { 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0 }, .. plain.ToArray()]).Answers.Single().Rdata,
            Is.EqualTo(handBuilt),
            () => $"the hand-built RDATA for TYPE{Type} does not survive an uncompressed round trip, so " +
                  $"the layout in this test is wrong and its compression verdict would be meaningless:\n{Bytes.Dump(handBuilt)}"
        );

        // Now the message that actually offers compression: the question name is
        // the embedded name, and lands at offset 12.
        var packet = new DNSPacket(
                         0x3597,
                         DNSQueryResponse.Response,
                         0, true, false, false, false,
                         DNSResponseCodes.NoError,
                         [ new DNSQuestion(DNSServiceName.Parse(EmbeddedName), (DNSResourceRecordTypes) Type, DNSQueryClasses.IN) ],
                         [ record ],
                         [],
                         []
                     );

        var ms = new MemoryStream();
        packet.Serialize(ms, UseCompression, CompressionOffsets: []);

        return RawDnsReader.Parse(ms.ToArray()).Answers.Single().Rdata;

    }

    #endregion


    #region Later_Types_Do_Not_Compress_Names_In_Their_Rdata()

    [TestCase(RawDnsType.AFSDB, TestName = "Rdata_uncompressed__AFSDB_hostname")]
    [TestCase(RawDnsType.RP,    TestName = "Rdata_uncompressed__RP_mailbox")]
    [TestCase(RawDnsType.SRV,   TestName = "Rdata_uncompressed__SRV_target")]
    [TestCase(RawDnsType.NAPTR, TestName = "Rdata_uncompressed__NAPTR_replacement")]
    [TestCase(RawDnsType.DNAME, TestName = "Rdata_uncompressed__DNAME_target")]
    [TestCase(RawDnsType.RRSIG, TestName = "Rdata_uncompressed__RRSIG_signer_name")]
    [TestCase(RawDnsType.NSEC,  TestName = "Rdata_uncompressed__NSEC_next_domain_name")]
    [TestCase(RawDnsType.SVCB,  TestName = "Rdata_uncompressed__SVCB_target")]
    [TestCase(RawDnsType.HTTPS, TestName = "Rdata_uncompressed__HTTPS_target")]
    [TestCase(RawDnsType.TKEY,  TestName = "Rdata_uncompressed__TKEY_algorithm")]
    [TestCase(RawDnsType.TSIG,  TestName = "Rdata_uncompressed__TSIG_algorithm")]
    public void Later_Types_Do_Not_Compress_Names_In_Their_Rdata(UInt16 Type)
    {

        var rdata = RdataAsSerializedInto(Type, UseCompression: true);

        Assert.That(rdata, Is.EqualTo(RdataFor(Type)),
                    $"TYPE{Type} postdates RFC 1035, so RFC 3597 §4 leaves it no compression to use — " +
                     "the embedded name has to go out in full even though the same name is already " +
                     "at offset 12 of this message.");

    }

    #endregion

    #region Well_Known_Types_Still_Compress()

    [TestCase(RawDnsType.NS,    TestName = "Rdata_compressed__NS_target")]
    [TestCase(RawDnsType.CNAME, TestName = "Rdata_compressed__CNAME_target")]
    [TestCase(RawDnsType.PTR,   TestName = "Rdata_compressed__PTR_target")]
    [TestCase(RawDnsType.MX,    TestName = "Rdata_compressed__MX_exchange")]
    [TestCase(RawDnsType.SOA,   TestName = "Rdata_compressed__SOA_mname")]
    public void Well_Known_Types_Still_Compress(UInt16 Type)
    {

        // The guard on the test above. RFC 3597 §4 permits compression for these
        // and only these, so this is Hermod's choice rather than a requirement —
        // but without it, "the RDATA contains the whole name" would also pass on
        // a build where compression had stopped working altogether, and eleven
        // assertions would be measuring nothing.
        var compressed   = RdataAsSerializedInto(Type, UseCompression: true);
        var uncompressed = RdataFor(Type);

        Assert.Multiple(() => {

            Assert.That(compressed.Length, Is.LessThan(uncompressed.Length),
                        $"TYPE{Type} is an RFC 1035 type and the name it carries is already at offset 12, " +
                         "so compression is both permitted and available here");

            Assert.That(compressed, Is.Not.EqualTo(uncompressed));

        });

    }

    #endregion

    #region Nothing_Is_Compressed_When_Compression_Is_Off()

    [TestCase(RawDnsType.NS,    TestName = "Compression_off__NS")]
    [TestCase(RawDnsType.MX,    TestName = "Compression_off__MX")]
    [TestCase(RawDnsType.SRV,   TestName = "Compression_off__SRV")]
    [TestCase(RawDnsType.RRSIG, TestName = "Compression_off__RRSIG")]
    public void Nothing_Is_Compressed_When_Compression_Is_Off(UInt16 Type)
    {

        // The other direction: turning compression off must not be overridden by
        // a type that "may" compress.
        Assert.That(RdataAsSerializedInto(Type, UseCompression: false), Is.EqualTo(RdataFor(Type)));

    }

    #endregion

}

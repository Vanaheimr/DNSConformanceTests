using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

namespace DNSConformance.WireFormat.Tests;

/// <summary>
/// RFC 2181 §8 (TTL range) and structural robustness of Hermod's
/// message-level parser against malformed input.
/// </summary>
[TestFixture]
public class TtlAndRobustnessTests
{

    #region Ttl_Of_2147483647_RoundTrips()

    [Test]
    [Property("RFC", "2181 §8")]
    public void Ttl_Of_2147483647_RoundTrips()
    {

        var record   = new A(
                           DomainName.Parse("maxttl.example."),
                           DNSQueryClasses.IN,
                           TimeSpan.FromSeconds(2147483647),      // 2^31-1: maximum valid TTL
                           IPv4Address.Parse("192.0.2.1")
                       );

        var ms = new MemoryStream();
        ms.Write(new Byte[12]);
        record.Serialize(ms, UseCompression: false, CompressionOffsets: []);

        var wire     = ms.ToArray();
        wire[4]      = 0; wire[5] = 0; wire[6] = 0; wire[7] = 1;  // patch ANCOUNT=1 into the dummy header

        var decoded  = RawDnsReader.Parse(wire);

        Assert.That(decoded.Answers.Single().Ttl, Is.EqualTo(2147483647u));

    }

    #endregion

    #region Ttl_With_The_Sign_Bit_Set_Is_Read_As_Zero(RawTTL)

    [Test]
    [Property("RFC", "2181 §8")]
    [TestCase(0x80000000u)]     // the sign bit alone
    [TestCase(0x80000001u)]     // 2^31+1: one second past the legal range
    [TestCase(0xC0000000u)]
    [TestCase(0xFFFFFFFFu)]     // every bit set
    public void Ttl_With_The_Sign_Bit_Set_Is_Read_As_Zero(UInt32 RawTTL)
    {

        // RFC 2181 §8: "Implementations should treat TTL values received with
        // the most significant bit set as if the entire value received was
        // zero." The TTL field is crafted by the independent writer:
        var record = ParseARecordWithTtl(RawTTL);

        Assert.That(record.TimeToLive.TotalSeconds,
                    Is.Zero,
                    $"a received TTL of 0x{RawTTL:X8} has the sign bit set and must read as zero");

    }

    #endregion

    #region Ttl_Below_The_Sign_Bit_Is_Read_Literally(RawTTL)

    [Test]
    [Property("RFC", "2181 §8")]
    [TestCase(0x00000000u)]
    [TestCase(0x00000001u)]
    [TestCase(0x0000012Cu)]     // 300, an ordinary TTL
    [TestCase(0x7FFFFFFEu)]
    [TestCase(0x7FFFFFFFu)]     // 2^31-1: the largest legal TTL, one below the clamp
    public void Ttl_Below_The_Sign_Bit_Is_Read_Literally(UInt32 RawTTL)
    {

        // The other half of §8, and the half a clamp can quietly break: every
        // value that fits in the low 31 bits must survive untouched. Without
        // this, "return zero always" would satisfy the rule above.
        var record = ParseARecordWithTtl(RawTTL);

        Assert.That(record.TimeToLive.TotalSeconds,
                    Is.EqualTo((Double) RawTTL),
                    $"a received TTL of 0x{RawTTL:X8} is within range and must be taken literally");

    }

    #endregion

    #region A_Sign_Bit_Ttl_Does_Not_Become_An_Entry_That_Never_Expires()

    [Test]
    [Property("RFC", "2181 §8")]
    public void A_Sign_Bit_Ttl_Does_Not_Become_An_Entry_That_Never_Expires()
    {

        // Why §8 bothers. The TTL is turned into an expiry the moment the
        // record is parsed, so reading 0xFFFFFFFF literally would date that
        // expiry 136 years out — a record that never leaves a cache again.
        var before  = DateTimeOffset.UtcNow;
        var record  = ParseARecordWithTtl(0xFFFFFFFFu);

        Assert.That(record.EndOfLife,
                    Is.LessThanOrEqualTo(before.AddMinutes(1)),
                    "a record whose TTL had the sign bit set must expire immediately, not in a century");

    }

    #endregion

    #region Ttl_Is_Never_Transmitted_With_The_Sign_Bit_Set()

    [Test]
    [Property("RFC", "2181 §8")]
    public void Ttl_Is_Never_Transmitted_With_The_Sign_Bit_Set()
    {

        // RFC 2181 §8: "When transmitted, this value shall be encoded in the
        // less significant 31 bits of the 32 bit TTL field, with the most
        // significant, or sign, bit set to zero." A TTL held in memory that
        // exceeds the range must therefore be capped on the way out, never
        // allowed to spill into the sign bit.
        var record   = new A(
                           DomainName.Parse("hugettl.example."),
                           DNSQueryClasses.IN,
                           TimeSpan.FromSeconds(4000000000),      // well past 2^31-1
                           IPv4Address.Parse("192.0.2.1")
                       );

        var ms       = new MemoryStream();
        ms.Write(new Byte[12]);
        record.Serialize(ms, UseCompression: false, CompressionOffsets: []);

        var wire     = ms.ToArray();
        wire[4]      = 0; wire[5] = 0; wire[6] = 0; wire[7] = 1;  // patch ANCOUNT=1 into the dummy header

        var ttl      = RawDnsReader.Parse(wire).Answers.Single().Ttl;

        Assert.Multiple(() => {

            Assert.That(ttl & 0x80000000u,
                        Is.Zero,
                        "the sign bit of a transmitted TTL must be zero");

            Assert.That(ttl,
                        Is.EqualTo(2147483647u),
                        "and the value must be capped at the maximum §8 allows, not wrapped");

        });

    }

    #endregion

    #region An_Opt_Keeps_Its_Extended_Rcode_When_The_Ttl_Field_Has_The_Sign_Bit_Set()

    [Test]
    [Property("RFC", "2181 §8, 6891 §6.1.3")]
    public void An_Opt_Keeps_Its_Extended_Rcode_When_The_Ttl_Field_Has_The_Sign_Bit_Set()
    {

        // The trap under §8: OPT reuses the four TTL octets for something that
        // is not a TTL — RFC 6891 §6.1.3 puts the extended RCODE in the high
        // byte, so the sign bit there belongs to RCODE bit 11. An extended
        // RCODE of 0x80 is a combined RCODE of 2048, well inside the 12-bit
        // space, and a clamp that mistook these octets for a TTL would erase it.
        var stream = new MemoryStream(new RawDnsWriter()
                         .U16(1232)                    // CLASS: payload size
                         .U32(0x80008000)              // extRCODE 0x80, version 0, DO
                         .U16(0)                       // no options
                         .ToArray());

        var opt = new OPT(DNSServiceName.Parse("."), stream);

        Assert.Multiple(() => {
            Assert.That(opt.ExtendedRCODE,  Is.EqualTo((Byte) 0x80), "extended RCODE survives");
            Assert.That(opt.Version,        Is.Zero,                 "version survives");
            Assert.That(opt.Flags & 0x8000, Is.EqualTo(0x8000),      "DO bit survives");
        });

    }

    #endregion

    #region (private static) ParseARecordWithTtl(RawTTL)

    /// <summary>
    /// An A record whose TTL field carries exactly the given 32 bits, built by
    /// the suite's own writer so the value under test never passes through the
    /// code being judged.
    /// </summary>
    private static A ParseARecordWithTtl(UInt32 RawTTL)
    {

        // CLASS (2) + TTL (4) + RDLENGTH (2) + RDATA — the stream an RR parser
        // is handed once the owner name and TYPE have been consumed:
        var rdata = new RawDnsWriter().U16(RawDnsClass.IN).U32(RawTTL).U16(4).Bytes(192, 0, 2, 1).ToArray();

        return new A(
                   DomainName.Parse("ttl.example."),
                   new MemoryStream(rdata)
               );

    }

    #endregion


    #region Message_Parser_Keeps_A_Record_It_Cannot_Read()

    [Test]
    [Property("RFC", "3597 §2")]
    public void Message_Parser_Keeps_A_Record_It_Cannot_Read()
    {

        // The request path. DNSPacket.Parse runs a deliberately narrow set of
        // type-specific parsers — a query has no business making a server run
        // the SSHFP decoder — but "not parsed" and "not kept" are different
        // things, and RFC 3597 §2 only licenses the first. A record read by its
        // outer shape alone still has an owner name, a type, a class, a TTL and
        // its RDATA; dropping it throws all five away to avoid decoding one.
        var wire = new RawDnsWriter().
                       Header(0x3597, 0, 1, 0, 0, 2).
                       Question("q.example.", RawDnsType.A).
                       RR("x.example.", 65280, RawDnsClass.IN, 300, Bytes.FromHex("deadbeef")).
                       RR(".",          65281, RawDnsClass.IN, 300, Bytes.FromHex("cafe")).
                       ToArray();

        var packet = DNSPacket.Parse(IPSocket.Zero, IPSocket.Zero, new MemoryStream(wire));

        Assert.That(packet.AdditionalRRs.Count(), Is.EqualTo(2),
                    "both records must survive the parse, including the one owned by the root name");

        var first = packet.AdditionalRRs.First();

        Assert.Multiple(() => {

            Assert.That((UInt16) first.Type,                 Is.EqualTo(65280));
            Assert.That(first.Class,                         Is.EqualTo(DNSQueryClasses.IN));
            Assert.That(first.TimeToLive.TotalSeconds,       Is.EqualTo(300));
            Assert.That(first.DomainName.ToString(),         Is.EqualTo("x.example."));
            Assert.That(((UnknownRecord) first).RData,       Is.EqualTo(Bytes.FromHex("deadbeef")));

            Assert.That((UInt16) packet.AdditionalRRs.Last().Type, Is.EqualTo(65281));

        });

    }

    #endregion

    #region Parser_Survives_Empty_And_Short_Messages()

    [TestCase(0)]
    [TestCase(1)]
    [TestCase(11)]
    public void Parser_Survives_Empty_And_Short_Messages(Int32 length)
    {

        var wire = new Byte[length];

        // Hermod may throw a typed exception — it must not hang or corrupt state.
        Assert.That(
            () => {
                try
                {
                    DNSPacket.Parse(IPSocket.Zero, IPSocket.Zero, new MemoryStream(wire));
                }
                catch (Exception e) when (e is not OutOfMemoryException and not StackOverflowException)
                {
                    // typed failure is acceptable
                }
            },
            Throws.Nothing
        );

    }

    #endregion

    #region Parser_Survives_Counts_Exceeding_Actual_Content()

    [Test]
    public void Parser_Survives_Counts_Exceeding_Actual_Content()
    {

        // Header claims 40 questions, none present (count-amplification probe).
        var wire = new RawDnsWriter()
                       .Header(0x0BAD, 0, 40, 0, 0, 0)
                       .ToArray();

        Assert.That(
            () => {
                try
                {
                    DNSPacket.Parse(IPSocket.Zero, IPSocket.Zero, new MemoryStream(wire));
                }
                catch (Exception e) when (e is not OutOfMemoryException and not StackOverflowException)
                {
                    // typed failure is acceptable — it must simply fail fast
                }
            },
            Throws.Nothing
        );

    }

    #endregion

    #region Parser_Survives_Garbage()

    [Test]
    public void Parser_Survives_Garbage()
    {

        var random = new Random(20260725);

        for (var i = 0; i < 200; i++)
        {

            var wire = new Byte[random.Next(12, 512)];
            random.NextBytes(wire);

            Assert.That(
                () => {
                    try
                    {
                        DNSPacket.Parse(IPSocket.Zero, IPSocket.Zero, new MemoryStream(wire));
                    }
                    catch (Exception e) when (e is not OutOfMemoryException and not StackOverflowException)
                    {
                        // typed failure is fine
                    }
                },
                Throws.Nothing,
                () => $"iteration {i}:\n{Bytes.Dump(wire)}"
            );

        }

    }

    #endregion

}

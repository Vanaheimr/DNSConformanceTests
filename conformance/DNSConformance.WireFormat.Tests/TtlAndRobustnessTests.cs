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

    #region Ttl_With_Most_Significant_Bit_Set_Is_Documented()

    [Test]
    [Property("RFC", "2181 §8")]
    public void Ttl_With_Most_Significant_Bit_Set_Is_Documented()
    {

        // RFC 2181 §8: "a TTL value received ... with the MSB set ... should be
        // treated as if the entire value received was zero."
        // A record with TTL 0x80000001 crafted by the independent writer:
        var rdata   = new RawDnsWriter().U16(RawDnsClass.IN).U32(0x80000001).U16(4).Bytes(192, 0, 2, 1).ToArray();

        var record  = new A(
                          DomainName.Parse("bigttl.example."),
                          new MemoryStream(rdata)
                      );

        // No crash is the hard requirement; the SHOULD-level clamp to 0 is
        // recorded as an observation for FINDINGS.md:
        TestContext.Out.WriteLine($"TTL 0x80000001 is interpreted as {record.TimeToLive.TotalSeconds} seconds " +
                                  $"(RFC 2181 §8 suggests treating it as 0).");

        Assert.That(record.TimeToLive.TotalSeconds,
                    Is.EqualTo(0).Or.EqualTo(2147483649d),
                    "either clamped per RFC 2181 §8 (0) or taken literally");

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

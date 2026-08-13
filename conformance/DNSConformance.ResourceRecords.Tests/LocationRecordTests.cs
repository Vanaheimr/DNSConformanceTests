using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 1876 — the LOC record's edges: the scaled octets, the offsets, and the
/// version field.
/// </summary>
/// <remarks>
/// <para>
/// LOC is a record whose fields nearly all mean something other than what they
/// hold. Latitude and longitude are unsigned with 2^31 for the origin, altitude
/// is unsigned with 100 km subtracted, and size and the two precisions are a
/// mantissa and an exponent packed into one octet. Six of the seven fields need
/// a conversion before they are a measurement.
/// </para>
/// <para>
/// Which is why the interesting failures here are quiet ones. A sign convention
/// applied backwards puts a location on the other hemisphere; a mantissa read
/// without its exponent is out by a factor of a billion; a size field silently
/// replaced by its default reads as a perfectly ordinary record. None of them
/// looks like an error from the outside, and that is the argument for asserting
/// the numbers rather than the rendered string.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "1876")]
public class LocationRecordTests
{

    private static readonly DomainName Name = DomainName.Parse("loc.example.");
    private static readonly TimeSpan   Ttl  = TimeSpan.FromHours(1);

    private static LOC Record(Byte    Version         = 0,
                              Byte    Size            = LOC.DefaultSize,
                              Byte    HorizPrecision  = LOC.DefaultHorizPrecision,
                              Byte    VertPrecision   = LOC.DefaultVertPrecision,
                              UInt32  Latitude        = 1u << 31,
                              UInt32  Longitude       = 1u << 31,
                              UInt32  Altitude        = 10_000_000)

        => new (Name, DNSQueryClasses.IN, Ttl,
                Version, Size, HorizPrecision, VertPrecision,
                Latitude, Longitude, Altitude);


    #region §2 — the scaled octets

    #region A_Scaled_Octet_Is_A_Mantissa_And_A_Power_Of_Ten()

    [TestCase((Byte) 0x00,           0UL, TestName = "Scaled__zero")]
    [TestCase((Byte) 0x12,         100UL, TestName = "Scaled__1e2_is_one_metre")]
    [TestCase((Byte) 0x16,     1000000UL, TestName = "Scaled__1e6_is_ten_kilometres")]
    [TestCase((Byte) 0x13,        1000UL, TestName = "Scaled__1e3_is_ten_metres")]
    [TestCase((Byte) 0x33,        3000UL, TestName = "Scaled__3e3_is_thirty_metres")]
    [TestCase((Byte) 0x29,  2000000000UL, TestName = "Scaled__2e9_is_twenty_thousand_kilometres")]
    [TestCase((Byte) 0x99,  9000000000UL, TestName = "Scaled__9e9_is_the_largest_expressible")]
    [TestCase((Byte) 0x90,           9UL, TestName = "Scaled__9e0_is_nine_centimetres")]
    [Property("RFC", "1876 §2")]
    public void A_Scaled_Octet_Is_A_Mantissa_And_A_Power_Of_Ten(Byte Encoded, UInt64 Centimetres)
    {

        // §2: "a pair of four-bit unsigned integers ... the most significant four
        // bits representing the base and the second number representing the power
        // of ten by which to multiply the base."
        //
        // 0x99 is the ceiling the format can express — 9e9 cm is 90,000 km, seven
        // times the equatorial diameter of the earth — and 0x29 is the value §2
        // itself points at as already larger than the planet.
        Assert.That(LOC.DecodeScaled(Encoded), Is.EqualTo(Centimetres));

    }

    #endregion

    #region An_Undefined_Scaled_Octet_Decodes_To_Nothing()

    [TestCase((Byte) 0xA0, TestName = "Undefined__base_ten")]
    [TestCase((Byte) 0xFF, TestName = "Undefined__both_nibbles_fifteen")]
    [TestCase((Byte) 0x0A, TestName = "Undefined__exponent_ten")]
    [TestCase((Byte) 0x05, TestName = "Undefined__base_zero_with_an_exponent")]
    [TestCase((Byte) 0x09, TestName = "Undefined__base_zero_with_the_largest_exponent")]
    [Property("RFC", "1876 §2")]
    public void An_Undefined_Scaled_Octet_Decodes_To_Nothing(Byte Encoded)
    {

        // §2: "Four-bit values greater than 9 are undefined, as are values with a
        // base of zero and a non-zero exponent."
        //
        // Both exclusions earn their place. Reading 0xFF as 15 × 10^15 cm gives a
        // sphere wider than the solar system, and reading 0x05 as zero quietly
        // agrees with a sender who meant something the RFC declines to define —
        // which is precisely why a reader must not guess at it.
        Assert.That(LOC.DecodeScaled(Encoded), Is.Null);

    }

    #endregion

    #region Every_Defined_Octet_Decodes_And_Every_Other_One_Does_Not()

    [Test]
    [Property("RFC", "1876 §2")]
    public void Every_Defined_Octet_Decodes_And_Every_Other_One_Does_Not()
    {

        // All 256 of them, because the rule is about nibbles and a per-case list
        // can always miss the one combination nobody thought of. §2 defines
        // exactly 0x00 and every base 1..9 with every exponent 0..9 — 91 values.
        var defined = 0;

        for (var octet = 0; octet <= 0xFF; octet++)
        {

            var mantissa = (octet >> 4) & 0x0F;
            var exponent =  octet       & 0x0F;

            var shouldDecode = mantissa <= 9 && exponent <= 9 &&
                               (mantissa != 0 || exponent == 0);

            Assert.That(LOC.DecodeScaled((Byte) octet).HasValue, Is.EqualTo(shouldDecode),
                        $"octet 0x{octet:X2} (base {mantissa}, exponent {exponent})");

            if (shouldDecode)
                defined++;

        }

        Assert.That(defined, Is.EqualTo(91), "0x00 plus nine bases times ten exponents");

    }

    #endregion

    #region Encoding_Round_Trips_Through_The_Values_It_Can_Hold()

    [TestCase(         0UL, TestName = "Encode__zero")]
    [TestCase(       100UL, TestName = "Encode__one_metre")]
    [TestCase(      1000UL, TestName = "Encode__ten_metres")]
    [TestCase(      3000UL, TestName = "Encode__thirty_metres")]
    [TestCase(   1000000UL, TestName = "Encode__ten_kilometres")]
    [TestCase(9000000000UL, TestName = "Encode__ninety_thousand_kilometres")]
    [Property("RFC", "1876 §2")]
    public void Encoding_Round_Trips_Through_The_Values_It_Can_Hold(UInt64 Centimetres)
    {

        Assert.That(LOC.DecodeScaled(LOC.EncodeScaled(Centimetres)), Is.EqualTo(Centimetres));

    }

    #endregion

    #region Encoding_Keeps_One_Significant_Digit()

    [Test]
    [Property("RFC", "1876 §2")]
    public void Encoding_Keeps_One_Significant_Digit()
    {

        // The format holds a single digit, so most values cannot be represented
        // and the question is only which nearby value is chosen. Rounding rather
        // than truncating is worth pinning: 25 m truncated is 20 m, which is a
        // fifth of the way wrong in a field whose whole purpose is to say how
        // wrong the coordinates might be.
        Assert.Multiple(() => {

            Assert.That(LOC.DecodeScaled(LOC.EncodeScaled(2500)),  Is.EqualTo(3000UL), "25 m rounds up to 30 m");
            Assert.That(LOC.DecodeScaled(LOC.EncodeScaled(2400)),  Is.EqualTo(2000UL), "24 m rounds down to 20 m");

            // And nothing larger than the format can say comes back as something
            // smaller than it was asked for.
            Assert.That(LOC.DecodeScaled(LOC.EncodeScaled(UInt64.MaxValue)), Is.EqualTo(9000000000UL));

        });

    }

    #endregion

    #endregion

    #region §2 — the offsets

    #region Latitude_And_Longitude_Are_Offset_From_Two_To_The_Thirtyfirst()

    [Test]
    [Property("RFC", "1876 §2")]
    public void Latitude_And_Longitude_Are_Offset_From_Two_To_The_Thirtyfirst()
    {

        // §2: "2^31 represents the equator; numbers above that are north
        // latitude" — and the same for the prime meridian. Applying that
        // subtraction backwards puts a location on the opposite hemisphere,
        // which is an error that produces a perfectly plausible answer.
        const Int64 equator = 1L << 31;

        Assert.Multiple(() => {

            Assert.That(Record(Latitude: (UInt32) equator).LatitudeInMilliArcSeconds, Is.Zero);

            Assert.That(Record(Latitude:  (UInt32) (equator + 3_600_000)).LatitudeInMilliArcSeconds,
                        Is.EqualTo( 3_600_000), "one degree north");

            Assert.That(Record(Latitude:  (UInt32) (equator - 3_600_000)).LatitudeInMilliArcSeconds,
                        Is.EqualTo(-3_600_000), "one degree south");

            Assert.That(Record(Longitude: (UInt32) (equator - 3_600_000)).LongitudeInMilliArcSeconds,
                        Is.EqualTo(-3_600_000), "one degree west");

        });

    }

    #endregion

    #region Altitude_Is_Measured_From_A_Hundred_Kilometres_Down()

    [Test]
    [Property("RFC", "1876 §2")]
    public void Altitude_Is_Measured_From_A_Hundred_Kilometres_Down()
    {

        // §2 measures altitude "from a base of 100,000m below" the WGS 84
        // spheroid. The offset is what lets an unsigned field carry negative
        // altitudes, and it is why the extremes are exactly the ends of the
        // 32-bit range: nothing a LOC record can hold is out of bounds, so there
        // is no range check to get wrong — only the offset.
        Assert.Multiple(() => {

            Assert.That(Record(Altitude: 10_000_000).AltitudeInCentimetres, Is.Zero,
                        "sea level");

            Assert.That(Record(Altitude: 0).AltitudeInCentimetres, Is.EqualTo(-10_000_000),
                        "the minimum the RFC gives: −100000.00 m");

            Assert.That(Record(Altitude: UInt32.MaxValue).AltitudeInCentimetres, Is.EqualTo(4_284_967_295),
                        "and the maximum: 42849672.95 m");

        });

    }

    #endregion

    #endregion

    #region §2 — the version field

    #region An_Unknown_Version_Is_Written_Generically()

    [Test]
    [Property("RFC", "1876 §2")]
    [Property("RFC", "3597 §5")]
    public void An_Unknown_Version_Is_Written_Generically()
    {

        // RFC 1876 §2: "Implementations are required to check this field and make
        // no assumptions about the format of unrecognized versions."
        //
        // Rendering a version-1 record in the version-0 presentation format is
        // exactly such an assumption, and it produces a coordinate that looks
        // ordinary and means nothing. RFC 3597 §5 gives the answer, naming this
        // very case: the generic form is useful "in the case of an RR type where
        // the text format varies depending on a version ... e.g., a LOC RR
        // [RFC1876] with a VERSION other than 0".
        var unknown  = Record(Version: 1);

        var rendered = unknown.ToZoneFileString();

        Assert.Multiple(() => {

            Assert.That(unknown.IsWellDefined, Is.False);

            Assert.That(rendered, Does.Contain(@"\# 16"),
                        "sixteen octets in the RFC 3597 §5 generic form");

            Assert.That(rendered, Does.Not.Contain(" N "),
                        "and no hemisphere, because nothing here knows where the latitude is");

        });

    }

    #endregion

    #region An_Undefined_Size_Octet_Is_Written_Generically()

    [Test]
    [Property("RFC", "1876 §2")]
    [Property("RFC", "3597 §5")]
    public void An_Undefined_Size_Octet_Is_Written_Generically()
    {

        // Same reasoning one field down: the record's version is known, but one
        // of its octets is not a value §2 assigns a meaning to. Writing "0m" for
        // 0x05 would be a claim the specification refuses to make.
        var record = Record(Size: 0x05);

        Assert.Multiple(() => {

            Assert.That(record.IsWellDefined, Is.False);
            Assert.That(record.ToZoneFileString(), Does.Contain(@"\# 16"));

        });

    }

    #endregion

    #region A_Version_Zero_Record_Is_Written_As_A_Location()

    [Test]
    [Property("RFC", "1876 §3")]
    public void A_Version_Zero_Record_Is_Written_As_A_Location()
    {

        // The control. Without it, "renders generically" would also be satisfied
        // by a build that had given up on the presentation format altogether.
        var record = Record(
                         Latitude:  (UInt32) ((1L << 31) + 42L * 3_600_000 + 21L * 60_000 + 54_000),
                         Longitude: (UInt32) ((1L << 31) - (71L * 3_600_000 + 6L * 60_000 + 18_000)),
                         Altitude:  (UInt32) (10_000_000 - 2_400)
                     );

        var rendered = record.ToZoneFileString();

        Assert.Multiple(() => {

            Assert.That(record.IsWellDefined, Is.True);

            Assert.That(rendered, Does.Contain("42 21 54.000 N"));
            Assert.That(rendered, Does.Contain("71 6 18.000 W"));
            Assert.That(rendered, Does.Contain("-24m"));
            Assert.That(rendered, Does.Not.Contain(@"\#"));

        });

    }

    #endregion

    #endregion

    #region §3 — the master file format

    #region The_Size_And_Precisions_Survive_A_Zone_File_Line()

    [Test]
    [Property("RFC", "1876 §3")]
    public void The_Size_And_Precisions_Survive_A_Zone_File_Line()
    {

        // §3 gives defaults "if omitted" — and only then. Substituting them for
        // values that were written is not defaulting, it is discarding: a zone
        // saying its coordinates are good to 40 m loaded as one claiming 10 km,
        // with nothing anywhere to say so.
        var parsed = (LOC) ADNSResourceRecord.ParseZoneFileString(
                               "loc.example. 3600 IN LOC 42 21 54 N 71 6 18 W -24m 30m 40m 50m"
                           );

        Assert.Multiple(() => {

            Assert.That(parsed.SizeInCentimetres,           Is.EqualTo(3000UL), "30 m");
            Assert.That(parsed.HorizPrecisionInCentimetres, Is.EqualTo(4000UL), "40 m");
            Assert.That(parsed.VertPrecisionInCentimetres,  Is.EqualTo(5000UL), "50 m");

            Assert.That(parsed.AltitudeInCentimetres,       Is.EqualTo(-2400));

        });

    }

    #endregion

    #region Omitted_Fields_Take_The_Defaults_Section_Three_Gives()

    [TestCase("42 21 54 N 71 6 18 W -24m",             100UL, 1000000UL, 1000UL, TestName = "Defaults__all_three_omitted")]
    [TestCase("42 21 54 N 71 6 18 W -24m 30m",        3000UL, 1000000UL, 1000UL, TestName = "Defaults__precisions_omitted")]
    [TestCase("42 21 54 N 71 6 18 W -24m 30m 40m",    3000UL,    4000UL, 1000UL, TestName = "Defaults__vertical_omitted")]
    [Property("RFC", "1876 §3")]
    public void Omitted_Fields_Take_The_Defaults_Section_Three_Gives(String RData,
                                                                    UInt64 Size,
                                                                    UInt64 HorizPrecision,
                                                                    UInt64 VertPrecision)
    {

        // "size defaults to 1m, horizontal precision defaults to 10000m, and
        // vertical precision defaults to 10m" — and the fields are positional, so
        // giving two means the third is the one that defaults.
        var parsed = (LOC) ADNSResourceRecord.ParseZoneFileString($"loc.example. 3600 IN LOC {RData}");

        Assert.Multiple(() => {

            Assert.That(parsed.SizeInCentimetres,           Is.EqualTo(Size));
            Assert.That(parsed.HorizPrecisionInCentimetres, Is.EqualTo(HorizPrecision));
            Assert.That(parsed.VertPrecisionInCentimetres,  Is.EqualTo(VertPrecision));

        });

    }

    #endregion

    #region A_Zone_File_Line_Round_Trips_Through_The_Wire()

    [Test]
    [Property("RFC", "1876 §2")]
    public void A_Zone_File_Line_Round_Trips_Through_The_Wire()
    {

        // Sixteen octets, in the order §2 gives them, read back by the
        // independent RawDns codec — so what the fields mean and where they sit
        // are checked separately.
        var parsed = (LOC) ADNSResourceRecord.ParseZoneFileString(
                               "loc.example. 3600 IN LOC 42 21 54 N 71 6 18 W -24m 30m 40m 50m"
                           );

        var rdata  = RRWire.Encode(parsed).Rdata;

        Assert.That(rdata, Has.Length.EqualTo(16));

        Assert.Multiple(() => {

            Assert.That(rdata[0], Is.Zero,           "version");
            Assert.That(rdata[1], Is.EqualTo(0x33),  "size: 3e3 cm");
            Assert.That(rdata[2], Is.EqualTo(0x43),  "horizontal precision: 4e3 cm");
            Assert.That(rdata[3], Is.EqualTo(0x53),  "vertical precision: 5e3 cm");

            Assert.That(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(rdata.AsSpan(4, 4)),
                        Is.EqualTo((UInt32) ((1L << 31) + 42L * 3_600_000 + 21L * 60_000 + 54_000)));

            Assert.That(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(rdata.AsSpan(8, 4)),
                        Is.EqualTo((UInt32) ((1L << 31) - (71L * 3_600_000 + 6L * 60_000 + 18_000))));

            Assert.That(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(rdata.AsSpan(12, 4)),
                        Is.EqualTo((UInt32) (10_000_000 - 2_400)));

        });

    }

    #endregion

    #endregion

}

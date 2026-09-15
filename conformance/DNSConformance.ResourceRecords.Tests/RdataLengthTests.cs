using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// The largest record that can be written down, and the one octet past it.
///
/// RFC 1035 §4.1.3 gives RDLENGTH sixteen bits: "an unsigned 16 bit integer that
/// specifies the length in octets of the RDATA field". So 65535 octets of RDATA
/// are exactly expressible and 65536 are not, and every type that assembles its
/// own RDATA carries a guard for it — twenty-two of them, written the same way
/// each time, and not one of them had ever been reached from either side.
///
/// A guard at a limit is the easiest kind to get wrong by one, because being
/// wrong by one costs nothing until the day something is exactly that long. The
/// tests below drive each guard to the octet: a record whose RDATA is exactly
/// 65535 octets has to be written, and the same record one octet longer has to
/// be refused.
///
/// The length is read back out of the octets rather than asked of the record,
/// for the same reason the suite reads everything else that way.
///
/// Eleven more of those twenty-two guards cannot be reached at all, and the last
/// test here is why: RFC 1035 §2.3.4 caps a domain name at 255 octets, so the
/// types whose RDATA is one or two names plus fixed fields top out three orders
/// of magnitude below the limit they check for.
/// </summary>
[TestFixture]
[Property("RFC", "1035 §4.1.3, 1035 §2.3.4")]
public class RdataLengthTests
{

    #region Data

    private static readonly DomainName Name   = DomainName.Parse("probe.example.");
    private static readonly DomainName Short  = DomainName.Parse("x.");
    private static readonly TimeSpan   Ttl    = TimeSpan.FromSeconds(3600);

    private const Int32 Max = 65535;

    /// <summary>
    /// Serialize a record uncompressed and return the RDLENGTH it actually
    /// wrote, walked out of the octets: owner name, TYPE, CLASS, TTL, RDLENGTH.
    /// </summary>
    private static Int32 RDataLength(IDNSResourceRecord Record)
    {

        var stream = new MemoryStream();
        Record.Serialize(stream, UseCompression: false, CompressionOffsets: []);

        var bytes   = stream.ToArray();
        var offset  = 0;

        while (bytes[offset] != 0)
            offset += 1 + bytes[offset];

        offset += 1;            // the root label
        offset += 2 + 2 + 4;    // TYPE, CLASS, TTL

        return (bytes[offset] << 8) | bytes[offset + 1];

    }

    /// <summary>
    /// Drive one RDLENGTH guard to the octet. The fixed part of the RDATA is
    /// measured rather than counted by hand — a number worked out in a comment
    /// is a number that goes stale the first time a field moves.
    /// </summary>
    private static void TheLastOctetThatFits(Func<Int32, IDNSResourceRecord> WithFreeFormOctets)
    {

        var fixedPart = RDataLength(WithFreeFormOctets(0));

        Assert.That(RDataLength(WithFreeFormOctets(Max - fixedPart)),
                    Is.EqualTo(Max),
                    "RFC 1035 §4.1.3: 65535 octets of RDATA are exactly what a 16-bit RDLENGTH can say");

        Assert.That(() => RDataLength(WithFreeFormOctets(Max + 1 - fixedPart)),
                    Throws.TypeOf<InvalidOperationException>(),
                    "one octet more cannot be written down, and writing it anyway would truncate the record");

    }

    #endregion


    #region The last octet that fits (RFC 1035 §4.1.3)

    [Test]
    public void An_Nsec_Fills_Rdlength_To_The_Octet()

        => TheLastOctetThatFits(octets => new NSEC(
                                              Name,
                                              DNSQueryClasses.IN,
                                              Ttl,
                                              Short,
                                              new Byte[octets]
                                          ));

    [Test]
    [Property("RFC", "4034 §3.1")]
    public void An_Rrsig_Fills_Rdlength_To_The_Octet()

        => TheLastOctetThatFits(octets => new RRSIG(
                                              Name,
                                              DNSQueryClasses.IN,
                                              Ttl,
                                              DNSResourceRecordTypes.A,
                                              8, 2, 3600,
                                              1700000000,
                                              1690000000,
                                              12345,
                                              Short,
                                              new Byte[octets]
                                          ));

    [Test]
    [Property("RFC", "2535 §4.1")]
    public void A_Sig_Fills_Rdlength_To_The_Octet()

        => TheLastOctetThatFits(octets => new SIG(
                                              Name,
                                              DNSQueryClasses.IN,
                                              Ttl,
                                              DNSResourceRecordTypes.A,
                                              8, 2, 3600,
                                              1700000000,
                                              1690000000,
                                              12345,
                                              Short,
                                              new Byte[octets]
                                          ));

    [Test]
    [Property("RFC", "8945 §4.2")]
    public void A_Tsig_Fills_Rdlength_To_The_Octet()

        => TheLastOctetThatFits(octets => new TSIG(
                                              Name,
                                              DNSQueryClasses.ANY,
                                              TimeSpan.Zero,
                                              Short,
                                              1700000000,
                                              300,
                                              new Byte[octets],
                                              4711,
                                              0,
                                              []
                                          ));

    [Test]
    [Property("RFC", "2930 §2")]
    public void A_Tkey_Fills_Rdlength_To_The_Octet()

        => TheLastOctetThatFits(octets => new TKEY(
                                              Name,
                                              DNSQueryClasses.ANY,
                                              TimeSpan.Zero,
                                              Short,
                                              1690000000,
                                              1700000000,
                                              3,
                                              0,
                                              new Byte[octets],
                                              []
                                          ));

    [Test]
    [Property("RFC", "9460 §2.2")]
    public void An_Svcb_Fills_Rdlength_To_The_Octet()

        => TheLastOctetThatFits(octets => new SVCB(
                                              Name,
                                              DNSQueryClasses.IN,
                                              Ttl,
                                              1,
                                              Short,
                                              [new SVCParameter(65280, new Byte[octets])]
                                          ));

    [Test]
    [Property("RFC", "9460 §2.2")]
    public void An_Https_Fills_Rdlength_To_The_Octet()

        => TheLastOctetThatFits(octets => new HTTPS(
                                              Name,
                                              DNSQueryClasses.IN,
                                              Ttl,
                                              1,
                                              Short,
                                              [new SVCParameter(65280, new Byte[octets])]
                                          ));

    #endregion

    #region The same limit, counted in character-strings (RFC 1035 §3.3.14)

    // TXT and SPF do not carry a free-form octet run: RFC 1035 §3.3.14 makes the
    // RDATA "one or more <character-string>s", each of them a length octet and
    // up to 255 octets of text. So the RDATA is the text plus one octet per
    // chunk, and the last text that fits is 65279 octets long — 256 chunks, 255
    // of them full — rather than 65535.

    [Test]
    [Property("RFC", "1035 §3.3.14")]
    public void A_Txt_Of_65279_Octets_Of_Text_Is_The_Last_One_That_Fits()
    {

        Assert.That(RDataLength(new TXT(Name, DNSQueryClasses.IN, Ttl, new String('x', 65279))),
                    Is.EqualTo(Max),
                    "256 character-strings, 255 of them full: 65279 octets of text and 256 length octets");

        Assert.That(() => RDataLength(new TXT(Name, DNSQueryClasses.IN, Ttl, new String('x', 65280))),
                    Throws.TypeOf<InvalidOperationException>(),
                    "one octet of text more is one octet of RDATA too many");

    }

    [Test]
    [Property("RFC", "7208 §3.3")]
    public void An_Spf_Of_65279_Octets_Of_Text_Is_The_Last_One_That_Fits()
    {

        Assert.That(RDataLength(new SPF(Name, DNSQueryClasses.IN, Ttl, new String('x', 65279))),
                    Is.EqualTo(Max));

        Assert.That(() => RDataLength(new SPF(Name, DNSQueryClasses.IN, Ttl, new String('x', 65280))),
                    Throws.TypeOf<InvalidOperationException>());

    }

    #endregion

    #region The same limit, counted in a URI target (RFC 7553 §4.5)

    [Test]
    [Property("RFC", "7553 §4.5")]
    public void A_Uri_Target_Fills_Rdlength_To_The_Octet()
    {

        // RFC 7553 §4.5: the Target is "the remaining octets of the RDATA", so
        // the RDATA is Priority, Weight and the target itself — four octets of
        // header and no length prefix.
        var prefix   = "http://e.example/";
        var padding  = new String('a', Max - 4 - prefix.Length);
        var target   = URL.Parse(prefix + padding);

        Assert.That(Encoding.ASCII.GetByteCount(target.ToString()),
                    Is.EqualTo(Max - 4),
                    "precondition: the URL survives parsing at its rendered length");

        Assert.That(RDataLength(new URI(DNSServiceName.Parse(Name.FullName), DNSQueryClasses.IN, Ttl, 10, 1, target)),
                    Is.EqualTo(Max));

        Assert.That(() => RDataLength(new URI(DNSServiceName.Parse(Name.FullName), DNSQueryClasses.IN, Ttl, 10, 1,
                                              URL.Parse(prefix + padding + "a"))),
                    Throws.TypeOf<InvalidOperationException>());

    }

    #endregion

    #region The same limit, on RDATA nobody has to understand (RFC 3597 §5)

    [Test]
    [Property("RFC", "3597 §5")]
    public void An_Unknown_Record_Takes_65535_Octets_And_Refuses_65536()
    {

        Assert.That(() => new UnknownRecord(Name, (DNSResourceRecordTypes) 65280, DNSQueryClasses.IN, Ttl, new Byte[Max]),
                    Throws.Nothing,
                    "RFC 3597 §5 puts no type-specific bound on generic RDATA; RFC 1035 §4.1.3 puts this one on all of it");

        Assert.That(() => new UnknownRecord(Name, (DNSResourceRecordTypes) 65280, DNSQueryClasses.IN, Ttl, new Byte[Max + 1]),
                    Throws.TypeOf<ArgumentException>());

    }

    [Test]
    [Property("RFC", "3597 §5")]
    public void The_Generic_Form_Carries_65535_Octets_Through_The_Reader()
    {

        // RFC 3597 §5 writes unknown RDATA as \# <length> <hex>. The reader hands
        // the octets back to the same registry that reads them off a socket, and
        // that hand-off has its own copy of the RDLENGTH limit.
        var record = ADNSResourceRecord.ParseZoneFileString(
                         $"probe.example. 3600 IN TYPE65280 \\# {Max} {new String('a', 2 * Max)}"
                     ) as UnknownRecord;

        Assert.That(record,             Is.Not.Null, "a record of the largest expressible size is still a record");
        Assert.That(record!.RData.Length, Is.EqualTo(Max));

    }

    #endregion

    #region Why eleven of those guards can never fire (RFC 1035 §2.3.4)

    [Test]
    [Property("RFC", "1035 §2.3.4")]
    [Property("RFC", "1035 §4.1.4")]
    public void A_Name_Stops_At_255_Octets_On_The_Wire()
    {

        // RFC 1035 §2.3.4: "names           255 octets or less". Counted on the
        // wire, that is a length octet plus the label for each label, and one
        // more for the root — so 63+63+63+61 characters is exactly 255 octets
        // and one character more is 256.
        var longest  = String.Join('.', new String('a', 63), new String('b', 63), new String('c', 63), new String('d', 61)) + ".";
        var tooLong  = String.Join('.', new String('a', 63), new String('b', 63), new String('c', 63), new String('d', 62)) + ".";

        Assert.Multiple(() => {

            Assert.That(DomainName.TryParse(longest, out _, out _), Is.True,
                        "255 octets is the largest name there is, not the first one too large");

            Assert.That(DomainName.TryParse(tooLong, out _, out var why), Is.False,
                        $"256 octets cannot be written into a message that gives a name 255 — {why}");

        });

        // And this is why a CNAME, DNAME, NS, PTR, MX, SOA, SRV, AFSDB, RP or
        // NAPTR can never reach the RDLENGTH limit its serializer checks for:
        // their RDATA is one or two of these plus a handful of fixed octets.
        var cname = new CNAME(Name, DNSQueryClasses.IN, Ttl, DomainName.Parse(longest));

        Assert.That(RDataLength(cname), Is.LessThanOrEqualTo(255));

    }

    #endregion

}

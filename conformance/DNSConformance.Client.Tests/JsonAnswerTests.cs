using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// The <c>application/dns-json</c> answer, as Google and Cloudflare publish it.
/// </summary>
/// <remarks>
/// <para>
/// Not an IETF standard — there is no RFC for this API, and what it carries is
/// judged by the RFCs that define the records rather than by a specification of
/// its own. The <c>data</c> field is the presentation form of the RDATA, which
/// is the whole reason the zone-file reader is the right thing to hand it to:
/// the two are the same format with the fields split apart differently.
/// </para>
/// <para>
/// Before finding 48 this path had a dispatch table of its own, forty entries
/// long, and everything it did not reach was dropped without a word — not
/// refused, not logged, simply absent from the answer. An empty answer is
/// indistinguishable from NODATA, so a DKIM lookup over this transport reported
/// that the selector did not exist.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "2181 §11, 3597 §2")]
public class JsonAnswerTests
{

    #region Data

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static async Task<DNSInfo> Ask(String Json)
    {

        await using var peer    = new ScriptedDoHServer(_ => null) { JSONResponse = Json };
        await using var client  = new DNSHTTPSClient(URL.Parse(peer.Url),
                                                     Mode:          DNSHTTPSMode.JSON,
                                                     QueryTimeout:  Timeout);

        return await client.Query(DNSServiceName.Parse("probe.example."),
                                  [ DNSResourceRecordTypes.TXT ],
                                  Timeout);

    }

    /// <summary>One answer of the given name, type and presentation RDATA.</summary>
    private static Task<DNSInfo> AskFor(String Name, Int32 Type, String Data)
        => Ask($$"""
               {"Status":0,"RA":true,"Answer":[{"name":"{{Name}}","type":{{Type}},"TTL":60,"data":"{{Data}}"}]}
               """);

    #endregion

    #region An_Underscore_Name_Is_Not_Dropped()

    [Test]
    public async Task An_Underscore_Name_Is_Not_Dropped()
    {

        // RFC 2181 §11 again, one transport further out. These four names are
        // most of what anyone looks up over this API in the first place — DMARC,
        // DKIM and DANE all live under underscore labels (RFC 8552) — and all
        // four came back as nothing at all.
        var cases = new (String Name, Int32 Type, String Data)[] {
            ("_dmarc.probe.example.",             16, "\\\"v=DMARC1; p=none\\\""),
            ("sel._domainkey.probe.example.",     16, "\\\"v=DKIM1\\\""),
            ("_443._tcp.probe.example.",          52, "3 1 1 00112233445566778899aabbccddeeff"),
            ("_25._tcp.probe.example.",           52, "3 1 1 00112233445566778899aabbccddeeff")
        };

        foreach (var (name, type, data) in cases)
        {
            var info = await AskFor(name, type, data);
            Assert.That(info.Answers.Count(), Is.EqualTo(1), $"{name} must survive the JSON reader");
        }

    }

    #endregion

    #region A_Wildcard_Name_Is_Not_Dropped()

    [Test]
    public async Task A_Wildcard_Name_Is_Not_Dropped()
    {

        // RFC 4592 §2.1.1: the asterisk reaches a client in its own right — an
        // NSEC or an RRSIG proving a wildcard match carries one as its owner.
        var info = await AskFor("*.probe.example.", 16, "\\\"wild\\\"");

        Assert.Multiple(() => {
            Assert.That(info.Answers.Count(), Is.EqualTo(1));
            Assert.That(info.Answers.First().DomainName.FullName.TrimEnd('.'),
                        Is.EqualTo("*.probe.example").IgnoreCase);
        });

    }

    #endregion

    #region A_Type_With_No_Parser_Arrives_As_Opaque_Data()

    [Test]
    [Property("RFC", "3597 §2, §5")]
    public async Task A_Type_With_No_Parser_Arrives_As_Opaque_Data()
    {

        // RFC 3597 §2 is unambiguous that an unknown type is data rather than an
        // error, and §5 gives it the "\# <length> <hex>" presentation form that
        // this API returns for one. Finding 21 was the same loss on the wire;
        // here the record simply was not added to the answer.
        var info   = await AskFor("probe.example.", 1234, "\\\\# 3 616263");

        Assert.That(info.Answers.Count(), Is.EqualTo(1), "an unknown type is kept, not dropped");

        var record = info.Answers.First();

        using var wire = new MemoryStream();
        ((ADNSResourceRecord) record).Serialize(wire, UseCompression: false);

        Assert.Multiple(() => {
            Assert.That((UInt16) record.Type, Is.EqualTo((UInt16) 1234), "and keeps its type number");
            Assert.That(Convert.ToHexString(wire.ToArray()).Contains("616263"),
                        Is.True, "with its three octets untouched");
        });

    }

    #endregion

    #region The_Additional_Section_Is_Not_Discarded()

    [Test]
    public async Task The_Additional_Section_Is_Not_Discarded()
    {

        // A DNS answer has four sections and this reader carried two. The
        // additional section is where glue lives, so discarding it turns a
        // referral into a set of names with no addresses — and it was discarded
        // by a hardcoded empty list rather than by anything that could fail.
        var info = await Ask("""
            {"Status":0,"RA":true,
             "Answer":[{"name":"probe.example.","type":16,"TTL":60,"data":"\"a\""}],
             "Authority":[{"name":"probe.example.","type":2,"TTL":60,"data":"ns1.probe.example."}],
             "Additional":[{"name":"ns1.probe.example.","type":1,"TTL":60,"data":"192.0.2.1"}]}
            """);

        Assert.Multiple(() => {
            Assert.That(info.Answers.          Count(), Is.EqualTo(1), "answer");
            Assert.That(info.Authorities.      Count(), Is.EqualTo(1), "authority");
            Assert.That(info.AdditionalRecords.Count(), Is.EqualTo(1), "additional");
        });

    }

    #endregion

    #region The_Json_Reader_Reads_What_The_Zone_File_Reader_Reads()

    [Test]
    public async Task The_Json_Reader_Reads_What_The_Zone_File_Reader_Reads()
    {

        // The two formats carry the same RDATA text, so any type one of them can
        // read the other must read as well. A dispatch table of its own is how
        // they drift apart, and the forty entries in this one were already a
        // strict subset of what the zone-file reader knew.
        //
        // The comparison is of RDATA octets rather than of objects, so it does
        // not depend on either reader agreeing with itself about anything else.
        var cases = new (Int32 Type, String Mnemonic, String Data)[] {
            (   1, "A",      "192.0.2.1"),
            (  28, "AAAA",   "2001:db8::1"),
            (  15, "MX",     "10 mail.probe.example."),
            (  16, "TXT",    "\\\"hello\\\""),
            (  33, "SRV",    "10 5 5060 sip.probe.example."),
            (  52, "TLSA",   "3 1 1 00112233445566778899aabbccddeeff"),
            ( 257, "CAA",    "0 issue \\\"letsencrypt.org\\\""),
            (  99, "SPF",    "\\\"v=spf1 -all\\\""),
            (  29, "LOC",    "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m"),
            ( 256, "URI",    "10 1 \\\"https://probe.example/\\\"")
        };

        foreach (var (type, mnemonic, data) in cases)
        {

            var info = await AskFor("probe.example.", type, data);

            Assert.That(info.Answers.Count(), Is.EqualTo(1), $"{mnemonic} arrives over JSON");

            var fromJson  = RData((ADNSResourceRecord) info.Answers.First());
            var fromZone  = RData((ADNSResourceRecord) ADNSResourceRecord.ParseZoneFileString(
                                      $"probe.example. 60 IN {mnemonic} {data.Replace("\\\"", "\"")}"));

            Assert.That(fromJson, Is.EqualTo(fromZone), $"{mnemonic}: the same RDATA either way");

        }

    }

    #endregion


    #region (private static) RData(Record)

    private static Byte[] RData(ADNSResourceRecord Record)
    {

        using var wire = new MemoryStream();
        Record.Serialize(wire, UseCompression: false);

        var bytes   = wire.ToArray();
        var offset  = 0;

        while (offset < bytes.Length && bytes[offset] != 0)
        {

            if ((bytes[offset] & 0xC0) == 0xC0)
            {
                offset++;
                break;
            }

            offset += 1 + bytes[offset];

        }

        offset += 1 + 8;

        var length = (bytes[offset] << 8) | bytes[offset + 1];

        return bytes[(offset + 2)..(offset + 2 + length)];

    }

    #endregion

}

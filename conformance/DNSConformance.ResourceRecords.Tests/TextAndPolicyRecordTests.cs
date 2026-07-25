using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core;
using DNSConformance.Core.RawDns;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 1035 §3.3.14 (TXT), RFC 7208 (SPF), RFC 1035 §3.3.2 (HINFO),
/// RFC 8659 (CAA), RFC 7553 (URI).
/// </summary>
[TestFixture]
public class TextAndPolicyRecordTests
{

    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(300);


    #region TXT_Short_Text_Is_One_CharacterString()

    [Test]
    [Property("RFC", "1035 §3.3.14")]
    public void TXT_Short_Text_Is_One_CharacterString()
    {

        var record   = new TXT(DomainName.Parse("txt.example."), DNSQueryClasses.IN, Ttl, "hello world");
        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter().CharacterString("hello world").ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region TXT_Longer_Than_255_Bytes_Splits_Into_Multiple_CharacterStrings()

    [Test]
    [Property("RFC", "1035 §3.3.14")]
    public void TXT_Longer_Than_255_Bytes_Splits_Into_Multiple_CharacterStrings()
    {

        // "TXT-DATA: One or more <character-string>s." — 600 bytes require 3.
        var text     = new String('x', 600);
        var record   = new TXT(DomainName.Parse("big.example."), DNSQueryClasses.IN, Ttl, text);
        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter()
                           .CharacterString(new String('x', 255))
                           .CharacterString(new String('x', 255))
                           .CharacterString(new String('x', 90))
                           .ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region TXT_MultiString_Rdata_Is_Fully_Parsed()

    [Test]
    [Property("RFC", "1035 §3.3.14")]
    [Category(TestCategories.KnownIssue)]   // FINDINGS.md #2: only the first character-string is read
    public void TXT_MultiString_Rdata_Is_Fully_Parsed()
    {

        // A TXT whose RDATA holds three character-strings; RFC 7208 §3.3 for
        // the concatenation requirement: "concatenated together without adding
        // spaces". Records longer than 255 bytes (DKIM keys, SPF) depend on this.
        var rdata   = new RawDnsWriter()
                          .CharacterString("part-one|")
                          .CharacterString("part-two|")
                          .CharacterString("part-three")
                          .ToArray();

        var record  = new TXT(
                          DomainName.Parse("multi.example."),
                          RRWire.RdataStream(rdata)
                      );

        Assert.That(record.Text, Is.EqualTo("part-one|part-two|part-three"),
                    "all character-strings of the RDATA must be concatenated");

    }

    #endregion

    #region TXT_MultiString_Parsing_Leaves_Stream_At_Rdata_End()

    [Test]
    [Property("RFC", "1035 §4.1.3")]
    [Category(TestCategories.KnownIssue)]   // FINDINGS.md #2: under-read desynchronizes all subsequent records
    public void TXT_MultiString_Parsing_Leaves_Stream_At_Rdata_End()
    {

        // RDLENGTH delimits the RDATA. A parser overrunning (or underrunning)
        // it desynchronizes every subsequent record in the message.
        var rdata    = new RawDnsWriter()
                           .CharacterString("first")
                           .CharacterString("second")
                           .ToArray();

        var stream   = RRWire.RdataStream(rdata);
        _            = new TXT(DomainName.Parse("sync.example."), stream);

        Assert.That(stream.Position, Is.EqualTo(stream.Length),
                    "parser must consume exactly RDLENGTH bytes");

    }

    #endregion

    #region SPF_Uses_TXT_Shaped_Rdata()

    [Test]
    [Property("RFC", "7208 §3.1")]
    public void SPF_Uses_TXT_Shaped_Rdata()
    {

        var record   = new SPF(DomainName.Parse("spf.example."), DNSQueryClasses.IN, Ttl, "v=spf1 -all");
        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter().CharacterString("v=spf1 -all").ToArray();

        Assert.Multiple(() => {
            Assert.That(encoded.Type,  Is.EqualTo((UInt16) 99));
            Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));
        });

    }

    #endregion

    #region HINFO_Is_Two_CharacterStrings()

    [Test]
    [Property("RFC", "1035 §3.3.2")]
    public void HINFO_Is_Two_CharacterStrings()
    {

        var record   = new HINFO(DomainName.Parse("hinfo.example."), DNSQueryClasses.IN, Ttl, "VAX-11/780", "UNIX");
        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter().CharacterString("VAX-11/780").CharacterString("UNIX").ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region CAA_Flags_Tag_Value_Encoding()

    [Test]
    [Property("RFC", "8659 §4.1")]
    public void CAA_Flags_Tag_Value_Encoding()
    {

        // CAA RDATA: flags (1 octet) + tag-length + tag + value (rest, NO length).
        var record   = new CAA(DomainName.Parse("caa.example."), DNSQueryClasses.IN, Ttl, 128, "issue", "ca.example.net");
        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter()
                           .U8(128)                                  // critical bit set
                           .CharacterString("issue")                 // tag = length-prefixed
                           .Bytes(Encoding.ASCII.GetBytes("ca.example.net"))   // value = remaining octets, unprefixed
                           .ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

    #region CAA_Parses_RawDns_Crafted_Rdata()

    [Test]
    public void CAA_Parses_RawDns_Crafted_Rdata()
    {

        var rdata   = new RawDnsWriter()
                          .U8(0)
                          .CharacterString("issuewild")
                          .Bytes(Encoding.ASCII.GetBytes(";"))
                          .ToArray();

        var record  = new CAA(
                          DomainName.Parse("caa.example."),
                          RRWire.RdataStream(rdata)
                      );

        Assert.Multiple(() => {
            Assert.That(record.Flags, Is.Zero);
            Assert.That(record.Tag,   Is.EqualTo("issuewild"));
            Assert.That(record.Value, Is.EqualTo(";"));
        });

    }

    #endregion

    #region URI_Target_Is_Not_A_CharacterString()

    [Test]
    [Property("RFC", "7553 §4.5")]
    [Category(TestCategories.KnownIssue)]   // FINDINGS.md #3: target is emitted as dot-split DNS labels
    public void URI_Target_Is_The_Remaining_Rdata_Octets()
    {

        // RFC 7553: RDATA = Priority (2) + Weight (2) + Target (remaining
        // octets, WITHOUT a length prefix, NOT a domain name).
        var record   = new URI(
                           DNSServiceName.Parse("_ftp._tcp.example."),
                           DNSQueryClasses.IN,
                           Ttl,
                           10,
                           1,
                           URL.Parse("https://www.example.com/path")
                       );

        var encoded  = RRWire.Encode(record);

        var golden   = new RawDnsWriter()
                           .U16(10).U16(1)
                           .Bytes(Encoding.ASCII.GetBytes("https://www.example.com/path"))
                           .ToArray();

        Assert.That(encoded.Rdata, Is.EqualTo(golden), Bytes.Diff(golden, encoded.Rdata));

    }

    #endregion

}

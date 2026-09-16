using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

using DNSConformance.Core.RawDns;

namespace DNSConformance.WireFormat.Tests;

/// <summary>
/// RFC 1035 §3.3/§4.1.1/§4.1.4 and §2.3.4 — the helpers every message passes
/// through on its way in and out: reading a name off the wire, reading a
/// character-string, writing a name back, and finding where the last record of a
/// message begins.
///
/// This is the code that meets octets somebody else wrote, so the boundaries
/// here are the ones that decide what a truncated or hostile message does.
/// </summary>
[TestFixture]
[Property("RFC", "1035")]
public class WireHelperBoundaryTests
{

    #region (helper) NameAt(Message, Offset)

    /// <summary>
    /// Read a name out of a message at a given offset, counted by this suite
    /// rather than asked of Hermod: a length octet and that many octets per
    /// label, a zero octet for the root, and a pointer followed once.
    /// </summary>
    private static String NameAt(Byte[] Message, Int32 Offset)
    {

        var labels = new List<String>();
        var i      = Offset;
        var hops   = 0;

        while (i < Message.Length)
        {

            var length = Message[i];

            if (length == 0)
                break;

            if ((length & 0xC0) == 0xC0)
            {
                if (++hops > 16)
                    throw new InvalidDataException("pointer loop");
                i = ((length & 0x3F) << 8) | Message[i + 1];
                continue;
            }

            // An offset that is not the start of a name runs off the end sooner
            // or later. Say so rather than throwing, so the assertion can report
            // what it found at the offset it was promised.
            if (i + 1 + length > Message.Length)
                return $"<runs past the end of the message at octet {i}>";

            labels.Add(Encoding.ASCII.GetString(Message, i + 1, length));
            i += 1 + length;

        }

        return labels.Count == 0
                   ? "."
                   : String.Join('.', labels) + ".";

    }

    #endregion


    // ------------------------------------------- reading a name off the wire

    #region A_Label_Of_63_Octets_Is_Read()

    /// <summary>
    /// RFC 1035 §2.3.4 allows a label of 63 octets, and §4.1.4 is why the limit
    /// is where it is: the top two bits of a length octet are spoken for, so 63
    /// is the largest length that is a length at all. It has to be read, not
    /// refused.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §2.3.4")]
    public void A_Label_Of_63_Octets_Is_Read()
    {

        var label = new String('a', 63);
        var wire  = new RawDnsWriter().RawLabel(label).RawLabel("example").EndName().ToArray();

        var name  = DNSTools.ExtractName(new MemoryStream(wire));

        Assert.That(name, Is.EqualTo($"{label}.example"),
                    "63 is a legal label length and the reader has to take it");

    }

    #endregion

    #region A_Length_Byte_Above_63_Is_Refused()

    /// <summary>
    /// 64 is not a length. RFC 1035 §4.1.4 gives the two top bits of the octet
    /// to the compression pointer, so 01 and 10 are reserved combinations and a
    /// reader that took them as lengths would walk off into the RDATA.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1.4")]
    public void A_Length_Byte_Above_63_Is_Refused()
    {

        var wire = new RawDnsWriter().RawLabel(64, Encoding.ASCII.GetBytes(new String('a', 64))).EndName().ToArray();

        Assert.That(() => DNSTools.ExtractName(new MemoryStream(wire)),
                    Throws.InstanceOf<InvalidDataException>(),
                    "a length octet with 01 in its top bits is reserved, not a label");

    }

    #endregion

    #region A_Pointer_To_The_Octet_After_The_Message_Is_Refused()

    /// <summary>
    /// RFC 1035 §4.1.4: a pointer names "a prior occurrence of the same name",
    /// so it points at an octet the message actually has. The first offset it
    /// does not have is the message's own length, and that one is worth naming
    /// separately: it is off the end by exactly one, which is where a reader
    /// that checks with the wrong comparison lets a pointer through.
    ///
    /// It fails either way — there is nothing to read there — but the two
    /// failures are not the same failure. "Invalid compression pointer" says
    /// the message is malformed; an end-of-stream says the message was cut
    /// short. Finding 21 was about exactly that distinction being lost.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1.4")]
    public void A_Pointer_To_The_Octet_After_The_Message_Is_Refused()
    {

        // Two octets, and a pointer to offset 2 — one past the last one there is.
        var wire = new RawDnsWriter().Pointer(2).ToArray();

        Assert.That(wire, Has.Length.EqualTo(2),
                    "the pointer is the whole message, so its target is the end of it");

        Assert.That(() => DNSTools.ExtractName(new MemoryStream(wire)),
                    Throws.InstanceOf<InvalidDataException>(),
                    "a pointer to the end of the message points at no octet");

    }

    #endregion

    #region A_Pointer_To_The_Last_Octet_Of_The_Message_Is_Followed()

    /// <summary>
    /// And the offset one below it is a real offset. Here the last octet of the
    /// message is the root's zero, so following the pointer yields the root.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1.4")]
    public void A_Pointer_To_The_Last_Octet_Of_The_Message_Is_Followed()
    {

        // C0 02 00 — a pointer to offset 2, which holds the root's zero octet.
        var wire = new RawDnsWriter().Pointer(2).U8(0).ToArray();

        Assert.That(DNSTools.ExtractName(new MemoryStream(wire)), Is.EqualTo("."),
                    "the last octet of a message is still inside it");

    }

    #endregion

    #region A_Label_That_Is_Not_Valid_Utf8_Is_Refused()

    /// <summary>
    /// RFC 2181 §11 permits any binary string as a label, and Hermod holds a
    /// name as text — so the two meet here, and what matters is which way the
    /// mismatch is resolved. Refusing the name says the reader cannot represent
    /// it. Decoding it leniently would put U+FFFD where the octets were, and two
    /// labels that differ on the wire would become one name: the record would
    /// look valid and be a different record. Finding 54 was that shape.
    ///
    /// The refusal is the representation's limit rather than a rule of the DNS,
    /// and it is recorded among FINDINGS.md's interpretations rather than
    /// claimed as conformance.
    /// </summary>
    [Test]
    [Property("RFC", "2181 §11")]
    public void A_Label_That_Is_Not_Valid_Utf8_Is_Refused()
    {

        // 0xFF and 0xFE never occur in well-formed UTF-8.
        var wire = new RawDnsWriter().RawLabel(2, [0xFF, 0xFE]).EndName().ToArray();

        Assert.That(() => DNSTools.ExtractName(new MemoryStream(wire)),
                    Throws.InstanceOf<DecoderFallbackException>(),
                    "octets that are not UTF-8 are refused, not replaced");

    }

    #endregion


    // ----------------------------------------------------- character-strings

    #region An_Empty_Character_String_Is_Still_A_Character_String()

    /// <summary>
    /// RFC 1035 §3.3: "&lt;character-string&gt; is a single length octet followed
    /// by that number of characters." Zero is a number of characters. An empty
    /// character-string occupies one octet and carries the empty string, and a
    /// reader that treats its length octet as an end-of-stream loses it — TXT
    /// records that carry an empty string among their strings are ordinary.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §3.3")]
    public void An_Empty_Character_String_Is_Still_A_Character_String()
    {

        var rdata   = new RawDnsWriter().CharacterString("ab").CharacterString("").CharacterString("cd").ToArray();

        var strings = DNSTools.ExtractCharacterStrings(new MemoryStream(rdata), rdata.Length).ToArray();

        Assert.That(strings, Is.EqualTo(new[] { "ab", "", "cd" }),
                    "a length octet of zero is an empty string, not the end of the RDATA");

    }

    #endregion

    #region A_Character_String_Longer_Than_The_Rdata_Is_Refused()

    /// <summary>
    /// RFC 1035 §4.1.3: RDLENGTH says where the RDATA stops, and a
    /// character-string claiming more than is left would read into the record
    /// behind it. Finding 4 was that overrun on another type.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1.3")]
    public void A_Character_String_Longer_Than_The_Rdata_Is_Refused()
    {

        // Declares five octets, and only three follow.
        var rdata = new RawDnsWriter().U8(5).Bytes(Encoding.ASCII.GetBytes("abc")).ToArray();

        Assert.That(() => DNSTools.ExtractCharacterStrings(new MemoryStream(rdata), rdata.Length).ToArray(),
                    Throws.InstanceOf<InvalidDataException>(),
                    "a character-string may not reach past RDLENGTH");

    }

    #endregion

    #region Character_Strings_Run_Until_A_Zero_Length_Byte()

    /// <summary>
    /// The overload without an RDLENGTH stops at a zero length octet instead.
    /// Both halves matter: the strings before it are read whole, and the zero
    /// ends the list rather than being read as a string of its own.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §3.3")]
    public void Character_Strings_Run_Until_A_Zero_Length_Byte()
    {

        var wire    = new RawDnsWriter().CharacterString("abc").CharacterString("de").U8(0).ToArray();

        var strings = DNSTools.ExtractCharacterStrings(new MemoryStream(wire)).ToArray();

        Assert.That(strings, Is.EqualTo(new[] { "abc", "de" }),
                    "every string before the zero, and none after it");

    }

    #endregion


    // -------------------------------------------- writing a name back out

    #region The_Root_Written_As_Text_Is_One_Zero_Octet()

    /// <summary>
    /// RFC 1035 §3.1: the root is the null label and nothing else, so it is one
    /// zero octet. Two would be an empty label followed by the root — a
    /// different name, and a malformed one.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §3.1")]
    public void The_Root_Written_As_Text_Is_One_Zero_Octet()
    {

        var fromDot   = new MemoryStream();
        var fromEmpty = new MemoryStream();

        ".".Serialize(fromDot,   0, false, []);
        "" .Serialize(fromEmpty, 0, false, []);

        Assert.Multiple(() => {

            Assert.That(fromDot.  ToArray(), Is.EqualTo(new Byte[] { 0 }),
                        "the root written as \".\"");

            Assert.That(fromEmpty.ToArray(), Is.EqualTo(new Byte[] { 0 }),
                        "and the root written as nothing at all");

        });

    }

    #endregion

    #region A_Label_Of_63_Characters_Is_Written_And_64_Is_Refused()

    [Test]
    [Property("RFC", "1035 §2.3.4")]
    public void A_Label_Of_63_Characters_Is_Written_And_64_Is_Refused()
    {

        var stream = new MemoryStream();

        $"{new String('a', 63)}.example.".Serialize(stream, 0, false, []);

        Assert.That(stream.ToArray()[0], Is.EqualTo(63),
                    "63 octets is a label, and its length octet says so");

        Assert.That(() => $"{new String('a', 64)}.example.".Serialize(new MemoryStream(), 0, false, []),
                    Throws.ArgumentException,
                    "64 is not");

    }

    #endregion

    #region A_Compression_Entry_Points_At_The_Name_It_Names()

    /// <summary>
    /// RFC 1035 §4.1.4: a pointer is "a prior occurrence of the same name". The
    /// table a serializer keeps is a promise about where each name it has
    /// written begins, and the promise is checkable without knowing anything
    /// about how it was built — read the message at the offset and the name has
    /// to be there.
    ///
    /// Every suffix of a name is itself a name, so each one earns an entry, and
    /// each entry has to be measured from where that suffix actually starts.
    /// Finding 9 was this table never matching; this is the other way it can be
    /// wrong, which is matching and pointing at the wrong octet.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §4.1.4")]
    public void A_Compression_Entry_Points_At_The_Name_It_Names()
    {

        var stream  = new MemoryStream();
        var offsets = new Dictionary<String, Int32>();

        "www.example.com.".Serialize(stream, 0, true, offsets);

        var message = stream.ToArray();

        Assert.That(offsets, Is.Not.Empty, "a name written out is a name that can be pointed at");

        Assert.Multiple(() => {

            Assert.That(offsets.Keys, Has.No.Member(String.Empty),
                        "the empty string is not a name, and the root is one octet — shorter than a pointer to it");

            foreach (var (name, offset) in offsets)
                Assert.That(NameAt(message, offset).TrimEnd('.'),
                            Is.EqualTo(name.TrimEnd('.')),
                            $"the table says '{name}' begins at octet {offset}");

        });

    }

    #endregion

    #region An_Soa_Leaves_A_Compression_Table_That_Points_Where_It_Says()

    /// <summary>
    /// The same promise, made by the record that writes a name through the text
    /// serializer rather than through <c>DomainName</c>: an SOA's RNAME is the
    /// responsible mailbox turned into a name, and it goes out by a different
    /// path than its MNAME two fields earlier.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §3.3.13")]
    public void An_Soa_Leaves_A_Compression_Table_That_Points_Where_It_Says()
    {

        var record  = new SOA(
                          DomainName.Parse("example.com."),
                          DNSQueryClasses.IN,
                          TimeSpan.FromHours(1),
                          DomainName.Parse("ns1.example.com."),
                          SimpleEMailAddress.Parse("hostmaster@example.com"),
                          2026091601,
                          TimeSpan.FromHours(2),
                          TimeSpan.FromHours(1),
                          TimeSpan.FromDays(14),
                          TimeSpan.FromMinutes(5)
                      );

        var stream  = new MemoryStream();
        var offsets = new Dictionary<String, Int32>();

        record.Serialize(stream, UseCompression: true, CompressionOffsets: offsets);

        var message = stream.ToArray();

        Assert.Multiple(() => {

            foreach (var (name, offset) in offsets)
                Assert.That(NameAt(message, offset).TrimEnd('.'),
                            Is.EqualTo(name.TrimEnd('.')),
                            $"the table says '{name}' begins at octet {offset}");

        });

    }

    #endregion


    // ----------------------------------------------- the mailbox of an RNAME

    #region The_First_Dot_Of_An_Rname_Is_The_At_Sign()

    /// <summary>
    /// RFC 1035 §3.3.13 makes the RNAME "a &lt;domain-name&gt; which specifies
    /// the mailbox of the person responsible", and the mapping is the one §8
    /// describes: the local part is the first label and the dot after it stands
    /// where the at-sign was. The first dot, wherever it is — a name whose first
    /// label is empty has an empty local part, and that is still where the
    /// at-sign goes.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §3.3.13")]
    public void The_First_Dot_Of_An_Rname_Is_The_At_Sign()
    {

        Assert.Multiple(() => {

            Assert.That(DNSTools.ReplaceFirstDotWithAt("hostmaster.example.com"),
                        Is.EqualTo("hostmaster@example.com"));

            Assert.That(DNSTools.ReplaceFirstDotWithAt("hostmaster"),
                        Is.EqualTo("hostmaster"),
                        "a name with no dot has no separator to find");

            Assert.That(DNSTools.ReplaceFirstDotWithAt(".example.com"),
                        Is.EqualTo("@example.com"),
                        "the first dot is the separator even at the front");

        });

    }

    #endregion


    #region The_Last_Ascii_Character_Is_Written_And_The_First_Above_It_Is_Not()

    /// <summary>
    /// NAPTR's flags, services and regexp (RFC 3403 §4.1) and SPF's strings go
    /// out through this writer, and it holds them to ASCII. ASCII is 0 to 127
    /// inclusive, so 127 is inside and 128 is the first one outside — a writer
    /// that refuses 127 would refuse a character-string the RFC allows, and one
    /// that accepts 128 would truncate a code point to a single octet and put a
    /// character on the wire that nobody wrote.
    /// </summary>
    [Test]
    [Property("RFC", "1035 §3.3")]
    public void The_Last_Ascii_Character_Is_Written_And_The_First_Above_It_Is_Not()
    {

        var stream = new MemoryStream();

        stream.WriteASCIIMax255("ab");

        Assert.Multiple(() => {

            Assert.That(stream.ToArray(), Is.EqualTo(new Byte[] { 3, (Byte) 'a', 0x7F, (Byte) 'b' }),
                        "127 is an ASCII code point and goes out as one octet");

            Assert.That(() => new MemoryStream().WriteASCIIMax255("ab"),
                        Throws.InstanceOf<InvalidOperationException>(),
                        "128 is not ASCII and must not be squeezed into one octet");

        });

    }

    #endregion


    // ------------------------------------------- where the last record starts

    #region A_Header_Only_Message_Carries_No_Signature()

    /// <summary>
    /// RFC 1035 §4.1.1: the header is twelve octets, and a message of exactly
    /// twelve is a whole message with no sections. RFC 8945 §5.1 puts a TSIG
    /// last in the additional section, so a message with no records has no TSIG
    /// — and one whose header claims a record it does not carry has none
    /// either. Neither is a signed message, and neither is an exception: this
    /// runs on whatever a peer sent.
    /// </summary>
    [Test]
    [Property("RFC", "8945 §5.1")]
    public void A_Header_Only_Message_Carries_No_Signature()
    {

        var empty     = new RawDnsWriter().Header(0x1234, 0x8000, 0, 0, 0, 0).ToArray();
        var lying     = new RawDnsWriter().Header(0x1234, 0x8000, 0, 0, 0, 1).ToArray();

        Assert.Multiple(() => {

            Assert.That(empty, Has.Length.EqualTo(12), "the header is twelve octets");
            Assert.That(lying, Has.Length.EqualTo(12));

            Assert.That(TSIGSigner.TryStripTSIG(empty, out _, out _), Is.False,
                        "a message with no records carries no TSIG");

            Assert.That(TSIGSigner.TryStripTSIG(lying, out _, out _), Is.False,
                        "and neither does one whose ARCOUNT is a claim it cannot keep");

        });

    }

    #endregion

}

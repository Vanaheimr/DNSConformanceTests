using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.Fixtures;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// The zone-file presentation format as a boundary: what Hermod can read of what
/// another implementation wrote, and what it writes back out.
/// </summary>
/// <remarks>
/// <para>
/// This is the half of <c>ParseZoneFileString</c> / <c>ToZoneFileString</c> that
/// no other test reaches. The suite deliberately brings its own readers so it
/// never measures Hermod with Hermod — <c>SignedZoneFixture</c> parses the signed
/// fixtures itself and hands <c>InMemoryDNSZone</c> finished records — and the
/// shadow of that independence is that Hermod's own reader and writer are never
/// exercised. Findings 43 and 44 both lived in exactly that shadow.
/// </para>
/// <para>
/// Two kinds of evidence here. The round trip catches a reader and a writer that
/// disagree with each other, which is cheap and weak: a field written wrongly and
/// read back wrongly round-trips perfectly, which is what finding 43 did for
/// years. The comparison against BIND's own text is the strong one, and it needs
/// somebody else's output to compare against — which the signed fixtures are.
/// </para>
/// </remarks>
[TestFixture]
public class ZoneFilePresentationTests
{

    #region Data

    /// <summary>
    /// One record of every type Hermod can both write and read, in the form a
    /// zone file would hold it.
    /// </summary>
    /// <remarks>
    /// KEY (RFC 2535) and SIG (RFC 2931) are deliberately absent, and their
    /// absence is itself a gap rather than a decision: both have a
    /// <c>ZoneFileRData</c> and neither has an entry in the zone-file type
    /// dispatch, so Hermod writes a line for them that it cannot read back. They
    /// belong in this list the moment that is fixed, and putting them in before
    /// that would only restate what is already recorded.
    /// </remarks>
    private static readonly String[] OneOfEachType = [
        "a.example.com. 3600 IN A 192.0.2.1",
        "a.example.com. 3600 IN AAAA 2001:db8::1",
        "a.example.com. 3600 IN NS ns1.example.com.",
        "a.example.com. 3600 IN CNAME target.example.com.",
        "a.example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 2026072501 7200 3600 1209600 3600",
        "a.example.com. 3600 IN PTR host.example.com.",
        "a.example.com. 3600 IN HINFO \"Intel\" \"Linux\"",
        "a.example.com. 3600 IN MX 10 mail.example.com.",
        "a.example.com. 3600 IN TXT \"hello world\"",
        "a.example.com. 3600 IN RP hostmaster.example.com. txt.example.com.",
        "a.example.com. 3600 IN AFSDB 1 afs.example.com.",
        "a.example.com. 3600 IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
        "a.example.com. 3600 IN NAPTR 100 10 \"u\" \"E2U+sip\" \"!^.*$!sip:x@y!\" .",
        "a.example.com. 3600 IN CERT 1 12345 8 AQID",
        "a.example.com. 3600 IN DNAME target.example.com.",
        "a.example.com. 3600 IN DS 12345 8 2 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "a.example.com. 3600 IN SSHFP 1 1 1469679466a193364f3928b7f3b6a15180244ec1",
        "a.example.com. 3600 IN RRSIG A 8 3 3600 20261014083329 20260914083329 1234 example.com. AQID",
        "a.example.com. 3600 IN NSEC next.example.com. A NS SOA MX TXT AAAA RRSIG NSEC DNSKEY",
        "a.example.com. 3600 IN DNSKEY 257 3 8 AQID",
        "a.example.com. 3600 IN NSEC3 1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG",
        "a.example.com. 3600 IN NSEC3PARAM 1 0 12 aabbccdd",
        "a.example.com. 3600 IN TLSA 3 1 1 00112233445566778899aabbccddeeff",
        "a.example.com. 3600 IN SMIMEA 3 1 1 00112233445566778899aabbccddeeff",
        "a.example.com. 3600 IN CDS 12345 8 2 00112233445566778899aabbccddeeff",
        "a.example.com. 3600 IN CDNSKEY 257 3 8 AQID",
        "a.example.com. 3600 IN OPENPGPKEY AQID",
        "a.example.com. 3600 IN CSYNC 2026051801 3 A NS AAAA",
        "a.example.com. 3600 IN ZONEMD 2026051801 1 1 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "a.example.com. 3600 IN SVCB 1 svc.example.com. alpn=\"h2,h3\" port=\"443\"",
        "a.example.com. 3600 IN HTTPS 1 . alpn=\"h2,h3\"",
        "a.example.com. 3600 IN SPF \"v=spf1 -all\"",
        "a.example.com. 3600 IN EUI48 00-11-22-33-44-55",
        "a.example.com. 3600 IN EUI64 00-11-22-33-44-55-66-77",
        "a.example.com. 3600 IN CAA 0 issue \"letsencrypt.org\"",
        "_sip._tcp.example.com. 3600 IN SRV 10 5 5060 sip.example.com.",
        "_svc._tcp.example.com. 3600 IN URI 10 1 \"https://example.com/\""
    ];

    /// <summary>
    /// Where Hermod's rendering of a record is known to differ from BIND's, with
    /// the reason. Asserted as an exact set, so a divergence that disappears
    /// fails this test too and has to be removed deliberately.
    /// </summary>
    /// <remarks>
    /// AAAA: <c>IPv6Address.ToString()</c> writes the fully expanded form. RFC
    /// 3596 §2.4 defines AAAA presentation by reference to the IPv6 text
    /// representation, which permits it; RFC 5952 §4 later named one canonical
    /// output form, which suppresses leading zeroes and uses "::". Hermod's choice
    /// is pinned by its own <c>IPv6AddressTests</c> and reaches far past DNS, so
    /// the suite records it rather than overturning it — see FINDINGS.md
    /// § Interpretations.
    /// </remarks>
    private static readonly Dictionary<String, String> KnownRenderingDivergences = new() {
        ["AAAA"] = "IPv6 in the fully expanded form rather than RFC 5952 §4's canonical one"
    };

    #endregion

    #region Every_Line_The_Reference_Signer_Wrote_Is_Readable()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void Every_Line_The_Reference_Signer_Wrote_Is_Readable()
    {

        // The plainest question the presentation format can be asked: can Hermod
        // read what dnssec-signzone wrote? Every line of it, not a sample —
        // finding 44 was 49 lines out of 345, all of them at or naming a
        // wildcard, and a sample could easily have missed the one zone that has
        // any.
        var failures = new List<String>();

        foreach (var (file, line) in ReferenceSignerLines())
        {
            try
            {
                ADNSResourceRecord.ParseZoneFileString(line);
            }
            catch (Exception e)
            {
                failures.Add($"{Path.GetFileName(file)}: {Shorten(line)}{Environment.NewLine}      {e.Message}");
            }
        }

        Assert.That(failures, Is.Empty,
                    $"{failures.Count} line(s) BIND wrote that Hermod cannot read:{Environment.NewLine}" +
                    String.Join(Environment.NewLine, failures.Take(8)));

    }

    #endregion

    #region Hermod_Renders_A_Record_The_Way_The_Reference_Signer_Did()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void Hermod_Renders_A_Record_The_Way_The_Reference_Signer_Did()
    {

        // The strong direction, and the one that would have caught finding 43 on
        // the day it was written: a field spelled wrongly in both the reader and
        // the writer survives a round trip untouched and shows up only against
        // somebody else's text.
        //
        // Whitespace is normalised away because RFC 4034 §2.2 lets Base64 carry
        // it and BIND breaks long keys across lines; the comparison is
        // case-insensitive because the hex and Base32hex fields are.
        var divergent = new Dictionary<String, String>();

        foreach (var (_, line) in ReferenceSignerLines())
        {

            var tokens = Split(line);

            if (tokens.Length < 5)
                continue;

            IDNSResourceRecord parsed;
            try   { parsed = ADNSResourceRecord.ParseZoneFileString(line); }
            catch { continue; }   // the readability test above owns that failure

            var type    = tokens[3];
            var theirs  = String.Concat(tokens[4..]);
            var mine    = String.Concat(Split(((ADNSResourceRecord) parsed).ToZoneFileString())[4..]);

            if (!String.Equals(theirs, mine, StringComparison.OrdinalIgnoreCase) && !divergent.ContainsKey(type))
                divergent[type] = $"BIND:   {Shorten(theirs)}{Environment.NewLine}      Hermod: {Shorten(mine)}";

        }

        Assert.That(divergent.Keys.Order(),
                    Is.EqualTo(KnownRenderingDivergences.Keys.Order()),
                    "the set of types Hermod renders differently from BIND has changed:" + Environment.NewLine +
                    String.Join(Environment.NewLine, divergent.Select(d => $"  {d.Key}{Environment.NewLine}      {d.Value}")));

    }

    #endregion

    #region Every_Record_Type_Survives_A_Presentation_Round_Trip()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void Every_Record_Type_Survives_A_Presentation_Round_Trip()
    {

        // Weak evidence on its own — a symmetric error round-trips perfectly —
        // but it is the only check that covers every type rather than the eleven
        // a signed zone happens to contain, and it catches a reader and a writer
        // that drift apart.
        var broken = new List<String>();

        foreach (var line in OneOfEachType)
        {

            var type = Split(line)[3];

            try
            {

                var first     = (ADNSResourceRecord) ADNSResourceRecord.ParseZoneFileString(line);
                var rendered  = first.ToZoneFileString();
                var second    = (ADNSResourceRecord) ADNSResourceRecord.ParseZoneFileString(rendered);

                if (!RData(first).SequenceEqual(RData(second)))
                    broken.Add($"{type}: {Shorten(line)}{Environment.NewLine}      became {Shorten(rendered.Trim())}");

            }
            catch (Exception e)
            {
                broken.Add($"{type}: {Shorten(line)}{Environment.NewLine}      {e.Message}");
            }

        }

        Assert.That(broken, Is.Empty,
                    "types that do not survive a presentation round trip:" + Environment.NewLine +
                    String.Join(Environment.NewLine, broken));

    }

    #endregion

    #region A_Wildcard_Owner_Name_Is_Read()

    [Test]
    [Property("RFC", "4592 §2.1.1, 2181 §11")]
    public void A_Wildcard_Owner_Name_Is_Read()
    {

        // RFC 2181 §11 is the sentence this rests on: any binary string whatever
        // can be the label of a resource record, and hostname syntax restricts
        // hostnames, not DNS names. RFC 4592 §2.1.1 then makes the asterisk an
        // ordinary label that happens to acquire a meaning in the leftmost
        // position.
        //
        // Not a corner case: the suite's own dname.dnssec.test fixture carries a
        // wildcard, and finding 44 was that all 49 of its lines were unreadable.
        foreach (var line in new[] {
            "*.example.com. 3600 IN A 192.0.2.1",
            "*.wild.example.com. 3600 IN AAAA 2001:db8::1",
            "*.example.com. 3600 IN TXT \"caught by the wildcard\"",
            "*.example.com. 3600 IN MX 10 mail.example.com."
        })
        {
            var record = ADNSResourceRecord.ParseZoneFileString(line);
            Assert.That(record.DomainName.FullName.TrimEnd('.'),
                        Is.EqualTo(Split(line)[0].TrimEnd('.')).IgnoreCase,
                        $"the owner name survives: {line}");
        }

    }

    #endregion

    #region An_Underscore_Owner_Name_Is_Read()

    [Test]
    [Property("RFC", "8552 §1, 2181 §11")]
    public void An_Underscore_Owner_Name_Is_Read()
    {

        // Underscore-prefixed names are how RFC 8552 scopes an attribute to a
        // domain, and between DMARC, DKIM, TLSA and the SRV family they are most
        // of what an operator actually puts into a zone file.
        //
        // These used to divide by record type rather than by name, which is the
        // tell: SRV and URI parsed because they take a DNSServiceName, and every
        // other type was refused for a name it shares with them.
        foreach (var line in new[] {
            "_dmarc.example.com. 3600 IN TXT \"v=DMARC1; p=none\"",
            "sel._domainkey.example.com. 3600 IN TXT \"v=DKIM1; k=rsa\"",
            "_443._tcp.example.com. 3600 IN TLSA 3 1 1 00112233445566778899aabbccddeeff",
            "_sip._tcp.example.com. 3600 IN SRV 10 5 5060 sip.example.com."
        })
        {
            var record = ADNSResourceRecord.ParseZoneFileString(line);
            Assert.That(record.DomainName.FullName.TrimEnd('.'),
                        Is.EqualTo(Split(line)[0].TrimEnd('.')).IgnoreCase,
                        $"the owner name survives: {line}");
        }

    }

    #endregion

    #region A_Refused_Owner_Name_Is_Reported_As_One()

    [Test]
    [Property("RFC", "2181 §11")]
    public void A_Refused_Owner_Name_Is_Reported_As_One()
    {

        // Not a conformance rule — a diagnostic one, and the reason finding 44
        // took a sweep to see rather than a glance. A name the parser will not
        // take leaves no DomainName, which skips the whole type dispatch, and the
        // line used to come back as bad RDATA for RDATA that was perfect.
        //
        // RFC 4592 §2.1.1 gives the asterisk its meaning in the leftmost position
        // only, and DomainName refuses it anywhere else by a documented choice,
        // so this is a name that is still rejected after the fix — which makes it
        // the case where the message has to be right.
        var thrown = Assert.Throws<ArgumentException>(
                         () => ADNSResourceRecord.ParseZoneFileString("a.*.example.com. 3600 IN A 192.0.2.1")
                     );

        Assert.Multiple(() => {

            Assert.That(thrown!.Message, Does.Contain("owner name"),
                        "the message names the half of the line that is actually wrong");

            Assert.That(thrown.Message, Does.Not.Contain("RDATA"),
                        "and does not blame 192.0.2.1, which is a perfectly good A record");

        });

    }

    #endregion

    #region Names_In_The_RDATA_Carry_The_Same_Labels()

    [Test]
    [Property("RFC", "2181 §11, 4592 §2.1.1")]
    public void Names_In_The_RDATA_Carry_The_Same_Labels()
    {

        // The same rule one field to the right. A name in the RDATA is not a
        // hostname either, and NSEC proves it: the Next Domain Name walks the
        // zone in canonical order, so it names whatever comes next — including
        // the wildcard, which is precisely what BIND wrote in the fixture that
        // started this.
        var refused = new List<String>();

        foreach (var line in new[] {
            "a.example.com. 3600 IN NSEC  *.wild.example.com. A RRSIG NSEC",
            "a.example.com. 3600 IN CNAME _dmarc.example.com.",
            "a.example.com. 3600 IN NS    _ns.example.com.",
            "a.example.com. 3600 IN MX    10 *.example.com.",
            "a.example.com. 3600 IN DNAME *.target.example.com.",
            "a.example.com. 3600 IN RP    hostmaster.example.com. _txt.example.com.",
            "a.example.com. 3600 IN AFSDB 1 *.afs.example.com.",
            "_x._tcp.example.com. 3600 IN SRV 10 5 5060 *.example.com."
        })
            try   { ADNSResourceRecord.ParseZoneFileString(line); }
            catch { refused.Add(line); }

        Assert.That(refused, Is.Empty,
                    "RDATA names refused for carrying a label a hostname may not have:" + Environment.NewLine +
                    String.Join(Environment.NewLine, refused));

    }

    #endregion


    #region (private static) helpers

    /// <summary>
    /// Every resource record line of every zone the reference signer produced.
    /// </summary>
    private static IEnumerable<(String File, String Line)> ReferenceSignerLines()
    {

        var directory = SignedZoneFixture.SignedZoneDirectory;

        if (directory is null || !Directory.Exists(directory))
            Assert.Ignore("fixtures/zones/signed is not present — run fixtures/zones/resign.sh.");

        var any = false;

        foreach (var file in Directory.GetFiles(directory!, "*.zone.flat"))
            foreach (var raw in File.ReadAllLines(file))
            {

                var line = raw.Trim();

                if (line.Length == 0 || line.StartsWith(';') || line.StartsWith('$') || Split(line).Length < 4)
                    continue;

                any = true;
                yield return (file, line);

            }

        Assert.That(any, Is.True, "the signed fixtures hold resource record lines to read");

    }

    private static String[] Split(String Line)
        => Line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);

    private static String Shorten(String Text)
        => Text.Length <= 110 ? Text : Text[..110] + "…";

    /// <summary>
    /// The RDATA of a record, taken from its own wire serialization so that the
    /// comparison does not go back through the presentation format it is testing.
    /// </summary>
    private static Byte[] RData(ADNSResourceRecord Record)
    {

        using var stream = new MemoryStream();
        Record.Serialize(stream, UseCompression: false);

        var bytes   = stream.ToArray();
        var offset  = 0;

        while (offset < bytes.Length && bytes[offset] != 0)
        {

            if ((bytes[offset] & 0xC0) == 0xC0)
            {
                offset += 1;
                break;
            }

            offset += 1 + bytes[offset];

        }

        offset += 1;    // the root label, or the second octet of a pointer
        offset += 8;    // type, class, TTL

        var length = (bytes[offset] << 8) | bytes[offset + 1];
        offset += 2;

        return bytes[offset..(offset + length)];

    }

    #endregion

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// Edges: the shortest RDATA a record can have, the least a JSON `data` field
/// can say, and the order two identifiers sort in.
///
/// Fourth entry from the mutation sweep (<see href="../../MUTATION.md"/>), and a
/// different shape from the three before it. A rejection path is a line that
/// says no; a boundary is a comparison that decides where yes turns into no, and
/// it can be moved one step in either direction without anything looking wrong.
/// The suite exercised the middle of every one of these ranges and never an end.
///
/// The truncation guards are the ones that matter most. RFC 3597 §2 requires a
/// reader to carry a record it does not understand, and finding 21 was what
/// happens when it cannot: an unknown type cost every record behind it. The
/// same applies to a record of a known type that arrives shorter than its own
/// fixed fields — reading it as zeros keeps the stream where the next record
/// begins, and a guard shifted one step either throws or reads past the end.
/// </summary>
[TestFixture]
[Property("RFC", "3597 §2, 4025 §2, 4701 §3.1, 8914 §2")]
public class RecordBoundaryTests
{

    #region Data

    private static readonly DomainName Name = DomainName.Parse("probe.example.");

    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(3600);

    private static IDNSResourceRecord Read(String Line)
    {
        Assert.That(ADNSResourceRecord.TryParseZoneFileString(Line, out var record, out var error),
                    Is.True,
                    $"the reader refused '{Line}': {error}");
        return record!;
    }

    #endregion


    #region The shortest RDATA a record can have (RFC 3597 §2)

    [Test]
    [Property("RFC", "4025 §2")]
    [Property("RFC", "3597 §2")]
    // RFC 4025 §2 gives IPSECKEY three fixed octets — precedence, gateway type,
    // algorithm — before anything that varies. A record carrying fewer than
    // three has been truncated, and §3597 §2 still requires the reader to get
    // past it: throwing here costs every record behind this one, which is
    // finding 21 exactly.
    [TestCase(@"\# 0",       0, 0, 0, TestName = "no octets at all")]
    [TestCase(@"\# 1 0a",   10, 0, 0, TestName = "precedence only")]
    [TestCase(@"\# 2 0a01", 10, 1, 0, TestName = "precedence and gateway type")]
    public void An_Ipseckey_Shorter_Than_Its_Fixed_Fields_Reads_As_Zeros(String  Generic,
                                                                         Int32   Precedence,
                                                                         Int32   GatewayType,
                                                                         Int32   Algorithm)
    {

        var record = Read($"probe.example. 3600 IN IPSECKEY {Generic}") as IPSECKEY;

        Assert.That(record, Is.Not.Null, "a truncated record is still a record");

        Assert.Multiple(() => {
            Assert.That(record!.Precedence,  Is.EqualTo((Byte) Precedence));
            Assert.That(record!.GatewayType, Is.EqualTo((Byte) GatewayType));
            Assert.That(record!.Algorithm,   Is.EqualTo((Byte) Algorithm));
        });

    }

    [Test]
    [Property("RFC", "4025 §2")]
    public void The_Third_Octet_Is_Where_An_Ipseckey_Becomes_Whole()
    {

        // The other side of the same three comparisons: with all three octets
        // present every field has to come from the record rather than from the
        // fallback. A guard shifted one step reads the third octet as a zero and
        // nothing else changes.
        var record = Read(@"probe.example. 3600 IN IPSECKEY \# 3 0a0102") as IPSECKEY;

        Assert.Multiple(() => {
            Assert.That(record!.Precedence,  Is.EqualTo((Byte) 10));
            Assert.That(record!.GatewayType, Is.EqualTo((Byte)  1));
            Assert.That(record!.Algorithm,   Is.EqualTo((Byte)  2));
        });

    }

    [Test]
    [Property("RFC", "4701 §3.1")]
    public void A_Dhcid_Of_Exactly_Its_Header_Has_An_Empty_Digest()
    {

        // RFC 4701 §3.1: two octets of identifier type and one of digest type,
        // then the digest. A record of exactly three octets is a header with no
        // digest — unusual, but well-formed, and the fields have to come out of
        // it. One step tighter and they all stay unset while the record still
        // looks like it parsed.
        var record = Read(@"probe.example. 3600 IN DHCID \# 3 000201") as DHCID;

        Assert.Multiple(() => {
            Assert.That(record!.IdentifierType, Is.EqualTo((UInt16) 2));
            Assert.That(record!.DigestType,     Is.EqualTo((Byte)   1));
            Assert.That(record!.Digest,         Is.Empty);
        });

    }

    [Test]
    [Property("RFC", "4701 §3.1")]
    public void A_Dhcid_Shorter_Than_Its_Header_Reads_As_Nothing()
    {

        var record = Read(@"probe.example. 3600 IN DHCID \# 2 0002") as DHCID;

        Assert.Multiple(() => {
            Assert.That(record,                 Is.Not.Null, "and it is still a record");
            Assert.That(record!.IdentifierType, Is.Null, "two octets are not a header, and the field says so rather than guessing a zero");
        });

    }

    [Test]
    [Property("RFC", "8914 §2")]
    public void An_Extended_Error_Of_Exactly_Two_Octets_Has_No_Extra_Text()
    {

        // RFC 8914 §2: "INFO-CODE" is 16 bits and "EXTRA-TEXT" is "a variable
        // length, UTF-8 encoded, text field" that may be empty. Two octets is
        // the whole option, and the text that is not there must read as absent
        // rather than as an empty string — one step either way turns a legal
        // option into an exception or an absence into a presence.
        var option = EDNSExtendedDNSError.Parse([0x00, 0x0C]);

        Assert.Multiple(() => {
            Assert.That(option.InfoCode,  Is.EqualTo((ExtendedDNSErrorCode) 12));
            Assert.That(option.ExtraText, Is.Null, "§2's EXTRA-TEXT is absent, not empty");
        });

    }

    [Test]
    [Property("RFC", "8914 §2")]
    public void An_Extended_Error_Shorter_Than_Its_Info_Code_Is_Refused()
    {

        Assert.Multiple(() => {
            Assert.That(() => EDNSExtendedDNSError.Parse([0x00]), Throws.TypeOf<ArgumentException>());
            Assert.That(() => EDNSExtendedDNSError.Parse([]),     Throws.TypeOf<ArgumentException>());
        });

    }

    [Test]
    [Property("RFC", "8914 §2")]
    public void One_Octet_Past_The_Info_Code_Is_Already_Extra_Text()
    {

        var option = EDNSExtendedDNSError.Parse([0x00, 0x0C, (Byte) 'x']);

        Assert.That(option.ExtraText, Is.EqualTo("x"));

    }

    #endregion

    #region The least a JSON data field can say

    [Test]
    // The JSON APIs hand over a `data` field as one string, and each of these
    // types needs a minimum number of words in it before there is a record at
    // all. One word fewer is not a record; one word more is the optional part
    // beginning, and a comparison shifted one step loses exactly that part
    // without failing. This is the path finding 48 lived in.
    public void A_Json_Data_Field_Below_Its_Minimum_Is_Not_A_Record()
    {

        Assert.Multiple(() => {

            Assert.That(SVCB. TryParseFromJSON(Name, Ttl, "1"),        Is.Null, "SVCB needs a priority and a target");
            Assert.That(HTTPS.TryParseFromJSON(Name, Ttl, "1"),        Is.Null, "and so does HTTPS");
            Assert.That(NSEC. TryParseFromJSON(Name, Ttl, ""),         Is.Null, "NSEC needs the next name");
            Assert.That(LOC.  TryParseFromJSON(Name, Ttl, "52 22 23"), Is.Null, "LOC needs at least four words");

        });

    }

    [Test]
    public void A_Json_Data_Field_At_Its_Minimum_Is_A_Record()
    {

        // The other side, which the test above cannot see: a comparison shifted
        // one step starts refusing the shortest legal form, and every assertion
        // that only feeds it too little would still pass.
        Assert.Multiple(() => {

            Assert.That(SVCB. TryParseFromJSON(Name, Ttl, "1 ."),                       Is.Not.Null, "priority and target are enough");
            Assert.That(HTTPS.TryParseFromJSON(Name, Ttl, "1 ."),                       Is.Not.Null);
            Assert.That(NSEC. TryParseFromJSON(Name, Ttl, "next.example."),              Is.Not.Null, "a next name with no types is a legal NSEC");
            Assert.That(LOC.  TryParseFromJSON(Name, Ttl, "52 22 23.000 N"),             Is.Not.Null);

        });

    }

    [Test]
    public void The_Optional_Part_Of_A_Json_Data_Field_Is_Read_When_It_Is_There()
    {

        // And the upper comparison: the part after the minimum is optional, so a
        // record without it parses — but a record *with* it must not lose it.
        var withParams = SVCB.TryParseFromJSON(Name, Ttl, "1 . alpn=h2");
        var without    = SVCB.TryParseFromJSON(Name, Ttl, "1 .");

        Assert.Multiple(() => {
            Assert.That(without?.   SVCParameters.Count(), Is.Zero,         "no parameters, and that is legal");
            Assert.That(withParams?.SVCParameters.Count(), Is.EqualTo(1),   "one parameter, and it must survive");
        });

    }

    #endregion

    #region Two identifiers and the order they sort in

    [Test]
    [Property("RFC", "2782")]
    public void The_Four_Comparison_Operators_Of_An_Srv_Spec_Agree_With_One_Another()
    {

        // Four operators over one CompareTo, and each of them can be shifted by
        // one without the others noticing. The equal case is what separates
        // them: `<` and `>` must be false for it while `<=` and `>=` are true.
        var http  = SRV_Spec.Parse("http",  "tcp");
        var https = SRV_Spec.Parse("https", "tcp");
        var same  = SRV_Spec.Parse("http",  "tcp");

        Assert.Multiple(() => {

            Assert.That(http <  https, Is.True);
            Assert.That(http <= https, Is.True);
            Assert.That(http >  https, Is.False);
            Assert.That(http >= https, Is.False);

            Assert.That(same <  http,  Is.False, "equal is not less");
            Assert.That(same <= http,  Is.True,  "equal is less-or-equal");
            Assert.That(same >  http,  Is.False, "equal is not greater");
            Assert.That(same >= http,  Is.True,  "equal is greater-or-equal");

        });

    }

    [Test]
    [Property("RFC", "2782")]
    public void The_Four_Comparison_Operators_Of_An_Srv_Endpoint_Agree_With_One_Another()
    {

        // RFC 2782 selects by priority and then by weight, so the order two
        // endpoints sort in is the order they are tried in — and the equal case
        // is a live one, because the RFC recommends equal weights when there is
        // no selection to make.
        var first  = new DNSSRVEndpoint("a.example.", 10, 0, IPPort.Parse(443), Ttl);
        var second = new DNSSRVEndpoint("b.example.", 20, 0, IPPort.Parse(443), Ttl);
        var same   = new DNSSRVEndpoint("a.example.", 10, 0, IPPort.Parse(443), Ttl);

        Assert.Multiple(() => {

            Assert.That(first <  second, Is.True);
            Assert.That(first <= second, Is.True);
            Assert.That(first >  second, Is.False);
            Assert.That(first >= second, Is.False);

            Assert.That(same <  first,   Is.False, "equal is not less");
            Assert.That(same <= first,   Is.True);
            Assert.That(same >  first,   Is.False, "equal is not greater");
            Assert.That(same >= first,   Is.True);

        });

    }

    #endregion

    #region Two endpoints that are the same one (RFC 4343, RFC 2782)

    [Test]
    public void An_Endpoint_Is_Equal_To_Itself_And_To_Its_Twin()
    {

        // Reflexivity is not a nicety: Object.Equals documents that x.Equals(x)
        // returns true, and every container in the framework relies on it.
        // GetHashCode is built from all seven fields, so two endpoints that
        // agree on all seven land in the same bucket — and must then agree that
        // they are the same one, or Contains and Distinct are quietly wrong.
        var endpoint = new DNSSRVEndpoint("a.example.", 10, 5, IPPort.Parse(443), Ttl);
        var twin     = new DNSSRVEndpoint("a.example.", 10, 5, IPPort.Parse(443), Ttl);

        Assert.Multiple(() => {

            Assert.That(endpoint.Equals(endpoint),          Is.True, "an endpoint is itself");
            Assert.That(endpoint.Equals(twin),              Is.True, "and so is one with the same fields");
            Assert.That(endpoint.GetHashCode(),             Is.EqualTo(twin.GetHashCode()));
            Assert.That(endpoint.CompareTo(twin),           Is.Zero, "and the comparison agrees with the equality");

            Assert.That(new[] { endpoint, twin }.Distinct().Count(), Is.EqualTo(1),
                        "which is what makes Distinct mean anything");

        });

    }

    [Test]
    public void Endpoints_That_Differ_Are_Not_The_Same_One()
    {

        var baseline = new DNSSRVEndpoint("a.example.", 10, 5, IPPort.Parse(443), Ttl);

        Assert.Multiple(() => {
            Assert.That(baseline.Equals(new DNSSRVEndpoint("b.example.", 10, 5, IPPort.Parse(443), Ttl)), Is.False, "a different target");
            Assert.That(baseline.Equals(new DNSSRVEndpoint("a.example.", 20, 5, IPPort.Parse(443), Ttl)), Is.False, "a different priority");
            Assert.That(baseline.Equals(new DNSSRVEndpoint("a.example.", 10, 7, IPPort.Parse(443), Ttl)), Is.False, "a different weight");
            Assert.That(baseline.Equals(new DNSSRVEndpoint("a.example.", 10, 5, IPPort.Parse(444), Ttl)), Is.False, "a different port");
            Assert.That(baseline.Equals(null),                                                            Is.False, "and nothing at all");
        });

    }

    [Test]
    [Property("RFC", "4343")]
    public void A_Target_Differing_Only_In_Case_Is_The_Same_Target()
    {

        // RFC 4343 makes domain names case-insensitive, and the target of an SRV
        // record is one. Comparing it as octets would make A.EXAMPLE. and
        // a.example. two endpoints, which is two connections to one host.
        var lower = new DNSSRVEndpoint("a.example.", 10, 5, IPPort.Parse(443), Ttl);
        var upper = new DNSSRVEndpoint("A.EXAMPLE.", 10, 5, IPPort.Parse(443), Ttl);

        Assert.Multiple(() => {
            Assert.That(lower.Equals(upper),      Is.True);
            Assert.That(lower.CompareTo(upper),   Is.Zero);
            Assert.That(lower.GetHashCode(),      Is.EqualTo(upper.GetHashCode()),
                        "and the hash has to fold the same way, or the two disagree in the other direction");
        });

    }

    [Test]
    [Property("RFC", "2782")]
    public void Sorting_Puts_Them_In_The_Order_Rfc_2782_Walks()
    {

        // "A client MUST attempt to contact the target host with the
        //  lowest-numbered priority it can reach" — so the natural order of two
        //  endpoints is priority first, and weight after it. A comparison that
        //  returns zero for everything leaves the list exactly as it was and
        //  looks like it sorted.
        var endpoints = new[] {
                            new DNSSRVEndpoint("c.example.", 20,  0, IPPort.Parse(443), Ttl),
                            new DNSSRVEndpoint("a.example.", 10, 50, IPPort.Parse(443), Ttl),
                            new DNSSRVEndpoint("b.example.", 10,  5, IPPort.Parse(443), Ttl)
                        };

        var sorted = endpoints.Order().ToArray();

        Assert.Multiple(() => {
            Assert.That(sorted[0].Target, Is.EqualTo("b.example."), "priority 10, weight 5");
            Assert.That(sorted[1].Target, Is.EqualTo("a.example."), "priority 10, weight 50");
            Assert.That(sorted[2].Target, Is.EqualTo("c.example."), "priority 20");
        });

    }

    #endregion

}

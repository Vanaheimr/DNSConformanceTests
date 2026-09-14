using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// RFC 1035 §5.1 — the master file format, as opposed to the single line of it
/// that <c>ParseZoneFileString</c> reads.
/// </summary>
/// <remarks>
/// <para>
/// The distinction is the whole point. A line carries no origin, so a name in it
/// that does not end in a dot cannot be resolved; §5.1 says such a name is
/// relative to the current origin, and the current origin is a property of the
/// file. Reading lines one at a time and calling the result a zone is how a
/// relative name becomes an absolute one without anyone noticing — finding 45.
/// </para>
/// <para>
/// The evidence that matters here is the reference zone file: the same
/// <c>fixtures/bind/interop.test.zone</c> that BIND, Knot, CoreDNS and Unbound
/// are all handed in the interop tests. Four foreign servers agree on what it
/// means, which makes it a fact about the format rather than about any one
/// reader.
/// </para>
/// </remarks>
[TestFixture]
public class MasterFileFormatTests
{

    #region Data

    private static readonly DomainName Origin = DomainName.Parse("example.com.");

    private static IDNSResourceRecord One(String Text, String? Origin = null)
        => DNSZoneFile.Parse(Text, DomainName.Parse(Origin ?? "example.com.")).Single();

    private static String Owner(IDNSResourceRecord Record)
        => Record.DomainName.FullName.TrimEnd('.');

    #endregion

    #region A_Relative_Owner_Name_Is_Qualified_Against_The_Origin()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Relative_Owner_Name_Is_Qualified_Against_The_Origin()
    {

        // "Domain names that end in a dot are called absolute, and are taken as
        // complete. Domain names which do not end in a dot are called relative"
        // — and a relative name that is treated as complete is not refused, it is
        // answered wrongly. `ns1` became the top-level name `ns1.`
        Assert.Multiple(() => {

            Assert.That(Owner(One("ns1     IN  A  192.0.2.53")),  Is.EqualTo("ns1.example.com").IgnoreCase);
            Assert.That(Owner(One("sub.dom IN  A  192.0.2.7")),   Is.EqualTo("sub.dom.example.com").IgnoreCase);
            Assert.That(Owner(One("_dns._udp IN SRV 10 60 5353 ns1.example.com.")),
                                                                  Is.EqualTo("_dns._udp.example.com").IgnoreCase);

        });

    }

    #endregion

    #region An_Absolute_Owner_Name_Is_Left_Alone()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void An_Absolute_Owner_Name_Is_Left_Alone()
    {

        // The other half of the same sentence, and the one that keeps the fix
        // from being "append the origin to everything".
        Assert.That(Owner(One("host.elsewhere.test. IN A 192.0.2.9")),
                    Is.EqualTo("host.elsewhere.test").IgnoreCase);

    }

    #endregion

    #region The_At_Sign_Names_The_Origin()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void The_At_Sign_Names_The_Origin()
    {

        // "@" — "A free standing @ is used to denote the current origin."
        Assert.That(Owner(One("@  IN  NS  ns1.example.com.")),
                    Is.EqualTo("example.com").IgnoreCase);

    }

    #endregion

    #region An_Omitted_Owner_Repeats_The_Previous_One()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void An_Omitted_Owner_Repeats_The_Previous_One()
    {

        // "if a line begins with a blank, then the owner is assumed to be the
        // same as that of the previous RR" — which is how an RRset of three is
        // usually written.
        var records = DNSZoneFile.Parse(
                          "multi  IN  A  192.0.2.10\n" +
                          "       IN  A  192.0.2.11\n" +
                          "       IN  A  192.0.2.12\n",
                          Origin
                      );

        Assert.Multiple(() => {

            Assert.That(records, Has.Count.EqualTo(3));

            Assert.That(records.Select(Owner).Distinct().Single(),
                        Is.EqualTo("multi.example.com").IgnoreCase);

            Assert.That(records.Cast<A>().Select(a => a.IPv4Address.ToString()).Order(),
                        Is.EqualTo(new[] { "192.0.2.10", "192.0.2.11", "192.0.2.12" }));

        });

    }

    #endregion

    #region Dollar_Origin_Changes_What_A_Relative_Name_Means()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void Dollar_Origin_Changes_What_A_Relative_Name_Means()
    {

        var records = DNSZoneFile.Parse(
                          "a  IN  A  192.0.2.1\n" +
                          "$ORIGIN sub.example.com.\n" +
                          "b  IN  A  192.0.2.2\n",
                          Origin
                      );

        Assert.Multiple(() => {
            Assert.That(Owner(records[0]), Is.EqualTo("a.example.com").IgnoreCase);
            Assert.That(Owner(records[1]), Is.EqualTo("b.sub.example.com").IgnoreCase);
        });

    }

    #endregion

    #region Dollar_Ttl_Supplies_An_Omitted_Ttl()

    [Test]
    [Property("RFC", "2308 §4")]
    public void Dollar_Ttl_Supplies_An_Omitted_Ttl()
    {

        // $TTL is RFC 2308 §4 rather than RFC 1035, which is why a file without
        // one is still legal and why the directive has to be optional.
        var records = DNSZoneFile.Parse(
                          "$TTL 7200\n" +
                          "a  IN     A  192.0.2.1\n" +
                          "b  300 IN A  192.0.2.2\n" +
                          "c  IN     A  192.0.2.3\n",
                          Origin
                      );

        Assert.Multiple(() => {
            Assert.That(records[0].TimeToLive, Is.EqualTo(TimeSpan.FromSeconds(7200)), "from $TTL");
            Assert.That(records[1].TimeToLive, Is.EqualTo(TimeSpan.FromSeconds(300)),  "its own");
            Assert.That(records[2].TimeToLive, Is.EqualTo(TimeSpan.FromSeconds(7200)), "back to $TTL, not to 300");
        });

    }

    #endregion

    #region Parentheses_Make_One_Record_Of_Several_Lines()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void Parentheses_Make_One_Record_Of_Several_Lines()
    {

        // "Parentheses are used to group data that crosses a line boundary" —
        // which every SOA in the world is written with.
        var soa = (SOA) One(
                      "@  IN  SOA ns1.example.com. hostmaster.example.com. (\n" +
                      "        2026072501 ; serial\n" +
                      "        7200       ; refresh\n" +
                      "        3600       ; retry\n" +
                      "        1209600    ; expire\n" +
                      "        3600 )     ; minimum\n"
                  );

        Assert.Multiple(() => {
            Assert.That(Owner(soa),     Is.EqualTo("example.com").IgnoreCase);
            Assert.That(soa.Serial,     Is.EqualTo(2026072501u));
            Assert.That(soa.Refresh,    Is.EqualTo(TimeSpan.FromSeconds(7200)));
            Assert.That(soa.Retry,      Is.EqualTo(TimeSpan.FromSeconds(3600)));
            Assert.That(soa.Expire,     Is.EqualTo(TimeSpan.FromSeconds(1209600)));
        });

    }

    #endregion

    #region Comments_And_Blank_Lines_Are_Not_Data()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void Comments_And_Blank_Lines_Are_Not_Data()
    {

        var records = DNSZoneFile.Parse(
                          "; a whole line of comment\n" +
                          "\n" +
                          "a  IN  A  192.0.2.1   ; and a trailing one\n" +
                          "   \n" +
                          "b  IN  TXT \"a ; inside quotes is data\"\n",
                          Origin
                      );

        Assert.Multiple(() => {
            Assert.That(records,                     Has.Count.EqualTo(2));
            Assert.That(((TXT) records[1]).Text,     Is.EqualTo("a ; inside quotes is data"));
        });

    }

    #endregion

    #region A_Relative_Name_In_The_RDATA_Is_Qualified_Too()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Relative_Name_In_The_RDATA_Is_Qualified_Too()
    {

        // §5.1 puts no limit on where a relative name may appear, and the RDATA
        // is where most of them are: "MX 10 mail1" is the ordinary way to write
        // it. Getting the owner right and the target wrong would leave the zone
        // just as broken, and more quietly.
        Assert.Multiple(() => {

            Assert.That(((MX)    One("mx    IN MX    10 mail1")).Exchange.FullName.TrimEnd('.'),
                        Is.EqualTo("mail1.example.com").IgnoreCase);

            Assert.That(((CNAME) One("alias IN CNAME a")).CName.FullName.TrimEnd('.'),
                        Is.EqualTo("a.example.com").IgnoreCase);

            Assert.That(((NS)    One("@     IN NS    ns1")).NameServer.FullName.TrimEnd('.'),
                        Is.EqualTo("ns1.example.com").IgnoreCase);

            Assert.That(((SRV)   One("_s._tcp IN SRV 10 5 5060 target")).Target.FullName.TrimEnd('.'),
                        Is.EqualTo("target.example.com").IgnoreCase);

            // The SOA carries two of them, and the second takes a detour: RFC
            // 1035 §3.3.13's RNAME is a domain name that Hermod keeps as a
            // mailbox, so it has to meet the origin before the first dot turns
            // into an "@".
            var soa = (SOA) One("@ IN SOA ns1 hostmaster 1 2 3 4 5");

            Assert.That(soa.Server.FullName.TrimEnd('.'), Is.EqualTo("ns1.example.com").IgnoreCase);
            Assert.That(soa.EMail.ToString(),             Is.EqualTo("hostmaster@example.com").IgnoreCase);

        });

    }

    #endregion

    #region An_Absolute_Name_In_The_RDATA_Is_Left_Alone()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void An_Absolute_Name_In_The_RDATA_Is_Left_Alone()
    {

        Assert.That(((MX) One("mx IN MX 10 mail.elsewhere.test.")).Exchange.FullName.TrimEnd('.'),
                    Is.EqualTo("mail.elsewhere.test").IgnoreCase);

    }

    #endregion

    #region Dollar_Include_Is_Refused_By_Name()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void Dollar_Include_Is_Refused_By_Name()
    {

        // $INCLUDE needs a file system, which a reader given a string does not
        // have. Refusing it is fine; refusing it silently is not, because the
        // records it would have brought would simply be missing from the zone.
        var thrown = Assert.Throws<ArgumentException>(
                         () => DNSZoneFile.Parse("$INCLUDE sub.zone\na IN A 192.0.2.1\n", Origin)
                     );

        Assert.That(thrown!.Message, Does.Contain("$INCLUDE"));

    }

    #endregion

    #region A_Relative_Name_With_No_Origin_At_All_Is_Refused()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Relative_Name_With_No_Origin_At_All_Is_Refused()
    {

        // The only honest answer when there is nothing to complete a name
        // against, and the direct replacement for what finding 45 was: taking it
        // as complete put every record at the top level and reported success.
        //
        // The trap this closes is in the zone API rather than in a file: a zone
        // takes its origin from its SOA, and the SOA comes out of the file being
        // loaded, so "use the zone's origin" is empty exactly when the first
        // record is read.
        var thrown = Assert.Throws<ArgumentException>(
                         () => DNSZoneFile.Parse("ns1  IN  A  192.0.2.53\n")
                     );

        Assert.Multiple(() => {
            Assert.That(thrown!.Message, Does.Contain("relative"));
            Assert.That(thrown.Message,  Does.Contain("$ORIGIN"));
        });

    }

    #endregion

    #region A_Fully_Absolute_File_Needs_No_Origin()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void A_Fully_Absolute_File_Needs_No_Origin()
    {

        // The other side of that refusal, and the reason it is not simply
        // "always demand an origin": the flattened form every signer emits names
        // everything absolutely, and it has to keep loading.
        var records = DNSZoneFile.Parse(
                          "ns1.example.com. 3600 IN A 192.0.2.53\n" +
                          "a.example.com.   3600 IN A 192.0.2.1\n"
                      );

        Assert.That(records.Select(Owner),
                    Is.EqualTo(new[] { "ns1.example.com", "a.example.com" }).IgnoreCase);

    }

    #endregion

    #region The_Reference_Zone_File_Loads_Into_A_Zone()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void The_Reference_Zone_File_Loads_Into_A_Zone()
    {

        // End to end, because loading a zone is the whole point of reading a zone
        // file, and because the origin has to come from outside the file: the
        // zone learns its own origin from the SOA, which is inside it.
        var zone = new InMemoryDNSZone().
                       AddZoneFile(File.ReadAllText(ReferenceZoneFile()),
                                   DomainName.Parse("interop.test."));

        Assert.That(zone.Origin?.FullName.TrimEnd('.'),
                    Is.EqualTo("interop.test").IgnoreCase,
                    "a zone with an SOA knows its own origin — and the SOA was written as @");

    }

    #endregion

    #region The_Reference_Zone_File_Loads_Whole()

    [Test]
    [Property("RFC", "1035 §5.1")]
    public void The_Reference_Zone_File_Loads_Whole()
    {

        // fixtures/bind/interop.test.zone, the file BIND, Knot, CoreDNS and
        // Unbound are each handed in the interop tests. Four foreign servers
        // agree on what it means, so this is a fact about the format.
        var records = DNSZoneFile.Parse(
                          File.ReadAllText(ReferenceZoneFile()),
                          DomainName.Parse("interop.test.")
                      );

        var outside = records.Where(r => !Owner(r).EndsWith("interop.test", StringComparison.OrdinalIgnoreCase)).
                              Select(Owner).
                              ToArray();

        Assert.Multiple(() => {

            // The catch-all, and the one that pins the finding: every owner name
            // in this file is relative, so if relative names are taken as
            // complete then every single one lands outside the zone.
            Assert.That(outside, Is.Empty,
                        "every owner name in this file belongs to interop.test — these did not: " +
                        String.Join(", ", outside));

            Assert.That(records.OfType<SOA>().Single().Serial, Is.EqualTo(2026072501u));

            Assert.That(records.OfType<A>().Single(a => Owner(a).Equals("a.interop.test", StringComparison.OrdinalIgnoreCase)).IPv4Address,
                        Is.EqualTo(IPv4Address.Parse("192.0.2.1")));

            Assert.That(records.OfType<A>().Count(a => Owner(a).Equals("multi.interop.test", StringComparison.OrdinalIgnoreCase)),
                        Is.EqualTo(3), "an RRset of three, each line naming its owner again");

            Assert.That(records.OfType<MX>().OrderBy(mx => mx.Preference).Select(mx => mx.Exchange.FullName.TrimEnd('.').ToLowerInvariant()),
                        Is.EqualTo(new[] { "mail1.interop.test", "mail2.interop.test" }));

            Assert.That(records.OfType<SRV>().Single().Target.FullName.TrimEnd('.'),
                        Is.EqualTo("ns1.interop.test").IgnoreCase);

            // The second character-string of the "big" TXT is the one finding 2
            // was about, and it has to survive the file layer as well.
            Assert.That(records.OfType<TXT>().Any(t => t.Text.Contains("and a second character-string")),
                        Is.True);

        });

    }

    #endregion


    #region (private static) ReferenceZoneFile()

    private static String ReferenceZoneFile()
    {

        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {

            var candidate = Path.Combine(directory.FullName, "fixtures", "bind", "interop.test.zone");

            if (File.Exists(candidate))
                return candidate;

            directory = directory.Parent;

        }

        Assert.Ignore("fixtures/bind/interop.test.zone is not present.");
        return "";

    }

    #endregion

}

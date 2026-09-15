using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace DNSConformance.ResourceRecords.Tests;

/// <summary>
/// Fields whose width the RFC states as a number, tested at that number and on
/// both sides of it.
///
/// Seventh entry from the mutation sweep. An address is the clearest case there
/// is — RFC 1035 §3.4.1 says thirty-two bits and RFC 3596 §2.2 says a hundred
/// and twenty-eight — and both guards could be inverted without a test noticing,
/// because every test had handed them exactly the right number of octets. A
/// guard that has only ever seen the right answer is indistinguishable from one
/// that accepts anything.
/// </summary>
[TestFixture]
[Property("RFC", "1035 §3.4.1, 3596 §2.2, 7871 §6, 7873 §5.2")]
public class FixedWidthRdataTests
{

    #region Data

    private static readonly DomainName Name = DomainName.Parse("probe.example.");
    private static readonly TimeSpan   Ttl  = TimeSpan.FromSeconds(300);

    #endregion


    #region An address is as wide as its type says (RFC 1035 §3.4.1, RFC 3596 §2.2)

    [Test]
    [Property("RFC", "1035 §3.4.1")]
    public void An_A_Record_Is_Four_Octets_And_Nothing_Else()
    {

        // RFC 1035 §3.4.1: "ADDRESS — A 32 bit Internet address." Four octets is
        // the only length there is, so three and five are both malformed — and a
        // guard that accepts them hands IPv4Address whatever arrived.
        Assert.That(A.Parse(Name, DNSQueryClasses.IN, Ttl, [192, 0, 2, 1]).IPv4Address.ToString(),
                    Is.EqualTo("192.0.2.1"));

        Assert.Multiple(() => {
            Assert.That(() => A.Parse(Name, DNSQueryClasses.IN, Ttl, [192, 0, 2]),
                        Throws.TypeOf<InvalidDataException>(), "three octets");
            Assert.That(() => A.Parse(Name, DNSQueryClasses.IN, Ttl, [192, 0, 2, 1, 5]),
                        Throws.TypeOf<InvalidDataException>(), "five octets");
            Assert.That(() => A.Parse(Name, DNSQueryClasses.IN, Ttl, []),
                        Throws.TypeOf<InvalidDataException>(), "none at all");
        });

    }

    [Test]
    [Property("RFC", "3596 §2.2")]
    public void An_Aaaa_Record_Is_Sixteen_Octets_And_Nothing_Else()
    {

        // RFC 3596 §2.2: "A 128 bit IPv6 address is encoded in the data portion
        // of an AAAA resource record, in network byte order."
        var sixteen = new Byte[16];
        sixteen[0]  = 0x20; sixteen[1] = 0x01; sixteen[2] = 0x0D; sixteen[3] = 0xB8; sixteen[15] = 1;

        // IPv6Address renders every group; the RFC 5952 §4 short form is the zone
        // file writer's business and has tests of its own.
        Assert.That(AAAA.Parse(Name, DNSQueryClasses.IN, Ttl, sixteen).IPv6Address.ToString(),
                    Is.EqualTo("2001:0db8:0000:0000:0000:0000:0000:0001"));

        Assert.Multiple(() => {
            Assert.That(() => AAAA.Parse(Name, DNSQueryClasses.IN, Ttl, new Byte[15]),
                        Throws.TypeOf<InvalidDataException>(), "fifteen octets");
            Assert.That(() => AAAA.Parse(Name, DNSQueryClasses.IN, Ttl, new Byte[17]),
                        Throws.TypeOf<InvalidDataException>(), "seventeen octets");
            Assert.That(() => AAAA.Parse(Name, DNSQueryClasses.IN, Ttl, [0x20, 0x01]),
                        Throws.TypeOf<InvalidDataException>(), "the first two");
        });

    }

    [Test]
    [Property("RFC", "1035 §3.4.1")]
    [Property("RFC", "3596 §2.2")]
    public async Task An_Address_Read_From_A_Stream_Is_Counted_The_Same_Way()
    {

        // The second reader of each, which takes the octets from a stream rather
        // than an array — and a stream that ends early is exactly how a truncated
        // message arrives. It is a separate guard, so it is a separate place for
        // the count to be wrong.
        Assert.That((await A.Parse(Name, DNSQueryClasses.IN, Ttl, new MemoryStream([192, 0, 2, 1]))).
                        IPv4Address.ToString(),
                    Is.EqualTo("192.0.2.1"));

        Assert.That(async () => await A.Parse(Name, DNSQueryClasses.IN, Ttl, new MemoryStream([192, 0, 2])),
                    Throws.TypeOf<InvalidDataException>());

        Assert.That(async () => await AAAA.Parse(Name, DNSQueryClasses.IN, Ttl, new MemoryStream(new Byte[15])),
                    Throws.TypeOf<InvalidDataException>());

    }

    #endregion


    #region An option whose width its own field decides (RFC 7871 §6, RFC 7873 §5.2)

    [Test]
    [Property("RFC", "7871 §6")]
    [Property("RFC", "7871 §7.1.1")]
    public void A_Client_Subnet_Address_Belongs_To_The_Family_The_Option_Names()
    {

        // RFC 7871 §6 gives the option a FAMILY field and §7.1.1 the two values
        // that matter: 1 for IPv4 and 2 for IPv6. The family decides how wide
        // the address is, and reading a four-octet prefix as the start of a
        // sixteen-octet one puts the client in a different internet.
        var v4 = EDNSClientSubnetOption.Parse([0x00, 0x01, 24, 0, 192, 0, 2]);
        var v6 = EDNSClientSubnetOption.Parse([0x00, 0x02, 32, 0, 0x20, 0x01, 0x0D, 0xB8]);

        Assert.Multiple(() => {
            Assert.That(v4.Address.AddressFamily, Is.EqualTo(AddressFamily.InterNetwork));
            Assert.That(v4.Address.ToString(),    Is.EqualTo("192.0.2.0"), "the bits below the prefix are zero");
            Assert.That(v6.Address.AddressFamily, Is.EqualTo(AddressFamily.InterNetworkV6));
            Assert.That(v6.Address.ToString(),    Does.StartWith("2001:db8"));
        });

    }

    [Test]
    [Property("RFC", "7873 §5.2")]
    public void A_Server_Cookie_Is_Eight_To_Thirty_Two_Octets()
    {

        // RFC 7873 §5.2: "The Server Cookie ... variable length, from 8 to 32
        // bytes." Both ends, and both of them refused — a bound that only fires
        // on one side lets the other through, and a two-octet server cookie is
        // a cookie an attacker can guess.
        Assert.Multiple(() => {

            Assert.That(() => new EDNSCookieOption(new Byte[8], new Byte[8]),  Throws.Nothing, "the shortest legal one");
            Assert.That(() => new EDNSCookieOption(new Byte[8], new Byte[32]), Throws.Nothing, "the longest legal one");

            Assert.That(() => new EDNSCookieOption(new Byte[8], new Byte[7]),
                        Throws.TypeOf<ArgumentException>(), "one octet short");
            Assert.That(() => new EDNSCookieOption(new Byte[8], new Byte[33]),
                        Throws.TypeOf<ArgumentException>(), "one octet long");
            Assert.That(() => new EDNSCookieOption(new Byte[8], []),
                        Throws.TypeOf<ArgumentException>(), "none at all");

        });

    }

    [Test]
    [Property("RFC", "7873 §5.2")]
    public void A_Client_Cookie_Is_Exactly_Eight_Octets()
    {

        // "Client Cookie: 8 bytes" — a fixed width, with no range around it.
        Assert.Multiple(() => {
            Assert.That(() => new EDNSCookieOption(new Byte[8]),  Throws.Nothing);
            Assert.That(() => new EDNSCookieOption(new Byte[7]),  Throws.TypeOf<ArgumentException>());
            Assert.That(() => new EDNSCookieOption(new Byte[9]),  Throws.TypeOf<ArgumentException>());
        });

    }

    #endregion

}

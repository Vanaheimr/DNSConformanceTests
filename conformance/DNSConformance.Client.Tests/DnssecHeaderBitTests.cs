using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 4035 §3.2 — the two header bits DNSSEC added, as the client sees them.
/// </summary>
/// <remarks>
/// <para>
/// Authentic Data (0x0020) and Checking Disabled (0x0010) live in the same octet
/// as RA and the RCODE. AD is how a validating resolver tells a stub that it
/// checked the answer, and RFC 6840 §5.7 makes that worth something exactly when
/// the channel to the resolver is secure — which is the case Hermod builds for,
/// with DoT and DoH clients of its own. CD is how a resolver that validates for
/// itself tells its upstream not to bother.
/// </para>
/// <para>
/// Neither bit existed anywhere in the stack before finding 47: not in
/// <c>DNSPacket</c>, not in <c>DNSInfo</c>, and in none of the three places that
/// read or write the flag octet. The suite had modelled both in its own reader
/// since the beginning and never once asserted them, which is why 951 tests
/// passed over the gap.
/// </para>
/// <para>
/// The peer here is scripted, so the response carries exactly the bits under
/// test and nothing else depends on a server choosing to set them.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "4035 §3.2")]
public class DnssecHeaderBitTests
{

    #region Data

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// An answer to whatever was asked, carrying the given flags on top of
    /// QR and RA, with the transaction ID the request came in with.
    /// </summary>
    private static Byte[] AnswerWith(Byte[] Request, UInt16 ExtraFlags)

        => new RawDnsWriter().
               Header(
                   (UInt16) ((Request[0] << 8) | Request[1]),
                   (UInt16) (RawDnsFlags.QR | RawDnsFlags.RD | RawDnsFlags.RA | ExtraFlags),
                   1, 1, 0, 0
               ).
               Question("bits.example.", RawDnsType.A).
               RR("bits.example.", RawDnsType.A, RawDnsClass.IN, 60, RawDnsWriter.IPv4("192.0.2.1")).
               ToArray();

    private static DNSClient ClientFor(ScriptedUdpServer Server)

        => new (IPv4Address.Localhost,
                IPPort.Parse((UInt16) Server.Port),
                QueryTimeout:   ShortTimeout,
                UseQueryCache:  false);

    private static async Task<DNSInfo> AskWith(UInt16 ExtraFlags)
    {

        await using var peer    = new ScriptedUdpServer(request => AnswerWith(request, ExtraFlags));
        using       var client  = ClientFor(peer);

        return await client.Query(DNSServiceName.Parse("bits.example."),
                                  [ DNSResourceRecordTypes.A ],
                                  ShortTimeout);

    }

    #endregion

    #region The_Client_Sees_The_Authentic_Data_Bit()

    [Test]
    public async Task The_Client_Sees_The_Authentic_Data_Bit()
    {

        // RFC 4035 §3.2.3: a security-aware resolver sets AD on an answer it has
        // validated. A stub that cannot read it cannot be a validating stub at
        // all — the verdict arrives and is thrown away in the header reader.
        var withAD     = await AskWith(RawDnsFlags.AD);
        var withoutAD  = await AskWith(0);

        Assert.Multiple(() => {
            Assert.That(withAD.   AuthenticData, Is.True,  "AD set by the resolver");
            Assert.That(withoutAD.AuthenticData, Is.False, "and not invented when it is clear");
            Assert.That(withAD.   Answers,       Is.Not.Empty, "the answer still arrives");
        });

    }

    #endregion

    #region The_Client_Sees_The_Checking_Disabled_Bit()

    [Test]
    public async Task The_Client_Sees_The_Checking_Disabled_Bit()
    {

        var withCD     = await AskWith(RawDnsFlags.CD);
        var withoutCD  = await AskWith(0);

        Assert.Multiple(() => {
            Assert.That(withCD.   CheckingDisabled, Is.True);
            Assert.That(withoutCD.CheckingDisabled, Is.False);
        });

    }

    #endregion

    #region The_Two_Bits_Are_Told_Apart()

    [Test]
    public async Task The_Two_Bits_Are_Told_Apart()
    {

        // They are adjacent, one bit apart, and a mask that is off by one reads
        // each as the other. Asserting them together is what catches that.
        var onlyAD  = await AskWith(RawDnsFlags.AD);
        var onlyCD  = await AskWith(RawDnsFlags.CD);

        Assert.Multiple(() => {
            Assert.That(onlyAD.AuthenticData,     Is.True);
            Assert.That(onlyAD.CheckingDisabled,  Is.False);
            Assert.That(onlyCD.AuthenticData,     Is.False);
            Assert.That(onlyCD.CheckingDisabled,  Is.True);
        });

    }

    #endregion

    #region A_Typed_Query_Keeps_Them_Too()

    [Test]
    public async Task A_Typed_Query_Keeps_Them_Too()
    {

        // Query<T> does not return what the transport parsed — it wraps it in a
        // DNSInfo<T> that copies the fields across one by one, and a field the
        // copy forgets is gone with no error. That is a second place to lose the
        // two bits, and the four tests above cannot see it because they take the
        // untyped Query.
        await using var peer    = new ScriptedUdpServer(request => AnswerWith(request, RawDnsFlags.AD));
        using       var client  = ClientFor(peer);

        var typed = await client.Query<A>(DomainName.Parse("bits.example."), ShortTimeout);

        Assert.Multiple(() => {
            Assert.That(typed.AuthenticData,   Is.True, "the wrapper keeps AD");
            Assert.That(typed.FilteredAnswers, Is.Not.Empty);
        });

    }

    #endregion

    #region A_Json_Answer_Carries_The_Same_Two_Bits()

    [Test]
    public async Task A_Json_Answer_Carries_The_Same_Two_Bits()
    {

        // The JSON API of Google and Cloudflare has no header, so AD and CD
        // arrive as named fields or not at all — and a client that reads the
        // header bits but not these would report a validated answer as
        // unvalidated depending only on which transport it happened to use.
        await using var peer = new ScriptedDoHServer(_ => null) {
                                   JSONResponse = """
                                       {"Status":0,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,
                                        "Question":[{"name":"bits.example.","type":1}],
                                        "Answer":[{"name":"bits.example.","type":1,"TTL":60,"data":"192.0.2.1"}]}
                                       """
                               };

        await using var client = new DNSHTTPSClient(
                                     URL.Parse(peer.Url),
                                     Mode:          DNSHTTPSMode.JSON,
                                     QueryTimeout:  ShortTimeout
                                 );

        var response = await client.Query<A>(DomainName.Parse("bits.example."), ShortTimeout);

        Assert.Multiple(() => {
            Assert.That(response.AuthenticData,     Is.True,  "AD, as the JSON field says");
            Assert.That(response.CheckingDisabled,  Is.False);
            Assert.That(response.FilteredAnswers,   Is.Not.Empty, "and the answer still arrives");
        });

    }

    #endregion

    #region Neither_Bit_Disturbs_The_Response_Code()

    [Test]
    public async Task Neither_Bit_Disturbs_The_Response_Code()
    {

        // The octet holds RA, Z, AD, CD and the four bits of the RCODE, and the
        // reader that lost AD and CD also took the RCODE's low bit for Z. Setting
        // both bits over a non-zero RCODE is the arrangement that would notice.
        var refused = await AskWith((UInt16) (RawDnsFlags.AD | RawDnsFlags.CD | RawDnsFlags.RCode(5)));

        Assert.Multiple(() => {
            Assert.That(refused.ResponseCode,      Is.EqualTo(DNSResponseCodes.Refused), "REFUSED = 5");
            Assert.That(refused.AuthenticData,     Is.True);
            Assert.That(refused.CheckingDisabled,  Is.True);
        });

    }

    #endregion

}

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using DNSConformance.Core.RawDns;
using DNSConformance.Core.Scripted;

namespace DNSConformance.Client.Tests;

/// <summary>
/// RFC 9824 — Compact Denial of Existence, as a large signer serves it today.
/// </summary>
/// <remarks>
/// <para>
/// An online signer cannot precompute the NSEC chain of a zone it signs on the
/// fly, so it answers every denial with one NSEC record made up for the query: its
/// owner is the QNAME and its Next Domain Name is the QNAME's immediate successor,
/// which is the QNAME with a label consisting of one zero octet put in front.
/// §3.1 spells it out:
/// </para>
/// <code>
/// a.example.com. 300 IN NSEC \000.a.example.com. RRSIG NSEC NXNAME
/// </code>
/// <para>
/// Cloudflare has answered this way for every zone it signs since long before the
/// RFC was published (the "black lies" of its 2016 write-up), and RFC 9824 is the
/// standardised form of exactly that. Both responses below were recorded from
/// 1.1.1.1 on 2026-10-04 with DO set: one for a name that exists without an A
/// record, one for a name that does not exist at all. Neither is synthetic — they
/// are the bytes a client with DNSSEC turned on receives, today, for every negative
/// answer in every zone that provider signs.
/// </para>
/// <para>
/// The signatures in them expired two days after the recording. That does not
/// matter here: nothing below validates anything. What is asked is whether the
/// response can be read at all.
/// </para>
/// </remarks>
[TestFixture]
[Property("RFC", "9824 §3.1, §3.2, 4034 §4.1.1")]
public class CompactDenialTests
{

    #region Data

    private static readonly TimeSpan ShortTimeout = TimeSpan.FromMilliseconds(800);

    /// <summary>
    /// <c>mail.ietf.org. A</c>: the name exists, the type does not — RFC 9824 §3.2.
    /// NOERROR, empty answer, SOA + NSEC + two RRSIGs in the authority section. The
    /// NSEC's Next Domain Name begins <c>01 00</c>: a one-octet label holding 0x00.
    /// </summary>
    private const String MailIetfOrgNoData =
        "424281A00001000000040001046D61696C0469657466036F72670000010001C01100060001000007080032046A696C6C026E730A636C6F7564666C61726503636F6D0003646E73C033900A0C06000027100000096000093A8000000708C011002E000100000708005C00060D02000007086AC3B7AA6AC0F88A86C90469657466036F7267002B05EE3916FE7207B4C5503E117E620BB647B11E1B3B0056B2C2DF475994C0686AAB11DE4F8DBDF2809C99026DE2D9190567FFCD33FDF4D1BBFC1E59553A7387C00C002F000100000708001F0100046D61696C0469657466036F7267000009000D800C540B0D04C00101C0C00C002E000100000708005C002F0D03000007086AC3B7AA6AC0F88A86C90469657466036F726700C1912B27C0C2A8BA2C6BC784E1615A069422F0C39B48E77857F8AC507B55811B543658155EE2C84F96019A7137ACD73D86947C9F397E60B655442CC27CC740A100002904D0000080000000";

    /// <summary>
    /// <c>no-such-name.ietf.org. A</c>: the name does not exist — RFC 9824 §3.1.
    /// Same shape, still NOERROR, and the type bitmap holds exactly RRSIG, NSEC and
    /// NXNAME (128), the signal §2 defines for "this name does not exist".
    /// </summary>
    private const String NoSuchNameIetfOrg =
        "424281A000010000000400010C6E6F2D737563682D6E616D650469657466036F72670000010001C01900060001000007080032046A696C6C026E730A636C6F7564666C61726503636F6D0003646E73C03B900A0C06000027100000096000093A8000000708C019002E000100000708005C00060D02000007086AC3B7AA6AC0F88A86C90469657466036F726700F7DD650AEAD7AD7AC3ABBAD11F3D213894DF2C195E44C87FF646FE76813F5C892143B83C0DEC242158AB403E90A7F15A9320D85B08F46AB3296A85189E35908AC00C002F000100000708002C01000C6E6F2D737563682D6E616D650469657466036F72670000110000000000030000000000000000000080C00C002E000100000708005C002F0D03000007086AC3B7AA6AC0F88A86C90469657466036F726700B55C5F0EE940F09B60A4AB280A88FEFE25B81D014CD43854E1B7D73823C4AB659A73C0B0833A3F661FD8D3DAFBAEF8475A2AAB5EBA7F09F67F22069E89D160C800002904D0000080000000";


    /// <summary>
    /// The recording, re-addressed to the query actually received: its ID, and its
    /// question section byte for byte. The client checks both before it accepts an
    /// answer (finding 49), and the recording's ID was chosen by the probe that made
    /// it. The question is the same name, so it is the same length, and every
    /// compression pointer in the recording still lands where it did.
    /// </summary>
    private static Byte[] Replay(String Recording, Byte[] Request)
    {

        var response        = Convert.FromHexString(Recording);
        var questionLength  = RawDnsReader.Parse(Request).Questions[0].Name.WireLength + 4;

        Assert.That(RawDnsReader.Parse(response).Questions[0].Name.WireLength + 4, Is.EqualTo(questionLength),
                    "the replayed question has the recorded length, or the pointers behind it move");

        response[0] = Request[0];
        response[1] = Request[1];

        Array.Copy(Request, 12, response, 12, questionLength);

        return response;

    }

    #endregion


    #region A_Compact_Denial_Is_A_Negative_Answer_Not_A_Server_Failure(Name, Recording)

    /// <summary>
    /// A negative answer from an online signer, read as what it is.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 4034 §4.1.1 places no restriction on the Next Domain Name beyond being a
    /// domain name in canonical order — and a label is any sequence of up to 63
    /// octets (RFC 2181 §11: "any binary string whatever can be used as the label
    /// of any resource record"). <c>\000</c> is the smallest label there is, which
    /// is precisely why RFC 9824 uses it: <c>\000.qname</c> is the first name after
    /// <c>qname</c> in the canonical order of §6.1.
    /// </para>
    /// <para>
    /// The client answered both recordings with ServerFailure and IsValid false —
    /// the same object it hands out when a server could not be reached. For a DANE
    /// client that is the whole difference: RFC 7672 §2.1.2 makes a failed TLSA
    /// lookup a reason not to deliver, and a TLSA lookup for a host that publishes
    /// none is answered by exactly this kind of NODATA. Under a Cloudflare-signed
    /// zone every such host became unreachable.
    /// </para>
    /// </remarks>
    [TestCase("mail.ietf.org.",         MailIetfOrgNoData,  TestName = "A_Compact_Denial_Is_A_Negative_Answer_Not_A_Server_Failure(NODATA)")]
    [TestCase("no-such-name.ietf.org.", NoSuchNameIetfOrg,  TestName = "A_Compact_Denial_Is_A_Negative_Answer_Not_A_Server_Failure(NXNAME)")]
    [Property("RFC", "9824 §3.1, §3.2, 4034 §4.1.1, 2181 §11")]
    public async Task A_Compact_Denial_Is_A_Negative_Answer_Not_A_Server_Failure(String  Name,
                                                                                 String  Recording)
    {

        await using var server = new ScriptedUdpServer(request => Replay(Recording, request));

        using var client = new DNSClient(
                               IPv4Address.Localhost,
                               IPPort.Parse((UInt16) server.Port),
                               QueryTimeout:   ShortTimeout,
                               UseQueryCache:  false
                           ) {
                               DnssecOK = true
                           };

        var response = await client.Query(DNSServiceName.Parse(Name), [ DNSResourceRecordTypes.A ], ShortTimeout);

        Assert.That(server.Requests, Has.Count.GreaterThanOrEqualTo(1),
                    "the query reached the scripted server, so whatever follows is about its answer");

        var nsec = response.Authorities.OfType<NSEC>().SingleOrDefault();

        Assert.Multiple(() => {

            Assert.That(response.ResponseCode, Is.EqualTo(DNSResponseCodes.NoError),
                        "the server said NOERROR: an empty answer section is the denial, not a failure");

            Assert.That(response.IsValid,      Is.True,
                        "the response is well-formed and may be relied upon");

            Assert.That(response.Authorities.OfType<SOA>().Count(), Is.EqualTo(1),
                        "the SOA that makes the denial cacheable (RFC 2308 §3) is kept");

            Assert.That(nsec, Is.Not.Null,
                        "the one NSEC the signer made up for this query is kept — it is the proof");

            Assert.That(nsec?.NextDomainName.Labels.FirstOrDefault(), Is.EqualTo("\0"),
                        "the successor's first label is the one zero octet RFC 9824 §3.1 puts there");

        });

    }

    #endregion

}
